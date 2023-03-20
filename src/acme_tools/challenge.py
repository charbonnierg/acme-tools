from __future__ import annotations

import sys
import time
import typing as t
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime

from acme import challenges, messages
from acme.crypto_util import make_csr

from acme_tools.defaults import DEFAULT_KEY_TYPE, DEFAULT_PROVIDER, DEFAULT_RESOLVER
from acme_tools.protocols import Provider, Resolver
from acme_tools.types import KeyType, Record, RecordOptions, RecordType
from acme_tools.utils import generate_private_key

from .account import AccountManager

DNS_LABEL = "_acme-challenge"


@dataclass
class DNS01Challenge:
    domains: list[str]
    manager: AccountManager
    key_type: KeyType = DEFAULT_KEY_TYPE
    provider: Provider = field(default_factory=DEFAULT_PROVIDER)
    resolver: Resolver = field(default_factory=DEFAULT_RESOLVER)
    clock: t.Callable[[], float] = time.time

    def __post_init__(self) -> None:
        # Start by creating a private key and a csr
        self.private_key = generate_private_key(self.key_type)
        self.csr = make_csr(self.private_key, self.domains)

    def debug(self, msg: str) -> None:
        print(f"DEBUG: {msg}")

    def __call__(self, deadline: datetime | None) -> messages.OrderResource:
        # Generate a new ACME order resource
        self.debug("Sending request to create new order using CSR...")
        order = self.manager.acme.new_order(self.csr)
        self.debug("OK")
        _challenges: list[messages.ChallengeBody] = []
        _responses: list[challenges.KeyAuthorizationChallengeResponse] = []
        _verification_tokens: list[str] = []
        self.debug("Checking that DNS-01 challenge is available...")
        # Loop through each of our authorizations
        for authz in order.authorizations:
            # Loop through each authorization's available challenges
            for item in authz.body.challenges:
                # Add the DNS-01 challenge if it is found
                if isinstance(item.chall, challenges.DNS01):
                    _challenges.append(item)
        # If no challenges were found, throw an error
        if not _challenges:
            msg = f"ACME server at '{self.manager.directory}' does not support DNS-01 challenge."
            raise RuntimeError(msg)

        self.debug("OK")

        # Loop through each of our challenges and extract the response and verification token from each
        for _, challenge in enumerate(_challenges):
            response, validation = challenge.response_and_validation(
                self.manager.http_client.key
            )
            _responses.append(response)
            _verification_tokens.append(validation)

        verification_tokens: list[tuple[str, str]] = []

        # Loop through each domain and group it with it's corresponding verification token
        for i, domain in enumerate(self.domains):
            # If wildcard domain, strip of the wildcard to validate the base domain instead.
            domain = domain[2:] if domain[:2] == "*." else domain
            # Add the ACME verification DNS name and token as a tuple to groupings
            verification_tokens.append(
                (DNS_LABEL + "." + domain, _verification_tokens[i])
            )

        self.debug(
            f"Extracted DNS-01 challenge verification tokens: {verification_tokens}"
        )
        # At this point we should update DNS records and wait for propagation
        # Since there are several records, and we're not doing async, we might
        # wait want to first create all records, then check all records
        with self.temporary_txt_records(verification_tokens):
            # For each challenge, request an answer.
            for index, challenge in enumerate(_challenges):
                self.debug(f"Responding to challenge {challenge}")
                answer = self.manager.acme.answer_challenge(
                    challenge, _responses[index]
                )
                self.debug(f"Got answer {answer.to_json()}")
            # Request our final order and save the certificate if successful
            return self.manager.acme.poll_and_finalize(order, deadline=deadline)

    @contextmanager
    def temporary_txt_records(
        self, records: list[tuple[str, str]]
    ) -> t.Iterator[list[Record]]:
        # Create an exit stack
        stack = ExitStack()
        # Enter the exit stack
        stack.__enter__()
        # Initialize empty list of DNS records
        dns_records: list[Record] = []
        try:
            # Create all records one by one
            for fqdn, value in records:
                self.debug(f"Creating TXT record for domain {fqdn} with value {value}")
                record = self.provider.create_record(
                    RecordOptions(
                        fqdn=fqdn,
                        record_type=RecordType.TXT,
                        record_value=value,
                        record_ttl=30,
                        append=True,
                        propagation_timeout=120,
                        query_interval=2,
                    )
                )
                # Add callback to delete record on stack exit
                stack.callback(self.provider.delete_record, record)
                # Append newly created DNS record
                dns_records.append(record)
            # Wait for changes to be propagated
            deadline = self.clock() + 120
            for record in dns_records:
                propagated = False
                while self.clock() < deadline:
                    print(
                        f"Waiting for record to be propagated for domain: {record}..."
                    )
                    # Attempt to resolve DNS query for record type
                    values = self.resolver.resolve(record.fqdn, record_type=record.type)
                    print(f"Found values: {values}")
                    # Look for value within resolved values
                    if record.data in values:
                        propagated = True
                        print("OK")
                        break
                    # Sleep for interval
                    time.sleep(2)

                if not propagated:
                    raise TimeoutError(
                        "Failed to query record before deadline. Record did not propagate."
                    )
            # Yield all records
            yield dns_records
        finally:
            # Exit context stack (delete all records)
            print("Deleting DNS records")
            stack.__exit__(*sys.exc_info())
