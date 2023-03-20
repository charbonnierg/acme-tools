from __future__ import annotations

import datetime
import time
import typing as t
from dataclasses import dataclass

from httpx import Client, Response

from acme_tools import errors
from acme_tools.protocols import Provider
from acme_tools.types import Record, RecordOptions, RecordType
from acme_tools.utils import get_domain

from .config import get_token


@dataclass
class DORecord(Record):
    resource_id: str
    """The resource ID of the DigitalOcean DNS record."""


def raise_for_status(response: Response) -> None:
    """Raise exceptions according to HTTP status code"""
    if response.status_code == 404:
        raise errors.ResourceNotFoundError("Resource not found")
    if response.status_code == 401:
        raise errors.UnauthorizedError(
            f"Unauthorized. Check request headers: {list(response.headers)}"
        )
    if response.status_code == 429:
        reset_time = response.headers.get("ratelimit-reset")
        minutes_until_reset = int(
            datetime.timedelta(seconds=reset_time - time.time()).total_seconds() / 60
        )
        raise errors.RateLimitExceededError(
            f"Rate limit exceeded. Retry in {minutes_until_reset} minute{'s' if minutes_until_reset else ''}"
        )
    if response.status_code == 500:
        raise errors.ServerError(response.json().get("message"))
    if response.status_code == 422:
        raise errors.InvalidRequestError(response.json().get("message"))
    response.raise_for_status()


def create_record(fqdn: str, values: dict[str, t.Any]) -> DORecord:
    """Create a record out of values received by DigitalOcean API."""
    return DORecord(
        type=RecordType(values["type"]),
        domain=get_domain(fqdn),
        fqdn=fqdn,
        name=values["name"],
        data=values["data"],
        ttl=values.get("ttl"),
        resource_id=values["id"],
    )


class DigitalOceanProvider(Provider):
    def __init__(
        self,
        token: str | None = None,
        token_file: str | None = None,
    ) -> None:
        """Create a new instance of Digital Ocean provider.

        When both token and token_file are omitted, the environment variables
        `DO_AUTH_TOKEN` and `DO_AUTH_TOKEN_FILE` are used to read the token respectively
        from the value, or from the file content.
        """
        self.token = get_token(token=token, token_file=token_file)
        self.client = Client(
            base_url="https://api.digitalocean.com/v2/domains",
            headers={"Authorization": f"Bearer {self.token}"},
            follow_redirects=True,
        )

    @staticmethod
    def _check_record_type(record_type: str) -> RecordType:
        record_type = RecordType(record_type)
        if record_type == RecordType.SOA:
            raise errors.InvalidRecordType(
                "Cannot manage SOA records using Digital Ocean API"
            )
        return record_type

    def _get_records(self, fqdn: str, record_type: RecordType) -> list[DORecord]:
        """Get Digital Ocean managed DNS DORecord for given FQDN and record type.

        Arguments:
            fqdn: The fully qualified domain name to get records for
            record_type: DORecord type to get (e.g: "A", "CNAME", "TXT", ...)

        Returns:
            A list of DORecord objects
        """
        record_type = self._check_record_type(record_type)
        domain = get_domain(fqdn)
        response = self.client.get(
            f"/{domain}/records/",
            params={"name": fqdn, "type": record_type.value},
        )
        raise_for_status(response)
        fqdn_records = response.json().setdefault("domain_records", [])
        return [create_record(domain, item) for item in fqdn_records]

    def _check_record(
        self, fqdn: str, record_type: RecordType, value: str, ttl: int
    ) -> DORecord | None:
        """Check if a DNS record already exists.

        Arguments:
            fqdn: The fully qualified domain name to get records for
            record_type: DORecord type to check (e.g: "A", "CNAME", "TXT", ...)
            value: The value to set for the record (e.g: an IPv4 address in case of "A" record,
              a hostname in case of "CNAME", a string in case of "TXT", ...)
            ttl: The duration before record expires in cache. Cannot be lower than 30 seconds.

        Returns:
            A DORecord object when record exists or None when record does not exist

        Raises:
            RecordAlreadyExistsError: When a record with different value already exists.
        """
        record_type = self._check_record_type(record_type)
        # Check if record alreaxy exists
        existing_records = self._get_records(fqdn, record_type)
        for existing_record in existing_records:
            if existing_record.data == value and existing_record.ttl == ttl:
                return existing_records[0]
            raise errors.RecordAlreadyExistsError(
                f"A record of type {record_type} for FQDN {fqdn} already exists with different value: {value}"
            )
        return None

    def create_record(
        self,
        options: RecordOptions,
    ) -> DORecord:
        """Create a Digital Ocean managed DNS record.

        Arguments:
            fqdn: The fully qualified domain name to set records for
            record_type: DORecord type to set (e.g: "A", "CNAME", "TXT", ...)
            value: The value to set for the record (e.g: an IPv4 address in case of "A" record,
              a hostname in case of "CNAME", a string in case of "TXT", ...)
            ttl: The duration before record expires in cache. Cannot be lower than 30 seconds.
            append: When True, do not raise an error if a different record already exist (default to False)

        Returns:
            A DORecord object upon successful creation.
        """
        record_type = self._check_record_type(options.record_type)
        # Check if record alreaxy exists
        try:
            existing_record = self._check_record(
                options.fqdn,
                options.record_type,
                options.record_value,
                options.record_ttl,
            )
        except errors.RecordAlreadyExistsError:
            if not options.append:
                raise
        else:
            # Do nothing when record already exists
            if existing_record:
                return existing_record
        # Need to create record
        domain = get_domain(options.fqdn)
        if domain == options.fqdn:
            name = "@"
        else:
            name = options.fqdn.split(f".{domain}")[0]
        response = self.client.post(
            f"/{domain}/records",
            json={
                "type": record_type,
                "name": name,
                "data": options.record_value,
                "ttl": options.record_ttl,
            },
        )
        raise_for_status(response)
        return create_record(
            options.fqdn, response.json().setdefault("domain_record", {})
        )

    def delete_record(self, record: Record) -> None:
        """Delete a single Digital Ocean managed DNS record by ID.

        Arguments:
            domain: the domain managed on Digital Ocean
            record_id: the ID of the DNS record to delete

        Returns:
            None
        """
        if not isinstance(record, DORecord):
            raise TypeError("Can only delete DORecord instances")
        response = self.client.delete(f"/{record.domain}/records/{record.resource_id}")
        raise_for_status(response)
