from __future__ import annotations

from typing import Protocol

from ..types import RecordType


class Resolver(Protocol):
    def resolve(
        self,
        fqdn: str,
        record_type: RecordType,
    ) -> list[str]:
        """Resolve a DNS query for given FQDN and record type.

        Allowed record types:
        - "A": query IPv4 addresses associated to the FQDN
        - "CNAME": query host aliases associated to the FQDN
        - "NS": query nameservers serving answers for the FQDN
        - "TXT": query TXT record values (useful for Let's Encrypt DNS-01 challenge)
        - "SOA": query the Start Of Authority for the FQDN domain

        Arguments:
            fqdn: the Fully Qualified Domain Name to run query for
            record_type: the Record Type to query.
            resolver: an instance of dnspython.resolver.Resolver can optionally be provided.
            This is for advanced usecase requiring specific resolver configuration,
            most users do not need to provide a value for this argument.

        Returns:
            A list of record values. For example, "A" record query returns a list of IPv4 addresses, "CNAME" record query
            return a list of hostnames.
        """
