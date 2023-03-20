"""A small module to perform simple DNS queries.

This module relies on dnspython package available on pypi to perform DNS queries.
"""
from __future__ import annotations

from dns.exception import DNSException
from dns.resolver import Answer
from dns.resolver import Resolver as _Resolver
from dns.resolver import get_default_resolver

from acme_tools.protocols import Resolver
from acme_tools.types import RecordType


class DNSPythonResolver(Resolver):
    def __init__(self, nameservers: list[str] | None = None) -> None:
        self.resolver = get_default_resolver()
        if nameservers:
            self.resolver.nameservers = nameservers

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
            resolver: an instance of dnspython.resolver._Resolver can optionally be provided.
            This is for advanced usecase requiring specific resolver configuration,
            most users do not need to provide a value for this argument.

        Returns:
            A list of record values. For example, "A" record query returns a list of IPv4 addresses, "CNAME" record query
            return a list of hostnames.
        """
        record_type = RecordType(record_type)
        if record_type == RecordType.A:
            return _resolve_ip_addresses(fqdn, self.resolver)
        if record_type == RecordType.CNAME:
            return _resolve_cname_targets(fqdn, self.resolver)
        if record_type == RecordType.NS:
            return _resolve_nameservers(fqdn, self.resolver)
        if record_type == RecordType.TXT:
            return _resolve_txt_records(fqdn, self.resolver)
        if record_type == RecordType.SOA:
            return _resolve_authorative_nameservers(fqdn, self.resolver)
        raise TypeError(f"Invalid record type: {record_type}")


def _resolve_ip_addresses(
    fqdn: str,
    resolver: _Resolver | None = None,
) -> list[str]:
    """Return A records for given FQDN.

    Arguments:
        fqdn: The fully qualified domain name to resolve
        resolver: An instance of dns.resolver._Resolver or None

    Returns:
        A list of IP addresses found in A records for this FQDN.
    """
    resolver = resolver or get_default_resolver()
    try:
        answer = resolver.resolve(fqdn, RecordType.A)
    except DNSException:
        return []
    return [record.address for record in answer]


def _resolve_cname_targets(
    fqdn: str,
    resolver: _Resolver | None = None,
) -> list[str]:
    """Return A records for given FQDN.

    Arguments:
        fqdn: The fully qualified domain name to resolve
        resolver: An instance of dns.resolver._Resolver or None

    Returns:
        A list of domain names found in CNAME records for this FQDN.
    """
    resolver = resolver or get_default_resolver()
    try:
        answer = resolver.resolve(fqdn, RecordType.CNAME)
    except DNSException:
        return []
    return [record.target.to_text().rstrip(".") for record in answer]


def _resolve_authorative_nameservers(
    fqdn: str,
    resolver: _Resolver | None = None,
) -> list[str]:
    """Return A records for given FQDN.

    Arguments:
        fqdn: The fully qualified domain name to resolve
        resolver: An instance of dns.resolver._Resolver or None

    Returns:
        A list of authoritative nameservers hosts found in SOA records for this FQDN.
    """
    resolver = resolver or get_default_resolver()
    domain = fqdn
    # Initialize answer
    answer: Answer | None = None
    # Attempt to find SOA using domain parts
    while "." in domain:
        try:
            answer = resolver.resolve(domain, "SOA")
            break
        except DNSException:
            domain = domain.split(".", maxsplit=1)[1]
    # Return nothing if no SOA was found
    if not answer:
        return []
    # Return nameserver names
    return [record.mname.to_text() for record in answer]


def _resolve_nameservers(
    fqdn: str,
    resolver: _Resolver | None = None,
) -> list[str]:
    """Return A records for given FQDN.

    Arguments:
        fqdn: The fully qualified domain name to resolve
        resolver: An instance of dns.resolver._Resolver or None

    Returns:
        A list of nameservers hosts found in SOA records for this FQDN.
    """
    resolver = resolver or get_default_resolver()
    domain = fqdn
    # Initialize answer
    answer: Answer | None = None
    # Attempt to find SOA using domain parts
    while "." in domain:
        try:
            answer = resolver.resolve(domain, RecordType.NS)
            break
        except DNSException:
            domain = domain.split(".", maxsplit=1)[1]
    # Return nothing if no SOA was found
    if not answer:
        return []
    # Return nameserver names
    return [record.target.to_text() for record in answer]


def _resolve_txt_records(
    fqdn: str,
    resolver: _Resolver | None = None,
) -> list[str]:
    resolver = resolver or get_default_resolver()
    try:
        answer = resolver.resolve(fqdn, RecordType.TXT)
    except DNSException:
        return []
    return [string.decode() for record in answer for string in record.strings]
