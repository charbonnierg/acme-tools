from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RecordType(str, Enum):
    """Record types supported for queries."""

    A = "A"
    """This record type is used to map an IPv4 address to a hostname."""

    CNAME = "CNAME"
    """This record type defines an alias for your canonical hostname (the one defined by an A or AAAA record)."""

    NS = "NS"
    """This record type defines the name servers that are used for this zone."""

    TXT = "TXT"
    """This record type is used to associate a string of text with a hostname, primarily used for verification."""

    SOA = "SOA"
    """This record type defines the Start Of Authority. Every domain must have a SOA."""


@dataclass
class Record:
    domain: str
    """The name of the domain managed on Digital Ocean."""

    type: RecordType
    """The type of the DNS record. For example: A, CNAME, TXT, ..."""

    fqdn: str
    """The fully qualified domain name being defined by the record."""

    name: str
    """The host name or alias being defined by the record."""

    data: str
    """Variable data depending on record type. For example, the "data" value for an A record would be the IPv4 address to which the domain will be mapped.
    For a CNAME record, it would contain the domain name of the alias target."""

    ttl: int | None
    """This value is the time to live for the record, in seconds. This defines the time frame that clients can cache queried information before a refresh should be requested."""


@dataclass
class RecordOptions:
    fqdn: str
    record_type: RecordType
    record_value: str
    record_ttl: int
    append: bool
    propagation_timeout: float
    query_interval: float


class KeyType(str, Enum):
    EC256 = "EC256"
    EC384 = "EC384"
    RSA2048 = "RSA2048"
    RSA3072 = "RSA3072"
    RSA4096 = "RSA4096"
