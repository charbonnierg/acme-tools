from __future__ import annotations

from typing import Protocol

from ..types import Record, RecordOptions


class Provider(Protocol):
    """DNS Provider is used when performing DNS-01 ACME Challenge to create and delete DNS records."""

    def create_record(self, options: RecordOptions) -> Record:
        """Create a new DNS record.

        Arguments:
            fqdn: The fully qualified domain name to set records for
            record_type: record type to set (e.g: "A", "CNAME", "TXT", ...)
            value: The value to set for the record (e.g: an IPv4 address in case of "A" record,
              a hostname in case of "CNAME", a string in case of "TXT", ...)
            ttl: The duration before record expires in cache. Cannot be lower than 30 seconds.
            append: When True, do not raise an error if a different record already exist (default to False)

        Returns:
            A Record object upon successful creation.
        """

    def delete_record(self, record: Record) -> None:
        """Delete a record.

        Arguments:
            record: The record to delete.

        Returns:
            None
        """
