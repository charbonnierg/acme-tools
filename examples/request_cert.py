"""Minimal example usage.

First create a new Let's Encrypt Account, then request a new certificate.
"""
from acme_tools import create_account_file, request_certificate
from acme_tools.account import STAGING_DIRECTORY

ACCOUNT_FILE = "./path/to/account.json"
EMAIL = "someone@somecompany.com"
DOMAINS = ["somedomain.somecompany.com"]

create_account_file(filepath=ACCOUNT_FILE, email=EMAIL, directory=STAGING_DIRECTORY)
"""Account file only needs to be created once."""

key, crt = request_certificate(domains=DOMAINS, account_file=ACCOUNT_FILE)
"""
* `key` the PEM-encoded private key of the certificate
* `crt` is the PEM-encoded certificate (with the full chain)
"""
