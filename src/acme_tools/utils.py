from __future__ import annotations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from .errors import InvalidDomainName
from .types import KeyType


def generate_private_key(key_type: KeyType = KeyType.EC256) -> bytes:
    """Generate a PEM-encoded private key as bytes.

    Arguments:
        key_type: Type of key to generate (`EC256`, `EC384`, `RSA2048`, `RSA3072`, `RSA4096`)

    Returns:
        PEM-encoded private key as bytes
    """
    # Declare key annotation
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    # Generate a EC256 private key
    if key_type == KeyType.EC256:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # Generate a EC384 private key
    elif key_type == KeyType.EC384:
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    # Generate a RSA2048 private key
    elif key_type == KeyType.RSA2048:
        key = rsa.generate_private_key(65537, 2048, default_backend())
    # Generate a RSA3072 private key
    elif key_type == KeyType.RSA3072:
        key = rsa.generate_private_key(65537, 3072, default_backend())
    # Generate a RSA4096 private key
    elif key_type == KeyType.RSA4096:
        key = rsa.generate_private_key(65537, 4096, default_backend())
    # Return private key as bytes
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )


def get_domain(fqdn: str) -> str:
    """Get root domain name out of FQDN."""
    if not fqdn:
        raise InvalidDomainName("Provided fqdn is empty")
    if "." not in fqdn:
        raise InvalidDomainName("Domain name must have an extension (.com, .fr, ...)")
    return ".".join(fqdn.split(".")[-2:])
