from time import time

from .adapters.providers import DigitalOceanProvider
from .adapters.resolvers import DNSPythonResolver
from .types import KeyType

DEFAULT_PROVIDER = DigitalOceanProvider
DEFAULT_RESOLVER = DNSPythonResolver
DEFAULT_KEY_TYPE = KeyType.RSA2048
DEFAULT_CLOCK = time


__all__ = ["DEFAULT_PROVIDER", "DEFAULT_RESOLVER", "DEFAULT_KEY_TYPE", "DEFAULT_CLOCK"]
