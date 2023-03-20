from __future__ import annotations

import typing as t
from datetime import datetime
from pathlib import Path

from .account import AccountManager
from .challenge import DNS01Challenge
from .defaults import (
    DEFAULT_CLOCK,
    DEFAULT_KEY_TYPE,
    DEFAULT_PROVIDER,
    DEFAULT_RESOLVER,
)
from .protocols import Provider, Resolver
from .types import KeyType


def create_account_file(
    filepath: str | Path, email: str, directory: str, key_type: KeyType | None = None
) -> None:
    manager = AccountManager.generate_new_account(
        email=email, directory=directory, key_type=key_type or DEFAULT_KEY_TYPE
    )
    manager.export_to_file(filepath)


def request_certificate(
    domains: list[str],
    account_file: str | Path,
    provider: Provider | None = None,
    resolver: Resolver | None = None,
    key_type: KeyType | None = None,
    clock: t.Callable[[], float] = DEFAULT_CLOCK,
    timeout: float = 120,
) -> tuple[bytes, bytes]:
    """Request a new certificate and return a tuple (key, cert) where key and cert
    are PEM-encoded bytes strings."""
    manager = AccountManager.import_from_file(account_file)
    challenge = DNS01Challenge(
        domains,
        manager=manager,
        provider=provider or DEFAULT_PROVIDER(),
        resolver=resolver or DEFAULT_RESOLVER(),
        key_type=key_type or DEFAULT_KEY_TYPE,
        clock=clock,
    )
    deadline = datetime.fromtimestamp(clock() + timeout)
    order = challenge(deadline=deadline)
    return challenge.private_key, order.fullchain_pem.encode()


__all__ = ["request_certificate", "create_account_file"]
