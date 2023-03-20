from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import josepy as jose
from acme import client, messages
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .types import KeyType
from .utils import generate_private_key

STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


@dataclass
class AccountManager:
    """An account manager can be used to create, import or export an ACME account resource."""

    email: str
    directory: str
    private_key: bytes

    def __post_init__(self) -> None:
        # Load private key
        self.account_key = jose.JWKRSA(key=load_pem_private_key(self.private_key, None))
        # Create a network client
        self.http_client = client.ClientNetwork(
            self.account_key, user_agent="acme_tools_py/0.1.0"
        )
        # Create an ACME directory
        directory = messages.Directory.from_json(
            self.http_client.get(self.directory).json()
        )
        # Create an ACME client
        self.acme = client.ClientV2(directory, net=self.http_client)
        # Create a new registration
        self.registration = messages.NewRegistration.from_data(
            email=self.email, terms_of_service_agreed=True
        )
        # Do not create account on init
        self._resource: messages.RegistrationResource | None = None

    @property
    def account(self) -> messages.RegistrationResource:
        """ACME Account resource object."""
        if self._resource is None:
            raise ValueError("Resource has not been created yet")
        return self._resource

    def create(self) -> None:
        """Create a new ACME account."""
        # Create a new registration
        self._resource = self.acme.new_account(self.registration)

    def deactivate(self) -> None:
        # Unregister
        self.acme.deactivate_registration(self.account)

    def export_to_json(self) -> str:
        """Export ACME account into a JSON string."""
        resource_data = self.account.to_json()
        return json.dumps(
            {
                "resource": resource_data,
                "directory": self.directory,
                "email": self.email,
                "private_key": self.private_key.hex(),
            }
        )

    def export_to_file(
        self, filepath: str | Path, create_parents: bool = False
    ) -> None:
        target = Path(filepath).expanduser()
        if create_parents:
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.export_to_json())

    @classmethod
    def import_from_json(cls, content: str | bytes) -> AccountManager:
        _data = json.loads(content)
        # Load account resource
        resource = _data["resource"]
        registration = messages.RegistrationResource.from_json(resource)
        # Create a new manager
        manager = cls(
            email=_data["email"],
            private_key=bytes.fromhex(_data["private_key"]),
            directory=_data["directory"],
        )
        # Query registration instead of creating it
        manager._resource = manager.acme.query_registration(registration)
        return manager

    @classmethod
    def import_from_file(cls, filepath: str | Path) -> AccountManager:
        content = Path(filepath).expanduser().read_bytes()
        return cls.import_from_json(content)

    @classmethod
    def generate_new_account(
        cls, email: str, directory: str, key_type: KeyType = KeyType.RSA2048
    ) -> AccountManager:
        """This method can be used to first generate a private key then register a new
        account with this private key."""
        private_key = generate_private_key(key_type=key_type)
        manager = cls(email=email, directory=directory, private_key=private_key)
        manager.create()
        return manager
