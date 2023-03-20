from __future__ import annotations

import os
from pathlib import Path

TOKEN_ENV_VAR = "DO_AUTH_TOKEN"
TOKEN_FILE_ENV_VAR = f"{TOKEN_ENV_VAR}_FILE"
DEFAULT_TOKEN_FILE = "~/.dotoken"


def get_token(token: str | None = None, token_file: str | None = None) -> str:
    """Get default token to interact with Digital Ocean API.

    If DO_AUTH_TOKEN environment variable is defined, value is
    used as token.
    If DO_AUTH_TOKEN_FILE environment variable is defined,
    file content is used as token.
    """
    if token:
        return token
    if token_file:
        return Path(token_file).expanduser().read_text().strip()
    token = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if token:
        return token
    token_file = os.environ.get(TOKEN_FILE_ENV_VAR, DEFAULT_TOKEN_FILE)
    try:
        return Path(token_file).expanduser().read_text().strip()
    except FileNotFoundError:
        raise RuntimeError(
            f"Either {TOKEN_ENV_VAR} or {TOKEN_ENV_VAR} environment variable must be defined."
        )
