"""`tenant.py`'s print helper and the operator's OpenBao login for `check <id> --token-file` (#1366, #1470).

A tenant's systems, case record and credentials are written by its admin through the platform API (#1470 O10); what is
left here is what `check` needs to ask whether each system has credentials at its current generation."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def say(message: object) -> None:
    """A refusal or a note, as every `tenant.py` subcommand prints it: `[tenant.py] <message>` on stderr."""
    print(f"[tenant.py] {message}", file=sys.stderr)


def operator_secrets(token_file: Path | None, *, mount: str) -> Any:
    """The operator's OpenBao login: the deployment's address, the token read from `token_file`; or a printed
    refusal and None."""
    from defender.configuration.issuer import DEPLOYMENT_ISSUER
    from defender.credential_proxy import OpenBaoSecrets
    from defender.tenancy.tenant_settings import read_regular_bytes

    if token_file is None:
        say("this command needs the operator's OpenBao token: give --token-file <path>")
        return None
    try:
        token = read_regular_bytes(Path(token_file)).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError) as unreadable:
        say(f"{token_file} cannot be read as a token: {type(unreadable).__name__}")
        return None
    if not token:
        say(f"{token_file} holds no token")
        return None
    return OpenBaoSecrets(addr=DEPLOYMENT_ISSUER.openbao_url, token=token, mount=mount)


__all__ = ["operator_secrets", "say"]
