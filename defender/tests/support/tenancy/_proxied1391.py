"""A fixture tenant whose elastic is a proxied system (#1391 P1/D12) needs, at run start, a live
generation holding a sign login (and the proxy's address, set by tests/conftest.py). Plants data
only; the suites using it fake their verbs, so nothing is sent to the address."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def sign_login_fields(tenant_id: str, salt: str) -> dict[str, Any]:
    """The sign-login fields a generation records (run start signs request tokens with them)."""
    return {"sign_approle": f"sign-{tenant_id}-{salt}", "sign_entity": f"tenant-{tenant_id}-{salt}-sign",
            "sign_role_id": "sign-role-1391", "sign_secret_file": Path(f"/nonexistent/{tenant_id}-{salt}-sign"),
            "sign_secret_accessor": f"sign-accessor-{tenant_id}-{salt}"}


def with_sign_login(tenant_id: str, fields: dict[str, Any]) -> dict[str, Any]:
    """`fields` (a generation's, e.g. `_active1214.generation_fields`) plus a sign login, unless it has one."""
    return {**sign_login_fields(tenant_id, str(fields["salt"])), **fields}


def sign_generation(tenant_id: str) -> dict[str, Any]:
    """The fields of one live credential generation of `tenant_id` that records a sign login
    (the host files it names are not written: run start reads the records only)."""
    salt = "t1391"
    return {"salt": salt, "status": "live", "bot_login": f"bot-{tenant_id}-{salt}",
            "oidc_role": f"oidc-{tenant_id}-{salt}", "approle": f"approle-{tenant_id}-{salt}",
            "role_id": "delivery-role-1391", "entity": f"entity-{tenant_id}-{salt}",
            "audience": f"audience-{tenant_id}-{salt}",
            "host_secret_file": Path(f"/nonexistent/{tenant_id}-{salt}"),
            "secret_accessor": f"accessor-{tenant_id}-{salt}",
            **sign_login_fields(tenant_id, salt)}
