"""The AppRole login of a tenant's live credential generation (#1214 Flow 3, #1163 A24').

A generation records two AppRole pairs: the delivery login (`role_id`, `host_secret_file`), which
the forge credential uses to mint the tenant's forge token, and the sign-only login
(`sign_role_id`, `sign_secret_file`), which the request signer uses to sign request tokens. Both log
in the same way, so the mechanics live here once: on every login the tenant's LIVE generation is
read from the tenant records, the address is checked to be https before the secret is read, and the
secret is read (bounded, no link followed) from the host file the generation names. Only the pair
asked for is read; the other pair's file is never opened.

Faults are this module's own small family (`AppRoleLoginError`); each caller maps them to its own
(the forge credential to `ForgejoAuthError`/`CredentialMisconfigured`, the signer to `kit.faults`).
An unreachable OpenBao keeps the `httpx` error as the cause, and a refused login an
`HTTPStatusError`, so a caller that sorts faults by their chain still can. The secret and the client
token never reach a message or a repr. A records database that cannot be reached raises
`RecordsUnreachable` as the directory does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from defender import _io

if TYPE_CHECKING:
    from defender.tenancy._directory import TenantDirectory
    from defender.tenancy.models import Generation

#: OpenBao's AppRole login below its address.
LOGIN_PATH = "/v1/auth/approle/login"


@dataclass(frozen=True)
class LoginPair:
    """Which of a generation's two AppRole pairs a login uses: `delivery` or `sign`."""

    name: str

    def of(self, generation: Generation) -> tuple[str | None, Path | None]:
        """`(role id, secret file)` as `generation` records them for this pair."""
        if self is SIGN_LOGIN:
            return generation.sign_role_id, generation.sign_secret_file
        return generation.role_id, generation.host_secret_file


#: The delivery login: the forge credential's (#1214).
DELIVERY_LOGIN = LoginPair("delivery")
#: The sign-only login: the request signer's (#1163 A24').
SIGN_LOGIN = LoginPair("sign")


class AppRoleLoginError(Exception):
    """A tenant's AppRole login could not be made (see the subclasses)."""


class NoLiveGeneration(AppRoleLoginError):
    """The tenant has no live credential generation (being created, or offboarded)."""


class LoginUnrecorded(AppRoleLoginError):
    """The live generation records no role id, or no absolute secret file, for the pair."""


class SecretFileUnusable(AppRoleLoginError):
    """The pair's secret file is missing, unreadable or does not hold one secret id."""


class CleartextAddress(AppRoleLoginError):
    """The OpenBao address is not https: the secret is never sent in cleartext."""


class LoginUnreachable(AppRoleLoginError):
    """OpenBao could not be reached for the login (the `httpx` error is the cause)."""


class LoginRefused(AppRoleLoginError):
    """OpenBao answered the login with no client token: `status` is its HTTP status (a refusal
    other than 200 carries an `HTTPStatusError` as the cause)."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class AppRoleLogin:
    """One login: the generation it was made for and the OpenBao client token it got."""

    generation: Generation = field(repr=False)
    client_token: str = field(repr=False)


def live_generation(directory: TenantDirectory, tenant_id: str) -> Generation:
    """The tenant's live credential generation as the records hold it now, or `NoLiveGeneration`."""
    live = [g for g in directory.generations(tenant_id) if g.status == "live"]
    if not live:
        raise NoLiveGeneration(f"tenant {tenant_id} has no live credential generation (it is being "
                               "created, or was offboarded)")
    return live[0]


def recorded_login(generation: Generation, pair: LoginPair, tenant_id: str) -> tuple[str, Path]:
    """`(role id, absolute secret file)` that `generation` records for `pair`, or `LoginUnrecorded`.
    Reads no file."""
    role_id, secret_file = pair.of(generation)
    if not role_id:
        raise LoginUnrecorded(f"tenant {tenant_id}'s live credential generation records no {pair.name} "
                              "login (no role id)")
    if not secret_file or not Path(secret_file).is_absolute():
        raise LoginUnrecorded(f"tenant {tenant_id}'s live credential generation records no absolute "
                              f"{pair.name} secret file")
    return role_id, Path(secret_file)


def _secret(path: Path, pair: LoginPair, tenant_id: str) -> str:
    try:
        data = _io.read_plain_bytes(path)
    except OSError as unreadable:
        raise SecretFileUnusable(
            f"tenant {tenant_id}'s {pair.name} secret file {path} could not be read: "
            f"{unreadable.strerror or type(unreadable).__name__}") from None
    # The file holds the secret id and one newline (#1214 r9); bounded and no-follow by `read_plain_bytes`.
    secret = data.decode("utf-8", "replace").strip()
    if not secret or "\n" in secret:
        raise SecretFileUnusable(f"tenant {tenant_id}'s {pair.name} secret file {path} does not hold "
                                 "one secret id")
    return secret


def approle_login(directory: TenantDirectory, tenant_id: str, *, pair: LoginPair, address: str,
                  client: httpx.Client) -> AppRoleLogin:
    """Log in to OpenBao at `address` over `client` as `pair` of the tenant's live generation, read
    now: the generation, then the recorded pair, then the https rule, and only then the secret
    file, so a refusal before the login sends nothing (module doc)."""
    generation = live_generation(directory, tenant_id)
    role_id, secret_file = recorded_login(generation, pair, tenant_id)
    address = address.rstrip("/")
    if urlsplit(address).scheme != "https":
        raise CleartextAddress("the OpenBao address must be an HTTPS URL: the AppRole secret is never "
                               "sent in cleartext")
    secret = _secret(secret_file, pair, tenant_id)
    try:
        response = client.post(f"{address}{LOGIN_PATH}", json={"role_id": role_id, "secret_id": secret},
                               follow_redirects=False)
    except httpx.HTTPError as down:
        # Never the request (its body holds the secret).
        raise LoginUnreachable(f"the {pair.name} AppRole login request failed: {type(down).__name__}") from down
    if response.status_code != 200:
        raise LoginRefused(
            f"OpenBao refused tenant {tenant_id}'s {pair.name} AppRole login (HTTP {response.status_code})",
            response.status_code,
        ) from httpx.HTTPStatusError("login refused", request=response.request, response=response)
    try:
        body = response.json()
    except ValueError:
        body = None
    auth = body.get("auth") if isinstance(body, dict) else None
    token = auth.get("client_token") if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token:
        raise LoginRefused(f"OpenBao's {pair.name} AppRole login returned no client token", response.status_code)
    return AppRoleLogin(generation=generation, client_token=token)


__all__ = ["DELIVERY_LOGIN", "LOGIN_PATH", "SIGN_LOGIN", "AppRoleLogin", "AppRoleLoginError", "CleartextAddress",
           "LoginPair", "LoginRefused", "LoginUnreachable", "LoginUnrecorded", "NoLiveGeneration",
           "SecretFileUnusable", "approle_login", "live_generation", "recorded_login"]
