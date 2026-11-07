"""Every OpenBao API call the tenant lifecycle makes, by what it does (#1440): the management
service's AppRoles, entities, OIDC roles and signing keys, and the bot's and the host's logins.
Each answers an `ApiCall` its caller sends with its own client; a call that must carry its own
token, or none, says so in its headers.

The lifecycle writes no OpenBao path of its own (`tooling/lint/lint_inline_api_paths.py`). The
credential proxy and the tenancy's AppRole login still reach OpenBao through their own paths."""
from __future__ import annotations

from collections.abc import Mapping

from defender._api_call import ApiCall
from defender.configuration.issuer import TRANSIT_MOUNT

_TOKEN = "X-Vault-Token"
_APPROLE = "/v1/auth/approle/role"
_ENTITY = "/v1/identity/entity/name"
_OIDC_ROLE = "/v1/identity/oidc/role"
_KEYS = f"/v1/{TRANSIT_MOUNT}/keys"


# --- logins and tokens ----------------------------------------------------------------------------


def auth_mounts() -> ApiCall:
    """The enabled auth mounts, each with its accessor."""
    return ApiCall("GET", "/v1/sys/auth")


def log_in_with_approle(role_id: str, secret_id: str) -> ApiCall:
    """Log in with an AppRole pair; the request carries no other token."""
    return ApiCall("POST", "/v1/auth/approle/login", json={"role_id": role_id, "secret_id": secret_id},
                   headers={_TOKEN: ""})


def oidc_token(role: str, *, token: str) -> ApiCall:
    """A JWT of the OIDC role `role`, read as `token`."""
    return ApiCall("GET", f"/v1/identity/oidc/token/{role}", headers={_TOKEN: token})


def unwrap(wrapping_token: str) -> ApiCall:
    """What `wrapping_token` wraps (spending it)."""
    return ApiCall("POST", "/v1/sys/wrapping/unwrap", headers={_TOKEN: wrapping_token})


# --- AppRoles and their secret ids ----------------------------------------------------------------


def write_approle(name: str, *, policy: str, ttl: str) -> ApiCall:
    """Make or rewrite the AppRole `name`: tokens on `policy` living `ttl`, secret ids that never
    expire by time or use."""
    return ApiCall("POST", f"{_APPROLE}/{name}", json={
        "token_policies": [policy], "token_ttl": ttl, "token_max_ttl": ttl,
        "secret_id_ttl": 0, "secret_id_num_uses": 0})


def approle_role_id(name: str) -> ApiCall:
    return ApiCall("GET", f"{_APPROLE}/{name}/role-id")


def delete_approle(name: str) -> ApiCall:
    return ApiCall("DELETE", f"{_APPROLE}/{name}")


def new_secret_id(approle: str, *, wrap_ttl: str | None = None) -> ApiCall:
    """A new secret id of `approle`, answered wrapped for `wrap_ttl` seconds when given."""
    return ApiCall("POST", f"{_APPROLE}/{approle}/secret-id",
                   headers=None if wrap_ttl is None else {"X-Vault-Wrap-TTL": wrap_ttl})


def secret_id_accessors(approle: str) -> ApiCall:
    """The accessors of `approle`'s secret ids (404 when it has none)."""
    return ApiCall("GET", f"{_APPROLE}/{approle}/secret-id", params={"list": "true"})


def destroy_secret_id(approle: str, accessor: str) -> ApiCall:
    return ApiCall("POST", f"{_APPROLE}/{approle}/secret-id-accessor/destroy", json={"secret_id_accessor": accessor})


# --- entities -------------------------------------------------------------------------------------


def write_entity(name: str, metadata: Mapping[str, str]) -> ApiCall:
    """Make or update the entity `name` with `metadata`."""
    return ApiCall("POST", f"{_ENTITY}/{name}", json={"metadata": dict(metadata)})


def entity(name: str) -> ApiCall:
    return ApiCall("GET", f"{_ENTITY}/{name}")


def delete_entity(name: str) -> ApiCall:
    """Delete the entity `name`, its aliases with it."""
    return ApiCall("DELETE", f"{_ENTITY}/{name}")


def create_entity_alias(*, name: str, entity_id: str, mount_accessor: str) -> ApiCall:
    return ApiCall("POST", "/v1/identity/entity-alias", json={
        "name": name, "canonical_id": entity_id, "mount_accessor": mount_accessor})


# --- OIDC roles -----------------------------------------------------------------------------------


def write_oidc_role(name: str, *, key: str, ttl: str, template: str, client_id: str | None = None) -> ApiCall:
    """Make or rewrite the OIDC role `name`, its audience `client_id` when given."""
    body: dict[str, str] = {"key": key, "ttl": ttl, "template": template}
    if client_id is not None:
        body["client_id"] = client_id
    return ApiCall("POST", f"{_OIDC_ROLE}/{name}", json=body)


def delete_oidc_role(name: str) -> ApiCall:
    return ApiCall("DELETE", f"{_OIDC_ROLE}/{name}")


# --- transit signing keys -------------------------------------------------------------------------


def transit_key(key: str) -> ApiCall:
    """Read the signing key `key` (404 when absent)."""
    return ApiCall("GET", f"{_KEYS}/{key}")


def create_transit_key(key: str) -> ApiCall:
    """Make `key` an ed25519 signing key."""
    return ApiCall("POST", f"{_KEYS}/{key}", json={"type": "ed25519"})


def allow_transit_key_deletion(key: str) -> ApiCall:
    return ApiCall("POST", f"{_KEYS}/{key}/config", json={"deletion_allowed": True})


def delete_transit_key(key: str) -> ApiCall:
    return ApiCall("DELETE", f"{_KEYS}/{key}")


def transit_sign(key: str, *, input_b64: str, token: str) -> ApiCall:
    """Sign the base64 `input_b64` with `key`, as `token`."""
    return ApiCall("POST", f"/v1/{TRANSIT_MOUNT}/sign/{key}", json={"input": input_b64}, headers={_TOKEN: token})
