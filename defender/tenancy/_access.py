"""The reader and strict parser of a system's access declaration (#1163, A5):
`settings/systems/<system>/access.yaml`. Read below the settings folder with no link followed;
a repeated key, an unknown key, a second base or any wrong shape is a `ConfigFault` naming the
file. The declaration type is `kit.access`."""
from __future__ import annotations

import re
import ssl
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from defender import _io, _yaml
from defender.kit.access import (
    BASIC,
    BEARER,
    HEADER,
    HTTP_PROXY,
    OAUTH_CLIENT_CREDENTIALS,
    PUBLIC_FIELD,
    AccessDeclaration,
    Auth,
    Route,
)
from defender.kit.faults import ConfigFault
from defender.kit.settings import NOT_CONFIGURED, pointer_to
from defender.kit.tls import trust_of_ca
from defender.kit.verbs import is_system_name

ACCESS_FILE = "access.yaml"
_KNOWN = ("access", "base", "auth", "reads", "writes", "ca")
#: The credential-set field names a scheme may name (the API's `CredentialKey` pattern).
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
_METHOD = re.compile(r"[A-Z]{3,10}")
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
_SCHEME_FIELDS: Mapping[str, tuple[str, ...]] = {
    BEARER: ("field",),
    HEADER: ("header", "field"),
    BASIC: (),
    OAUTH_CLIENT_CREDENTIALS: ("token_url", "scopes"),
}


def access_pointer(system: str) -> str:
    """How a fault names `system`'s access declaration: by the settings pointer, never a host
    path."""
    return pointer_to(f"systems/{system}/{ACCESS_FILE}")


def read_access(settings: Path, system: str) -> AccessDeclaration:
    """`system`'s declaration under `settings/`, or `ConfigFault` naming `access.yaml`: absent
    (the system is not configured for the proxy), unreadable, or not a valid declaration."""
    return _read_below(Path(settings), "", system)


def read_export_access(export_root: Path, system: str) -> AccessDeclaration:
    """`system`'s declaration in the export folder `export_root` (`<T>/exports/<commit>/`), read
    as `settings/systems/<system>/access.yaml` below that folder: a link at `settings/` is
    refused like any other, where `read_access` binds at `settings/` and so follows a linked
    `settings/` itself (the credential proxy, #1163 O2). Same refusals as `read_access`."""
    return _read_below(Path(export_root), "settings/", system)


def _read_below(root_dir: Path, prefix: str, system: str) -> AccessDeclaration:
    shown = access_pointer(system)
    if not is_system_name(system):
        raise ConfigFault(f"{shown}: {system!r} is not a system name")
    try:
        with _io.bind(root_dir) as root:
            got = root.read(f"{prefix}systems/{system}/{ACCESS_FILE}")
    except OSError as e:
        raise ConfigFault(f"{shown} cannot be read: {e.strerror or type(e).__name__}") from None
    if got.text is None:
        if got.absent:
            raise ConfigFault(f"{shown} not found — {NOT_CONFIGURED}")
        raise ConfigFault(f"{shown} cannot be read: {got.reason}")
    return parse_access(got.text, system=system)


def parse_access(text: str, *, system: str) -> AccessDeclaration:  # noqa: C901 — one flat shape check
    shown = access_pointer(system)
    duplicates = _yaml.duplicate_key_paths(text)
    if duplicates:
        raise ConfigFault(f"{shown} has duplicate key(s) {list(duplicates)}; write each key once")
    try:
        data = _yaml.safe_load(text)
    except yaml.YAMLError:
        raise ConfigFault(f"{shown} does not parse as YAML") from None
    if not isinstance(data, Mapping):
        raise ConfigFault(f"{shown} must be a mapping carrying the key(s) {list(_KNOWN)}")
    _yaml.reject_unread_keys(shown, data, _KNOWN, error=ConfigFault)
    if data.get("access") != HTTP_PROXY:
        raise ConfigFault(f"{shown}: `access` must be {HTTP_PROXY!r}")
    base = _base(shown, data.get("base"), "base")
    auth = _auth(shown, data.get("auth"))
    return AccessDeclaration(
        base=base, auth=auth,
        reads=_routes(shown, data.get("reads", []), "reads"),
        writes=_routes(shown, data.get("writes", []), "writes"),
        ca=_ca(shown, data.get("ca"), base, auth),
    )


def _ca(shown: str, value: object, base: str, auth: Auth) -> str | None:
    """The declaration's private CA (#1391 O4): certificates only, judged now so a bad one is a
    settings fault and never a failure at the first request. It covers every leg, so no leg may
    be plain `http://`. The text is never echoed: a pasted private key must not reach a record."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigFault(f"{shown}: `ca` must be PEM certificates as one string")
    if urlsplit(base).scheme != "https":
        raise ConfigFault(f"{shown}: `ca` needs an https `base`")
    if auth.token_url is not None and urlsplit(auth.token_url).scheme != "https":
        raise ConfigFault(f"{shown}: `ca` needs an https `auth.token_url`")
    try:
        trust_of_ca(value)
    except (ValueError, ssl.SSLError):
        raise ConfigFault(f"{shown}: `ca` must be PEM certificate blocks and nothing else "
                          "(no key, no other text), each a valid certificate") from None
    return value


def _base(shown: str, value: object, key: str) -> str:
    if not isinstance(value, str):
        raise ConfigFault(f"{shown}: `{key}` must be one URL string")
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.query
            or parts.fragment or parts.username is not None or parts.password is not None):
        raise ConfigFault(f"{shown}: `{key}` must be an http(s) URL with a host and no query, "
                          "fragment or login")
    return value


def _field(shown: str, value: object, key: str) -> str:
    if not isinstance(value, str) or not _FIELD.fullmatch(value):
        raise ConfigFault(f"{shown}: `auth.{key}` must name a credential field")
    if value in PUBLIC_FIELD.values():
        # r7 A19: the secret a scheme sends may not be a field that is public by name
        raise ConfigFault(f"{shown}: `auth.{key}` may not name the public field {value!r}")
    return value


def _auth(shown: str, value: object) -> Auth:
    if not isinstance(value, Mapping):
        raise ConfigFault(f"{shown}: `auth` must be a mapping with a `scheme`")
    scheme = value.get("scheme")
    if not isinstance(scheme, str) or scheme not in _SCHEME_FIELDS:
        raise ConfigFault(f"{shown}: `auth.scheme` must be one of {sorted(_SCHEME_FIELDS)}")
    _yaml.reject_unread_keys(shown, value, ("scheme", *_SCHEME_FIELDS[scheme]), error=ConfigFault)
    missing = [k for k in _SCHEME_FIELDS[scheme] if k not in value]
    if missing:
        raise ConfigFault(f"{shown}: auth scheme {scheme!r} needs {missing}")
    if scheme == HEADER:
        name = value["header"]
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise ConfigFault(f"{shown}: `auth.header` must be a header name")
        return Auth(scheme, header=name, field=_field(shown, value["field"], "field"))
    if scheme == BEARER:
        return Auth(scheme, field=_field(shown, value["field"], "field"))
    if scheme == BASIC:
        return Auth(scheme)
    scopes = value["scopes"]
    if not isinstance(scopes, list) or not all(isinstance(s, str) and s for s in scopes):
        raise ConfigFault(f"{shown}: `auth.scopes` must be a list of scope strings")
    return Auth(
        scheme, token_url=_base(shown, value["token_url"], "auth.token_url"),
        scopes=tuple(scopes))


def _routes(shown: str, value: object, key: str) -> tuple[Route, ...]:
    if not isinstance(value, list):
        raise ConfigFault(f"{shown}: `{key}` must be a list of {{method, path}}")
    routes = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ConfigFault(f"{shown}: each `{key}` entry must be a mapping")
        _yaml.reject_unread_keys(shown, item, ("method", "path"), error=ConfigFault)
        method, path = item.get("method"), item.get("path")
        if not isinstance(method, str) or not _METHOD.fullmatch(method):
            raise ConfigFault(f"{shown}: a `{key}` entry needs an upper-case `method`")
        if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
            raise ConfigFault(f"{shown}: a `{key}` entry needs a `path` starting with `/`")
        routes.append(Route(method, path))
    return tuple(routes)


__all__ = ["ACCESS_FILE", "access_pointer", "parse_access", "read_access", "read_export_access"]
