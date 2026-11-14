"""The program's settings: one type, parsed once from the environment and the files it names. Every field is
required and none has a default; a missing or invalid one refuses start naming it (#1083 O1, Am-7)."""

from __future__ import annotations

import dataclasses
import re
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import SecretStr, ValidationError
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from defender._io import read_text_utf8
from defender._yaml import safe_load
from defender.identity import Bootstrap, DataRuleViolation
from defender.identity.keycloak import check_issuer, check_server_url  # lint-shippable: ok — the program wires the one sign-in vendor the platform supports (#1083).

T = TypeVar("T")


class StartRefused(Exception):
    """A start step refused; the message is what the operator reads on stderr, naming the setting or the step."""


@dataclasses.dataclass(frozen=True)
class Settings:
    """The client secrets are `SecretStr`: printing the settings shows `**********`, and the one place that hands a
    secret to an adapter reads it out by name."""

    database_dsn: str
    host: str
    port: int
    frontend_origin: str
    administrators: Bootstrap
    keycloak_server_url: str
    signin_issuer: str
    signin_client_id: str
    signin_client_secret: SecretStr
    signin_redirect_uri: str
    signin_admin_client_id: str
    signin_admin_client_secret: SecretStr
    programs_issuer: str
    programs_audience: str
    programs_admin_client_id: str
    programs_admin_client_secret: SecretStr

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Settings:
        """Parse every setting, refusing the first that is missing, empty, padded, unprintable or misshapen."""
        def text(name: str) -> str:
            return _setting_text(environ, name)

        def parsed(name: str, parse: Callable[[str], T]) -> T:
            value = text(name)
            try:
                return parse(value)
            except ValueError as why:
                raise StartRefused(f"{name}: {why}") from None

        def secret(name: str) -> SecretStr:
            return SecretStr(_secret_from_file(name, text(name)))

        return cls(
            database_dsn=parsed("DEFENDER_DATABASE_DSN", _database_dsn),
            host=text("DEFENDER_API_HOST"),
            port=parsed("DEFENDER_API_PORT", _port),
            frontend_origin=parsed("DEFENDER_API_FRONTEND_ORIGIN", _origin),
            administrators=_administrators("DEFENDER_API_ADMINISTRATORS_FILE", text("DEFENDER_API_ADMINISTRATORS_FILE")),
            keycloak_server_url=parsed("DEFENDER_KEYCLOAK_SERVER_URL", check_server_url),
            signin_issuer=parsed("DEFENDER_KEYCLOAK_ISSUER", check_issuer),
            signin_client_id=text("DEFENDER_KEYCLOAK_CLIENT_ID"),
            signin_client_secret=secret("DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE"),
            signin_redirect_uri=parsed("DEFENDER_KEYCLOAK_REDIRECT_URI", _absolute_url),
            signin_admin_client_id=text("DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID"),
            signin_admin_client_secret=secret("DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE"),
            programs_issuer=parsed("DEFENDER_KEYCLOAK_PROGRAMS_ISSUER", check_issuer),
            programs_audience=text("DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE"),
            programs_admin_client_id=text("DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID"),
            programs_admin_client_secret=secret("DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE"),
        )


def _setting_text(environ: Mapping[str, str], name: str) -> str:
    """The setting's value: present, non-empty, no edge whitespace, every character printable."""
    if name not in environ:
        raise StartRefused(f"{name} is not set")
    value = environ[name]
    if not value:
        raise StartRefused(f"{name} is empty")
    if value != value.strip() or not value.isprintable():
        raise StartRefused(f"{name} has edge whitespace or a character that cannot be printed")
    return value


def _database_dsn(value: str) -> str:
    try:
        url = make_url(value)
    except ArgumentError:
        raise ValueError("is not a database address (postgresql://...)") from None
    if not url.drivername.startswith("postgresql"):
        raise ValueError("is not a PostgreSQL address (postgresql://...)")
    return value


def _port(value: str) -> int:
    if not (value.isascii() and value.isdecimal()) or not 1 <= int(value) <= 65535:
        raise ValueError("is not a port number from 1 to 65535")
    return int(value)


def _http_url(value: str) -> urllib.parse.SplitResult:
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("is not an http or https URL")
    try:
        parts.port  # noqa: B018 — reading it is the check: a port outside 0-65535 or not a number raises
    except ValueError:
        raise ValueError("has a port that is not a number from 0 to 65535") from None
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("must not carry credentials")
    return parts


def _absolute_url(value: str) -> str:
    _http_url(value)
    return value


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(value: str) -> str:
    """Scheme, host and optional port: no path (a trailing slash too), query or fragment. Written exactly as a
    browser sends it in `Origin` (lower case, no default port, an ASCII host), since requests are compared to it
    character for character; any other spelling refuses, naming the one to write."""
    parts = _http_url(value)
    if parts.path or parts.query or parts.fragment:
        raise ValueError("must be a scheme, host and optional port only (no path, even a trailing slash)")
    host = parts.hostname or ""
    if not host.isascii():
        raise ValueError("must name its host in ASCII (an internationalized name in its xn-- form), as a browser sends it")
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and parts.port != _DEFAULT_PORTS[parts.scheme]:
        netloc += f":{parts.port}"
    canonical = f"{parts.scheme}://{netloc}"
    if value != canonical:
        raise ValueError(f"must be written as a browser sends it: {canonical}")
    return value


_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
def _secret_from_file(name: str, path: str) -> str:
    """A secret file holds one value and one trailing newline at most."""
    try:
        raw = read_text_utf8(Path(path))
    except (OSError, UnicodeDecodeError) as why:
        raise StartRefused(f"{name}: cannot read the secret file: {type(why).__name__}") from None
    value = raw.removesuffix("\n")
    if not value or "\n" in value:
        raise StartRefused(f"{name}: the secret file must hold exactly one non-empty line")
    return value


def _administrators(name: str, path: str) -> Bootstrap:
    """`administrators: [<email>, ...]`, nothing else (the tenants section went with #1214)."""
    try:
        document: Any = safe_load(read_text_utf8(Path(path)))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as why:
        raise StartRefused(f"{name}: cannot read the administrators file: {type(why).__name__}") from None
    if not isinstance(document, dict) or set(document) != {"administrators"} \
            or not isinstance(document["administrators"], list):
        raise StartRefused(f"{name}: the file must be a mapping with one key, `administrators: [<email>, ...]`")
    listed = document["administrators"]
    if not all(isinstance(e, str) and _EMAIL.fullmatch(e) for e in listed):
        raise StartRefused(f"{name}: every administrator must be an email address (name@host)")
    try:
        return Bootstrap(administrators=tuple(listed))
    except (ValidationError, TypeError, DataRuleViolation) as why:
        raise StartRefused(f"{name}: the administrators are not all email addresses: {why}") from None
