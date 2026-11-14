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
from pydantic import ValidationError
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from defender.identity import Bootstrap

T = TypeVar("T")


class StartRefused(Exception):
    """A start step refused; the message is what the operator reads on stderr, naming the setting or the step."""


@dataclasses.dataclass(frozen=True)
class Settings:
    database_dsn: str
    host: str
    port: int
    frontend_origin: str
    administrators: Bootstrap
    keycloak_server_url: str
    signin_issuer: str
    signin_client_id: str
    signin_client_secret: str
    signin_redirect_uri: str
    signin_admin_client_id: str
    signin_admin_client_secret: str
    programs_issuer: str
    programs_audience: str
    programs_admin_client_id: str
    programs_admin_client_secret: str

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Settings:
        """Parse every setting, refusing the first that is missing, empty, padded, unprintable or misshapen."""
        def text(name: str) -> str:
            return _text(environ, name)

        def parsed(name: str, parse: Callable[[str], T]) -> T:
            value = text(name)
            try:
                return parse(value)
            except ValueError as why:
                raise StartRefused(f"{name}: {why}") from None

        def secret(name: str) -> str:
            return _secret(name, text(name))

        return cls(
            database_dsn=parsed("DEFENDER_DATABASE_DSN", _dsn),
            host=text("DEFENDER_API_HOST"),
            port=parsed("DEFENDER_API_PORT", _port),
            frontend_origin=parsed("DEFENDER_API_FRONTEND_ORIGIN", _origin),
            administrators=_administrators("DEFENDER_API_ADMINISTRATORS_FILE", text("DEFENDER_API_ADMINISTRATORS_FILE")),
            keycloak_server_url=parsed("DEFENDER_KEYCLOAK_SERVER_URL", _origin),
            signin_issuer=parsed("DEFENDER_KEYCLOAK_ISSUER", _issuer),
            signin_client_id=text("DEFENDER_KEYCLOAK_CLIENT_ID"),
            signin_client_secret=secret("DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE"),
            signin_redirect_uri=parsed("DEFENDER_KEYCLOAK_REDIRECT_URI", _absolute_url),
            signin_admin_client_id=text("DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID"),
            signin_admin_client_secret=secret("DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE"),
            programs_issuer=parsed("DEFENDER_KEYCLOAK_PROGRAMS_ISSUER", _issuer),
            programs_audience=text("DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE"),
            programs_admin_client_id=text("DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID"),
            programs_admin_client_secret=secret("DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE"),
        )


def _text(environ: Mapping[str, str], name: str) -> str:
    """The setting's value: present, non-empty, no edge whitespace, every character printable."""
    if name not in environ:
        raise StartRefused(f"{name} is not set")
    value = environ[name]
    if not value:
        raise StartRefused(f"{name} is empty")
    if value != value.strip() or not value.isprintable():
        raise StartRefused(f"{name} has edge whitespace or a character that cannot be printed")
    return value


def _dsn(value: str) -> str:
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


def _absolute(value: str) -> urllib.parse.SplitResult:
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("is not an http or https URL")
    return parts


def _absolute_url(value: str) -> str:
    _absolute(value)
    return value


def _origin(value: str) -> str:
    """Scheme, host and optional port: no path (a trailing slash too), query or fragment."""
    parts = _absolute(value)
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("must be a scheme, host and optional port only (no path, even a trailing slash)")
    return value


_REALM = re.compile(r"/realms/[^/]+")


def _issuer(value: str) -> str:
    parts = _absolute(value)
    if not _REALM.fullmatch(parts.path) or parts.query or parts.fragment:
        raise ValueError("must be <scheme>://<host>/realms/<realm>")
    return value


def _secret(name: str, path: str) -> str:
    """A secret file holds one value and one trailing newline at most."""
    try:
        raw = Path(path).read_text()
    except (OSError, UnicodeDecodeError) as why:
        raise StartRefused(f"{name}: cannot read the secret file: {type(why).__name__}") from None
    value = raw.removesuffix("\n")
    if not value or "\n" in value:
        raise StartRefused(f"{name}: the secret file must hold exactly one non-empty line")
    return value


def _administrators(name: str, path: str) -> Bootstrap:
    """`administrators: [<email>, ...]`, nothing else (the tenants section went with #1214)."""
    try:
        document: Any = yaml.safe_load(Path(path).read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as why:
        raise StartRefused(f"{name}: cannot read the administrators file: {type(why).__name__}") from None
    if not isinstance(document, dict) or set(document) != {"administrators"} \
            or not isinstance(document["administrators"], list):
        raise StartRefused(f"{name}: the file must be a mapping with one key, `administrators: [<email>, ...]`")
    try:
        return Bootstrap(administrators=tuple(document["administrators"]))
    except (ValidationError, TypeError) as why:
        raise StartRefused(f"{name}: the administrators are not all email addresses: {why}") from None
