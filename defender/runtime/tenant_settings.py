"""#1107 — the settings half of a run's tenant record: what each system's `config.env` says, parsed
ONCE at resolve, and the lookup that hands out the tenant's secrets.

WHY IT EXISTS. Adapters used to find their URLs, container names and credentials themselves, when
called: each parsed its own `config.env` and let the process environment override it, so "whose
systems does this run talk to" was decided by how the process was launched. Here the file is read
once, when the run's tenant is resolved (`run_tenant.resolve_run_tenant`), and the values ride the
run as the record's `systems` / `elastic` / `secrets` fields. Nothing below the entry point reads
the process environment or the tenant folder for a setting again.

FAULTS ARE VALUES, never raises, at resolve. A system whose `config.env` is missing, unreadable or
not UTF-8 is kept as its `ConfigFault` under its name; the adapter that asks for it raises that
fault when CALLED (exit 2 → the breaker), and the run goes on (O5). `TenantRefused` keeps only
its tenant-acceptance reasons.

NO MODEL, NO PYDANTIC. The record's parts are plain read-only classes: a pydantic `ValidationError`
echoes the offending field's repr, and a secret must never ride into error text (O4).

This module is outside `bash_exec`'s per-exec import closure (#1096) and must stay so.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import re
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType

from defender.scripts.adapters.faults import ConfigFault

_log = logging.getLogger(__name__)

#: The one implemented access method (D2). A system's `<PREFIX>_TRANSPORT` names it.
DOCKER_EXEC = "docker-exec"

#: A reference key ends with this; its value names an entry of `settings/secrets.env` (D3).
SECRET_REF_SUFFIX = "_SECRET_REF"

SECRETS_FILE = "secrets.env"

#: The text a missing system folder raises — one wording for "this tenant's settings do not
#: configure this system", whether the folder is absent or its `config.env` is.
NOT_CONFIGURED = "this tenant's settings do not configure this system"

#: A secrets file larger than this is not a secrets file.
_SECRETS_MAX_BYTES = 1 << 20

#: The model-facing name of the tenant's settings folder, as `runtime.verbs.SETTINGS_POINTER`
#: spells it. Restated rather than imported: `verbs` imports the record, not the other way.
_SETTINGS_POINTER = "the tenant's settings/"

_PREFIX_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


# --------------------------------------------------------------------------------------------
# The one parser.
# --------------------------------------------------------------------------------------------

def parse_env(text: str) -> dict[str, str]:
    """`KEY=VALUE` lines of a `config.env` / `secrets.env`, as written. @owns config.env parse

    THE ONE PARSE for every settings file (the system configs, `secrets.env`, and the connect
    validator that checks them) — two parsers had grown with different quote rules, so one
    file described two deployments. Rules:
      * blank lines, `#` comment lines and lines with no `=` are skipped; a `#` mid-line is part
        of the value;
      * an `export K=v` line is skipped, not a key literally named `export K`;
      * the value is stripped, then ONE matched pair of surrounding quotes is trimmed (never a
        character set: a value that legitimately ends in a quote keeps it);
      * keys match case-sensitively and keep their prefix; a duplicate key yields the later
        line; a leading byte-order mark is not part of the first key; CRLF leaves no `\\r`.
    """
    out: dict[str, str] = {}
    for line in text.removeprefix("\ufeff").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line or re.match(r"export\s", line):
            continue
        key, _, raw = line.partition("=")
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            raw = raw[1:-1]
        out[key.strip()] = raw
    return out


def read_env_file(path: Path) -> dict[str, str]:
    """`parse_env` over the file at `path`, or `ConfigFault`: a missing file is "this tenant's
    settings do not configure this system", and one that cannot be read or is not UTF-8 text is
    that system down — never an `OSError` or `UnicodeDecodeError` out of resolve."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ConfigFault(f"config file not found: {path} — {NOT_CONFIGURED}") from None
    except OSError as e:
        raise ConfigFault(f"config file unreadable: {path}: {e.strerror or type(e).__name__}") from e
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigFault(f"config file is not UTF-8 text: {path}") from None
    return parse_env(text)


def is_blank(value: str) -> bool:
    """THE blank rule: empty or whitespace-only. Shared by the view, the lookup and the validator."""
    return not value.strip()


# --------------------------------------------------------------------------------------------
# The record's parts.
# --------------------------------------------------------------------------------------------

class SystemConfig(Mapping[str, str]):
    """One system's `config.env`, verbatim: the keys as written (prefix included, so
    `CMDB_URL_BASE`, never `URL_BASE`), each to its string value. Read-only."""

    __slots__ = ("_data",)
    _data: Mapping[str, str]

    def __init__(self, data: Mapping[str, str]) -> None:
        object.__setattr__(self, "_data", MappingProxyType(dict(data)))

    def __getitem__(self, key: str) -> str:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SystemConfig is read-only")

    def __repr__(self) -> str:
        return f"SystemConfig(keys={sorted(self._data)})"


@dataclasses.dataclass(frozen=True)
class ElasticSettings:
    """The named Elastic view of `systems["elastic"]` (D4): the keys platform code reads.

    All-or-nothing over its key set — a tenant that uses only Elasticsearch still names Kibana's
    container, because this part never degrades half-way (MF-7). Values are carried verbatim:
    presence and non-blank only, `ssl_verify` the raw string."""

    events_index: str
    alerts_index: str
    url: str
    ssl_verify: str
    es_container: str
    kibana_container: str
    docker_context: str


#: `ElasticSettings`' attribute <- the `config.env` key it carries.
ELASTIC_KEYS: dict[str, str] = {
    "events_index": "ELASTIC_EVENTS_INDEX",
    "alerts_index": "ELASTIC_ALERTS_INDEX",
    "url": "ELASTICSEARCH_URL",
    "ssl_verify": "ELASTIC_SSL_VERIFY",
    "es_container": "ELASTIC_ES_CONTAINER",
    "kibana_container": "ELASTIC_KIBANA_CONTAINER",
    "docker_context": "ELASTIC_DOCKER_CONTEXT",
}


#: The two causes an unusable Elastic part is reported under — lead-zero's "unavailable" note and
#: the branch launcher's refusal both say one of them (O9).
NO_ELASTIC = "no elastic system configured"
BAD_ELASTIC = "elastic config is bad"


def elastic_problem(elastic: ElasticSettings | ConfigFault | None) -> str | None:
    """Why `record.elastic` cannot be used, or `None` when it can: `NO_ELASTIC` for a tenant with
    no `systems/elastic/` folder, `BAD_ELASTIC: <fault>` for a part that could not stand. The
    fault text is the resolver's own and may name a host path: a caller that shows it to a model
    or writes it into a run passes it through `verbs.redact_settings_path`."""
    if elastic is None:
        return NO_ELASTIC
    if isinstance(elastic, ConfigFault):
        return f"{BAD_ELASTIC}: {elastic}"
    return None


def system_prefix(system: str) -> str:
    """A system folder's config-key prefix: `case-history` → `CASE_HISTORY`."""
    return system.upper().replace("-", "_")


def read_systems(settings: Path) -> Mapping[str, SystemConfig | ConfigFault]:
    """One entry per non-hidden folder under `settings/systems/`, keyed by its exact name: the
    `SystemConfig` of its `config.env`, or the `ConfigFault` for why there is none. Never
    raises for a system's config. @owns systems"""
    systems_dir = Path(settings) / "systems"
    out: dict[str, SystemConfig | ConfigFault] = {}
    if systems_dir.is_dir():
        for folder in sorted(systems_dir.iterdir()):
            if folder.name.startswith(".") or not folder.is_dir():
                continue
            try:
                out[folder.name] = SystemConfig(read_env_file(folder / "config.env"))
            except ConfigFault as fault:
                out[folder.name] = fault
    return MappingProxyType(out)


def warn_missing_access_method(tenant_id: str, systems: Mapping[str, SystemConfig | ConfigFault]) -> None:
    """One warning naming each system whose config predates D2: it lacks `<PREFIX>_TRANSPORT` or
    `<PREFIX>_DOCKER_CONTEXT`, so every call it makes will fault (there is no default)."""
    lacking = []
    for name, entry in systems.items():
        if not isinstance(entry, SystemConfig) or not _PREFIX_NAME.match(name):
            continue
        prefix = system_prefix(name)
        missing = [k for k in (f"{prefix}_TRANSPORT", f"{prefix}_DOCKER_CONTEXT") if k not in entry]
        if missing:
            lacking.append(f"{name} ({', '.join(missing)})")
    if lacking:
        _log.warning(
            "tenant %r: system config lacks an access-method key, so these systems are down "
            "until it is added: %s", tenant_id, "; ".join(lacking))


def elastic_view(systems: Mapping[str, SystemConfig | ConfigFault]) -> ElasticSettings | ConfigFault | None:
    """The Elastic part, or `None` when the tenant has no `systems/elastic/` folder, or the
    `ConfigFault` for why it cannot stand — a missing file, a key absent or blank, or an access
    method other than docker-exec. Never raised (O5). @owns elastic

    THE ONE PLACE platform code interprets config keys (D4)."""
    entry = systems.get("elastic")
    if entry is None:
        return None
    if isinstance(entry, ConfigFault):
        return ConfigFault(str(entry))
    bad = [key for key in ("ELASTIC_TRANSPORT", *ELASTIC_KEYS.values())
           if key not in entry or is_blank(entry[key])]
    if bad:
        return ConfigFault(
            f"elastic config is missing or blank: {', '.join(bad)} — the Elastic part is "
            "all-or-nothing over these keys")
    if entry["ELASTIC_TRANSPORT"].strip() != DOCKER_EXEC:
        return ConfigFault(
            f"ELASTIC_TRANSPORT={entry['ELASTIC_TRANSPORT']!r} names an access method that is "
            f"not implemented — only {DOCKER_EXEC!r} is")
    return ElasticSettings(**{attr: entry[key] for attr, key in ELASTIC_KEYS.items()})


# --------------------------------------------------------------------------------------------
# Secrets.
# --------------------------------------------------------------------------------------------

#: What a `*_SECRET_REF` value must look like to be the NAME of a `secrets.env` entry: letters,
#: digits and underscore, not starting with a digit. A value of any other shape is a secret pasted
#: where a reference belongs (the connect validator FAILs it, naming only the key).
_SECRET_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_secret_name(value: str) -> bool:
    """Whether `value` is shaped like the name of a `secrets.env` entry."""
    return _SECRET_NAME.match(value) is not None


def declared_secrets(systems: Mapping[str, SystemConfig | ConfigFault]) -> dict[str, tuple[str, ...]]:
    """Secret name → the all-uppercase `*_SECRET_REF` keys that declare it, across EVERY parsed
    system of the tenant (a faulted sibling narrows nothing). A blank reference declares
    nothing; a key spelled in any other case is not a reference (the validator FAILs it)."""
    declared: dict[str, set[str]] = {}
    for entry in systems.values():
        if not isinstance(entry, SystemConfig):
            continue
        for key, held in entry.items():
            if key.endswith(SECRET_REF_SUFFIX) and key == key.upper() and not is_blank(held):
                declared.setdefault(held, set()).add(key)
    return {name: tuple(sorted(keys)) for name, keys in declared.items()}


class _Refused(Exception):
    """The secrets file, or a folder above it, is a link or not a regular file."""


def _read_no_links(root: Path, parts: tuple[str, ...]) -> bytes:
    """The bytes of `root/parts...`, opened one component at a time from a directory handle, each
    with no-follow: a link at ANY level (the tenant folder, `settings/`, the file) is refused, and
    so is a last component that is not a regular file or has more than one name (a hard link is
    another tenant's bytes under this name). `O_NONBLOCK` keeps a FIFO with no writer from
    blocking the open — it is then refused as not regular."""
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise _Refused
        chunks = []
        remaining = _SECRETS_MAX_BYTES + 1
        while remaining > 0 and (chunk := os.read(fd, min(65536, remaining))):
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > _SECRETS_MAX_BYTES:
        raise _Refused
    return data


class SecretLookup:
    """Resolves a secret name for THIS tenant, only if some `*_SECRET_REF` key in its systems
    declares it (O3), reading `settings/secrets.env` on each lookup — a rotation takes effect
    mid-run (O2's exemption), while the declarations ride the run's start (MF-2). @owns secrets

    A fault names the DECLARING KEY, never a value or the string the key holds (MF-15), so the
    text is safe for a row, a log and a model. `repr` shows declared names only."""

    __slots__ = ("_declared", "_root", "_parts")
    _declared: Mapping[str, tuple[str, ...]]
    _root: Path
    _parts: tuple[str, ...]

    def __init__(self, tenants_root: Path, tenant_id: str, declared: Mapping[str, tuple[str, ...]]) -> None:
        object.__setattr__(self, "_root", Path(tenants_root))
        object.__setattr__(self, "_parts", (str(tenant_id), "settings", SECRETS_FILE))
        object.__setattr__(self, "_declared", MappingProxyType(dict(declared)))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretLookup is read-only")

    def __repr__(self) -> str:
        return f"SecretLookup(declared={sorted(self._declared)})"

    def get(self, name: str) -> str:
        """The value of the declared secret `name`, or `ConfigFault`."""
        keys = self._declared.get(name)
        if not keys:
            raise ConfigFault(
                "secret is not declared: no *_SECRET_REF key in this tenant's systems names it")
        ref = ", ".join(keys)
        try:
            text = _read_no_links(self._root, self._parts).decode("utf-8")
        except FileNotFoundError:
            raise ConfigFault(f"{ref}: {_SETTINGS_POINTER}{SECRETS_FILE} is missing") from None
        except (OSError, _Refused):
            raise ConfigFault(
                f"{ref}: {_SETTINGS_POINTER}{SECRETS_FILE} cannot be read (a link, not a regular "
                "file, or unreadable)") from None
        except UnicodeDecodeError:
            raise ConfigFault(f"{ref}: {_SETTINGS_POINTER}{SECRETS_FILE} is not UTF-8 text") from None
        value = parse_env(text).get(name)
        if value is None or is_blank(value):
            raise ConfigFault(f"{ref}: {_SETTINGS_POINTER}{SECRETS_FILE} has no non-blank entry for it")
        return value


__all__ = [
    "DOCKER_EXEC",
    "ELASTIC_KEYS",
    "BAD_ELASTIC",
    "NO_ELASTIC",
    "NOT_CONFIGURED",
    "SECRET_REF_SUFFIX",
    "ElasticSettings",
    "SecretLookup",
    "SystemConfig",
    "declared_secrets",
    "elastic_problem",
    "elastic_view",
    "is_blank",
    "is_secret_name",
    "parse_env",
    "read_env_file",
    "read_systems",
    "system_prefix",
    "warn_missing_access_method",
]
