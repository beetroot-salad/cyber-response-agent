"""#1107 — the settings half of a run's tenant record: what each system's `config.env` says, parsed
ONCE at resolve.

WHY IT EXISTS. Adapters used to find their URLs, container names and credentials themselves, when
called: each parsed its own `config.env` and let the process environment override it, so "whose
systems does this run talk to" was decided by how the process was launched. Here the file is read
once, when the run's tenant is resolved (`run_tenant.resolve_run_tenant`), and the values ride the
run as the record's `systems` / `elastic` fields. Nothing below the entry point reads
the process environment or the tenant folder for a setting again.

FAULTS ARE VALUES, never raises, at resolve. A system whose `config.env` is missing, unreadable or
not UTF-8 is kept as its `ConfigFault` under its name; the adapter that asks for it raises that
fault when CALLED (exit 2 → the breaker), and the run goes on (O5). `TenantRefused` keeps only
its tenant-acceptance reasons.

NO MODEL, NO PYDANTIC. The record's parts are plain read-only classes: a pydantic `ValidationError`
echoes the offending field's repr into error text.

NO SECRETS. Credential delivery (`*_SECRET_REF` references into a tenant `secrets.env`) is #1163;
until it lands a `config.env` holds no secret, and the connect validator FAILs one.

This module is outside `bash_exec`'s per-exec import closure (#1096) and must stay so.
"""
from __future__ import annotations

import dataclasses
import errno
import logging
import os
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType

from defender._io import is_plain_entry
from defender.scripts.adapters.faults import ConfigFault

_log = logging.getLogger(__name__)

#: The one implemented access method (D2). A system's `<PREFIX>_TRANSPORT` names it.
DOCKER_EXEC = "docker-exec"

#: The text a missing system folder raises — one wording for "this tenant's settings do not
#: configure this system", whether the folder is absent or its `config.env` is.
NOT_CONFIGURED = "this tenant's settings do not configure this system"

#: A settings file larger than this is not a settings file. Every one is read whole at resolve,
#: so an unbounded read would let one sparse file exhaust memory before any fault could be kept
#: as a value.
SETTINGS_MAX_BYTES = 1 << 20

#: The model-facing name of the tenant's settings folder, as `runtime.verbs.SETTINGS_POINTER`
#: spells it. Restated rather than imported: `verbs` imports the record, not the other way.
_SETTINGS_POINTER = "the tenant's settings/"

#: A line ends at CRLF, CR or LF — exactly the endings a universal-newline read (the connect
#: validator's `read_plain`) recognises, and no others (`str.splitlines` would also split on a
#: form feed or a vertical tab inside a value).
_LINE_END = re.compile(r"\r\n|\r|\n")

_PREFIX_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


# --------------------------------------------------------------------------------------------
# The one parser.
# --------------------------------------------------------------------------------------------

def parse_env(text: str) -> dict[str, str]:
    """`KEY=VALUE` lines of a `config.env`, as written. @owns config.env parse

    THE ONE PARSE for every settings file (the system configs, and the connect validator that
    checks them) — two parsers had grown with different quote rules, so one
    file described two deployments. Rules:
      * blank lines, `#` comment lines and lines with no `=` are skipped; a `#` mid-line is part
        of the value;
      * an `export K=v` line is skipped, not a key literally named `export K`;
      * the value is stripped, then ONE matched pair of surrounding quotes is trimmed (never a
        character set: a value that legitimately ends in a quote keeps it);
      * keys match case-sensitively and keep their prefix; a duplicate key yields the later
        line; a leading byte-order mark is not part of the first key;
      * a line ends at CRLF, CR or LF (`_LINE_END`), so a file the validator reads as five lines
        is five lines here too.
    """
    return {key: value for key, value, exported in assignments(text) if not exported}


def assignments(text: str) -> list[tuple[str, str, bool]]:
    """Every `KEY=VALUE` line of a settings file as written, in order: `(key, value, exported)`,
    an `export K=v` line included (as `K`, `exported` True) and every duplicate kept. The same
    line, comment and quote rules as `parse_env`, which is the last non-exported value per key —
    what a run reads. The connect validator scans all of them: a secret on a line the run ignores
    is still a secret in a tracked file."""
    out: list[tuple[str, str, bool]] = []
    for line in _LINE_END.split(text.removeprefix("\ufeff")):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        exported = re.match(r"export\s", line) is not None
        if exported:
            line = line[len("export"):].lstrip()
        key, _, raw = line.partition("=")
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            raw = raw[1:-1]
        out.append((key.strip(), raw, exported))
    return out


class _Refused(OSError):
    """A settings file that is a link, not a plain single-linked regular file, or too large. An
    `OSError`, so every reader's "cannot be read" arm covers it."""


def read_plain_fd(fd: int) -> bytes:
    """The bytes behind an open `fd`, judged before any is read: it must be a plain regular file
    with at most one name (`_io.is_plain_entry`, the repo's one rule — a file renamed over after
    it was opened has 0 names and still qualifies, so a rotation by rename never refuses a
    reader), and at most `SETTINGS_MAX_BYTES` long. `_Refused` otherwise.

    THE ONE READ every settings file goes through: the system configs and the case-history
    mapping."""
    if not is_plain_entry(os.fstat(fd)):
        raise _Refused(errno.EINVAL, "not a plain, single-linked regular file")
    chunks = []
    remaining = SETTINGS_MAX_BYTES + 1
    while remaining > 0 and (chunk := os.read(fd, min(65536, remaining))):
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > SETTINGS_MAX_BYTES:
        raise _Refused(errno.EFBIG, f"larger than {SETTINGS_MAX_BYTES} bytes")
    return data


def read_regular_bytes(path: Path) -> bytes:
    """`read_plain_fd` over `path`, opened without following a link at its last component and
    without blocking (a FIFO or device planted at a settings path is refused, never a read that
    waits forever). The folders above it were walked for links when the tenant was accepted."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        return read_plain_fd(fd)
    finally:
        os.close(fd)


def pointer_to(rel: str) -> str:
    """How a fault names the settings file at `rel` (relative to the tenant's `settings/`): by
    the settings pointer, never by its host path, so no fault text has a host path to redact."""
    return f"{_SETTINGS_POINTER}{rel}"


def config_pointer(system: str) -> str:
    """`pointer_to` for `system`'s `config.env`."""
    return pointer_to(f"systems/{system}/config.env")


def read_env_file(path: Path, *, shown: str) -> dict[str, str]:
    """`parse_env` over the file at `path`, or `ConfigFault` naming it as `shown`: a missing file
    is "this tenant's settings do not configure this system", and one that cannot be read or is
    not UTF-8 text is that system down — never an `OSError` or `UnicodeDecodeError` out of
    resolve."""
    try:
        raw = read_regular_bytes(path)
    except FileNotFoundError:
        raise ConfigFault(f"config file not found: {shown} — {NOT_CONFIGURED}") from None
    except OSError as e:
        raise ConfigFault(f"config file unreadable: {shown}: {e.strerror or type(e).__name__}") from e
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigFault(f"config file is not UTF-8 text: {shown}") from None
    return parse_env(text)


def is_blank(value: str) -> bool:
    """THE blank rule: empty or whitespace-only. Shared by the view and the validator."""
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
                out[folder.name] = SystemConfig(
                    read_env_file(folder / "config.env", shown=config_pointer(folder.name)))
            except ConfigFault as fault:
                # A fresh instance, never the caught one: the caught fault's traceback holds this
                # frame (and `out`, the live dict behind the read-only view) and its cause holds
                # the OSError with the host path. The record keeps the text only.
                out[folder.name] = ConfigFault(str(fault))
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
    if entry["ELASTIC_TRANSPORT"] != DOCKER_EXEC:
        return ConfigFault(
            f"ELASTIC_TRANSPORT={entry['ELASTIC_TRANSPORT']!r} names an access method that is "
            f"not implemented — only {DOCKER_EXEC!r} is")
    return ElasticSettings(**{attr: entry[key] for attr, key in ELASTIC_KEYS.items()})


__all__ = [
    "DOCKER_EXEC",
    "ELASTIC_KEYS",
    "BAD_ELASTIC",
    "NO_ELASTIC",
    "NOT_CONFIGURED",
    "SETTINGS_MAX_BYTES",
    "ElasticSettings",
    "SystemConfig",
    "assignments",
    "config_pointer",
    "elastic_problem",
    "elastic_view",
    "is_blank",
    "parse_env",
    "pointer_to",
    "read_env_file",
    "read_plain_fd",
    "read_regular_bytes",
    "read_systems",
    "system_prefix",
    "warn_missing_access_method",
]
