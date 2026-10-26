"""The settings value types an adapter reads (#1080): one system's parsed `config.env`, the
config-key prefix rule, the blank rule, and how a fault names a settings file. The parser that
reads `config.env` from disk stays in `runtime.tenant_settings`."""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from types import MappingProxyType

#: How model-facing text names a tenant's host-only `settings/` folder: by what it is, never by
#: its host path. The table pointers, the fault redaction and every settings fault build on it.
SETTINGS_POINTER = "the tenant's settings/"

#: The one implemented access method (D2). A system's `<PREFIX>_TRANSPORT` names it.
DOCKER_EXEC = "docker-exec"

#: The text a missing system folder raises — one wording for "this tenant's settings do not
#: configure this system", whether the folder is absent or its `config.env` is.
NOT_CONFIGURED = "this tenant's settings do not configure this system"


def pointer_to(rel: str) -> str:
    """How a fault names the settings file at `rel` (relative to the tenant's `settings/`): by
    the settings pointer, never by its host path, so no fault text has a host path to redact."""
    return f"{SETTINGS_POINTER}{rel}"


def config_pointer(system: str) -> str:
    """`pointer_to` for `system`'s `config.env`."""
    return pointer_to(f"systems/{system}/config.env")


def is_blank(value: str) -> bool:
    """THE blank rule: empty or whitespace-only. Shared by the view and the validator."""
    return not value.strip()


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


def system_prefix(system: str) -> str:
    """A system folder's config-key prefix: `case-history` → `CASE_HISTORY`."""
    return system.upper().replace("-", "_")


__all__ = [
    "DOCKER_EXEC",
    "NOT_CONFIGURED",
    "SETTINGS_POINTER",
    "SystemConfig",
    "config_pointer",
    "is_blank",
    "pointer_to",
    "system_prefix",
]
