"""The settings value types an adapter reads (#1080): one system's parsed `config.env`, the
config-key prefix rule, the blank rule, and how a fault names a settings file. The parser that
reads `config.env` from disk stays in `tenancy.tenant_settings`."""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Protocol

from defender.kit.faults import ConfigFault

#: How model-facing text names a tenant's host-only `settings/` folder: by what it is, never by
#: its host path. The table pointers, the fault redaction and every settings fault build on it.
SETTINGS_POINTER = "the tenant's settings/"

#: The text a missing system folder raises — one wording for "this tenant's settings do not
#: configure this system", whether the folder is absent or its `config.env` is.
NOT_CONFIGURED = "this tenant's settings do not configure this system"


#: The word the tenant template leaves in every value an operator must fill in. A value still
#: carrying it, in `config.env` or `access.yaml`, means the system is not configured (#1391 S2).
PLACEHOLDER = "CHANGE-ME"


class ConfigAbsent(ConfigFault):
    """A system folder with no `config.env`: "config file not found" to every reader, except the
    settings judgement of an adapter that reads no key, for which there is nothing to read
    (#1391 O-S1)."""


def pointer_to(rel: str) -> str:
    """How a fault names the settings file at `rel` (relative to the tenant's `settings/`): by
    the settings pointer, never by its host path, so no fault text has a host path to redact."""
    return f"{SETTINGS_POINTER}{rel}"


def config_pointer(system: str) -> str:
    """`pointer_to` for `system`'s `config.env`."""
    return pointer_to(f"systems/{system}/config.env")


#: The two parts of a system's record a fault can be about (#1366 DC6): its settings and its
#: access declaration.
Part = Literal["settings", "access"]

#: The file each part was held in, in a folder of the retired layout or a connect handoff.
PART_FILES: Mapping[str, str] = MappingProxyType({"settings": "config.env", "access": "access.yaml"})


class Locator(Protocol):
    """How a fault names where the thing at fault is held (#1366 DC6): a stored record names the
    record ("system cmdb settings"), a folder handed in (the import's export, connect's handoff)
    names the file. Every settings fault an adapter or the record judgement raises asks the
    locator of the tenant record it judges, so one judgement prints one sentence in both places
    and only the locator differs."""

    def system(self, system: str) -> str:
        """The whole of `system`'s record or folder."""
        ...

    def part(self, system: str, part: Part) -> str:
        """`system`'s settings or its access declaration."""
        ...

    def case(self) -> str:
        """The tenant's case record."""
        ...


@dataclass(frozen=True)
class RecordLocator:
    """The locator of a tenant's stored records: `system <s>`, `system <s> settings`, `system <s>
    access`, `the case record`. The default of every tenant record that carries none."""

    def system(self, system: str) -> str:
        return f"system {system}"

    def part(self, system: str, part: Part) -> str:
        return f"system {system} {part}"

    def case(self) -> str:
        return "the case record"


@dataclass(frozen=True)
class FolderLocator:
    """The locator of a settings folder of the retired layout (`<shown>systems/<s>/config.env`,
    `<shown>case-record.yaml`): the import's candidate, read from the tenant's published export,
    names the file an operator fixes there. `shown` is how the folder is named, never a host path
    unless the caller means one (connect's handoff names the folder it was given)."""

    shown: str = SETTINGS_POINTER

    def system(self, system: str) -> str:
        return f"{self.shown}systems/{system}/"

    def part(self, system: str, part: Part) -> str:
        return f"{self.shown}systems/{system}/{PART_FILES[part]}"

    def case(self) -> str:
        return f"{self.shown}case-record.yaml"


#: The stored records' locator (`RecordLocator`), shared.
RECORDS: Locator = RecordLocator()


def locator_of(tenant: object) -> Locator:
    """The locator a tenant record carries (`tenant.locator`), else the stored records' one: every
    tenant a run or a judgement holds is built from records (#1366 R10)."""
    found = getattr(tenant, "locator", None)
    return found if found is not None else RECORDS


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
    """A system folder's config-key prefix: `change-mgmt` → `CHANGE_MGMT`."""
    return system.upper().replace("-", "_")


__all__ = [
    "NOT_CONFIGURED",
    "PART_FILES",
    "PLACEHOLDER",
    "RECORDS",
    "SETTINGS_POINTER",
    "ConfigAbsent",
    "FolderLocator",
    "Locator",
    "Part",
    "RecordLocator",
    "SystemConfig",
    "config_pointer",
    "is_blank",
    "locator_of",
    "pointer_to",
    "system_prefix",
]
