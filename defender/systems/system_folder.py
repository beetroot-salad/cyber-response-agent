"""A system's folder (#1366 O9, O11, DC8): `config.env` plus `access.yaml`, the shape the operator's `set-system` takes,
`systems --export` writes, connect hands off and the import reads from a tenant's retired `settings/systems/<s>/`.

One reader for all four, so a folder means the same thing wherever it is handed in. A record holds exactly what the
folder says: every `KEY=value` line of `config.env` is a setting, and a line a parser could ignore or override (an
`export` line, a key set twice) is refused rather than dropped, so a value on such a line never becomes, or hides
behind, a stored setting. A missing `config.env` is no settings and a missing `access.yaml` is no declaration: what
that leaves unusable is the record judgement's to say (`record_judgement`), not the reader's. Faults name the folder's
parts through the caller's locator (DC6): the record's words for `set-system`, the file for the import and connect."""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from pathlib import Path

from defender.kit.settings import PART_FILES, Locator
from defender.tenancy.tenant_settings import assignments, read_regular_bytes


@dataclasses.dataclass(frozen=True)
class SystemFolder:
    """A folder read: its settings (keys as stored, prefixed), its access declaration's text, and why it cannot be a
    record as it stands (empty when it can be judged)."""

    settings: Mapping[str, str]
    access: str
    faults: tuple[str, ...] = ()


def folder_of_bytes(system: str, *, config: bytes | None, access: bytes | None, locator: Locator) -> SystemFolder:
    """The folder whose `config.env` and `access.yaml` hold `config` and `access` (None: the file is absent)."""
    faults: list[str] = []
    settings: dict[str, str] = {}
    if config is not None:
        text = _text(config)
        if text is None:
            faults.append(f"{locator.part(system, 'settings')}: is not UTF-8 text")
        else:
            seen: set[str] = set()
            for key, value, exported in assignments(text):
                if exported:
                    faults.append(f"{locator.part(system, 'settings')}: `export {key}` is an export line; a setting is a "
                                  "plain KEY=value line")
                elif key in seen:
                    faults.append(f"{locator.part(system, 'settings')}: {key} is set more than once; set each key once")
                else:
                    settings[key] = value
                seen.add(key)
    declaration = ""
    if access is not None:
        text = _text(access)
        if text is None:
            faults.append(f"{locator.part(system, 'access')}: is not UTF-8 text")
        else:
            declaration = text
    return SystemFolder(settings=settings, access=declaration, faults=tuple(faults))


def read_folder(folder: Path, system: str, *, locator: Locator) -> SystemFolder:
    """`folder`'s `config.env` and `access.yaml`, each read whole with no link followed (`read_regular_bytes`). A file
    that is present but cannot be read is that part's fault."""
    parts: dict[str, bytes | None] = {}
    faults: list[str] = []
    for part, name in PART_FILES.items():
        try:
            parts[part] = read_regular_bytes(Path(folder) / name)
        except FileNotFoundError:
            parts[part] = None
        except OSError as e:
            parts[part] = None
            faults.append(f"{locator.part(system, part)}: cannot be read ({e.strerror or type(e).__name__})")  # type: ignore[arg-type]
    read = folder_of_bytes(system, config=parts["settings"], access=parts["access"], locator=locator)
    return dataclasses.replace(read, faults=(*faults, *read.faults))


def config_text(settings: Mapping[str, str]) -> str:
    """`config.env` text holding `settings` (`KEY="value"` lines, sorted), which `folder_of_bytes` reads back as is."""
    return "".join(f'{key}="{value}"\n' for key, value in sorted(settings.items()))


def _text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


__all__ = ["SystemFolder", "config_text", "folder_of_bytes", "read_folder"]
