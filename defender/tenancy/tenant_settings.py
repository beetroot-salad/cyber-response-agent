"""#1107 — the settings half of a run's tenant record: what each system's `config.env` says, parsed
ONCE at resolve."""
from __future__ import annotations

import errno
import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from defender._io import is_plain_entry
from defender.kit.faults import ConfigFault
from defender.kit.settings import NOT_CONFIGURED, SystemConfig, config_pointer, pointer_to

_log = logging.getLogger(__name__)

#: A settings file larger than this is not a settings file. Every one is read whole at resolve,
#: so an unbounded read would let one sparse file exhaust memory before any fault could be kept
#: as a value.
SETTINGS_MAX_BYTES = 1 << 20

#: A line ends at CRLF, CR or LF — exactly the endings a universal-newline read (the connect
#: validator's `read_plain`) recognises, and no others (`str.splitlines` would also split on a
#: form feed or a vertical tab inside a value).
_LINE_END = re.compile(r"\r\n|\r|\n")


# --------------------------------------------------------------------------------------------
# The one parser.
# --------------------------------------------------------------------------------------------

def parse_env(text: str) -> dict[str, str]:
    """`KEY=VALUE` lines of a `config.env`, as written. @owns config.env parse"""
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


# --------------------------------------------------------------------------------------------
# The record's parts.
# --------------------------------------------------------------------------------------------

def read_systems(settings: Path) -> Mapping[str, SystemConfig | ConfigFault]:
    """One entry per non-hidden folder under `settings/systems/`, keyed by its exact name: the
    `SystemConfig` of its `config.env`, or the `ConfigFault` for why there is none. Never
    raises: a `systems/` folder that cannot be listed is warned and configures no system, and a
    system folder that cannot be examined is that system's `ConfigFault`. @owns systems"""
    systems_dir = Path(settings) / "systems"
    out: dict[str, SystemConfig | ConfigFault] = {}
    try:
        folders = sorted(systems_dir.iterdir()) if systems_dir.is_dir() else []
    except OSError as e:
        _log.warning("%s cannot be listed (%s), so this tenant configures no system",
                     pointer_to("systems/"), e.strerror or type(e).__name__)
        folders = []
    for folder in folders:
        if folder.name.startswith("."):
            continue
        try:
            is_folder = folder.is_dir()
        except OSError as e:
            out[folder.name] = ConfigFault(
                f"{pointer_to(f'systems/{folder.name}/')} cannot be examined: "
                f"{e.strerror or type(e).__name__}")
            continue
        if is_folder:
            try:
                out[folder.name] = SystemConfig(
                    read_env_file(folder / "config.env", shown=config_pointer(folder.name)))
            except ConfigFault as fault:
                # A fresh instance, never the caught one: the caught fault's traceback holds this
                # frame (and `out`, the live dict behind the read-only view) and its cause holds
                # the OSError with the host path. The record keeps the text only.
                out[folder.name] = ConfigFault(str(fault))
    return MappingProxyType(out)


__all__ = [
    "SETTINGS_MAX_BYTES",
    "assignments",
    "parse_env",
    "read_env_file",
    "read_plain_fd",
    "read_regular_bytes",
    "read_systems",
]
