"""An adapter's base files (#1471 P-8, P-9): the product content a carried adapter ships for the tenant's `agent/` (its
per-system skill, its seed query templates), rendered under a system's name and named by a digest of the rendering.

Pure functions, shared by the adoption helper, the adoption job and the CI test that runs connect's scaffold validator over
every shipped set. The API may load them: nothing here reaches run code.

The folder (`CatalogEntry.base_files`, the adapter's `BASE_FILES`) mirrors the tenant's `agent/` root with a literal
`{system}` path segment, e.g. `skills/{system}/SKILL.md`. `render` places each file at `agent/<path>` and fills the
system's name into the folder names and into the content, and fills nothing else (P-8)."""
from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

from defender._io import read_bytes_capped
from defender.system_rules.catalog import CatalogEntry

#: The one placeholder; it is filled in paths and content, never anything else.
SYSTEM_PLACEHOLDER = "{system}"
#: Where a rendered path starts: the tenant repository's agent root.
AGENT_ROOT = "agent"
#: P-9's length frame: 4-byte big-endian unsigned (the repository's `">I"` framing). Changing it renames every branch.
_LENGTH = struct.Struct(">I")


def render(entry: CatalogEntry, system: str) -> dict[str, bytes]:
    """`{agent/<path>: bytes}` for every file of `entry`'s base files, with `system` filled into each path and each file's
    bytes (unfiltered: no newline translation, no decoding). A folder holding anything but regular files and directories, or
    an entry shipping none, raises `ValueError`; so does a system name that is not one safe path segment."""
    if entry.base_files is None:
        raise ValueError(f"adapter {entry.adapter_id!r} ships no base files")
    if not system or system in {".", ".."} or any(c in system for c in "/\\\0{}"):
        raise ValueError(f"{system!r} is not a system name that can stand as one path segment")
    root = Path(entry.base_files)
    name = system.encode("utf-8")
    placeholder = SYSTEM_PLACEHOLDER.encode("utf-8")
    rendered: dict[str, bytes] = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for filename in sorted(files):
            path = Path(folder) / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"{path} is not a regular file: base files are plain files only")
            relative = path.relative_to(root).as_posix().replace(SYSTEM_PLACEHOLDER, system)
            rendered[f"{AGENT_ROOT}/{relative}"] = read_bytes_capped(path).replace(placeholder, name)
        for sub in dirs:
            if (Path(folder) / sub).is_symlink():
                raise ValueError(f"{Path(folder) / sub} is a link: base files are plain files only")
    return rendered


def digest(rendering: dict[str, bytes]) -> str:  # lint-dup: ok — P-9 names it; the other `digest` is the learning store key digest, a different rule
    """SHA-256, lowercase hex, over the concatenation, for each rendered path (the `render()` key, `agent/` included) in
    order of its UTF-8 bytes, of a 4-byte big-endian length, the path's UTF-8 bytes, a 4-byte big-endian length and the
    content bytes. No file count, separator or terminator (P-9)."""
    hasher = hashlib.sha256()
    for path, content in sorted((p.encode("utf-8"), c) for p, c in rendering.items()):
        hasher.update(_LENGTH.pack(len(path)))
        hasher.update(path)
        hasher.update(_LENGTH.pack(len(content)))
        hasher.update(content)
    return hasher.hexdigest()


def branch_of(system: str, digest: str) -> str:
    """The branch an offer is named by: `adopt/<system>/<first 16 hex of the digest>` (P-9)."""
    return f"adopt/{system}/{digest[:16]}"
