"""The owned box image's name, derived from the tree it is built from.

Stdlib-only with no package-relative import: `defender/scripts/box_image.py` also loads this
file by path on a bare CI `python3` with no venv.

The name hashes only the parts of `box.Dockerfile`, `uv.lock` and `pyproject.toml` the image is
built from: the Dockerfile's bytes, `[tool.uv]`, the core + `box` requirement strings, and the
lock's `box_closure`. Edits the image cannot see (lint config, other extras, lock reformatting)
keep the name; an unlocked requirement edit renames it so `uv sync --locked` can refuse it. The
closure is a superset, so some relocks rename an unchanged image: an extra rebuild, never a
stale image.

No file is read at import time.
"""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any
from defender._io import read_bytes_capped

#: Bumped whenever the recipe (what the inputs mean, not their bytes) changes. Prefixes every
#: name, so a mounted tree's own, possibly different, `_image.py` cannot collide with ours.
RECIPE_VERSION = "v2"

#: The files the image name depends on, in read order (which decides the first file a
#: "cannot read" fault names).
HASH_INPUTS: tuple[str, ...] = ("box.Dockerfile", "uv.lock", "pyproject.toml")

#: The optional-dependency set the image installs beside the core (`box.Dockerfile`'s
#: `--extra box`).
BOX_EXTRA = "box"


class ImageInputError(Exception):
    """One of `HASH_INPUTS` could not be read ("cannot read") or could not be parsed, checked
    or digested ("cannot use")."""

    def __init__(self, tree: Path, name: str, reason: BaseException | str, *, unreadable: bool = False) -> None:
        self.tree = tree
        self.name = name
        self.reason = reason
        super().__init__(f"{tree}: cannot {'read' if unreadable else 'use'} {name}: {reason}")


class MissingLockEntry(KeyError):
    """`box_closure` met a name — the root, or a link's target — the lock has no entry for."""


def normalized_name(name: str) -> str:
    """A package name as uv writes it into `uv.lock` (PEP 503: lowercase, each run of `-`, `_`,
    `.` one `-`), so `[project].name = "Defender_Agent"` finds its `defender-agent` entry."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _root_links(root: dict[str, Any]) -> list[dict[str, Any]]:
    """The links the image is built from: the root's core dependencies plus its `box` extra."""
    return [*root.get("dependencies", []), *root.get("optional-dependencies", {}).get(BOX_EXTRA, [])]


def _entry_links(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Every link a reached entry carries — its dependencies AND every optional set, requested
    or not."""
    return [*entry.get("dependencies", []), *(
        link for links in entry.get("optional-dependencies", {}).values() for link in links
    )]


def box_closure(lock: dict[str, Any], root_name: str) -> list[dict[str, Any]]:
    """@owns the image's package set, as the lock records it — every `[[package]]` entry
    reachable from the root's core dependencies plus its `box` extra, in lock order.

    Reads only each link's target `name`; `extra`, `marker`, `version` and `source` are never
    interpreted, so they cannot be misinterpreted. Every optional set of a reached entry is
    followed, making this a superset of any build (an extra rename at worst, never a missed
    one). Raises `MissingLockEntry` for a name the lock does not carry."""
    root_name = normalized_name(root_name)
    by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in lock.get("package", []):
        by_name.setdefault(entry["name"], []).append(entry)
    if root_name not in by_name:
        raise MissingLockEntry(root_name)
    stack = [link["name"] for root in by_name[root_name] for link in _root_links(root)]
    walked: set[str] = set()
    reached: set[int] = set()
    while stack:
        name = stack.pop()
        if name in walked:
            continue
        walked.add(name)
        if name not in by_name:
            raise MissingLockEntry(name)
        for entry in by_name[name]:
            reached.add(id(entry))
            stack.extend(link["name"] for link in _entry_links(entry))
    return [entry for entry in lock.get("package", []) if id(entry) in reached]


def _read(tree: Path, name: str) -> bytes:
    try:
        return read_bytes_capped(tree / name)
    except OSError as e:
        raise ImageInputError(tree, name, e, unreadable=True) from e


def _is_links(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(link, dict) and isinstance(link.get("name"), str) for link in value
    )


def _lock_packages(tree: Path, data: bytes) -> list[dict[str, Any]]:
    """`uv.lock`'s `[[package]]` entries, checked only for the shape the walk reads."""
    packages = tomllib.loads(data.decode("utf-8")).get("package", [])
    if not isinstance(packages, list):
        raise ImageInputError(tree, "uv.lock", "`package` is not a list of tables")
    for entry in packages:
        if not (isinstance(entry, dict) and isinstance(entry.get("name"), str)):
            raise ImageInputError(tree, "uv.lock", "a package entry is not a table with a string name")
        optional = entry.get("optional-dependencies", {})
        if not (_is_links(entry.get("dependencies", []))
                and isinstance(optional, dict) and all(_is_links(v) for v in optional.values())):
            raise ImageInputError(
                tree, "uv.lock", f"{entry['name']!r}: a dependency link is not a table with a string name"
            )
    return packages


def _is_strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _project_parts(tree: Path, data: bytes) -> tuple[str, dict[str, Any], dict[str, list[str]]]:
    """From `pyproject.toml`: the root's name (normalised as the lock spells it), `[tool.uv]`
    (absent → empty), and the core + `box` requirement strings as written (absent → [])."""
    doc = tomllib.loads(data.decode("utf-8"))
    project, uv = doc.get("project", {}), doc.get("tool", {}).get("uv", {})
    name = project.get("name")
    requirements = {
        "dependencies": project.get("dependencies", []),
        BOX_EXTRA: project.get("optional-dependencies", {}).get(BOX_EXTRA, []),
    }
    if not isinstance(name, str) or not isinstance(uv, dict):
        raise ImageInputError(tree, "pyproject.toml", "no [project] name, or [tool.uv] is not a table")
    if not all(_is_strings(r) for r in requirements.values()):
        raise ImageInputError(tree, "pyproject.toml", "a core or box requirement list is not a list of strings")
    return normalized_name(name), uv, requirements


def _encode(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _order_free(value: Any) -> Any:
    """`value` with every list sorted canonically: list order never changes what a sync
    installs, so it must not change the name."""
    if isinstance(value, dict):
        return {k: _order_free(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_order_free(v) for v in value), key=_encode)
    return value


def image_tag(tree: Path) -> str:
    """`defender-box:<RECIPE_VERSION>-<12 hex>` — a sha256 over the Dockerfile's bytes,
    `[tool.uv]` (keys sorted, lists as written) and, in order-free canonical form, the core +
    `box` requirement strings, the root's core + `box` links and `box_closure`'s entries.

    Every input is read before any is parsed. After the reads, any failure is the input's
    fault and raises `ImageInputError` naming the file being processed."""
    tree = Path(tree)
    data = {name: _read(tree, name) for name in HASH_INPUTS}
    at = "uv.lock"
    try:
        packages = _lock_packages(tree, data["uv.lock"])
        at = "pyproject.toml"
        root_name, tool_uv, requirements = _project_parts(tree, data["pyproject.toml"])
        at = "uv.lock"
        closure = box_closure({"package": packages}, root_name)
        roots = [_root_links(entry) for entry in packages if entry["name"] == root_name]
        at = "pyproject.toml"
        # `[tool.uv]` keeps its list order: `[[tool.uv.index]]` order is index priority.
        parts: list[tuple[str, bytes]] = [
            ("box.Dockerfile", data["box.Dockerfile"]),
            ("tool.uv", _encode(tool_uv).encode("ascii")),
            ("requirements", _encode(_order_free(requirements)).encode("ascii")),
        ]
        at = "uv.lock"
        parts += [
            ("roots", _encode(_order_free(roots)).encode("ascii")),
            ("closure", _encode(_order_free(closure)).encode("ascii")),
        ]
    except ImageInputError:
        raise
    except MissingLockEntry as e:
        raise ImageInputError(tree, "uv.lock", f"no package entry for {e.args[0]!r}") from e
    except Exception as e:  # noqa: BLE001 — every failure after the reads is the input's

        raise ImageInputError(tree, at, f"{type(e).__name__}: {e}") from e
    digest = hashlib.sha256()
    for label, part in parts:
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(part)
        digest.update(b"\0")
    return f"defender-box:{RECIPE_VERSION}-{digest.hexdigest()[:12]}"
