"""The owned box image's NAME, derived from the tree it is built from (#1092 M3, #1097).

STDLIB-ONLY, and no package-relative import: this module is loaded two ways — the normal
package door (`defender.runtime.box`, now free to pull pydantic — #1092 O2) and BY FILE PATH
from `defender/scripts/box_image.py`, which runs on a bare CI runner `python3` with no uv and
no venv on it. A relative import would make the second door unusable.

The name is a function of three files under the tree — `box.Dockerfile`, `uv.lock`,
`pyproject.toml`, read in that order (the order also decides which file a "cannot read" fault
names first) — but of only the parts of them the image is built from (#1097): the
Dockerfile's bytes, `pyproject.toml`'s `[tool.uv]`, and the lock's entries for the core
dependencies plus the `box` extra. An edit the image cannot see — lint config, the `dev` or
`runtime` extras and their lock entries, a comment, uv rewriting the lock's layout — keeps the
name, so already-built images stay valid; any edit to what the image installs names a new one.
Same name therefore means the same closure under the same recipe, not the same manifest bytes.

Nothing here reads any file at import time — only `image_tag` touches disk, and only when
called.
"""
from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

#: Bumped whenever the RECIPE (the meaning of the input files, not their bytes) changes in a
#: way the hash alone would not capture — e.g. the resolver starts reading another file.
#: Prefixes every name, so a mounted tree's own (possibly foreign) `_image.py` can never be
#: mistaken for the running package's (MF3). v2 (#1097): the lock's box closure, not its bytes.
RECIPE_VERSION = "v2"

#: The files the image name is a function of, IN THE ORDER the resolver reads them.
HASH_INPUTS: tuple[str, ...] = ("box.Dockerfile", "uv.lock", "pyproject.toml")

#: The optional-dependency set the image installs beside the core (`box.Dockerfile`'s
#: `--extra box`).
BOX_EXTRA = "box"


class ImageInputError(Exception):
    """One of `HASH_INPUTS` could not be read under `tree` — missing, a directory in its
    place, any other `OSError` — or could not be understood (not TOML, no root entry, an edge
    to a package the lock does not carry). Carries enough to build an operator-facing message
    without importing anything outside the stdlib."""

    def __init__(self, tree: Path, name: str, reason: BaseException | str) -> None:
        self.tree = tree
        self.name = name
        self.reason = reason
        super().__init__(f"{tree}: cannot read {name}: {reason}")


def _edges(entry: dict[str, Any], extras: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """An entry's dependency edges, plus those of each of its optional sets in `extras`."""
    out = list(entry.get("dependencies", []))
    for extra in extras:
        out += entry.get("optional-dependencies", {}).get(extra, [])
    return out


def box_closure(lock: dict[str, Any], root_name: str) -> list[dict[str, Any]]:
    """@owns the image's package set, as the lock records it — every `[[package]]` entry
    reachable from `root_name`'s core dependencies plus its `box` extra, whole.

    Each edge is followed BY NAME to every entry of that name, and markers are ignored: a
    lock that splits one package across versions or platforms contributes all of its entries.
    That is a superset of what any one build installs, so it can cost an extra rename but can
    never miss one — and it needs no marker evaluation, which the stdlib cannot do. An edge's
    `extra = [...]` also pulls in the target's matching optional dependencies.

    Raises `KeyError` naming the missing package when the root or an edge's target has no
    entry. The order of the result is the lock's."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in lock.get("package", []):
        by_name.setdefault(entry["name"], []).append(entry)
    if root_name not in by_name:
        raise KeyError(root_name)
    stack = [
        (edge["name"], tuple(edge.get("extra", ())))
        for root in by_name[root_name]
        for edge in _edges(root, (BOX_EXTRA,))
    ]
    seen: set[tuple[str, tuple[str, ...]]] = set()
    reached: set[int] = set()
    while stack:
        name, extras = stack.pop()
        if (name, extras) in seen:
            continue
        seen.add((name, extras))
        if name not in by_name:
            raise KeyError(name)
        for entry in by_name[name]:
            reached.add(id(entry))
            stack.extend((e["name"], tuple(e.get("extra", ()))) for e in _edges(entry, extras))
    return [entry for entry in lock.get("package", []) if id(entry) in reached]


def _read(tree: Path, name: str) -> bytes:
    try:
        return (tree / name).read_bytes()
    except OSError as e:
        raise ImageInputError(tree, name, e) from e


def _loads_input(tree: Path, name: str, data: bytes) -> Any:
    """One input's TOML, unchecked — each reader below narrows the part it uses."""
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ImageInputError(tree, name, e) from e


def _lock_packages(tree: Path, data: bytes) -> list[dict[str, Any]]:
    """`uv.lock`'s `[[package]]` entries, each checked to be a table with a string `name` —
    the one shape `box_closure` relies on."""
    doc = _loads_input(tree, "uv.lock", data)
    packages = doc.get("package", []) if isinstance(doc, dict) else None
    if not isinstance(packages, list) or not all(
        isinstance(p, dict) and isinstance(p.get("name"), str) for p in packages
    ):
        raise ImageInputError(tree, "uv.lock", "`package` is not a list of named tables")
    return packages


def _project_root_and_uv(tree: Path, data: bytes) -> tuple[str, dict[str, Any]]:
    """`pyproject.toml`'s `[project].name` (the lock's root entry) and its `[tool.uv]` table
    (absent → empty)."""
    doc = _loads_input(tree, "pyproject.toml", data)
    project, tool = (doc.get("project", {}), doc.get("tool", {})) if isinstance(doc, dict) else (None, None)
    name = project.get("name") if isinstance(project, dict) else None
    uv = tool.get("uv", {}) if isinstance(tool, dict) else None
    if not isinstance(name, str) or not isinstance(uv, dict):
        raise ImageInputError(tree, "pyproject.toml", "no [project] name, or [tool.uv] is not a table")
    return name, uv


def _digest_form(value: Any) -> bytes:
    """One byte string per value, whatever order the TOML wrote its keys in."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("ascii")


def image_tag(tree: Path) -> str:
    """`defender-box:<RECIPE_VERSION>-<12 hex>` — a sha256 over the Dockerfile's bytes,
    `[tool.uv]`, the root's core + `box` edges and `box_closure`'s entries, the last three in
    canonical form. Every input is read before any is parsed, so a fault names the FIRST
    unreadable file; a file that reads but cannot be understood raises `ImageInputError`
    naming it. Never hashes a tree it could not fully read and understand."""
    tree = Path(tree)
    dockerfile, lock_bytes, pyproject_bytes = (_read(tree, name) for name in HASH_INPUTS)
    packages = _lock_packages(tree, lock_bytes)
    root_name, tool_uv = _project_root_and_uv(tree, pyproject_bytes)
    try:
        closure = box_closure({"package": packages}, root_name)
    except KeyError as e:
        raise ImageInputError(tree, "uv.lock", f"no package entry for {e.args[0]!r}") from e
    roots = [
        {"dependencies": entry.get("dependencies", []),
         BOX_EXTRA: entry.get("optional-dependencies", {}).get(BOX_EXTRA, [])}
        for entry in packages if entry["name"] == root_name
    ]
    digest = hashlib.sha256()
    for label, part in (
        ("box.Dockerfile", dockerfile),
        ("tool.uv", _digest_form(tool_uv)),
        ("roots", _digest_form(roots)),
        ("closure", _digest_form(sorted(_digest_form(e).decode("ascii") for e in closure))),
    ):
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(part)
        digest.update(b"\0")
    return f"defender-box:{RECIPE_VERSION}-{digest.hexdigest()[:12]}"
