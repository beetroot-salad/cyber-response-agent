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
import re
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
    place, any other `OSError` ("cannot read") — or was read but cannot be used: not TOML, not
    the shape the walk reads, no root entry, a link to a package the lock does not carry, a
    value too deep to encode ("cannot use"). Carries enough to build an operator-facing message
    without importing anything outside the stdlib."""

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
    reachable from `root_name`'s core dependencies plus its `box` extra, whole.

    Reads ONE thing from the lock: the `name` each link points at (#1097, amendment 2). A link's
    `extra`, `marker`, `version` and `source` are never interpreted — so they can never be
    MISinterpreted. From each reached entry the walk follows its dependencies and every list
    under its `optional-dependencies`, whether or not anything asks for that extra, and a name
    reaches every entry of that name (a split package contributes all of them). That is a
    superset of what any build installs: an extra rename at worst, never a missed one. The
    recipe's sync is fenced to the same set (`--no-install-project --no-default-groups`), so
    nothing it can install lies outside what this walk reads.

    Raises `MissingLockEntry` naming the root or a link target the lock does not carry. The
    root itself is never in the result. The order of the result is the lock's."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in lock.get("package", []):
        by_name.setdefault(entry["name"], []).append(entry)
    if root_name not in by_name:
        raise MissingLockEntry(root_name)
    stack = [link["name"] for root in by_name[root_name] for link in _root_links(root)]
    # The root is never expanded as an ordinary entry, even if some package links back to it:
    # its other optional lists are the dev and runtime extras, which the image never installs.
    walked: set[str] = {root_name}
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
        return (tree / name).read_bytes()
    except OSError as e:
        raise ImageInputError(tree, name, e, unreadable=True) from e


def _loads_input(tree: Path, name: str, data: bytes) -> Any:
    """One input's TOML, unchecked — each reader below narrows the part it uses."""
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as e:
        raise ImageInputError(tree, name, e) from e


def _is_links(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(link, dict) and isinstance(link.get("name"), str) for link in value
    )


def _lock_packages(tree: Path, data: bytes) -> list[dict[str, Any]]:
    """`uv.lock`'s `[[package]]` entries, checked for the one shape the walk reads: each a table
    with a string `name`, whose `dependencies` is a list of links (tables with a string
    `name`) and whose `optional-dependencies` is a table of such lists. Nothing else in an
    entry is read, so nothing else is checked."""
    doc = _loads_input(tree, "uv.lock", data)
    packages = doc.get("package", []) if isinstance(doc, dict) else None
    if not isinstance(packages, list):
        raise ImageInputError(tree, "uv.lock", "`package` is not a list of tables")
    for entry in packages:
        if not (isinstance(entry, dict) and isinstance(entry.get("name"), str)):
            raise ImageInputError(tree, "uv.lock", f"a package entry has no string name: {entry!r:.80}")
        optional = entry.get("optional-dependencies", {})
        if not (_is_links(entry.get("dependencies", []))
                and isinstance(optional, dict) and all(_is_links(v) for v in optional.values())):
            raise ImageInputError(
                tree, "uv.lock", f"{entry['name']!r}: a dependency link is not a table with a string name"
            )
    return packages


def _project_root_and_uv(tree: Path, data: bytes) -> tuple[str, dict[str, Any]]:
    """`pyproject.toml`'s `[project].name`, normalised as uv writes it (the lock's root entry),
    and its `[tool.uv]` table (absent → empty)."""
    doc = _loads_input(tree, "pyproject.toml", data)
    project, tool = (doc.get("project", {}), doc.get("tool", {})) if isinstance(doc, dict) else (None, None)
    name = project.get("name") if isinstance(project, dict) else None
    uv = tool.get("uv", {}) if isinstance(tool, dict) else None
    if not isinstance(name, str) or not isinstance(uv, dict):
        raise ImageInputError(tree, "pyproject.toml", "no [project] name, or [tool.uv] is not a table")
    return normalized_name(name), uv


def _digest_form(tree: Path, name: str, value: Any) -> bytes:
    """One byte string per value, whatever order the TOML wrote its keys in; a value too deep
    to encode is a fault in the file it came from, never a crash."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str,
        ).encode("ascii")
    except (RecursionError, ValueError) as e:
        raise ImageInputError(tree, name, f"a value cannot be encoded: {e}") from e


def image_tag(tree: Path) -> str:
    """`defender-box:<RECIPE_VERSION>-<12 hex>` — a sha256 over the Dockerfile's bytes,
    `[tool.uv]`, the root's core + `box` links and `box_closure`'s entries, the last three in
    canonical form. Every input is read before any is parsed, so a fault names the FIRST
    unreadable file; a file that reads but cannot be used raises `ImageInputError` naming it.
    Never hashes a tree it could not fully read and understand."""
    tree = Path(tree)
    data = {name: _read(tree, name) for name in HASH_INPUTS}
    packages = _lock_packages(tree, data["uv.lock"])
    root_name, tool_uv = _project_root_and_uv(tree, data["pyproject.toml"])
    try:
        closure = box_closure({"package": packages}, root_name)
    except MissingLockEntry as e:
        raise ImageInputError(tree, "uv.lock", f"no package entry for {e.args[0]!r}") from e
    roots = [_root_links(entry) for entry in packages if entry["name"] == root_name]
    closure_forms = sorted(_digest_form(tree, "uv.lock", e).decode("ascii") for e in closure)
    digest = hashlib.sha256()
    for label, part in (
        ("box.Dockerfile", data["box.Dockerfile"]),
        ("tool.uv", _digest_form(tree, "pyproject.toml", tool_uv)),
        ("roots", _digest_form(tree, "uv.lock", roots)),
        ("closure", _digest_form(tree, "uv.lock", closure_forms)),
    ):
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(part)
        digest.update(b"\0")
    return f"defender-box:{RECIPE_VERSION}-{digest.hexdigest()[:12]}"
