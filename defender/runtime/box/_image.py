"""The owned box image's NAME, derived from the tree it is built from (#1092 M3, #1097).

STDLIB-ONLY, and no package-relative import: this module is loaded two ways — the normal
package door (`defender.runtime.box`, now free to pull pydantic — #1092 O2) and BY FILE PATH
from `defender/scripts/box_image.py`, which runs on a bare CI runner `python3` with no uv and
no venv on it. A relative import would make the second door unusable.

The name is a function of three files under the tree — `box.Dockerfile`, `uv.lock`,
`pyproject.toml`, read in that order (the order also decides which file a "cannot read" fault
names first) — but of only the parts of them the image is built from (#1097): the
Dockerfile's bytes, `pyproject.toml`'s `[tool.uv]` and its core + `box` requirement strings,
and the lock's entries for the core dependencies plus the `box` extra (`box_closure`). An edit
the image cannot see — lint config, the `dev`/`runtime` requirement lists, a comment, uv
reordering or reformatting the lock — keeps the name, so already-built images stay valid; any
edit to what the image installs names a new one, and so does an unlocked edit to the core or
`box` requirements (so the build's `uv sync --locked` gets the chance to refuse it loudly).
Same name therefore means the same closure under the same recipe, not the same manifest bytes.

The closure is deliberately a SUPERSET (see `box_closure`), which couples the name to the
runtime stack in one direction: a relock that moves a package the runtime shares with the
closure (`idna`, via pydantic's `email` extra), or that changes which extras of a closure
package the runtime asks for, renames the image though its contents are unchanged. That is an
extra rebuild, never a stale image.

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
    place, any other `OSError` ("cannot read") — or was read but cannot be used: anything that
    goes wrong while parsing, checking, walking or digesting it ("cannot use"). Carries enough
    to build an operator-facing message without importing anything outside the stdlib."""

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
    reachable from the root's core dependencies plus its `box` extra, whole. `root_name` is
    normalised as uv writes names, so a `[project].name` can be passed as spelled.

    Reads ONE thing from the lock: the `name` each link points at (#1097, amendment 2). A link's
    `extra`, `marker`, `version` and `source` are never interpreted — so they can never be
    MISinterpreted. From each reached entry the walk follows its dependencies and every list
    under its `optional-dependencies`, whether or not anything asks for that extra, and a name
    reaches every entry of that name (a split package contributes all of them). The root is no
    exception once a link reaches it: it is walked and returned like any entry. That is a
    superset of what any build installs: an extra rename at worst, never a missed one. The
    recipe's sync is fenced to the same set (`--no-install-project --no-default-groups`), so
    nothing it can install lies outside what this walk reads.

    Raises `MissingLockEntry` naming the root or a link target the lock does not carry. The
    order of the result is the lock's."""
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
        return (tree / name).read_bytes()
    except OSError as e:
        raise ImageInputError(tree, name, e, unreadable=True) from e


def _is_links(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(link, dict) and isinstance(link.get("name"), str) for link in value
    )


def _lock_packages(tree: Path, data: bytes) -> list[dict[str, Any]]:
    """`uv.lock`'s `[[package]]` entries, checked for the one shape the walk reads: each a table
    with a string `name`, whose `dependencies` is a list of links (tables with a string
    `name`) and whose `optional-dependencies` is a table of such lists. Nothing else in an
    entry is read, so nothing else is checked."""
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
    """`value` with every list sorted by its members' canonical encoding (and dict keys by
    `_encode`'s `sort_keys`): the lock's lists and the requirement lists never decide what a
    sync installs by their order, so their order never decides the name either."""
    if isinstance(value, dict):
        return {k: _order_free(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_order_free(v) for v in value), key=_encode)
    return value


def image_tag(tree: Path) -> str:
    """`defender-box:<RECIPE_VERSION>-<12 hex>` — a sha256 over the Dockerfile's bytes,
    `[tool.uv]` (keys sorted, lists as written) and, in order-free canonical form, the core +
    `box` requirement strings, the root's core + `box` links and `box_closure`'s entries.

    Every input is read before any is parsed, so a missing file is named first ("cannot
    read"). Everything after the reads is one pure computation over those bytes, so ANY
    failure in it — bad TOML, the wrong shape, a missing entry, a value nothing can encode —
    is the input's fault: it raises `ImageInputError` naming the file being processed ("cannot
    use"). Never hashes a tree it could not fully read and understand."""
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
        # `[tool.uv]` keeps its written list order: `[[tool.uv.index]]` order is index
        # priority, so there a reordering IS a change to what the sync resolves.
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
    except Exception as e:  # noqa: BLE001 — see the docstring: every failure here is the input's
        raise ImageInputError(tree, at, f"{type(e).__name__}: {e}") from e
    digest = hashlib.sha256()
    for label, part in parts:
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(part)
        digest.update(b"\0")
    return f"defender-box:{RECIPE_VERSION}-{digest.hexdigest()[:12]}"
