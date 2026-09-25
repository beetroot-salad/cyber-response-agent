"""#1097 (design amendment) — the owned image is named from the lock's core + `box` closure.

The name is `defender-box:v2-<12 hex>` over: the bytes of `box.Dockerfile`; `[tool.uv]` from
`pyproject.toml` (absent -> `{}`); the root lock entry's `dependencies` + `optional-
dependencies.box` (the root is the lock package `[project].name` names); and every lock
`[[package]]` entry reachable from those edges — `runtime/box/_image.py::box_closure` — each a
whole parsed dict, canonically digested.

Design amendment 2 (M1″): the walk reads ONE thing from the lock, each dependency link's
`name`. From the root it takes the links in `dependencies` + `optional-dependencies.box`; from
every entry it reaches, the links in `dependencies` AND in EVERY list under
`optional-dependencies`, whether or not any link asks for that extra. A link reaches EVERY
entry with its name; its `extra`, `marker`, `version` and `source` are never interpreted (the
superset rule: at most an extra rename, never a missed one). The root is found by
`[project].name` normalised as uv writes names (PEP 503). A lock or manifest the walk cannot
use — a malformed entry or link, a value the canonical form cannot encode — is
`ImageInputError` naming the file and saying "cannot use"; an unreadable file says "cannot
read".

Design amendment 3 (M1‴): the digest also covers `pyproject.toml`'s `[project].dependencies`
and `[project].optional-dependencies.box` AS WRITTEN (lists of requirement strings; absent ->
`[]`; anything else is `ImageInputError` naming `pyproject.toml`), so a core or `box`
requirement edited without a relock renames the image and the build's `--locked` sync fails
loudly (the `dev`/`runtime` lists stay out). Everything after the three reads — parse, shape
check, walk, digest — is ONE fault boundary: any exception there is `ImageInputError`
("cannot use") naming the file being processed. Every list inside a hashed value is sorted by
its canonical encoding, so no list ORDER renames. And the root is not special once reached: a
link that reaches the root entry walks and hashes it like any other entry, all its optional
lists included. `box_closure` normalises the `root_name` it is given (PEP 503).

O1: an edit that cannot change the image does not rename it — `[tool.*]` other than
`[tool.uv]`, the root's `dev`/`runtime` extras and their lock entries, comments, reordering
and reformatting the lock, reordering any list in a hashed value. O2: an edit to a closure
entry (version, source, an artifact hash, its own links and optional lists), to an entry
reached only through a closure entry's unrequested extra, to the closure's roots, to the core
or `box` requirement strings, to `[tool.uv]`, or to the recipe's bytes renames it.

Real inputs through the real primitive: every tree is planted from well-formed TOML text
(`_spec1092.PLANTED_LOCK`, or a copy of THIS checkout's `uv.lock`/`pyproject.toml`) and the
resolver parses the bytes itself. The synthetic lock is edited as parsed data and written back
through `_lock_toml` below, whose every output is re-parsed and checked against the data it was
asked to write — so an edit is exactly the edit named, and a reformatted lock is exactly the
same lock. Each negative carries its positive control in the same test.
"""
from __future__ import annotations

import copy
import json
import re
import shutil
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest

from defender.tests._spec1092 import (
    DEFENDER,
    HASH_INPUTS,
    PLANTED_INPUT_BYTES,
    PLANTED_LOCK,
    PLANTED_PYPROJECT,
    TAG_RE,
    box_closure,
    image_module,
    image_tag,
    plant_tree,
)

#: The planted lock as the resolver will parse it.
BASE_LOCK: dict = tomllib.loads(PLANTED_LOCK)
ROOT = "planted"

#: Two `[[tool.uv.index]]` tables in a given order — index priority is their order.
_INDEXES = (
    '\n[[tool.uv.index]]\nname = "{first}"\nurl = "https://{first}.example/simple"\n'
    '\n[[tool.uv.index]]\nname = "{second}"\nurl = "https://{second}.example/simple"\n'
)

#: The planted closure (see `_spec1092.PLANTED_LOCK`): both `split` entries, the marker-gated
#: `winonly`, the optional lists' targets `eta` (beta's `speed`) and `delta` (gamma's `fast`),
#: and `epsilon` — the target of beta's `docs` and gamma's `slow`, extras NO link asks for
#: (amendment 2: every optional list of a reached entry is walked).
PLANTED_CLOSURE = sorted([
    ("alpha", "1.0.0"), ("beta", "2.0.0"), ("delta", "4.0.0"), ("epsilon", "5.0.0"),
    ("eta", "6.0.0"), ("gamma", "3.0.0"), ("split", "1.0.0"), ("split", "2.0.0"),
    ("winonly", "9.0.0"),
])
#: In the planted lock and outside the closure: devtool/devdep are the ROOT's `dev` extra's,
#: rtlib is its `runtime` extra's — of the root's optional lists only `box` is walked FROM the
#: root; nothing in the planted lock links back to the root, so they stay out (amendment 3: a
#: link that did reach the root would walk them too).
PLANTED_OUTSIDE = ("devdep", "devtool", "rtlib")

#: This checkout's core + `box` closure today (#1097 item 2). A relock that moves it moves this
#: list — on purpose: it is the review point for what enters the boundary. The last three are
#: pydantic's `email` extra — nothing asks for it and the image does not install them, but
#: amendment 2 walks every optional list of a reached entry, so they are hashed (the superset).
REAL_CLOSURE_NAMES = sorted([
    "annotated-types", "duckdb", "pydantic", "pydantic-core", "pyyaml", "typing-extensions",
    "typing-inspection",
    "dnspython", "email-validator", "idna",
])

_REGISTRY = {"registry": "https://pypi.org/simple"}


# ---- writing a lock back out -------------------------------------------------------------------
_SUBTABLES = frozenset({"optional-dependencies", "metadata", "dev-dependencies"})


def _key(k: str) -> str:
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k, ensure_ascii=False)


def _value(v, *, multiline: bool, reverse_keys: bool) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        # A JSON string with raw non-ASCII is a valid TOML basic string (never a surrogate
        # `\\u` escape, which TOML forbids).
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        items = [_value(x, multiline=False, reverse_keys=reverse_keys) for x in v]
        if multiline and items:
            return "[\n" + "".join(f"    {item},\n" for item in items) + "]"
        return "[" + ", ".join(items) + "]"
    if isinstance(v, dict):
        keys = list(v)[::-1] if reverse_keys else list(v)
        body = ", ".join(f"{_key(k)} = {_value(v[k], multiline=False, reverse_keys=reverse_keys)}" for k in keys)
        return "{ " + body + " }"
    raise TypeError(f"no TOML spelling for {type(v).__name__}")


def _canonical(lock: dict) -> tuple[str, list[str]]:
    """A lock as order-free data: the top-level fields, and the entries as a sorted multiset."""
    top = json.dumps({k: v for k, v in lock.items() if k != "package"}, sort_keys=True)
    return top, sorted(json.dumps(p, sort_keys=True) for p in lock.get("package", []))


def _lock_toml(lock: dict, *, multiline: bool = True, reverse_keys: bool = False,
               reverse_entries: bool = False, comments: bool = False) -> str:
    """`lock` written as uv-shaped TOML (`[[package]]` tables, `[package.optional-dependencies]`
    / `[package.metadata]` subtables, inline tables for edges and artifacts). The knobs change
    only the SPELLING: one-line arrays, every table's keys in reverse, the entries in reverse,
    comment lines between them. The text is re-parsed here and must be the same lock."""
    def table(pairs: dict) -> list[str]:
        keys = list(pairs)[::-1] if reverse_keys else list(pairs)
        lines = [f"{_key(k)} = {_value(pairs[k], multiline=multiline, reverse_keys=reverse_keys)}"
                 for k in keys if not (k in _SUBTABLES and isinstance(pairs[k], dict))]
        for k in keys:
            if k in _SUBTABLES and isinstance(pairs[k], dict):
                lines += ["", f"[package.{_key(k)}]"]
                sub = pairs[k]
                sub_keys = list(sub)[::-1] if reverse_keys else list(sub)
                lines += [f"{_key(s)} = {_value(sub[s], multiline=multiline, reverse_keys=reverse_keys)}"
                          for s in sub_keys]
        return lines

    head = table({k: v for k, v in lock.items() if k != "package"})
    entries = lock["package"][::-1] if reverse_entries else lock["package"]
    sep = "\n\n# reformatted: a comment the resolver must not read\n\n" if comments else "\n\n"
    text = "\n".join(head) + "\n\n" + sep.join(
        "\n".join(["[[package]]", *table(entry)]) for entry in entries
    ) + "\n"
    assert _canonical(tomllib.loads(text)) == _canonical(lock), "the writer changed the lock"
    return text


# ---- trees and edits ---------------------------------------------------------------------------
def _plant(tmp_path: Path, label: str, *, lock: dict | None = None,
           pyproject: str = PLANTED_PYPROJECT, dockerfile: bytes | None = None) -> Path:
    """A planted defender dir whose `uv.lock` is `lock` (default: the planted lock) written by
    `_lock_toml` in uv's own layout — so two trees differ in exactly the edit between them."""
    defender_dir = plant_tree(tmp_path / label, copy_code=False)
    (defender_dir / "uv.lock").write_text(_lock_toml(BASE_LOCK if lock is None else lock), encoding="utf-8")
    (defender_dir / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    if dockerfile is not None:
        (defender_dir / "box.Dockerfile").write_bytes(dockerfile)
    return defender_dir


def _entry(lock: dict, name: str, version: str | None = None) -> dict:
    """The ONE entry of `lock` named `name` (at `version`, when the name is split)."""
    hits = [p for p in lock["package"]
            if p["name"] == name and (version is None or p["version"] == version)]
    assert len(hits) == 1, (name, version, [p.get("version") for p in hits])
    return hits[0]


def _flip_hex(digest: str) -> str:
    """`digest` with its last hex character changed — one byte of one artifact hash."""
    return digest[:-1] + ("1" if digest[-1] != "1" else "2")


def _lock_edit(fn: Callable[[dict], None]) -> dict:
    lock = copy.deepcopy(BASE_LOCK)
    fn(lock)
    return lock


def _walk_to(lock: dict, path: list):
    """The container `path[:-1]` addresses — `path[0]` names an entry, the rest index into it."""
    node = _entry(lock, path[0])
    for step in path[1:-1]:
        node = node[step]
    return node


def _set(path: list, value) -> Callable[[dict], None]:
    """An edit setting `path` (entry name, then keys/indices) to `value`."""
    return lambda lock: _walk_to(lock, path).__setitem__(path[-1], copy.deepcopy(value))


def _append(path: list, item) -> Callable[[dict], None]:
    """An edit appending `item` to the list at `path` (entry name, then keys)."""
    return lambda lock: _walk_to(lock, path)[path[-1]].append(copy.deepcopy(item))


def _reverse(path: list, version: str | None = None) -> Callable[[dict], None]:
    """An edit reversing the list at `path` (entry name — at `version`, when split — then
    keys). The list must hold two or more DIFFERENT items, or the edit would change nothing."""
    def fn(lock: dict) -> None:
        node = _entry(lock, path[0], version)
        for step in path[1:-1]:
            node = node[step]
        target = node[path[-1]]
        assert target != target[::-1], f"reversing {path} changes nothing: {target}"
        target.reverse()
    return fn


def _reverse_every_list(node) -> None:
    """Every list at every depth of `node` reversed in place — entries, links, wheels,
    resolution-markers, metadata rows, the lot."""
    if isinstance(node, dict):
        for value in node.values():
            _reverse_every_list(value)
    elif isinstance(node, list):
        node.reverse()
        for value in node:
            _reverse_every_list(value)


def _two_wheels(lock: dict) -> None:
    """`alpha` gains a second wheel (a manylinux build beside its `py3-none-any`), so its
    `wheels` list has an order to change."""
    wheel = dict(_entry(lock, "alpha")["wheels"][0])
    wheel["url"] = wheel["url"].replace("py3-none-any", "cp311-cp311-manylinux_2_17_x86_64")
    wheel["hash"] = "sha256:" + "5a" * 32
    _entry(lock, "alpha")["wheels"].append(wheel)


def _flip_artifact(name: str, artifact: str, version: str | None = None) -> Callable[[dict], None]:
    """An edit changing one byte of an entry's sdist hash, or of its first wheel's."""
    def fn(lock: dict) -> None:
        entry = _entry(lock, name, version)
        target = entry["sdist"] if artifact == "sdist" else entry["wheels"][0]
        target["hash"] = _flip_hex(target["hash"])
    return fn


def _replace_once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new)


def _names(entries: list[dict]) -> list[tuple[str, str]]:
    return sorted((e["name"], e["version"]) for e in entries)


def _every_link(lock: dict):
    """Every dependency link in `lock`: each entry's `dependencies` and every optional list."""
    for entry in lock["package"]:
        yield from entry.get("dependencies", [])
        for links in entry.get("optional-dependencies", {}).values():
            yield from links


def _strip_extras(lock: dict) -> None:
    for link in _every_link(lock):
        link.pop("extra", None)


def _foreign_extras(lock: dict) -> None:
    for link in _every_link(lock):
        if "extra" in link:
            link["extra"] = ["no-such-extra"]


# ---- box_closure: the walk ---------------------------------------------------------------------
def test_box_closure_reads_only_link_names_and_walks_every_optional_list_of_every_reached_entry():
    """`box_closure(lock, "planted")` over the planted lock returns exactly the entries
    reachable BY LINK NAME from the root's `dependencies` + `optional-dependencies.box`, each
    the lock's own parsed dict: BOTH `split` entries (a link reaches every entry with its name
    — the superset rule); `winonly`, whose link's marker no Linux build satisfies (markers are
    ignored); `eta` and `delta`, the targets of beta's `speed` and gamma's `fast` lists; and
    `epsilon`, the target of beta's `docs` and gamma's `slow` — extras NO link asks for, walked
    because every list under a reached entry's `optional-dependencies` is (amendment 2, M1″).
    FROM the root only `dependencies` + `box` are taken, and nothing in the planted lock links
    back to the root, so the `dev` and `runtime` extras' entries (devtool, devdep, rtlib) stay
    out and the root itself is not returned (a lock whose link DOES reach the root is
    `test_a_link_that_reaches_the_root_walks_and_hashes_it_like_any_entry`'s). The
    `eta -> alpha` cycle ends the walk rather than looping it.

    Nothing on a link but its `name` is read. A link's `version` does not narrow it: with the
    root's two `split` links replaced by ONE transitive link carrying `version = "1.0.0"`, both
    `split` entries are still returned. A link's `extra` neither widens nor narrows it: with
    every `extra` stripped from the lock's links, or replaced by an extra no entry declares,
    the closure is the same."""
    got = box_closure(copy.deepcopy(BASE_LOCK), ROOT)
    assert isinstance(got, list), type(got)
    assert _names(got) == PLANTED_CLOSURE, _names(got)
    for entry in got:
        assert entry in BASE_LOCK["package"], f"not the lock's own entry: {entry}"
    returned = {name for name, _ in _names(got)}
    assert "epsilon" in returned, "an unrequested extra of a reached entry was not walked"
    for outside in (*PLANTED_OUTSIDE, ROOT):
        assert outside not in returned, f"{outside} is not in the core + box closure"

    def one_versioned_link(lock: dict) -> None:
        root = _entry(lock, ROOT)
        root["dependencies"] = [d for d in root["dependencies"] if d["name"] != "split"]
        _entry(lock, "alpha")["dependencies"].append({
            "name": "split", "version": "1.0.0", "source": _REGISTRY,
            "marker": "python_full_version < '3.12'",
        })

    narrowed = _lock_edit(one_versioned_link)
    assert _names(box_closure(narrowed, ROOT)) == PLANTED_CLOSURE, "a link's version narrowed the walk"

    # Nor a link's `source`: one that matches no entry's still reaches them all (#1097
    # round-3 adversary H7 — a source filter dropped alpha's whole subtree).
    def foreign_source(lock: dict) -> None:
        _entry(lock, ROOT)["dependencies"][0]["source"] = {"registry": "https://pypi.org/simple/"}
    assert _names(box_closure(_lock_edit(foreign_source), ROOT)) == PLANTED_CLOSURE, "a link's source narrowed the walk"

    for what, fn in (("no link carries an extra", _strip_extras),
                     ("every extra names nothing", _foreign_extras)):
        edited = _lock_edit(fn)
        assert edited != BASE_LOCK, f"{what}: the edit changed nothing"
        assert _names(box_closure(edited, ROOT)) == PLANTED_CLOSURE, f"{what}: the closure moved"


def test_a_string_extra_on_a_link_walks_exactly_like_no_extra_and_is_no_fault(tmp_path):
    """A link whose `extra` is a STRING — `{ name = "beta", extra = "speed" }`, and the root's
    `{ name = "gamma", extra = "fast" }` — is walked exactly like the same link with no `extra`
    and like the list spelling uv writes: `box_closure` returns the same entries (eta and delta
    included; a walk that iterated the string would look for extras `s`, `p`, `e`, … and drop
    them), and `image_tag` over the tree names an image rather than faulting.

    The NAME does move with that spelling — the link sits inside `alpha`'s entry and the root's
    `box` list, both hashed as opaque data — so no equality with the baseline name is pinned
    here; only the walk and the absence of a fault are."""
    def stringly(lock: dict) -> None:
        for link in _entry(lock, "alpha")["dependencies"]:
            if link["name"] == "beta":
                link["extra"] = "speed"
        for link in _entry(lock, ROOT)["optional-dependencies"]["box"]:
            link["extra"] = "fast"

    string_lock = _lock_edit(stringly)
    assert {"name": "beta", "extra": "speed"} in _entry(string_lock, "alpha")["dependencies"]
    assert _names(box_closure(string_lock, ROOT)) == _names(box_closure(_lock_edit(_strip_extras), ROOT)) \
        == _names(box_closure(copy.deepcopy(BASE_LOCK), ROOT)) == PLANTED_CLOSURE

    named = image_tag(_plant(tmp_path, "string-extra", lock=string_lock))
    assert TAG_RE.match(named), named


def test_box_closure_of_this_checkouts_lock_is_exactly_the_core_and_box_closure_and_no_dev_or_runtime_package():
    """Over THIS checkout's `uv.lock`, with the root that `pyproject.toml`'s `[project].name`
    names, `box_closure` returns exactly the seven packages the image installs —
    annotated-types, duckdb, pydantic, pydantic-core, pyyaml, typing-extensions and
    typing-inspection — PLUS email-validator, dnspython and idna, which only pydantic's `email`
    extra reaches (nothing asks for it; amendment 2 walks every optional list of a reached
    entry, the superset cost it records), each at its locked version — and none of the packages
    the `dev` or `runtime` extras reach directly (pytest, ruff, mypy, pydantic-ai-slim, toons,
    …). `duckdb`, which `runtime` also names, is in: it is `box`'s."""
    pyproject = tomllib.loads((DEFENDER / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    root_name = pyproject["project"]["name"]
    got = box_closure(lock, root_name)
    names = sorted(e["name"] for e in got)
    assert names == REAL_CLOSURE_NAMES, names
    for entry in got:
        assert entry in lock["package"], f"not the lock's own entry: {entry['name']}"
    pydantic_extras = _entry(lock, "pydantic").get("optional-dependencies", {})
    assert [d["name"] for d in pydantic_extras.get("email", [])] == ["email-validator"], pydantic_extras

    root = _entry(lock, root_name)
    extras = root.get("optional-dependencies", {})
    other = {d["name"] for extra in ("dev", "runtime") for d in extras.get(extra, [])}
    assert {"pytest", "ruff", "mypy", "pydantic-ai-slim", "toons"} <= other, sorted(other)
    assert sorted(other & set(names)) == ["duckdb"], sorted(other & set(names))


# ---- O1: what does NOT rename the image --------------------------------------------------------
def test_an_edit_that_cannot_change_the_image_does_not_rename_it(tmp_path):
    """Over the planted tree, none of these renames the image: in `pyproject.toml` a
    `[tool.ruff]` or `[tool.mypy]` edit, a comment, and the `dev` or `runtime` extra changing
    without a relock (amendment 3 moved a CORE or `box` requirement edited without a relock to
    the renaming side — `test_an_edit_to_the_box_closure_its_roots_tool_uv_or_the_recipe_renames_the_image`);
    in `uv.lock` a version or artifact-hash change to an entry outside the closure (the dev
    tool, its dependency, the runtime library — the ROOT's `dev`/`runtime` extras are never
    taken FROM the root, and nothing in the planted lock links back to it),
    a dev-extra relock that adds an entry, a link under the root's `optional-dependencies.dev`
    and a `requires-dist` row, and a runtime-extra relock that links the root's `runtime` list to
    an entry outside the closure; and a file outside the three inputs.

    Positive controls, same tree: a closure entry's version change renames it (the lock is
    read), and a `[tool.uv]` change renames it (the manifest is read)."""
    baseline = image_tag(_plant(tmp_path, "baseline"))
    assert TAG_RE.match(baseline), baseline

    def pyproject_edit(old: str, new: str) -> str:
        return _replace_once(PLANTED_PYPROJECT, old, new)

    def bump(name: str, version: str) -> Callable[[dict], None]:
        def fn(lock: dict) -> None:
            _entry(lock, name)["version"] = version
            _entry(lock, name)["sdist"]["hash"] = _flip_hex(_entry(lock, name)["sdist"]["hash"])
        return fn

    def dev_relock(lock: dict) -> None:
        root = _entry(lock, ROOT)
        root["optional-dependencies"]["dev"].append({"name": "newdev"})
        root["metadata"]["requires-dist"].append({"name": "newdev", "marker": "extra == 'dev'"})
        lock["package"].append({
            "name": "newdev", "version": "1.0.0", "source": _REGISTRY,
            "sdist": {"url": "https://files.example/newdev-1.0.0.tar.gz",
                      "hash": "sha256:" + "ab" * 32, "size": 10},
        })

    def runtime_relock(lock: dict) -> None:
        _entry(lock, ROOT)["optional-dependencies"]["runtime"].append({"name": "devdep"})

    # `[tool.uv]` keys in another order: a table has no order (#1097 round-4 adversary A6).
    two_keys = _replace_once(PLANTED_PYPROJECT, "package = false\n", "package = false\ncompile-bytecode = true\n")
    swapped_keys = _replace_once(PLANTED_PYPROJECT, "package = false\n", "compile-bytecode = true\npackage = false\n")
    assert image_tag(_plant(tmp_path, "uv-keys", pyproject=two_keys)) == image_tag(
        _plant(tmp_path, "uv-keys-swapped", pyproject=swapped_keys)), "reordering [tool.uv] keys renamed the image"

    holding: dict[str, dict] = {
        "a [tool.ruff] edit": {"pyproject": pyproject_edit("line-length = 100", "line-length = 120")},
        "a [tool.mypy] edit": {"pyproject": pyproject_edit("strict = true", "strict = false")},
        "a pyproject comment": {"pyproject": "# a comment\n" + PLANTED_PYPROJECT},
        "the dev extra, unlocked": {"pyproject": pyproject_edit('dev = ["devtool"]', 'dev = ["devtool", "newdev"]')},
        "the runtime extra, unlocked": {"pyproject": pyproject_edit('runtime = ["rtlib"]', 'runtime = ["rtlib>=8"]')},
        "the dev tool's entry": {"lock": _lock_edit(bump("devtool", "7.0.1"))},
        "the dev tool's dependency": {"lock": _lock_edit(bump("devdep", "0.1.1"))},
        "the runtime library's entry": {"lock": _lock_edit(bump("rtlib", "8.0.1"))},
        "a dev-extra relock": {"lock": _lock_edit(dev_relock)},
        "a runtime-extra relock": {"lock": _lock_edit(runtime_relock)},
        # uv re-emitting the lock under a newer format revision, and a release bump of the
        # project itself (its own version, in pyproject and on the root entry): neither is
        # anything the image installs (#1097 round-2 adversary H5).
        "the lock's format revision": {"lock": _lock_edit(lambda lock: lock.__setitem__("revision", 4))},
        # Dependency groups: the fenced sync (`--no-default-groups`) cannot install them, so a
        # group edit and its relock never rename (#1097 round-3 adversary H5).
        "a dependency group and its relock": {
            "pyproject": PLANTED_PYPROJECT + '\n[dependency-groups]\nlint = ["devtool>=7"]\n',
            "lock": _lock_edit(lambda lock: _entry(lock, ROOT).__setitem__(
                "dev-dependencies", {"lint": [{"name": "devtool"}]})),
        },
        "the project's own version": {
            "pyproject": pyproject_edit('version = "0.0.0"', 'version = "0.0.1"'),
            "lock": _lock_edit(lambda lock: _entry(lock, ROOT).__setitem__("version", "0.0.1")),
        },
    }
    for i, (what, edit) in enumerate(holding.items()):
        held = image_tag(_plant(tmp_path, f"hold-{i}", **edit))
        assert held == baseline, f"{what} renamed the image"

    outside = _plant(tmp_path, "outside")
    (outside / "README.md").write_text("not a hash input\n", encoding="utf-8")
    (outside / "runtime").mkdir(exist_ok=True)
    (outside / "runtime" / "extra.py").write_text("x = 1\n", encoding="utf-8")
    assert image_tag(outside) == baseline, "a file outside the three inputs renamed the image"

    lock_read = image_tag(_plant(tmp_path, "control-lock", lock=_lock_edit(bump("alpha", "1.0.1"))))
    manifest_read = image_tag(_plant(tmp_path, "control-manifest", pyproject=pyproject_edit(
        "package = false", "package = true")))
    assert lock_read != baseline, "the positive control: a closure entry's version did not rename"
    assert manifest_read != baseline, "the positive control: [tool.uv] did not rename"


def test_reordering_or_reformatting_the_lock_does_not_rename_the_image(tmp_path):
    """The same lock spelled differently names the same image: its `[[package]]` entries in
    reverse order (the parsed entry LIST differs), every table's keys in reverse order (the
    parsed dicts are equal but their key order differs), one-line arrays, comment lines between
    entries — and all of these at once, which is what a re-emitting tool (a newer uv) does to a
    lock. Positive control, same spelling: a closure entry's one artifact-hash byte renames it."""
    baseline = image_tag(_plant(tmp_path, "baseline"))
    spellings = {
        "entries reversed": {"reverse_entries": True},
        "keys reversed": {"reverse_keys": True},
        "one-line arrays": {"multiline": False},
        "comments between entries": {"comments": True},
        "all at once": {"reverse_entries": True, "reverse_keys": True, "multiline": False, "comments": True},
    }
    uv_text = _lock_toml(BASE_LOCK)
    for i, (what, knobs) in enumerate(spellings.items()):
        text = _lock_toml(BASE_LOCK, **knobs)
        assert text != uv_text, f"{what}: the spelling did not change"
        parsed = tomllib.loads(text)
        if knobs.get("reverse_entries"):
            assert parsed["package"] != BASE_LOCK["package"], "the entry order did not change"
        if knobs.get("reverse_keys"):
            first = [p for p in parsed["package"] if p["name"] == "alpha"][0]
            assert list(first) != list(_entry(BASE_LOCK, "alpha")), "the key order did not change"
        tree = _plant(tmp_path, f"spelled-{i}")
        (tree / "uv.lock").write_text(text, encoding="utf-8")
        assert image_tag(tree) == baseline, f"{what} renamed the image"

        one_hash_byte = _lock_edit(_flip_artifact("gamma", "wheel"))
        (tree / "uv.lock").write_text(_lock_toml(one_hash_byte, **knobs), encoding="utf-8")
        assert image_tag(tree) != baseline, f"{what}: the positive control did not rename"


def test_reordering_a_list_inside_a_hashed_value_does_not_rename_the_image(tmp_path):
    """Amendment 3, M1‴ (c): every list inside a hashed value is sorted by its canonical
    encoding before hashing, so no list ORDER renames the image — none of them changes what the
    sync installs. Each of these holds the name, over a lock that is otherwise the same: a
    closure entry's `dependencies` reversed (alpha's two links); its `wheels` reversed (alpha
    with a second wheel); one of its optional lists reversed (gamma's `slow` with a second link);
    the root's `dependencies` reversed (its three links) and its `box` links reversed (with a
    second `box` link); an entry's `resolution-markers` reversed (`split` 1.0.0 with a second
    marker); EVERY list at every depth of the lock reversed at once; and in `pyproject.toml` the
    core requirements reordered and the `box` requirements reordered (with a second one).

    Positive control under each reordering, same tree: a version or one artifact-hash byte of
    an entry in the closure — or, for the requirement lists, one requirement's specifier —
    still renames the image. A list only has an order to change when it holds two different
    items, so each baseline that needs one grows it first (`_reverse` refuses a no-op)."""
    def two_slow(lock: dict) -> None:
        _append(["gamma", "optional-dependencies", "slow"], {"name": "devdep"})(lock)

    def two_box(lock: dict) -> None:
        _append([ROOT, "optional-dependencies", "box"], {"name": "delta"})(lock)

    def two_markers(lock: dict) -> None:
        _entry(lock, "split", "1.0.0")["resolution-markers"].append("sys_platform == 'linux'")

    def every_base(lock: dict) -> None:
        for fn in (_two_wheels, two_slow, two_box, two_markers):
            fn(lock)

    def every_list(lock: dict) -> None:
        before = copy.deepcopy(lock)
        _reverse_every_list(lock)
        assert lock != before, "reversing every list changed nothing"

    # case -> (the edit that gives the baseline lists an order, the reordering, the control)
    lock_cases: dict[str, tuple[Callable[[dict], None] | None, Callable[[dict], None], Callable[[dict], None]]] = {
        "a closure entry's dependencies reversed": (
            None, _reverse(["alpha", "dependencies"]), _set(["alpha", "version"], "1.0.1")),
        "a closure entry's wheels reversed": (
            _two_wheels, _reverse(["alpha", "wheels"]), _flip_artifact("alpha", "wheel")),
        "a closure entry's optional list reversed": (
            two_slow, _reverse(["gamma", "optional-dependencies", "slow"]), _set(["epsilon", "version"], "5.0.1")),
        "the root's dependencies reversed": (
            None, _reverse([ROOT, "dependencies"]), _flip_artifact("split", "wheel", "2.0.0")),
        "the root's box links reversed": (
            two_box, _reverse([ROOT, "optional-dependencies", "box"]), _flip_artifact("delta", "wheel")),
        "an entry's resolution-markers reversed": (
            two_markers, _reverse(["split", "resolution-markers"], "1.0.0"), _flip_artifact("split", "sdist", "1.0.0")),
        "every list in the lock reversed at once": (
            every_base, every_list, _flip_artifact("alpha", "sdist")),
    }
    for i, (what, (base_edit, reorder, control)) in enumerate(lock_cases.items()):
        base = _lock_edit(base_edit or (lambda lock: None))
        reordered = copy.deepcopy(base)
        reorder(reordered)
        assert reordered != base, f"{what}: the reordering changed nothing"
        controlled = copy.deepcopy(reordered)
        control(controlled)
        before = image_tag(_plant(tmp_path, f"lock-{i}-base", lock=base))
        assert image_tag(_plant(tmp_path, f"lock-{i}-reordered", lock=reordered)) == before, f"{what} renamed the image"
        assert image_tag(_plant(tmp_path, f"lock-{i}-control", lock=controlled)) != before, (
            f"{what}: the positive control did not rename")

    core = '    "alpha>=1",\n    "split",\n'
    two_box_reqs = _replace_once(PLANTED_PYPROJECT, 'box = ["gamma[fast]"]', 'box = ["gamma[fast]", "delta"]')
    manifest_cases: dict[str, tuple[str, str, str]] = {
        # case -> (the baseline manifest, the reordered one, the reordered one with a specifier moved)
        "the core requirements reordered": (
            PLANTED_PYPROJECT,
            _replace_once(PLANTED_PYPROJECT, core, '    "split",\n    "alpha>=1",\n'),
            _replace_once(PLANTED_PYPROJECT, core, '    "split",\n    "alpha>=2",\n'),
        ),
        "the box requirements reordered": (
            two_box_reqs,
            _replace_once(two_box_reqs, '["gamma[fast]", "delta"]', '["delta", "gamma[fast]"]'),
            _replace_once(two_box_reqs, '["gamma[fast]", "delta"]', '["delta", "gamma[fast]>=3"]'),
        ),
    }
    for i, (what, (base_text, reordered_text, control_text)) in enumerate(manifest_cases.items()):
        before = image_tag(_plant(tmp_path, f"manifest-{i}-base", pyproject=base_text))
        assert image_tag(_plant(tmp_path, f"manifest-{i}-reordered", pyproject=reordered_text)) == before, (
            f"{what} renamed the image")
        assert image_tag(_plant(tmp_path, f"manifest-{i}-control", pyproject=control_text)) != before, (
            f"{what}: the positive control did not rename")


# ---- O2: what DOES rename the image ------------------------------------------------------------
def test_an_edit_to_the_box_closure_its_roots_tool_uv_or_the_recipe_renames_the_image(tmp_path):
    """Each of these renames the image — `defender-box:v2-` stays, the 12 hex move, and no two
    edits collide: a closure entry's version (core `alpha`, marker-gated `winonly`, `eta`
    behind beta's `speed` list), its `source`, one byte of an sdist or a wheel hash (`alpha`,
    `delta` behind gamma's `fast` list), a closure entry gaining a link — to an entry already
    in the closure (the entry is digested whole) or to one outside it (which the walk then
    pulls in) — and a change to a closure entry's own optional-dependencies under an extra
    nobody asks for; the version and one hash byte of `epsilon`, an entry ONLY unrequested
    extras reach (beta's `docs`, gamma's `slow` — amendment 2 walks every optional list of a
    reached entry, so it is in the hashed superset); the root's `dependencies` gaining a link to
    an already-reached entry, a `box` link gaining a marker (the closure's entries unchanged:
    the ROOTS moved), a `box` link asking for another extra, and `box` gaining a link;
    `[tool.uv]` changing a value, gaining a key, or losing its only key; one byte of
    `box.Dockerfile`; and — amendment 3, M1‴ (a) — `pyproject.toml`'s core or `box`
    requirements edited WITHOUT a relock: a core requirement added, one dropped, one's
    specifier changed, the `box` requirement's specifier changed, a `box` requirement added
    (the lock untouched in each: the rename is what sends the next box start to the build,
    whose `--locked` sync then fails loudly instead of the old name silently holding).

    Both requirement lists read absent as `[]`: no `dependencies` key names the same image as
    `dependencies = []`, and no `box` key — or no `[project.optional-dependencies]` table at
    all — the same as `box = []`; each differs from the planted tree's name.

    The walk through unrequested extras is transitive and needs no link to ask: with gamma's
    `slow` list also naming `devdep`, a bump of devdep (reached ONLY that way) renames; and with
    the root's `box` link carrying no `extra` at all, epsilon is still in the closure and its
    bump still renames.

    `[tool.uv]` absent reads as `{}`: an EMPTY `[tool.uv]` table and no `[tool.uv]` at all name
    the same image (and it differs from `package = false`'s)."""
    baseline = image_tag(_plant(tmp_path, "baseline"))
    assert baseline.startswith("defender-box:v2-"), baseline

    lock_edits: dict[str, Callable[[dict], None]] = {
        "a core entry's version": _set(["alpha", "version"], "1.0.1"),
        "a marker-gated entry's version": _set(["winonly", "version"], "9.0.1"),
        "a transitive extra's target's version": _set(["eta", "version"], "6.0.1"),
        "a closure entry's source": _set(["alpha", "source"], {"registry": "https://mirror.example/simple"}),
        "an sdist hash byte": _flip_artifact("alpha", "sdist"),
        "a wheel hash byte of a box extra's target": _flip_artifact("delta", "wheel"),
        "an edge to an entry already in the closure": _append(["alpha", "dependencies"], {"name": "delta"}),
        "an edge to an entry outside the closure": _append(["alpha", "dependencies"], {"name": "devdep"}),
        "an unrequested extra of a closure entry": _append(["gamma", "optional-dependencies", "slow"], {"name": "devdep"}),
        "an entry only unrequested extras reach": _set(["epsilon", "version"], "5.0.1"),
        "a hash byte of an entry only unrequested extras reach": _flip_artifact("epsilon", "wheel"),
        "a root dependency to an already-reached entry": _append([ROOT, "dependencies"], {"name": "beta"}),
        "a marker on the box edge": _set([ROOT, "optional-dependencies", "box", 0, "marker"], "sys_platform == 'linux'"),
        "another extra on the box edge": _set([ROOT, "optional-dependencies", "box", 0, "extra"], ["fast", "slow"]),
        "a new box edge": _append([ROOT, "optional-dependencies", "box"], {"name": "rtlib"}),
        # A closure entry's OWN edge marker: `alpha -> winonly` gated to linux instead of
        # win32 changes what a Linux build installs (#1097 round-2 adversary H2).
        "a closure entry's edge marker": _set(["alpha", "dependencies", 1, "marker"], "sys_platform == 'linux'"),
        # A root CORE link's marker or version, the names unchanged: the Linux image stops
        # installing alpha (#1097 round-3 adversary H1 — core links hashed by name only).
        "a root core link's marker": _set([ROOT, "dependencies", 0, "marker"], "sys_platform == 'win32'"),
        "a root core link's version": _set([ROOT, "dependencies", 0, "version"], "1.0.0"),
        # Entries are hashed whole: a wheel's url alone moves the name (#1097 round-3
        # adversary H6 — url/size/upload-time projected away).
        "a wheel's url alone": _set(["alpha", "wheels", 0, "url"], "https://mirror.example/alpha-1.0.0-py3-none-any.whl"),
    }
    manifest_edits = {
        "[tool.uv] value": _replace_once(PLANTED_PYPROJECT, "package = false", "package = true"),
        "[tool.uv] key": _replace_once(PLANTED_PYPROJECT, "package = false\n", "package = false\ncompile-bytecode = true\n"),
        "[tool.uv] emptied": _replace_once(PLANTED_PYPROJECT, "package = false\n", ""),
        # Not only scalars: a list-valued key and a nested table change what a sync does
        # without touching the lock (#1097 round-2 adversary H4).
        "[tool.uv] list key": _replace_once(PLANTED_PYPROJECT, "package = false\n", 'package = false\nno-binary-package = ["gamma"]\n'),
        "[tool.uv] nested table": PLANTED_PYPROJECT + "\n[tool.uv.pip]\nno-build = true\n",
        # `[tool.uv]` lists keep their written order: `[[tool.uv.index]]` order is index
        # priority (#1097 round-4 adversary A1 — sorting them hid a swap). The pair's two
        # orders must name different images; see the assertion after the loop.
        "[tool.uv] indexes a, b": PLANTED_PYPROJECT + _INDEXES.format(first="a", second="b"),
        "[tool.uv] indexes b, a": PLANTED_PYPROJECT + _INDEXES.format(first="b", second="a"),
        # Requirement strings are hashed AS WRITTEN — extras and markers included (#1097
        # round-4 adversary A2 — reducing them to name + specifier hid these).
        "the box requirement's extra dropped, unlocked": _replace_once(PLANTED_PYPROJECT, 'box = ["gamma[fast]"]', 'box = ["gamma"]'),
        "a core requirement's marker added, unlocked": _replace_once(
            PLANTED_PYPROJECT, '"alpha>=1",', '"alpha>=1; sys_platform == \'linux\'",'),
        "a core requirement's marker value's case, unlocked": _replace_once(
            PLANTED_PYPROJECT, '"alpha>=1",', '"alpha>=1; sys_platform == \'Linux\'",'),
        # Amendment 3, M1‴ (a): the core and `box` requirement lists as written, lock untouched.
        "a core requirement, unlocked": _replace_once(PLANTED_PYPROJECT, '"split",\n', '"split",\n    "requests>=2",\n'),
        "a core requirement dropped, unlocked": _replace_once(PLANTED_PYPROJECT, '    "split",\n', ""),
        "a core requirement's specifier, unlocked": _replace_once(PLANTED_PYPROJECT, '"alpha>=1"', '"alpha>=2"'),
        "the box requirement, unlocked": _replace_once(PLANTED_PYPROJECT, 'box = ["gamma[fast]"]', 'box = ["gamma[fast]>=3"]'),
        "a box requirement added, unlocked": _replace_once(PLANTED_PYPROJECT, 'box = ["gamma[fast]"]', 'box = ["gamma[fast]", "delta"]'),
    }
    moved: dict[str, str] = {}
    for i, (what, fn) in enumerate(lock_edits.items()):
        moved[what] = image_tag(_plant(tmp_path, f"lock-{i}", lock=_lock_edit(fn)))
    for i, (what, text) in enumerate(manifest_edits.items()):
        moved[what] = image_tag(_plant(tmp_path, f"manifest-{i}", pyproject=text))
    dockerfile = PLANTED_INPUT_BYTES["box.Dockerfile"]
    moved["a Dockerfile byte"] = image_tag(_plant(
        tmp_path, "recipe", dockerfile=dockerfile.replace(b"RUN true", b"RUN tru3")))

    for what, name in moved.items():
        assert name != baseline, f"{what} did not rename the image"
        assert name.startswith("defender-box:v2-"), f"{what}: the version prefix moved: {name}"
    assert len(set(moved.values())) == len(moved), "two different edits named one image"

    no_tool_uv = _replace_once(PLANTED_PYPROJECT, "[tool.uv]\npackage = false\n\n", "")
    absent = image_tag(_plant(tmp_path, "tool-uv-absent", pyproject=no_tool_uv))
    assert absent == moved["[tool.uv] emptied"], "an absent [tool.uv] is not read as {}"

    # The two requirement lists read absent as [] (amendment 3, M1‴ (a)).
    core_block = 'dependencies = [\n    "alpha>=1",\n    "split",\n]\n'
    no_core = image_tag(_plant(tmp_path, "core-absent", pyproject=_replace_once(PLANTED_PYPROJECT, core_block, "")))
    empty_core = image_tag(_plant(tmp_path, "core-empty", pyproject=_replace_once(
        PLANTED_PYPROJECT, core_block, "dependencies = []\n")))
    assert no_core == empty_core, "an absent [project].dependencies is not read as []"
    assert no_core != baseline, "the core requirement list is not digested"
    box_line = 'box = ["gamma[fast]"]\n'
    empty_box = image_tag(_plant(tmp_path, "box-empty", pyproject=_replace_once(PLANTED_PYPROJECT, box_line, "box = []\n")))
    no_box = image_tag(_plant(tmp_path, "box-absent", pyproject=_replace_once(PLANTED_PYPROJECT, box_line, "")))
    no_table = image_tag(_plant(tmp_path, "optional-absent", pyproject=_replace_once(
        PLANTED_PYPROJECT, '[project.optional-dependencies]\nbox = ["gamma[fast]"]\ndev = ["devtool"]\nruntime = ["rtlib"]\n\n', "")))
    assert no_box == empty_box == no_table, "an absent box requirement list is not read as []"
    assert empty_box != baseline, "the box requirement list is not digested"

    # EVERY wheel's hash is digested, not the first: over an entry carrying two wheels, one
    # byte of the second moves the name (#1097 round-2 adversary H1 — the image's own
    # manylinux wheel is rarely wheels[0]).
    two = _lock_edit(_two_wheels)
    second_flipped = copy.deepcopy(two)
    wheel = _entry(second_flipped, "alpha")["wheels"][1]
    wheel["hash"] = _flip_hex(wheel["hash"])
    assert image_tag(_plant(tmp_path, "two-wheels", lock=two)) != image_tag(
        _plant(tmp_path, "two-wheels-flipped", lock=second_flipped)), "the second wheel's hash is not digested"

    # Unrequested extras are walked TRANSITIVELY: devdep, linked from gamma's `slow` list (an
    # extra no link asks for) and from nowhere else the walk takes, is in the superset.
    deeper = _lock_edit(_append(["gamma", "optional-dependencies", "slow"], {"name": "devdep"}))
    assert "devdep" in {e["name"] for e in box_closure(deeper, ROOT)}, "an unrequested extra's new target was not walked"
    deeper_bumped = copy.deepcopy(deeper)
    _entry(deeper_bumped, "devdep")["version"] = "0.1.1"
    assert image_tag(_plant(tmp_path, "deeper", lock=deeper)) != image_tag(
        _plant(tmp_path, "deeper-bumped", lock=deeper_bumped)), "an unrequested extra's target did not rename"

    # No link needs to ask for an extra (the round-2 walk followed only requested ones): with
    # the root's `box -> gamma` link stripped of its `extra`, epsilon (and delta) are still in
    # the closure, and epsilon's bump still renames.
    unasked = _lock_edit(lambda lock: _entry(lock, ROOT)["optional-dependencies"]["box"][0].pop("extra"))
    unasked_names = {e["name"] for e in box_closure(unasked, ROOT)}
    assert {"epsilon", "delta"} <= unasked_names, sorted(unasked_names)
    unasked_bumped = copy.deepcopy(unasked)
    _entry(unasked_bumped, "epsilon")["version"] = "5.0.1"
    assert image_tag(_plant(tmp_path, "unasked", lock=unasked)) != image_tag(
        _plant(tmp_path, "unasked-bumped", lock=unasked_bumped)), "epsilon behind an unasked extra did not rename"

    # A TOML datetime in [tool.uv] (uv's `exclude-newer`) is digested, not a crash.
    dated = _replace_once(PLANTED_PYPROJECT, "package = false\n", "package = false\nexclude-newer = 2026-01-01T00:00:00Z\n")
    assert image_tag(_plant(tmp_path, "dated", pyproject=dated)) not in (baseline, *moved.values())

    # An entry reached only THROUGH an optional list has its own optional lists walked too:
    # give `delta` (reached via gamma[fast]) an optional list naming `rtlib`, and a bump to
    # rtlib renames (#1097 round-3 adversary H2 — a two-phase walk read delta's links only).
    nested = _lock_edit(_set(["delta", "optional-dependencies"], {"x": [{"name": "rtlib"}]}))
    assert "rtlib" in {e["name"] for e in box_closure(nested, ROOT)}, "delta's optional list was not walked"
    nested_bumped = copy.deepcopy(nested)
    _entry(nested_bumped, "rtlib")["version"] = "8.0.1"
    assert image_tag(_plant(tmp_path, "nested", lock=nested)) != image_tag(
        _plant(tmp_path, "nested-bumped", lock=nested_bumped)), "a target behind a nested optional list did not rename"

    # A NaN or infinity in a hashed value names an image or faults — never another exception
    # (#1097 round-3 adversary H4).
    for i, special in enumerate(("nan", "inf")):
        text = _replace_once(PLANTED_PYPROJECT, "package = false\n", f"package = false\nx = {special}\n")
        try:
            image_tag(_plant(tmp_path, f"special-{i}", pyproject=text))
        except image_module().ImageInputError:
            pass


def test_a_package_split_across_two_lock_entries_renames_the_image_whichever_entry_changes(tmp_path):
    """The planted lock resolves `split` to two versions the way uv writes a fork — two
    same-named `[[package]]` entries, each with `resolution-markers`, root edges carrying
    `version` + `marker`. One artifact-hash byte of EITHER entry renames the image, and the two
    renames differ — including the `python_full_version >= '3.12'` entry the 3.11 image never
    installs (the superset rule: at most an extra rename, never a missed one). So does a relock
    that moves one side's version, edge and entry together.

    # rejected: evaluating markers for the image's environment — the name would then depend on
    # the builder's platform, and an entry the walk misjudged would never rename (the design
    # amendment's M1')."""
    baseline = image_tag(_plant(tmp_path, "baseline"))
    assert _names([e for e in box_closure(copy.deepcopy(BASE_LOCK), ROOT) if e["name"] == "split"]) == [
        ("split", "1.0.0"), ("split", "2.0.0"),
    ]

    def relock_upper(lock: dict) -> None:
        _entry(lock, "split", "2.0.0")["version"] = "2.0.1"
        for edge in _entry(lock, ROOT)["dependencies"]:
            if edge.get("version") == "2.0.0":
                edge["version"] = "2.0.1"

    lower = image_tag(_plant(tmp_path, "lower", lock=_lock_edit(_flip_artifact("split", "wheel", "1.0.0"))))
    upper = image_tag(_plant(tmp_path, "upper", lock=_lock_edit(_flip_artifact("split", "wheel", "2.0.0"))))
    relocked = image_tag(_plant(tmp_path, "relocked", lock=_lock_edit(relock_upper)))
    assert lower != baseline, "the < 3.12 entry did not rename the image"
    assert upper != baseline, "the >= 3.12 entry did not rename the image"
    assert lower != upper, "the two entries' edits named one image"
    assert relocked not in (baseline, lower, upper), relocked


# ---- the real lock ------------------------------------------------------------------------------
def test_on_this_checkouts_manifests_a_dev_tool_relock_holds_the_name_and_a_closure_relock_moves_it(tmp_path):
    """Over copies of THIS checkout's `uv.lock` and `pyproject.toml`: a pytest bump (its
    version and one sdist-hash byte), a dev-extra edge dropped from the root, the lock's
    entries in reverse order with a comment, the whole lock re-spelled (every key reversed,
    one-line arrays), a `[tool.mypy]`/`[tool.ruff.lint]` key and a dev requirement added to
    `pyproject.toml`, and the core requirements reordered (amendment 3's order-free form) —
    none renames the image (the key flow "a pytest bump plus relock: the name holds"). A
    pydantic bump, one wheel-hash byte of pydantic-core, a typing-inspection bump (reached only
    through pydantic), one sdist-hash byte of duckdb (`box`'s), a second `box` edge, and
    `[tool.uv]`'s `package` flipped each rename it — and so does a dnspython or an idna bump,
    packages the image does NOT install, reached only through pydantic's unrequested `email`
    extra (amendment 2's recorded superset cost: a relock bumping them renames the image; it
    never goes stale) — and, amendment 3, a core requirement added to `pyproject.toml` or the
    `box` requirement's specifier changed, each WITHOUT a relock (the next box start is sent
    to the build, whose `--locked` sync fails loudly)."""
    lock_text = (DEFENDER / "uv.lock").read_text(encoding="utf-8")
    pyproject_text = (DEFENDER / "pyproject.toml").read_text(encoding="utf-8")
    lock = tomllib.loads(lock_text)

    def tree(label: str, *, lock_bytes: str = lock_text, manifest: str = pyproject_text) -> str:
        defender_dir = tmp_path / label / "defender"
        defender_dir.mkdir(parents=True)
        shutil.copyfile(DEFENDER / "box.Dockerfile", defender_dir / "box.Dockerfile")
        (defender_dir / "uv.lock").write_text(lock_bytes, encoding="utf-8")
        (defender_dir / "pyproject.toml").write_text(manifest, encoding="utf-8")
        return image_tag(defender_dir)

    def version_line(name: str, new: str) -> str:
        entry = _entry(lock, name)
        return _replace_once(lock_text, f'name = "{name}"\nversion = "{entry["version"]}"\n',
                             f'name = "{name}"\nversion = "{new}"\n')

    def hash_byte(name: str, artifact: str) -> str:
        entry = _entry(lock, name)
        digest = entry["sdist"]["hash"] if artifact == "sdist" else entry["wheels"][0]["hash"]
        return _replace_once(lock_text, digest, _flip_hex(digest))

    head, *blocks = lock_text.split("\n[[package]]\n")
    assert len(blocks) == len(lock["package"]), "the lock did not split into its entries"
    reversed_lock = head + "\n# re-ordered by hand\n" + "".join(f"\n[[package]]\n{b}" for b in reversed(blocks))
    assert _canonical(tomllib.loads(reversed_lock)) == _canonical(lock)
    assert tomllib.loads(reversed_lock)["package"] != lock["package"]

    installed_wheel = next(
        w["hash"] for w in _entry(lock, "pydantic-core")["wheels"]
        if "cp311-cp311-manylinux_2_17_x86_64" in w["url"]
    )
    assert installed_wheel != _entry(lock, "pydantic-core")["wheels"][0]["hash"]

    baseline = tree("baseline")
    assert TAG_RE.match(baseline), baseline
    holding = {
        "a pytest version": {"lock_bytes": version_line("pytest", "99.0.0")},
        "a pytest sdist hash byte": {"lock_bytes": hash_byte("pytest", "sdist")},
        "a dev edge dropped": {"lock_bytes": _replace_once(lock_text, '    { name = "radon" },\n', "")},
        "the entries reversed": {"lock_bytes": reversed_lock},
        "the lock re-spelled": {"lock_bytes": _lock_toml(lock, reverse_keys=True, multiline=False, comments=True)},
        "a [tool.mypy] key": {"manifest": _replace_once(pyproject_text, "[tool.mypy]\n", "[tool.mypy]\nplanted_1097 = true\n")},
        "a [tool.ruff.lint] key": {"manifest": _replace_once(pyproject_text, "[tool.ruff.lint]\n", "[tool.ruff.lint]\nplanted-1097 = 1\n")},
        "a dev requirement, unlocked": {"manifest": _replace_once(pyproject_text, 'dev = [\n', 'dev = [\n    "planted-1097",\n')},
        "the core requirements reordered": {"manifest": _replace_once(
            _replace_once(pyproject_text, '    "pyyaml>=6.0",\n', ""),
            '    "typing-extensions>=4.12",\n]\n', '    "typing-extensions>=4.12",\n    "pyyaml>=6.0",\n]\n')},
    }
    for i, (what, edit) in enumerate(holding.items()):
        assert tree(f"hold-{i}", **edit) == baseline, f"{what} renamed the image"

    moving = {
        "a pydantic version": {"lock_bytes": version_line("pydantic", "99.0.0")},
        "a pydantic-core wheel hash byte": {"lock_bytes": hash_byte("pydantic-core", "wheel")},
        # The wheel the image actually installs — not wheels[0] (#1097 round-2 adversary H1).
        "the installed pydantic-core wheel's hash byte": {"lock_bytes": _replace_once(
            lock_text, installed_wheel, _flip_hex(installed_wheel))},
        "a typing-inspection version": {"lock_bytes": version_line("typing-inspection", "99.0.0")},
        "a dnspython version (pydantic's email extra)": {"lock_bytes": version_line("dnspython", "99.0.0")},
        "an idna version (pydantic's email extra)": {"lock_bytes": version_line("idna", "99.0.0")},
        "a duckdb sdist hash byte": {"lock_bytes": hash_byte("duckdb", "sdist")},
        "a second box edge": {"lock_bytes": _replace_once(
            lock_text, 'box = [\n    { name = "duckdb" },\n]', 'box = [\n    { name = "duckdb" },\n    { name = "pyyaml" },\n]')},
        "[tool.uv] package": {"manifest": _replace_once(pyproject_text, "package = false", "package = true")},
        "a core requirement, unlocked": {"manifest": _replace_once(
            pyproject_text, 'dependencies = [\n', 'dependencies = [\n    "planted-1097",\n')},
        "the box requirement, unlocked": {"manifest": _replace_once(
            pyproject_text, 'box = [\n    "duckdb>=1.5,<2",\n]', 'box = [\n    "duckdb>=1.5,<3",\n]')},
    }
    for i, (what, edit) in enumerate(moving.items()):
        assert tree(f"move-{i}", **edit) != baseline, f"{what} did not rename the image"


# ---- the root: found by the normalised project name -------------------------------------------
def _renamed_root(new: str) -> Callable[[dict], None]:
    return lambda lock: _entry(lock, ROOT).__setitem__("name", new)


def _named(project_name: str) -> str:
    return _replace_once(PLANTED_PYPROJECT, 'name = "planted"\n', f'name = "{project_name}"\n')


def test_the_root_is_the_lock_entry_the_pep503_normalised_project_name_names(tmp_path):
    """`image_tag` finds the lock's root entry by `[project].name` normalised the way uv writes
    lock names (PEP 503: lowercase, every run of `-`, `_`, `.` becomes one `-`): `name =
    "Planted"` or `"PLANTED"` over the planted lock (root entry `planted`) names the SAME image
    as `name = "planted"` — `[project].name` is not itself hashed, only used to find the root —
    and over a lock whose root entry is `planted-x`, `"planted_x"`, `"planted.x"`,
    `"Planted__X"` and `"planted-_.x"` each name the same image as `"planted-x"`.

    Positive control — normalising is not matching loosely: `"plantedx"` over that same lock
    (a name that normalises to no entry) still raises `ImageInputError` naming `uv.lock` and the
    missing name, as a lock with no root entry does."""
    image = image_module()
    baseline = image_tag(_plant(tmp_path, "baseline"))
    for i, spelling in enumerate(("Planted", "PLANTED")):
        got = image_tag(_plant(tmp_path, f"case-{i}", pyproject=_named(spelling)))
        assert got == baseline, f"[project].name {spelling!r} did not find the root `planted`"

    lock_x = _lock_edit(_renamed_root("planted-x"))
    base_x = image_tag(_plant(tmp_path, "x", lock=lock_x, pyproject=_named("planted-x")))
    assert TAG_RE.match(base_x), base_x
    for i, spelling in enumerate(("planted_x", "planted.x", "Planted__X", "planted-_.x")):
        got = image_tag(_plant(tmp_path, f"sep-{i}", lock=lock_x, pyproject=_named(spelling)))
        assert got == base_x, f"[project].name {spelling!r} did not find the root `planted-x`"

    absent = _plant(tmp_path, "absent", lock=lock_x, pyproject=_named("plantedx"))
    with pytest.raises(image.ImageInputError) as e:
        image.image_tag(absent)
    message = str(e.value)
    assert str(absent) in message, message
    assert "uv.lock" in message, message
    assert "plantedx" in message, message
    assert "pyproject.toml" not in message, message


def test_box_closure_normalises_the_root_name_it_is_given():
    """Amendment 3, M1‴ (e): `box_closure(lock, root_name)` normalises `root_name` itself
    (PEP 503), so a direct caller need not: over the planted lock `"Planted"` and `"PLANTED"`
    return exactly what `"planted"` returns, and over a lock whose root entry is `planted-x`,
    `"planted_x"`, `"Planted.X"` and `"planted-_.x"` return exactly what `"planted-x"` returns
    (the planted closure, the root not in it).

    Positive control — normalising is not matching loosely: `"plantedx"` over that lock still
    raises the walk's missing-entry `KeyError` naming it."""
    planted = box_closure(copy.deepcopy(BASE_LOCK), ROOT)
    assert _names(planted) == PLANTED_CLOSURE, _names(planted)
    for spelling in ("Planted", "PLANTED"):
        assert box_closure(copy.deepcopy(BASE_LOCK), spelling) == planted, spelling

    lock_x = _lock_edit(_renamed_root("planted-x"))
    base_x = box_closure(copy.deepcopy(lock_x), "planted-x")
    assert _names(base_x) == PLANTED_CLOSURE, _names(base_x)
    for spelling in ("planted_x", "Planted.X", "planted-_.x"):
        assert box_closure(copy.deepcopy(lock_x), spelling) == base_x, spelling

    with pytest.raises(KeyError) as e:
        box_closure(copy.deepcopy(lock_x), "plantedx")
    assert "plantedx" in str(e.value), str(e.value)


def _links_to_the_root(lock: dict) -> None:
    """`alpha` (a closure entry) gains a link back to the root, asking for its `runtime` extra —
    the shape of a `defender[runtime]` link."""
    _append(["alpha", "dependencies"], {"name": ROOT, "extra": ["runtime"]})(lock)


def test_a_link_that_reaches_the_root_walks_and_hashes_it_like_any_entry(tmp_path):
    """Amendment 3, M1‴ (d): the root is not special once reached. Over a lock where `alpha`
    links `{ name = "planted", extra = ["runtime"] }`, `box_closure` returns the root entry
    itself (the lock's own dict) AND the targets of EVERY one of its optional lists — rtlib
    (`runtime`), devtool (`dev`) and devdep (devtool's) — beside the planted closure; the same
    link with no `extra` returns the same entries (a link's `extra` is never read). Under that
    lock a bump to rtlib, and a bump to devdep, each rename the image.

    Negative control, same test: over the planted lock (no link reaches the root) none of
    those is in the closure and the rtlib bump holds the name."""
    reached = _lock_edit(_links_to_the_root)
    got = box_closure(copy.deepcopy(reached), ROOT)
    root_entry = _entry(reached, ROOT)
    assert root_entry in got, "a root reached by a link is not in the closure"
    assert _names(got) == sorted([*PLANTED_CLOSURE, ("devdep", "0.1.0"), ("devtool", "7.0.0"),
                                  (ROOT, "0.0.0"), ("rtlib", "8.0.0")]), _names(got)
    for entry in got:
        assert entry in reached["package"], f"not the lock's own entry: {entry['name']}"

    bare = _lock_edit(lambda lock: _append(["alpha", "dependencies"], {"name": ROOT})(lock))
    assert _names(box_closure(bare, ROOT)) == _names(got), "a link's extra changed what the root reaches"

    unreached = {name for name, _ in _names(box_closure(copy.deepcopy(BASE_LOCK), ROOT))}
    assert not unreached & {ROOT, "rtlib", "devtool", "devdep"}, sorted(unreached)

    def bumped(lock: dict, name: str, version: str) -> dict:
        out = copy.deepcopy(lock)
        _entry(out, name)["version"] = version
        return out

    base = image_tag(_plant(tmp_path, "reached", lock=reached))
    assert image_tag(_plant(tmp_path, "reached-rtlib", lock=bumped(reached, "rtlib", "8.0.1"))) != base, (
        "rtlib, behind the reached root's runtime list, did not rename")
    assert image_tag(_plant(tmp_path, "reached-devdep", lock=bumped(reached, "devdep", "0.1.1"))) != base, (
        "devdep, behind the reached root's dev list, did not rename")

    # The reached root is HASHED, not only walked: a change to its own dict alone — its
    # version, or a marker on its runtime link — renames (#1097 round-4 adversary A3).
    root_version = copy.deepcopy(reached)
    _entry(root_version, ROOT)["version"] = "0.0.1"
    runtime_marker = copy.deepcopy(reached)
    _entry(runtime_marker, ROOT)["optional-dependencies"]["runtime"][0]["marker"] = "sys_platform == 'win32'"
    assert image_tag(_plant(tmp_path, "reached-root-version", lock=root_version)) != base, (
        "the reached root's own version did not rename")
    assert image_tag(_plant(tmp_path, "reached-root-marker", lock=runtime_marker)) != base, (
        "a marker on the reached root's runtime link did not rename")

    planted = image_tag(_plant(tmp_path, "planted"))
    assert image_tag(_plant(tmp_path, "planted-rtlib", lock=bumped(BASE_LOCK, "rtlib", "8.0.1"))) == planted, (
        "rtlib renamed the image with no link reaching the root")


# ---- faults: never a fallback name --------------------------------------------------------------
READ, USE = "cannot read", "cannot use"


def _without_root(lock: dict) -> None:
    lock["package"] = [p for p in lock["package"] if p["name"] != ROOT]


def _deep_header(table: str, depth: int = 20_000) -> str:
    """A TOML table header `depth` keys below `table` — it parses (tomllib builds dotted
    headers without recursion) into a value nested far past what `json` can encode, the
    canonical form's own recursion limit."""
    return f"\n[{table}." + ".".join(["x"] * depth) + "]\nb = 1\n"


#: An integer literal past CPython's 4300-digit int<->str limit: tomllib's `int()` raises a
#: bare ValueError PARSING it (claim d1). The hex spelling parses (a power-of-two base has no
#: limit) but cannot be turned back into decimal — its `repr` and any encoder raise instead.
_BIG_INT = "1" * 5000
_BIG_HEX = "0x" + "f" * 4000


def _with_key(entry: str, key: str) -> str:
    """The planted lock with `key` added right after `entry`'s `name`/`version` lines."""
    head = f'name = "{entry}"\nversion = "{_entry(BASE_LOCK, entry)["version"]}"\n'
    return _replace_once(PLANTED_LOCK, head, head + key + "\n")


def _in_tool_uv(line: str) -> str:
    return _replace_once(PLANTED_PYPROJECT, "package = false\n", f"package = false\n{line}\n")


def _write_lock(fn: Callable[[dict], None]) -> Callable[[Path], None]:
    return lambda d: d.joinpath("uv.lock").write_text(_lock_toml(_lock_edit(fn)), encoding="utf-8")


def _write(name: str, text: str) -> Callable[[Path], None]:
    return lambda d: d.joinpath(name).write_text(text, encoding="utf-8")


def _into_a_directory(name: str) -> Callable[[Path], None]:
    def fn(d: Path) -> None:
        (d / name).unlink()
        (d / name).mkdir()
    return fn


#: case -> (the file the fault names, the verb it says, a word of the reason it must carry,
#: a phrase it must NOT carry, how to break the tree). ENTRY-level shape (a table with a string
#: `name`) is pinned over any entry of the lock; LINK-level shape (`dependencies`,
#: `optional-dependencies` and the links in them) only on entries the walk REACHES (alpha,
#: beta, gamma) — whether a malformed link on an unreached entry must fault is left open.
_FAULTS: dict[str, tuple[str, str, str | None, str | None, Callable[[Path], None]]] = {
    # -- cannot read: the file is not there to parse --
    "box.Dockerfile missing": ("box.Dockerfile", READ, None, None, lambda d: (d / "box.Dockerfile").unlink()),
    "uv.lock missing": ("uv.lock", READ, None, None, lambda d: (d / "uv.lock").unlink()),
    "pyproject.toml missing": ("pyproject.toml", READ, None, None, lambda d: (d / "pyproject.toml").unlink()),
    "uv.lock is a directory": ("uv.lock", READ, None, None, _into_a_directory("uv.lock")),
    # -- cannot use: it reads, and is not a lock/manifest the resolver can use --
    "uv.lock is not TOML": ("uv.lock", USE, None, None, _write("uv.lock", PLANTED_LOCK + "[[package]\n")),
    "pyproject.toml is not TOML": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", PLANTED_PYPROJECT + "[project\n")),
    "the lock holds no root entry": ("uv.lock", USE, ROOT, None, _write_lock(_without_root)),
    "a closure entry's link names no entry": ("uv.lock", USE, "ghost", None, _write_lock(
        _append(["alpha", "dependencies"], {"name": "ghost"}))),
    "the lock holds no [[package]] at all": ("uv.lock", USE, ROOT, None, _write(
        "uv.lock", "version = 1\nrevision = 3\n")),
    "pyproject.toml has no [project] name": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(PLANTED_PYPROJECT, 'name = "planted"\n', ""))),
    "a box link names no entry": ("uv.lock", USE, "ghost", None, _write_lock(
        _append([ROOT, "optional-dependencies", "box"], {"name": "ghost"}))),
    # -- amendment 2's one shape check, at the parse seam --
    "a reached entry's link has no name": ("uv.lock", USE, None, "no package entry", _write_lock(
        _append(["alpha", "dependencies"], {"version": "2.0.0"}))),
    "a reached entry's link is not a table": ("uv.lock", USE, None, None, _write_lock(
        _append(["alpha", "dependencies"], "beta"))),
    "a reached entry's dependencies is a string": ("uv.lock", USE, None, None, _write_lock(
        _set(["alpha", "dependencies"], "beta"))),
    "a reached entry's optional-dependencies is a list": ("uv.lock", USE, None, None, _write_lock(
        _set(["beta", "optional-dependencies"], [{"name": "eta"}]))),
    "a reached entry's unrequested optional list is a string": ("uv.lock", USE, None, None, _write_lock(
        _set(["gamma", "optional-dependencies", "slow"], "epsilon"))),
    "an entry's name is not a string": ("uv.lock", USE, None, None, _write_lock(
        _set(["winonly", "name"], 9))),
    "an entry is not a table": ("uv.lock", USE, None, None, _write(
        "uv.lock", 'version = 1\npackage = [\n    { name = "planted", version = "0.0.0" },\n    1,\n]\n')),
    # -- the ROOT's links are shape-checked too (#1097 round-3 adversary H3) --
    "the root's dependencies is a string": ("uv.lock", USE, None, None, _write_lock(
        _set([ROOT, "dependencies"], "alpha"))),
    "the root's optional-dependencies is a list": ("uv.lock", USE, None, None, _write_lock(
        _set([ROOT, "optional-dependencies"], [{"name": "gamma"}]))),
    "the root's box list is a string": ("uv.lock", USE, None, None, _write_lock(
        _set([ROOT, "optional-dependencies", "box"], "gamma"))),
    # -- a hashed value the canonical form cannot encode: a fault naming its file, never
    #    RecursionError --
    "[tool.uv] nested 2000 arrays deep": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(
            PLANTED_PYPROJECT, "package = false\n", "package = false\nx = " + "[" * 2000 + "]" * 2000 + "\n"))),
    "[tool.uv] nested 20000 tables deep": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", PLANTED_PYPROJECT + _deep_header("tool.uv"))),
    "a reached lock entry nested 20000 tables deep": ("uv.lock", USE, None, None, _write(
        "uv.lock", PLANTED_LOCK + _deep_header("package"))),   # the last [[package]]: winonly
    # -- amendment 3, M1‴ (b): ONE fault boundary after the reads — any exception while
    #    parsing, checking, walking or digesting names the file being processed, "cannot use"
    #    (the /code-review round-3 reproductions, and one per stage) --
    "a nameless entry nested 20000 tables deep": ("uv.lock", USE, None, None, _write(
        "uv.lock", PLANTED_LOCK + "\n[[package]]" + _deep_header("package"))),   # its repr recursed
    "a nameless entry holding a hex integer past the digit limit": ("uv.lock", USE, None, None, _write(
        "uv.lock", PLANTED_LOCK + f"\n[[package]]\nx = {_BIG_HEX}\n")),        # its repr cannot be decimal
    "a 5000-digit integer in [tool.uv]": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _in_tool_uv(f"x = {_BIG_INT}"))),
    "a 5000-digit integer in a reached lock entry": ("uv.lock", USE, None, None, _write(
        "uv.lock", _with_key("alpha", f"x = {_BIG_INT}"))),
    "a 5000-digit integer in an unreached lock entry": ("uv.lock", USE, None, None, _write(
        "uv.lock", _with_key("devtool", f"x = {_BIG_INT}"))),
    "a hex integer past the digit limit in [tool.uv]": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _in_tool_uv(f"x = {_BIG_HEX}"))),
    "a hex integer past the digit limit in a reached lock entry": ("uv.lock", USE, None, None, _write(
        "uv.lock", _with_key("alpha", f"x = {_BIG_HEX}"))),
    # -- amendment 3, M1‴ (a): the two requirement lists are lists of strings --
    "[project].dependencies is a string": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(
            PLANTED_PYPROJECT, 'dependencies = [\n    "alpha>=1",\n    "split",\n]\n', 'dependencies = "alpha>=1"\n'))),
    "a core requirement is an integer": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(PLANTED_PYPROJECT, '    "split",\n', '    "split",\n    1,\n'))),
    "a core requirement is a table": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(PLANTED_PYPROJECT, '    "split",\n', '    { name = "split" },\n'))),
    "the box requirement list is a string": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(PLANTED_PYPROJECT, 'box = ["gamma[fast]"]', 'box = "gamma[fast]"'))),
    "a box requirement is an integer": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(PLANTED_PYPROJECT, 'box = ["gamma[fast]"]', 'box = ["gamma[fast]", 3]'))),
    "[project].optional-dependencies is a string": ("pyproject.toml", USE, None, None, _write(
        "pyproject.toml", _replace_once(
            PLANTED_PYPROJECT,
            '[project.optional-dependencies]\nbox = ["gamma[fast]"]\ndev = ["devtool"]\nruntime = ["rtlib"]\n',
            "").replace('requires-python = ">=3.11"\n', 'requires-python = ">=3.11"\noptional-dependencies = "box"\n', 1))),
}


@pytest.mark.parametrize("case", list(_FAULTS))
def test_a_tree_the_resolver_cannot_read_parse_or_walk_raises_image_input_error_naming_the_file(tmp_path, case):
    """`image_tag` over a tree it cannot fully read, parse or walk raises `ImageInputError` —
    never a name, never a hash of the bytes it did read, never a TypeError, AttributeError,
    KeyError or RecursionError — whose message carries the tree and names the ONE file at
    fault, and says which kind of fault it is: "cannot read" for a file that is not there to
    read (each of the three missing in turn, a directory in `uv.lock`'s place), "cannot use"
    for one that reads but is not usable (and never the other verb):

      - a `uv.lock` or `pyproject.toml` that is not TOML; a `pyproject.toml` with no
        `[project].name`;
      - a lock with no entry for the root (the message names the root), and a link — from a
        closure entry or from the root's `box` extra — to a name the lock has no entry for
        (the message names it);
      - amendment 2's shape check: a link with no `name` (a shape fault, NOT a hunt for a
        package called "name"), a link that is not a table, `dependencies` a string,
        `optional-dependencies` a list, one of its lists a string (under an extra no link asks
        for — the walk reads every list), an entry whose `name` is not a string, an entry that
        is not a table;
      - a value the canonical form cannot encode — `[tool.uv]` nested 2000 arrays or 20000
        tables deep, a reached lock entry nested 20000 tables deep — naming the file it came
        from;
      - amendment 3's ONE fault boundary (M1‴ (b)): whatever raises while the read bytes are
        parsed, checked, walked or digested is `ImageInputError` naming the file being
        processed — the /code-review round-3 reproductions: a `[[package]]` entry with no
        `name` whose body is a table 20000 deep (the shape fault's own `repr` of it recursed),
        a 5000-digit integer literal (tomllib raises a bare ValueError parsing it) in
        `[tool.uv]`, in a reached lock entry and in an UNREACHED one; and one per later stage:
        a nameless entry holding a hex integer too long to print in decimal (its `repr`
        raises), the same hex integer in `[tool.uv]` and in a reached entry (the encoder
        raises);
      - amendment 3's requirement lists (M1‴ (a)): `[project].dependencies` a string, a core
        requirement an integer or a table, `optional-dependencies.box` a string, a `box`
        requirement an integer, `[project].optional-dependencies` itself a string — each
        naming `pyproject.toml`.

    Positive control, same test: the complete tree names an image. The resolver's constants
    are pinned exactly: `HASH_INPUTS` is the three files in read order, `RECIPE_VERSION` is
    `v2` (#1097's rename of every image, once)."""
    image = image_module()
    assert tuple(image.HASH_INPUTS) == HASH_INPUTS == ("box.Dockerfile", "uv.lock", "pyproject.toml")
    assert image.RECIPE_VERSION == "v2"

    named, verb, reason, not_said, breaks = _FAULTS[case]
    defender_dir = _plant(tmp_path, "tree")
    assert TAG_RE.match(image_tag(defender_dir)), "the positive control: the complete tree names an image"
    breaks(defender_dir)
    with pytest.raises(image.ImageInputError) as e:
        image.image_tag(defender_dir)
    message = str(e.value)
    assert str(defender_dir) in message, message
    assert named in message, message
    for other in HASH_INPUTS:
        if other != named:
            assert other not in message, (other, message)
    assert verb in message, (verb, message)
    assert ({READ, USE} - {verb}).pop() not in message, message
    if reason is not None:
        assert reason in message, (reason, message)
    if not_said is not None:
        assert not_said not in message, (not_said, message)
