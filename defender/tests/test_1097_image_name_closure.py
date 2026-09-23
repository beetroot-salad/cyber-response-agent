"""#1097 (design amendment) — the owned image is named from the lock's core + `box` closure.

The name is `defender-box:v2-<12 hex>` over: the bytes of `box.Dockerfile`; `[tool.uv]` from
`pyproject.toml` (absent -> `{}`); the root lock entry's `dependencies` + `optional-
dependencies.box` (the root is the lock package `[project].name` names); and every lock
`[[package]]` entry reachable from those edges — `runtime/box/_image.py::box_closure` — each a
whole parsed dict, canonically digested. The walk follows edges BY NAME to EVERY entry of that
name (markers and an edge's `version` ignored: the superset rule) and, for an edge carrying
`extra = [...]`, the target's `optional-dependencies[<extra>]` too.

O1: an edit that cannot change the image does not rename it — `[tool.*]` other than
`[tool.uv]`, the `dev`/`runtime` extras and their lock entries, comments, reordering and
reformatting the lock. O2: an edit to a closure entry (version, source, an artifact hash, its
own edges), to the closure's roots, to `[tool.uv]`, or to the recipe's bytes renames it.

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

#: The planted closure (see `_spec1092.PLANTED_LOCK`): both `split` entries, the marker-gated
#: `winonly`, and the extras' targets `eta` (alpha -> beta[speed]) and `delta` (box ->
#: gamma[fast]).
PLANTED_CLOSURE = sorted([
    ("alpha", "1.0.0"), ("beta", "2.0.0"), ("delta", "4.0.0"), ("eta", "6.0.0"),
    ("gamma", "3.0.0"), ("split", "1.0.0"), ("split", "2.0.0"), ("winonly", "9.0.0"),
])
#: In the planted lock and outside the closure: epsilon is only the target of extras nobody
#: asks for (beta[docs], gamma[slow]); devtool/devdep are `dev`'s, rtlib is `runtime`'s.
PLANTED_OUTSIDE = ("devdep", "devtool", "epsilon", "rtlib")

#: This checkout's core + `box` closure today (#1097 item 2). A relock that moves it moves this
#: list — on purpose: it is the review point for what enters the boundary.
REAL_CLOSURE_NAMES = sorted([
    "annotated-types", "duckdb", "pydantic", "pydantic-core", "pyyaml", "typing-extensions",
    "typing-inspection",
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


# ---- box_closure: the walk ---------------------------------------------------------------------
def test_box_closure_follows_every_edge_by_name_to_every_entry_ignoring_markers_and_versions_and_takes_each_edges_extras():
    """`box_closure(lock, "planted")` over the planted lock returns exactly the entries
    reachable from the root's `dependencies` + `optional-dependencies.box`, each the lock's own
    parsed dict: BOTH `split` entries (an edge reaches every entry with its name — the superset
    rule); `winonly`, whose edge's marker no Linux build satisfies (markers are ignored); `eta`
    through `alpha -> beta[speed]` and `delta` through `box -> gamma[fast]` (an edge's `extra`
    adds the target's `optional-dependencies[<extra>]`); and nothing else — not the root, not
    `epsilon` (only the target of extras nobody asks for), not the `dev`/`runtime` extras'
    entries. The `eta -> alpha` cycle ends the walk rather than looping it.

    An edge's `version` does not narrow it: with the root's two `split` edges replaced by ONE
    transitive edge carrying `version = "1.0.0"`, both `split` entries are still returned."""
    got = box_closure(copy.deepcopy(BASE_LOCK), ROOT)
    assert isinstance(got, list), type(got)
    assert _names(got) == PLANTED_CLOSURE, _names(got)
    for entry in got:
        assert entry in BASE_LOCK["package"], f"not the lock's own entry: {entry}"
    returned = {name for name, _ in _names(got)}
    for outside in (*PLANTED_OUTSIDE, ROOT):
        assert outside not in returned, f"{outside} is not in the core + box closure"

    def one_versioned_edge(lock: dict) -> None:
        root = _entry(lock, ROOT)
        root["dependencies"] = [d for d in root["dependencies"] if d["name"] != "split"]
        _entry(lock, "alpha")["dependencies"].append({
            "name": "split", "version": "1.0.0", "source": _REGISTRY,
            "marker": "python_full_version < '3.12'",
        })

    narrowed = _lock_edit(one_versioned_edge)
    assert _names(box_closure(narrowed, ROOT)) == PLANTED_CLOSURE, "an edge's version narrowed the walk"


def test_box_closure_of_this_checkouts_lock_is_exactly_the_core_and_box_closure_and_no_dev_or_runtime_package():
    """Over THIS checkout's `uv.lock`, with the root that `pyproject.toml`'s `[project].name`
    names, `box_closure` returns exactly annotated-types, duckdb, pydantic, pydantic-core,
    pyyaml, typing-extensions and typing-inspection, each at its locked version — and none of
    the packages the `dev` or `runtime` extras reach directly (pytest, ruff, mypy,
    pydantic-ai-slim, toons, …). `duckdb`, which `runtime` also names, is in: it is `box`'s."""
    pyproject = tomllib.loads((DEFENDER / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    root_name = pyproject["project"]["name"]
    got = box_closure(lock, root_name)
    names = sorted(e["name"] for e in got)
    assert names == REAL_CLOSURE_NAMES, names
    for entry in got:
        assert entry in lock["package"], f"not the lock's own entry: {entry['name']}"

    root = _entry(lock, root_name)
    extras = root.get("optional-dependencies", {})
    other = {d["name"] for extra in ("dev", "runtime") for d in extras.get(extra, [])}
    assert {"pytest", "ruff", "mypy", "pydantic-ai-slim", "toons"} <= other, sorted(other)
    assert sorted(other & set(names)) == ["duckdb"], sorted(other & set(names))


# ---- O1: what does NOT rename the image --------------------------------------------------------
def test_an_edit_that_cannot_change_the_image_does_not_rename_it(tmp_path):
    """Over the planted tree, none of these renames the image: in `pyproject.toml` a
    `[tool.ruff]` or `[tool.mypy]` edit, a comment, the `dev` or `runtime` extra changing, and a
    core or `box` requirement edited WITHOUT a relock (the key flow: the name holds, and every
    `--locked` build fails with uv's sentence instead); in `uv.lock` a version or artifact-hash
    change to an entry outside the closure (the dev tool, its dependency, the runtime library,
    `epsilon` behind extras nobody asks for), and a dev-extra relock that adds an entry, an edge
    under the root's `optional-dependencies.dev` and a `requires-dist` row; and a file outside
    the three inputs.

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
        _entry(lock, ROOT)["optional-dependencies"]["runtime"].append({"name": "epsilon"})

    holding: dict[str, dict] = {
        "a [tool.ruff] edit": {"pyproject": pyproject_edit("line-length = 100", "line-length = 120")},
        "a [tool.mypy] edit": {"pyproject": pyproject_edit("strict = true", "strict = false")},
        "a pyproject comment": {"pyproject": "# a comment\n" + PLANTED_PYPROJECT},
        "the dev extra, unlocked": {"pyproject": pyproject_edit('dev = ["devtool"]', 'dev = ["devtool", "newdev"]')},
        "the runtime extra, unlocked": {"pyproject": pyproject_edit('runtime = ["rtlib"]', 'runtime = ["rtlib>=8"]')},
        "a core requirement, unlocked": {"pyproject": pyproject_edit('"split",\n', '"split",\n    "requests>=2",\n')},
        "the box requirement, unlocked": {"pyproject": pyproject_edit('box = ["gamma[fast]"]', 'box = ["gamma[fast]>=3"]')},
        "the dev tool's entry": {"lock": _lock_edit(bump("devtool", "7.0.1"))},
        "the dev tool's dependency": {"lock": _lock_edit(bump("devdep", "0.1.1"))},
        "the runtime library's entry": {"lock": _lock_edit(bump("rtlib", "8.0.1"))},
        "an entry only unrequested extras reach": {"lock": _lock_edit(bump("epsilon", "5.0.1"))},
        "a dev-extra relock": {"lock": _lock_edit(dev_relock)},
        "a runtime-extra relock": {"lock": _lock_edit(runtime_relock)},
        # uv re-emitting the lock under a newer format revision, and a release bump of the
        # project itself (its own version, in pyproject and on the root entry): neither is
        # anything the image installs (#1097 round-2 adversary H5).
        "the lock's format revision": {"lock": _lock_edit(lambda lock: lock.__setitem__("revision", 4))},
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


# ---- O2: what DOES rename the image ------------------------------------------------------------
def test_an_edit_to_the_box_closure_its_roots_tool_uv_or_the_recipe_renames_the_image(tmp_path):
    """Each of these renames the image — `defender-box:v2-` stays, the 12 hex move, and no two
    edits collide: a closure entry's version (core `alpha`, marker-gated `winonly`, `eta`
    reached through `beta[speed]`), its `source`, one byte of an sdist or a wheel hash (`alpha`,
    `delta` reached through `gamma[fast]`), a closure entry gaining an edge — to an entry
    already in the closure (the entry is digested whole) or to one outside it (which the walk
    then pulls in) — and a change to a closure entry's own optional-dependencies even under an
    extra nobody asks for (the entry is digested whole); the root's `dependencies` gaining an
    edge to an already-reached entry, a `box` edge gaining a marker (the closure's entries
    unchanged: the ROOTS moved), a `box` edge asking for another extra, and `box` gaining an
    edge; `[tool.uv]` changing a value, gaining a key, or losing its only key; and one byte of
    `box.Dockerfile`.

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
        "a root dependency to an already-reached entry": _append([ROOT, "dependencies"], {"name": "beta"}),
        "a marker on the box edge": _set([ROOT, "optional-dependencies", "box", 0, "marker"], "sys_platform == 'linux'"),
        "another extra on the box edge": _set([ROOT, "optional-dependencies", "box", 0, "extra"], ["fast", "slow"]),
        "a new box edge": _append([ROOT, "optional-dependencies", "box"], {"name": "rtlib"}),
        # A closure entry's OWN edge marker: `alpha -> winonly` gated to linux instead of
        # win32 changes what a Linux build installs (#1097 round-2 adversary H2).
        "a closure entry's edge marker": _set(["alpha", "dependencies", 1, "marker"], "sys_platform == 'linux'"),
    }
    manifest_edits = {
        "[tool.uv] value": _replace_once(PLANTED_PYPROJECT, "package = false", "package = true"),
        "[tool.uv] key": _replace_once(PLANTED_PYPROJECT, "package = false\n", "package = false\ncompile-bytecode = true\n"),
        "[tool.uv] emptied": _replace_once(PLANTED_PYPROJECT, "package = false\n", ""),
        # Not only scalars: a list-valued key and a nested table change what a sync does
        # without touching the lock (#1097 round-2 adversary H4).
        "[tool.uv] list key": _replace_once(PLANTED_PYPROJECT, "package = false\n", 'package = false\nno-binary-package = ["gamma"]\n'),
        "[tool.uv] nested table": PLANTED_PYPROJECT + "\n[tool.uv.pip]\nno-build = true\n",
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

    # EVERY wheel's hash is digested, not the first: over an entry carrying two wheels, one
    # byte of the second moves the name (#1097 round-2 adversary H1 — the image's own
    # manylinux wheel is rarely wheels[0]).
    def two_wheels(lock: dict) -> None:
        wheel = dict(_entry(lock, "alpha")["wheels"][0])
        wheel["url"] = wheel["url"].replace("py3-none-any", "cp311-cp311-manylinux_2_17_x86_64")
        wheel["hash"] = "sha256:" + "5a" * 32
        _entry(lock, "alpha")["wheels"].append(wheel)
    two = _lock_edit(two_wheels)
    second_flipped = copy.deepcopy(two)
    wheel = _entry(second_flipped, "alpha")["wheels"][1]
    wheel["hash"] = _flip_hex(wheel["hash"])
    assert image_tag(_plant(tmp_path, "two-wheels", lock=two)) != image_tag(
        _plant(tmp_path, "two-wheels-flipped", lock=second_flipped)), "the second wheel's hash is not digested"

    # EVERY extra an edge asks for is walked, not the first: with `box -> gamma[fast, slow]`
    # `epsilon` (gamma's `slow` target) is in the closure, and its bump moves the name
    # (#1097 round-2 adversary H3).
    both = _lock_edit(_set([ROOT, "optional-dependencies", "box", 0, "extra"], ["fast", "slow"]))
    assert "epsilon" in {e["name"] for e in box_closure(both, ROOT)}, "the second extra was not walked"
    bumped = copy.deepcopy(both)
    _entry(bumped, "epsilon")["version"] = "5.0.1"
    assert image_tag(_plant(tmp_path, "both-extras", lock=both)) != image_tag(
        _plant(tmp_path, "both-extras-bumped", lock=bumped)), "a second extra's target did not rename"

    # A TOML datetime in [tool.uv] (uv's `exclude-newer`) is digested, not a crash.
    dated = _replace_once(PLANTED_PYPROJECT, "package = false\n", "package = false\nexclude-newer = 2026-01-01T00:00:00Z\n")
    assert image_tag(_plant(tmp_path, "dated", pyproject=dated)) not in (baseline, *moved.values())


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
    `pyproject.toml` — none renames the image (the key flow "a pytest bump plus relock: the
    name holds"). A pydantic bump, one wheel-hash byte of pydantic-core, a typing-inspection
    bump (reached only through pydantic), one sdist-hash byte of duckdb (`box`'s), a second
    `box` edge, and `[tool.uv]`'s `package` flipped each rename it."""
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
        "a duckdb sdist hash byte": {"lock_bytes": hash_byte("duckdb", "sdist")},
        "a second box edge": {"lock_bytes": _replace_once(
            lock_text, 'box = [\n    { name = "duckdb" },\n]', 'box = [\n    { name = "duckdb" },\n    { name = "pyyaml" },\n]')},
        "[tool.uv] package": {"manifest": _replace_once(pyproject_text, "package = false", "package = true")},
    }
    for i, (what, edit) in enumerate(moving.items()):
        assert tree(f"move-{i}", **edit) != baseline, f"{what} did not rename the image"


# ---- faults: never a fallback name --------------------------------------------------------------
def _without_root(lock: dict) -> None:
    lock["package"] = [p for p in lock["package"] if p["name"] != ROOT]


_FAULTS: dict[str, tuple[str, str | None, Callable[[Path], None]]] = {
    # case -> (the file the fault names, a word of the reason it must carry, how to break the tree)
    "box.Dockerfile missing": ("box.Dockerfile", None, lambda d: (d / "box.Dockerfile").unlink()),
    "uv.lock missing": ("uv.lock", None, lambda d: (d / "uv.lock").unlink()),
    "pyproject.toml missing": ("pyproject.toml", None, lambda d: (d / "pyproject.toml").unlink()),
    "uv.lock is not TOML": ("uv.lock", None, lambda d: d.joinpath("uv.lock").write_text(
        PLANTED_LOCK + "[[package]\n", encoding="utf-8")),
    "pyproject.toml is not TOML": ("pyproject.toml", None, lambda d: d.joinpath("pyproject.toml").write_text(
        PLANTED_PYPROJECT + "[project\n", encoding="utf-8")),
    "the lock holds no root entry": ("uv.lock", ROOT, lambda d: d.joinpath("uv.lock").write_text(
        _lock_toml(_lock_edit(_without_root)), encoding="utf-8")),
    "a closure entry's edge names no entry": ("uv.lock", "ghost", lambda d: d.joinpath("uv.lock").write_text(
        _lock_toml(_lock_edit(lambda lock: _entry(lock, "alpha")["dependencies"].append({"name": "ghost"}))),
        encoding="utf-8")),
    "the lock holds no [[package]] at all": ("uv.lock", ROOT, lambda d: d.joinpath("uv.lock").write_text(
        "version = 1\nrevision = 3\n", encoding="utf-8")),
    "pyproject.toml has no [project] name": ("pyproject.toml", None, lambda d: d.joinpath("pyproject.toml").write_text(
        _replace_once(PLANTED_PYPROJECT, 'name = "planted"\n', ""), encoding="utf-8")),
    "a box edge names no entry": ("uv.lock", "ghost", lambda d: d.joinpath("uv.lock").write_text(
        _lock_toml(_lock_edit(lambda lock: _entry(lock, ROOT)["optional-dependencies"]["box"].append(
            {"name": "ghost"}))), encoding="utf-8")),
}


@pytest.mark.parametrize("case", list(_FAULTS))
def test_a_tree_the_resolver_cannot_read_parse_or_walk_raises_image_input_error_naming_the_file(tmp_path, case):
    """`image_tag` over a tree it cannot fully read, parse or walk raises `ImageInputError` —
    never a name, and never a hash of the bytes it did read — whose message carries the tree
    and names the ONE file at fault: a missing input (each of the three in turn), a
    `uv.lock` or `pyproject.toml` that is not TOML, a lock with no entry for the root
    `[project].name` names (the message names the root), and an edge — from a closure entry or
    from the root's `box` extra — to a name the lock has no entry for (the message names it).

    Positive control, same test: the complete tree names an image. The resolver's constants
    are pinned exactly: `HASH_INPUTS` is the three files in read order, `RECIPE_VERSION` is
    `v2` (#1097's rename of every image, once)."""
    image = image_module()
    assert tuple(image.HASH_INPUTS) == HASH_INPUTS == ("box.Dockerfile", "uv.lock", "pyproject.toml")
    assert image.RECIPE_VERSION == "v2"

    named, reason, breaks = _FAULTS[case]
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
    if reason is not None:
        assert reason in message, (reason, message)
