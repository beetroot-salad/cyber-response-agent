"""The image name digests the Dockerfile plus the lock's core + box dependency closure (box/_image.py::box_closure)."""
from __future__ import annotations

import copy
import json
import re
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest

from defender.tests.support.sandbox._spec1092 import (
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

PLANTED_CLOSURE = sorted([
    ("alpha", "1.0.0"), ("beta", "2.0.0"), ("delta", "4.0.0"), ("epsilon", "5.0.0"),
    ("eta", "6.0.0"), ("gamma", "3.0.0"), ("split", "1.0.0"), ("split", "2.0.0"),
    ("winonly", "9.0.0"),
])
PLANTED_OUTSIDE = ("devdep", "devtool", "rtlib")


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


# ---- O1: what does NOT rename the image --------------------------------------------------------
def test_an_edit_that_cannot_change_the_image_does_not_rename_it(tmp_path):
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


# ---- O2: what DOES rename the image ------------------------------------------------------------
def test_an_edit_to_the_box_closure_its_roots_tool_uv_or_the_recipe_renames_the_image(tmp_path):
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


# ---- the root: found by the normalised project name -------------------------------------------
def _renamed_root(new: str) -> Callable[[dict], None]:
    return lambda lock: _entry(lock, ROOT).__setitem__("name", new)


def _named(project_name: str) -> str:
    return _replace_once(PLANTED_PYPROJECT, 'name = "planted"\n', f'name = "{project_name}"\n')


def test_the_root_is_the_lock_entry_the_pep503_normalised_project_name_names(tmp_path):
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


# ---- faults: never a fallback name --------------------------------------------------------------
READ, USE = "cannot read", "cannot use"


def _without_root(lock: dict) -> None:
    lock["package"] = [p for p in lock["package"] if p["name"] != ROOT]


def _deep_header(table: str, depth: int = 20_000) -> str:
    """A TOML table header `depth` keys below `table` — it parses (tomllib builds dotted
    headers without recursion) into a value nested far past what `json` can encode, the
    canonical form's own recursion limit."""
    return f"\n[{table}." + ".".join(["x"] * depth) + "]\nb = 1\n"


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
