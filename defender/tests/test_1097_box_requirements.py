"""#1097 — the box image is installed from, and named from, one committed export of the lock.

`defender/box-requirements.txt` is the output of `uv export --locked --no-dev --extra box
--no-emit-project --no-header --no-annotate` run in `defender/` (M1). ONE function owns that
command — `defender/scripts/box_image.py::export_requirements(defender_dir)` — and the
script's `export` subcommand rewrites the committed file from it. These tests pin:

  - M4 (O3): the committed list agrees with a fresh export of THIS tree, compared over parsed
    entries (name, version, marker, hash set) — never bytes, because CI's uv is unpinned and a
    formatting change in a newer uv must not turn CI red on its own. A missing `uv` FAILS here;
    nothing in this file skips.
  - the list is exactly the core + `box` closure of `uv.lock` (read with `tomllib`, an oracle
    independent of uv), at the locked versions and the lock's own artifact hashes.
  - `export_requirements` exports with `--locked` semantics: over a manifest the lock no longer
    satisfies it raises and leaves the lock's bytes alone.
  - the `export` subcommand writes exactly that text into ITS OWN tree's list, and a machine
    with no `uv` gets one stderr line and exit 1, not a traceback.

Real uv, real files, no fakes: the script is loaded by file path (it is stdlib-only and never
an importable `defender.*` module) and run as a subprocess over planted copies. The real tree
is only ever read — each test that could write checks it did not.
"""
from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from defender.tests._spec1092 import (
    BOX_REQUIREMENTS,
    DEFENDER,
    EXPORT_COMMAND,
    PLANTED_INPUT_BYTES,
    image_tag,
    load_box_image_script,
    lock_closure,
    parse_pinned,
    plant_real_manifests,
    plant_tree,
)

#: Packages the lock carries OUTSIDE the core + `box` closure: the dev toolchain and the
#: `runtime` extra. Each must be in `uv.lock` (so its absence from the list means something)
#: and none may be in the list.
DEV_PACKAGES = ("pytest", "ruff", "mypy")
RUNTIME_PACKAGES = ("pydantic-ai-slim", "toons", "anthropic")

#: A core dependency the lock ALREADY resolves (as a transitive of pydantic) but the
#: `defender` package entry does not list: adding it to `[project].dependencies` without a
#: relock makes the lock stale while every package it names is still in it. So no network and
#: no resolution is ever needed — `--frozen` exports it happily and a flagless export relocks
#: it offline; only `--locked` refuses (probed on uv 0.11.28: rc 2, rc 0, rc 0).
UNLOCKED_CORE_DEP = "annotated-types>=0.6"


def _snapshot(path: Path) -> bytes | None:
    return path.read_bytes() if path.is_file() else None


def _export(defender_dir: Path) -> str:
    """`export_requirements(defender_dir)` through the script's own door. The attribute is
    reached HERE, outside any `pytest.raises`, so a script without it fails on the lookup."""
    export = load_box_image_script().export_requirements
    return export(defender_dir)


def _export_tree(tmp_path: Path, name: str = "tree") -> Path:
    """A `defender/`-shaped tree holding copies of `scripts/box_image.py`, `runtime/box/
    _image.py`, the synthetic hash inputs, and the REAL `pyproject.toml` + `uv.lock`. Returns
    the defender dir."""
    defender_dir = plant_real_manifests(plant_tree(tmp_path / name))
    assert (defender_dir / "scripts" / "box_image.py").is_file(), "box_image.py was not copied"
    return defender_dir


def _unlock(defender_dir: Path) -> None:
    """Add `UNLOCKED_CORE_DEP` to the copy's `[project].dependencies` without relocking."""
    pyproject = defender_dir / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    edited = text.replace("\ndependencies = [\n", f'\ndependencies = [\n    "{UNLOCKED_CORE_DEP}",\n', 1)
    assert UNLOCKED_CORE_DEP in tomllib.loads(edited)["project"]["dependencies"], "edit missed"
    pyproject.write_text(edited, encoding="utf-8")


def _run_script(script: Path, *args: str, cwd: Path, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True,
        encoding="utf-8", cwd=str(cwd), env=env, timeout=120,
    )


# ---- M4: the drift check ------------------------------------------------------------------------
def test_the_committed_box_requirements_agree_with_a_fresh_locked_export_of_this_tree():
    """`export_requirements(DEFENDER)` — a fresh `uv export --locked` of this checkout —
    lists the same entries as the committed `defender/box-requirements.txt`: the same names,
    each at the same version, under the same marker, with the same set of artifact hashes.
    Compared PARSED, so wrapping, spacing, quoting and hash order may differ between uv
    versions; what would be installed may not. On a mismatch the failure names the
    regenerate command. A relock that moved the closure, or a `pyproject.toml` the lock no
    longer satisfies, fails here (the latter because the export is `--locked`). The export
    leaves `uv.lock` and `pyproject.toml` byte-for-byte as they were.

    # rejected: skipping when `uv` is absent — CI's `test` job has uv, and a drift check that
    # can silently not run is the #1095 stale-image hole again (#1097 M4)."""
    assert BOX_REQUIREMENTS.is_file(), (
        f"{BOX_REQUIREMENTS} is not committed — generate it with `{EXPORT_COMMAND}`"
    )
    manifests = {name: (DEFENDER / name).read_bytes() for name in ("uv.lock", "pyproject.toml")}
    fresh = parse_pinned(_export(DEFENDER))
    committed = parse_pinned(BOX_REQUIREMENTS.read_text(encoding="utf-8"))
    assert {name: (DEFENDER / name).read_bytes() for name in manifests} == manifests, (
        "the export rewrote a manifest"
    )
    if fresh != committed:
        changed = sorted(n for n in set(fresh) & set(committed) if fresh[n] != committed[n])
        pytest.fail(
            "defender/box-requirements.txt is stale against uv.lock — regenerate it with "
            f"`{EXPORT_COMMAND}` and commit the result. "
            f"only in the fresh export: {sorted(set(fresh) - set(committed))}; "
            f"only in the committed list: {sorted(set(committed) - set(fresh))}; "
            f"changed: {changed}"
        )


# ---- the list is the core + box closure, nothing else -------------------------------------------
def test_the_committed_box_requirements_list_exactly_the_core_and_box_closure_at_the_locked_pins():
    """The committed list names exactly the closure `uv.lock` resolves for the project's core
    dependencies plus the `box` extra (walked with `tomllib`, independent of uv) — `duckdb`
    and `pydantic` among them — each at the lock's version, each carrying at least one hash,
    and every hash one the lock records for that package's artifacts. It names none of the
    dev toolchain (`pytest`, `ruff`, `mypy`) and none of the `runtime` extra
    (`pydantic-ai-slim`, `toons`, `anthropic`), though the lock holds every one of them.

    # rejected: `--extra runtime` (byte-for-byte the host venv) — ships the LLM stack into the
    # boundary for no consumer (#1092 D1)."""
    assert BOX_REQUIREMENTS.is_file(), (
        f"{BOX_REQUIREMENTS} is not committed — generate it with `{EXPORT_COMMAND}`"
    )
    listed = parse_pinned(BOX_REQUIREMENTS.read_text(encoding="utf-8"))
    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    by_name = {p["name"]: p for p in lock["package"]}

    assert {"duckdb", "pydantic"} <= set(listed), sorted(listed)
    for name in (*DEV_PACKAGES, *RUNTIME_PACKAGES):
        assert name in by_name, f"{name} is not in uv.lock — the negative below proves nothing"
        assert name not in listed, f"{name} is outside the core + box closure but listed"

    assert {n: e.version for n, e in listed.items()} == lock_closure()
    for name, entry in listed.items():
        package = by_name[name]
        recorded = {w["hash"] for w in package.get("wheels", [])}
        if package.get("sdist"):
            recorded.add(package["sdist"]["hash"])
        assert entry.hashes, name
        assert entry.hashes <= recorded, (name, sorted(entry.hashes - recorded))


# ---- --locked -------------------------------------------------------------------------------------
def test_export_requirements_refuses_a_manifest_the_lock_does_not_satisfy_and_never_rewrites_the_lock(tmp_path):
    """Over a copy of this tree's `pyproject.toml` + `uv.lock` whose `[project].dependencies`
    gained a package without a relock, `export_requirements(copy)` raises with uv's reason
    (it names the lock) in its message, and the copy's `uv.lock` is byte-for-byte unchanged
    afterwards. Over an unedited copy it returns the same
    entries a fresh export of the real tree does — the positive control that the call works
    on a copy at all, so the raise is the lock's staleness and not the copy.

    The edit adds a package the lock already resolves, so the ONLY thing that can refuse it is
    the `--locked` freshness check: `--frozen` skips the check and exports the stale set, and
    a flagless export silently relocks (rewriting `uv.lock`) — both fail this test.

    # rejected: `--frozen` in the owner function (the #1095 finding, moved here by #1097 M4)."""
    good = plant_real_manifests(plant_tree(tmp_path / "good", copy_code=False))
    assert parse_pinned(_export(good)) == parse_pinned(_export(DEFENDER))

    stale = plant_real_manifests(plant_tree(tmp_path / "stale", copy_code=False))
    _unlock(stale)
    lock_before = (stale / "uv.lock").read_bytes()
    export = load_box_image_script().export_requirements
    with pytest.raises(Exception, match=r"(?i)lock") as caught:
        export(stale)
    assert not isinstance(caught.value, (AttributeError, NameError, TypeError)), caught.value
    assert (stale / "uv.lock").read_bytes() == lock_before, "the export rewrote the stale lock"


# ---- the `export` subcommand -------------------------------------------------------------------
def test_box_image_export_writes_the_fresh_export_into_its_own_trees_list_and_renames_the_image(tmp_path):
    """`python3 <tree>/defender/scripts/box_image.py export`, run from a directory that is
    not the tree, exits 0 and rewrites `<tree>/defender/box-requirements.txt` to exactly the
    text `export_requirements(<tree>/defender)` returns — the tree derived from the script's
    own location, the same as `tag`/`build` — leaving the tree's `uv.lock` and
    `pyproject.toml` untouched, writing nothing into the working directory and nothing into
    this checkout's own list. Because the list is a hash input, the export that changed it
    also changed the tree's image name.

    # rejected: a second copy of the `uv export` argv anywhere (a CI step, a Makefile) — the
    # command has ONE owner, which the drift check calls (#1097 M1)."""
    defender_dir = _export_tree(tmp_path)
    script = defender_dir / "scripts" / "box_image.py"
    listed = defender_dir / "box-requirements.txt"
    assert listed.read_bytes() == PLANTED_INPUT_BYTES["box-requirements.txt"]
    manifests = {n: (defender_dir / n).read_bytes() for n in ("uv.lock", "pyproject.toml")}
    real_list = _snapshot(BOX_REQUIREMENTS)
    tag_before = image_tag(defender_dir)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    out = _run_script(script, "export", cwd=elsewhere)
    assert out.returncode == 0, (out.returncode, out.stderr)
    assert "Traceback" not in out.stderr, out.stderr
    written = listed.read_text(encoding="utf-8")
    assert written == _export(defender_dir)
    assert {"duckdb", "pydantic"} <= set(parse_pinned(written)), written[:200]
    assert {n: (defender_dir / n).read_bytes() for n in manifests} == manifests
    assert list(elsewhere.iterdir()) == []
    assert _snapshot(BOX_REQUIREMENTS) == real_list, "the export wrote this checkout's list"
    assert image_tag(defender_dir) != tag_before, "a changed list did not rename the image"

    extra = _run_script(script, "export", "extra", cwd=elsewhere)
    assert extra.returncode == 2, (extra.returncode, extra.stderr)
    assert "usage" in extra.stderr.lower(), extra.stderr


def test_box_image_export_without_uv_on_path_prints_one_line_exits_1_and_leaves_the_list(tmp_path):
    """`export` on a machine with no `uv` on PATH (the interpreter itself found by absolute
    path) prints exactly one line on stderr, `box_image.py: …` naming uv, nothing on stdout,
    no traceback, exits 1, and leaves the tree's existing list byte-for-byte as it was — no
    truncated or half-written file. Positive control: the same tree with uv reachable
    exports (the previous test)."""
    defender_dir = _export_tree(tmp_path)
    script = defender_dir / "scripts" / "box_image.py"
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    out = _run_script(script, "export", cwd=tmp_path, env={"PATH": str(empty)})
    assert out.returncode == 1, (out.returncode, out.stderr)
    assert out.stdout == "", out.stdout
    assert "Traceback" not in out.stderr, out.stderr
    lines = out.stderr.strip().splitlines()
    assert len(lines) == 1, out.stderr
    assert lines[0].startswith("box_image.py:"), lines
    assert "uv" in lines[0], lines
    assert (defender_dir / "box-requirements.txt").read_bytes() == PLANTED_INPUT_BYTES["box-requirements.txt"]


def test_box_image_export_over_a_lock_its_manifest_outgrew_exits_1_and_leaves_the_list(tmp_path):
    """`export` over a tree whose `pyproject.toml` gained a dependency its `uv.lock` was not
    relocked for exits 1, prints nothing on stdout and no traceback, carries uv's reason (it
    names the lock) to stderr, and leaves both the tree's list and its `uv.lock` byte-for-byte
    as they were: a stale lock is never exported, and never silently relocked, by the
    command the drift check tells a developer to run."""
    defender_dir = _export_tree(tmp_path)
    _unlock(defender_dir)
    script = defender_dir / "scripts" / "box_image.py"
    lock_before = (defender_dir / "uv.lock").read_bytes()
    out = _run_script(script, "export", cwd=tmp_path)
    assert out.returncode == 1, (out.returncode, out.stderr)
    assert out.stdout == "", out.stdout
    assert "Traceback" not in out.stderr, out.stderr
    assert "lock" in out.stderr.lower(), out.stderr
    assert (defender_dir / "box-requirements.txt").read_bytes() == PLANTED_INPUT_BYTES["box-requirements.txt"]
    assert (defender_dir / "uv.lock").read_bytes() == lock_before
