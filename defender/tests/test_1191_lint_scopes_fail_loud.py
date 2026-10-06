"""#1191 — a lint whose fixed scope path has gone missing fails loud instead of scanning less.

O1  A lint run over THIS repo never passes while a fixed path that decides what it scans, or how
    strictly, is missing: `lint_tree_read_follows_link.LINT_TREE_READER_MODULES`,
    `lint_run_records.SWEEP_DIRS`, `lint_unguarded_tree_write.LINT_HARD_GATED_MODULES` (an entry
    ending `/` is a directory) and `lint_stage_prompt_frames`' default scope. Exit 2, naming the
    entry.
O2  The run-records lint never passes while a top-level `defender/` directory holding production
    `.py` (any `.py` the lint's own `_in_scope` filter keeps) is neither in `SWEEP_DIRS` nor
    spelled `defender/<name>` in `UNSCANNED_TREES` — exact spelling, so the bare repo-top-level
    `scripts` / `experiments` entries admit nothing under `defender/`. Exit 2, naming the dir.
O3  A run against a planted or partial root (`scope=` / `root=`) keeps today's tolerance.
O4  The escapes O1/O2 surface are closed: `runtime/branch/*` is back under the tree-read lint,
    `api/` is swept by the run-records lint and holds no record name, and the real lints do not
    go blind over the real repo.
D1  The shared helper is `_astlib.require_paths(root, entries)` (the design leaves the name open;
    this spec fixes it): `ScanBlind` naming EVERY missing root-relative entry, silent when all
    exist.

HOW O1 AND O2 ARE OBSERVED. "This repo" is the root a lint derives from its own file
(`Path(__file__).resolve().parents[2]`, as 53b7efec defines it). Loading the real lint and handing
it a scratch root takes the tolerant path, so it would mask the check. Each O1/O2 test instead
builds a MINI REPO under tmp: a copy of `scripts/lint/` (the lint, its siblings `_astlib.py`,
`_baseline.py`, `_gitscope.py`, its baseline) plus the data files the lint reads, and a
`defender/` laid out from the lint's OWN list constant, read off a fresh load of the real lint so
the test follows the list rather than today's entries. The copy's own file is then run as a child
(`python <tmp>/scripts/lint/<lint>.py`), the way CI runs it, so for that child tmp IS this repo.
Every negative is paired with a positive control on the same mini repo: untouched it exits 0, and a
planted violation is reported (so the scan ran and the layout is faithful).

`lint_run_records` imports the owner modules (`defender._run_paths`, ...): the child gets
`PYTHONPATH=<this checkout>`, and `defender` being a namespace package, the copy's own `defender/`
(which holds no owner module) is searched first and the owners come from this checkout. Its mini
repo therefore never holds a top-level `defender/*.py`.

RED UNTIL IMPLEMENTED: every O1/O2 negative (today a missing entry or an unlisted package scans
less and exits 0), the `require_paths` unit tests (no such helper), and the O4 census tests (the
tree-read list still names the dead `runtime/branch.py`; `api` is not swept). GREEN NOW and meant
to stay green: the positive controls, O3, the real-repo runs, and the demo's seeded artifacts.
"""
from __future__ import annotations

import ast
import datetime as _dt
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType

import pytest

from defender._run_paths import RUN_LAYOUT
from defender.tests._by_path import DEFENDER, LINT_DIR, WORKTREE, import_lint_lib, load_lint_gate

TREE_READ = "lint_tree_read_follows_link"
RUN_RECORDS = "lint_run_records"
TREE_WRITE = "lint_unguarded_tree_write"
STAGE_FRAMES = "lint_stage_prompt_frames"

#: The data files `lint_run_records.main` reads (its kinds registry and the page it renders).
RUN_RECORDS_DATA = ("defender/docs/run-records-kinds.tsv", "defender/docs/run-records.md")

#: The package `runtime/branch.py` was split into by #979.
BRANCH_PACKAGE = tuple(f"runtime/branch/{m}.py" for m in ("__init__", "_frontier", "_seed", "_spec"))

#: The file every mini-repo directory is given, so it holds a `.py` without shadowing a real
#: module name.
PLANTED = "planted_1191.py"
INERT = '"""Planted by #1191\'s mini repo; nothing to find here."""\n'

#: A link-following admit check: a tree-read finding in a listed module.
TREE_READ_PROBE = "def _probe_1191(p):\n    return p.is_file()\n"
#: A raw write: a tree-write finding, hard-gated in a listed module.
TREE_WRITE_PROBE = "def _probe_1191(p):\n    p.write_text('x', encoding='utf-8')\n"
#: A module-level interpolated boundary: a stage-frames finding.
STAGE_FRAMES_PROBE = 'GREETING_1191 = f"<{__name__}>"\n'


def record_name_probe() -> str:
    """A whole run-record name held as a literal: a run-records finding. Taken from the owner, not
    spelled here."""
    return f"NAME_1191 = {RUN_LAYOUT.report.name!r}\n"


# ======================================================================================
# Plumbing
# ======================================================================================


def _fresh(stem: str, suffix: str = "") -> ModuleType:
    """A fresh load of the REAL lint (this checkout's), for its constants or an in-process run."""
    return load_lint_gate(stem, name=f"{stem}_1191{suffix}")


def _write(path: Path, text: str = INERT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mini_repo(root: Path, stem: str, *, data: Iterable[str] = ()) -> Path:
    """`root` laid out as a repo holding a copy of `scripts/lint/` and `data` (repo-relative files
    copied from this checkout), with an empty `defender/`. Returns the copy of `<stem>.py`."""
    shutil.copytree(LINT_DIR, root / "scripts" / "lint",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for rel in data:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(WORKTREE / rel, dst)
    (root / "defender").mkdir(exist_ok=True)
    lint_file = root / "scripts" / "lint" / f"{stem}.py"
    assert lint_file.is_file(), f"no {stem}.py in {LINT_DIR}"
    return lint_file


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(WORKTREE)
    return env


def _run(lint_file: Path) -> subprocess.CompletedProcess[str]:
    """The lint file as CI runs it: `python <file>` from its repo's root, no arguments."""
    return subprocess.run(  # noqa: S603 — fixed argv built by the test
        [sys.executable, str(lint_file)], cwd=lint_file.parents[2], capture_output=True,
        encoding="utf-8", errors="replace", env=_child_env(), timeout=300, check=False)


def _said(result: subprocess.CompletedProcess[str]) -> str:
    return (f"rc={result.returncode}\n--- stdout ---\n{result.stdout[-1500:]}"
            f"\n--- stderr ---\n{result.stderr[-1500:]}")


def _rebind(lint_file: Path, name: str, expr: str) -> None:
    """Rebind module constant `name` to `expr` in the COPY, right after its own assignment, so
    everything below it in the copy (every def, every default) sees the new value."""
    text = lint_file.read_text(encoding="utf-8")
    end = None
    for stmt in ast.parse(text).body:
        targets = stmt.targets if isinstance(stmt, ast.Assign) else (
            [stmt.target] if isinstance(stmt, ast.AnnAssign) else [])
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            end = stmt.end_lineno
            break
    assert end is not None, f"{lint_file.name} has no module-level assignment to {name}"
    lines = text.splitlines(keepends=True)
    lines.insert(end, f"{name} = {expr}\n")
    lint_file.write_text("".join(lines), encoding="utf-8")


def _not_blind_when_each_removed(lint_file: Path, base: Path, entries: Iterable[str]) -> dict[str, str]:
    """For each entry (relative to `base`) in turn: move it out of the tree, run the copy, put it
    back. Returns entry -> what the run said, for every entry whose removal did NOT exit 2 with
    the entry named on stderr."""
    aside = lint_file.parents[2] / "aside_1191"
    aside.mkdir(exist_ok=True)
    wrong: dict[str, str] = {}
    for i, entry in enumerate(sorted(entries)):
        target = base / entry.rstrip("/")
        assert target.exists(), f"the mini repo lacks {entry}"
        held = aside / str(i)
        target.rename(held)
        try:
            result = _run(lint_file)
        finally:
            held.rename(target)
        if result.returncode != 2 or entry.rstrip("/") not in result.stderr:
            wrong[entry] = _said(result)
    return wrong


def _assert_clean(lint_file: Path, what: str) -> None:
    result = _run(lint_file)
    assert result.returncode == 0, f"control: the untouched {what} mini repo is not clean\n{_said(result)}"


def _expect(result: subprocess.CompletedProcess[str], rc: int, named: str, *, on: str,
            why: str) -> None:
    """The run exited `rc` and named `named` on stream `on` ("stdout" or "stderr")."""
    said = _said(result)
    assert result.returncode == rc, f"{why}\n{said}"
    assert named in getattr(result, on), f"{why}: {named!r} is not named on {on}\n{said}"


# ======================================================================================
# D1 — the shared helper
# ======================================================================================


def test_require_paths_is_silent_when_every_entry_exists(tmp_path):
    """`_astlib.require_paths(root, entries)` returns without raising when every root-relative
    entry exists: a file, a directory entry spelled with a trailing `/`, a nested file. Entries
    may come as any iterable (the lists are frozensets and tuples)."""
    astlib = import_lint_lib("_astlib")
    _write(tmp_path / "kept_module.py")
    _write(tmp_path / "kept_dir" / "inner.py")
    _write(tmp_path / "nested" / "deep" / "leaf.py")
    entries = ("kept_module.py", "kept_dir/", "nested/deep/leaf.py")
    astlib.require_paths(tmp_path, entries)
    astlib.require_paths(tmp_path, frozenset(entries))


def test_require_paths_names_every_missing_entry_and_only_those(tmp_path):
    """A missing entry is a blind scan: `require_paths` raises the `ScanBlind` the gates already
    turn into exit 2, and its message names EVERY missing entry — a file, a directory entry ending
    `/`, a nested file — not just the first, and names none that exists."""
    astlib = import_lint_lib("_astlib")
    _write(tmp_path / "kept_module.py")
    _write(tmp_path / "kept_dir" / "inner.py")
    entries = ("kept_module.py", "lost_module.py", "kept_dir/", "lost_dir/", "nested/lost_leaf.py")
    with pytest.raises(astlib.ScanBlind) as caught:
        astlib.require_paths(tmp_path, entries)
    message = str(caught.value)
    unnamed = [e for e in ("lost_module.py", "lost_dir", "nested/lost_leaf.py") if e not in message]
    assert not unnamed, f"missing entries the ScanBlind does not name: {unnamed}\n{message}"
    named = [e for e in ("kept_module.py", "kept_dir") if e in message]
    assert not named, f"the ScanBlind names entries that exist: {named}\n{message}"


def test_require_paths_names_a_missing_directory_entry(tmp_path):
    """A directory entry (trailing `/`) is checked as a path in its own right: present -> silent,
    absent -> `ScanBlind` naming it. (Whether a FILE at a `/` entry's spelling counts is not
    pinned.)"""
    astlib = import_lint_lib("_astlib")
    (tmp_path / "pkg").mkdir()
    astlib.require_paths(tmp_path, ["pkg/"])
    with pytest.raises(astlib.ScanBlind, match="gone_pkg"):
        astlib.require_paths(tmp_path, ["pkg/", "gone_pkg/"])


# ======================================================================================
# O1 — over this repo, a missing scope entry is exit 2 naming it
# ======================================================================================


def _tree_read_mini(root: Path) -> tuple[Path, list[str]]:
    lint_file = _mini_repo(root, TREE_READ)
    modules = sorted(_fresh(TREE_READ).LINT_TREE_READER_MODULES)
    for rel in modules:
        _write(root / "defender" / rel)
    return lint_file, modules


def test_o1_tree_read_control_scans_its_census(tmp_path):
    """POSITIVE CONTROL for the tree-read lint's mini repo (green now): every listed module
    present and inert -> exit 0; a link-following `is_file()` planted in a listed module -> exit 1
    naming it, so the copy really scans the census it was given."""
    lint_file, modules = _tree_read_mini(tmp_path)
    _assert_clean(lint_file, TREE_READ)
    _write(tmp_path / "defender" / modules[0], TREE_READ_PROBE)
    result = _run(lint_file)
    _expect(result, 1, modules[0], on="stdout",
            why=f"a planted is_file() in listed {modules[0]} was not reported")


def test_o1_tree_read_missing_census_module_is_blind(tmp_path):
    """Over this repo, each `LINT_TREE_READER_MODULES` entry whose module is gone makes the lint
    exit 2 naming it (RED until O1: today the module silently leaves the scan, exit 0). Every entry
    is removed in turn, so a check that looks at only some of the list fails here."""
    lint_file, modules = _tree_read_mini(tmp_path)
    _assert_clean(lint_file, TREE_READ)
    wrong = _not_blind_when_each_removed(lint_file, tmp_path / "defender", modules)
    assert not wrong, (
        f"{len(wrong)} of {len(modules)} census entries went missing without a blind scan "
        f"naming them:\n" + "\n".join(f"== {e}\n{w}" for e, w in wrong.items()))


def test_o1_tree_read_names_every_missing_census_module(tmp_path):
    """Two census modules gone at once: the blind scan names both, not just the first it met
    (RED until O1)."""
    lint_file, modules = _tree_read_mini(tmp_path)
    _assert_clean(lint_file, TREE_READ)
    gone = (modules[0], modules[-1])
    for rel in gone:
        (tmp_path / "defender" / rel).unlink()
    result = _run(lint_file)
    assert result.returncode == 2, f"two missing census modules did not blind the scan\n{_said(result)}"
    unnamed = [rel for rel in gone if rel not in result.stderr]
    assert not unnamed, f"the blind scan does not name {unnamed}\n{_said(result)}"


def _tree_write_mini(root: Path) -> tuple[Path, list[str]]:
    lint_file = _mini_repo(root, TREE_WRITE)
    entries = sorted(_fresh(TREE_WRITE).LINT_HARD_GATED_MODULES)
    for entry in entries:
        _write(root / "defender" / entry / PLANTED if entry.endswith("/")
               else root / "defender" / entry)
    return lint_file, entries


def test_o1_tree_write_control_hard_gates_its_census(tmp_path):
    """POSITIVE CONTROL for the tree-write lint's mini repo (green now): every hard-gated module
    (and a file in every hard-gated package) present and inert -> exit 0; a raw `write_text`
    planted in a hard-gated module -> exit 1, HARD-GATED, naming it."""
    lint_file, entries = _tree_write_mini(tmp_path)
    _assert_clean(lint_file, TREE_WRITE)
    module = next(e for e in entries if not e.endswith("/"))
    _write(tmp_path / "defender" / module, TREE_WRITE_PROBE)
    result = _run(lint_file)
    why = f"a raw write planted in hard-gated {module} was not hard-gated"
    _expect(result, 1, "HARD-GATED", on="stderr", why=why)
    _expect(result, 1, module, on="stderr", why=why)


def test_o1_tree_write_missing_hard_gated_entry_is_blind(tmp_path):
    """Over this repo, each `LINT_HARD_GATED_MODULES` entry that is gone — a module, or a package
    entry ending `/` — makes the lint exit 2 naming it (RED until O1: today a stale entry silently
    demotes the moved module from hard-gated to baseline-ratcheted)."""
    lint_file, entries = _tree_write_mini(tmp_path)
    _assert_clean(lint_file, TREE_WRITE)
    wrong = _not_blind_when_each_removed(lint_file, tmp_path / "defender", entries)
    assert not wrong, (
        f"{len(wrong)} of {len(entries)} hard-gated entries went missing without a blind scan "
        f"naming them:\n" + "\n".join(f"== {e}\n{w}" for e, w in wrong.items()))


def _run_records_mini(root: Path) -> tuple[Path, tuple[str, ...]]:
    lint_file = _mini_repo(root, RUN_RECORDS, data=RUN_RECORDS_DATA)
    sweep = tuple(_fresh(RUN_RECORDS).SWEEP_DIRS)
    for d in sweep:
        _write(root / "defender" / d / PLANTED)
    return lint_file, sweep


def test_o1_run_records_control_sweeps_its_dirs(tmp_path):
    """POSITIVE CONTROL for the run-records lint's mini repo (green now): every swept dir present
    with an inert module -> exit 0 (and the copied page is up to date); a record-name literal
    planted in a swept dir -> exit 1 naming the file."""
    lint_file, sweep = _run_records_mini(tmp_path)
    _assert_clean(lint_file, RUN_RECORDS)
    _write(tmp_path / "defender" / sweep[0] / PLANTED, record_name_probe())
    result = _run(lint_file)
    _expect(result, 1, f"{sweep[0]}/{PLANTED}", on="stdout",
            why=f"a record-name literal planted in swept {sweep[0]}/ was not reported")


def test_o1_run_records_missing_sweep_dir_is_blind(tmp_path):
    """Over this repo, each `SWEEP_DIRS` entry whose `defender/<d>` is gone makes the lint exit 2
    naming it (RED until O1: today `sweep_files` returns nothing for a missing dir and `main` has
    no exit-2 path at all, c10)."""
    lint_file, sweep = _run_records_mini(tmp_path)
    _assert_clean(lint_file, RUN_RECORDS)
    wrong = _not_blind_when_each_removed(lint_file, tmp_path / "defender", sweep)
    assert not wrong, (
        f"{len(wrong)} of {len(sweep)} swept dirs went missing without a blind scan naming "
        f"them:\n" + "\n".join(f"== {e}\n{w}" for e, w in wrong.items()))


def _stage_frames_mini(root: Path) -> tuple[Path, str]:
    lint_file = _mini_repo(root, STAGE_FRAMES)
    lint = _fresh(STAGE_FRAMES)
    scope = Path(lint.LEARNING).relative_to(lint.REPO_ROOT).as_posix()
    _write(root / scope / PLANTED)
    return lint_file, scope


def test_o1_stage_frames_control_scans_its_scope(tmp_path):
    """POSITIVE CONTROL for the stage-frames lint's mini repo (green now): its default scope
    present with an inert module -> exit 0; a module-level interpolated boundary planted there
    -> exit 1."""
    lint_file, scope = _stage_frames_mini(tmp_path)
    _assert_clean(lint_file, STAGE_FRAMES)
    _write(tmp_path / scope / PLANTED, STAGE_FRAMES_PROBE)
    result = _run(lint_file)
    _expect(result, 1, PLANTED, on="stdout",
            why=f"a module-level f-string planted in {scope}/ was not reported")


def test_o1_stage_frames_missing_default_scope_is_blind(tmp_path):
    """Over this repo, the stage-frames lint's default scope (`defender/learning`) gone makes it
    exit 2 naming it (RED until O1: today it scans nothing and exits 0, c12)."""
    lint_file, scope = _stage_frames_mini(tmp_path)
    _assert_clean(lint_file, STAGE_FRAMES)
    shutil.rmtree(tmp_path / scope)
    result = _run(lint_file)
    _expect(result, 2, Path(scope).name, on="stderr",
            why=f"the stage-frames lint ran over this repo without its scope {scope}")


# ======================================================================================
# O2 — run-records closure over defender/'s top-level directories
# ======================================================================================


def test_o2_unlisted_package_is_blind(tmp_path):
    """A top-level `defender/newpkg/` holding production `.py` that is neither swept nor declared
    unscanned makes the run-records lint exit 2 naming it — directly under it or nested deeper
    (RED until O2: today new code there is simply never scanned, the way `api/` escaped).
    Control: the same mini repo without it exits 0."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    _assert_clean(lint_file, RUN_RECORDS)
    planted = _write(tmp_path / "defender" / "newpkg" / "x.py")
    result = _run(lint_file)
    _expect(result, 2, "newpkg", on="stderr",
            why="an unlisted defender/newpkg/ holding .py did not blind the scan")
    shutil.rmtree(planted.parent)
    _write(tmp_path / "defender" / "otherpkg" / "sub" / "deep.py")
    result = _run(lint_file)
    _expect(result, 2, "otherpkg", on="stderr",
            why="an unlisted defender/otherpkg/ holding only nested .py did not blind the scan")


def test_o2_listing_the_package_settles_it(tmp_path):
    """POSITIVE CONTROLS (green now): the same `defender/newpkg/x.py` is accepted once the copy
    sweeps it (`SWEEP_DIRS` + `newpkg`: exit 0, and a record-name literal planted there is then
    reported, exit 1) or declares it unscanned (`UNSCANNED_TREES` + `defender/newpkg`: exit 0)."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    original = lint_file.read_text(encoding="utf-8")
    module = _write(tmp_path / "defender" / "newpkg" / "x.py")

    _rebind(lint_file, "SWEEP_DIRS", '(*SWEEP_DIRS, "newpkg")')
    _assert_clean(lint_file, f"{RUN_RECORDS} (newpkg swept)")
    _write(module, record_name_probe())
    result = _run(lint_file)
    _expect(result, 1, "newpkg/x.py", on="stdout",
            why="swept newpkg/ was not scanned: a planted record-name literal went unreported")

    _write(module)
    lint_file.write_text(original, encoding="utf-8")
    _rebind(lint_file, "UNSCANNED_TREES", '(*UNSCANNED_TREES, "defender/newpkg")')
    _assert_clean(lint_file, f"{RUN_RECORDS} (defender/newpkg declared unscanned)")


def test_o2_a_repo_top_level_unscanned_name_admits_nothing_under_defender(tmp_path):
    """The closure matches `defender/<name>` exactly: `UNSCANNED_TREES`' bare `experiments` and
    `scripts` name repo-top-level trees, so a `defender/experiments/` or (unswept)
    `defender/scripts/` holding `.py` still makes the lint exit 2 naming it (RED until O2).
    Controls: the untouched mini repo exits 0 with the same constants."""
    lint = _fresh(RUN_RECORDS)
    for bare in ("experiments", "scripts"):
        assert bare in lint.UNSCANNED_TREES, f"precondition: {lint.UNSCANNED_TREES}"
        assert f"defender/{bare}" not in lint.UNSCANNED_TREES, (
            f"precondition: UNSCANNED_TREES holds bare {bare!r} only: {lint.UNSCANNED_TREES}")
    assert "experiments" not in lint.SWEEP_DIRS, f"precondition: {lint.SWEEP_DIRS}"

    # Each case's mini repo root is named so its path cannot spell the dir under test.
    lint_file, _sweep = _run_records_mini(tmp_path / "case_a")
    _assert_clean(lint_file, RUN_RECORDS)
    _write(tmp_path / "case_a" / "defender" / "experiments" / "x.py")
    result = _run(lint_file)
    _expect(result, 2, "experiments", on="stderr",
            why="bare 'experiments' in UNSCANNED_TREES admitted defender/experiments/")

    lint_file, _sweep = _run_records_mini(tmp_path / "case_b")
    _assert_clean(lint_file, RUN_RECORDS)
    # The mini repo already holds defender/scripts/ (it is swept); stop sweeping it in the copy.
    _rebind(lint_file, "SWEEP_DIRS", 'tuple(d for d in SWEEP_DIRS if d != "scripts")')
    result = _run(lint_file)
    _expect(result, 2, "scripts", on="stderr",
            why="bare 'scripts' in UNSCANNED_TREES admitted an unswept defender/scripts/")


def test_o2_excluded_or_py_free_content_is_not_a_package(tmp_path):
    """A top-level directory whose `.py` the lint's own `_in_scope` filter drops (only under
    `tests`, `.venv`, `__pycache__`), a directory with no `.py`, and a top-level module are not
    unlisted packages: exit 0. Then, in the same mini repo, a real unlisted package does blind it
    (RED until O2 at that second step; the first guards against an over-eager closure)."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    d = tmp_path / "defender"
    _write(d / "tests" / "test_planted_1191.py")
    _write(d / ".venv" / "lib" / "site-packages" / "vendored.py")
    _write(d / "__pycache__" / "stray.py")
    _write(d / "fixtures_1191" / "tests" / "conftest.py")
    _write(d / "notes_1191" / "README.md", "not code\n")
    _write(d / "top_level_1191.py")
    _assert_clean(lint_file, f"{RUN_RECORDS} (excluded content only)")
    _write(d / "newpkg" / "x.py")
    result = _run(lint_file)
    _expect(result, 2, "newpkg", on="stderr",
            why="an unlisted defender/newpkg/ beside excluded content did not blind the scan")


def test_o2_a_dot_directory_is_seen(tmp_path):
    """The closure iterates `defender/`'s entries (`iterdir`, per the design, precisely so a
    dot-directory is not skipped): a `defender/.stash/` holding `.py` the `_in_scope` filter keeps
    makes the lint exit 2 naming it (RED until O2). Control: the mini repo without it exits 0."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    _assert_clean(lint_file, RUN_RECORDS)
    _write(tmp_path / "defender" / ".stash" / "x.py")
    result = _run(lint_file)
    _expect(result, 2, ".stash", on="stderr",
            why="an unlisted defender/.stash/ holding .py did not blind the scan")


# ======================================================================================
# O3 — a planted or partial root keeps today's tolerance
# ======================================================================================


def test_o3_tree_read_planted_root_missing_census_modules_is_still_checked(tmp_path, capsys):
    """`main(scope=<planted defender/>)` over a tree holding ONE census module (the rest absent)
    is not blind: a planted `is_file()` there -> exit 1 naming it; inert -> exit 0."""
    lint = _fresh(TREE_READ)
    one = sorted(lint.LINT_TREE_READER_MODULES)[0]
    scope = tmp_path / "defender"
    _write(scope / one, TREE_READ_PROBE)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 1
    assert one in capsys.readouterr().out
    _write(scope / one)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 0


def test_o3_tree_write_planted_root_missing_hard_gated_entries_is_still_checked(tmp_path, capsys):
    """`main(scope=<planted defender/>)` over a tree holding ONE hard-gated module (every other
    entry absent) is not blind: a raw write planted there -> exit 1, HARD-GATED; inert -> 0."""
    lint = _fresh(TREE_WRITE)
    one = sorted(e for e in lint.LINT_HARD_GATED_MODULES if not e.endswith("/"))[0]
    scope = tmp_path / "defender"
    _write(scope / one, TREE_WRITE_PROBE)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 1
    assert "HARD-GATED" in capsys.readouterr().err
    _write(scope / one)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 0


def test_o3_run_records_partial_root_is_swept_without_closure(tmp_path):
    """`sweep_files(<planted defender/>)` and `scan(<planted defender/>)` over a tree holding ONE
    swept dir (the rest absent) and an unlisted `newpkg/` raise nothing: neither the existence
    check nor the closure applies off this repo. The plant in the swept dir is still reported."""
    lint = _fresh(RUN_RECORDS)
    d = lint.SWEEP_DIRS[0]
    root = tmp_path / "defender"
    planted = _write(root / d / PLANTED, record_name_probe())
    _write(root / "newpkg" / "x.py")
    assert planted in lint.sweep_files(root)
    found = lint.scan(root, allow_list={})
    assert any(f.fingerprint.startswith(f"{d}/{PLANTED}") for f in found), (
        f"the plant in {d}/ was not reported over a partial root: {[f.display for f in found]}")


def test_o3_stage_frames_planted_scope_is_still_checked(tmp_path):
    """`main(argv, scope=<planted dir>)` over a scope outside this repo scans it as before: a
    module-level f-string -> exit 1; inert -> 0. (A planted scope that does not EXIST is not
    pinned: the design leaves open whether it keeps c12's exit 0.)"""
    lint = _fresh(STAGE_FRAMES)
    scope = tmp_path / "learning"
    _write(scope / PLANTED, STAGE_FRAMES_PROBE)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 1
    _write(scope / PLANTED)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 0


# ======================================================================================
# O4 — the escapes are closed, in the real repo
# ======================================================================================


def test_o4_tree_read_census_holds_the_branch_package_and_no_dead_path():
    """`LINT_TREE_READER_MODULES` lists all four modules `runtime/branch.py` was split into, and
    every entry exists under `defender/` (RED until D3: it still lists the dead
    `runtime/branch.py` and none of the four)."""
    modules = _fresh(TREE_READ).LINT_TREE_READER_MODULES
    assert all((DEFENDER / m).is_file() for m in BRANCH_PACKAGE), (
        f"precondition: the split package is on disk: {BRANCH_PACKAGE}")
    unlisted = [m for m in BRANCH_PACKAGE if m not in modules]
    dead = sorted(m for m in modules if not (DEFENDER / m).exists())
    assert not unlisted, f"tree-read census does not list these branch modules: {unlisted}"
    assert not dead, f"tree-read census entries naming no file under defender/: {dead}"


def test_o4_run_records_sweeps_api():
    """`SWEEP_DIRS` holds `api`, so the real sweep reaches `defender/api/` (RED until D3)."""
    lint = _fresh(RUN_RECORDS)
    assert "api" in lint.SWEEP_DIRS, f"api/ is not swept: {lint.SWEEP_DIRS}"
    swept = {p.relative_to(DEFENDER).as_posix() for p in lint.sweep_files(DEFENDER)}
    assert "api/demo.py" in swept, "the real sweep does not reach api/demo.py"


def test_o4_api_holds_no_run_record_name():
    """Swept, `defender/api/` yields no run-records finding (RED until D3: `api/demo.py` spells
    three record names). Driven on a fresh load whose `SWEEP_DIRS` is made to include `api`, so
    this half fails on the findings independently of the list edit; control: that sweep does
    reach `api/demo.py`, so the empty result is not an unscanned one."""
    lint = _fresh(RUN_RECORDS, "_api")
    lint.SWEEP_DIRS = tuple(dict.fromkeys((*lint.SWEEP_DIRS, "api")))
    assert DEFENDER / "api" / "demo.py" in lint.sweep_files(DEFENDER), "control: api/ not swept"
    found = [f.display for f in lint.scan(DEFENDER, allow_list={})
             if f.fingerprint.startswith("api/")]
    assert not found, "run-records findings under api/:\n" + "\n".join(found)


@pytest.mark.parametrize("stem", [TREE_READ, RUN_RECORDS, TREE_WRITE, STAGE_FRAMES])
def test_o4_real_lint_is_not_blind_over_this_repo(stem):
    """The real lint, run the way CI runs it over this checkout, does not exit 2: no scope entry
    of it is missing and no `defender/` package escapes the run-records closure (green now; red
    if the checks land before D3)."""
    result = _run(LINT_DIR / f"{stem}.py")
    assert result.returncode != 2, f"{stem} went blind over this repo\n{_said(result)}"


def test_o4_demo_still_seeds_the_run_record_names():
    """D3 changes how `api/demo.py` spells its seeded artifacts, not what they are: the completed
    investigation the demo seeds still lists the run's report, investigation and runtime page,
    by the owner's names (green now; guards the rewrite)."""
    from defender.api.demo import demo_deps

    tenant = "t-one"
    deps = demo_deps((tenant,), lambda: _dt.datetime(2026, 10, 6, 12, tzinfo=_dt.UTC))
    done = deps.investigations.get_investigation(tenant, f"{tenant}-inv-completed")
    assert done is not None, "the demo seeds no completed investigation"
    assert done.artifacts == [RUN_LAYOUT.report.name, RUN_LAYOUT.investigation.name,
                              RUN_LAYOUT.runtime_html.name], done.artifacts
