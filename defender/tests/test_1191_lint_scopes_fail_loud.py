"""#1191 — a lint whose fixed scope entry no longer selects code fails loud instead of scanning less.

O1  (as restated by design amendment 1) A lint run over THIS repo never passes while an entry of
    a fixed scope list SELECTS NONE OF THE FILES THE LINT SCANS — a vanished path, an emptied
    directory, a file entry now naming a directory: `lint_tree_read_follows_link`
    `.LINT_TREE_READER_MODULES`, `lint_run_records.SWEEP_DIRS`,
    `lint_unguarded_tree_write.LINT_HARD_GATED_MODULES`, `lint_tenant_env_reads.SWEPT` (an entry
    ending `/` selects every file under it, any other entry only the file it equals) and
    `lint_stage_prompt_frames`' default scope. Exit 2, naming the entry and no other.
O2  The run-records lint never passes while a top-level `defender/` directory holding production
    `.py` (any `.py` the lint's own `_in_scope` filter keeps) is neither in `SWEEP_DIRS` nor
    spelled `defender/<name>` in `UNSCANNED_TREES` — exact spelling, so the bare repo-top-level
    `scripts` / `experiments` entries admit nothing under `defender/`. Exit 2, naming the dir.
O3  A run against a planted or partial root (`scope=` / `root=`) keeps today's tolerance.
O4  The escapes O1/O2 surface are closed: `runtime/branch/` (D5: one package entry, so a future
    module of the package is covered too) is back under the tree-read lint, `api/` is swept by the
    run-records lint and holds no record name, and the real lints exit 0 over the real repo.
O5  Which files a lint scans does not depend on where the checkout lives (a parent dir named
    `tests` or `.venv`) or on gitignored local content; an untracked, not-ignored new file is
    still scanned.
O6  The run-records lint's written scope (`SCOPE_STATEMENT`) names exactly its swept dirs and its
    declared-unscanned trees — derived from the two lists, not kept by hand.
O7  A blind run-records scan (exit 2) writes nothing, `--render` included.
D1' The shared helpers in `_astlib` (names fixed by the amendment): `source_files(root,
    excluded)` -> the `.py` files under `root` as root-relative POSIX `str` paths, pruning
    directory NAMES in `excluded` below `root` (never its ancestors) and dropping what git
    ignores; `selects(entry, rel)`; `require_selected(root, real_root, entries, rels)`.
Design amendment 2 adds: O9 an unreadable directory under the scanned root is blind; O10 a
    source file whose name is not UTF-8 is blind (exit 2, the name escaped, no traceback) —
    superseding amendment 1's "returns it"; O11 a planted tree inside a git-ignored directory of
    the enclosing repo is listed in full; O12 the env-read lint names its dead entries; O13 a dead
    `defender/...` entry of run-records' `UNSCANNED_TREES` is blind; O14 the scope statement
    spells a repo-level unscanned entry "top-level <name>"; O15 tree-read parses only census
    modules and tree-write never parses test modules; O16 stage-frames' real scope is blind when
    it lists nothing, however its path is spelled; D8 `source_files(..., suffixes=(".py",))`.
    O8 (every lint lists through `source_files`) is `test_1191_one_listing.py`.

HOW O1 AND O2 ARE OBSERVED. "This repo" is the root a lint derives from its own file
(`Path(__file__).resolve().parents[2]`, as 53b7efec defines it). Loading the real lint and handing
it a scratch root takes the tolerant path, so it would mask the check. Each O1/O2 test instead
builds a MINI REPO under tmp: a copy of `scripts/lint/` (the lint, its siblings `_astlib.py`,
`_baseline.py`, `_gitscope.py`, its baseline) plus the data files the lint reads, and a
`defender/` laid out from the lint's OWN list constant, read off a fresh load of the real lint so
the test follows the list rather than today's entries. The copy's own file is then run as a child
(`python <tmp>/scripts/lint/<lint>.py`), the way CI runs it, so for that child tmp IS this repo.
Every negative is paired with a positive control on the same mini repo: untouched it exits 0, and a
planted violation is reported (so the scan ran and the layout is faithful). A mini repo has no
`.git`, takes no arguments and passes no `scope=`, so the same strictness is ALSO pinned over the
real checkout (a fresh private load of the real lint with one phantom entry, its own `main`), and
under `--update-baseline`.

`lint_run_records` imports the owner modules (`defender.run_repository`, ...): the child gets
`PYTHONPATH=<this checkout>`, and `defender` being a namespace package, the copy's own `defender/`
(which holds no owner module) is searched first and the owners come from this checkout. Its mini
repo therefore never holds a top-level `defender/*.py`.

Written in three commits: the spec (a73867c5), the adversary's holes (5de3d6ff), and design
amendment 1 (the D1' unit tests, O1's "selects nothing" cases, O5, O6, O7, D5, and the env-read
lint as a fifth surface). The `require_paths` unit tests of the first commit pinned only the
superseded existence check and are gone.
Design amendment 3 (supersedes D1''s and D11's filter-after-walk): a lint scans what git would
    put in the tree. Nothing inside a git-IGNORED dir can blind the listing or be listed (O9/O10
    now apply to what is listed: in a git repo, tracked or untracked, they still blind); a
    relative root lists what the absolute one does, anchored ignores included; a tracked module
    deleted from the working tree is not listed (O17).
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType

import pytest

from defender import _git
from defender.run_repository import RUN_LAYOUT
from defender.tests._by_path import DEFENDER, LINT_DIR, WORKTREE, import_lint_lib, load_lint_gate
from defender.tests._repo import seed_repo

TREE_READ = "lint_tree_read_follows_link"
RUN_RECORDS = "lint_run_records"
TREE_WRITE = "lint_unguarded_tree_write"
STAGE_FRAMES = "lint_stage_prompt_frames"
ENV_READS = "lint_tenant_env_reads"

#: Each list-scoped lint's fixed scope list, and the directory (relative to the repo root) its
#: entries are relative to.
SCOPE_LISTS: dict[str, tuple[str, str]] = {
    TREE_READ: ("LINT_TREE_READER_MODULES", "defender"),
    TREE_WRITE: ("LINT_HARD_GATED_MODULES", "defender"),
    ENV_READS: ("SWEPT", "."),
}

#: The stage-frames lint's default scope, fixed by the design (D4: the entry `learning/` under
#: `defender/`).
STAGE_FRAMES_SCOPE = "defender/learning"

#: The data files `lint_run_records.main` reads (its kinds registry and the page it renders).
RUN_RECORDS_DATA = ("defender/docs/run-records-kinds.tsv", "defender/docs/run-records.md")

#: The file every mini-repo directory is given, so it holds a `.py` without shadowing a real
#: module name.
PLANTED = "planted_1191.py"
#: Git-ignore rules naming nothing a lint could prune by spelling (an ignored `build/` can be
#: pruned by name without ever asking git).
IGNORES = "zz_ign_1191/\n*_ignored_1191.py\n"
INERT = '"""Planted by #1191\'s mini repo; nothing to find here."""\n'

#: A link-following admit check: a tree-read finding in a listed module.
TREE_READ_PROBE = "def _probe_1191(p):\n    return p.is_file()\n"
#: A raw write: a tree-write finding, hard-gated in a listed module.
TREE_WRITE_PROBE = "def _probe_1191(p):\n    p.write_text('x', encoding='utf-8')\n"
#: A module-level interpolated boundary: a stage-frames finding.
STAGE_FRAMES_PROBE = 'GREETING_1191 = f"<{__name__}>"\n'
#: A process-environment lookup: a tenant-env-read finding.
ENV_READS_PROBE = "import os\n\n\ndef _probe_1191():\n    return os.environ.get('X_1191')\n"


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


def _run(lint_file: Path, *args: str,
         env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """The lint file as CI runs it: `python <file>` from its repo's root (no arguments, unless a
    test passes the operator's `--update-baseline`; `env_extra` adds to the child's env)."""
    return subprocess.run(  # noqa: S603 — fixed argv built by the test
        [sys.executable, str(lint_file), *args], cwd=lint_file.parents[2], capture_output=True,
        encoding="utf-8", errors="replace", env={**_child_env(), **(env_extra or {})},
        timeout=300, check=False)


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


def _named(text: str, entries: Iterable[str]) -> list[str]:
    """The entries `text` names as WHOLE paths: as listed, with or without a `defender/` prefix
    and with or without a directory entry's trailing `/`, bounded on both sides by something that
    cannot continue a path. So `runtime/tools/` is not named by `runtime/tools_gather.py`, nor
    `_io.py` by `x/_io.py`."""
    named: list[str] = []
    for entry in entries:
        bare = re.escape(entry.rstrip("/"))
        if re.search(rf"(?<![\w./-])(?:defender/)?{bare}/?(?![\w./-])", text):
            named.append(entry)
    return named


def _not_blind_when_each_removed(lint_file: Path, base: Path, entries: Iterable[str]) -> dict[str, str]:
    """For each entry (relative to `base`) in turn: move it out of the tree, run the copy, put it
    back. Returns entry -> what the run said, for every entry whose removal did NOT exit 2 with
    the entry named on stderr and NO entry still present named there."""
    listed = sorted(entries)
    aside = lint_file.parents[2] / "aside_1191"
    aside.mkdir(exist_ok=True)
    wrong: dict[str, str] = {}
    for i, entry in enumerate(listed):
        target = base / entry.rstrip("/")
        assert target.exists(), f"the mini repo lacks {entry}"
        held = aside / str(i)
        target.rename(held)
        try:
            # Still present: every other entry whose path survived the move (an entry nested
            # under a removed package entry left with it).
            present = [e for e in listed if e != entry and (base / e.rstrip("/")).exists()]
            result = _run(lint_file)
        finally:
            held.rename(target)
        present_named = _named(result.stderr, present)
        if result.returncode != 2 or entry.rstrip("/") not in result.stderr or present_named:
            wrong[entry] = f"also names present entries {present_named}\n{_said(result)}"
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


def _selects(entry: str, rel: str) -> bool:
    """The amendment's selection rule, as this spec's own oracle (independent of
    `_astlib.selects`): equal, or `entry` ends in `/` and `rel` is under it."""
    return rel == entry or (entry.endswith("/") and rel.startswith(entry))


def _real_rels(base: Path, excluded: Iterable[str]) -> list[str]:
    """Every `.py` under `base` (root-relative POSIX), directory names in `excluded` pruned."""
    skip = set(excluded)
    rels: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in skip]
        rels += [(Path(dirpath) / f).relative_to(base).as_posix()
                 for f in filenames if f.endswith(".py")]
    return sorted(rels)


def _lay_out(base: Path, entries: Iterable[str]) -> None:
    """Each entry made real under `base`: a `/` entry as a package holding one inert module, any
    other entry as the inert file it names."""
    for entry in entries:
        _write(base / entry / PLANTED if entry.endswith("/") else base / entry)


def _file_entries(entries: Iterable[str]) -> list[str]:
    """The entries naming one module (`.py`), sorted."""
    return sorted(e for e in entries if e.endswith(".py"))


def _surface(root: Path, stem: str) -> tuple[Path, list[str], Path]:
    """A mini repo for a list-scoped lint, laid out from its own list: (copied lint file, the
    list's entries, the directory they are relative to)."""
    lint_file = _mini_repo(root, stem)
    name, under = SCOPE_LISTS[stem]
    entries = sorted(getattr(_fresh(stem), name))
    base = (root / under).resolve() if under == "." else root / under
    _lay_out(base, entries)
    return lint_file, entries, base


def _git_repo(root: Path, gitignore: str) -> None:
    """`root` made a git repo with `gitignore` as its `.gitignore`, everything in it staged — so
    a file written afterwards is untracked, and one under an ignored name is ignored."""
    _write(root / ".gitignore", gitignore)
    _git.git(["init", "-q", "-b", "main"], cwd=root)
    _git.git(["add", "-A"], cwd=root)


# ======================================================================================
# D1' — the shared listing and selection helpers (names fixed by design amendment 1)
# ======================================================================================


def test_source_files_lists_py_root_relative_pruning_excluded_names_below_root(tmp_path):
    """`_astlib.source_files(root, excluded)` lists the `.py` files under `root` as root-relative
    POSIX `str` paths (the `rel`s `selects` matches with a prefix), pruning directories whose NAME
    is in `excluded` — below `root` only: this root sits under ancestors named `tests` and `.venv`
    and every file of it is still listed. `excluded` may be any iterable of names."""
    astlib = import_lint_lib("_astlib")
    root = tmp_path / "tests" / ".venv" / "repo"
    for rel in ("a.py", "pkg/b.py", "pkg/sub/c.py", "pkg/__pycache__/d.py", "tests/t.py",
                "pkg/tests/u.py", "notes.md", "pkg/data.json", "pkg/e.pyc"):
        _write(root / rel)
    got = sorted(astlib.source_files(root, frozenset({"__pycache__", "tests"})))
    assert got == ["a.py", "pkg/b.py", "pkg/sub/c.py"], got
    got = sorted(astlib.source_files(root, ("__pycache__",)))
    assert got == ["a.py", "pkg/b.py", "pkg/sub/c.py", "pkg/tests/u.py", "tests/t.py"], got


def test_source_files_drops_what_git_ignores_and_keeps_untracked(tmp_path):
    """In a git repo, `source_files` drops what git IGNORES and keeps what git merely does not
    track: listed over a subdirectory of the repo (the way the lints list `defender/`), an ignored
    `build/` at any depth is gone, an unstaged new module is there."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    for rel in ("defender/kept.py", "defender/build/x.py", "defender/pkg/build/y.py",
                "defender/pkg/z.py"):
        _write(repo / rel)
    _git_repo(repo, "build/\n")
    _write(repo / "defender" / "new_untracked.py")
    got = sorted(astlib.source_files(repo / "defender", ()))
    assert got == ["kept.py", "new_untracked.py", "pkg/z.py"], got


def test_source_files_outside_a_git_repo_drops_nothing(tmp_path):
    """Outside a git repo nothing is dropped (git's answer fails open): the same layout and
    `.gitignore` without `git init` lists the `build/` modules too."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    for rel in ("defender/kept.py", "defender/build/x.py"):
        _write(repo / rel)
    _write(repo / ".gitignore", "build/\n")
    got = sorted(astlib.source_files(repo / "defender", ()))
    assert got == ["build/x.py", "kept.py"], got


@pytest.mark.parametrize(("entry", "rel", "selected"), [
    ("runtime/observe.py", "runtime/observe.py", True),
    ("runtime/tools/", "runtime/tools/x.py", True),
    ("runtime/tools/", "runtime/tools/sub/y.py", True),
    ("runtime/tools/", "runtime/tools_gather.py", False),
    ("runtime/driver", "runtime/driver/x.py", False),
    ("x.py", "a/x.py", False),
    ("runtime/observe.py", "runtime/observe.pyi.py", False),
])
def test_selects(entry, rel, selected):
    """`_astlib.selects(entry, rel)`: an entry selects the file it equals; an entry ending `/`
    selects every file under it and nothing that merely shares its spelling as a prefix; a
    directory named without the `/` selects nothing under it; there is no suffix match."""
    astlib = import_lint_lib("_astlib")
    assert bool(astlib.selects(entry, rel)) is selected, (entry, rel)


def test_require_selected_is_a_no_op_off_this_repo(tmp_path):
    """`_astlib.require_selected(root, real_root, entries, rels)` does nothing unless `root`
    resolves to `real_root`: a planted root may lack what the lists name."""
    astlib = import_lint_lib("_astlib")
    (tmp_path / "planted").mkdir()
    (tmp_path / "real").mkdir()
    astlib.require_selected(tmp_path / "planted", tmp_path / "real",
                            ("gone_module.py", "lost_pkg/"), [])


def test_require_selected_names_every_entry_that_selects_nothing(tmp_path):
    """Over the real root, `require_selected` raises the `ScanBlind` the gates turn into exit 2,
    naming EVERY entry that selects no `rel` — a vanished file, an empty package entry, a
    directory named without its `/` — and no entry that selects one. `root` is compared after
    resolving (`<real>/sub/..` is the real root)."""
    astlib = import_lint_lib("_astlib")
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    entries = ("kept_module.py", "kept_pkg/", "gone_module.py", "lost_pkg/", "dir_named_bare")
    rels = ["kept_module.py", "kept_pkg/x.py", "dir_named_bare/y.py", "other.py"]
    for root in (real, real / "sub" / ".."):
        with pytest.raises(astlib.ScanBlind) as caught:
            astlib.require_selected(root, real, entries, rels)
        message = str(caught.value)
        unnamed = [e for e in ("gone_module.py", "lost_pkg", "dir_named_bare") if e not in message]
        assert not unnamed, f"entries selecting nothing that the ScanBlind does not name: {unnamed}\n{message}"
        named = _named(message, ("kept_module.py", "kept_pkg/"))
        assert not named, f"the ScanBlind names entries that select files: {named}\n{message}"
    astlib.require_selected(real, real, ("kept_module.py", "kept_pkg/"), rels)


# ======================================================================================
# O1 — over this repo, a missing scope entry is exit 2 naming it
# ======================================================================================


def _tree_read_mini(root: Path) -> tuple[Path, list[str]]:
    lint_file, modules, _base = _surface(root, TREE_READ)
    return lint_file, modules


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


def _tree_write_mini(root: Path) -> tuple[Path, list[str]]:
    lint_file, entries, _base = _surface(root, TREE_WRITE)
    return lint_file, entries


def _run_records_mini(root: Path) -> tuple[Path, tuple[str, ...]]:
    lint_file = _mini_repo(root, RUN_RECORDS, data=RUN_RECORDS_DATA)
    lint = _fresh(RUN_RECORDS)
    sweep = tuple(lint.SWEEP_DIRS)
    for d in sweep:
        if d == lint.OWNER_PACKAGE:
            # #1105: every module in the owner package is an owner the lint imports by name, so
            # the package is the real one, not an inert plant.
            for src in sorted((DEFENDER / d).glob("*.py")):
                _write(root / "defender" / d / src.name, src.read_text(encoding="utf-8"))
        else:
            _write(root / "defender" / d / PLANTED)
    # D13: a `defender/...` entry of UNSCANNED_TREES must select a file too, so the mini repo
    # holds one under each.
    for tree in lint.UNSCANNED_TREES:
        if tree.startswith("defender/"):
            _write(root / tree / PLANTED)
    return lint_file, sweep


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
    scope = STAGE_FRAMES_SCOPE
    _write(root / scope / PLANTED)
    return lint_file, scope


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


# ======================================================================================
# O3 — a planted or partial root keeps today's tolerance
# ======================================================================================


# ======================================================================================
# O4 — the escapes are closed, in the real repo
# ======================================================================================


# ======================================================================================
# O1/O2 over the REAL checkout — strictness must not hinge on anything a mini repo lacks
# ======================================================================================
#
# The mini repos above have no `.git`, are run with no arguments, and never pass `scope=`. A check
# keyed on any of those (strict only without a `.git`, only when `argv is None`, only when
# `scope is None`) passes them all and is never strict where it matters. These tests load the
# REAL lint fresh (a private module object), give it one entry that names nothing, and call its
# own `main` over this checkout. Positive control in each: the unmodified fresh load exits 0.

#: An entry no checkout holds.
PHANTOM = "nope_1191"


def _main(lint: ModuleType, capsys: pytest.CaptureFixture[str], argv: list[str],
          **kw: object) -> tuple[int, str]:
    rc = lint.main(argv, **kw)
    return rc, capsys.readouterr().err


@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE])
def test_o1_update_baseline_over_a_blind_scan_keeps_the_baseline(tmp_path, stem):
    """In a mini repo, `--update-baseline` with a listed entry gone exits 2 naming it and leaves
    the copy's baseline byte-identical. Control: with the entry back, the same command exits 0
    and does rewrite that baseline (the mini repo has none of the real findings), so "identical"
    above means the update was refused, not that it had nothing to write."""
    build = _tree_read_mini if stem == TREE_READ else _tree_write_mini
    lint_file, entries = build(tmp_path)
    baseline = lint_file.with_name(f"{stem}_baseline.json")
    before = baseline.read_bytes()
    entry = entries[0]
    target = tmp_path / "defender" / entry.rstrip("/")
    held = tmp_path / "aside_1191"
    target.rename(held)
    result = _run(lint_file, "--update-baseline")
    held.rename(target)
    _expect(result, 2, entry.rstrip("/"), on="stderr",
            why=f"--update-baseline with {entry} gone was not refused as a blind scan")
    assert baseline.read_bytes() == before, (
        f"--update-baseline rewrote {baseline.name} from a blind scan\n{_said(result)}")
    control = _run(lint_file, "--update-baseline")
    assert control.returncode == 0, f"control: --update-baseline failed\n{_said(control)}"
    assert baseline.read_bytes() != before, "control: --update-baseline wrote nothing"


# ======================================================================================
# O2 — the closure is a rule over every name, matched exactly
# ======================================================================================


# ======================================================================================
# O4 / D3 — the escape fixes, by mechanism
# ======================================================================================


# ======================================================================================
# Design amendment 1 — O1 restated: an entry that EXISTS but selects nothing is blind
# ======================================================================================

#: Each lint's probe and the stream its finding lands on (tree-write's listed modules are
#: hard-gated, reported on stderr).
PROBES: dict[str, tuple[str, str]] = {
    TREE_READ: (TREE_READ_PROBE, "stdout"),
    TREE_WRITE: (TREE_WRITE_PROBE, "stderr"),
    ENV_READS: (ENV_READS_PROBE, "stdout"),
    RUN_RECORDS: (record_name_probe(), "stdout"),
    STAGE_FRAMES: (STAGE_FRAMES_PROBE, "stdout"),
}


def _listed(root: Path, stem: str) -> tuple[Path, list[str], Path]:
    """`_surface`, with run-records' swept dirs spelled as the package entries they are."""
    if stem == RUN_RECORDS:
        lint_file, sweep = _run_records_mini(root)
        return lint_file, [f"{d}/" for d in sweep], root / "defender"
    return _surface(root, stem)


def _plantable(root: Path, stem: str) -> tuple[Path, Path, str]:
    """A mini repo for `stem` and a module it scans: (copied lint file, that module, the name its
    finding is reported under)."""
    if stem == STAGE_FRAMES:
        lint_file, scope = _stage_frames_mini(root)
        return lint_file, root / scope / PLANTED, PLANTED
    lint_file, entries, base = _listed(root, stem)
    if stem == RUN_RECORDS:
        rel = f"{entries[0]}{PLANTED}"
        return lint_file, base / rel, rel
    rel = _file_entries(entries)[0]
    return lint_file, base / rel, rel


#: Per list-scoped lint, two entries that EXIST in the real checkout and select nothing: a
#: package dir named without its `/` (it holds `.py`), and a dir holding no `.py` at all.
REAL_IDLE: dict[str, tuple[str, str]] = {
    TREE_READ: ("runtime/branch", "docs/"),
    TREE_WRITE: ("runtime/driver", "docs/"),
    ENV_READS: ("defender/runtime/lead_zero", "defender/docs/"),
}


# ======================================================================================
# O5 — what a lint scans does not depend on where the checkout lives, or on ignored content
# ======================================================================================


# ======================================================================================
# O6 — the written scope is derived from the two lists
# ======================================================================================

#: Prints the copied run-records lint's SCOPE_STATEMENT (argv[1]: the copy's directory).
_READ_STATEMENT = ("import sys; sys.path.insert(0, sys.argv[1]); "
                   "import lint_run_records as m; print(m.SCOPE_STATEMENT)")


def _statement_of_copy(root: Path, sweep_expr: str, unscanned_expr: str) -> str:
    """The `SCOPE_STATEMENT` of a copy of the run-records lint whose `SWEEP_DIRS` and
    `UNSCANNED_TREES` are rebound to the given expressions, read off the copy in a child."""
    lint_file = _mini_repo(root, RUN_RECORDS, data=RUN_RECORDS_DATA)
    _rebind(lint_file, "SWEEP_DIRS", sweep_expr)
    _rebind(lint_file, "UNSCANNED_TREES", unscanned_expr)
    result = subprocess.run(  # noqa: S603 — fixed argv built by the test
        [sys.executable, "-c", _READ_STATEMENT, str(lint_file.parent)], cwd=root,
        capture_output=True, encoding="utf-8", errors="replace", env=_child_env(), timeout=120,
        check=False)
    assert result.returncode == 0, f"the copied lint did not load\n{_said(result)}"
    return result.stdout


def _spelled(text: str, path: str) -> bool:
    """`path` appears in `text` as a whole path, exactly as spelled (no prefix allowance: bare
    `scripts` is not spelled by `defender/scripts`)."""
    return re.search(rf"(?<![\w./-]){re.escape(path)}(?![\w./-])", text) is not None


# ======================================================================================
# O7 — a blind run-records scan writes nothing
# ======================================================================================


# ======================================================================================
# Holes the amendment adversary found in 0d415c26 (each passed by a cheating implementation)
# ======================================================================================


def test_source_files_follows_the_repos_own_ignore_rules(tmp_path, monkeypatch):
    """`source_files` drops exactly what git ignores, by the repo's OWN rules — not a list of
    usual names: here `.gitignore` ignores another directory name, a file glob, and re-includes
    one file by negation, and does NOT ignore `build/` or `venv/`. (Git's global and system
    config are switched off for this test so a developer's own excludes cannot change the
    answer.)"""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    for rel in ("defender/kept.py", "defender/build/b.py", "defender/scratch_1191/s.py",
                "defender/pkg/gen_1191.py", "defender/venv/v.py"):
        _write(repo / rel)
    _git_repo(repo, "scratch_1191/\n*_1191.py\n!defender/pkg/keep_1191.py\n")
    _write(repo / "defender" / "pkg" / "keep_1191.py")
    got = sorted(astlib.source_files(repo / "defender", ()))
    assert got == ["build/b.py", "kept.py", "pkg/keep_1191.py", "venv/v.py"], got


#: Where an item under test sits: outside any repo (the walk), or in a git repo, tracked
#: (staged with the layout) or untracked (written after it).
GIT_CASES = ("plain", "tracked", "untracked")


def _git_case(repo: Path, case: str, *, before, item) -> Path:
    """`repo` laid out by `before(repo)`, with `item(repo)` added per `case` (see GIT_CASES).
    Skips where the filesystem refuses the item (an undecodable name)."""
    before(repo)
    if case == "untracked":
        _git_repo(repo, IGNORES)
    try:
        item(repo)
    except (OSError, UnicodeError) as refused:
        pytest.skip(f"this filesystem refuses an undecodable name: {refused!r}")
    if case == "tracked":
        _git_repo(repo, IGNORES)
    return repo


def _undecodable_name() -> str:
    """`bad\\xff.py` as Python surfaces it (surrogate-escaped)."""
    return os.fsdecode(b"bad\xff.py")


def test_source_files_refuses_an_undecodable_file_name(tmp_path):
    """O10/D10 (supersedes amendment 1's "returns it"): a module whose name is not valid UTF-8 is
    refused loudly — `source_files` raises `ScanBlind` naming it in escaped (`ascii()`) form —
    outside a repo, and in a git repo whether the module is tracked or untracked (amendment 3:
    the git path lists it, and a LISTED name is still refused). Skipped where the filesystem
    refuses such a name."""
    astlib = import_lint_lib("_astlib")
    bad = _undecodable_name()
    for case in GIT_CASES:
        repo = _git_case(tmp_path / case, case, before=lambda r: _write(r / "defender" / "kept.py"),
                         item=lambda r: _write(r / "defender" / bad))
        with pytest.raises(astlib.ScanBlind) as caught:
            astlib.source_files(repo / "defender", ())
        message = str(caught.value)
        assert "bad\\udcff.py" in message, (
            f"{case}: the refusal does not name {ascii(bad)}: {message!r}")


def test_source_files_refuses_an_undecodable_directory_name(tmp_path):
    """O10/D10 on a DIRECTORY component: a module whose root-relative name is not valid UTF-8
    only because of the directory it sits in (`bad\\xffdir/m.py`, a valid basename) is refused
    the same way — `ScanBlind` naming the directory in escaped form — outside a repo, and in a
    git repo tracked or untracked."""
    astlib = import_lint_lib("_astlib")
    bad_dir = os.fsdecode(b"bad\xffdir")
    for case in GIT_CASES:
        repo = _git_case(tmp_path / case, case, before=lambda r: _write(r / "defender" / "kept.py"),
                         item=lambda r: _write(r / "defender" / bad_dir / "m_1191.py"))
        with pytest.raises(astlib.ScanBlind) as caught:
            astlib.source_files(repo / "defender", ())
        message = str(caught.value)
        assert "bad\\udcffdir" in message, (
            f"{case}: the refusal does not name {ascii(bad_dir)}: {message!r}")


# ======================================================================================
# Design amendment 2 — the shared listing's edges (D8–D11) and the review's findings (O12–O16)
# ======================================================================================


def test_source_files_lists_the_suffixes_it_is_asked_for(tmp_path):
    """D8: `source_files(root, excluded, suffixes=(".py",))` — the default lists `.py`; the
    text-file lints pass their own suffixes and get exactly those files."""
    astlib = import_lint_lib("_astlib")
    for rel in ("a.py", "b.md", "c.txt", "d.json", "sub/e.md", "sub/f.py"):
        _write(tmp_path / rel)
    assert sorted(astlib.source_files(tmp_path, ())) == ["a.py", "sub/f.py"]
    got = sorted(astlib.source_files(tmp_path, (), suffixes=(".md", ".txt")))
    assert got == ["b.md", "c.txt", "sub/e.md"], got


def _locked_dir(path: Path) -> Path:
    """`path` created holding one module, then made unreadable (mode 000). Skips the test where
    the mode is not enforced (running as root with the DAC capabilities)."""
    _write(path / "inside_1191.py")
    path.chmod(0)
    try:
        os.listdir(path)
    except PermissionError:
        return path
    path.chmod(0o755)
    pytest.skip("a mode-000 directory is still readable here (root): the mode is not enforced")


def test_source_files_is_blind_on_an_unreadable_directory(tmp_path):
    """O9/D9: a directory under the root that the listing cannot read raises `ScanBlind` naming
    it — never a silent skip of what it holds — outside a repo (the walk) and in a git repo,
    the dir tracked or untracked (amendment 3: git lists past it with only a warning)."""
    astlib = import_lint_lib("_astlib")
    for case in GIT_CASES:
        repo = _git_case(tmp_path / case, case, before=lambda r: _write(r / "defender" / "kept.py"),
                         item=lambda r: _write(r / "defender" / "pkg" / "locked_1191" / "inside_1191.py"))
        locked = _locked_dir(repo / "defender" / "pkg" / "locked_1191")
        try:
            with pytest.raises(astlib.ScanBlind, match="locked_1191"):
                astlib.source_files(repo / "defender", ())
        finally:
            locked.chmod(0o755)


def test_o9_an_unreadable_directory_blinds_a_lint(tmp_path, capsys):
    """O9 through a lint: the tree-write lint over a planted scope holding a mode-000 directory
    exits 2 naming it. Control: with the directory readable again, the same run exits 0."""
    lint = _fresh(TREE_WRITE)
    scope = tmp_path / "defender"
    _write(scope / "kept.py")
    locked = _locked_dir(scope / "locked_1191")
    try:
        rc = lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json")
        err = capsys.readouterr().err
    finally:
        locked.chmod(0o755)
    assert rc == 2, f"an unreadable directory under the scope did not blind the scan: rc={rc}\n{err}"
    assert "locked_1191" in err, f"the blind scan does not name the unreadable directory:\n{err}"
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 0


def test_o10_an_undecodable_module_name_blinds_a_lint_without_a_traceback(tmp_path):
    """O10 through a lint, on a strict-UTF-8 stdout/stderr: the tree-write lint over a mini repo
    holding a module named by the bytes `bad\\xff.py` (and carrying a raw write, so a lint that
    reported it would print the name) exits 2, shows the name escaped, and prints no traceback.
    Control: the same mini repo without it exits 0."""
    lint_file, _entries = _tree_write_mini(tmp_path)
    strict = {"PYTHONIOENCODING": "utf-8:strict"}
    clean = _run(lint_file, env_extra=strict)
    assert clean.returncode == 0, f"control: the mini repo is not clean\n{_said(clean)}"
    bad = _undecodable_name()
    try:
        _write(tmp_path / "defender" / bad, TREE_WRITE_PROBE)
    except (OSError, UnicodeError) as refused:
        pytest.skip(f"this filesystem refuses an undecodable name: {refused!r}")
    result = _run(lint_file, env_extra=strict)
    assert "Traceback" not in result.stderr, f"the lint crashed on the name\n{_said(result)}"
    _expect(result, 2, "bad\\udcff.py", on="stderr",
            why="a module whose name is not UTF-8 did not blind the scan with the name escaped")


def test_source_files_lists_a_tree_inside_an_ignored_directory_in_full(tmp_path):
    """O11/D11: a planted tree that sits inside a git-ignored directory of the enclosing repo
    (`<repo>/build/planted`, `build/` ignored) is listed in full — the root being ignored does
    not make everything under it vanish. (A dir ignored BELOW the root still is: amendment 1.)"""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "kept.py")
    _git_repo(repo, "build/\n")
    planted = repo / "build" / "planted"
    for rel in ("a.py", "sub/b.py"):
        _write(planted / rel)
    assert sorted(astlib.source_files(planted, ())) == ["a.py", "sub/b.py"]


def test_source_files_drops_ignored_modules_under_a_root_git_does_not_ignore(tmp_path):
    """D11's exception is for a ROOT git ignores, asked of git — not inferred from the files: a
    root that is NOT ignored, every module of which happens to be ignored (generated modules,
    `*_gen_1191.py`), lists nothing. Control: the same tree with one module that is not ignored
    lists just that one."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "README.md", "x\n")
    _git_repo(repo, "*_gen_1191.py\n")
    _write(repo / "defender" / "a_gen_1191.py")
    _write(repo / "defender" / "pkg" / "b_gen_1191.py")
    assert astlib.source_files(repo / "defender", ()) == []
    _write(repo / "defender" / "pkg" / "kept_1191.py")
    assert astlib.source_files(repo / "defender", ()) == ["pkg/kept_1191.py"]


def test_o11_a_lint_over_a_tree_inside_an_ignored_directory_reports_its_plant(tmp_path, capsys):
    """O11 through a lint: the tree-write lint with `scope=<repo>/build/planted` (`build/`
    ignored by the enclosing repo) reports the raw write planted there (exit 1, named)."""
    repo = tmp_path / "repo"
    _write(repo / "kept.py")
    _git_repo(repo, "build/\n")
    scope = repo / "build" / "planted"
    _write(scope / "pkg_1191" / "m.py", TREE_WRITE_PROBE)
    lint = _fresh(TREE_WRITE)
    rc = lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json")
    out = capsys.readouterr().out
    assert rc == 1, f"the plant under an ignored enclosing dir went unreported: rc={rc}\n{out}"
    assert "pkg_1191/m.py" in out, f"the finding does not name the plant:\n{out}"


#: A module that does not parse.
UNPARSEABLE = "def broken_1191(:\n"
#: Test-module shapes outside `tests/` (the lints' own notion: `test_*.py`, `*_test.py`,
#: `conftest.py`).
TEST_MODULE_NAMES = ("test_broken_1191.py", "broken_1191_test.py", "conftest.py")


#: Runs the copied stage-frames lint's `main([], scope=argv[2], baseline_path=argv[3])` (argv[1]:
#: the copy's directory) and exits with its status.
_STAGE_FRAMES_MAIN = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                      "import lint_stage_prompt_frames as m; "
                      "sys.exit(m.main([], scope=Path(sys.argv[2]), baseline_path=Path(sys.argv[3])))")


# ======================================================================================
# Design amendment 3 — what git would put in the tree (O5 restated, O17)
# ======================================================================================


def _ignored_tree(repo: Path) -> Path:
    """A git repo ignoring IGNORES whose `defender/` holds a kept module, a module in a package,
    and nothing else that is source. Returns `defender/`."""
    _write(repo / "defender" / "kept.py")
    _write(repo / "defender" / "pkg" / "a.py")
    _git_repo(repo, IGNORES)
    return repo / "defender"


def test_source_files_never_enters_an_ignored_dir_holding_undecodable_names(tmp_path):
    """O5 restated (a)/D17: in a git repo, non-UTF-8 names that git ignores — a module and a
    directory inside an ignored `zz_ign_1191/` (top-level and nested), and a module whose ignored
    file NAME is not UTF-8 — are not listed and do not make the listing blind: O10 applies only
    to what is listed."""
    astlib = import_lint_lib("_astlib")
    root = _ignored_tree(tmp_path / "repo")
    bad_file, bad_dir = os.fsdecode(b"bad\xff_1191.py"), os.fsdecode(b"bad\xffdir_1191")
    try:
        for ignored in ("zz_ign_1191", "pkg/zz_ign_1191"):
            _write(root / ignored / bad_file)
            _write(root / ignored / bad_dir / "m_1191.py")
        _write(root / "pkg" / os.fsdecode(b"bad\xff_ignored_1191.py"))
    except (OSError, UnicodeError) as refused:
        pytest.skip(f"this filesystem refuses an undecodable name: {refused!r}")
    assert astlib.source_files(root, ()) == ["kept.py", "pkg/a.py"]


def test_source_files_never_enters_an_ignored_unreadable_dir(tmp_path):
    """O5 restated (a)/D17: in a git repo, a mode-000 directory inside an ignored `zz_ign_1191/`
    is never entered: no `ScanBlind`, nothing from it listed. Skipped where the mode is not
    enforced (root with the DAC capabilities)."""
    astlib = import_lint_lib("_astlib")
    root = _ignored_tree(tmp_path / "repo")
    locked = _locked_dir(root / "zz_ign_1191" / "locked_1191")
    try:
        listed = astlib.source_files(root, ())
    finally:
        locked.chmod(0o755)
    assert listed == ["kept.py", "pkg/a.py"]


_LIST_FROM_CWD = ("import json, sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                  "import _astlib; print(json.dumps(_astlib.source_files(Path(sys.argv[2]), ())))")


@pytest.mark.parametrize("spelled", ["defender", "./defender", "defender/pkg/.."])
def test_source_files_from_a_relative_root_keeps_anchored_ignores(tmp_path, spelled):
    """O5 restated (c)/D17 (r2): `source_files` handed a RELATIVE root, from the repo's top as
    cwd, lists what it lists from the absolute root — an anchored ignore (`/defender/runs/`)
    still drops `runs/`. Run in a child process so the cwd is the fixture repo's."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "defender" / "kept.py")
    _write(repo / "defender" / "pkg" / "a.py")
    _write(repo / "defender" / "runs" / "r1" / "b.py")
    _git_repo(repo, "/defender/runs/\n")
    absolute = astlib.source_files(repo / "defender", ())
    assert absolute == ["kept.py", "pkg/a.py"], f"control: the absolute root lists {absolute}"
    result = subprocess.run(  # noqa: S603 — fixed argv built by the test
        [sys.executable, "-c", _LIST_FROM_CWD, str(LINT_DIR), spelled], cwd=repo,
        capture_output=True, encoding="utf-8", env=_child_env(), timeout=120, check=False)
    assert result.returncode == 0, _said(result)
    assert json.loads(result.stdout) == absolute, (
        f"source_files({spelled!r}) from {repo} lists differently from the absolute root\n"
        f"{_said(result)}")


@pytest.mark.parametrize("committed", [False, True], ids=["staged", "committed"])
def test_source_files_skips_a_tracked_module_deleted_from_the_tree(tmp_path, committed):
    """O17/D17: a tracked module (staged, or committed) deleted from the working tree but not
    from the index is not listed — the listing never names a file that is no longer there."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "defender" / "kept.py")
    gone = _write(repo / "defender" / "pkg" / "gone_1191.py")
    if committed:
        seed_repo(repo)
    else:
        _git_repo(repo, IGNORES)
    gone.unlink()
    assert astlib.source_files(repo / "defender", ()) == ["kept.py"]


# --- amendment 3, the adversary's holes: what IS in the tree ------------------------------


def _git_tree(repo: Path) -> Path:
    """A git repo ignoring IGNORES with `defender/kept.py` and `defender/pkg/a.py` staged."""
    _write(repo / "defender" / "kept.py")
    _write(repo / "defender" / "pkg" / "a.py")
    _git_repo(repo, IGNORES)
    return repo / "defender"


def test_source_files_lists_tracked_modules_git_would_ignore(tmp_path):
    """O5 restated ("tracked files plus untracked files that are not ignored"): a module
    force-added (`git add -f`) under an ignored dir, and a tracked module whose own name is
    ignored, are TRACKED — listed."""
    astlib = import_lint_lib("_astlib")
    root = _git_tree(tmp_path / "repo")
    _write(root / "zz_ign_1191" / "forced_1191.py")
    _write(root / "pkg" / "forced_ignored_1191.py")
    _git.git(["add", "-f", "defender/zz_ign_1191/forced_1191.py",
              "defender/pkg/forced_ignored_1191.py"], cwd=tmp_path / "repo")
    assert astlib.source_files(root, ()) == [
        "kept.py", "pkg/a.py", "pkg/forced_ignored_1191.py", "zz_ign_1191/forced_1191.py"]


#: Valid UTF-8 names git C-quotes when not asked for `-z` output.
QUOTED_NAMES = ('q"uote_1191.py', "back\\slash_1191.py", "tab\t_1191.py")


@pytest.mark.parametrize("case", ["tracked", "untracked"])
def test_source_files_lists_names_git_would_quote(tmp_path, case):
    """O5 restated: a tracked or untracked, not-ignored module whose valid UTF-8 name git
    C-quotes (a `"`, a backslash, a tab) is in the tree, so listed as named."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "defender" / "kept.py")
    if case == "untracked":
        _git_repo(repo, IGNORES)
    for name in QUOTED_NAMES:
        _write(repo / "defender" / "pkg" / name)
    if case == "tracked":
        _git_repo(repo, IGNORES)
    assert astlib.source_files(repo / "defender", ()) == sorted(
        ["kept.py", *(f"pkg/{n}" for n in QUOTED_NAMES)])


@pytest.mark.parametrize("case", ["tracked", "untracked"])
def test_source_files_lists_a_dangling_symlink_module(tmp_path, case):
    """D17 (as corrected): only a path that is GONE is dropped. A dangling symlink module is
    there (`lstat` succeeds), so it is listed — tracked or untracked — and the gate that cannot
    read it says so (see the all-lints test)."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "defender" / "kept.py")
    (repo / "defender" / "pkg").mkdir(parents=True)
    if case == "untracked":
        _git_repo(repo, IGNORES)
    os.symlink("nowhere_1191.py", repo / "defender" / "pkg" / "dangling_1191.py")
    if case == "tracked":
        _git_repo(repo, IGNORES)
    assert astlib.source_files(repo / "defender", ()) == ["kept.py", "pkg/dangling_1191.py"]


def test_source_files_drops_a_tracked_module_whose_dir_became_a_file(tmp_path):
    """D17 (as corrected): `NotADirectoryError` is "gone" too — a tracked `pkg/nd_1191/m.py`
    whose directory was replaced by a plain file is not listed, and does not blind the
    listing."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    root = _git_tree(repo)
    _write(root / "pkg" / "nd_1191" / "m_1191.py")
    _git.git(["add", "-A"], cwd=repo)
    shutil.rmtree(root / "pkg" / "nd_1191")
    _write(root / "pkg" / "nd_1191", "now a file\n")
    assert astlib.source_files(root, ()) == ["kept.py", "pkg/a.py"]


@pytest.mark.parametrize("case", ["tracked", "untracked"])
def test_source_files_is_blind_on_a_listed_module_it_cannot_stat(tmp_path, case):
    """O9 + the D17 correction: a mode-0644 directory (its names readable, its entries not
    searchable) holding a tracked or untracked module — git lists the module with no warning,
    `lstat` then fails with EACCES, which is NOT "gone": `ScanBlind` naming it, never a silent
    drop. Skipped where the mode is not enforced (root with the DAC capabilities)."""
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "defender" / "kept.py")
    if case == "untracked":
        _git_repo(repo, IGNORES)
    _write(repo / "defender" / "pkg" / "rd_1191" / "m_1191.py")
    if case == "tracked":
        _git_repo(repo, IGNORES)
    rd = _unsearchable_dir(repo / "defender" / "pkg" / "rd_1191")
    try:
        with pytest.raises(astlib.ScanBlind, match="rd_1191"):
            astlib.source_files(repo / "defender", ())
    finally:
        rd.chmod(0o755)


def _unsearchable_dir(path: Path) -> Path:
    """`path` (an existing dir) made mode 0644: its names readable, its entries not statable.
    Skips the test where the mode is not enforced."""
    path.chmod(0o644)
    try:
        next(path.iterdir()).lstat()
    except PermissionError:
        return path
    path.chmod(0o755)
    pytest.skip("a mode-0644 directory is still searchable here (root): the mode is not enforced")


def test_source_files_prunes_nested_dirs_on_the_git_path(tmp_path):
    """D17 step 4 ("on either path ... drop any file under a directory `prune` rejects"): in a
    git repo, a venv (`pyvenv.cfg`) and a hidden dir NESTED below the top level, untracked and
    not ignored, are pruned as the walk prunes them. Control: their sibling module is kept, and
    outside a repo the same `prune` gives the same listing."""
    astlib = import_lint_lib("_astlib")

    def lay_out(root: Path) -> None:
        _write(root / "learning" / "site_env" / "pyvenv.cfg", "home = /usr/bin\n")
        _write(root / "learning" / "site_env" / "lib" / "probe.py")
        _write(root / "learning" / ".hidden_1191" / "probe.py")
        _write(root / "learning" / "swept.py")

    def prune(d: Path) -> bool:
        return d.name.startswith(".") or (d / "pyvenv.cfg").is_file()

    root = _git_tree(tmp_path / "repo")
    lay_out(root)
    want = ["kept.py", "learning/swept.py", "pkg/a.py"]
    assert astlib.source_files(root, (), prune=prune) == want
    plain = tmp_path / "plain" / "defender"
    _write(plain / "kept.py")
    _write(plain / "pkg" / "a.py")
    lay_out(plain)
    assert astlib.source_files(plain, (), prune=prune) == want


def test_source_files_refuses_only_kept_undecodable_names(tmp_path):
    """D17 step 4 (O10 limited to KEPT paths): in a git repo, an untracked, not-ignored non-`.py`
    file with a bad name, and a bad `.py` name inside an excluded dir, are not kept — a `.py`
    listing is not blind. Control: the same bad name kept (a `.md` listing) is refused."""
    astlib = import_lint_lib("_astlib")
    root = _git_tree(tmp_path / "repo")
    try:
        _write(root / "pkg" / os.fsdecode(b"notes\xff_1191.md"))
        _write(root / "skipme_1191" / os.fsdecode(b"bad\xff_1191.py"))
    except (OSError, UnicodeError) as refused:
        pytest.skip(f"this filesystem refuses an undecodable name: {refused!r}")
    assert astlib.source_files(root, ("skipme_1191",)) == ["kept.py", "pkg/a.py"]
    with pytest.raises(astlib.ScanBlind, match="notes"):
        astlib.source_files(root, ("skipme_1191",), suffixes=(".md",))
