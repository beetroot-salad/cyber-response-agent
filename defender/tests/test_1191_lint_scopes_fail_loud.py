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
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
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


def test_o1_tree_read_control_scans_its_census(tmp_path):
    """POSITIVE CONTROL for the tree-read lint's mini repo (green now): every listed module
    present and inert -> exit 0; a link-following `is_file()` planted in a listed module -> exit 1
    naming it, so the copy really scans the census it was given."""
    lint_file, modules = _tree_read_mini(tmp_path)
    _assert_clean(lint_file, TREE_READ)
    module = _file_entries(modules)[0]
    _write(tmp_path / "defender" / module, TREE_READ_PROBE)
    result = _run(lint_file)
    _expect(result, 1, module, on="stdout",
            why=f"a planted is_file() in listed {module} was not reported")


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
    files = _file_entries(modules)
    gone = (files[0], files[-1])
    for rel in gone:
        (tmp_path / "defender" / rel).unlink()
    result = _run(lint_file)
    assert result.returncode == 2, f"two missing census modules did not blind the scan\n{_said(result)}"
    unnamed = [rel for rel in gone if rel not in result.stderr]
    assert not unnamed, f"the blind scan does not name {unnamed}\n{_said(result)}"
    present_named = _named(result.stderr, [m for m in modules if m not in gone])
    assert not present_named, f"the blind scan also names present {present_named}\n{_said(result)}"


def _tree_write_mini(root: Path) -> tuple[Path, list[str]]:
    lint_file, entries, _base = _surface(root, TREE_WRITE)
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
    scope = STAGE_FRAMES_SCOPE
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
    one = _file_entries(lint.LINT_TREE_READER_MODULES)[0]
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
    module-level f-string -> exit 1; inert -> 0. (A scope that does not exist is
    `test_o1_stage_frames_missing_explicit_scope_is_blind`.)"""
    lint = _fresh(STAGE_FRAMES)
    scope = tmp_path / "learning"
    _write(scope / PLANTED, STAGE_FRAMES_PROBE)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 1
    _write(scope / PLANTED)
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 0


# ======================================================================================
# O4 — the escapes are closed, in the real repo
# ======================================================================================


def test_o4_tree_read_census_selects_the_whole_branch_package():
    """D5: the tree-read census selects every real `runtime/branch/*.py` (equal, or under a `/`
    entry), no census entry selects nothing over the real `defender/`, and a module ADDED to the
    package later is selected too — the package entry `runtime/branch/` covers future modules
    (shape B is no longer excused for a package entry)."""
    modules = _fresh(TREE_READ).LINT_TREE_READER_MODULES
    branch = [r for r in _real_rels(DEFENDER / "runtime" / "branch", {"__pycache__"})]
    assert branch, "precondition: defender/runtime/branch/ holds modules"
    unselected = [f"runtime/branch/{r}" for r in branch
                  if not any(_selects(e, f"runtime/branch/{r}") for e in modules)]
    assert not unselected, f"tree-read census does not select {unselected}"
    rels = _real_rels(DEFENDER, {".venv", "__pycache__"})
    idle = sorted(e for e in modules if not any(_selects(e, r) for r in rels))
    assert not idle, f"tree-read census entries selecting no file under defender/: {idle}"
    future = "runtime/branch/_new_module_1191.py"
    assert any(_selects(e, future) for e in modules), (
        f"a new module of the branch package ({future}) would be unscanned: the census lists the "
        f"package file by file, not as `runtime/branch/`")


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


@pytest.mark.parametrize("stem", [TREE_READ, RUN_RECORDS, TREE_WRITE, STAGE_FRAMES, ENV_READS])
def test_o4_real_lint_is_not_blind_over_this_repo(stem):
    """The real lint, run the way CI runs it over this checkout, exits 0: no scope entry of it is
    missing, no `defender/` package escapes the run-records closure, and what the re-listed
    modules report is baselined (red if the checks land before D3)."""
    result = _run(LINT_DIR / f"{stem}.py")
    assert result.returncode == 0, f"{stem} is not clean over this repo\n{_said(result)}"


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


def test_o1_real_checkout_tree_read_phantom_entry_is_blind(tmp_path, capsys):
    """Over this checkout, a census entry that names nothing makes the tree-read lint exit 2
    naming it, and only it — called as CI calls it (`main([])`) and with this repo's scope passed
    explicitly (`main([], scope=SCOPE)`). `--update-baseline` over the same blind scan exits 2
    and leaves the baseline byte-identical (it must not rewrite the ratchet from a scan that
    proved nothing)."""
    assert _fresh(TREE_READ, "_control").main([]) == 0, "control: the real lint is not clean"
    capsys.readouterr()
    lint = _fresh(TREE_READ, "_phantom")
    present = sorted(lint.LINT_TREE_READER_MODULES)
    phantom = f"{PHANTOM}.py"
    lint.LINT_TREE_READER_MODULES = frozenset({*present, phantom})
    for kw in ({}, {"scope": lint.SCOPE}):
        rc, err = _main(lint, capsys, [], **kw)
        assert rc == 2, f"main([], **{kw}) over this checkout with {phantom} listed: rc={rc}\n{err}"
        assert phantom in err, f"the blind scan does not name {phantom}:\n{err}"
        assert not _named(err, present), f"the blind scan names present entries:\n{err}"
    baseline = tmp_path / "baseline.json"
    shutil.copyfile(lint.BASELINE_PATH, baseline)
    before = baseline.read_bytes()
    rc, err = _main(lint, capsys, ["--update-baseline"], baseline_path=baseline)
    assert rc == 2, f"--update-baseline over a blind scan: rc={rc}\n{err}"
    assert baseline.read_bytes() == before, "--update-baseline rewrote the baseline from a blind scan"


def test_o1_real_checkout_tree_write_phantom_entry_is_blind(tmp_path, capsys):
    """Over this checkout, a hard-gated package entry (`<name>/`) that names nothing makes the
    tree-write lint exit 2 naming it, and only it — via `main([])` and `main([], scope=SCOPE)`;
    `--update-baseline` exits 2 and leaves the baseline byte-identical."""
    assert _fresh(TREE_WRITE, "_control").main([]) == 0, "control: the real lint is not clean"
    capsys.readouterr()
    lint = _fresh(TREE_WRITE, "_phantom")
    present = sorted(lint.LINT_HARD_GATED_MODULES)
    phantom = f"{PHANTOM}/"
    lint.LINT_HARD_GATED_MODULES = frozenset({*present, phantom})
    for kw in ({}, {"scope": lint.SCOPE}):
        rc, err = _main(lint, capsys, [], **kw)
        assert rc == 2, f"main([], **{kw}) over this checkout with {phantom} listed: rc={rc}\n{err}"
        assert PHANTOM in err, f"the blind scan does not name {phantom}:\n{err}"
        assert not _named(err, present), f"the blind scan names present entries:\n{err}"
    baseline = tmp_path / "baseline.json"
    shutil.copyfile(lint.BASELINE_PATH, baseline)
    before = baseline.read_bytes()
    rc, err = _main(lint, capsys, ["--update-baseline"], baseline_path=baseline)
    assert rc == 2, f"--update-baseline over a blind scan: rc={rc}\n{err}"
    assert baseline.read_bytes() == before, "--update-baseline rewrote the baseline from a blind scan"


def test_o1_real_checkout_run_records_phantom_sweep_dir_is_blind(capsys):
    """Over this checkout, a `SWEEP_DIRS` entry whose `defender/<d>` does not exist makes
    `main([])` exit 2 naming it, and no swept dir that exists."""
    assert _fresh(RUN_RECORDS, "_control").main([]) == 0, "control: the real lint is not clean"
    capsys.readouterr()
    lint = _fresh(RUN_RECORDS, "_phantom")
    present = list(lint.SWEEP_DIRS)
    lint.SWEEP_DIRS = (*present, PHANTOM)
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"main([]) over this checkout with {PHANTOM} swept: rc={rc}\n{err}"
    assert PHANTOM in err, f"the blind scan does not name {PHANTOM}:\n{err}"
    assert not _named(err, present), f"the blind scan names present swept dirs:\n{err}"


def test_o2_real_checkout_unswept_package_is_blind(capsys):
    """Over this checkout, a real `defender/` package holding production `.py` that the list stops
    sweeping (`hooks` dropped from `SWEEP_DIRS`, and not declared unscanned) makes `main([])` exit
    2 naming it — the closure runs over the real `defender/`, not only over a mini repo."""
    lint = _fresh(RUN_RECORDS, "_unswept")
    assert "hooks" in lint.SWEEP_DIRS, f"precondition: {lint.SWEEP_DIRS}"
    assert "defender/hooks" not in lint.UNSCANNED_TREES, f"precondition: {lint.UNSCANNED_TREES}"
    assert any(p.name != "__init__.py" for p in (DEFENDER / "hooks").rglob("*.py")), (
        "precondition: defender/hooks holds production .py")
    lint.SWEEP_DIRS = tuple(d for d in lint.SWEEP_DIRS if d != "hooks")
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"main([]) over this checkout with hooks/ unswept: rc={rc}\n{err}"
    assert "hooks" in err, f"the blind scan does not name hooks:\n{err}"


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


def test_o2_an_unforeseeable_package_name_is_blind(tmp_path):
    """The closure checks every top-level directory, not a list of expected names: a package
    named at random holding `.py` makes the lint exit 2 naming it. Control: clean before it."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    _assert_clean(lint_file, RUN_RECORDS)
    name = f"pkg_{uuid.uuid4().hex[:12]}"
    _write(tmp_path / "defender" / name / "x.py")
    _expect(_run(lint_file), 2, name, on="stderr",
            why=f"an unlisted defender/{name}/ holding .py did not blind the scan")


def test_o2_a_name_extending_a_listed_one_is_not_listed(tmp_path):
    """Membership is exact: a directory whose name extends a swept dir (`<swept>_v2`,
    `legacy_<swept>`) or a declared-unscanned `defender/<name>` (`<name>_archive`) is a different,
    unlisted package -> exit 2 naming it. Control: clean before each."""
    lint = _fresh(RUN_RECORDS)
    swept = lint.SWEEP_DIRS[0]
    unscanned = next(t.removeprefix("defender/") for t in lint.UNSCANNED_TREES
                     if t.startswith("defender/"))
    names = (f"{swept}_v2", f"legacy_{swept}", f"{unscanned}_archive")
    listed = [n for n in names if n in lint.SWEEP_DIRS or f"defender/{n}" in lint.UNSCANNED_TREES]
    assert not listed, f"precondition: {listed} are listed"
    lint_file, _sweep = _run_records_mini(tmp_path)
    admitted: dict[str, str] = {}
    for name in names:
        _assert_clean(lint_file, RUN_RECORDS)
        planted = _write(tmp_path / "defender" / name / "x.py")
        result = _run(lint_file)
        shutil.rmtree(planted.parent)
        if result.returncode != 2 or name not in result.stderr:
            admitted[name] = _said(result)
    assert not admitted, ("names extending a listed one were admitted:\n"
                          + "\n".join(f"== {n}\n{w}" for n, w in admitted.items()))


# ======================================================================================
# O4 / D3 — the escape fixes, by mechanism
# ======================================================================================


def test_o4_demo_spells_its_artifacts_through_run_layout():
    """D3's mechanism: every element of the `artifacts=[...]` list `api/demo.py` seeds is
    `RUN_LAYOUT.<record>.name` off `defender.run_repository` (resolved through `_astlib`, so an alias
    counts and a local `RUN_LAYOUT` does not) — report, investigation, runtime page, in that
    order. A name assembled from pieces (`"report" + ".md"`) is not that, and is exactly what the
    run-records gate is structurally blind to."""
    astlib = import_lint_lib("_astlib")
    path = DEFENDER / "api" / "demo.py"
    _text, tree = astlib.read_and_parse(path, "api/demo.py")
    env = astlib.module_env(tree, module="defender.api.demo", package="defender.api")
    lists = [kw.value for node in ast.walk(tree) if isinstance(node, ast.Call)
             for kw in node.keywords
             if kw.arg == "artifacts" and isinstance(kw.value, ast.List) and kw.value.elts]
    assert lists, "api/demo.py seeds no non-empty artifacts=[...] list"
    want = [f"defender.run_repository.RUN_LAYOUT.{r}.name"
            for r in ("report", "investigation", "runtime_html")]
    for listed in lists:
        got = [astlib.origin(el, env) for el in listed.elts]
        assert got == want, (
            f"api/demo.py:{listed.lineno} seeds {ast.unparse(listed)}; resolved {got}, "
            f"want {want}")


def test_o4_scope_statement_names_every_swept_dir():
    """The gate's own statement of what it sweeps names every swept dir as `defender/<d>` — `api`
    included once it is swept — so the statement does not claim less (or other) than the sweep."""
    lint = _fresh(RUN_RECORDS)
    unnamed = [d for d in lint.SWEEP_DIRS if f"defender/{d}" not in lint.SCOPE_STATEMENT]
    assert not unnamed, f"SCOPE_STATEMENT does not name {unnamed}:\n{lint.SCOPE_STATEMENT}"


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


@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE, RUN_RECORDS, ENV_READS])
def test_o1_an_emptied_listed_package_is_blind(tmp_path, stem):
    """A listed package that still EXISTS but holds no file the lint scans — only a `__pycache__`
    module and a README — makes the lint exit 2 naming it, and no other entry. (Run-records'
    swept dirs are package entries by construction; the others must spell a package with a
    trailing `/`, as D4/D5 do — the precondition says so where a list has none.)"""
    lint_file, entries, base = _listed(tmp_path, stem)
    packages = [e for e in entries if e.endswith("/")]
    assert packages, (f"precondition: {stem}'s scope list has no package entry ending '/' "
                      f"(D4 spells packages so; D5 lists runtime/branch/): {entries}")
    _assert_clean(lint_file, stem)
    entry = packages[0]
    shutil.rmtree(base / entry)
    _write(base / entry / "__pycache__" / "stale_1191.py")
    _write(base / entry / "README.md", "not code\n")
    result = _run(lint_file)
    assert result.returncode == 2, (
        f"listed {entry} holds no scanned file and the scan was not blind\n{_said(result)}")
    assert _named(result.stderr, [entry]), f"the blind scan does not name {entry}\n{_said(result)}"
    named = _named(result.stderr, [e for e in entries if not e.startswith(entry)])
    assert not named, f"the blind scan also names entries that select files: {named}\n{_said(result)}"


@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE, ENV_READS])
def test_o1_a_file_entry_naming_a_package_dir_is_blind(tmp_path, stem):
    """A module listed by file that became a package, its entry edited to the package's name
    WITHOUT the trailing `/` (`x/y.py` -> `x/y`): the path exists and holds `.py`, but the entry
    selects none of it -> exit 2 naming it. Control: spelled `x/y/`, the same entry is clean and
    a violation planted in the package is reported, so the `/` is what selects."""
    lint_file, entries, base = _surface(tmp_path, stem)
    name, _under = SCOPE_LISTS[stem]
    _assert_clean(lint_file, stem)
    entry = _file_entries(entries)[0]
    package = entry.removesuffix(".py")
    (base / entry).unlink()
    module = _write(base / package / PLANTED)
    original = lint_file.read_text(encoding="utf-8")

    def relist(spelled: str) -> None:
        lint_file.write_text(original, encoding="utf-8")
        _rebind(lint_file, name, f"type({name})({spelled!r} if e == {entry!r} else e for e in {name})")

    relist(package)
    result = _run(lint_file)
    _expect(result, 2, package, on="stderr",
            why=f"entry {package!r} names a package dir without '/' and the scan was not blind")
    named = _named(result.stderr, [e for e in entries if e != entry])
    assert not named, f"the blind scan also names entries that select files: {named}\n{_said(result)}"

    relist(f"{package}/")
    _assert_clean(lint_file, f"{stem} ({package}/ listed)")
    probe, on = PROBES[stem]
    _write(module, probe)
    _expect(_run(lint_file), 1, f"{package}/{PLANTED}", on=on,
            why=f"a violation planted in listed package {package}/ was not reported")


#: Per list-scoped lint, two entries that EXIST in the real checkout and select nothing: a
#: package dir named without its `/` (it holds `.py`), and a dir holding no `.py` at all.
REAL_IDLE: dict[str, tuple[str, str]] = {
    TREE_READ: ("runtime/branch", "docs/"),
    TREE_WRITE: ("runtime/driver", "docs/"),
    ENV_READS: ("defender/runtime/lead_zero", "defender/docs/"),
}


@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE, ENV_READS])
def test_o1_real_checkout_entry_that_exists_but_selects_nothing_is_blind(capsys, stem):
    """Over this checkout, a list entry that exists but selects nothing — a package dir named
    without its `/`, a dir with no `.py` — makes the lint's own `main([])` exit 2 naming both, and
    no entry that selects files. Control: the unmodified fresh load exits 0."""
    name, under = SCOPE_LISTS[stem]
    base = WORKTREE if under == "." else WORKTREE / under
    bare, empty = REAL_IDLE[stem]
    assert _real_rels(base / bare, {"__pycache__"}), f"precondition: {bare} is a dir holding .py"
    assert (base / empty).is_dir(), f"precondition: {empty} exists"
    assert not _real_rels(base / empty, ()), f"precondition: {empty} holds no .py"
    assert _fresh(stem, "_control").main([]) == 0, f"control: the real {stem} is not clean"
    capsys.readouterr()
    lint = _fresh(stem, "_idle")
    present = sorted(getattr(lint, name))
    setattr(lint, name, type(getattr(lint, name))((*present, bare, empty)))
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"main([]) over this checkout with {bare!r}, {empty!r} listed: rc={rc}\n{err}"
    unnamed = [e for e in (bare, empty) if e.rstrip("/") not in err]
    assert not unnamed, f"the blind scan does not name {unnamed}:\n{err}"
    same = {bare.rstrip("/"), empty.rstrip("/")}
    named = _named(err, [e for e in present if e.rstrip("/") not in same])
    assert not named, f"the blind scan names entries that select files: {named}\n{err}"


def test_o1_real_checkout_swept_dir_with_no_module_is_blind(capsys):
    """Over this checkout, a swept dir that exists but holds no `.py` (`defender/docs`) makes the
    run-records lint's `main([])` exit 2 naming it. Control: the unmodified fresh load exits 0."""
    assert (DEFENDER / "docs").is_dir(), "precondition: defender/docs exists"
    assert not _real_rels(DEFENDER / "docs", ()), "precondition: defender/docs holds no .py"
    assert _fresh(RUN_RECORDS, "_control").main([]) == 0, "control: the real lint is not clean"
    capsys.readouterr()
    lint = _fresh(RUN_RECORDS, "_idle")
    present = list(lint.SWEEP_DIRS)
    lint.SWEEP_DIRS = (*present, "docs")
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"main([]) over this checkout with docs swept: rc={rc}\n{err}"
    assert "docs" in err, f"the blind scan does not name docs:\n{err}"
    assert not _named(err, present), f"the blind scan names present swept dirs:\n{err}"


@pytest.mark.parametrize("stem", [TREE_WRITE, RUN_RECORDS, ENV_READS])
def test_o1_every_real_scope_entry_selects_a_real_file(stem):
    """Every entry of the real list selects at least one real module under the amendment's rule
    (equal, or under a `/` entry) — so a package must be spelled with its `/`. (Tree-read's census
    is checked by the D5 test.)"""
    lint = _fresh(stem)
    if stem == RUN_RECORDS:
        entries = [f"{d}/" for d in lint.SWEEP_DIRS]
        rels = _real_rels(DEFENDER, {".venv", "__pycache__", "tests"})
    elif stem == TREE_WRITE:
        entries = sorted(lint.LINT_HARD_GATED_MODULES)
        rels = _real_rels(DEFENDER, {".venv", "__pycache__"})
    else:
        entries = sorted(lint.SWEPT)
        rels = [f"defender/{r}" for r in _real_rels(DEFENDER, {".venv", "__pycache__"})]
    idle = [e for e in entries if not any(_selects(e, r) for r in rels)]
    assert not idle, f"{stem} entries selecting no real module: {idle}"


def test_o1_stage_frames_missing_explicit_scope_is_blind(tmp_path):
    """D4 settles what the spec left open: a missing explicit `scope=` exits 2 (a scan of nothing
    proves nothing), wherever it points. Control: an existing planted scope exits 0."""
    lint = _fresh(STAGE_FRAMES)
    baseline = tmp_path / "baseline.json"
    assert lint.main([], scope=tmp_path / "nope_1191", baseline_path=baseline) == 2
    _write(tmp_path / "learning" / PLANTED)
    assert lint.main([], scope=tmp_path / "learning", baseline_path=baseline) == 0


# ======================================================================================
# O5 — what a lint scans does not depend on where the checkout lives, or on ignored content
# ======================================================================================


@pytest.mark.parametrize("parent", ["tests", ".venv"])
@pytest.mark.parametrize("stem", [RUN_RECORDS, TREE_READ, TREE_WRITE, STAGE_FRAMES, ENV_READS])
def test_o5_a_checkout_under_an_excluded_name_still_scans(tmp_path, stem, parent):
    """The mini repo placed under a parent directory named like an excluded name (`tests`,
    `.venv`): clean -> exit 0, and a violation planted in a scanned module is still reported
    (exit 1, named). Excluded names are matched below the scan root, never on its ancestors.
    Control: the same plant under a neutral parent (`test_o1_*_control_*`)."""
    lint_file, module, rel = _plantable(tmp_path / parent / "repo", stem)
    _assert_clean(lint_file, f"{stem} under {parent}/")
    probe, on = PROBES[stem]
    _write(module, probe)
    _expect(_run(lint_file), 1, rel, on=on,
            why=f"with the checkout under a dir named {parent!r}, a plant in {rel} was not reported")


@pytest.mark.parametrize("stem", [RUN_RECORDS, TREE_WRITE, STAGE_FRAMES])
def test_o5_gitignored_content_is_not_scanned_but_untracked_content_is(tmp_path, stem):
    """In a mini repo that is a git repo ignoring `zz_ign_1191/` and `*_ignored_1191.py` (names
    no lint could prune by spelling; its layout staged): an untracked, not-ignored new module
    holding a violation IS reported (ignored-ness decides, not tracked-ness); the same violation
    in gitignored dirs — beside a scanned module and, for run-records, as a top-level
    `defender/zz_ign_1191/` the closure would otherwise name — or in an ignored file name, is
    not scanned: exit 0."""
    lint_file, module, _rel = _plantable(tmp_path, stem)
    _git_repo(tmp_path, IGNORES)
    _assert_clean(lint_file, f"{stem} as a git repo")
    probe, _on = PROBES[stem]
    new = _write(module.parent / "new_1191.py", probe)
    _expect(_run(lint_file), 1, "new_1191.py", on="stdout",
            why="an untracked, not-ignored module holding a violation was not scanned")
    new.unlink()
    _write(module.parent / "zz_ign_1191" / "x_1191.py", probe)
    _write(tmp_path / "defender" / "zz_ign_1191" / "y_1191.py", probe)
    _write(module.parent / "z_ignored_1191.py", probe)
    result = _run(lint_file)
    assert result.returncode == 0, (
        f"violations only in gitignored content were scanned (or blinded the closure)\n"
        f"{_said(result)}")


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


def test_o6_scope_statement_names_exactly_both_lists(tmp_path):
    """Edit the COPIED lint's lists — a swept dir added and one dropped, a `defender/` tree and a
    repo-top-level tree declared unscanned — and its `SCOPE_STATEMENT` follows: it names
    `defender/<d>` for every swept dir, every `UNSCANNED_TREES` entry, and no longer the dropped
    dir. A hand-kept statement cannot."""
    real = _fresh(RUN_RECORDS)
    dropped = real.SWEEP_DIRS[-1]
    added = ("zz_swept_1191", "defender/zz_unscanned_1191", "zz_top_1191")
    statement = _statement_of_copy(
        tmp_path, f"(*(d for d in SWEEP_DIRS if d != {dropped!r}), {added[0]!r})",
        f"(*UNSCANNED_TREES, {added[1]!r}, {added[2]!r})")
    swept = [d for d in real.SWEEP_DIRS if d != dropped] + [added[0]]
    want = [f"defender/{d}" for d in swept] + [*real.UNSCANNED_TREES, added[1], added[2]]
    unnamed = [w for w in want if w not in statement]
    assert not unnamed, f"SCOPE_STATEMENT does not name {unnamed}:\n{statement}"
    gone = re.search(rf"(?<![\w./-])defender/{re.escape(dropped)}(?![\w./-])", statement)
    assert not gone, f"SCOPE_STATEMENT still names the dropped defender/{dropped}:\n{statement}"


# ======================================================================================
# O7 — a blind run-records scan writes nothing
# ======================================================================================


def test_o7_a_blind_render_writes_nothing(tmp_path):
    """With the page stale and a swept dir gone, `lint_run_records.py --render` exits 2 naming the
    dir and leaves the page byte-identical. Control: with the dir back, the same `--render` exits
    0 and rewrites the stale page — so "identical" means the write was withheld."""
    lint_file, sweep = _run_records_mini(tmp_path)
    page = tmp_path / RUN_RECORDS_DATA[1]
    mark = _fresh(RUN_RECORDS).BEGIN_MARK
    text = page.read_text(encoding="utf-8")
    assert mark in text, "precondition: the page carries the generated block"
    page.write_text(text.replace(mark, f"{mark}\n| stale_1191 | row |", 1), encoding="utf-8")
    stale = page.read_bytes()
    target = tmp_path / "defender" / sweep[0]
    held = tmp_path / "aside_1191"
    target.rename(held)
    result = _run(lint_file, "--render")
    held.rename(target)
    _expect(result, 2, sweep[0], on="stderr", why=f"--render with {sweep[0]}/ gone was not blind")
    assert page.read_bytes() == stale, f"a blind --render rewrote the page\n{_said(result)}"
    control = _run(lint_file, "--render")
    assert control.returncode == 0, f"control: --render failed\n{_said(control)}"
    assert page.read_bytes() != stale, "control: --render did not rewrite the stale page"


# ======================================================================================
# Holes the amendment adversary found in 0d415c26 (each passed by a cheating implementation)
# ======================================================================================


@pytest.mark.parametrize("leftovers", [("__pycache__/stale_1191.py", "README.md"),
                                       ("tests/test_x_1191.py",)])
def test_o1_stage_frames_emptied_default_scope_is_blind(tmp_path, leftovers):
    """O1 restated covers the stage-frames lint's default scope (D4: the entry `learning/` under
    `defender/`): emptied — left holding only a `__pycache__` module and a README, or only a test
    module — it EXISTS but selects nothing the lint scans: exit 2 naming it. Control: the
    untouched mini repo exits 0."""
    lint_file, scope = _stage_frames_mini(tmp_path)
    _assert_clean(lint_file, STAGE_FRAMES)
    shutil.rmtree(tmp_path / scope)
    for rel in leftovers:
        _write(tmp_path / scope / rel, "not code\n" if rel.endswith(".md") else INERT)
    _expect(_run(lint_file), 2, "learning", on="stderr",
            why=f"defender/learning holds only {leftovers} and the scan was not blind")


@pytest.mark.parametrize("leftover", ["test_stale_1191.py", "conftest.py", "tests/helper_1191.py"])
@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE])
def test_o1_a_listed_package_holding_only_test_modules_is_blind(tmp_path, stem, leftover):
    """A listed package left holding only a test module (`test_*.py`, `conftest.py`, a module
    under `tests/`) selects a listed file but nothing the lint SCANS (both lints drop test
    modules): exit 2 naming the package entry itself — matched as a whole path, so a nested entry
    removed with it (`runtime/branch/_family.py`) does not stand in for it. Control: the
    untouched mini repo exits 0."""
    lint_file, entries, base = _surface(tmp_path, stem)
    packages = [e for e in entries if e.endswith("/")]
    assert packages, f"precondition: {stem}'s list has a package entry: {entries}"
    entry = packages[0]
    _assert_clean(lint_file, stem)
    shutil.rmtree(base / entry)
    _write(base / entry / leftover)
    result = _run(lint_file)
    assert result.returncode == 2, (
        f"listed {entry} holds only {leftover} (never scanned) and the scan was not blind\n"
        f"{_said(result)}")
    assert _named(result.stderr, [entry]), f"the blind scan does not name {entry}\n{_said(result)}"


@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE, ENV_READS])
def test_o5_gitignored_content_under_a_listed_package_is_not_scanned(tmp_path, stem):
    """O5/D4 for every list-scoped lint: in a git repo ignoring `zz_ign_1191/` and
    `*_ignored_1191.py` (layout staged), an untracked, not-ignored module holding a violation
    inside a listed package IS reported; the same violation under that package's gitignored
    dir, or in an ignored file name, is not: exit 0."""
    lint_file, entries, base = _surface(tmp_path, stem)
    packages = [e for e in entries if e.endswith("/")]
    assert packages, f"precondition: {stem}'s list has a package entry: {entries}"
    package = base / packages[0]
    _git_repo(tmp_path, IGNORES)
    _assert_clean(lint_file, f"{stem} as a git repo")
    probe, on = PROBES[stem]
    new = _write(package / "new_1191.py", probe)
    _expect(_run(lint_file), 1, "new_1191.py", on=on,
            why=f"an untracked, not-ignored module in listed {packages[0]} was not scanned")
    new.unlink()
    _write(package / "zz_ign_1191" / "x_1191.py", probe)
    _write(package / "z_ignored_1191.py", probe)
    result = _run(lint_file)
    assert result.returncode == 0, (
        f"a violation in gitignored content of {packages[0]} was scanned\n{_said(result)}")


def test_o7_a_render_blinded_by_the_closure_writes_nothing(tmp_path):
    """O7 whatever makes the scan blind: an unlisted package (the closure) with the page stale —
    `--render` exits 2 naming the package and leaves the page byte-identical. Control: without
    the package, the same `--render` exits 0 and rewrites the page."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    page = tmp_path / RUN_RECORDS_DATA[1]
    mark = _fresh(RUN_RECORDS).BEGIN_MARK
    text = page.read_text(encoding="utf-8")
    assert mark in text, "precondition: the page carries the generated block"
    page.write_text(text.replace(mark, f"{mark}\n| stale_1191 | row |", 1), encoding="utf-8")
    stale = page.read_bytes()
    planted = _write(tmp_path / "defender" / "newpkg_1191" / "x.py")
    result = _run(lint_file, "--render")
    _expect(result, 2, "newpkg_1191", on="stderr", why="an unlisted package did not blind --render")
    assert page.read_bytes() == stale, f"a closure-blind --render rewrote the page\n{_said(result)}"
    shutil.rmtree(planted.parent)
    control = _run(lint_file, "--render")
    assert control.returncode == 0, f"control: --render failed\n{_said(control)}"
    assert page.read_bytes() != stale, "control: --render did not rewrite the stale page"


def test_o6_dropping_any_entry_of_either_list_unnames_it(tmp_path):
    """O6 "exactly", from both ends of both lists: drop the FIRST swept dir and the LAST
    declared-unscanned tree in the copy, and the statement names neither (a statement kept by
    hand for today's entries plus the delta would still name them)."""
    real = _fresh(RUN_RECORDS)
    swept, unscanned = real.SWEEP_DIRS[0], real.UNSCANNED_TREES[-1]
    statement = _statement_of_copy(
        tmp_path, f"tuple(d for d in SWEEP_DIRS if d != {swept!r})",
        f"tuple(t for t in UNSCANNED_TREES if t != {unscanned!r})")
    assert not _spelled(statement, f"defender/{swept}"), (
        f"SCOPE_STATEMENT still names dropped defender/{swept}:\n{statement}")
    assert not _spelled(statement, unscanned), (
        f"SCOPE_STATEMENT still names dropped {unscanned}:\n{statement}")
    kept = [f"defender/{d}" for d in real.SWEEP_DIRS if d != swept]
    assert all(_spelled(statement, k) for k in kept), f"control: {kept} not all named:\n{statement}"


def test_o6_each_list_lands_on_its_own_side_of_the_sentence(tmp_path):
    """D6 generates a "sweeps ... / never enters ..." sentence: every swept dir (as
    `defender/<d>`) is named before "never enters", every declared-unscanned tree after it, and
    no unscanned tree is named before it — on the real lint, and on a copy with one entry added
    to each list (which must land on its own side and only there)."""
    added_swept, added_unscanned = "zz_swept_1191", "defender/zz_unscanned_1191"
    copy = _statement_of_copy(tmp_path, f"(*SWEEP_DIRS, {added_swept!r})",
                              f"(*UNSCANNED_TREES, {added_unscanned!r})")
    real = _fresh(RUN_RECORDS)
    for statement, swept, unscanned in (
            (real.SCOPE_STATEMENT, list(real.SWEEP_DIRS), list(real.UNSCANNED_TREES)),
            (copy, [*real.SWEEP_DIRS, added_swept], [*real.UNSCANNED_TREES, added_unscanned])):
        head, sep, tail = statement.partition("never enters")
        assert sep, f"no 'never enters' clause:\n{statement}"
        unswept = [d for d in swept if not _spelled(head, f"defender/{d}")]
        assert not unswept, f"swept dirs not named before 'never enters': {unswept}\n{statement}"
        unnamed = [t for t in unscanned if not _spelled(tail, t)]
        assert not unnamed, f"unscanned trees not named after 'never enters': {unnamed}\n{statement}"
        misplaced = [t for t in unscanned if _spelled(head, t)]
        assert not misplaced, f"unscanned trees named as swept: {misplaced}\n{statement}"
    assert added_swept not in copy.partition("never enters")[2], f"{added_swept} named as unscanned"


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


def test_o2_an_unlisted_dir_holding_only_gitignored_modules_is_not_a_package(tmp_path):
    """D2': the closure runs on the shared listing, so a top-level `defender/newpkg/` whose only
    `.py` sits under a gitignored `build/` is no package: exit 0. Control: with `build/` no longer
    ignored, the same tree exits 2 naming `newpkg_1191`."""
    lint_file, _sweep = _run_records_mini(tmp_path)
    _git_repo(tmp_path, "build/\n")
    _assert_clean(lint_file, f"{RUN_RECORDS} as a git repo")
    _write(tmp_path / "defender" / "newpkg_1191" / "build" / "x.py")
    result = _run(lint_file)
    assert result.returncode == 0, (
        f"only-ignored .py under newpkg_1191/ blinded the closure\n{_said(result)}")
    _write(tmp_path / ".gitignore", "# nothing ignored\n")
    _expect(_run(lint_file), 2, "newpkg_1191", on="stderr",
            why="control: with build/ un-ignored, unlisted newpkg_1191/ did not blind the scan")


def test_o1_real_checkout_env_reads_root_flag_naming_this_repo_is_strict(capsys):
    """Strictness follows where the root RESOLVES, not whether `--root` was passed: the env-read
    lint handed this checkout by `--root` (plainly, or as `defender/..`) with a phantom `SWEPT`
    entry exits 2 naming it. Control: the unmodified fresh load, same argv, exits 0."""
    for argv in (["--root", str(WORKTREE)], ["--root", str(WORKTREE / "defender" / "..")]):
        assert _fresh(ENV_READS, "_control").main(argv) == 0, f"control: main({argv}) not clean"
        capsys.readouterr()
        lint = _fresh(ENV_READS, "_phantom")
        lint.SWEPT = (*lint.SWEPT, f"defender/{PHANTOM}.py")
        rc, err = _main(lint, capsys, argv)
        assert rc == 2, f"main({argv}) over this checkout with a phantom entry: rc={rc}\n{err}"
        assert PHANTOM in err, f"the blind scan does not name {PHANTOM}:\n{err}"


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


def test_o12_env_reads_names_its_dead_entries_when_none_selects(capsys):
    """O12/D12: over this checkout, with EVERY `SWEPT` entry dead, the env-read lint's blind scan
    names the dead entries (not only "none of the trees is there"). Control: the unmodified
    fresh load exits 0."""
    assert _fresh(ENV_READS, "_control").main([]) == 0, "control: the real lint is not clean"
    capsys.readouterr()
    lint = _fresh(ENV_READS, "_dead")
    phantoms = tuple(f"defender/{PHANTOM}_{i}.py" for i in range(len(lint.SWEPT)))
    lint.SWEPT = phantoms
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"every SWEPT entry dead: rc={rc}\n{err}"
    unnamed = [p for p in phantoms if p not in err]
    assert not unnamed, f"the blind scan does not name the dead entries {unnamed}:\n{err}"


def test_o13_a_dead_unscanned_defender_tree_is_blind(capsys):
    """O13/D13: over this checkout, a `defender/...` entry of `UNSCANNED_TREES` that selects no
    file makes the run-records lint's `main([])` exit 2 naming it, like a dead swept dir.
    Control: the unmodified fresh load exits 0."""
    assert _fresh(RUN_RECORDS, "_control").main([]) == 0, "control: the real lint is not clean"
    capsys.readouterr()
    lint = _fresh(RUN_RECORDS, "_dead_unscanned")
    dead = f"defender/{PHANTOM}"
    lint.UNSCANNED_TREES = (*lint.UNSCANNED_TREES, dead)
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"main([]) with {dead} declared unscanned: rc={rc}\n{err}"
    assert PHANTOM in err, f"the blind scan does not name {dead}:\n{err}"


def test_o13_an_unscanned_defender_tree_holding_no_module_is_blind(capsys):
    """O13/D13 is "selects no file", not "does not exist": over this checkout, declaring
    `defender/docs` unscanned — a directory that EXISTS and holds no `.py` — makes the
    run-records lint's `main([])` exit 2 naming it."""
    docs = DEFENDER / "docs"
    assert docs.is_dir(), "precondition: defender/docs exists"
    assert not [p for p in docs.rglob("*.py")], "precondition: defender/docs holds no module"
    lint = _fresh(RUN_RECORDS, "_idle_unscanned")
    lint.UNSCANNED_TREES = (*lint.UNSCANNED_TREES, "defender/docs")
    rc, err = _main(lint, capsys, [])
    assert rc == 2, f"main([]) with defender/docs declared unscanned: rc={rc}\n{err}"
    assert _named(err, ["docs/"]), f"the blind scan does not name defender/docs:\n{err}"


def test_o14_a_repo_level_unscanned_entry_is_spelled_top_level(tmp_path):
    """O14/D14: the scope statement renders a bare (repo-level) `UNSCANNED_TREES` entry as
    "top-level <name>", after "never enters", and never bare there — on the real lint, and on
    a copy with one more bare entry declared — so it never reads as both sweeping and never
    entering `scripts`."""
    real = _fresh(RUN_RECORDS)
    copy = _statement_of_copy(tmp_path, "SWEEP_DIRS", '(*UNSCANNED_TREES, "zz_top_1191")')
    for statement, unscanned in ((real.SCOPE_STATEMENT, list(real.UNSCANNED_TREES)),
                                 (copy, [*real.UNSCANNED_TREES, "zz_top_1191"])):
        tail = statement.partition("never enters")[2]
        bare = [t for t in unscanned if not t.startswith("defender/")]
        assert bare, f"precondition: a repo-level unscanned entry: {unscanned}"
        unspelled = [t for t in bare if f"top-level {t}" not in tail]
        assert not unspelled, (
            f"repo-level unscanned entries not spelled 'top-level <name>' after 'never enters': "
            f"{unspelled}\n{statement}")
        # ...and ONLY so: no bare mention of the name as a whole path anywhere after it.
        named_bare = [t for t in bare
                      if re.search(rf"(?<![\w./-])(?<!top-level ){re.escape(t)}(?![\w./-])", tail)]
        assert not named_bare, (
            f"repo-level unscanned entries also named bare after 'never enters': {named_bare}"
            f"\n{statement}")


#: A module that does not parse.
UNPARSEABLE = "def broken_1191(:\n"
#: Test-module shapes outside `tests/` (the lints' own notion: `test_*.py`, `*_test.py`,
#: `conftest.py`).
TEST_MODULE_NAMES = ("test_broken_1191.py", "broken_1191_test.py", "conftest.py")


def test_o15_tree_read_parses_only_census_modules(tmp_path):
    """O15/D15: the tree-read lint parses only census modules that are not tests — an unlisted
    module, or a test module under `tests/` or of any test shape inside a listed package
    (`test_*.py`, `*_test.py`, `conftest.py`), with a syntax error leaves it clean (exit 0). Control: a census module with a syntax error is blind (exit 2,
    named)."""
    lint_file, modules = _tree_read_mini(tmp_path)
    _assert_clean(lint_file, TREE_READ)
    d = tmp_path / "defender"
    packages = [m for m in modules if m.endswith("/")]
    planted = [d / "zz_unlisted_1191.py", d / "tests" / "test_broken_1191.py"]
    for package in packages[:1]:
        planted += [d / package / name for name in TEST_MODULE_NAMES]
    for path in planted:
        _write(path, UNPARSEABLE)
    result = _run(lint_file)
    assert result.returncode == 0, (
        f"an unparseable module outside the census (or a test module) blinded the tree-read "
        f"lint\n{_said(result)}")
    module = _file_entries(modules)[0]
    _write(d / module, UNPARSEABLE)
    _expect(_run(lint_file), 2, module, on="stderr",
            why=f"control: unparseable census module {module} did not blind the scan")


def test_o15_tree_write_never_parses_test_modules(tmp_path):
    """O15/D15: the tree-write lint never parses test modules — under `tests/`, or of any test
    shape outside it (`test_*.py`, `*_test.py`, `conftest.py`, top-level or in a package) — so
    one with a syntax error leaves it clean (exit 0). Control: a non-test module with a
    syntax error is blind (exit 2, named)."""
    lint_file, _entries = _tree_write_mini(tmp_path)
    _assert_clean(lint_file, TREE_WRITE)
    d = tmp_path / "defender"
    planted = [d / "tests" / "test_broken_1191.py", d / "conftest.py"]
    planted += [d / "pkg_1191" / name for name in TEST_MODULE_NAMES]
    for path in planted:
        _write(path, UNPARSEABLE)
    result = _run(lint_file)
    assert result.returncode == 0, f"an unparseable test module blinded the tree-write lint\n{_said(result)}"
    _write(d / "zz_broken_1191.py", UNPARSEABLE)
    _expect(_run(lint_file), 2, "zz_broken_1191.py", on="stderr",
            why="control: an unparseable non-test module did not blind the scan")


def test_o3_an_empty_planted_stage_frames_scope_keeps_todays_tolerance(tmp_path):
    """O3 + D16: only the REAL scope is blind on an empty listing. A planted scope that exists
    and holds no module (only a README) exits 0 — as it did before #1191 (76e48940's lint:
    `main([], scope=<planted>)` over such a scope returns 0)."""
    lint = _fresh(STAGE_FRAMES, "_empty_planted")
    scope = tmp_path / "learning"
    _write(scope / "README.md", "not code\n")
    assert lint.main([], scope=scope, baseline_path=tmp_path / "baseline.json") == 0


def test_o16_stage_frames_real_scope_through_a_symlink_is_not_blind(tmp_path):
    """O16: the stage-frames lint handed the real `defender/learning` through a symlink scans it
    like the real scope: not blind (exit 0, the real tree being clean)."""
    lint = _fresh(STAGE_FRAMES)
    link = tmp_path / "learning_link_1191"
    link.symlink_to(DEFENDER / "learning", target_is_directory=True)
    baseline = tmp_path / "baseline.json"
    shutil.copyfile(lint.BASELINE_PATH, baseline)
    assert lint.main([], scope=link, baseline_path=baseline) == 0


#: Runs the copied stage-frames lint's `main([], scope=argv[2], baseline_path=argv[3])` (argv[1]:
#: the copy's directory) and exits with its status.
_STAGE_FRAMES_MAIN = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                      "import lint_stage_prompt_frames as m; "
                      "sys.exit(m.main([], scope=Path(sys.argv[2]), baseline_path=Path(sys.argv[3])))")


def test_o16_an_emptied_real_scope_is_blind_however_it_is_spelled(tmp_path):
    """O16/D16: over this repo, the stage-frames scope that lists no file is blind whatever its
    path is spelled as — the copy's own `defender/learning`, emptied, handed to its `main` by its
    real path and through a symlink, exits 2 both times. Control: populated, both exit 0."""
    lint_file, scope = _stage_frames_mini(tmp_path)
    real = tmp_path / scope
    link = tmp_path / "learning_link_1191"
    link.symlink_to(real, target_is_directory=True)

    def run(spelled: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 — fixed argv built by the test
            [sys.executable, "-c", _STAGE_FRAMES_MAIN, str(lint_file.parent), str(spelled),
             str(tmp_path / "baseline.json")], cwd=tmp_path, capture_output=True,
            encoding="utf-8", errors="replace", env=_child_env(), timeout=120, check=False)

    for spelled in (real, link):
        control = run(spelled)
        assert control.returncode == 0, f"control: scope {spelled} not clean\n{_said(control)}"
    shutil.rmtree(real)
    _write(real / "README.md", "not code\n")
    for spelled in (real, link):
        result = run(spelled)
        assert result.returncode == 2, (
            f"the emptied real scope, spelled {spelled}, was not blind\n{_said(result)}")


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


@pytest.mark.parametrize("spelled", [".", "./", "defender/.."])
def test_o5_env_reads_from_a_relative_root_keeps_anchored_ignores(tmp_path, spelled):
    """O5 restated (c): the env-read lint run as `--root <relative>` from its repo's top keeps an
    ANCHORED ignore: a read planted under `/<swept package>/zz_ign_1191/` is not reported.
    Control: the same read planted beside it, not ignored, is (exit 1, named)."""
    lint_file, entries, base = _surface(tmp_path, ENV_READS)
    packages = [e for e in entries if e.endswith("/")]
    assert packages, f"precondition: {ENV_READS}'s list has a package entry: {entries}"
    package = base / packages[0]
    anchored = f"/{(package / 'zz_ign_1191').relative_to(tmp_path.resolve()).as_posix()}/\n"
    _git_repo(tmp_path, anchored)
    kept = _write(package / "kept_1191.py", ENV_READS_PROBE)
    _expect(_run(lint_file, "--root", spelled), 1, "kept_1191.py", on="stdout",
            why=f"control: a read in {packages[0]} not ignored was not reported")
    kept.unlink()
    _write(package / "zz_ign_1191" / "x_1191.py", ENV_READS_PROBE)
    result = _run(lint_file, "--root", spelled)
    assert result.returncode == 0, (
        f"--root {spelled}: a read under the anchored ignore {anchored.strip()} was scanned\n"
        f"{_said(result)}")
