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
from defender.tests.support.shared.contracts._by_path import DEFENDER, LINT_DIR, WORKTREE, import_lint_lib, load_lint_gate
from defender.tests.support.shared.contracts._repo import seed_repo

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


def _fresh(stem: str, suffix: str = "") -> ModuleType:
    """A fresh load of the REAL lint (this checkout's), for its constants or an in-process run."""
    return load_lint_gate(stem, name=f"{stem}_1191{suffix}")


def _write(path: Path, text: str = INERT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mini_repo(root: Path, stem: str, *, data: Iterable[str] = ()) -> Path:
    """`root` laid out as a repo holding a copy of `tooling/lint/` and `data` (repo-relative files
    copied from this checkout), with an empty `defender/`. Returns the copy of `<stem>.py`."""
    shutil.copytree(LINT_DIR, root / "tooling" / "lint",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for rel in data:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(WORKTREE / rel, dst)
    (root / "defender").mkdir(exist_ok=True)
    lint_file = root / "tooling" / "lint" / f"{stem}.py"
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


def test_source_files_lists_py_root_relative_pruning_excluded_names_below_root(tmp_path):
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


def _tree_read_mini(root: Path) -> tuple[Path, list[str]]:
    lint_file, modules, _base = _surface(root, TREE_READ)
    return lint_file, modules


def test_o1_tree_read_missing_census_module_is_blind(tmp_path):
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


def test_o2_unlisted_package_is_blind(tmp_path):
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


#: An entry no checkout holds.
PHANTOM = "nope_1191"


def _main(lint: ModuleType, capsys: pytest.CaptureFixture[str], argv: list[str],
          **kw: object) -> tuple[int, str]:
    rc = lint.main(argv, **kw)
    return rc, capsys.readouterr().err


@pytest.mark.parametrize("stem", [TREE_READ, TREE_WRITE])
def test_o1_update_baseline_over_a_blind_scan_keeps_the_baseline(tmp_path, stem):
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


def test_source_files_follows_the_repos_own_ignore_rules(tmp_path, monkeypatch):
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
    astlib = import_lint_lib("_astlib")
    repo = tmp_path / "repo"
    _write(repo / "kept.py")
    _git_repo(repo, "build/\n")
    planted = repo / "build" / "planted"
    for rel in ("a.py", "sub/b.py"):
        _write(planted / rel)
    assert sorted(astlib.source_files(planted, ())) == ["a.py", "sub/b.py"]


def test_source_files_drops_ignored_modules_under_a_root_git_does_not_ignore(tmp_path):
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


def _ignored_tree(repo: Path) -> Path:
    """A git repo ignoring IGNORES whose `defender/` holds a kept module, a module in a package,
    and nothing else that is source. Returns `defender/`."""
    _write(repo / "defender" / "kept.py")
    _write(repo / "defender" / "pkg" / "a.py")
    _git_repo(repo, IGNORES)
    return repo / "defender"


def test_source_files_never_enters_an_ignored_dir_holding_undecodable_names(tmp_path):
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
