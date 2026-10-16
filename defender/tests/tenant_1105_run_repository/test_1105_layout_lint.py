"""#1105 PR 1 — D7's layout lint, `scripts/lint/lint_run_layout_imports.py` (→ O1), and the
neighbouring gates it must agree with (MF-05, MF-06, MF-07, MF-19, MF-20: the interim FENCE until
#1082; NM-08, NM-09).

Outside the owners, production code may not take a run-folder layout name, an episode-runs name,
`Tenant.runs` or a handle constructor except where D7's category table exempts it or the PR 1
allow-list names the use. The allow-list is the only hatch (no inline suppression); a stale
entry fails; PR 1's list holds exactly 18 entries: ruling 1's nine sites, `cli.py:1089`
(`tenant.tenant.runs`), `run_common.py:90` (`tenant.runs`) and `:96` (`Run.for_tenant`),
`visualize_run.py:633` (`Run.at`) and the five unmigrated callers' module-level `RunPaths`
imports. (PR 1 also carried a `deferred_legacy` row exempting four per-case readers by
(module, function); #1166 deleted the readers and the row.)

#1105 PR 2 reached that end state (D7″, J15): the allow-list is empty, the `unmigrated` row is
gone (F-09 moved its modules to the rows their remaining use fits), and F-13 deleted
`resolve_run_bundle`. The tests below that pinned PR 1's interim list now pin the empty one.

THE LINT'S TEST INTERFACE (coined here; the implementer matches it, or renames it HERE):

* the program `scripts/lint/lint_run_layout_imports.py`, run by CI as
  `python scripts/lint/lint_run_layout_imports.py`, and imported by this suite as
  `scripts.lint.lint_run_layout_imports` with `scripts/lint/` on `sys.path` (the gates import
  `_astlib` by bare name);
* `DEFENDER: Path` — the default root, derived from the script's own location
  (`Path(__file__).resolve().parents[2] / "defender"`), so a run from any working directory or
  a worktree sweeps its own checkout;
* `main(argv: list[str] | None = None) -> int` — 0 clean, nonzero on any finding, every finding's
  `display` printed to stdout; `--root DIR` sweeps a `defender/`-shaped tree DIR instead of
  `DEFENDER`, with the same allow-list and table;
* `scan(root: Path = DEFENDER, *, allow_list=None) -> list[Finding]` — the whole sweep;
  `allow_list=None` means `ALLOW_LIST`. Every unlisted gated use, every stale or duplicate
  allow-list entry and every module that does not parse or decode is a `Finding`;
* `Finding.key: tuple[str, str, str] | None` — (module path under the root, posix; the enclosing
  qualified function, or `"<module>"`; the gated name), `None` for a stale or duplicate entry and
  an unreadable module; `Finding.display: str` names the module, the function and the name (a
  stale entry's says `stale`, a duplicate's says `duplicate`, an unreadable module's names it);
* gated names are spelled: a layout name bare (`RunPaths`); a gated member `Class.member`
  (`Tenant.runs`, `Episode.runs`, `EpisodePaths.runs`, `EpisodePaths.sibling_run_dir`,
  `EpisodeLayout.runs` / `.run` / `.run_page` / `.sibling_run_dir`); `RUNS_DIRNAME`; a
  constructor call `Run` / `ArchivedWorld`; a constructor reference `Run.at`, `Run.for_tenant`,
  `Run.under`, `ArchivedWorld.at`;
* `ALLOW_LIST: Sequence[tuple[str, str, str, int]]` — `(module, function, name, count)` entries
  (a sequence, so a duplicate can be written and is a finding; entries are not normalised);
* `CATEGORIES: Mapping[str, Sequence[str]]` — row name -> module paths under `defender/`, the
  rows `owners`, `running-investigation`, `names-only`, `run-lifecycle`, `path-taking-readers`,
  `not-a-run`, `helpers-only` (PR 1's `unmigrated` row went with #1105 PR 2);
* `HELPERS: frozenset[str]` — the eight ungated layout helpers;
* the sweep skips `evals/` and `tests/` under the root, every `__pycache__` and hidden directory,
  and a venv (a directory named `venv` / `.venv`, or one holding `pyvenv.cfg`; the planted venvs
  here pin each clause alone: `venv` with no `pyvenv.cfg`, and a `pyvenv.cfg` directory of
  another name);
* the layout-name universe is read from the SWEPT tree's `run_repository/_layout.py` (its public
  module-level bindings, of every form), so a planted tree carries its own; every planted tree
  here starts from a copy of the real package and the owner sources the receiver typing reads;
* the door keeps a static `__all__` (the universe test reads it to compute the layout names).

Red at base 80888efb: the script does not exist (each test fails on the loader's
`pytest.fail`), `ci.yml` has no step for it, `learning/core/config.py` still re-exports
`RunPaths`, and `lint_run_records` / #1134's census do not recognise a door spelling.
"""
from __future__ import annotations

import ast
import collections
import importlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from defender.tests.tenant_1105_run_repository import _spec1105 as H

if TYPE_CHECKING:  # the import heuristic's view of the target; loaded by `_lint()` at run time
    from scripts.lint import lint_run_layout_imports  # noqa: F401

LINT_DIR = H.WORKTREE / "scripts" / "lint"
LINT_FILE = LINT_DIR / "lint_run_layout_imports.py"

#: The eight layout names that are not gated (D7: rev 3's five plus the predicates and shape
#: constants in use outside the owners at bc4ce944, R4-26).
HELPERS = frozenset({"artifact_file", "artifact_dir", "plain_file", "contained_payload",
                     "LEAD_ID_RE", "gather_summaries_shape", "is_case_answer_key",
                     "GATHER_RAW_SHAPE"})
#: Layout names D7 names as gated.
#: (#1105 PR 2, F-13: `resolve_run_bundle` lost its last caller with J3's union and is deleted.)
NAMED_GATED = ("RunPaths", "RUN_LAYOUT", "SessionPaths", "WIRE_LOG_NAMES", "GATE_METADATA_KEY",
               "RunLayout", "WireLogNames")

_CLI = "learning/branch/cli.py"


# ==========================================================================================
# Same-file helpers: load, plant, read findings. None of them asserts on a demand's behalf.
# ==========================================================================================

def _lint() -> ModuleType:
    """The lint program, imported as CI runs it (its own directory on `sys.path`). Its absence
    — the state at base — is this test's failure, never a crash."""
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    missing = None
    try:
        return importlib.import_module("scripts.lint.lint_run_layout_imports")
    except ModuleNotFoundError as err:
        if err.name not in ("scripts.lint.lint_run_layout_imports", "scripts.lint", "scripts"):
            raise
        missing = err.name
    pytest.fail(f"{LINT_FILE.relative_to(H.WORKTREE)} does not exist ({missing} is not "
                "importable): D7's layout lint is not written yet")


#: The modules a planted tree carries besides the package, so the lint's receiver typing reads
#: the same owner sources it reads on the real tree (`Episode.open`'s return, `LAYOUT`'s class,
#: `RunTenant.tenant`'s type).
_CONTEXT = ("_episode_paths.py", "_episode_handle.py", "_tenant.py", "runtime/run_tenant.py")


def _planted(tmp_path: Path) -> Path:
    """A `defender/`-shaped tree holding a copy of the real package (the lint reads the layout
    universe from the swept tree's `run_repository/_layout.py`) and the `_CONTEXT` modules, and
    nothing else."""
    root = tmp_path / "defender"
    if H.PACKAGE.is_dir():
        shutil.copytree(H.PACKAGE, root / "run_repository",
                        ignore=shutil.ignore_patterns("__pycache__"))
    else:
        (root / "run_repository").mkdir(parents=True)
    for rel in _CONTEXT:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(H.DEFENDER / rel, root / rel)
    return root


def _plant(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _add(root: Path, rel: str, text: str) -> Path:
    """`text` appended to the planted tree's copy of `rel` (an owner keeps its own source), or
    planted as `rel` when the tree has none."""
    path = root / rel
    if not path.is_file():
        return _plant(root, rel, text)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n\n" + text)
    return path


def _production_files(defender: Path) -> list[Path]:
    """Every `.py` under `defender/` in D7's sweep (minus tests/, evals/, caches, hidden
    directories and venvs) — used to copy the sweep and to census it, never as an expected
    value. Directories are pruned before descent (a venv is never walked)."""
    out: list[Path] = []
    for top, dirs, files in os.walk(defender):
        at_root = Path(top) == defender
        dirs[:] = sorted(d for d in dirs
                         if not (d.startswith(".") or d in ("__pycache__", "venv", "tests")
                                 or (at_root and d == "evals")))
        out.extend(Path(top) / f for f in sorted(files) if f.endswith(".py"))
    return out


def _sweep_copy(tmp_path: Path) -> Path:
    """A scratch copy of the real sweep: every production `.py` under `defender/`, at its own
    path, so the real allow-list and table apply to it unchanged."""
    root = tmp_path / "defender"
    for path in _production_files(H.DEFENDER):
        dest = root / path.relative_to(H.DEFENDER)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    return root


def _keys(found: Any) -> collections.Counter:
    return collections.Counter(getattr(f, "key", None) for f in found
                               if getattr(f, "key", None) is not None)


def _in(found: Any, module: str) -> list[tuple[str, str, str]]:
    """The keys of `found` in `module`."""
    return [k for k in _keys(found).elements() if k[0] == module]


def _displays(found: Any) -> str:
    return "\n".join(str(getattr(f, "display", f)) for f in found)


def _main(lint_run_layout_imports: Any, root: Path, capsys: Any) -> tuple[Any, str]:
    capsys.readouterr()
    code = lint_run_layout_imports.main(["--root", str(root)])
    return code, capsys.readouterr().out



def test_1105_layout_lint_fails_a_planted_new_gated_use(tmp_path, capsys):
    """A gated use planted in a scratch copy of the sweep (a RunPaths import in a new module, a
    second RunPaths import in a migrated caller's function, a Run.at call in a former names-only
    user) makes the lint exit nonzero naming the module, function and name. Positive control: a
    planted helper import (artifact_file) passes."""
    lint_run_layout_imports = _lint()
    root = _sweep_copy(tmp_path)
    _plant(root, "learning/planted_new.py",
           "from defender.run_repository import RunPaths  # noqa: F401\n")
    with (root / _CLI).open("a", encoding="utf-8") as fh:
        fh.write("\n\ndef _planted_second(run_dir):\n"
                 "    from defender.run_repository import RunPaths\n"
                 "    return RunPaths(run_dir)\n")
    with (root / "learning/judge/render.py").open("a", encoding="utf-8") as fh:
        fh.write("\n\ndef _planted_page(run_dir):\n"
                 "    from defender.run_repository import Run\n"
                 "    return Run.at(run_dir)\n")
    code, out = _main(lint_run_layout_imports, root, capsys)
    assert isinstance(code, int), f"three planted gated uses passed:\n{out}"
    assert code != 0, f"three planted gated uses passed:\n{out}"
    for module, function, name in (("learning/planted_new.py", "<module>", "RunPaths"),
                                   (_CLI, "_planted_second", "RunPaths"),
                                   ("learning/judge/render.py", "_planted_page", "Run.at")):
        line = [ln for ln in out.splitlines() if module in ln and function in ln and name in ln]
        assert line, f"no finding names {module} / {function} / {name}:\n{out}"
    clean = _sweep_copy(tmp_path / "control")
    _plant(clean, "learning/planted_helper.py",
           "from defender.run_repository import artifact_file  # noqa: F401\n")
    code, out = _main(lint_run_layout_imports, clean, capsys)
    assert code == 0, f"a helper import (artifact_file) was flagged:\n{out}"


def test_1105_layout_lint_fails_a_stale_allow_list_entry(tmp_path, capsys):
    """An allow-list entry with no matching use, or with a count above the uses it covers, makes
    the lint exit nonzero naming the stale entry."""
    lint_run_layout_imports = _lint()
    root = _sweep_copy(tmp_path)
    caller = _CLI
    # #1105 PR 2 migrated this caller off RunPaths (the launcher keeps only the predicates,
    # helpers-only) and emptied the allow-list (D7″), so the entry PR 1 listed for its import is
    # now stale on the tree itself.
    entry = (caller, "<module>", "RunPaths", 1)
    found = lint_run_layout_imports.scan(root, allow_list=(entry,))
    stale = [f for f in found if "stale" in str(getattr(f, "display", ""))
             and caller in str(getattr(f, "display", ""))
             and "RunPaths" in str(getattr(f, "display", ""))]
    assert stale, (f"the cli.py entry covers no use, and the lint did not name it "
                   f"stale: {_displays(found)}")
    code, out = _main(lint_run_layout_imports, root, capsys)
    assert code == 0, f"without the entry the copy is not clean under the empty list:\n{out}"
    # A module whose row gates RunPaths (archive.py, PR 1's sample, is a path-taking reader
    # since F-09; the launcher is helpers-only).
    planted = _planted(tmp_path / "count")
    _plant(planted, caller,
           "from defender.run_repository import RunPaths  # noqa: F401\n")
    entry = (caller, "<module>", "RunPaths")
    assert not lint_run_layout_imports.scan(planted, allow_list=(entry + (1,),)), (
        "one use, one entry of count 1: clean")
    found = lint_run_layout_imports.scan(planted, allow_list=(entry + (2,),))
    assert any("stale" in str(getattr(f, "display", "")) and caller in
               str(getattr(f, "display", "")) for f in found), (
        f"a count above the uses it covers is not reported stale: {_displays(found)}")
    found = lint_run_layout_imports.scan(
        planted, allow_list=(entry + (1,), (caller, "gone", "RunPaths", 1)))
    assert any("stale" in str(getattr(f, "display", "")) and "gone" in
               str(getattr(f, "display", "")) for f in found), (
        f"an entry with no matching use is not reported stale: {_displays(found)}")



# ==========================================================================================
# What is gated.
# ==========================================================================================

def test_1105_layout_lint_gates_every_layout_name_but_the_eight_helpers_including_a_new_export(tmp_path):
    """In a module with no layout exemption, importing any of the eight helpers (artifact_file,
    artifact_dir, plain_file, contained_payload, LEAD_ID_RE, gather_summaries_shape,
    is_case_answer_key, GATHER_RAW_SHAPE) passes, importing each other layout name (RunPaths,
    RUN_LAYOUT, SessionPaths, WIRE_LOG_NAMES, GATE_METADATA_KEY, RunLayout, WireLogNames) is
    flagged, and a name newly added to _layout is flagged until it is
    listed."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    layout = root / "run_repository" / "_layout.py"
    layout.parent.mkdir(parents=True, exist_ok=True)
    with layout.open("a", encoding="utf-8") as fh:
        fh.write('\n\nBRAND_NEW_LAYOUT_NAME = "brand-new"\n')
    mod = "learning/default_deny_probe.py"
    imports = "".join(f"from defender.run_repository import {n}  # noqa: F401\n"
                      for n in (*sorted(HELPERS), *NAMED_GATED))
    _plant(root, mod, imports + "from defender.run_repository._layout import "
                                "BRAND_NEW_LAYOUT_NAME  # noqa: F401\n")
    flagged = {k[2] for k in _in(lint_run_layout_imports.scan(root, allow_list=()), mod)}
    assert flagged == {*NAMED_GATED, "BRAND_NEW_LAYOUT_NAME"}, (
        f"gated: expected the eight named layout names and the new export, got {sorted(flagged)}")
    assert frozenset(lint_run_layout_imports.HELPERS) == HELPERS, (
        "the helper list (what 'listed' means) is not exactly the eight helpers")



def test_1105_layout_lint_flags_a_star_import_from_the_door_or_an_owner(tmp_path):
    """`from defender.run_repository import *` and a star import from _episode_paths,
    _episode_handle or _tenant are flagged in a non-owner module."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    modules = {f"learning/star_{i}.py": f"from {source} import *  # noqa: F403\n"
               for i, source in enumerate(("defender.run_repository", "defender._episode_paths",
                                           "defender._episode_handle", "defender._tenant"))}
    for module, text in modules.items():
        _plant(root, module, text)
    _plant(root, "learning/star_control.py", "from os.path import *  # noqa: F403\n")
    found = lint_run_layout_imports.scan(root, allow_list=())
    for module, text in modules.items():
        assert _in(found, module), f"{text.strip()!r} in a non-owner module is not flagged"
    assert not _in(found, "learning/star_control.py"), "a star import of a non-owner was flagged"



# ==========================================================================================
# The categories table and the sweep.
# ==========================================================================================


def test_1105_layout_lint_reports_an_unparseable_module(tmp_path, capsys):
    """A module in the sweep that does not parse, or cannot be decoded as UTF-8, is reported as a
    finding, the rest of the sweep still runs, and the lint exits nonzero; such a module is never
    skipped."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    _plant(root, "learning/broken_syntax.py", "def broken(:\n")
    (root / "learning" / "broken_bytes.py").write_bytes(b"x = '\xff\xfe'\n")
    _plant(root, "learning/after_broken.py",
           "from defender.run_repository import RunPaths  # noqa: F401\n")
    found = lint_run_layout_imports.scan(root, allow_list=())
    shown = _displays(found)
    for broken in ("learning/broken_syntax.py", "learning/broken_bytes.py"):
        assert broken in shown, f"{broken} is not reported (a skipped module is unlinted):\n{shown}"
    assert _in(found, "learning/after_broken.py"), "the sweep stopped at the broken module"
    code, out = _main(lint_run_layout_imports, root, capsys)
    assert code != 0, f"exit {code}:\n{out}"
    assert "broken_syntax.py" in out, f"exit {code}:\n{out}"




# ==========================================================================================
# The neighbouring gates under the fence (MF-19, MF-20).
# ==========================================================================================

