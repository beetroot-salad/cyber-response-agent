"""#1105 PR 1 — D7's layout lint, `scripts/lint/lint_run_layout_imports.py` (→ O1), and the
neighbouring gates it must agree with (MF-05, MF-06, MF-07, MF-19, MF-20: the interim FENCE until
#1082; NM-08, NM-09; the After-the-gate AUTO keying `deferred_legacy` by (module, function)).

Outside the owners, production code may not take a run-folder layout name, an episode-runs name,
`Tenant.runs` or a handle constructor except where D7's category table exempts it or the PR 1
allow-list names the use. The allow-list is the only hatch (no inline suppression); a stale
entry fails; PR 1's list holds exactly 18 entries: ruling 1's nine sites, `cli.py:1089`
(`tenant.tenant.runs`), `run_common.py:90` (`tenant.runs`) and `:96` (`Run.for_tenant`),
`visualize_run.py:633` (`Run.at`) and the five unmigrated callers' module-level `RunPaths`
imports. The module-level `RunPaths` imports of `learning/author/lessons/run.py` (:11) and
`learning/author/verify_forward/forward.py` (:6), which the (module, function) keying of
`deferred_legacy` would leave outside the four exempt readers, move inside `disposition_for` and
`load_run_context` in PR 1 (the owner's Phase F ruling on FR-1: the allow-list stays 18, so
PR 2's empty allow-list stays reachable); no allow-list entry names either module.

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
  `not-a-run`, `deferred_legacy`, `unmigrated`, `helpers-only`;
* `DEFERRED_LEGACY: frozenset[tuple[str, str]]` — the four exempt (module, function) pairs;
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
CI = H.WORKTREE / ".github" / "workflows" / "ci.yml"

#: The eight layout names that are not gated (D7: rev 3's five plus the predicates and shape
#: constants in use outside the owners at bc4ce944, R4-26).
HELPERS = frozenset({"artifact_file", "artifact_dir", "plain_file", "contained_payload",
                     "LEAD_ID_RE", "gather_summaries_shape", "is_case_answer_key",
                     "GATHER_RAW_SHAPE"})
#: Layout names D7 names as gated.
NAMED_GATED = ("RunPaths", "RUN_LAYOUT", "SessionPaths", "WIRE_LOG_NAMES", "GATE_METADATA_KEY",
               "RunLayout", "WireLogNames", "resolve_run_bundle")
#: The door's public names that are not layout names (D1.3).
NON_LAYOUT = frozenset({"Run", "RunRecord", "ArchivedWorld", "RecordHandle", "case_ref", "RunId",
                        "open_run", "list_run_ids", "bound_runs", "run_exists",
                        "record_episode_runs", "episode_runs", "sibling_run_ids",
                        "episode_sibling_ids", "RunRefused"})

_VE = "scripts/visualize/visualize_episode.py"
_CLI = "learning/branch/cli.py"
_LESSONS = "learning/author/lessons/run.py"
_FORWARD = "learning/author/verify_forward/forward.py"
#: PR 1's allow-list (A4-10; the owner's Phase F ruling on FR-1): 18 (module, function, name,
#: count). The two deferred_legacy modules' module-level imports move into their exempt readers.
EXPECTED_ALLOW_LIST = (
    ("run_common.py", "materialize_run", "EpisodePaths.runs", 1),          # :88
    ("run_common.py", "materialize_run", "Tenant.runs", 1),                # :90
    ("run_common.py", "materialize_run", "Run.for_tenant", 1),             # :96
    (_CLI, "sibling_runs_base", "EpisodePaths.runs", 1),                   # :540
    (_CLI, "start_family", "Episode.runs", 1),                             # :604
    (_CLI, "_launch", "Tenant.runs", 1),                                   # :1089
    ("run.py", "main", "Episode.runs", 1),                                 # :554
    (_VE, "_load_episode", "EpisodeLayout.run", 1),                        # :709
    (_VE, "_build_roster", "EpisodeLayout.runs", 1),                       # :763
    (_VE, "_render_roster_item", "EpisodeLayout.run_page", 1),             # :1615
    (_VE, "_render_one_world", "EpisodeLayout.run_page", 1),               # :1666
    (_VE, "_render_findings_section", "EpisodeLayout.runs", 1),            # :1847
    ("scripts/visualize/visualize_run.py", "main", "Run.at", 1),           # :633
    ("learning/branch/archive.py", "<module>", "RunPaths", 1),
    ("learning/branch/questioner/__init__.py", "<module>", "RunPaths", 1),
    ("learning/leads/lead_author/__init__.py", "<module>", "RunPaths", 1),
    ("learning/ops/trace_lesson.py", "<module>", "RunPaths", 1),
    (_CLI, "<module>", "RunPaths", 1),
)

#: The four legacy readers `deferred_legacy` exempts, keyed by (module, function) (N-f; the
#: After-the-gate AUTO, NF-15).
EXPECTED_DEFERRED_LEGACY = frozenset({
    (_LESSONS, "disposition_for"), (_LESSONS, "_has_confident_ground_truth"),
    (_FORWARD, "load_run_context"), (_FORWARD, "expected_disposition")})

_PACKAGE_FILES = ("__init__.py", "_layout.py", "_handle.py", "_lookup.py", "_record.py",
                  "_held.py", "_id.py", "_errors.py")
#: D7's categories table (design-rev4.md, "Categories, by module"), every module in exactly one
#: row: the owners plus the 57 non-owner production importers of the layout at 80888efb.
EXPECTED_CATEGORIES: dict[str, frozenset[str]] = {
    "owners": frozenset({*(f"run_repository/{f}" for f in _PACKAGE_FILES),
                         "_episode_paths.py", "_episode_handle.py", "_tenant.py"}),
    "running-investigation": frozenset({
        "hooks/budget_enforcer.py", "hooks/record_lead.py",
        "runtime/challenge_gate.py", "runtime/circuit_breaker.py", "runtime/close_tool.py",
        "runtime/driver/__init__.py", "runtime/driver/_build.py",
        "runtime/lead_zero/__init__.py", "runtime/lead_zero/_capture.py", "runtime/observe.py",
        "runtime/permission/files.py", "runtime/permission/policies/_common.py",
        "runtime/run_end.py", "runtime/scrub.py", "runtime/session_store.py",
        "runtime/tools/_deps.py", "runtime/tools/_document.py", "runtime/tools/_files.py",
        "runtime/tools_gather.py", "runtime/toon_gate.py", "runtime/box/_lifecycle.py",
        "runtime/branch/__init__.py", "runtime/branch/_frontier.py", "runtime/branch/_seed.py",
        "runtime/branch/_spec.py", "scripts/case_history/case_ticket.py",
        "scripts/gather_tools/record_query.py", "skills/invlang/corpus.py"}),
    "names-only": frozenset({
        "_report.py", "_artifact_schema.py", "runtime/compaction.py", "learning/judge/render.py",
        "learning/branch/seams.py", "learning/judge/__init__.py",
        "learning/author/verify_forward/checks.py", "learning/core/config.py",
        "scripts/workspace_map.py"}),
    "run-lifecycle": frozenset({"run.py", "run_common.py",
                                "scripts/case_history/ticket_writer.py"}),
    "path-taking-readers": frozenset({
        "learning/lead_repository.py", "scripts/visualize/visualize_run.py",
        "scripts/visualize/visualize_runtime.py", "scripts/visualize/visualize_messages.py",
        "scripts/visualize/visualize_data.py", "scripts/visualize/visualize_primitives.py"}),
    "not-a-run": frozenset({_VE}),
    "deferred_legacy": frozenset({_LESSONS, _FORWARD}),
    "unmigrated": frozenset({
        "learning/branch/archive.py", "learning/branch/questioner/__init__.py",
        "learning/leads/lead_author/__init__.py", "learning/ops/trace_lesson.py", _CLI}),
    "helpers-only": frozenset({"learning/branch/ledger.py", "learning/judge/enqueue.py",
                               "learning/judge/run.py"}),
}

#: One representative module per row, for the planted-tree tests.
_ROW_SAMPLE = {
    "owners": "_episode_handle.py",
    "running-investigation": "runtime/observe.py",
    "names-only": "learning/judge/render.py",
    "run-lifecycle": "run_common.py",
    "path-taking-readers": "scripts/visualize/visualize_run.py",
    "not-a-run": _VE,
    "deferred_legacy": _LESSONS,
    "unmigrated": "learning/branch/archive.py",
    "helpers-only": "learning/judge/enqueue.py",
    "uncategorised": "learning/planted_probe.py",
}


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


def _drop_import(path: Path, name: str) -> None:
    """Rewrite `path` without its module-level import of `name` (the rest of the module is
    kept, unparsed back from its AST)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    body: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and any(a.name == name for a in node.names):
            node.names = [a for a in node.names if a.name != name]
            if not node.names:
                continue
        body.append(node)
    tree.body = body
    path.write_text(ast.unparse(tree) + "\n", encoding="utf-8")


# ==========================================================================================
# CI, the real tree and the allow-list.
# ==========================================================================================

def test_1105_ci_runs_the_layout_lint_as_its_own_step():
    """.github/workflows/ci.yml has a blocking step whose run line executes
    scripts/lint/lint_run_layout_imports.py (no continue-on-error), so a planted violation fails
    the build."""
    doc = yaml.safe_load(CI.read_text(encoding="utf-8"))
    steps = [(job_name, job, step) for job_name, job in (doc.get("jobs") or {}).items()
             for step in job.get("steps") or []
             if "scripts/lint/lint_run_layout_imports.py" in str(step.get("run", ""))]
    assert steps, ("no CI step runs scripts/lint/lint_run_layout_imports.py (D7, F32: a lint is "
                   "in CI only once a step names it)")
    for job_name, job, step in steps:
        assert not job.get("continue-on-error"), f"the {job_name} step {step.get('name')!r} may fail without failing the build"
        assert not step.get("continue-on-error"), f"the {job_name} step {step.get('name')!r} may fail without failing the build"
        assert "|| true" not in str(step["run"]), f"{step['run']!r} swallows the exit status"
    lint_run_layout_imports = _lint()
    assert Path(lint_run_layout_imports.__file__).resolve() == LINT_FILE.resolve(), (
        "the step runs the program this suite pins")


@pytest.mark.gate
def test_1105_layout_lint_is_clean_on_the_tree_and_every_allow_list_entry_is_load_bearing():
    """lint_run_layout_imports exits 0 on the tree with its PR 1 allow-list of exactly 18
    entries: ruling 1's nine sites (run_common.py:88, learning/branch/cli.py:540,604, run.py:554,
    scripts/visualize/visualize_episode.py:709,763,1615,1666,1847), cli.py:1089
    (tenant.tenant.runs), run_common.py:90 (tenant.runs) and :96 (Run.for_tenant),
    visualize_run.py:633 (Run.at), and the module-level RunPaths imports of
    learning/branch/archive.py, learning/branch/questioner/__init__.py,
    learning/leads/lead_author/__init__.py, learning/ops/trace_lesson.py and
    learning/branch/cli.py; removing any one entry makes the lint fail."""
    lint_run_layout_imports = _lint()
    assert lint_run_layout_imports.main([]) == 0, "the layout lint is not clean on the tree"
    listed = sorted(tuple(e) for e in lint_run_layout_imports.ALLOW_LIST)
    assert listed == sorted(EXPECTED_ALLOW_LIST), (
        f"the PR 1 allow-list is not the 18 named entries: {listed}")
    raw = lint_run_layout_imports.scan(lint_run_layout_imports.DEFENDER, allow_list=())
    uses = _keys(raw)
    expected = collections.Counter({(m, f, n): c for m, f, n, c in EXPECTED_ALLOW_LIST})
    assert uses == expected, (
        "with no allow-list the tree's gated uses are not exactly the listed ones, so some "
        f"entry is not load-bearing or some use is unlisted: {sorted(uses - expected)} extra, "
        f"{sorted(expected - uses)} missing")
    dropped = EXPECTED_ALLOW_LIST[1:]
    found = lint_run_layout_imports.scan(lint_run_layout_imports.DEFENDER, allow_list=dropped)
    assert _keys(found) == collections.Counter({EXPECTED_ALLOW_LIST[0][:3]: 1}), (
        f"dropping one entry did not leave exactly its use flagged: {_displays(found)}")


def test_1105_layout_lint_fails_a_planted_new_gated_use(tmp_path, capsys):
    """A gated use planted in a scratch copy of the sweep (a RunPaths import in a new module, a
    second RunPaths import in an unmigrated caller's function, a Run.at call in a names-only
    user) makes the lint exit nonzero naming the module, function and name. Positive control: a
    planted helper import (artifact_file) passes."""
    lint_run_layout_imports = _lint()
    root = _sweep_copy(tmp_path)
    _plant(root, "learning/planted_new.py",
           "from defender.run_repository import RunPaths  # noqa: F401\n")
    with (root / "learning/ops/trace_lesson.py").open("a", encoding="utf-8") as fh:
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
                                   ("learning/ops/trace_lesson.py", "_planted_second", "RunPaths"),
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
    caller = "learning/ops/trace_lesson.py"
    _drop_import(root / caller, "RunPaths")
    code, out = _main(lint_run_layout_imports, root, capsys)
    stale = [ln for ln in out.splitlines() if "stale" in ln and caller in ln and "RunPaths" in ln]
    assert isinstance(code, int), (f"the trace_lesson.py entry covers no use any more, and the lint did not name it stale "
        f"(exit {code}):\n{out}")
    assert code != 0, (f"the trace_lesson.py entry covers no use any more, and the lint did not name it stale "
        f"(exit {code}):\n{out}")
    assert stale, (f"the trace_lesson.py entry covers no use any more, and the lint did not name it stale "
        f"(exit {code}):\n{out}")
    shutil.copyfile(H.DEFENDER / caller, root / caller)
    code, out = _main(lint_run_layout_imports, root, capsys)
    assert code == 0, f"with the use restored the copy is not clean under the 18 entries:\n{out}"
    planted = _planted(tmp_path / "count")
    _plant(planted, "learning/branch/archive.py",
           "from defender.run_repository import RunPaths  # noqa: F401\n")
    entry = ("learning/branch/archive.py", "<module>", "RunPaths")
    assert not lint_run_layout_imports.scan(planted, allow_list=(entry + (1,),)), (
        "one use, one entry of count 1: clean")
    found = lint_run_layout_imports.scan(planted, allow_list=(entry + (2,),))
    assert any("stale" in str(getattr(f, "display", "")) and "archive.py" in
               str(getattr(f, "display", "")) for f in found), (
        f"a count above the uses it covers is not reported stale: {_displays(found)}")
    found = lint_run_layout_imports.scan(
        planted, allow_list=(entry + (1,), ("learning/branch/archive.py", "gone", "RunPaths", 1)))
    assert any("stale" in str(getattr(f, "display", "")) and "gone" in
               str(getattr(f, "display", "")) for f in found), (
        f"an entry with no matching use is not reported stale: {_displays(found)}")


_KEYED = """\
from defender.run_repository import Run


def _register(opener):
    return lambda fn: fn


class Holder:
    def method(self, run_dir):
        return Run.at(run_dir)


def outer(run_dir):
    return (lambda: Run.at(run_dir))()


@_register(Run.at)
def decorated(run_dir, opener=Run.at):
    return run_dir
"""


def test_1105_layout_lint_keys_the_allow_list_by_module_function_and_name_with_a_count_and_has_no_inline_hatch(tmp_path):
    """The allow-list key is (module, enclosing qualified function or <module>, gated name) with
    an exact count: lambdas, decorators and defaults key under the def or <module> that evaluates
    them; a listed use moved to another function, or repeated beyond its count, fails; a count
    above the uses is stale and fails; a duplicate entry is a finding; and no inline comment on a
    gated use (a noqa or an 'ok' marker) silences it."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    mod = "learning/keyed_probe.py"
    _plant(root, mod, _KEYED)
    found = lint_run_layout_imports.scan(root, allow_list=())
    expected = collections.Counter({(mod, "Holder.method", "Run.at"): 1,
                                    (mod, "outer", "Run.at"): 1,
                                    (mod, "<module>", "Run.at"): 2})
    assert _keys(found) == expected, (
        f"keys are not (module, qualified def or <module>, name): {sorted(_keys(found).items())}")
    exact = tuple(k + (c,) for k, c in expected.items())
    assert not lint_run_layout_imports.scan(root, allow_list=exact), "the exact list is clean"
    moved = tuple(e if e[1] != "outer" else (mod, "decorated", "Run.at", 1) for e in exact)
    assert _in(lint_run_layout_imports.scan(root, allow_list=moved), mod), (
        "a listed use moved to another function still passes")
    beyond = tuple(e if e[1] != "<module>" else (mod, "<module>", "Run.at", 1) for e in exact)
    assert (mod, "<module>", "Run.at") in _keys(
        lint_run_layout_imports.scan(root, allow_list=beyond)), (
        "a use repeated beyond its count passes")
    above = tuple(e if e[1] != "outer" else (mod, "outer", "Run.at", 2) for e in exact)
    found = lint_run_layout_imports.scan(root, allow_list=above)
    assert any("stale" in str(getattr(f, "display", "")) for f in found), (
        "a count above the uses is not stale")
    found = lint_run_layout_imports.scan(root, allow_list=exact + exact[:1])
    assert any("duplicate" in str(getattr(f, "display", "")) for f in found), (
        f"a duplicate allow-list entry is not a finding: {_displays(found)}")
    hatched = "learning/hatched_probe.py"
    _plant(root, hatched,
           "from defender.run_repository import RunPaths  # noqa\n"
           "from defender.run_repository import RUN_LAYOUT  # lint-run-layout: ok — legacy\n"
           "from defender.run_repository import SessionPaths  # lint-run-layout-imports: ok — x\n")
    names = {k[2] for k in _in(lint_run_layout_imports.scan(root, allow_list=exact), hatched)}
    assert names == {"RunPaths", "RUN_LAYOUT", "SessionPaths"}, (
        f"an inline comment silenced a gated use: only {sorted(names)} reported")


# ==========================================================================================
# What is gated.
# ==========================================================================================

def test_1105_layout_lint_gates_every_layout_name_but_the_eight_helpers_including_a_new_export(tmp_path):
    """In a module with no layout exemption, importing any of the eight helpers (artifact_file,
    artifact_dir, plain_file, contained_payload, LEAD_ID_RE, gather_summaries_shape,
    is_case_answer_key, GATHER_RAW_SHAPE) passes, importing each other layout name (RunPaths,
    RUN_LAYOUT, SessionPaths, WIRE_LOG_NAMES, GATE_METADATA_KEY, RunLayout, WireLogNames,
    resolve_run_bundle) is flagged, and a name newly added to _layout is flagged until it is
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


_EPISODE_RUNS = """\
from pathlib import Path

from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT, RUNS_DIRNAME, EpisodePaths


def reads(ep: Path, episode: Episode):
    return (EpisodePaths(ep).runs, EpisodePaths(ep).sibling_run_dir("e", "a"), LAYOUT.runs,
            LAYOUT.run("r"), LAYOUT.run_page("r"), LAYOUT.sibling_run_dir("e", "a"),
            episode.runs, RUNS_DIRNAME)


def writes(episode: Episode):
    episode.runs = None
    del episode.runs
"""

_EPISODE_RUNS_NAMES = {"EpisodePaths.runs", "EpisodePaths.sibling_run_dir", "EpisodeLayout.runs",
                       "EpisodeLayout.run", "EpisodeLayout.run_page",
                       "EpisodeLayout.sibling_run_dir", "Episode.runs", "RUNS_DIRNAME"}


def test_1105_layout_lint_flags_each_episode_runs_name_outside_the_owners(tmp_path):
    """A read, write or delete of each episode-runs name (EpisodePaths(x).runs, .sibling_run_dir,
    LAYOUT.runs/.run/.run_page/.sibling_run_dir, Episode.runs, and an import of RUNS_DIRNAME) is
    flagged in every category but the owners, the running investigation and names-only users
    included; the same code in an owner module passes."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    for module in _ROW_SAMPLE.values():
        _add(root, module, _EPISODE_RUNS)
    found = lint_run_layout_imports.scan(root, allow_list=())
    for row, module in _ROW_SAMPLE.items():
        keys = _in(found, module)
        if row == "owners":
            assert not keys, f"the same code in an owner module ({module}) was flagged: {keys}"
            continue
        names = {k[2] for k in keys}
        assert names == _EPISODE_RUNS_NAMES, (
            f"{row} ({module}): episode-runs names flagged {sorted(names)}, "
            f"missing {sorted(_EPISODE_RUNS_NAMES - names)}")
        assert collections.Counter(k[1] for k in keys if k[2] == "Episode.runs")["writes"] == 2, (
            f"{row}: the write and the delete of Episode.runs are not both flagged")


_TENANT_RUNS = """\
from defender._tenant import Tenant
from defender.runtime.run_tenant import RunTenant


def direct(tenant: Tenant):
    return tenant.runs


def carried(run_tenant: RunTenant):
    return run_tenant.tenant.runs
"""


def test_1105_layout_lint_flags_tenant_runs_outside_the_owners(tmp_path):
    """tenant.runs on a receiver typed as an accepted Tenant, and tenant.tenant.runs on its
    RunTenant carrier, are flagged outside the owners; the same read in _tenant.py or the package
    passes."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    for module in ("learning/tenant_probe.py", "runtime/observe.py", "_tenant.py",
                   "run_repository/_lookup.py"):
        _add(root, module, _TENANT_RUNS)
    found = lint_run_layout_imports.scan(root, allow_list=())
    for module in ("learning/tenant_probe.py", "runtime/observe.py"):
        assert sorted(_in(found, module)) == [(module, "carried", "Tenant.runs"),
                                              (module, "direct", "Tenant.runs")], (
            f"{module}: tenant.runs / tenant.tenant.runs not both flagged: {_in(found, module)}")
    for owner in ("_tenant.py", "run_repository/_lookup.py"):
        assert not _in(found, owner), f"the owner {owner} was flagged: {_in(found, owner)}"


_CONSTRUCTORS = """\
from defender.run_repository import ArchivedWorld, Run


def build(run_dir, tenant_id, run_id, runs_base):
    return (Run(run_dir, runs_base=None), Run.at(run_dir),
            Run.for_tenant(tenant_id, run_id, runs_base=runs_base), Run.under(runs_base, run_id),
            ArchivedWorld.at(run_dir), Run.at)
"""


def test_1105_layout_lint_flags_every_handle_constructor_outside_the_owners_but_not_a_type_import_of_run(tmp_path):
    """A call Run(...) and any reference to Run.at, Run.for_tenant, Run.under or ArchivedWorld.at
    is flagged outside the owners, the running investigation included; importing Run only to
    annotate a parameter is not flagged."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    for module in ("learning/ctor_probe.py", "runtime/observe.py", "run_repository/_lookup.py"):
        _add(root, module, _CONSTRUCTORS)
    _plant(root, "learning/type_only.py",
           "from defender.run_repository import Run\n\n\ndef takes(run: Run) -> None:\n"
           "    return None\n")
    found = lint_run_layout_imports.scan(root, allow_list=())
    expected = collections.Counter(
        {"Run": 1, "Run.at": 2, "Run.for_tenant": 1, "Run.under": 1, "ArchivedWorld.at": 1})
    for module in ("learning/ctor_probe.py", "runtime/observe.py"):
        names = collections.Counter(k[2] for k in _in(found, module))
        assert names == expected, f"{module}: constructors flagged {dict(names)}"
    assert not _in(found, "learning/type_only.py"), "importing Run for a type was flagged"
    assert not _in(found, "run_repository/_lookup.py"), "the package (an owner) was flagged"


def test_1105_layout_lint_flags_a_gated_import_wherever_it_sits(tmp_path):
    """An import of a gated name is flagged at module level, inside a function, inside a try
    block and under `if TYPE_CHECKING:`."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    sources = {
        "learning/at_module.py": "from defender.run_repository import RunPaths  # noqa: F401\n",
        "learning/in_function.py": ("def f():\n    from defender.run_repository import RunPaths\n"
                                    "    return RunPaths\n"),
        "learning/in_try.py": ("try:\n    from defender.run_repository import RunPaths  # noqa\n"
                               "except ImportError:\n    RunPaths = None\n"),
        "learning/type_checking.py": (
            "from typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n"
            "    from defender.run_repository import RunPaths  # noqa: F401\n"),
    }
    for module, text in sources.items():
        _plant(root, module, text)
    found = lint_run_layout_imports.scan(root, allow_list=())
    for module in sources:
        assert [k[2] for k in _in(found, module)] == ["RunPaths"], (
            f"{module}: the gated import is not flagged exactly once: {_in(found, module)}")
    assert _in(found, "learning/in_function.py")[0][1] == "f", "the function is the key's def"


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


_BINDING_FORMS = """\
from __future__ import annotations

from pathlib import Path
from typing import Optional

from defender._episode_handle import Episode


def with_target(d: Path):
    with Episode.open(d) as episode:
        return episode.runs


def for_target(episodes: list[Episode]):
    for ep in episodes:
        return ep.runs


def comprehension(episodes: list[Episode]):
    return [ep.runs for ep in episodes]


def optional_param(ep: Optional[Episode]):
    return ep.runs


def union_param(ep: Episode | None):
    return ep.runs


def string_annotation(ep: "Episode"):
    return ep.runs


def _make() -> Episode:
    raise NotImplementedError


def annotated_return():
    return _make().runs


def opened(d: Path):
    return Episode.open(d).runs


def untyped(ep):
    return ep.runs
"""


def test_1105_layout_lint_types_owner_receivers_through_every_binding_form_the_precedent_missed(tmp_path):
    """A gated member read is flagged when its receiver is typed as an owner through a with-as
    target, a for target, a comprehension variable, an Optional[X] or X | None or string
    annotation, an annotated return, or Episode.open(...); run.py:554 (`with door as episode`)
    is among the findings the allow-list covers. An untyped receiver is not flagged (the recorded
    gap)."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    mod = "learning/binding_forms.py"
    _plant(root, mod, _BINDING_FORMS)
    shutil.copyfile(H.DEFENDER / "run.py", root / "run.py")
    found = lint_run_layout_imports.scan(root, allow_list=())
    functions = {k[1] for k in _in(found, mod) if k[2] == "Episode.runs"}
    typed = {"with_target", "for_target", "comprehension", "optional_param", "union_param",
             "string_annotation", "annotated_return", "opened"}
    assert functions == typed, (
        f"typed receivers flagged in {sorted(functions)}; missing {sorted(typed - functions)}, "
        f"wrongly flagged {sorted(functions - typed)} (an untyped receiver is the recorded gap)")
    assert ("run.py", "main", "Episode.runs") in _keys(found), (
        "run.py:554's `with door as episode` read of episode.runs is not seen (F41)")
    assert ("run.py", "main", "Episode.runs", 1) in {
        tuple(e) for e in lint_run_layout_imports.ALLOW_LIST}, (
        "run.py:554 is not among the allow-list's entries")


def test_1105_layout_lint_flags_a_re_exports_own_import(tmp_path):
    """A module that re-exports a gated name (imports it and lists it or binds it for others) is
    flagged at its own import of that name."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    _plant(root, "learning/relay_all.py",
           'from defender.run_repository import RunPaths\n\n__all__ = ["RunPaths"]\n')
    _plant(root, "learning/relay_bind.py",
           "from defender.run_repository import RunPaths as _RunPaths\n\nPATHS = _RunPaths\n")
    _plant(root, "learning/relay_helper.py",
           'from defender.run_repository import artifact_file\n\n__all__ = ["artifact_file"]\n')
    found = lint_run_layout_imports.scan(root, allow_list=())
    for module in ("learning/relay_all.py", "learning/relay_bind.py"):
        assert (module, "<module>", "RunPaths") in _keys(found), (
            f"{module}: the relay's own import of RunPaths is not flagged: {_in(found, module)}")
    assert not _in(found, "learning/relay_helper.py"), "re-exporting a helper was flagged"


# ==========================================================================================
# The categories table and the sweep.
# ==========================================================================================

def test_1105_layout_lint_puts_every_layout_importer_in_exactly_one_category(tmp_path):
    """The lint's category table places each of the 57 non-owner production importers of the
    layout at 80888efb in exactly one row as D7's table lists them, the owners in their own row,
    and exempts layout names exactly in the running-investigation, names-only, run-lifecycle,
    path-taking-reader, not-a-run and deferred_legacy rows; a module in no row gets no
    exemption. (The deferred_legacy row exempts only its four readers, keyed by (module,
    function), per the After-the-gate AUTO.)"""
    lint_run_layout_imports = _lint()
    table = {row: frozenset(mods) for row, mods in dict(lint_run_layout_imports.CATEGORIES).items()}
    assert table == EXPECTED_CATEGORIES, (
        f"the category table is not D7's: rows {sorted(table)}; differing rows "
        f"{sorted(r for r in EXPECTED_CATEGORIES if table.get(r) != EXPECTED_CATEGORIES[r])}")
    every = [m for mods in table.values() for m in mods]
    assert len(every) == len(set(every)), "a module sits in more than one row"
    assert sum(len(v) for r, v in EXPECTED_CATEGORIES.items() if r != "owners") == 57
    root = _planted(tmp_path)
    for module in _ROW_SAMPLE.values():
        _add(root, module, "from defender.run_repository import RunPaths  # noqa: F401\n\n\n"
                           "def disposition_for(cfg, run_id):\n"
                           "    from defender.run_repository import RUN_LAYOUT\n"
                           "    return RUN_LAYOUT\n")
    found = lint_run_layout_imports.scan(root, allow_list=())
    exempt_rows = {"owners", "running-investigation", "names-only", "run-lifecycle",
                   "path-taking-readers", "not-a-run"}
    for row, module in _ROW_SAMPLE.items():
        keys = set(_in(found, module))
        if row in exempt_rows:
            assert not keys, f"{row} ({module}) is exempt for layout names but was flagged: {keys}"
        elif row == "deferred_legacy":
            assert keys == {(module, "<module>", "RunPaths")}, (
                f"deferred_legacy exempts disposition_for only, not the module: {keys}")
        else:
            assert keys == {(module, "<module>", "RunPaths"),
                            (module, "disposition_for", "RUN_LAYOUT")}, (
                f"{row} ({module}) gets no layout exemption, but flagged only {keys}")


def test_1105_the_legacy_readers_sit_in_deferred_legacy_not_on_the_allow_list(tmp_path):
    """The deferred_legacy exemption is keyed by (module, function) for the four named readers,
    not by module: disposition_for and _has_confident_ground_truth in
    learning/author/lessons/run.py, load_run_context and expected_disposition in
    learning/author/verify_forward/forward.py. A gated layout use elsewhere in either module
    (lessons/run.py holds the live findings drain) is not exempt: it joins the allow-list or the
    run-lifecycle category per D7's table, and a planted new use in either module outside the
    four functions fails the lint. No allow-list entry names either module, under any function
    or <module>: PR 1 moves their module-level RunPaths imports into disposition_for and
    load_run_context (the owner's Phase F ruling on FR-1)."""
    lint_run_layout_imports = _lint()
    assert frozenset(tuple(p) for p in lint_run_layout_imports.DEFERRED_LEGACY) == (
        EXPECTED_DEFERRED_LEGACY), "the deferred_legacy exemption is not the four (module, def)"
    listed = {tuple(e)[:2] for e in lint_run_layout_imports.ALLOW_LIST}
    assert not listed & EXPECTED_DEFERRED_LEGACY, "an allow-list entry names a legacy reader"
    named = sorted(e for e in listed if e[0] in (_LESSONS, _FORWARD))
    assert not named, (
        f"an allow-list entry names a deferred_legacy module ({named}); FR-1 keeps the list at 18 "
        "by moving the two module-level RunPaths imports into the exempt readers")
    root = _planted(tmp_path)
    for module, readers in ((_LESSONS, ("disposition_for", "_has_confident_ground_truth")),
                            (_FORWARD, ("load_run_context", "expected_disposition"))):
        body = "".join(f"def {fn}(*args):\n    from defender.run_repository import RunPaths\n"
                       f"    return RunPaths\n\n\n" for fn in (*readers, "_planted_drain_use"))
        _plant(root, module, body)
    found = lint_run_layout_imports.scan(root, allow_list=())
    for module in (_LESSONS, _FORWARD):
        assert set(_in(found, module)) == {(module, "_planted_drain_use", "RunPaths")}, (
            f"{module}: only the use outside the four readers is a finding: {_in(found, module)}")


#: The modules a deferred_legacy reader may take a layout name from, in every spelling the
#: two modules could use at HEAD or after the re-spell.
_LEGACY_SOURCES = ("defender._run_paths", "defender.run_repository",
                   "defender.run_repository._layout")


def _resolved(node: ast.ImportFrom, package: str) -> str:
    """The absolute module an import-from names (`package` is the importing module's)."""
    if not node.level:
        return node.module or ""
    parts = package.split(".")
    base = parts[: len(parts) - node.level + 1]
    return ".".join([*base, *([node.module] if node.module else [])])


def _qualnames(tree: ast.Module) -> dict[ast.AST, str]:
    """Each node of `tree` mapped to its innermost enclosing qualified def (classes included),
    or "<module>"."""
    out: dict[ast.AST, str] = {}

    def walk(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = child.name if scope == "<module>" else f"{scope}.{child.name}"
            out[child] = inner
            walk(child, inner)

    walk(tree, "<module>")
    return out


def _bindings(node: ast.AST, package: str) -> list[tuple[str, str]]:
    """(bound name, what) for each name `node` binds from `_LEGACY_SOURCES`: a non-helper name
    imported from one (absolute, relative or aliased), or one of them imported whole."""
    out: list[tuple[str, str]] = []
    if isinstance(node, ast.ImportFrom):
        source = _resolved(node, package)
        for alias in node.names:
            whole = f"{source}.{alias.name}"
            if source in _LEGACY_SOURCES and alias.name not in HELPERS:
                out.append((alias.asname or alias.name, f"imports {alias.name} from {source}"))
            elif whole in _LEGACY_SOURCES:
                out.append((alias.asname or alias.name, f"imports {whole} whole"))
    elif isinstance(node, ast.Import):
        out.extend((alias.asname or alias.name.split(".")[0], f"imports {alias.name} whole")
                   for alias in node.names if alias.name in _LEGACY_SOURCES)
    return out


def _layout_uses(path: Path, rel: str) -> list[tuple[str, int, str]]:
    """(enclosing qualified def or "<module>", line, what) for every binding `_bindings` finds
    in the module `rel` at `path`, and every read of a name so bound."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scope = _qualnames(tree)
    package = ".".join(("defender", *Path(rel).parts[:-1]))
    bound: set[str] = set()
    uses: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        for name, what in _bindings(node, package):
            bound.add(name)
            uses.append((scope[node], getattr(node, "lineno", 0), what))
    uses.extend((scope[node], node.lineno, f"reads {node.id}") for node in ast.walk(tree)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                and node.id in bound)
    return uses


def test_1105_the_legacy_modules_use_layout_names_only_inside_their_exempt_readers(tmp_path):
    """In learning/author/lessons/run.py and learning/author/verify_forward/forward.py every
    binding of a gated layout name (RunPaths) imported from the door, its _layout submodule or
    the old _run_paths module, under any spelling (absolute, relative, aliased, or the module
    imported whole), and every read of a name so bound, sits inside one of the four
    deferred_legacy readers (disposition_for, _has_confident_ground_truth, load_run_context,
    expected_disposition), never at module level: PR 1 moves the module-level imports at
    lessons/run.py:11 and forward.py:6 into disposition_for and load_run_context (the owner's
    Phase F ruling on FR-1), so the 18-entry allow-list needs no row for either module.
    lint_run_layout_imports, run with no allow-list over a planted tree holding the two real
    modules, reports nothing in them; positive control: the same tree with a module-level
    RunPaths import restored in each is flagged there."""
    for module in (_LESSONS, _FORWARD):
        uses = _layout_uses(H.DEFENDER / module, module)
        outside = [u for u in uses if (module, u[0]) not in EXPECTED_DEFERRED_LEGACY]
        assert not outside, (
            f"{module}: layout uses outside the four deferred_legacy readers (FR-1 moves them "
            f"inside): {outside}")
        assert uses, f"{module}: no layout use found at all, so this census reads nothing"
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path / "moved")
    control = _planted(tmp_path / "control")
    for module in (_LESSONS, _FORWARD):
        text = (H.DEFENDER / module).read_text(encoding="utf-8")
        _plant(root, module, text)
        _plant(control, module, "from defender.run_repository import RunPaths  # noqa: F401\n"
                                + text)
    found = lint_run_layout_imports.scan(root, allow_list=())
    assert isinstance(found, list), f"scan() did not return a list of findings: {found!r}"
    legacy = [f for f in found
              if any(m in str(getattr(f, "display", "")) for m in (_LESSONS, _FORWARD))]
    assert legacy == [], (
        f"the lint flags the moved legacy modules with no allow-list: {_displays(legacy)}")
    flagged = lint_run_layout_imports.scan(control, allow_list=())
    for module in (_LESSONS, _FORWARD):
        assert (module, "<module>", "RunPaths") in _keys(flagged), (
            f"{module}: a restored module-level RunPaths import is not flagged, so the clean "
            f"verdict above says nothing: {_in(flagged, module)}")


def test_1105_layout_lint_sweeps_defender_minus_evals_and_tests(tmp_path):
    """A gated import planted under defender/evals/, defender/tests/, a __pycache__ directory, a
    hidden directory or a venv is not reported, while the same import planted under
    defender/learning/ is; the lint finds its root from its own checkout, so a run from another
    working directory or a worktree gives the same findings. Each venv clause is pinned alone:
    venv/ holds no pyvenv.cfg (skipped by its name), and learning/site_env/ holds one under a
    name no other rule skips."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    use = "from defender.run_repository import RunPaths  # noqa: F401\n"
    outside = ("evals/held_out_probe.py", "tests/test_probe.py", "learning/__pycache__/cached.py",
               "learning/.hidden/probe.py", ".venv/lib/probe.py", "venv/probe.py",
               "learning/site_env/lib/probe.py")
    for module in (*outside, "learning/swept_probe.py"):
        _plant(root, module, use)
    for venv in (".venv", "learning/site_env"):
        (root / venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    found = lint_run_layout_imports.scan(root, allow_list=())
    assert _in(found, "learning/swept_probe.py"), "the import under defender/learning/ is missed"
    for module in outside:
        assert not _in(found, module), f"{module} is outside the sweep but was reported"
    assert Path(lint_run_layout_imports.DEFENDER).resolve() == H.DEFENDER.resolve(), (
        "the default root is not derived from the lint's own checkout")
    outs = []
    for cwd in (tmp_path, H.WORKTREE):
        proc = subprocess.run([sys.executable, str(LINT_FILE), "--root", str(root)], cwd=cwd,
                              capture_output=True, text=True, encoding="utf-8", timeout=300,
                              env={**os.environ, "PYTHONPATH": str(H.WORKTREE)})
        outs.append((proc.returncode, proc.stdout))
    assert outs[0] == outs[1], f"the same tree gives different findings from another working directory: {outs}"
    assert outs[0][0] != 0, f"the same tree gives different findings from another working directory: {outs}"


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


def test_1105_core_config_no_longer_re_exports_run_paths():
    """defender.learning.core.config no longer has a RunPaths attribute. Positive control: it
    still uses WIRE_LOG_NAMES (a names-only user), and LoopPaths is still exposed."""
    config = importlib.import_module("defender.learning.core.config")
    assert not hasattr(config, "RunPaths"), (
        "learning/core/config.py still re-exports RunPaths (D7: its re-export at :13 is removed)")
    from defender.run_repository import WIRE_LOG_NAMES

    assert config.WIRE_LOG_NAMES is WIRE_LOG_NAMES, "config's WIRE_LOG_NAMES is not the door's"
    assert isinstance(config.LoopPaths, type), "LoopPaths is no longer exposed"


_SPELLINGS = {
    "learning/sp_alias.py": ("from defender.run_repository import Run as R\n\n\n"
                             "def f(run_dir):\n    return R.at(run_dir)\n",
                             {("f", "Run.at")}),
    "sp_top.py": ("from .run_repository import RunPaths  # noqa: F401\n",
                  {("<module>", "RunPaths")}),
    "learning/sp_relative.py": ("from ..run_repository import RunPaths  # noqa: F401\n",
                                {("<module>", "RunPaths")}),
    "learning/deep/sp_relative.py": ("from ...run_repository import RunPaths  # noqa: F401\n",
                                     {("<module>", "RunPaths")}),
    "learning/sp_module_alias.py": (
        "import defender.run_repository\nimport defender.run_repository as rr\n"
        "from defender.run_repository import _layout\n\n\n"
        "def f(x):\n    return rr.RunPaths(x), defender.run_repository.RunPaths(x), "
        "_layout.RunPaths(x)\n",
        {("f", "RunPaths")}),
    "learning/sp_relay.py": ("from defender.run_repository import RunPaths  # noqa: F401\n",
                             {("<module>", "RunPaths")}),
    "learning/sp_downstream.py": ("from defender.learning.sp_relay import RunPaths  # noqa\n",
                                  {("<module>", "RunPaths")}),
}


def test_1105_layout_lint_flags_every_static_import_spelling_of_a_gated_name(tmp_path):
    """The lint flags a gated name reached through each statically resolvable import spelling: an
    aliased from-import (`from defender.run_repository import Run as R; R.at(d)`), a relative
    import of the door at any depth, a module-alias attribute read (`rr.RunPaths(x)`,
    `defender.run_repository.RunPaths(x)`, `_layout.RunPaths(x)`), and a downstream module
    importing a gated name from any relay, flagged by the name, with the relay's own import.
    getattr and importlib routes are not reported (the recorded gap)."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    for module, (text, _expected) in _SPELLINGS.items():
        _plant(root, module, text)
    _plant(root, "learning/sp_gap.py",
           "import importlib\n\nrr = importlib.import_module('defender.run_repository')\n\n\n"
           "def f(x):\n    return getattr(rr, 'RunPaths')(x)\n")
    found = lint_run_layout_imports.scan(root, allow_list=())
    for module, (_text, expected) in _SPELLINGS.items():
        got = {k[1:] for k in _in(found, module)}
        assert expected <= got, f"{module}: flagged {sorted(got)}, expected {sorted(expected)}"
    assert collections.Counter(k[2] for k in _in(found, "learning/sp_module_alias.py"))[
        "RunPaths"] == 3, "each module-alias read of RunPaths is a finding"
    assert not _in(found, "learning/sp_gap.py"), "a getattr/importlib route was reported"


_RECEIVERS = """\
from __future__ import annotations

import dataclasses
from pathlib import Path

from defender._episode_handle import Episode
from defender._tenant import Tenant
from defender.run_repository import ArchivedWorld, Run


def typed_constructor(run: Run, x):
    return run.at(x)


def archived_call(world_dir):
    return ArchivedWorld(world_dir)


def class_level():
    return Tenant.runs


def _tenant_of() -> Tenant:
    raise NotImplementedError


def annotated_return():
    return _tenant_of().runs


@dataclasses.dataclass
class Holder:
    tenant: Tenant


def dataclass_field(holder: Holder):
    return holder.tenant.runs


async def async_with(d: Path):
    async with Episode.open(d) as episode:
        return episode.runs


def walrus(d: Path):
    if (episode := Episode.open(d)) is not None:
        return episode.runs
    return None


def untyped(x):
    return x.at(1), x.runs
"""


def test_1105_layout_lint_flags_what_typing_reaches_and_tags_the_launchers_carrier_read(tmp_path):
    """The lint flags a typed-receiver constructor reference (`r: Run; r.at(x)`), a call
    ArchivedWorld(...) like Run(...), a class-level Tenant.runs, reads through an annotated return
    and a dataclass field, and owner receivers bound by async with and the walrus; the extended
    tracer tags learning/branch/cli.py:1089 (tenant.tenant.runs through _episode_tenant(...) ->
    RunTenant), which today's owner_derived does not (RG-14-a), so that named allow-list entry is
    load-bearing. An untyped receiver is not flagged."""
    lint_run_layout_imports = _lint()
    root = _planted(tmp_path)
    mod = "learning/receivers.py"
    _plant(root, mod, _RECEIVERS)
    (root / "learning" / "branch").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(H.DEFENDER / _CLI, root / _CLI)
    found = lint_run_layout_imports.scan(root, allow_list=())
    got = {k[1:] for k in _in(found, mod)}
    expected = {("typed_constructor", "Run.at"), ("archived_call", "ArchivedWorld"),
                ("class_level", "Tenant.runs"), ("annotated_return", "Tenant.runs"),
                ("dataclass_field", "Tenant.runs"), ("async_with", "Episode.runs"),
                ("walrus", "Episode.runs")}
    assert got == expected, (
        f"typing-reached receivers: flagged {sorted(got)}; missing {sorted(expected - got)}; "
        f"wrongly flagged {sorted(got - expected)} (an untyped receiver is the recorded gap)")
    assert (_CLI, "_launch", "Tenant.runs") in _keys(found), (
        "cli.py:1089's tenant.tenant.runs through _episode_tenant(...) -> RunTenant is not "
        "tagged, so its allow-list entry would be stale (RG-14-a)")


def test_1105_layout_lint_table_equals_the_importer_population_and_an_unlisted_module_gets_no_exemption(tmp_path):
    """The lint's category table equals the production importer population of the layout (a
    stale or renamed row fails this test), a production module in no row gets no exemption so
    its gated uses are findings, and the layout-name universe is every name the door serves
    minus the non-layout public names and the eight helpers, a name bound by tuple unpack, a for
    loop, an annotated assignment or inside an if included."""
    lint_run_layout_imports = _lint()
    import defender.run_repository as rr

    layout_names = frozenset(rr.__all__) - NON_LAYOUT
    population = _layout_importers(H.DEFENDER, layout_names)
    rows = dict(lint_run_layout_imports.CATEGORIES)
    owners = set(rows.get("owners") or ())
    tabled = {m for row, mods in rows.items() if row != "owners" for m in mods}
    population -= owners
    assert tabled, (f"the table is not the importer population: stale rows {sorted(tabled - population)}, "
        f"unlisted importers {sorted(population - tabled)}")
    assert tabled == population, (f"the table is not the importer population: stale rows {sorted(tabled - population)}, "
        f"unlisted importers {sorted(population - tabled)}")
    for row, mods in rows.items():
        for module in mods:
            assert (H.DEFENDER / module).is_file(), f"row {row} names a missing module {module}"
    root = _planted(tmp_path)
    layout = root / "run_repository" / "_layout.py"
    layout.parent.mkdir(parents=True, exist_ok=True)
    with layout.open("a", encoding="utf-8") as fh:
        fh.write('\n\nFORM_TUPLE_A, FORM_TUPLE_B = "a", "b"\nfor FORM_LOOP in ("x",):\n'
                 '    pass\nFORM_ANNOTATED: str = "y"\nif True:\n    FORM_IN_IF = "z"\n')
    forms = {"FORM_TUPLE_A", "FORM_TUPLE_B", "FORM_LOOP", "FORM_ANNOTATED", "FORM_IN_IF"}
    mod = "learning/universe_probe.py"
    door_names = sorted(layout_names | NON_LAYOUT)
    _plant(root, mod, "".join(f"from defender.run_repository import {n}  # noqa: F401\n"
                              for n in door_names) +
           "".join(f"from defender.run_repository._layout import {n}  # noqa: F401\n"
                   for n in sorted(forms)))
    flagged = {k[2] for k in _in(lint_run_layout_imports.scan(root, allow_list=()), mod)}
    assert flagged == (layout_names - HELPERS) | forms, (
        f"the gated universe is not the door's layout names minus the helpers, every definition "
        f"form included: missing {sorted((layout_names - HELPERS) | forms - flagged)}, extra "
        f"{sorted(flagged - ((layout_names - HELPERS) | forms))}")


def _layout_importers(defender: Path, layout_names: frozenset[str]) -> set[str]:
    """Every production module outside the package (D7's sweep) that imports a layout name from
    the door or `_layout`, imports `_layout` itself, or imports the door as a module and reads a
    layout name off it — computed from the tree, never restated."""
    out: set[str] = set()
    for path in _production_files(defender):
        rel = path.relative_to(defender)
        if rel.parts[0] == "run_repository":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        package = ".".join(("defender", *rel.parts[:-1]))
        reads = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    base = package.split(".")[: len(package.split(".")) - node.level + 1]
                    module = ".".join([*base, *([module] if module else [])])
                if module == "defender.run_repository._layout" or (
                        module == "defender.run_repository"
                        and any(a.name in layout_names or a.name in ("_layout", "*")
                                for a in node.names)) or (
                        module == "defender" and reads & layout_names
                        and any(a.name == "run_repository" for a in node.names)):
                    out.add(rel.as_posix())
            elif isinstance(node, ast.Import) and any(
                    a.name == "defender.run_repository._layout"
                    or (a.name == "defender.run_repository" and reads & layout_names)
                    for a in node.names):
                out.add(rel.as_posix())
    return out


# ==========================================================================================
# The neighbouring gates under the fence (MF-19, MF-20).
# ==========================================================================================

def _records_lint() -> ModuleType:
    from defender.tests._by_path import load_lint_gate

    return load_lint_gate("lint_run_records")


_ARM_B = """\
import os
from pathlib import Path

from defender.run_repository import RunPaths
from defender.run_repository._layout import RunPaths as LayoutRunPaths


def joins(run_dir: Path, lead: str):
    return RunPaths(run_dir).gather_raw / lead, LayoutRunPaths(run_dir).gather_raw / lead


def upward(run_dir: Path, lead: str):
    return (RunPaths(run_dir).gather_raw.parent / lead, f"{RunPaths(run_dir).gather_raw}/{lead}",
            os.path.join(RunPaths(run_dir).gather_raw, lead),
            RunPaths(run_dir).gather_raw.joinpath(lead), str(RunPaths(run_dir).gather_raw) + lead,
            RunPaths(run_dir).gather_raw.with_name(lead))
"""


def test_1105_run_records_arm_b_keeps_todays_verdicts_through_the_door(tmp_path):
    """After the move lint_run_records arm (b) flags a '/' join onto an owner-derived value
    reached through the door or the _layout submodule, as it does today through the old module,
    and flags nothing else: joins derived upward through .parent, f-strings, os.path.join,
    .joinpath, '+' and .with_name stay unflagged (RG-14-c; the recorded gap)."""
    gate = _records_lint()
    _plant(tmp_path, "learning/arm_b_probe.py", _ARM_B)
    found = [f.display for f in gate.scan(tmp_path) if "arm_b_probe.py" in f.display]
    joins = [d for d in found if "joins()" in d and "owner-derived" in d]
    assert len(joins) == 2, (
        f"a '/' join onto RunPaths(...) through the door and through _layout is not flagged "
        f"twice: {found}")
    assert not [d for d in found if "upward()" in d], (
        f"arm (b) flagged a join not spelled '/' (RG-14-c keeps those unflagged): {found}")
    assert len(found) == 2, f"the door spellings drew findings today's spelling does not: {found}"
    from defender.run_repository import RunPaths
    from defender.run_repository._layout import RunPaths as LayoutRunPaths

    assert RunPaths is LayoutRunPaths, "the door's RunPaths is the layout submodule's"


def test_1105_neighbouring_gates_give_each_door_spelling_the_old_modules_verdict(tmp_path):
    """Each spelling through the door gets the verdict the same spelling of the old module gets
    today: arm (c)'s owner-name set is extended so a record-name constant imported through the
    door or _layout, absolutely or relatively, or read off a module alias of the door
    (rr.ALERT, the door's form of ep.RUNS_DIRNAME), is flagged, as each _episode_paths
    spelling is (RG-15-a, RG-15-c), owners are
    identified by dotted path so an unrelated module named _errors is not an owner, and #1134's
    re-spelled census counts the door's from-import, alias, relative, module-alias and submodule
    spellings of a disk-touching layout call while a star import gets no hit, before and after
    (RG-25-b)."""
    gate = _records_lint()
    probes = {
        "learning/arm_c_door.py": "from defender.run_repository import ALERT  # noqa: F401\n",
        "learning/arm_c_layout.py": (
            "from defender.run_repository._layout import ALERT  # noqa: F401\n"),
        "learning/arm_c_episode.py": "from defender._episode_paths import RUNS_DIRNAME  # noqa\n",
        "learning/arm_c_door_rel.py": "from ..run_repository import ALERT  # noqa: F401\n",
        "learning/arm_c_episode_rel.py": "from .._episode_paths import RUNS_DIRNAME  # noqa\n",
        "learning/arm_c_door_alias.py": ("import defender.run_repository as rr\n\n\n"
                                         "def f(run_dir):\n    return run_dir / rr.ALERT\n"),
        "learning/arm_c_episode_alias.py": ("import defender._episode_paths as ep\n\n\n"
                                            "def f(world):\n    return world / ep.RUNS_DIRNAME\n"),
        "learning/_errors.py": 'ALERT = "alert.json"\n',
        "learning/arm_c_errors.py": "from defender.learning._errors import ALERT  # noqa: F401\n",
    }
    for module, text in probes.items():
        _plant(tmp_path, module, text)
    shown = [f.display for f in gate.scan(tmp_path)]

    def held(module: str) -> list[str]:
        return [d for d in shown if module in d and "record name" in d]

    for module in ("learning/arm_c_door.py", "learning/arm_c_layout.py",
                   "learning/arm_c_episode.py", "learning/arm_c_door_rel.py",
                   "learning/arm_c_episode_rel.py"):
        assert held(module), f"{module}: importing a record-name constant is not flagged ({shown})"
    for module in ("learning/arm_c_door_alias.py", "learning/arm_c_episode_alias.py"):
        assert [d for d in held(module) if "off an owner module" in d], (
            f"{module}: reading a record name off a module alias is not flagged ({shown})")
    assert [d for d in shown if "learning/_errors.py" in d], (
        "a non-owner module named _errors.py is exempt by its basename")
    assert not held("learning/arm_c_errors.py"), (
        "an unrelated module named _errors is treated as an owner by arm (c)")
    from defender.run_repository import artifact_file
    from defender.tests import _census1134 as C

    tree = C.Tree(H.WORKTREE)
    spellings = {
        "from": "from defender.run_repository import artifact_file\n\n\n"
                "def f(p):\n    return artifact_file(p)\n",
        "alias": "from defender.run_repository import artifact_file as af\n\n\n"
                 "def f(p):\n    return af(p)\n",
        "relative": "from ..run_repository import artifact_file\n\n\n"
                    "def f(p):\n    return artifact_file(p)\n",
        "module-alias": "import defender.run_repository as rr\n\n\n"
                        "def f(p):\n    return rr.artifact_file(p)\n",
        "submodule": "from defender.run_repository._layout import artifact_file\n\n\n"
                     "def f(p):\n    return artifact_file(p)\n",
    }
    for spelling, source in spellings.items():
        hits = [h for h in C.census_source(H.WORKTREE, "learning/census_probe.py", source,
                                           tree=tree) if h.qualname == "f"]
        assert hits, f"#1134's census misses the door's {spelling} spelling of artifact_file(p)"
    for star in ("from defender.run_repository import *\n", "from defender._run_paths import *\n"):
        hits = C.census_source(H.WORKTREE, "learning/census_probe.py",
                               star + "\n\ndef f(p):\n    return artifact_file(p)\n", tree=tree)
        assert not [h for h in hits if h.qualname == "f"], (
            f"a star import ({star.strip()!r}) got a census hit")
    assert callable(artifact_file), "the door serves artifact_file"
