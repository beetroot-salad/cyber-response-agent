"""#1105 PR 1 — the package `defender/run_repository/` itself (D1, D11, O2, O5; MF-18, NM-01,
NM-05..NM-07, NM-09; MF-09 reading B / O5.13).

The handle (`_run_handle.py`) and the layout owner (`_run_paths.py`) move into the package as
`_handle.py` and `_layout.py`; the package's files are pinned to eight names (D1.1, plus `_held.py` by owner ruling); the door
(`__init__.py`) serves the public surface lazily (PEP 562 `__getattr__`), so a layout name loads
the layout submodule alone and stays importable without pydantic (R4-6, R4-7). No old import
path is kept (N-m), every live string reference moves with the code (D1.5), and every gate that
sweeps `defender/` sees the package under its new name (D11: no skip rule matches it).

The O2 private-import scan and the old-name census are censuses THIS FILE owns (an AST or
`git grep` scan with a planted positive control); every other test drives the real door, the
real lint modules, the real box argv builder or the existing tests' own census constants.

Census vocabularies spelled here are the design's, read at base 80888efb: the 53 public layout
names and its 10 imported names (R4-42), the names today's importers take from the two moved
modules (R4-26), the five vulture entries keyed on the moved files (R4-23).

Red at base: every test that reads the package's files, imports the door, or reads a list that
must name the new paths. Green at base, pinning unchanged things: `nothing moves` (N-k) and
`every repo gate sees the package` (D11; the skip rules need no change, R4-34).
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests._by_path import import_lint_lib, load_lint_gate
from defender.tests._import_blocker import run_blocked
from defender.tests.tenant_1105_run_repository import _spec1105 as H

#: D1.1's pinned file names (owner sets, baselines and path-keyed tests name them): the seven
#: it named plus `_held.py`, the held runs folder `_lookup` and `_record` both build on (owner
#: ruling, #1105 PR 1 review: it replaced their import cycle).
PACKAGE_FILES = ("__init__.py", "_layout.py", "_handle.py", "_lookup.py", "_record.py",
                 "_held.py", "_id.py", "_errors.py")
#: The 53 public names `defender/_run_paths.py` defines at module level at 80888efb (R4-42).
LAYOUT_NAMES = frozenset({
    "WIRE_LOG_DIR", "WIRE_LOG", "PROVENANCE", "GATE_METADATA_KEY", "ALERT", "REPORT",
    "INVESTIGATION", "EXECUTED_QUERIES", "SOURCE_REFS", "RAW_MARKER", "GATHER_SUMMARIES_DIRNAME",
    "LEAD_AUTHOR_DIRNAME", "TICKET_READS_MARKER", "LEAD_CLAIM_SUFFIX", "REVIEW_RECORD_PREFIX",
    "TRACE_SUFFIX", "REVIEW_TRACE_SUFFIX", "JSONL_EXT", "AGENT_TRACE_SUFFIX",
    "AGENT_FRAMED_TRACE_SUFFIX", "SERVED_PREFIX", "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX",
    "TOOL_TRACE", "POLICY_DENIALS", "BUDGET", "CIRCUIT_BREAKER", "LESSONS_LOADED",
    "SESSION_POINTER", "RUNTIME_HTML", "BOX_SENTINEL", "RUN_END_SIDECAR_SUFFIX",
    "SCRUB_VERDICT_SUFFIX", "ACCOUNTING_FAILURES_SUFFIX", "TICKET_WRITE_SUFFIX",
    "SESSIONS_DIRNAME", "RunLayout", "RUN_LAYOUT", "WireLogNames", "WIRE_LOG_NAMES", "RunPaths",
    "SessionPaths", "LEAD_ID_BODY", "LEAD_ID_RE", "GATHER_RAW_SHAPE", "CASE_ANSWER_KEY_NAMES",
    "is_case_answer_key", "gather_summaries_shape", "artifact_file", "plain_file", "artifact_dir",
    "resolve_run_bundle", "contained_payload",
})
#: The layout's 10 public IMPORTED names, which the door does not serve (D1.3, R4-42).
LAYOUT_IMPORTED = ("ALIAS_READ_REFUSAL", "Path", "PurePosixPath", "annotations", "dataclasses",
                   "errno", "is_plain_entry", "re", "refuse_bad_case_id", "stat")
#: The private layout helpers `_episode_paths.py` imports from the submodule (R4-27).
PRIVATE_HELPERS = ("_check_component", "_check_index", "_confine")
HANDLE_NAMES = frozenset({"Run", "RunRecord", "ArchivedWorld", "RecordHandle", "case_ref"})
#: The door's 15 non-layout public names (D1.3).
NON_LAYOUT_PUBLIC = HANDLE_NAMES | {
    "RunId", "open_run", "list_run_ids", "bound_runs", "run_exists", "record_episode_runs",
    "episode_runs", "sibling_run_ids", "episode_sibling_ids", "RunRefused",
    # Owner rulings (the high and xhigh reviews): the repository answers "may this text name a
    # run?" and holds a runs folder for its outside callers (run setup, the family gate), so
    # neither re-derives the sidecar clause or the hold's refusals.
    "run_name_fault", "hold_runs_folder"}
#: Every public name today's code from-imports from the two moved modules (R4-26).
TODAYS_IMPORTED = frozenset({
    "Run", "case_ref", "ALERT", "CASE_ANSWER_KEY_NAMES", "GATE_METADATA_KEY", "GATHER_RAW_SHAPE",
    "GATHER_SUMMARIES_DIRNAME", "INVESTIGATION", "LEAD_ID_RE", "LESSONS_LOADED", "PROVENANCE",
    "REPORT", "RUN_LAYOUT", "RunPaths", "SERVED_PREFIX", "SessionPaths", "TRACE_SUFFIX",
    "WIRE_LOG", "WIRE_LOG_DIR", "WIRE_LOG_NAMES", "artifact_dir", "artifact_file",
    "contained_payload", "gather_summaries_shape", "is_case_answer_key", "plain_file",
    "resolve_run_bundle",
})
#: The owner modules the O2 scan exempts, by their path under `defender/` (OP-3).
O2_OWNERS = ("_episode_paths.py", "_episode_handle.py", "_tenant.py")
OLD_MODULES = ("_run_paths", "_run_handle")


# ==========================================================================================
# Local helpers — they return values; the tests assert.
# ==========================================================================================

def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=H.WORKTREE, capture_output=True, text=True,
                          encoding="utf-8", check=False)


def _child_env() -> dict[str, str]:
    """The child's environment: this worktree first on PYTHONPATH (RG-09-a), then whatever
    the parent already carries."""
    inherited = os.environ.get("PYTHONPATH", "")
    return {**os.environ,
            "PYTHONPATH": os.pathsep.join(p for p in (str(H.WORKTREE), inherited) if p)}


def _child(body: str, *, block: tuple[str, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    if block:
        return run_blocked(body, block=block, cwd=H.WORKTREE, env=_child_env())
    return subprocess.run([sys.executable, "-c", body], capture_output=True, check=False,
                          cwd=str(H.WORKTREE), env=_child_env(), timeout=180)


def _out(proc: subprocess.CompletedProcess[bytes]) -> str:
    return proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


def _defined_in(obj: object) -> Path | None:
    """The file of the module that defines `obj` (its `__module__`), or `None`."""
    mod = sys.modules.get(getattr(obj, "__module__", "") or "")
    f = getattr(mod, "__file__", None)
    return Path(f).resolve() if f else None


def _module_defs(tree: ast.Module) -> list[str]:
    """Every name a module body DEFINES at module level (defs, classes, assignments), in order;
    imports are not definitions."""
    out: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append(node.name)
        elif isinstance(node, ast.Assign):
            out += [n.id for t in node.targets for n in ast.walk(t) if isinstance(n, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.append(node.target.id)
    return out


def _type_checking_imports(tree: ast.Module, package: str) -> list[tuple[str, str]]:
    """`(bound name, source module)` for every from-import under `if TYPE_CHECKING:`."""
    out: list[tuple[str, str]] = []
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        name = test.id if isinstance(test, ast.Name) else getattr(test, "attr", None)
        if name != "TYPE_CHECKING":
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.ImportFrom):
                module = sub.module or ""
                if sub.level:
                    base = package.rsplit(".", sub.level - 1)[0] if sub.level > 1 else package
                    module = f"{base}.{module}" if module else base
                out += [(a.asname or a.name, module) for a in sub.names]
    return out


def _plant(root: Path, rel: str, text: str) -> Path:
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _joins_tagged(astlib: Any, source: str) -> list[bool]:
    """`owner_derived` on the left operand of every `/` join in `source`."""
    tree = ast.parse(source)
    env = astlib.module_env(tree)
    return [astlib.owner_derived(n.left, env) for n in ast.walk(tree)
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)]


_DOOR = "defender.run_repository"


def _module_of(rel: str) -> str:
    """`learning/x/y.py` (relative to `defender/`) -> `defender.learning.x.y`."""
    parts = Path(rel).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(("defender", *parts))


def _resolve_from(rel: str, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    package = _module_of(rel) if rel.endswith("__init__.py") else _module_of(rel).rpartition(".")[0]
    for _ in range(node.level - 1):
        package = package.rpartition(".")[0]
    return f"{package}.{node.module}" if node.module else package


def _private_reaches(rel: str, tree: ast.Module) -> list[str]:  # noqa: C901, PLR0912 — one AST pass, one branch per import spelling the O2 scan must see (from, relative, module alias, attribute chain, TYPE_CHECKING)
    """Every way `tree` (the module at `rel` under `defender/`) reaches a `_`-prefixed
    submodule of the package: an import of one (absolute or relative, at any depth,
    TYPE_CHECKING included), a from-import of one off the door, or a static attribute chain off
    a module-level binding of the door (`import defender.run_repository` /
    `import defender.run_repository as rr` / `from defender import run_repository`)."""
    hits: list[str] = []
    door_bindings: set[str] = set()

    def private(dotted: str) -> bool:
        if not dotted.startswith(_DOOR + "."):
            return False
        head = dotted[len(_DOOR) + 1:].split(".")[0]
        return head.startswith("_") and not head.startswith("__")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if private(a.name):
                    hits.append(f"{rel}:{node.lineno}: import {a.name}")
                elif a.name == _DOOR:
                    door_bindings.add(a.asname or "defender")
                    if a.asname is None:
                        door_bindings.add("defender")
        elif isinstance(node, ast.ImportFrom):
            module = _resolve_from(rel, node)
            if private(module):
                hits.append(f"{rel}:{node.lineno}: from {module} import ...")
            elif module == _DOOR:
                for a in node.names:
                    if a.name.startswith("_") and not a.name.startswith("__"):
                        hits.append(f"{rel}:{node.lineno}: from {module} import {a.name}")
            elif module == "defender":
                for a in node.names:
                    if a.name == "run_repository":
                        door_bindings.add(a.asname or a.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        chain: list[str] = []
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name) or cur.id not in door_bindings:
            continue
        dotted = ".".join([cur.id, *reversed(chain)])
        if cur.id == "defender":
            if private(dotted):
                hits.append(f"{rel}:{node.lineno}: {dotted}")
        elif private(f"{_DOOR}.{'.'.join(reversed(chain))}"):
            hits.append(f"{rel}:{node.lineno}: {dotted}")
    return sorted(set(hits))


def _o2_scan(defender_root: Path, *, exempt_owners: bool = True) -> list[str]:
    """O2's scan: every production module under `defender_root` (minus `tests/`, `evals/`,
    caches and venvs) outside `run_repository/` that reaches a private submodule of it; the
    owner modules are exempt by their path under `defender/`."""
    found: list[str] = []
    for path in sorted(defender_root.rglob("*.py")):
        rel = path.relative_to(defender_root).as_posix()
        parts = Path(rel).parts
        if parts[0] in ("tests", "evals", "run_repository") or {"__pycache__", ".venv"} & set(parts):
            continue
        if exempt_owners and rel in O2_OWNERS:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError) as exc:
            found.append(f"{rel}: unparseable ({exc.__class__.__name__})")
            continue
        found += _private_reaches(rel, tree)
    return found


#: The live old-name spellings (D1.5, F-10): the dotted module, its file name, the module used
#: as a module (`_run_paths.X`), and a from-import of it off `defender`. `git grep -E` syntax.
_OLD_NAME_RE = (r"defender\._run_(paths|handle)([^A-Za-z0-9_]|$)"
                r"|(^|[^A-Za-z0-9_.])_run_(paths|handle)\.(py([^A-Za-z0-9_]|$)|[A-Za-z_])"
                r"|from[[:space:]]+defender[[:space:]]+import[[:space:]].*_run_(paths|handle)")
#: Archival trees N-m leaves alone; `defender/docs/run-records.md` (regenerated) is NOT one.
#: This spec's own directory records the move in its prose, so its own text is not a reference.
_ARCHIVAL = ("experiments", "spec-flow/specs", "docs", "defender/docs",
             "defender/tests/tenant_1105_run_repository")


def _old_name_hits(*pathspec: str) -> list[str]:
    proc = _git("grep", "-n", "-I", "-E", _OLD_NAME_RE, "--", *pathspec)
    return [line for line in proc.stdout.splitlines() if line]


# ==========================================================================================
# The tests.
# ==========================================================================================

def test_1105_run_refused_is_a_plain_exception_distinct_from_tenant_refused():
    """RunRefused, served by the door, is an Exception subclass that is neither a ValueError nor a
    TenantRefused, and TenantRefused is not a RunRefused: an except clause for one never catches
    the other."""
    from defender._tenant import TenantRefused
    from defender.run_repository import RunRefused

    assert isinstance(RunRefused, type), f"the door's RunRefused is not an Exception class: {RunRefused!r}"
    assert issubclass(RunRefused, Exception), f"the door's RunRefused is not an Exception class: {RunRefused!r}"
    assert not issubclass(RunRefused, ValueError), "RunRefused must not be a ValueError (OP-5)"
    assert not issubclass(RunRefused, TenantRefused), "RunRefused must not be a TenantRefused"
    assert not issubclass(TenantRefused, RunRefused), "TenantRefused must not be a RunRefused"

    def catches(raised_cls: type, handler: type) -> bool:
        try:
            raise raised_cls("refused")
        except handler:
            return True
        except Exception:  # noqa: BLE001 — the point: did the narrower handler catch it?
            return False

    assert catches(RunRefused, RunRefused), "positive control: each handler catches its own error"
    assert catches(TenantRefused, TenantRefused), "positive control: each handler catches its own error"
    assert not catches(RunRefused, TenantRefused), "an except TenantRefused caught RunRefused"
    assert not catches(TenantRefused, RunRefused), "an except RunRefused caught TenantRefused"
    assert not catches(RunRefused, ValueError), "an except ValueError caught RunRefused"


def test_1105_the_resolve_data_root_census_scans_the_package_and_finds_no_call_in_it(tmp_path):
    """test_1120_censuses' production-file walk includes every .py under defender/run_repository/,
    and none of them calls resolve_data_root: the F39 census covers the package under its new
    name with no change to the census. Positive control: a planted run_repository/_lookup.py
    calling resolve_data_root is walked and its call is found."""
    from defender import run_repository
    from defender.tests.tenant_1120_piece1 import test_1120_censuses as census

    walked = {p.resolve() for p in census._production_files()}
    package = [(H.PACKAGE / name).resolve() for name in PACKAGE_FILES]
    assert not [p for p in package if p not in walked], (
        f"the F39 census walk misses package files: "
        f"{[p.name for p in package if p not in walked]}")
    assert Path(run_repository.__file__).resolve() == H.PACKAGE / "__init__.py", (
        "the door is the package the census walked")
    assert census._resolve_calls(package) == [], (
        "the repository must not resolve the data root (D2: it reads no environment)")
    planted = _plant(tmp_path / "root", "run_repository/_lookup.py",
                     "from defender._tenant import resolve_data_root\n\n\n"
                     "def f():\n    return resolve_data_root()\n")
    walked_planted = census._production_files(roots=(tmp_path / "root",))
    assert planted in walked_planted, "positive control: the walk enters run_repository/"
    assert census._resolve_calls([planted]), "positive control: the planted call is found"


def test_1105_the_package_holds_exactly_its_seven_pinned_submodules():  # name kept: the spec graph cites it; eight files since the owner's _held.py ruling
    """defender/run_repository/ holds exactly __init__.py, _layout.py, _handle.py, _lookup.py,
    _record.py, _held.py, _id.py and _errors.py: the entries of the directory on disk equal those
    names, caches ignored, so a stray lookup.py fails (MF-18); each submodule imports by its
    dotted name; _handle defines Run, RunRecord, RecordHandle, ArchivedWorld and case_ref, and
    _layout defines the 53 public names defender/_run_paths.py defined. The directory is read
    on disk, not through git's index, so an uncommitted package is judged by its files."""
    import importlib

    from defender import run_repository

    assert H.PACKAGE.is_dir(), f"{H.PACKAGE} is not a directory on disk"
    held = {entry.name for entry in H.PACKAGE.iterdir() if entry.name != "__pycache__"}
    assert held == set(PACKAGE_FILES), (
        f"defender/run_repository/ holds {sorted(held)}, not D1.1's pinned "
        f"{sorted(PACKAGE_FILES)}")
    assert Path(run_repository.__file__).resolve() == H.PACKAGE / "__init__.py", (
        "the door is defender/run_repository/__init__.py")
    for name in PACKAGE_FILES:
        dotted = _DOOR if name == "__init__.py" else f"{_DOOR}.{name.removesuffix('.py')}"
        module = importlib.import_module(dotted)
        assert Path(module.__file__).resolve() == H.PACKAGE / name, f"{dotted} imported elsewhere"
    handle_defs = set(_module_defs(ast.parse((H.PACKAGE / "_handle.py").read_text("utf-8"))))
    assert handle_defs >= HANDLE_NAMES, f"_handle lacks {sorted(HANDLE_NAMES - handle_defs)}"
    layout_public = {n for n in _module_defs(ast.parse((H.PACKAGE / "_layout.py").read_text(
        "utf-8"))) if not n.startswith("_")}
    assert layout_public == LAYOUT_NAMES, (
        f"_layout's public definitions differ from _run_paths.py's 53: missing "
        f"{sorted(LAYOUT_NAMES - layout_public)}, extra {sorted(layout_public - LAYOUT_NAMES)}")


def test_1105_the_door_serves_exactly_its_68_public_names():  # 70 since the owner rulings; the spec graph cites this name
    """defender.run_repository.__all__ is exactly the 70 public names: the layout's 53 (the
    door's layout surface equals _layout's public names, NM-06), Run, RunRecord, ArchivedWorld,
    RecordHandle, case_ref, RunId, open_run, list_run_ids, bound_runs, run_exists,
    record_episode_runs, episode_runs, sibling_run_ids, episode_sibling_ids, RunRefused,
    run_name_fault and hold_runs_folder; it
    lists none of the layout's 10 imported names nor _check_component, _check_index, _confine,
    and serves none of them as an attribute but annotations, which the door's own
    `from __future__ import annotations` binds; every name today's code imports from the two
    moved modules, private helpers aside, is in it."""
    from defender import run_repository as door
    from defender.run_repository import _layout

    served = set(door.__all__)
    assert served == LAYOUT_NAMES | NON_LAYOUT_PUBLIC, (
        f"__all__ differs from D1.3's 68 plus the two ruled names: missing "
        f"{sorted((LAYOUT_NAMES | NON_LAYOUT_PUBLIC) - served)}, extra "
        f"{sorted(served - LAYOUT_NAMES - NON_LAYOUT_PUBLIC)}")
    assert len(served) == 70, f"{len(served)} public names, not 70"
    layout_public = {n for n in _module_defs(ast.parse(Path(_layout.__file__).read_text(
        "utf-8"))) if not n.startswith("_")}
    assert served - NON_LAYOUT_PUBLIC == layout_public, (
        "the door's layout surface is not exactly _layout's public names (NM-06)")
    for name in (*LAYOUT_IMPORTED, *PRIVATE_HELPERS):
        assert name not in served, f"the door lists {name!r}, which it must not serve"
        if name == "annotations":
            continue  # the door's own `from __future__ import annotations` binds this name
        err = H.raised(getattr, door, name)
        assert isinstance(err, AttributeError), f"the door served {name!r} ({err!r})"
    assert served >= TODAYS_IMPORTED, (
        f"names today's importers take are not served: {sorted(TODAYS_IMPORTED - served)}")


def test_1105_the_doors_all_its_type_checking_names_and_its_getattr_names_are_one_set():
    """The door's __all__, the names it declares under TYPE_CHECKING, and the names its __getattr__
    serves are one set with no duplicate in any of them, each served name is the very object its
    submodule defines, and __getattr__ raises AttributeError for any other name."""
    import importlib

    from defender import run_repository as door

    all_names = list(door.__all__)
    assert all_names, f"__all__ is empty or holds duplicates: {all_names[:5]}"
    assert len(all_names) == len(set(all_names)), f"__all__ is empty or holds duplicates: {all_names[:5]}"
    tree = ast.parse((H.PACKAGE / "__init__.py").read_text(encoding="utf-8"))
    declared = _type_checking_imports(tree, _DOOR)
    declared_names = [n for n, _ in declared]
    assert len(declared_names) == len(set(declared_names)), "a TYPE_CHECKING name is duplicated"
    assert set(declared_names) == set(all_names), (
        f"TYPE_CHECKING declares {sorted(set(declared_names) ^ set(all_names))} differently "
        "from __all__ (mypy would type an undeclared door name as Any, R4-30)")
    # `annotations` is left out: the door's own `from __future__ import annotations` binds it.
    probes = set(all_names) | set(declared_names) | set(LAYOUT_IMPORTED) | set(PRIVATE_HELPERS)
    probes = (probes | {"NotAName", "Tenant", "hold"}) - {"annotations"}
    served = {n for n in probes if H.raised(getattr, door, n) is None}
    assert served == set(all_names), (
        f"__getattr__ serves {sorted(served ^ set(all_names))} differently from __all__")
    for name, module in declared:
        own = getattr(importlib.import_module(module), name)
        assert getattr(door, name) is own, f"door.{name} is not {module}.{name} itself"
    for name in ("NotAName", "Path", "_check_component", "refuse_bad_case_id"):
        assert isinstance(H.raised(getattr, door, name), AttributeError), (
            f"__getattr__ did not raise AttributeError for {name!r}")


def test_1105_a_layout_name_from_the_door_loads_the_layout_submodule_alone_without_pydantic():
    """In a fresh interpreter with pydantic* blocked, `from defender.run_repository import
    RunPaths, RUN_LAYOUT` succeeds with the layout submodule loaded and the handle submodule,
    defender._tenant and pydantic not loaded (NM-05: the pin names what must not load, not an
    exact module set); RunId and RunRefused import from the door under the same block; and in a
    fresh interpreter without the block every public name imports."""
    from defender.run_repository import RUN_LAYOUT, RunPaths

    probe = (
        "import json, sys\n"
        "from defender.run_repository import RunPaths, RUN_LAYOUT\n"
        "mods = sorted(sys.modules)\n"
        "print(json.dumps({'layout': 'defender.run_repository._layout' in mods,\n"
        "  'handle': 'defender.run_repository._handle' in mods,\n"
        "  'tenant': 'defender._tenant' in mods,\n"
        "  'pydantic': [m for m in mods if m.split('.')[0].startswith('pydantic')],\n"
        "  'alert': str(RUN_LAYOUT.alert), 'paths': RunPaths.__name__}))\n")
    proc = _child(probe, block=("pydantic*",))
    assert proc.returncode == 0, f"the layout names do not import without pydantic: {_out(proc)}"
    seen = json.loads(proc.stdout.decode("utf-8"))
    assert seen["layout"], f"the layout submodule did not load: {seen}"
    assert not seen["handle"], f"a layout name loaded more than the layout (R4-6): {seen}"
    assert not seen["tenant"], f"a layout name loaded more than the layout (R4-6): {seen}"
    assert not seen["pydantic"], f"a layout name loaded more than the layout (R4-6): {seen}"
    assert seen["alert"] == str(RUN_LAYOUT.alert) == "alert.json", (
        f"the child's RUN_LAYOUT is not the door's: {seen}")
    assert seen["paths"] == RunPaths.__name__ == "RunPaths", f"the child's RunPaths: {seen}"
    proc = _child("from defender.run_repository import RunId, RunRefused\n"
                  "print(RunId.parse('r1'), RunRefused.__name__)\n", block=("pydantic*",))
    assert proc.returncode == 0, f"RunId and RunRefused must import pydantic-free (NM-05): {_out(proc)}"
    assert _out(proc).split()[:2] == ["r1", "RunRefused"], f"RunId and RunRefused must import pydantic-free (NM-05): {_out(proc)}"
    proc = _child("import defender.run_repository as rr\n"
                  "missing = [n for n in rr.__all__ if getattr(rr, n, None) is None]\n"
                  "print(len(rr.__all__), missing)\n")
    assert proc.returncode == 0, f"not every public name imports in a fresh interpreter: {_out(proc)}"
    assert _out(proc).split()[0] == "70", f"not every public name imports in a fresh interpreter: {_out(proc)}"
    assert "[]" in _out(proc), f"not every public name imports in a fresh interpreter: {_out(proc)}"


def test_1105_a_failed_first_import_through_the_door_propagates_and_is_retried():
    """In one interpreter, reading Run from the door while pydantic is blocked raises the import
    error, and reading it again once the block is removed returns the class: the failure is not
    cached."""
    from defender.run_repository import Run

    probe = (
        "import json, sys\n"
        "import defender.run_repository as rr\n"
        "first = None\n"
        "try:\n"
        "    rr.Run\n"
        "except ImportError as e:\n"
        "    first = type(e).__name__\n"
        "sys.meta_path[:] = [f for f in sys.meta_path if type(f).__name__ != '_Blocker']\n"
        "second = rr.Run\n"
        "print(json.dumps({'first': first, 'second': getattr(second, '__name__', None),\n"
        "                  'module': getattr(second, '__module__', None)}))\n")
    proc = _child(probe, block=("pydantic*",))
    assert proc.returncode == 0, f"the retry raised: {_out(proc)}"
    seen = json.loads(proc.stdout.decode("utf-8"))
    assert seen["first"] in ("ModuleNotFoundError", "ImportError"), (
        f"reading Run with pydantic blocked did not propagate the import error: {seen}")
    assert seen["second"] == Run.__name__, f"the second read did not return the handle's Run — the failure was cached: {seen}"
    assert (seen["module"] == Run.__module__ == (
            f"{_DOOR}._handle")), f"the second read did not return the handle's Run — the failure was cached: {seen}"


def test_1105_no_production_module_outside_the_package_imports_a_private_submodule(tmp_path):
    """An AST scan of defender/ minus tests/ and evals/, TYPE_CHECKING imports included, finds no
    module outside defender/run_repository/ importing a _-prefixed submodule of it or reaching one
    through a static attribute chain (`import defender.run_repository` then
    `defender.run_repository._lookup.x`), other than the owners, which are exempt by their path
    under defender/ (_episode_paths.py, _episode_handle.py, _tenant.py). Positive control: the
    same scan reports a planted `from defender.run_repository._layout import RunPaths` and a
    planted attribute chain in a non-owner module of a scratch tree, and does not exempt a
    non-owner file named _tenant.py elsewhere. The exemption is load-bearing on the real tree:
    unexempted, the scan sees _episode_paths.py's import of the layout's private helpers
    (D1.3, R4-27)."""
    from defender import run_repository

    found = _o2_scan(H.DEFENDER)
    assert found == [], f"production modules reach a private submodule (O2): {found}"
    assert Path(run_repository.__file__).resolve() == H.PACKAGE / "__init__.py", (
        "the scanned package is the door at defender/run_repository/")
    raw = _o2_scan(H.DEFENDER, exempt_owners=False)
    assert any(h.startswith("_episode_paths.py:") for h in raw), (
        f"the owner _episode_paths.py should import the layout's private helpers from "
        f"{_DOOR}._layout (D1.3), and the scan should see it before exempting it: {raw}")
    root = tmp_path / "defender"
    _plant(root, "learning/x.py", "from defender.run_repository._layout import RunPaths\n")
    _plant(root, "learning/y.py",
           "import defender.run_repository\n\nv = defender.run_repository._lookup.open_run\n")
    _plant(root, "learning/z.py",
           "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
           "    from defender.run_repository import _record\n")
    _plant(root, "learning/_tenant.py", "import defender.run_repository._id\n")
    _plant(root, "_tenant.py", "from defender.run_repository._layout import _confine\n")
    _plant(root, "run_repository/_lookup.py", "from ._layout import RunPaths\n")
    _plant(root, "tests/test_x.py", "from defender.run_repository._lookup import open_run\n")
    _plant(root, "evals/e.py", "from defender.run_repository._lookup import open_run\n")
    _plant(root, "learning/clean.py", "from defender.run_repository import open_run, RunId\n")
    planted = _o2_scan(root)
    files = {h.split(":", 1)[0] for h in planted}
    assert files == {"learning/x.py", "learning/y.py", "learning/z.py", "learning/_tenant.py"}, (
        f"positive control: the scan reports exactly the planted private reaches outside the "
        f"owners, the package, tests and evals: {planted}")


def test_1105_the_old_modules_are_gone_and_no_live_file_imports_them():
    """No file and no directory stands at defender/_run_handle.py, defender/_run_paths.py or an
    old-name directory (an empty defender/_run_paths/ would import as a namespace package,
    RG-22-a); importing either old name raises ModuleNotFoundError in a fresh child interpreter;
    and no tracked .py outside experiments/ imports them or plants an import of them in a fixture
    source string. Positive control: defender.run_repository imports."""
    from defender import run_repository

    present = [name for old in OLD_MODULES for name in (f"{old}.py", old)
               if os.path.lexists(H.DEFENDER / name)]
    assert present == [], f"an old module or old-name directory still stands: {present}"
    for old in OLD_MODULES:
        proc = _child("import importlib, sys\n"
                      "try:\n"
                      f"    importlib.import_module('defender.' + {old!r})\n"
                      "except ModuleNotFoundError:\n    print('gone')\n"
                      "else:\n    print('importable')\n")
        assert _out(proc).split()[:1] == ["gone"], f"defender.{old} still imports: {_out(proc)}"
    proc = _child("import defender.run_repository as rr\nprint(rr.__name__)\n")
    assert proc.returncode == 0, f"positive control: the door imports in a fresh interpreter: {_out(proc)}"
    assert _out(proc).split()[:1] == [run_repository.__name__], f"positive control: the door imports in a fresh interpreter: {_out(proc)}"
    old_import = re.compile(
        r"(?m)^\s*(from\s+defender\.(_run_paths|_run_handle)\b|import\s+defender\."
        r"(_run_paths|_run_handle)\b|from\s+defender\s+import\s+.*\b(_run_paths|_run_handle)\b)")
    # This spec's own directory spells the old paths to pin their absence (owner ruling,
    # 2026-10-05: excluded here as in test_1105_no_live_file_names_the_old_module_paths).
    candidates = [line for line in _git("grep", "-l", "-E", "_run_(paths|handle)", "--",
                                        "*.py", ":!experiments",
                                        ":!defender/tests/tenant_1105_run_repository"
                                        ).stdout.splitlines() if line]
    offenders: list[str] = []
    for rel in candidates:
        text = (H.WORKTREE / rel).read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            # A deliberately broken fixture: its import lines are read as text.
            offenders += [f"{rel} (unparseable)" for _ in old_import.finditer(text)][:1]
            continue
        defender_rel = rel.removeprefix("defender/")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [f"{rel}:{node.lineno}" for a in node.names
                              if a.name.split(".")[:2] in (["defender", m] for m in OLD_MODULES)]
            elif isinstance(node, ast.ImportFrom):
                module = (_resolve_from(defender_rel, node) if rel.startswith("defender/")
                          else node.module or "")
                names = {a.name for a in node.names}
                if (module.split(".")[:2] in (["defender", m] for m in OLD_MODULES)
                        or (module == "defender" and names & set(OLD_MODULES))):
                    offenders.append(f"{rel}:{node.lineno}")
            elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
                  and old_import.search(node.value)):
                offenders.append(f"{rel}:{node.lineno} (fixture source)")
    assert offenders == [], f"live files import the old modules: {offenders[:20]}"


def test_1105_no_live_file_names_the_old_module_paths():
    """No tracked file outside experiments/, spec-flow/specs/, docs/ and defender/docs/
    (run-records.md excepted) names defender._run_paths, defender._run_handle, _run_paths.py or
    _run_handle.py, or `_run_paths.`/`_run_handle.` as a module: lint lists, lint messages,
    baselines, profile rows, CI comments, CLAUDE.md and test path pins all name the new paths.
    Positive control: the scan finds the archival mention in
    experiments/judge-glm52-vs-kimik3/analyze.py. (This spec's own directory, which records the
    move in its prose, is not scanned.)"""
    from defender import run_repository

    # Owner ruling (merge of #1080): a suite's goldens/ hold outputs captured at some base
    # commit, frozen data that may name a file, never code that depends on it (#647's rule).
    live = _old_name_hits(".", *(f":!{tree}" for tree in _ARCHIVAL), ":!**/goldens/**")
    live += _old_name_hits("defender/docs/run-records.md")
    assert live == [], (f"{len(live)} live references still name the old modules, e.g. "
                        f"{live[:15]}")
    assert Path(run_repository.__file__).resolve() == H.PACKAGE / "__init__.py", (
        "the names move to the package at defender/run_repository/")
    archival = _old_name_hits("experiments/judge-glm52-vs-kimik3/analyze.py")
    assert archival, "positive control: the scan sees the archival import in experiments/"


def test_1105_the_package_is_not_ignored_and_run_data_still_is():
    """Every file of defender/run_repository/ exists on disk and git check-ignore --no-index
    admits each of them, so each is tracked once committed whatever the index holds, while a run
    folder path such as defender/runs/r1/alert.json is still ignored by .gitignore's run-data
    rule. Neither half reads git's index."""
    from defender import run_repository

    expected = {f"defender/run_repository/{name}" for name in PACKAGE_FILES}
    absent = sorted(rel for rel in expected if not (H.WORKTREE / rel).is_file())
    assert not absent, f"package files are not on disk: {absent}"
    assert Path(run_repository.__file__).resolve() == H.PACKAGE / "__init__.py", (
        "the package on disk is the door")
    for rel in sorted(expected):
        ignored = _git("check-ignore", "--no-index", "-q", rel)
        assert ignored.returncode == 1, f"{rel} is git-ignored (rc {ignored.returncode})"
    still = _git("check-ignore", "--no-index", "-q", "defender/runs/r1/alert.json")
    assert still.returncode == 0, "run data under defender/runs/ is no longer ignored (D11)"


def _listed_by(lint, path: Path) -> bool:
    """Would the shared listing a lint builds over `defender/` keep `path`?"""
    return not set(path.relative_to(H.DEFENDER).parts[:-1]) & set(lint.EXCLUDED_DIRS)


def test_1105_every_repo_gate_that_sweeps_defender_sees_the_package():
    """Each of the four lints' scope admits every package file, and neither
    test_1120_censuses._SKIPPED_PARTS nor _spec1120._CHECKOUT_IGNORE contains a part of
    defender/run_repository/. Positive control: each rejects the same files under defender/runs/,
    the name the package did not take (R4-34)."""
    from defender.tests.tenant_1120_piece1 import _spec1120
    from defender.tests.tenant_1120_piece1 import test_1120_censuses as census

    lint_duplicate_helpers = load_lint_gate("lint_duplicate_helpers")
    lint_borrowed_vocabulary = load_lint_gate("lint_borrowed_vocabulary")
    lint_half_read_table = load_lint_gate("lint_half_read_table")
    lint_unowned_field = load_lint_gate("lint_unowned_field")
    scopes = {
        "lint_duplicate_helpers": lambda p: lint_duplicate_helpers._in_scope(p),
        "lint_borrowed_vocabulary": lambda p: lint_borrowed_vocabulary._in_scope(p, H.DEFENDER),
        # #1191: these two list through `_astlib.source_files`, which prunes a directory by
        # its name below the root — so their scope is their `EXCLUDED_DIRS` applied that way.
        "lint_half_read_table": lambda p: _listed_by(lint_half_read_table, p),
        "lint_unowned_field": lambda p: _listed_by(lint_unowned_field, p),
    }
    for lint, in_scope in scopes.items():
        for name in PACKAGE_FILES:
            assert in_scope(H.PACKAGE / name), f"{lint} drops run_repository/{name}"
            assert not in_scope(H.DEFENDER / "runs" / name), (
                f"positive control: {lint} drops defender/runs/{name}")
    parts = set(Path("defender/run_repository").parts)
    assert not parts & set(census._SKIPPED_PARTS), (
        f"test_1120_censuses skips {sorted(parts & set(census._SKIPPED_PARTS))}")
    ignored = _spec1120._CHECKOUT_IGNORE(str(H.DEFENDER), ["run_repository", "runs", "tests"])
    assert "run_repository" not in ignored, f"_spec1120._CHECKOUT_IGNORE drops {sorted(ignored)}"
    assert "runs" in ignored, f"_spec1120._CHECKOUT_IGNORE drops {sorted(ignored)}"


def test_1105_owner_derived_tags_each_moved_origin_through_the_door_and_the_submodule():
    """_astlib.owner_derived tags a '/' join on RunPaths(x), SessionPaths(x), Run(...), RUN_LAYOUT
    and WIRE_LOG_NAMES from-imported from defender.run_repository and from its _layout/_handle
    submodules, and on the three classes reached through a module alias of the door; the origin
    sets no longer name defender._run_paths or defender._run_handle."""
    _astlib = import_lint_lib("_astlib")
    joins = {
        "RunPaths": "RunPaths(d).alert / x", "SessionPaths": "SessionPaths(d).sessions_dir / x",
        "Run": "Run(d, runs_base=None).run_dir / x", "RUN_LAYOUT": "RUN_LAYOUT.gather_raw / x",
        "WIRE_LOG_NAMES": "WIRE_LOG_NAMES.curator_batch / x",
    }
    for name, join in joins.items():
        sub = "_handle" if name == "Run" else "_layout"
        for module in (_DOOR, f"{_DOOR}.{sub}"):
            source = f"from {module} import {name}\n\n\ndef f(d, x):\n    return {join}\n"
            assert _joins_tagged(_astlib, source) == [True], (
                f"owner_derived does not tag {name} from-imported from {module} (R4-8)")
    for name in ("RunPaths", "SessionPaths", "Run"):
        source = (f"import {_DOOR} as rr\n\n\ndef f(d, x):\n"
                  f"    return rr.{joins[name]}\n")
        assert _joins_tagged(_astlib, source) == [True], (
            f"owner_derived does not tag rr.{name} through a module alias of the door")
    origins = set(_astlib._OWNER_CLASS_ORIGINS) | set(_astlib._OWNER_VALUE_ORIGINS)
    stale = sorted(o for o in origins if o.startswith(("defender._run_paths.",
                                                       "defender._run_handle.")))
    assert stale == [], f"the origin sets still name the removed modules: {stale}"
    control = "def f(d, x):\n    return d / x\n"
    assert _joins_tagged(_astlib, control) == [False], "control: a plain join is not tagged"


def test_1105_run_records_owners_are_matched_by_path_so_a_same_named_file_is_not_exempt(tmp_path):
    """lint_run_records.OWNER_MODULES equals _spec1077.OWNER_MODULE_FILES and names every file of
    defender/run_repository/ by its path under defender/, each of the package's entries naming an
    existing file (NM-07 A); a join under tenant.runs inside the package is not reported, the
    same join in a non-owner module is (arm b), and a non-owner file named __init__.py or
    _handle.py elsewhere in the sweep is not exempted by its basename."""
    from defender.tests import _spec1077

    lint_run_records = load_lint_gate("lint_run_records")
    owners = set(lint_run_records.OWNER_MODULES)
    package = {f"run_repository/{name}" for name in PACKAGE_FILES}
    assert package <= owners, (
        f"OWNER_MODULES does not name the package's files by path: {sorted(package - owners)}")
    assert owners == set(_spec1077.OWNER_MODULE_FILES), (
        f"lint_run_records.OWNER_MODULES {sorted(owners)} != _spec1077.OWNER_MODULE_FILES "
        f"{sorted(_spec1077.OWNER_MODULE_FILES)}")
    assert {"_episode_paths.py", "_tenant.py"} <= owners, "the two owners outside stay owners"
    nowhere = sorted(rel for rel in owners
                     if rel.startswith("run_repository/") and not (H.DEFENDER / rel).is_file())
    assert not nowhere, f"OWNER_MODULES names package files that do not exist: {nowhere}"
    assert not owners & {"_run_paths.py", "_run_handle.py", "__init__.py", "_handle.py"}, (
        f"OWNER_MODULES keeps a removed or bare-basename entry: {sorted(owners)}")
    join = ("from defender._tenant import Tenant\n\n\n"
            "def f(tenant: Tenant, name: str):\n    return tenant.runs / name\n")
    inside = tmp_path / "inside"
    _plant(inside, "run_repository/_lookup.py", join)
    assert lint_run_records.scan(inside) == [], "a join inside the package is reported"
    for rel in ("learning/joins.py", "learning/__init__.py", "runtime/_handle.py",
                "hooks/_lookup.py", "learning/_tenant.py"):
        root = tmp_path / rel.replace("/", "_")
        _plant(root, rel, join)
        found = [f.display for f in lint_run_records.scan(root)]
        assert any(rel in d for d in found), (
            f"the join in non-owner {rel} was not reported (a basename exemption?): {found}")


def test_1105_run_records_sweep_covers_the_package(tmp_path):
    """lint_run_records.SWEEP_DIRS names the package exactly once and still includes runtime,
    learning, scripts, evals and hooks. The sweep enters a planted run_repository/ folder."""
    lint_run_records = load_lint_gate("lint_run_records")
    dirs = list(lint_run_records.SWEEP_DIRS)
    assert dirs.count("run_repository") == 1, f"SWEEP_DIRS {dirs} does not name the package once"
    assert {"runtime", "learning", "scripts", "evals", "hooks"} <= set(dirs), (
        f"the swept set shrank: {dirs}")
    planted = _plant(tmp_path, "run_repository/_record.py", "X = 1\n")
    assert planted in lint_run_records.sweep_files(tmp_path), "the sweep does not enter it"


def test_1105_tree_read_lint_lists_the_new_submodules_and_not_the_moved_ones(tmp_path):
    """LINT_TREE_READER_MODULES names run_repository/_lookup.py, _record.py and _id.py, each of
    its package entries names an existing file (NM-07 A; its other entries are not judged here:
    the dead runtime/branch.py entry is recorded, not pruned, 20-demands F-9), and it names neither
    run_repository/_layout.py nor run_repository/_handle.py; the tree-read lint reports no plain
    listing call (RG-06-a). Positive control: a link-following is_dir() in a listed submodule is
    reported."""
    lint_tree_read_follows_link = load_lint_gate("lint_tree_read_follows_link")
    listed = set(lint_tree_read_follows_link.LINT_TREE_READER_MODULES)
    new = {"run_repository/_lookup.py", "run_repository/_record.py", "run_repository/_id.py"}
    assert new <= listed, f"the tree-read lint does not list {sorted(new - listed)}"
    nowhere = sorted(rel for rel in listed
                     if rel.startswith("run_repository/") and not (H.DEFENDER / rel).is_file())
    assert not nowhere, f"LINT_TREE_READER_MODULES names package files that do not exist: {nowhere}"
    assert not listed & {"run_repository/_layout.py", "run_repository/_handle.py"}, (
        "the moved files are not added (D7: neither is listed today)")
    _plant(tmp_path, "run_repository/_lookup.py",
           "import os\n\n\ndef listing(p):\n"
           "    return [c.name for c in p.iterdir()], os.listdir(p), list(os.scandir(p))\n\n\n"
           "def admit(p):\n    return p.is_dir()\n")
    found = [f.display for f in lint_tree_read_follows_link._scan(tmp_path)]
    assert len(found) == 1, f"the lint must flag the link-following admit and no plain listing: {found}"
    assert "admit" in found[0], f"the lint must flag the link-following admit and no plain listing: {found}"
    assert "is_dir" in found[0], f"the lint must flag the link-following admit and no plain listing: {found}"


def test_1105_lint_baselines_name_no_deleted_path_and_unused_public_names_cite_pr_2():
    """No lint list or baseline names defender/_run_paths.py or defender/_run_handle.py; the five
    vulture entries keyed on them are keyed on run_repository/_layout.py and _handle.py with their
    reasons, a sixth entry covers the door's own __getattr__ (RG-05-c), and every vulture entry
    for a public repository name with no PR 1 caller gives a reason naming PR 2."""
    lint_dir = H.WORKTREE / "scripts" / "lint"
    baseline = json.loads((lint_dir / "lint_vulture_baseline.json").read_text("utf-8"))["entries"]
    moved = {
        "defender/run_repository/_handle.py: unused attribute 'logger_factory' (60% confidence)",
        "defender/run_repository/_handle.py: unused property 'subcollections' (60% confidence)",
        "defender/run_repository/_handle.py: unused variable 'alert_ref' (60% confidence)",
        "defender/run_repository/_handle.py: unused variable 'tables' (60% confidence)",
        "defender/run_repository/_layout.py: unused function 'resolve_run_bundle' "
        "(60% confidence)",
    }
    assert moved <= set(baseline), (
        f"the five moved vulture entries are not re-keyed: {sorted(moved - set(baseline))}")
    assert all(str(baseline[k]).strip() for k in moved), "a re-keyed entry lost its reason"
    door = [k for k in baseline
            if k.startswith("defender/run_repository/__init__.py:") and "'__getattr__'" in k]
    assert len(door) == 1, f"no sixth vulture entry (with a reason) for the door's __getattr__ (RG-05-c): {door}"
    assert str(baseline[door[0]]).strip(), f"no sixth vulture entry (with a reason) for the door's __getattr__ (RG-05-c): {door}"
    stale = [f"{p.name}: {k}" for p in sorted(lint_dir.glob("*.json"))
             for k in re.findall(r"defender/_run_(?:paths|handle)\.py", p.read_text("utf-8"))]
    for p in sorted(lint_dir.glob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        docstrings = {id(n.value) for n in ast.walk(tree)
                      if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        stale += [f"{p.name}:{n.lineno}: {n.value!r}" for n in ast.walk(tree)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and id(n) not in docstrings
                  and re.search(r"(^|/)_run_(paths|handle)\.py\b", n.value)]
    assert stale == [], f"lint lists or baselines still name a deleted path: {stale}"
    public = sorted(NON_LAYOUT_PUBLIC - HANDLE_NAMES - {"RunRefused"})
    for key, reason in baseline.items():
        if key.startswith("defender/run_repository/") and any(f"'{n}'" in key for n in public):
            assert "PR 2" in str(reason), (
                f"{key}: a public repository name with no PR 1 caller must cite PR 2 "
                f"(NF-16): {reason!r}")


def test_1105_the_spec_flow_profile_names_the_moved_symbols_at_their_new_paths():
    """Every .claude/spec-flow.json row of the form <file>::<symbol> that named a moved file names
    its new submodule path, and that symbol is defined there."""
    from defender.run_repository import Run, contained_payload

    profile = json.loads((H.WORKTREE / ".claude" / "spec-flow.json").read_text("utf-8"))
    rows: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, str) and re.fullmatch(r"[\w./-]+\.py::[\w.]+", value):
            rows.append(value)

    walk(profile)
    old = [r for r in rows if r.split("::")[0] in ("defender/_run_paths.py",
                                                    "defender/_run_handle.py")]
    assert old == [], f"profile rows still name the moved files: {old}"
    expected = {"defender/run_repository/_layout.py::contained_payload",
                "defender/run_repository/_handle.py::Run.for_tenant",
                "defender/run_repository/_handle.py::Run._exit_class"}
    assert expected <= set(rows), f"the moved rows are missing: {sorted(expected - set(rows))}"
    for row in (r for r in rows if r.startswith("defender/run_repository/")):
        rel, symbol = row.split("::")
        tree = ast.parse((H.WORKTREE / rel).read_text(encoding="utf-8"))
        head, _, member = symbol.partition(".")
        node = next((n for n in tree.body if getattr(n, "name", None) == head
                     or head in _module_defs(ast.Module(body=[n], type_ignores=[]))), None)
        assert node is not None, f"{row}: {head} is not defined in {rel}"
        if member:
            names = {getattr(n, "name", None) for n in getattr(node, "body", [])}
            assert member in names, f"{row}: {head} defines no {member}"
    for row, obj in (("defender/run_repository/_layout.py::contained_payload", contained_payload),
                     ("defender/run_repository/_handle.py::Run.for_tenant", Run.for_tenant),
                     ("defender/run_repository/_handle.py::Run._exit_class", Run._exit_class)):
        rel, symbol = row.split("::")
        assert _defined_in(obj) == (H.WORKTREE / rel).resolve(), (
            f"{row}: the door's object is defined in {_defined_in(obj)}")
        assert getattr(obj, "__qualname__", None) == symbol, f"{row}: {obj!r} is another symbol"


@pytest.mark.gate
def test_1105_run_records_lint_is_clean_and_its_rendered_page_is_current(monkeypatch, capsys):
    """lint_run_records exits 0 on the tree, run from the repository root, and
    defender/docs/run-records.md is the page `--render` writes, so the kinds registry's citations
    into moved files are live and no unattributed record spelling remains."""
    monkeypatch.chdir(H.WORKTREE)
    lint_run_records = load_lint_gate("lint_run_records")
    rc = lint_run_records.main([])
    out = capsys.readouterr().out
    assert rc == 0, f"lint_run_records is not clean on the tree (or its page is stale):\n{out}"
    registry = (H.DEFENDER / "docs" / "run-records-kinds.tsv").read_text(encoding="utf-8")
    stale = re.findall(r"_run_(?:paths|handle)\.py(?::\d+)?", registry)
    assert stale == [], f"the kinds registry still cites the moved files: {stale}"
    for name, line in re.findall(r"(_layout|_handle)\.py:(\d+)", registry):
        lines = (H.PACKAGE / f"{name}.py").read_text(encoding="utf-8").splitlines()
        assert int(line) <= len(lines), f"{name}.py:{line} cites past the end of the file"


def test_1105_nothing_moves_but_the_handle_and_the_layout():
    """defender/run_common.py, the defender/runtime/branch/ package, scripts/visualize/
    visualize_run.py and visualize_episode.py, learning/branch/cli.py (still defining
    _episode_tenant), _episode_paths.py, _episode_handle.py and _tenant.py exist and import at
    their paths. No run_service package and no host_env.py appear (N-k, N-j)."""
    import importlib

    stay = {
        "defender.run_common": "run_common.py",
        "defender.runtime.branch": "runtime/branch/__init__.py",
        "defender.scripts.visualize.visualize_run": "scripts/visualize/visualize_run.py",
        "defender.scripts.visualize.visualize_episode": "scripts/visualize/visualize_episode.py",
        "defender.learning.branch.cli": "learning/branch/cli.py",
        "defender._episode_paths": "_episode_paths.py",
        "defender._episode_handle": "_episode_handle.py",
        "defender._tenant": "_tenant.py",
    }
    for dotted, rel in stay.items():
        module = importlib.import_module(dotted)
        assert Path(module.__file__).resolve() == (H.DEFENDER / rel).resolve(), (
            f"{dotted} moved: it imports from {module.__file__}, not defender/{rel}")
    cli = importlib.import_module("defender.learning.branch.cli")
    assert callable(getattr(cli, "_episode_tenant", None)), (
        "the launcher's _episode_tenant stays in learning/branch/cli.py (N-k)")
    assert not os.path.lexists(H.DEFENDER / "run_service"), "no run_service package (rev 4)"
    assert not os.path.lexists(H.DEFENDER / "host_env.py"), "no host_env.py (D8 dropped)"


def test_1105_the_episode_reader_census_names_the_layout_submodule():
    """test_1025_episode_reader's census owner list names defender/run_repository/_layout.py, that
    file exists, and the census's own file walk returns it among the files it censused, so a stale
    entry fails instead of silently dropping the layout (today's rglob over a missing path yields
    nothing, A4-21). The censused file is the one the door's layout names are defined in."""
    from defender.run_repository import RunPaths
    from defender.tests import test_1025_episode_reader as census

    assert "run_repository/_layout.py" in census._OWNER_MODULES, (
        f"the episode-reader census owners {census._OWNER_MODULES} do not name the layout "
        "submodule")
    layout = H.DEFENDER / "run_repository" / "_layout.py"
    assert layout.is_file(), f"{layout} does not exist"
    assert _defined_in(RunPaths) == layout.resolve(), (
        f"the door's RunPaths is not defined in {layout}: {_defined_in(RunPaths)}")
    assert "run_repository/_layout.py" in census._shipped_modules(), (
        "the census's own walk did not return the layout submodule")


def test_1105_the_meta_json_census_exclude_matches_the_layout_submodule():
    """test_meta_json_retirement_647's accessor census excludes
    defender/run_repository/_layout.py's own RunPaths( calls and its exclude matches an existing
    file, so a stale exclude fails instead of letting the layout's calls hide a deleted reader;
    every existing test that plants, pins or reads a moved file names the new path."""
    from defender.run_repository import RunPaths
    from defender.tests import test_meta_json_retirement_647 as census

    tree = ast.parse(Path(census.__file__).read_text(encoding="utf-8"))
    #: Every `name = "<str>"` binding in the module, function locals included, so an exclude
    #: spelled through a named constant resolves to its text.
    bound = {t.id: n.value.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
             and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
             for t in n.targets if isinstance(t, ast.Name)}
    excludes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "extra_excludes":
            for elt in getattr(node.value, "elts", []):
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    excludes.append(elt.value)
                elif isinstance(elt, ast.Name) and elt.id in bound:
                    excludes.append(bound[elt.id])
    layout = "defender/run_repository/_layout.py"
    assert layout in excludes, f"the census excludes {excludes}, not {layout}"
    assert (H.WORKTREE / layout).is_file(), f"the exclude {layout} matches no file"
    assert _defined_in(RunPaths) == (H.WORKTREE / layout).resolve(), (
        "the excluded file is the one the door's RunPaths is defined in")
    pins = _git("grep", "-n", "-E", r"_run_(paths|handle)\.py", "--", "defender/tests",
                ":!defender/tests/tenant_1105_run_repository",
                ":!**/goldens/**").stdout.splitlines()
    assert pins == [], f"existing tests still plant, pin or read a moved file: {pins[:15]}"


def test_1105_the_1134_census_reads_its_layout_vocabulary_from_the_submodule(tmp_path):
    """#1134's census reads its layout vocabulary from defender/run_repository/_layout.py and fails
    loudly on an empty vocabulary (NM-01), and in_vocabulary recognises a disk-touching layout
    function reached through the door (defender.run_repository.artifact_file) and through the
    submodule spelling."""
    from defender.run_repository import artifact_file
    from defender.tests import _census1134 as census

    layout = H.PACKAGE / "_layout.py"
    assert layout.is_file(), f"the census's layout file {layout} does not exist"
    tree = census.Tree(H.WORKTREE)
    vocab = set(getattr(tree, "run_paths_vocab", ()))
    disk = {"artifact_file", "artifact_dir", "plain_file", "contained_payload"}
    assert disk <= vocab, f"the census's layout vocabulary is {sorted(vocab)}, missing {disk}"
    assert tree.in_vocabulary(f"{_DOOR}.artifact_file"), "the door spelling is not vocabulary"
    assert tree.in_vocabulary(f"{_DOOR}._layout.artifact_file"), (
        "the submodule spelling is not vocabulary")
    assert not tree.in_vocabulary(f"{_DOOR}.is_case_answer_key"), (
        "control: a pure layout function is not vocabulary")
    assert _defined_in(artifact_file) == layout.resolve(), (
        f"the door's artifact_file is not defined in {layout}")
    empty = tmp_path / "empty"
    (empty / "defender").mkdir(parents=True)
    shutil.copy2(H.DEFENDER / "_io.py", empty / "defender" / "_io.py")
    err = H.raised(census.Tree, empty)
    assert err is not None, (f"a checkout with no layout submodule must fail loudly, not census an empty "
        f"vocabulary: {err!r}")
    assert not isinstance(err, (AttributeError, KeyError, TypeError)), (f"a checkout with no layout submodule must fail loudly, not census an empty "
        f"vocabulary: {err!r}")
    copied = tmp_path / "copied"
    (copied / "defender" / "run_repository").mkdir(parents=True)
    shutil.copy2(H.DEFENDER / "_io.py", copied / "defender" / "_io.py")
    shutil.copy2(layout, copied / "defender" / "run_repository" / "_layout.py")
    assert disk <= set(getattr(census.Tree(copied), "run_paths_vocab", ())), (
        "the vocabulary is not read from run_repository/_layout.py")


def test_1105_no_box_bind_reaches_the_episode_records_or_the_tenant_record(tmp_path):
    """The box's create argv for a run under tenant.runs (runtime/box/_lifecycle._create_argv)
    binds no source at or above tenant.runs read-write, so neither _episodes/ nor _tenant.json is
    under a writable bind. Positive control: the run's own run_dir is bound read-write. (A BoxSpec
    with an explicit rootfs keeps _create_argv off the filesystem: resolve_rootfs returns it
    verbatim, _docker.py:65-70; GR-A1, executed, is the design's own discharge.)"""
    from defender.run_repository import RunId, open_run
    from defender.runtime.box import BoxSpec
    from defender.runtime.box._lifecycle import _create_argv

    t = H.tenant(tmp_path / "data", H.T_ID)
    runs = H.runs_folder(t)
    H.make_run(runs, "r1")
    H.plant_record(runs, "r1-n1", t.id, "r1", {"a": "r1-n1-a"})
    run = open_run(t, RunId.parse("r1"))
    assert getattr(run, "run_dir", None) == runs / "r1", f"open_run handed out {run!r}"
    create = _create_argv("defender-run-r1", run.run_dir, H.DEFENDER,
                          BoxSpec(runtime="runc", rootfs="busybox"), tenant_agent=t.agent)
    argv = create.argv
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    binds = []
    for spec in mounts:
        fields = dict(f.split("=", 1) for f in spec.split(",") if "=" in f)
        binds.append((Path(fields["source"]), "readonly" in spec.split(",")))
    writable = [src for src, ro in binds if not ro]
    assert writable == [runs / "r1"], (
        f"the box's writable binds are {writable}, not exactly the run's own folder")
    for protected in (runs, runs / "_tenant.json", runs / "_episodes",
                      runs / "_episodes" / "r1-n1.json"):
        under = [src for src in writable if protected == src or src in protected.parents]
        assert under == [], f"{protected} sits under a writable box bind: {under}"
    assert "--read-only" in argv, "the box's own root is read-only"


def test_1105_a_handles_address_is_frozen_after_init(tmp_path):
    """After a Run is built, assigning or deleting run_dir, runs_base or tenant_id on it raises
    AttributeError (the frozen-dataclass convention, DV-4), and assigning tenant_id to a Run.at
    handle, which has none, raises too; partial_failures and the handle's five group attributes
    stay its own mutable state."""
    from defender.run_repository import Run

    runs = tmp_path / H.T_ID / "runs"
    H.plant_tenant_record(runs, H.T_ID)
    run_dir = H.make_run(runs, "r1")
    for run in (Run.under(runs, "r1", tenant_id=H.T_ID),
                Run.for_tenant(H.T_ID, "r1", runs_base=runs),
                Run(run_dir, runs_base=runs, tenant_id=H.T_ID)):
        for attr, value in (("run_dir", tmp_path / "elsewhere"), ("runs_base", tmp_path),
                            ("tenant_id", H.U_ID)):
            err = H.raised(setattr, run, attr, value)
            assert isinstance(err, AttributeError), f"assigning {attr} gave {err!r}"
            err = H.raised(delattr, run, attr)
            assert isinstance(err, AttributeError), f"deleting {attr} gave {err!r}"
        assert (run.run_dir, run.runs_base, run.tenant_id) == (run_dir, runs, H.T_ID), (
            "the address changed")
        run.partial_failures = ("noted",)
        assert run.partial_failures == ("noted",), "partial_failures stays the handle's state"
        for group in ("tables", "facts", "documents", "observability", "session"):
            assert getattr(run, group, None) is not None, f"the {group} group is gone"
            setattr(run, group, getattr(run, group))
    at = Run.at(run_dir)
    err = H.raised(setattr, at, "tenant_id", H.T_ID)
    assert isinstance(err, AttributeError), f"a Run.at handle took a tenant_id: {err!r}"
    assert not hasattr(at, "tenant_id"), "a Run.at handle has no tenant_id"
    err = H.raised(setattr, at, "run_dir", tmp_path)
    assert isinstance(err, AttributeError), f"a Run.at handle's run_dir moved: {err!r}"
