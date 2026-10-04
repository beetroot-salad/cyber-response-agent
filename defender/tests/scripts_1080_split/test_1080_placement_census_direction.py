"""#1080 — the placement contract, the O1 import census, the O2 direction test, the wrapper
rules and the shippable-surface lint's reach into integrations (spec
`spec-flow/specs/spec_graph_1080-scripts-split.yaml`, §7 record `70-resolutions.md`).

Every check here is STATIC (s129): it reads tracked files and parses ASTs through
`_census1080`, never imports a moved module to learn where it lives. Moved code is reached at
call time through `_spec1080`'s symbol locator, so a home that does not exist yet is one
failing test, not a collection error. Faults are planted in a tmp git copy of the tree
(`tree_copy` / `plant`) or in an `overlay`, never in the real tree.

SCOPE CUT (2026-10-04, human): only the reshaping half moves (`_spec1080`'s docstring). The O2
direction tests, the O7 shippable-surface tests and the placement cells of the OUT modules are
parked with their owners (`spec-flow/specs/parked/1080/parked_placement_census_direction.py`); the
tables below keep their IN rows, and O1's exception list is the cut's 35 named pairs (E1, E2).

At the base (80888efb) the demands the move must satisfy are red here — the files are still
under `defender/scripts/`, the old edges still exist, the new homes do not. The tests that pin a
property of the census itself (a planted edge is found, junk is ignored, a string is not an
import) are green at the base by construction: they drive the same scan over a planted copy.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import sys
import textwrap
from pathlib import Path

import pytest

from defender import _git
from defender.tests import _import_blocker
from defender.tests.scripts_1080_split import _census1080 as C
from defender.tests.scripts_1080_split import _spec1080 as S

# ======================================================================================
# Tables (from demand #0's placement map, amended by §7)
# ======================================================================================

#: Investigation symbols: under `defender/runtime/` (E2 of the 2026-10-04 cut: `payload_view`'s
#: and the sql engine's own anchors; the `record_query` guards and `workspace_map` stay in
#: `scripts/`, owned by #1165 and #1105).
INVESTIGATION = ("passthrough_max_bytes", "_load_payload", "_arrow_refusal")
#: The flat tier (`defender/_*.py`): the query-id and request-key rules under their BASE names
#: (`S.QUERY_RULE_PUBLIC` is the identity map since the cut) and the venv helper.
FLAT_TIER_RULES = (
    *S.QUERY_RULE_PUBLIC.values(), "is_reserved_query_id", "ABOVE_GUARD_QUERY_ID",
    "BASH_SHIM_QUERY_ID", "DENIED_QUERY_ID", "REPEAT_TRIP_QUERY_ID", "_QID_FORBIDDEN",
    "reexec_into_venv",
)
#: Under `runtime/providers/`.
IN_PROVIDERS = ("usage_cost",)
#: The lessons engine: outside `scripts/` and outside the content folder `defender/lessons/`.
LESSONS_ENGINE = (
    "cmd_grep", "cmd_tags", "cmd_show", "match_lessons", "match_loaded", "Hit",
    "WRITE_RETURN_LEAD", "FOLD_LEAD", "resolve_corpus", "as_list", "csv_set",
)

#: One anchor symbol per moved module (base path → a name only it defines), for the scans that
#: read "every moved module": m2's anchor scan, the engines. E2: the seven modules the cut moves.
MODULE_ANCHORS = {
    "defender/scripts/gather_tools/payload_view.py": "passthrough_max_bytes",
    "defender/scripts/gather_tools/sql.py": "_load_payload",
    "defender/scripts/pricing.py": "usage_cost",
    "defender/scripts/_venv.py": "reexec_into_venv",
    "defender/scripts/lessons/lessons_fm.py": "cmd_tags",
    "defender/scripts/lessons/lessons_frontier.py": "match_lessons",
    "defender/scripts/lessons/_lessons_common.py": "resolve_corpus",
}
#: record_query is split: its query-rule slice moves (anchored here), its remainder stays.
RECORD_QUERY_ANCHORS = ("is_reserved_query_id",)

#: Each engine a shim's wrapper delegates to, by an anchor the engine defines.
ENGINE_OF_SHIM = {"defender-sql": "_load_payload", "defender-lessons": "cmd_tags"}

#: The moved module whose `__main__` block travels with it (human, 2026-10-04: KEPT), by anchor.
UNCALLED = (("WRITE_RETURN_LEAD", None),)

#: The packages the dev-only `code-smells` job (`uv sync --extra dev`) does NOT install: the
#: `runtime` and `api` extras' import names (defender/pyproject.toml at the base).
NOT_IN_DEV_JOB = ("pydantic_ai*", "pydantic_graph", "pydantic_evals", "anthropic", "openai",
                  "mcp", "fastmcp", "logfire", "toons", "duckdb", "pytz", "fastapi", "uvicorn",
                  "starlette")

PLANT_IMPORT = "from defender.scripts.policy_cli import main\n"


# ======================================================================================
# Small helpers
# ======================================================================================


def _base_files() -> list[str]:
    return list(S.base_inventory()["files"])


def _kept_at_base() -> set[str]:
    """The base paths that stay files under `scripts/` (commands, wrappers, adapters, and the
    cut's named OUT files, E1)."""
    return {*C.STAYING_COMMANDS, *C.wrappers(), *C.adapters_expected(), *C.OUT_STAYING}


def _moved_old_py() -> list[str]:
    """Every base `.py` under `scripts/` that moves out (none of the kept files): the cut's IN
    files."""
    kept = _kept_at_base()
    return [f for f in _base_files() if f.endswith(".py") and f not in kept]


def _new_definitions(name: str, root: Path = S.REPO_ROOT) -> list[str]:
    """Definitions of `name` outside `scripts/` that are not ones the base already had there."""
    base_other = set(S.base_inventory()["base_defs_outside_scripts"].get(name, ()))
    return [d for d in S.definitions(name, root)
            if not S.under(d, "defender/scripts") and d not in base_other]


def _placed(name: str, home: str | None) -> str:
    """`name`'s one home (inside `home` when given), and no second definition anywhere new."""
    where = S.home_of(name, home=home)
    if home is not None:
        assert S.under(where, home), f"`{name}` is defined in {where}, not under {home}"
    new = _new_definitions(name)
    assert new == [where], f"`{name}` must have exactly one home; definitions outside " \
                           f"scripts/: {new}"
    return where


def _rel_edges(edges: list[C.Edge]) -> list[tuple[str, int, str]]:
    return [(e.importer, e.line, e.target) for e in edges]


def _overlay_with(relpath: str, extra: str) -> dict[str, str]:
    """`relpath`'s real source with `extra` appended (an overlay entry)."""
    p = S.REPO_ROOT / relpath
    before = p.read_text(encoding="utf-8") if p.is_file() else ""
    if before and not before.endswith("\n"):
        before += "\n"
    return {relpath: before + extra}


def _line_of(source: str, needle: str) -> int:
    for i, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} is not in the planted source")


def _child_find_spec(names: list[str]) -> dict[str, bool]:
    """Whether each dotted name resolves to a module, asked of a child pinned to THIS tree."""
    body = ("import importlib.util, json, sys\n"
            "out = {}\n"
            "for n in json.loads(sys.argv[1]):\n"
            "    try:\n"
            "        out[n] = importlib.util.find_spec(n) is not None\n"
            "    except ModuleNotFoundError:\n"
            "        out[n] = False\n"
            "print(json.dumps(out))\n")
    cp = S.python("-c", body, json.dumps(names))
    assert cp.returncode == 0, cp.stderr.decode()
    result: dict[str, bool] = json.loads(cp.stdout)
    return result


# ======================================================================================
# D0 — what `scripts/` holds, and where each moved symbol lives
# ======================================================================================


def test_1080_scripts_holds_only_entry_points():
    """D1 under the 2026-10-04 scope cut: the IN files are gone from `defender/scripts/`, no
    re-export shim is left, and their old dotted names do not resolve. Every tracked file under
    `defender/scripts/` is one of these: `tenant.py`, `policy_cli.py`, `box_image.py`,
    `tacit_cli.py`; a thin wrapper that a `bin/` shim invokes, which means the `defender-sql`
    and `defender-lessons` engines' wrappers; a file under `scripts/adapters/` (all of its base
    files stay until #1172); or one of the cut's named OUT files that stay with their owners
    (`visualize/`'s eight modules and three assets and `workspace_map.py`, #1105;
    `case_history/ticket_writer.py` and `gather_tools/record_query.py`, #1165;
    `case_history/case_ticket.py`, the case_ticket follow-up #1190). The IN files (`_venv.py`,
    `pricing.py`, `gather_tools/payload_view.py`, `lessons/lessons_frontier.py`,
    `lessons/_lessons_common.py`) are not left there, and no re-export shim keeps their old
    `defender.scripts.*` path importable.

    Observed: the placement check over every TRACKED file under `defender/scripts/` (any file
    type), the adapters folder against its base files, and a child pinned to this tree asked
    whether each IN module's old dotted name still resolves. Positive control: the staying
    adapters' dotted names do resolve in the same child.
    """
    assert C.placement_findings() == [], "files left under defender/scripts/ that are none " \
        "of the staying commands, the shims' wrappers or the adapters' files"
    assert C.tracked_files(S.REPO_ROOT, C.ADAPTERS) == sorted(C.adapters_expected())
    old = [S.dotted(f) for f in _moved_old_py()]
    staying = [S.dotted(f) for f in C.adapters_expected() if f.endswith(".py")]
    found = _child_find_spec(old + staying)
    assert all(found[n] for n in staying), {n: found[n] for n in staying}
    assert [n for n in old if found[n]] == [], "an old defender.scripts.* path still imports"


def _check_group(names, home, extra=None):
    out = {}
    for n in names:
        where = _placed(n, home)
        if extra is not None:
            extra(n, where)
        out[n] = where
    return out


def _not_tools_or_branch(name, where):
    for bad in ("defender/runtime/tools", "defender/runtime/branch"):
        assert not S.under(where, bad), f"`{name}` landed in {bad}: {where}"


def _outside_lessons_content(name, where):
    assert not S.under(where, "defender/lessons"), \
        f"`{name}` is engine code inside the lesson content folder: {where}"


def test_1080_each_moved_symbol_is_defined_under_its_home():
    """Homes are found by the symbol each moved module defines (dF0). Under the 2026-10-04
    scope cut each moved symbol of the reshaping half is defined (as a `def`, `class` or
    module-level assignment) outside `defender/scripts/`, in a module under its home:
    `payload_view`'s and the sql engine's symbols under `defender/runtime/` (not in its
    `tools/` or `branch/` packages); the query-id and request-key rules (under their base names)
    and `reexec_into_venv` in a flat-tier `defender/_*.py` module; `usage_cost` under
    `runtime/providers/`; the lessons engine outside `defender/lessons/`. The groups the cut
    parks (verbs, the exit-code vocabulary, integrations, the Elastic module, reports and its
    assets, the tenants home, the runs writers) are not asserted here.

    Observed through the symbol locator: each name's one definition outside `scripts/`, inside
    its home, and no second new definition anywhere (the one-home rule).
    """
    _check_group(INVESTIGATION, S.RUNTIME, _not_tools_or_branch)
    _check_group(FLAT_TIER_RULES, S.FLAT_TIER)
    _check_group(IN_PROVIDERS, S.PROVIDERS)
    _check_group(LESSONS_ENGINE, None, _outside_lessons_content)


# ======================================================================================
# O1 — the import census
# ======================================================================================


def test_1080_no_module_outside_scripts_imports_a_module_under_it():
    """An AST census over every `.py` under `defender/` and the repo's `scripts/`, excluding
    `tests/` directories, finds no `import` or `from … import` that names `defender.scripts` or
    anything under it. Relative imports are resolved against their package. Under the
    2026-10-04 scope cut the allowed exceptions are the 35 named (importer, target) pairs (37
    import statements) into the `scripts/` modules the cut leaves where they are, each tagged
    with the issue that retires it (#1172/#1121, #1165, #1105, the case_ticket follow-up #1190). Any
    other import into the folder fails, and an exception whose edge no longer exists is itself a
    finding ([218]); o1_exception_list_is_the_named_edges pins the list.

    Observed: the census over the real tree, minus the named pairs, is empty, and no pair is
    stale. Positive control (cheap form of o1_census_flags_a_planted_edge): the
    same census with one import planted in a runtime module (an overlay) reports it.
    """
    violations = C.o1_violations()
    assert _rel_edges(violations) == [], "imports of defender.scripts.* from outside it"
    assert C.stale_o1_exceptions() == []
    planted = "defender/runtime/verbs.py"
    overlay = _overlay_with(planted, PLANT_IMPORT)
    line = _line_of(overlay[planted], PLANT_IMPORT.strip())
    assert (planted, line, "defender.scripts.policy_cli") in _rel_edges(
        C.o1_violations(overlay=overlay))


def test_1080_the_import_census_flags_a_planted_edge_and_exempts_tests(tmp_path):
    """The same census, run over a copy of the tree with `from defender.scripts.policy_cli
    import main` planted in a runtime module, reports exactly that file and line. The same line
    planted in a file under `defender/tests/` is not reported, and neither is a line in
    `conftest.py`; the same line planted in a `test_*.py` file beside production code outside
    any `tests` directory is reported ([155]). The test-import lane is the one deliberate
    asymmetry: a census that began flagging files under `tests/`, or that exempted a non-test
    path, fails here.

    Observed: the census of a tmp git copy before and after four planted (tracked) files; the
    difference is exactly the runtime line and the beside-production `test_*.py` line.
    """
    root = C.tree_copy(tmp_path / "copy")
    before = set(_rel_edges(C.census(root)))
    runtime_line = C.plant(root, "defender/runtime/verbs.py", PLANT_IMPORT)
    C.plant(root, "defender/tests/test_zz_spec1080_planted.py", PLANT_IMPORT)
    C.plant(root, "defender/learning/conftest.py", PLANT_IMPORT)
    beside_line = C.plant(root, "defender/runtime/test_spec1080_beside.py", PLANT_IMPORT)
    after = set(_rel_edges(C.census(root)))
    assert after - before == {
        ("defender/runtime/verbs.py", runtime_line, "defender.scripts.policy_cli"),
        ("defender/runtime/test_spec1080_beside.py", beside_line, "defender.scripts.policy_cli"),
    }
    assert before - after == set()


def test_1080_the_o1_exception_list_is_exactly_the_named_edges_and_none_is_stale():
    """The import census's exception list holds exactly the 35 named (importer, target) pairs
    the 2026-10-04 scope cut leaves standing — 37 import statements at the base, the 59 base
    edges less the 22 the cut's moves retire — each tagged with the owner that retires it:
    #1172/#1121 (20: into `_stub_transport`, `confinement`, `elastic_adapter`, `esql_text` and
    `faults`), #1165 (6: into `record_query` and `ticket_writer`), #1105 (6: into the
    `visualize/` modules and `workspace_map`) and the case_ticket follow-up #1190 (3: into
    `case_ticket`). H4 (i)'s `ticket_writer -> _stub_transport` edge is internal to `scripts/`
    and is not listed. Every listed pair still exists in the tree, so an entry that outlives the
    edge it excused is a finding, not a silent widening, and the list can only shrink. A new
    import from outside `scripts/` into `scripts/adapters/` (another importer, or another
    adapters module) planted in a copy of the tree is reported. `scripts/adapters/` keeps all
    of its base files until #1172. (E1; M-A (a); [218].)

    Observed: the list's pairs and owners, its liveness over the real tree, an overlay that
    removes staging's `_stub_transport` edge (reported stale), two planted new edges (both
    reported), and the adapters folder's tracked files.
    """
    exceptions = C.o1_exceptions()
    pairs = [(i, t) for i, t, _ in exceptions]
    assert len(pairs) == len(set(pairs)) == 35
    owners: dict[str, int] = {}
    for _, _, owner in exceptions:
        owners[owner] = owners.get(owner, 0) + 1
    assert owners == {"#1172/#1121": 20, "#1165": 6, "#1105": 6, "case_ticket follow-up #1190": 3}
    assert all(not S.is_test_path(i) and not S.under(i, "defender/scripts")
               for i, _ in pairs)
    assert all(C.is_scripts_target(t) for _, t in pairs)
    assert C.stale_o1_exceptions() == []
    staging = "defender/learning/branch/staging.py"
    src = (S.REPO_ROOT / staging).read_text(encoding="utf-8")
    cut = "\n".join(line for line in src.splitlines() if "_stub_transport" not in line) + "\n"
    stale = C.stale_o1_exceptions(overlay={staging: cut})
    assert [(x[0], x[1]) for x in stale] == [(staging, C.STUB_TRANSPORT)]
    fourth = {**_overlay_with("defender/runtime/verbs.py",
                              "from defender.scripts.adapters import _stub_transport\n"),
              **_overlay_with(staging, "from defender.scripts.adapters.cmdb_adapter import VERBS\n")}
    reported = {(e.importer, e.target) for e in C.o1_violations(overlay=fourth)}
    assert ("defender/runtime/verbs.py", C.STUB_TRANSPORT) in reported
    assert (staging, "defender.scripts.adapters.cmdb_adapter") in reported
    assert C.tracked_files(S.REPO_ROOT, C.ADAPTERS) == sorted(C.adapters_expected())


# ======================================================================================
# D1 — the wrappers, and the mains that no caller runs
# ======================================================================================


def _is_main_guard(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Compare) \
        and isinstance(stmt.test.left, ast.Name) and stmt.test.left.id == "__name__" \
        and any(isinstance(c, ast.Constant) and c.value == "__main__"
                for c in stmt.test.comparators)


def _is_docstring(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) \
        and isinstance(stmt.value.value, str)


def _one_call(stmt: ast.stmt) -> bool:
    """A statement that is one delegating call: `f(...)`, `return f(...)`,
    `raise SystemExit(f(...))` or `sys.exit(f(...))`."""
    if isinstance(stmt, ast.Expr | ast.Return):
        return isinstance(stmt.value, ast.Call)
    return isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call)


def _is_log_setup(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) \
        and "configure_from_env" in ast.unparse(stmt.value.func)


def _sys_path_mutations(tree: ast.AST) -> list[ast.AST]:
    out: list[ast.AST] = []
    for n in ast.walk(tree):
        call = isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
            and n.func.attr in {"insert", "append", "extend"} \
            and ast.unparse(n.func.value) == "sys.path"
        assign = isinstance(n, ast.Assign | ast.AugAssign) and "sys.path" in ast.unparse(n)
        if call or assign:
            out.append(n)
    return out


def _inserts_first(stmt: ast.stmt) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "insert" and ast.unparse(n.func.value) == "sys.path"
               and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == 0
               for n in ast.walk(stmt))


def _main_only_delegates(fn: ast.FunctionDef) -> bool:
    body = [s for s in fn.body if not _is_docstring(s)]
    return len(body) == 1 and _one_call(body[0])


def _final_call_ok(stmt: ast.stmt) -> bool:
    if _one_call(stmt):
        return True
    if not _is_main_guard(stmt):
        return False
    assert isinstance(stmt, ast.If)
    body = [s for s in stmt.body if not _is_log_setup(s)]
    return not stmt.orelse and len(body) == 1 and _one_call(body[0])


def _wrapper_problems(rel: str, source: str) -> tuple[list[str], ast.stmt | None]:
    """What makes `rel` more than imports, one bootstrap, an optional delegating `main` and one
    final call into its engine; and the bootstrap statement."""
    tree = ast.parse(source, filename=rel)
    body = [s for s in tree.body if not _is_docstring(s)]
    problems: list[str] = []
    if not body or not _final_call_ok(body[-1]):
        problems.append("the module does not end in one call into its engine")
    bootstraps: list[ast.stmt] = []
    for s in body[:-1]:
        if isinstance(s, ast.Import | ast.ImportFrom):
            continue
        if isinstance(s, ast.FunctionDef) and s.name == "main" and _main_only_delegates(s):
            continue
        if _inserts_first(s):
            bootstraps.append(s)
            continue
        problems.append(f"line {s.lineno}: `{ast.unparse(s).splitlines()[0]}` is neither an "
                        f"import, the bootstrap, a delegating main nor the final call")
    if len(bootstraps) != 1:
        problems.append(f"{len(bootstraps)} import-root bootstraps (exactly one is the rule)")
    files = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "__file__"]
    inside = {id(n) for b in bootstraps for n in ast.walk(b)}
    if any(id(n) not in inside for n in files):
        problems.append("derives a path from its own location outside the bootstrap")
    return problems, (bootstraps[0] if len(bootstraps) == 1 else None)


def _bootstrap_puts_own_root_first(wrapper: Path, source: str, stmt: ast.stmt) -> str:
    """Run the wrapper's stdlib imports and its bootstrap alone in a child whose `sys.path`
    already holds a foreign checkout first and this one later; return `sys.path[0]`."""
    tree = ast.parse(source)
    stdlib = [ast.get_source_segment(source, s) or "" for s in tree.body
              if isinstance(s, ast.Import | ast.ImportFrom)
              and not (isinstance(s, ast.ImportFrom) and s.module == "__future__")
              and all((a.name if isinstance(s, ast.Import) else (s.module or "")).split(".")[0]
                      in sys.stdlib_module_names for a in s.names)]
    code = "\n".join([*stdlib, f"__file__ = {str(wrapper)!r}",
                      ast.get_source_segment(source, stmt) or "",
                      "import json, sys as _s", "print(json.dumps(_s.path[0]))"])
    foreign = wrapper.parent  # any directory that is not this checkout's root
    env = S.child_env(pythonpath=False, PYTHONPATH=f"{foreign}{os.pathsep}{S.REPO_ROOT}")
    cp = S.python("-c", code, env=env, cwd=foreign)
    assert cp.returncode == 0, cp.stderr.decode()
    first: str = json.loads(cp.stdout)
    return first


def _engine_main_is_called(wrapper_src: str, engine: str) -> bool:
    mod = S.dotted(engine)
    tree = ast.parse(wrapper_src)
    for st in S.import_statements("defender/scripts/_w.py", wrapper_src):
        if st.module == mod and "main" in st.names:
            return True
    return any(isinstance(n, ast.Attribute) and n.attr == "main" for n in ast.walk(tree)) \
        and any(st.module == mod or mod.startswith(st.module + ".")
                for st in S.import_statements("defender/scripts/_w.py", wrapper_src))


def test_1080_each_wrapper_left_in_scripts_only_delegates_to_its_engine():
    """Each wrapper under `defender/scripts/` (every `.py` file there except `tenant.py`,
    `policy_cli.py`, `box_image.py`, `tacit_cli.py`, `scripts/adapters/` and the 2026-10-04
    cut's named OUT files that stay with their owners, E1) has a module body
    of imports and one call into its engine's entry. It defines no function or class except an
    optional `main` that only delegates. It carries exactly one import-root bootstrap, a
    statement that puts the wrapper's own root (the checkout root that holds `defender/`) first
    on `sys.path`, and derives no other path from its own location. The engines it calls carry
    no bootstrap, and the `bin/` shims and the launchers are unchanged. (M-H (a); dF3 amended.)

    Observed: each wrapper's AST against the shape above; its bootstrap run alone in a child
    whose `sys.path` already holds a foreign directory first and this checkout later (the
    root must come out first); the wrapper imports its engine (found by an anchor symbol); the
    engine has no `sys.path` mutation; the three `bin/` shims hash to their base bytes.
    """
    wrappers = [r for r in C.tracked_files(S.REPO_ROOT, "defender/scripts")
                if r.endswith(".py") and r not in C.STAYING_COMMANDS
                and not S.under(r, C.ADAPTERS) and r not in C.OUT_STAYING]
    assert sorted(wrappers) == sorted(C.wrappers())
    for shim, anchor in ENGINE_OF_SHIM.items():
        rel = C.shim_target(S.REPO_ROOT, shim)
        src = (S.REPO_ROOT / rel).read_text(encoding="utf-8")
        problems, boot = _wrapper_problems(rel, src)
        assert problems == [], f"{rel}: {problems}"
        assert boot is not None
        first = _bootstrap_puts_own_root_first(S.REPO_ROOT / rel, src, boot)
        assert Path(first).resolve() == S.REPO_ROOT.resolve(), (rel, first)
        engine = S.home_of(anchor)
        imported = {st.module for st in S.import_statements(rel, src)}
        assert S.dotted(engine) in imported or any(
            S.dotted(engine).startswith(m + ".") for m in imported if m.startswith("defender.")
        ), f"{rel} does not import its engine {engine}"
        engine_tree = ast.parse((S.REPO_ROOT / engine).read_bytes())
        assert _sys_path_mutations(engine_tree) == [], f"the engine {engine} carries a bootstrap"
    shims = S.base_inventory()["shims"]
    for shim, digest in shims.items():
        assert hashlib.sha256((S.BIN / shim).read_bytes()).hexdigest() == digest, \
            f"bin/{shim} changed"


def _command_guard(source: bytes | str) -> ast.If | None:
    """The module-level `if __name__ == "__main__":` guard that runs the module's own command:
    its body calls the module-level `main` the module defines (`sys.exit(main(...))`). A guard
    that only re-execs into the venv (`reexec_into_venv(__file__)`) is not one."""
    tree = ast.parse(source)
    if "main" not in {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}:
        return None
    for n in tree.body:
        if isinstance(n, ast.If) and S.has_main_block(ast.unparse(n)) and any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "main"
                for stmt in n.body for c in ast.walk(stmt)):
            return n
    return None


def test_1080_the_moved_lessons_frontier_keeps_its_main_block():
    """The moved `lessons_frontier` keeps its command block in its new home: the module-level `if __name__ == "__main__":` guard that runs its own `main` (`sys.exit(main(sys.argv))`, `lessons_frontier.py:546` at the base), not only the venv re-exec guard above its imports (:36). Human, 2026-10-04: the block travels with the module, though no `bin/` shim, `run_common`, CI step or doc invokes it. The other three modules M-D (a) would have stripped (`workspace_map`, `visualize_run`, `visualize_episode`) do not move under the cut; their cells are parked with #1105.

    Observed: the module, found by a symbol only it defines (outside `defender/scripts/`), read
    for a module-level `__main__` guard whose body calls the module's `main`. Controls, on files
    that stay put: the reader finds the command guard of `box_image.py` (a staying command CI
    invokes) and none in `scripts/adapters/faults.py`. The discriminating control is the module
    itself: with its command guard cut out of its source, the reader finds none, even though the
    venv re-exec guard is still there. A move that drops the command block therefore fails.
    """
    assert _command_guard((S.SCRIPTS / "box_image.py").read_bytes())
    assert not _command_guard((S.SCRIPTS / "adapters" / "faults.py").read_bytes())
    for anchor, home in UNCALLED:
        where = S.home_of(anchor, home=home)
        source = (S.REPO_ROOT / where).read_text(encoding="utf-8")
        guard = _command_guard(source)
        if guard is not None:
            lines = source.splitlines(keepends=True)
            dropped = "".join(lines[:guard.lineno - 1] + lines[guard.end_lineno:])
            assert _command_guard(dropped) is None, \
                f"control: {where} with its command block cut out still reads as keeping it"
        assert not S.under(where, "defender/scripts"), f"the lessons engine is still {where}"
        assert guard is not None, (
            f"{where} dropped its command block (the `__main__` guard that runs its `main`) "
            f"that the move must keep")


# ======================================================================================
# Lessons content, the flat tier, file-depth anchors
# ======================================================================================


def test_1080_no_python_module_lands_in_the_lesson_content_folder():
    """No `.py` file exists under `defender/lessons/`. Its lesson `.md` files are still there
    (positive control).

    Observed: every file under `defender/lessons/` on disk (junk directories skipped), and the
    lessons engine found by its symbols outside that folder (it exists: the folder is not empty
    of `.py` because the engine vanished).
    """
    on_disk = [p for p in S.LESSONS_CONTENT.rglob("*")
               if p.is_file() and not set(p.relative_to(S.REPO_ROOT).parts) & S.JUNK_DIRS]
    assert [S.rel(p) for p in on_disk if p.suffix == ".py"] == []
    assert any(p.suffix == ".md" for p in on_disk), "the lesson .md files are gone"
    for anchor in ("cmd_tags", "match_lessons"):
        engine = S.home_of(anchor)
        assert not S.under(engine, "defender/lessons")
        assert not S.under(engine, "defender/scripts"), f"the lessons engine is still {engine}"


def test_1080_every_flat_tier_module_at_the_base_keeps_its_name():
    """Every `defender/_*.py` module present at the base still exists at the same path. New
    flat-tier modules may be added.

    Observed against the base inventory's flat tier (30 modules at 80888efb). Green at the base
    by construction: it guards the move against regrouping the tier (N10).
    """
    base = S.base_inventory()["flat_tier"]
    assert len(base) == 30
    assert [f for f in base if not (S.REPO_ROOT / f).is_file()] == []


def test_1080_no_moved_module_derives_a_path_from_its_own_file_depth():
    """No moved module computes a path as `Path(__file__)…parents[N]` or `.parent.parent`. A
    sibling `Path(__file__).parent / "assets"` that travels with its module is allowed. Positive
    control: the scan flags a planted `parents[2]`. Under the 2026-10-04 cut "every moved
    module" is the IN set: `_venv`, `pricing`, `payload_view`, the sql engine, the three lessons
    engine modules and `record_query`'s query-rule slice.

    Observed: every moved module, found by an anchor symbol it defines (record_query's rule
    slice by its own anchor), scanned for a file-depth anchor; the control plants
    `parents[2]` and `.parent.parent` (both flagged) beside an allowed `.parent / "assets"`.
    """
    planted = textwrap.dedent('''\
        from pathlib import Path
        ASSETS = Path(__file__).parent / "assets"
        ROOT = Path(__file__).resolve().parents[2]
        UP = Path(__file__).parent.parent
    ''')
    assert C.file_depth_anchors(planted) == [3, 4]
    anchors = [*MODULE_ANCHORS.values(), *RECORD_QUERY_ANCHORS]
    homes = sorted({S.home_of(a) for a in anchors})
    found = {h: C.file_depth_anchors((S.REPO_ROOT / h).read_bytes(), h) for h in homes}
    assert {h: lines for h, lines in found.items() if lines} == {}
    assert not any(S.under(h, "defender/scripts") for h in homes)


# ======================================================================================
# The census's reach (sNNN settled premises)
# ======================================================================================


_RARE = textwrap.dedent('''\
    import sys
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from defender.scripts.pricing import usage_cost
    def f():
        from defender.scripts.workspace_map import workspace_map
        return workspace_map
    try:
        import defender.scripts.tenant
    except ImportError:
        pass
    if sys.platform == "win32":
        from defender.scripts.tacit_cli import main
    from defender.scripts.box_image import main as _bm
''')


def test_census_meets_an_edge_seen_only_on_a_rare_path():
    """The import census flags an import of a module under scripts/ wherever the statement
    sits: module level, inside a function body, inside a try, under `if TYPE_CHECKING:`, or
    behind a platform/interpreter conditional. The tree is reported clean only when none exist,
    and the census's positive control (a planted ordinary module-level import) and a planted
    rare-path import are each reported. K1's census already counts nested imports
    (lessons_push.py:28 under TYPE_CHECKING is a hit today).

    Observed: the real tree's census is clean (beyond the three named exceptions), and a
    planted module holding one import in each position is reported once per position.
    """
    assert _rel_edges(C.o1_violations()) == []
    rel = "defender/runtime/_spec1080_rare.py"
    got = {(e.line, e.target) for e in C.census(overlay={rel: _RARE}) if e.importer == rel}
    assert got == {(4, "defender.scripts.pricing"), (6, "defender.scripts.workspace_map"),
                   (9, "defender.scripts.tenant"), (13, "defender.scripts.tacit_cli"),
                   (14, "defender.scripts.box_image")}


def _pointer_verdict(root: Path):
    from defender.tests.scripts_1080_split import _pointers1080 as P

    return sorted(P.stale_scripts_pointers(root)), sorted(P.dead_scripts_pointers(root))


def _junk_checkout(root: Path, tmp: Path) -> None:
    """Untracked junk in a checkout: a nested checkout at an older layout, a `.venv` link, a
    `__pycache__` source file and a scratch file — each spelling `defender.scripts`."""
    nested = root / "defender" / "old_checkout"
    (nested / "defender" / "runtime").mkdir(parents=True)
    (nested / "defender" / "runtime" / "m.py").write_text(PLANT_IMPORT, encoding="utf-8")
    _git.git(["init", "-q"], cwd=nested)
    venv_target = tmp / "venv_target"
    (venv_target / "lib").mkdir(parents=True)
    (venv_target / "lib" / "m.py").write_text(PLANT_IMPORT, encoding="utf-8")
    (root / "defender" / ".venv").symlink_to(venv_target, target_is_directory=True)
    cache = root / "defender" / "runtime" / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "stale.py").write_text(PLANT_IMPORT, encoding="utf-8")
    (root / "defender" / "runtime" / "scratch_spec1080.py").write_text(PLANT_IMPORT,
                                                                         encoding="utf-8")


def test_census_and_pointer_scans_run_in_a_checkout_holding_nested_checkouts(tmp_path):
    """The census, the 'scripts holds only entry points' check and the doc-pointer scan give
    the same verdict in the main checkout, in a linked worktree and in CI. They cover only that
    checkout's own defender/ and repo scripts/ trees; untracked nested checkouts at older
    commits, a .venv link, __pycache__ and scratch files change nothing and are never reported
    as hits. (O1 scopes the census to defender/ and the repo's scripts/.)

    Observed: a committed tmp copy (the main checkout) given untracked junk that spells
    `defender.scripts`, a linked worktree of it (`git worktree add`) and a fresh clone (CI's
    checkout): the three verdicts are equal, and no hit names a junk path.
    """
    main = C.tree_copy(tmp_path / "main", commit=True,
                       also=("docs", "defender/docs", "defender/CLAUDE.md", "defender/skills"))
    _junk_checkout(main, tmp_path)
    linked = tmp_path / "linked"
    _git.git(["worktree", "add", "-q", "--detach", str(linked)], cwd=main)
    clone = tmp_path / "clone"
    _git.git(["clone", "-q", str(main), str(clone)], cwd=tmp_path)
    verdicts = [(_rel_edges(C.census(r)), C.placement_findings(r), _pointer_verdict(r))
                for r in (main, linked, clone)]
    assert verdicts[0] == verdicts[1] == verdicts[2]
    junk = ("defender/old_checkout", "defender/.venv", "__pycache__", "scratch_spec1080")
    assert not [e for e in verdicts[0][0] if any(j in e[0] for j in junk)]


#: Split modules' names that may vanish: lessons_frontier's location-derived root (m2: it may
#: become an import of the paths helper). Its `main` and `_positive_int` stay: its `__main__`
#: block travels with it (human, 2026-10-04).
ALLOWED_DROPS = {"defender/scripts/lessons/lessons_frontier.py": {"REPO_ROOT"}}
RECORD_QUERY = "defender/scripts/gather_tools/record_query.py"
#: record_query's query-rule slice, the cut's IN item 6 (95-cut): these names move to the flat
#: tier under their base names; every other record_query name stays in it (#1165).
RULE_SLICE = frozenset({
    "_request_key", "PARAMS_NESTING_LIMIT", "ParamsTooDeep", "_json_safe_params",
    "params_too_deep", "call_args_too_deep", "RESERVED_QUERY_ID_PREFIX", "is_reserved_query_id",
    "ABOVE_GUARD_QUERY_ID", "BASH_SHIM_QUERY_ID", "DENIED_QUERY_ID", "REPEAT_TRIP_QUERY_ID",
    "_QID_FORBIDDEN", "_KEBAB_SEGMENT", "resolve_query_id",
})
#: E2 of the 2026-10-04 cut: the split modules are record_query (rules and remainder) and
#: lessons_frontier (moved whole, one name allowed to vanish).
SPLIT_MODULES = (RECORD_QUERY, "defender/scripts/lessons/lessons_frontier.py")


def _moves(base_path: str, name: str) -> bool:
    """Whether `base_path`'s `name` leaves `scripts/` (all of lessons_frontier; record_query's
    rule slice only)."""
    return base_path != RECORD_QUERY or name in RULE_SLICE


def _homes_of_module(base_path: str, names: list[str], shared: set[str]) -> set[str]:
    """The new modules that hold `base_path`'s moving names that no other scripts module
    defines."""
    out: set[str] = set()
    for n in names:
        if n in shared or n == "__all__" or not _moves(base_path, n):
            continue
        out.update(_new_definitions(S.QUERY_RULE_PUBLIC.get(n, n)))
    return out


def _name_census(base_path: str, shared: set[str]) -> list[str]:
    names = list(S.base_inventory()["py_names"][base_path])
    homes = _homes_of_module(base_path, names, shared)
    drops = ALLOWED_DROPS.get(base_path, set())
    problems: list[str] = []
    for n in names:
        if n == "__all__":
            continue
        new = _new_definitions(S.QUERY_RULE_PUBLIC.get(n, n))
        if n in shared:
            new = [d for d in new if d in homes]
        if not _moves(base_path, n):
            if new or base_path not in S.definitions(n):
                problems.append(f"{base_path}::{n} must stay in {base_path} -> {new or 'gone'}")
            continue
        if len(new) > 1 or (not new and n not in drops):
            problems.append(f"{base_path}::{n} -> {new or 'dropped'}")
        if (S.REPO_ROOT / base_path).exists() and base_path in S.definitions(n):
            problems.append(f"{base_path}::{n} is still defined at its old path")
    return problems


def test_a_name_in_a_split_module_that_no_placement_row_claims():
    """Every top-level name defined in a split module has exactly one home after the move: none
    dropped, none defined twice, none left importable from the old path, every importer
    repointed. Under the 2026-10-04 scope cut the split modules are `record_query` (its
    query-rule slice moves to the flat tier under base names; its remainder, the guards and
    writers owned by #1165, stays in `record_query.py`) and `lessons_frontier` (moved whole with
    its `__main__` block; only its location-derived `REPO_ROOT` may go, m2). The name census
    (old names in = new names out, per P9) reconciles. Where a name goes when the doc's table
    does not place it is the implementer's within the 10-03 module placement, but the one-home
    rule is not.

    Observed: each base name (golden inventory) counted among the new definitions outside
    `scripts/` (a name several scripts modules define is counted inside the homes of its own
    module's other names); each record_query remainder name is still defined in
    `record_query.py` and nowhere new, and no rule-slice name is; `lessons_frontier.py` is
    gone and the census holds no edge into it.
    """
    inv = S.base_inventory()["py_names"]
    seen: dict[str, int] = {}
    for names in inv.values():
        for n in names:
            seen[n] = seen.get(n, 0) + 1
    shared = {n for n, k in seen.items() if k > 1}
    shared |= set(S.base_inventory()["base_defs_outside_scripts"])
    problems = [p for m in SPLIT_MODULES for p in _name_census(m, shared)]
    assert problems == []
    whole = [m for m in SPLIT_MODULES if m != RECORD_QUERY]
    assert [m for m in whole if (S.REPO_ROOT / m).exists()] == []
    old = {S.dotted(m) for m in whole}
    assert [e for e in _rel_edges(C.census()) if e[2] in old] == []


def _invocation_lines(text: str) -> list[tuple[int, str]]:
    """Lines that run something (an interpreter, a shim's `$PY`, `exec`, `-m`)."""
    runs = re.compile(r"\bpython[\d.]*\b|\$\{?PY\b|sys\.executable|\bexec\b|\s-m\s")
    return [(i, line) for i, line in enumerate(text.splitlines(), start=1) if runs.search(line)]


_PATH_CALL = re.compile(r"(?:defender/|\}/)(scripts/[\w./-]+?\.py)\b")
_MODULE_CALL = re.compile(r"-m\s+(defender\.scripts(?:\.\w+)+)")


def _caller_files() -> list[str]:
    """The non-test callers a command may have: the `bin/` shims, `run_common`, CI workflows
    and tracked docs (not the spec-flow records or experiments' fixtures)."""
    tracked = C.tracked_files(S.REPO_ROOT, ".")
    out = []
    for r in tracked:
        parts = r.split("/")
        if "tests" in parts or parts[0] in {"spec-flow", ".spec-flow", "experiments"}:
            continue
        if S.under(r, "defender/bin") or r == "defender/run_common.py" \
                or S.under(r, ".github/workflows") or r.endswith(".md"):
            out.append(r)
    return out


def _invocations() -> list[tuple[str, int, str]]:
    """(caller, line, invoked target) — a target is a repo path or a dotted module name."""
    out = []
    for r in _caller_files():
        text = (S.REPO_ROOT / r).read_text(encoding="utf-8", errors="replace")
        for i, line in _invocation_lines(text):
            out += [(r, i, "defender/" + m) for m in _PATH_CALL.findall(line)]
            out += [(r, i, m) for m in _MODULE_CALL.findall(line)]
    return out


def _lint_log_setup():
    lint_dir = str(S.REPO_ROOT / "scripts" / "lint")
    sys.path.insert(0, lint_dir)
    try:
        import lint_log_setup as mod
    finally:
        if lint_dir in sys.path:
            sys.path.remove(lint_dir)
    return mod


#: s016 under the 2026-10-04 cut: the OUT modules whose `__main__` blocks no listed caller runs
#: stay in `scripts/` with their modules (M-D (a)'s drops of them are parked with #1105), named.
OUT_MAIN_BLOCKS = (
    "defender/scripts/visualize/_mirror_write.py",
    "defender/scripts/visualize/visualize_episode.py",
    "defender/scripts/visualize/visualize_run.py",
    "defender/scripts/workspace_map.py",
)


@pytest.mark.gate
def test_wrapper_and_engine_each_may_carry_a_main_block():
    """Every `__main__` block that survives under scripts/ has a non-test caller (a bin shim,
    run_common, CI, docs), except the named OUT modules' blocks, which stay in scripts/ with
    their modules under the 2026-10-04 cut (`visualize/_mirror_write.py`,
    `visualize/visualize_episode.py`, `visualize/visualize_run.py`, `workspace_map.py`; their
    drops are parked with #1105). Each surviving block configures logging
    or carries the logging-setup marker, so the logging-setup gate stays green. The wrapper set
    passes the repository-wide gates (logging setup, python duplication, dead code, import
    order) without exemption and without growing a baseline; the engine keeps a main only if
    the wrapper calls it.

    Observed: each tracked `scripts/` module with a `__main__` guard is invoked by path or `-m`
    from a shim, `run_common`, a CI workflow or a tracked doc; the real logging-setup lint's
    scan reports no `scripts/` file; no lint baseline names a wrapper and no wrapper carries an
    inline exemption other than the logging-setup marker; an engine that defines `main` is
    called through it by its wrapper; each named OUT module still carries its block. Positive
    control: the invocation finder sees CI's `box_image.py` call.
    """
    calls = _invocations()
    invoked = {t for _, _, t in calls}
    assert "defender/scripts/box_image.py" in invoked
    holders = [r for r in C.tracked_files(S.REPO_ROOT, "defender/scripts")
               if r.endswith(".py") and S.has_main_block((S.REPO_ROOT / r).read_bytes())]
    assert [r for r in OUT_MAIN_BLOCKS if r not in holders] == []
    uncalled = [r for r in holders if r not in invoked and S.dotted(r) not in invoked
                and r not in OUT_MAIN_BLOCKS]
    assert uncalled == [], "__main__ blocks under scripts/ that no non-test caller runs"
    log_findings = [f.display for f in _lint_log_setup()._scan()
                    if f.fingerprint.startswith("defender/scripts/")]
    assert log_findings == []
    baselines = sorted((S.REPO_ROOT / "scripts" / "lint").glob("*_baseline.json"))
    for w in C.wrappers():
        assert [b.name for b in baselines if w in b.read_text(encoding="utf-8")] == []
        text = (S.REPO_ROOT / w).read_text(encoding="utf-8")
        marks = [ln for ln in text.splitlines()
                 if ("noqa" in ln or "lint-" in ln) and "lint-log-setup: ok" not in ln]
        assert marks == [], f"{w} carries inline exemptions: {marks}"
    for shim, anchor in ENGINE_OF_SHIM.items():
        engine = S.home_of(anchor)
        if "main" in S.module_level_names((S.REPO_ROOT / engine).read_bytes()):
            w = C.shim_target(S.REPO_ROOT, shim)
            assert _engine_main_is_called((S.REPO_ROOT / w).read_text(encoding="utf-8"), engine)


def test_a_test_or_child_process_loads_a_moved_module_by_its_old_file_path():
    """A test that loads a moved module by its old file path or spawns a moved program by that
    path fails with a clear missing-file error once the file is gone; none passes on a stale
    compiled copy (an orphan __pycache__ is not importable without its source). O5's suites are
    repointed (fixtures may change, assertions do not), by-path loaders and child spawns going
    to the wrapper or the engine's new path.

    Observed: no test file outside this suite holds a string literal (docstrings aside) naming
    a moved module's old path; each old path is absent, so a path load raises the missing-file
    error naming it (scripts_path_load_of_a_moved_file_errors_and_serves_no_stale_copy drives
    the loads, spawns and the orphan cache).
    """
    old = [f.split("defender/", 1)[1] for f in _moved_old_py()]
    assert [f for f in _moved_old_py() if (S.REPO_ROOT / f).exists()] == []
    suite = S.rel(S.SUITE)
    stale = []
    for r in C.tracked_files(S.REPO_ROOT, "defender/tests"):
        if not r.endswith(".py") or S.under(r, suite):
            continue
        src = (S.REPO_ROOT / r).read_text(encoding="utf-8")
        tree = ast.parse(src, filename=r)
        docs = {id(s.value) for s in ast.walk(tree)
                if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)}
        lines = src.splitlines()
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs \
                    and "lint-stale-ref: ok" not in lines[n.lineno - 1]:
                stale += [f"{r}:{n.lineno}: {p}" for p in old if p in n.value]
    assert stale == [], "tests still reach a moved module by its old file path"


def test_old_directory_survives_holding_only_compiled_caches_or_assets(tmp_path):
    """An old scripts subfolder left in a working tree holding only caches, assets or nothing
    has no package initialiser, so the old dotted name would import as an empty namespace
    package; the placement check and the O1 census give the same verdict in that tree and in a
    fresh clone: no module remains there, an outside importer of the old name is a hit, and the
    empty folder is not treated as holding an entry point or a module.

    Observed: a committed tmp copy with an outside importer of an old subfolder's name planted
    (and committed), then given an untracked leftover subfolder (a compiled cache, an asset, an
    empty directory) — its placement and census verdicts equal a fresh clone's; the clone's
    placement verdict is empty (no module remains under scripts/) and the importer is a hit in
    both.
    """
    work = C.tree_copy(tmp_path / "work")
    line = C.plant(work, "defender/runtime/verbs.py",
                   "from defender.scripts.visualize import visualize_run\n")
    _git.git(["-c", "user.name=spec1080", "-c", "user.email=spec1080@example.invalid",
              "commit", "-q", "--no-verify", "-m", "copy"], cwd=work)
    clone = tmp_path / "clone"
    _git.git(["clone", "-q", str(work), str(clone)], cwd=tmp_path)
    left = work / "defender" / "scripts" / "visualize"
    (left / "__pycache__").mkdir(parents=True, exist_ok=True)
    (left / "__pycache__" / "visualize_run.cpython-311.pyc").write_bytes(b"\x00" * 16)
    (left / "assets").mkdir(exist_ok=True)
    (left / "assets" / "leftover.css").write_text("body{}\n", encoding="utf-8")
    (work / "defender" / "scripts" / "emptied").mkdir(exist_ok=True)
    assert C.placement_findings(work) == C.placement_findings(clone) == []
    edges = (_rel_edges(C.census(work)), _rel_edges(C.census(clone)))
    assert edges[0] == edges[1]
    hit = ("defender/runtime/verbs.py", line)
    assert any(e[:2] == hit and e[2].startswith("defender.scripts.visualize") for e in edges[1])


def test_old_dotted_name_that_still_resolves_because_another_checkout_with_the_old_layout_is_importable(
        tmp_path):
    """A leftover import of a vanished defender.scripts module is found by the census (an AST
    check that does not depend on resolution) and by CI's clean checkout, even where a second
    checkout with the old layout makes the name resolve locally; a local green run proves
    nothing about it, and the suite must not rely on resolution to detect it.

    Observed: a child whose path holds this checkout and then a foreign checkout with the old
    layout; the vanished name resolves there (through the `defender` namespace), and the census
    run in that same child over a copy holding the leftover import reports it — as does the
    census over a fresh clone of the copy.
    """
    foreign = tmp_path / "foreign"
    (foreign / "defender" / "scripts").mkdir(parents=True)
    (foreign / "defender" / "scripts" / "vanished_1080.py").write_text("X = 1\n", "utf-8")
    copy = C.tree_copy(tmp_path / "copy")
    line = C.plant(copy, "defender/runtime/verbs.py",
                   "from defender.scripts.vanished_1080 import X\n")
    _git.git(["-c", "user.name=spec1080", "-c", "user.email=spec1080@example.invalid",
              "commit", "-q", "--no-verify", "-m", "copy"], cwd=copy)
    body = ("import importlib.util, json, sys\n"
            "from pathlib import Path\n"
            "from defender.tests.scripts_1080_split import _census1080 as C\n"
            "resolves = importlib.util.find_spec('defender.scripts.vanished_1080') is not None\n"
            "edges = [[e.importer, e.line, e.target] for e in C.census(Path(sys.argv[1]))]\n"
            "print(json.dumps({'resolves': resolves, 'edges': edges}))\n")
    env = S.child_env(pythonpath=False, PYTHONPATH=f"{S.REPO_ROOT}{os.pathsep}{foreign}")
    cp = S.python("-c", body, str(copy), env=env)
    assert cp.returncode == 0, cp.stderr.decode()
    out = json.loads(cp.stdout)
    assert out["resolves"] is True
    leftover = ["defender/runtime/verbs.py", line, "defender.scripts.vanished_1080"]
    assert leftover in out["edges"]
    clone = tmp_path / "clone"
    _git.git(["clone", "-q", str(copy), str(clone)], cwd=tmp_path)
    assert tuple(leftover) in _rel_edges(C.census(clone))


def test_new_home_directory_with_no_package_marker_among_packages_that_have_one(tmp_path):
    """A moved module's directory is seen by the census and the placement test whether or not
    it has an __init__.py (they find modules by walking files or resolving imports, not by
    package markers): the new directory choice cannot make a module invisible to either. (The
    direction-test half is parked with the O2 test, #1105 / #1172, by the 2026-10-04 cut.)

    Observed: in a tmp git copy, two directories with no `__init__.py` — a runtime one holding
    an import of scripts (census hit) and a scripts one holding a stray module (placement
    finding).
    """
    root = C.tree_copy(tmp_path / "copy")
    a = C.plant(root, "defender/runtime/nomark_a/m.py", PLANT_IMPORT)
    C.plant(root, "defender/scripts/nomark_d/stray.py", "X = 1\n")
    for d in ("runtime/nomark_a", "scripts/nomark_d"):
        assert not (root / "defender" / d / "__init__.py").exists()
    assert ("defender/runtime/nomark_a/m.py", a, "defender.scripts.policy_cli") in _rel_edges(
        C.census(root))
    assert "defender/scripts/nomark_d/stray.py" in C.placement_findings(root)


def test_placement_and_direction_checks_run_in_the_environment_of_the_job_that_runs_them():
    """The placement, census and lint checks are static (AST or file reads): none imports a
    moved module to find where it is defined, so each runs in the dev-only code-smells job. A
    lint that already reaches platform code (shippable-surface via declared_systems, the
    disposition census via the verb roster) keeps its import chain inside what that job
    installs after the moves. (The direction-test half is parked with the O2 test by the
    2026-10-04 cut.)

    Observed: (1) a child runs the census, the placement check and the anchor scan, then
    reports which `defender.*` modules it loaded — no scripts module, no integrations or reports
    module; (2) a child that refuses every package the dev-only job does not install imports
    both lints and resolves the shippable-surface exclusions.
    """
    body = ("import json, sys\n"
            "from defender.tests.scripts_1080_split import _census1080 as C\n"
            "C.census(); C.placement_findings()\n"
            "C.file_depth_anchors(open(C.S.SCRIPTS / 'tenant.py').read())\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('defender.'))))\n")
    cp = S.python("-c", body)
    assert cp.returncode == 0, cp.stderr.decode()
    loaded = json.loads(cp.stdout)
    assert [m for m in loaded if m.startswith(("defender.scripts", "defender.integrations",
                                               "defender.reports"))] == []
    lint_dir = str(S.REPO_ROOT / "scripts" / "lint")
    lints = (f"import sys\nsys.path.insert(0, {lint_dir!r})\n"
             "from pathlib import Path\n"
             "import lint_shippable_surface as L\n"
             f"print(len(L.excluded_prefixes(Path({str(S.REPO_ROOT)!r}))))\n"
             "import lint_verb_disposition_census\n")
    cp = _import_blocker.run_blocked(lints, block=NOT_IN_DEV_JOB, cwd=S.REPO_ROOT,
                                     env=S.child_env())
    assert cp.returncode == 0, cp.stderr.decode()


_ALIASES = textwrap.dedent('''\
    import defender.scripts.pricing as p
    from defender.scripts.workspace_map import *
    from defender.scripts.visualize import visualize_run, visualize_episode as ve
    from defender.scripts.tenant import main as m1, main as m2
''')


def test_import_aliased_or_wildcard():
    """An import of a scripts module under an alias, with a trailing wildcard or as one of
    several names on one line is a census hit: aliasing and multiplicity do not hide it, and a
    wildcard from a scripts module is flagged.

    Observed: a planted module with each form; every target is reported on its line.
    """
    rel = "defender/runtime/_spec1080_alias.py"
    got = [(e.line, e.target) for e in C.census(overlay={rel: _ALIASES}) if e.importer == rel]
    assert {line for line, _ in got} == {1, 2, 3, 4}
    expected = {1: "defender.scripts.pricing", 2: "defender.scripts.workspace_map",
                3: "defender.scripts.visualize", 4: "defender.scripts.tenant"}
    assert all(t.startswith(expected[line]) for line, t in got), got


def test_relative_import_that_climbs_into_scripts():
    """A relative import of two or more dots that reaches a scripts module from another
    defender package is a census hit: relative forms are resolved to the target module before
    the check (as in the K1 census).

    Observed: planted relative imports of two and three dots from runtime packages, and of
    the bare package; each is reported as the absolute scripts target.
    """
    overlay = {
        "defender/runtime/_spec1080_rel.py": "from ..scripts.pricing import usage_cost\n",
        "defender/runtime/branch/_spec1080_rel.py": "from ...scripts import pricing\n",
        "defender/learning/_spec1080_rel.py": "from .. import scripts\n",
    }
    got = {(e.importer, e.target) for e in C.census(overlay=overlay) if e.importer in overlay}
    assert {i for i, _ in got} == set(overlay)
    assert ("defender/runtime/_spec1080_rel.py", "defender.scripts.pricing") in got
    assert ("defender/learning/_spec1080_rel.py", "defender.scripts") in got
    # `from ...scripts import pricing` names the module when it exists, else the package
    branch = {t for i, t in got if i == "defender/runtime/branch/_spec1080_rel.py"}
    assert branch <= {"defender.scripts.pricing", "defender.scripts"}, branch


_STRINGS = textwrap.dedent('''\
    """Moved out of defender.scripts.pricing (see defender/scripts/pricing.py)."""
    import logging
    # formerly: from defender.scripts.pricing import usage_cost
    LOG = logging.getLogger(__name__)
    REMEDY = "run python3 defender/scripts/tenant.py setup"
    TABLE = {"old": "defender.scripts.workspace_map"}
    def f():
        LOG.warning("defender.scripts.visualize.visualize_run is gone")
''')


def test_module_named_only_in_a_string_a_comment_or_a_docstring():
    """A module outside scripts/ that spells a scripts path only in a docstring, comment, log
    message, remedy string or data constant, and imports nothing from it, is not an
    import-census hit (no import statement). Its stale path text is the pointer gate's concern
    (A43), not O1's.

    Observed: a planted module spelling scripts paths in each of those places is not reported;
    the same module with one real import added is (positive control).
    """
    rel = "defender/runtime/_spec1080_strings.py"
    assert [e for e in C.census(overlay={rel: _STRINGS}) if e.importer == rel] == []
    with_import = _STRINGS + "from defender.scripts.pricing import usage_cost\n"
    assert [(e.line, e.target) for e in C.census(overlay={rel: with_import})
            if e.importer == rel] == [(9, "defender.scripts.pricing")]


def test_scripts_path_exec_from_shell_ci_and_docs(tmp_path):
    """A bin/ shim, a CI step or a markdown file that invokes a scripts file by path or `-m`,
    with no Python file importing it, is not an O1 hit: those callers are legitimate and are
    exactly why a wrapper stays; the path or module they name keeps working after the move
    (F40).

    Observed: every invocation by path or `-m` in the shims, `run_common`, CI workflows and
    tracked docs that named a live file at the base still names a file that exists (a pin
    already dead at the base, such as a doc's `wazuh_adapter.py`, is s110's, not this demand's);
    and a tmp copy given a planted shell
    script, CI step, markdown invocation and a by-path spawn in Python reports the same census
    as before.
    """
    base = set(S.base_inventory()["files"])
    calls = [(caller, line, target, target if target.endswith(".py")
              else target.replace(".", "/") + ".py") for caller, line, target in _invocations()]
    live_at_base = [c for c in calls if c[3] in base]
    assert live_at_base, "the invocation finder found no live invocation (blind)"
    missing = [f"{caller}:{line}: {target}" for caller, line, target, path in live_at_base
               if not (S.REPO_ROOT / path).is_file()]
    assert missing == [], "invocations that name a file or module that no longer exists"
    root = C.tree_copy(tmp_path / "copy")
    before = _rel_edges(C.census(root))
    C.plant(root, "defender/bin/spec1080-probe",
            '#!/bin/sh\nexec "$PY" "${DEFENDER}/scripts/tenant.py" "$@"\n')
    C.plant(root, ".github/workflows/spec1080.yml",
            "      - run: defender/.venv/bin/python -m defender.scripts.tacit_cli check\n")
    C.plant(root, "defender/docs/spec1080.md", "python3 defender/scripts/box_image.py build\n")
    C.plant(root, "defender/runtime/_spec1080_spawn.py",
            "import subprocess, sys\n"
            "subprocess.run([sys.executable, 'defender/scripts/tenant.py', 'check'])\n")
    assert _rel_edges(C.census(root)) == before


_JUNK = ("defender/.venv/lib/m.py", "defender/runtime/__pycache__/m.py",
         "defender/node_modules/pkg/m.py", "defender/build/m.py", "defender/dist/m.py",
         "defender/.mypy_cache/m.py", "scripts/.ruff_cache/m.py", "defender/site-packages/m.py")


def test_python_files_in_caches_vendored_trees_and_build_output(tmp_path):
    """The census scans the source of the checkout's defender/ and the repo's scripts/ and
    ignores virtualenvs, __pycache__, node_modules, build or dist output and tool caches: files
    there that spell `scripts` produce no hits and cannot flip the verdict.

    Observed: a tmp git copy where each junk location holds a module importing a scripts
    module — once untracked, once force-added to the index — reports the same census as the
    clean copy. Positive control: the same module in a source directory is a hit.
    """
    root = C.tree_copy(tmp_path / "copy")
    clean = _rel_edges(C.census(root))
    for i, rel in enumerate(_JUNK):
        C.plant(root, rel, PLANT_IMPORT, add=bool(i % 2))
    assert _rel_edges(C.census(root)) == clean
    for rel in _JUNK:
        _git.git(["add", "-f", "--", rel], cwd=root)
    assert _rel_edges(C.census(root)) == clean
    line = C.plant(root, "defender/runtime/_spec1080_src.py", PLANT_IMPORT)
    assert ("defender/runtime/_spec1080_src.py", line, "defender.scripts.policy_cli") in \
        _rel_edges(C.census(root))


_OTHER_SCRIPTS = textwrap.dedent('''\
    from scripts.lint import _astlib
    import scripts.testing.helpers
    from scripts.lint._baseline import gate
    import mypkg.scripts.thing
    from defender.scriptsx import y
    from defender.learning.scripts import z
''')


def test_the_other_scripts_package():
    """The repo's top-level `scripts/` (lint, testing, analytics) importing `from
    scripts.lint…` is not an import of defender/scripts: only modules under defender/scripts/
    are targets of O1. The repo's scripts/ is an importer scope (O1 scans it), not a target,
    and a dotted path merely containing the word scripts is not a hit.

    Observed: a planted module under the repo's `scripts/` importing the repo's own scripts
    package and look-alike dotted paths is not reported; the same module with a real
    `defender.scripts` import is (the repo's scripts/ is scanned).
    """
    rel = "scripts/lint/_spec1080_other.py"
    assert [e for e in C.census(overlay={rel: _OTHER_SCRIPTS}) if e.importer == rel] == []
    real = _OTHER_SCRIPTS + "from defender.scripts.tenant import main\n"
    assert [(e.line, e.target) for e in C.census(overlay={rel: real})
            if e.importer == rel] == [(7, "defender.scripts.tenant")]


def test_importer_inside_scripts_of_a_moved_module():
    """A staying wrapper under defender/scripts/ importing its engine from the new home, and a
    staying scripts file importing another scripts file, are not O1 hits: the census flags
    importers outside scripts/ of modules under it. Inside-scripts edges are free.

    Observed: a staying command importing another staying command and an adapter importing the
    stub transport and the integrations faults, planted inside `scripts/`, are not reported; the
    same line in a runtime module is (positive control).
    """
    overlay = {
        **_overlay_with("defender/scripts/tenant.py", PLANT_IMPORT),
        **_overlay_with("defender/scripts/adapters/cmdb_adapter.py",
                        "from defender.scripts.adapters import _stub_transport\n"
                        "from defender.integrations import faults\n"),
    }
    assert [e for e in C.census(overlay=overlay) if S.under(e.importer, "defender/scripts")] == []
    outside = _overlay_with("defender/runtime/verbs.py", PLANT_IMPORT)
    assert any(e.importer == "defender/runtime/verbs.py" for e in C.census(overlay=outside))


def test_1080_a_path_load_or_spawn_of_a_moved_scripts_file_errors_with_a_missing_file_message(
        tmp_path):
    """A path load (`spec_from_file_location`), a spawn by path or a `-m` run of a file that
    moved out of `defender/scripts/` fails with a missing-file error that names the old path,
    and no orphan compiled copy answers in its place. The registry's path load of the adapters
    that stay under `scripts/adapters/` still succeeds. The import census counts import
    statements only, so a path load is not a census hit (H1 (a)); this is the fail-loud half the
    census does not give the lane.

    Observed: each moved file is absent and a path load of it raises `FileNotFoundError` naming
    it; a spawn by path and by `-m` of the moved `lessons_frontier` exits nonzero naming the
    path or module (the 2026-10-04 cut keeps `visualize_run` and `workspace_map` in place, so
    their two spawns are parked with #1105); an orphan
    `__pycache__` copy of a module whose source is gone is not importable in a child; the
    registry's own loader runs every staying adapter and reads the base roster's verbs (golden).
    """
    old = _moved_old_py()
    assert [f for f in old if (S.REPO_ROOT / f).exists()] == [], "moved files are still there"
    for f in old:
        spec = importlib.util.spec_from_file_location(f"_spec1080_old_{Path(f).stem}",
                                                      S.REPO_ROOT / f)
        assert spec is not None
        assert spec.loader is not None
        with pytest.raises(FileNotFoundError, match=re.escape(str(S.REPO_ROOT / f))):
            spec.loader.exec_module(importlib.util.module_from_spec(spec))
    for f in ("defender/scripts/lessons/lessons_frontier.py",):
        by_path = S.python(f)
        assert by_path.returncode != 0
        assert f in by_path.stderr.decode(), by_path.stderr
        by_mod = S.python("-m", S.dotted(f))
        assert by_mod.returncode != 0
        assert S.dotted(f) in by_mod.stderr.decode(), by_mod.stderr
    _orphan_cache_is_not_importable(tmp_path)
    from defender._paths import PATHS
    from defender.runtime import verbs

    roster = verbs.read_roster(PATHS.adapters_dir)
    got = {s: sorted(verbs._load_adapter_module(p).VERBS) for s, p in sorted(roster.accepted.items())}
    assert got == S.golden("core")["roster_verbs"]


def _orphan_cache_is_not_importable(tmp_path: Path) -> None:
    pkg = tmp_path / "orphan" / "defender" / "scripts" / "gone_1080"
    pkg.mkdir(parents=True)
    src = pkg / "mod.py"
    src.write_text("X = 1\n", encoding="utf-8")
    import py_compile

    py_compile.compile(str(src), cfile=str(pkg / "__pycache__" / f"mod.{sys.implementation.cache_tag}.pyc"))
    src.unlink()
    body = ("import importlib, sys\n"
            "try:\n"
            "    importlib.import_module('defender.scripts.gone_1080.mod')\n"
            "except ModuleNotFoundError as e:\n"
            "    print('missing', e)\n"
            "else:\n"
            "    print('imported')\n")
    env = S.child_env(pythonpath=False,
                      PYTHONPATH=f"{tmp_path / 'orphan'}{os.pathsep}{S.REPO_ROOT}")
    cp = S.python("-c", body, env=env, cwd=tmp_path)
    assert cp.returncode == 0, cp.stderr.decode()
    assert cp.stdout.decode().startswith("missing"), cp.stdout
