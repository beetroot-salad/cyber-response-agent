from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import sys
import textwrap
from pathlib import Path

import pytest

from defender import _git
from defender.tests.support.shared.contracts import _import_blocker
from defender.tests.tooling.layout_contracts import _census1080 as C
from defender.tests.tooling.layout_contracts import _spec1080 as S


INVESTIGATION = ("passthrough_max_bytes", "_load_payload", "_arrow_refusal")
#: The flat tier (`defender/_*.py`): the query-id and request-key rules under their BASE names
#: (`S.QUERY_RULE_PUBLIC` is the identity map since the cut) and the venv helper.
FLAT_TIER_RULES = (
    *S.QUERY_RULE_PUBLIC.values(), "is_reserved_query_id", "ABOVE_GUARD_QUERY_ID",
    "BASH_SHIM_QUERY_ID", "DENIED_QUERY_ID", "REPEAT_TRIP_QUERY_ID", "_QID_FORBIDDEN",
    "reexec_into_venv", "usage_cost",
)
#: The lessons engine: outside `scripts/` and outside the content folder `defender/lessons/`.
LESSONS_ENGINE = (
    "cmd_grep", "cmd_tags", "cmd_show", "match_lessons", "match_loaded", "Hit",
    "WRITE_RETURN_LEAD", "FOLD_LEAD", "resolve_corpus", "as_list", "csv_set",
)

MODULE_ANCHORS = {
    "defender/runtime/payload_view.py": "passthrough_max_bytes",
    "defender/runtime/sql.py": "_load_payload",
    "defender/scripts/pricing.py": "usage_cost",
    "defender/scripts/_venv.py": "reexec_into_venv",
    "defender/scripts/lessons/lessons_fm.py": "cmd_tags",
    "defender/scripts/lessons/lessons_frontier.py": "match_lessons",
    "defender/scripts/lessons/_lessons_common.py": "resolve_corpus",
    "defender/integrations/case_ticket.py": "load_case_mapping",
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


def test_1080_scripts_holds_only_entry_points():
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
    _check_group(INVESTIGATION, S.RUNTIME, _not_tools_or_branch)
    _check_group(tuple(n for n in FLAT_TIER_RULES if n not in {"reexec_into_venv", "usage_cost"}), S.QUERY_RULES)
    _check_group(("reexec_into_venv",), S.VENV)
    _check_group(("usage_cost",), S.PRICING)
    _check_group(LESSONS_ENGINE, None, _outside_lessons_content)


def test_1080_no_module_outside_scripts_imports_a_module_under_it():
    violations = C.o1_violations()
    assert _rel_edges(violations) == [], "imports of defender.scripts.* from outside it"
    assert C.stale_o1_exceptions() == []
    planted = "defender/runtime/verbs.py"
    overlay = _overlay_with(planted, PLANT_IMPORT)
    line = _line_of(overlay[planted], PLANT_IMPORT.strip())
    assert (planted, line, "defender.scripts.policy_cli") in _rel_edges(
        C.o1_violations(overlay=overlay))


def test_1080_the_import_census_flags_a_planted_edge_and_exempts_tests(tmp_path):
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
    # Every formerly exempt library now has an owner outside scripts; none needs an allowance.
    assert C.o1_exceptions() == ()
    assert C.stale_o1_exceptions() == []
    example = "defender/skills/connect/examples/example_adapter.py"
    fourth = {**_overlay_with("defender/runtime/verbs.py",
                              "from defender.scripts.adapters import _stub_transport\n"),
              **_overlay_with(example, "from defender.scripts.adapters.cmdb_adapter import VERBS\n")}
    reported = {(e.importer, e.target) for e in C.o1_violations(overlay=fourth)}
    assert ("defender/runtime/verbs.py", "defender.scripts.adapters") in reported
    assert (example, "defender.scripts.adapters.cmdb_adapter") in reported
    assert C.tracked_files(S.REPO_ROOT, C.ADAPTERS) == sorted(C.adapters_expected())


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


def test_1080_each_wrapper_left_in_scripts_only_delegates_to_its_engine():
    leftover = [r for r in C.tracked_files(S.REPO_ROOT, "defender/scripts")
                if r.endswith(".py") and r not in C.STAYING_COMMANDS
                and not S.under(r, C.ADAPTERS) and r not in C.OUT_STAYING]
    assert leftover == [], f"wrappers left in scripts/: {leftover}"
    assert C.wrappers() == ()
    for shim, anchor in ENGINE_OF_SHIM.items():
        text = (S.BIN / shim).read_text(encoding="utf-8")
        exec_line = next(ln for ln in text.splitlines() if "exec " in ln and " -m " in ln)
        assert ' -P -m ' in exec_line, f"bin/{shim} does not keep the cwd off sys.path: {exec_line}"
        engine = S.home_of(anchor)
        assert S.shim_exec_module(shim) == S.dotted(engine), (shim, exec_line, engine)
        path_line = next(ln for ln in text.splitlines() if "PYTHONPATH=" in ln)
        assert re.search(r'PYTHONPATH="\$ROOT\$\{PYTHONPATH:\+:\$PYTHONPATH\}"',
                         path_line), f"bin/{shim} does not put its own root first: {path_line}"
        engine_src = (S.REPO_ROOT / engine).read_text(encoding="utf-8")
        assert _sys_path_mutations(ast.parse(engine_src)) == [], \
            f"the engine {engine} carries a bootstrap"
        assert _command_guard(engine_src) is not None, f"{engine} has no `__main__` guard"


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
    assert _command_guard(S.IMAGE_CLI.read_bytes())
    assert not _command_guard((S.DEFENDER / "integrations" / "faults.py").read_bytes())
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


def test_1080_no_python_module_lands_in_the_lesson_content_folder():
    on_disk = [p for p in S.LESSONS_CONTENT.rglob("*")
               if p.is_file() and not set(p.relative_to(S.REPO_ROOT).parts) & S.JUNK_DIRS]
    assert [S.rel(p) for p in on_disk if p.suffix == ".py"] == []
    assert any(p.suffix == ".md" for p in on_disk), "the lesson .md files are gone"
    for anchor in ("cmd_tags", "match_lessons"):
        engine = S.home_of(anchor)
        assert not S.under(engine, "defender/lessons")
        assert not S.under(engine, "defender/scripts"), f"the lessons engine is still {engine}"


def test_1080_every_flat_tier_module_at_the_base_keeps_its_name():
    base = S.base_inventory()["flat_tier"]
    assert len(base) == 30
    # Owner ruling (merge with #1105 PR 1): the run layout and the run handle moved into
    # defender/run_repository/ (#1105 D1.1), which retired these two; the rest keep their paths.
    moved_by_1105 = {f"defender/_run_{kind}.py" for kind in ("paths", "handle")}
    assert moved_by_1105 <= set(base)
    assert [f for f in base if f not in moved_by_1105 and not (S.REPO_ROOT / S.current_path(f)).is_file()] == []


def test_1080_no_moved_module_derives_a_path_from_its_own_file_depth():
    planted = textwrap.dedent('''\
        from pathlib import Path
        ASSETS = Path(__file__).parent / "assets"
        ROOT = Path(__file__).resolve().parents[2]
        UP = Path(__file__).parent.parent
    ''')
    assert C.file_depth_anchors(planted) == [3, 4]
    anchors = [*MODULE_ANCHORS.values(), *RECORD_QUERY_ANCHORS]
    homes = sorted({S.home_of(a) for a in anchors})
    found = {h: C.file_depth_anchors((S.REPO_ROOT / h).read_bytes(), h) for h in homes if h != S.VENV}
    # The venv bootstrap owns its checkout root; its dedicated subprocess tests pin that root.
    assert {h: lines for h, lines in found.items() if lines} == {}
    assert not any(S.under(h, "defender/scripts") for h in homes)


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
    assert _rel_edges(C.o1_violations()) == []
    rel = "defender/runtime/_spec1080_rare.py"
    got = {(e.line, e.target) for e in C.census(overlay={rel: _RARE}) if e.importer == rel}
    assert got == {(4, "defender.scripts.pricing"), (6, "defender.scripts.workspace_map"),
                   (9, "defender.scripts.tenant"), (13, "defender.scripts.tacit_cli"),
                   (14, "defender.scripts.box_image")}


def _pointer_verdict(root: Path):
    from defender.tests.tooling.layout_contracts import _pointers1080 as P

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


ALLOWED_DROPS = {"defender/scripts/lessons/lessons_frontier.py": {"REPO_ROOT"}}
#: Remainder names a later issue deleted outright, so they are defined nowhere: #1235 moved the
#: per-lead row read onto the run's `RunState.lead_rows`, and the file reader `lead_rows` left.
RETIRED_REMAINDER = {"defender/scripts/gather_tools/record_query.py": {"lead_rows"}}
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
    out: set[str] = {S.current_path(base_path)} if base_path == RECORD_QUERY else set()
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
            if n in RETIRED_REMAINDER.get(base_path, set()):
                if new or S.current_path(base_path) in S.definitions(n):
                    problems.append(f"{base_path}::{n} was retired but is still defined -> {new}")
                continue
            if new != [S.current_path(base_path)]:
                problems.append(f"{base_path}::{n} must stay in {base_path} -> {new or 'gone'}")
            continue
        if len(new) > 1 or (not new and n not in drops):
            problems.append(f"{base_path}::{n} -> {new or 'dropped'}")
        if (S.REPO_ROOT / base_path).exists() and S.current_path(base_path) in S.definitions(n):
            problems.append(f"{base_path}::{n} is still defined at its old path")
    return problems


def test_a_name_in_a_split_module_that_no_placement_row_claims():
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


_PATH_CALL = re.compile(r"(?:defender/|\}/)((?:cli|box|presentation)/[\w./-]+?\.py)\b")
_MODULE_CALL = re.compile(r"-m\s+(defender\.(?:cli|box|presentation)(?:\.\w+)+)")


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
    lint_dir = str(S.REPO_ROOT / "tooling" / "lint")
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
    "defender/presentation/_mirror_write.py",
    "defender/presentation/visualize_episode.py",
    "defender/presentation/visualize_run.py",
    "defender/cli/workspace_map.py",
)


@pytest.mark.gate
def test_wrapper_and_engine_each_may_carry_a_main_block():
    calls = _invocations()
    invoked = {t for _, _, t in calls}
    assert "defender/box/image_cli.py" in invoked
    holders = [r for r in C.tracked_files(S.REPO_ROOT, "defender/cli", "defender/presentation", "defender/box/image_cli.py")
               if r.endswith(".py") and S.has_main_block((S.REPO_ROOT / r).read_bytes())]
    assert [r for r in OUT_MAIN_BLOCKS if r not in holders] == []
    uncalled = [r for r in holders if r not in invoked and S.dotted(r) not in invoked
                and r not in OUT_MAIN_BLOCKS]
    assert uncalled == [], "__main__ blocks under scripts/ that no non-test caller runs"
    log_findings = [f.display for f in _lint_log_setup()._scan()
                    if f.fingerprint.startswith("defender/scripts/")]
    assert log_findings == []
    baselines = sorted((S.REPO_ROOT / "tooling" / "lint").glob("*_baseline.json"))
    for w in C.wrappers():
        assert [b.name for b in baselines if w in b.read_text(encoding="utf-8")] == []
        text = (S.REPO_ROOT / w).read_text(encoding="utf-8")
        marks = [ln for ln in text.splitlines()
                 if ("noqa" in ln or "lint-" in ln) and "lint-log-setup: ok" not in ln]
        assert marks == [], f"{w} carries inline exemptions: {marks}"
    for shim, anchor in ENGINE_OF_SHIM.items():
        engine = S.home_of(anchor)
        if "main" in S.module_level_names((S.REPO_ROOT / engine).read_bytes()):
            # The shim runs the engine as a module, so the engine's own guard calls its `main`.
            assert S.shim_exec_module(shim) == S.dotted(engine), (shim, engine)
            assert _command_guard((S.REPO_ROOT / engine).read_bytes()) is not None, engine


def test_a_test_or_child_process_loads_a_moved_module_by_its_old_file_path():
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
    (work / "defender" / "scripts" / "emptied").mkdir(parents=True, exist_ok=True)
    assert C.placement_findings(work) == C.placement_findings(clone) == []
    edges = (_rel_edges(C.census(work)), _rel_edges(C.census(clone)))
    assert edges[0] == edges[1]
    hit = ("defender/runtime/verbs.py", line)
    assert any(e[:2] == hit and e[2].startswith("defender.scripts.visualize") for e in edges[1])


def test_old_dotted_name_that_still_resolves_because_another_checkout_with_the_old_layout_is_importable(
        tmp_path):
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
            "from defender.tests.tooling.layout_contracts import _census1080 as C\n"
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
    root = C.tree_copy(tmp_path / "copy")
    a = C.plant(root, "defender/runtime/nomark_a/m.py", PLANT_IMPORT)
    C.plant(root, "defender/scripts/nomark_d/stray.py", "X = 1\n")
    for d in ("runtime/nomark_a", "scripts/nomark_d"):
        assert not (root / "defender" / d / "__init__.py").exists()
    assert ("defender/runtime/nomark_a/m.py", a, "defender.scripts.policy_cli") in _rel_edges(
        C.census(root))
    assert "defender/scripts/nomark_d/stray.py" in C.placement_findings(root)


def test_placement_and_direction_checks_run_in_the_environment_of_the_job_that_runs_them():
    body = ("import json, sys\n"
            "from defender.tests.tooling.layout_contracts import _census1080 as C\n"
            "C.census(); C.placement_findings()\n"
            "C.file_depth_anchors(open(C.S.CLI / 'tenant.py').read())\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('defender.'))))\n")
    cp = S.python("-c", body)
    assert cp.returncode == 0, cp.stderr.decode()
    loaded = json.loads(cp.stdout)
    assert [m for m in loaded if m.startswith(("defender.scripts", "defender.integrations",
                                               "defender.reports"))] == []
    lint_dir = str(S.REPO_ROOT / "tooling" / "lint")
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
    rel = "defender/runtime/_spec1080_alias.py"
    got = [(e.line, e.target) for e in C.census(overlay={rel: _ALIASES}) if e.importer == rel]
    assert {line for line, _ in got} == {1, 2, 3, 4}
    expected = {1: "defender.scripts.pricing", 2: "defender.scripts.workspace_map",
                3: "defender.scripts.visualize", 4: "defender.scripts.tenant"}
    assert all(t.startswith(expected[line]) for line, t in got), got


def test_relative_import_that_climbs_into_scripts():
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
    REMEDY = "run python3 defender/cli/tenant.py setup"
    TABLE = {"old": "defender.cli.workspace_map"}
    def f():
        LOG.warning("defender.presentation.visualize_run is gone")
''')


def test_module_named_only_in_a_string_a_comment_or_a_docstring():
    rel = "defender/runtime/_spec1080_strings.py"
    assert [e for e in C.census(overlay={rel: _STRINGS}) if e.importer == rel] == []
    with_import = _STRINGS + "from defender.scripts.pricing import usage_cost\n"
    assert [(e.line, e.target) for e in C.census(overlay={rel: with_import})
            if e.importer == rel] == [(9, "defender.scripts.pricing")]


def test_scripts_path_exec_from_shell_ci_and_docs(tmp_path):
    base = {S.current_path(path) for path in S.base_inventory()["files"]}
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
            "      - run: defender/.venv/bin/python -m defender.cli.tacit_cli check\n")
    C.plant(root, "defender/docs/spec1080.md", "python3 defender/box/image_cli.py build\n")
    C.plant(root, "defender/runtime/_spec1080_spawn.py",
            "import subprocess, sys\n"
            "subprocess.run([sys.executable, 'defender/cli/tenant.py', 'check'])\n")
    assert _rel_edges(C.census(root)) == before


_JUNK = ("defender/.venv/lib/m.py", "defender/runtime/__pycache__/m.py",
         "defender/node_modules/pkg/m.py", "defender/build/m.py", "defender/dist/m.py",
         "defender/.mypy_cache/m.py", "scripts/.ruff_cache/m.py", "defender/site-packages/m.py")


def test_python_files_in_caches_vendored_trees_and_build_output(tmp_path):
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
    from tooling.lint import _astlib
    import tooling.testing.helpers
    from tooling.lint._baseline import gate
    import mypkg.scripts.thing
    from defender.scriptsx import y
    from defender.learning.scripts import z
''')


def test_the_other_scripts_package():
    rel = "tooling/lint/_spec1080_other.py"
    assert [e for e in C.census(overlay={rel: _OTHER_SCRIPTS}) if e.importer == rel] == []
    real = _OTHER_SCRIPTS + "from defender.scripts.tenant import main\n"
    assert [(e.line, e.target) for e in C.census(overlay={rel: real})
            if e.importer == rel] == [(7, "defender.scripts.tenant")]


def test_importer_inside_scripts_of_a_moved_module():
    overlay = {
        **_overlay_with("defender/cli/tenant.py", PLANT_IMPORT),
        **_overlay_with("defender/integrations/cmdb_adapter.py",
                        "from defender.integrations import _stub_transport\n"
                        "from defender.integrations import faults\n"),
    }
    assert [e for e in C.census(overlay=overlay) if S.under(e.importer, "defender/scripts")] == []
    outside = _overlay_with("defender/runtime/verbs.py", PLANT_IMPORT)
    assert any(e.importer == "defender/runtime/verbs.py" for e in C.census(overlay=outside))


def test_1080_a_path_load_or_spawn_of_a_moved_scripts_file_errors_with_a_missing_file_message(
        tmp_path):
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
