"""The tree's layout after the #1080 cut: the engines the `bin/` shims run, the lesson content
folder, and where modules take their root from.

The rest of what used to be asserted here (placement under `defender/scripts/`, nothing importing
`defender.scripts.*`, every base name still defined, the old paths erroring) guarded the move
out of `defender/scripts/`, which #1268 removed; nothing can be placed under or import from a
folder that does not exist."""
from __future__ import annotations

import ast
import re
import textwrap

from defender.tests.tooling.layout_contracts import _spec1080 as S

#: One anchor name per moved engine; `S.home_of` finds the module that defines it today.
ANCHORS = ("passthrough_max_bytes", "_load_payload", "usage_cost", "reexec_into_venv", "cmd_tags",
           "match_lessons", "resolve_corpus", "load_case_mapping", "is_reserved_query_id")
#: Each engine a shim's wrapper delegates to, by an anchor the engine defines.
ENGINE_OF_SHIM = {"defender-sql": "_load_payload", "defender-lessons": "cmd_tags"}
#: The moved module whose `__main__` block travels with it, by anchor.
UNCALLED = (("WRITE_RETURN_LEAD", None),)



def _mentions_file(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(node))


def file_depth_anchors(source: str | bytes, filename: str = "<src>") -> list[int]:
    """Lines where a module derives a path from its own file DEPTH: `<…__file__…>.parents[N]`
    with N ≥ 1 (or a non-constant N), `<…__file__…>.parent.parent`, or
    `os.path.dirname(os.path.dirname(<…__file__…>))`. A single `.parent` (a sibling such as
    `Path(__file__).parent / "assets"` that travels with its module) is allowed."""
    tree = ast.parse(source, filename=filename)
    hits: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute) \
                and n.value.attr == "parents" and _mentions_file(n.value.value):
            idx = n.slice
            if not (isinstance(idx, ast.Constant) and isinstance(idx.value, int)
                    and idx.value == 0):
                hits.add(n.lineno)
        elif isinstance(n, ast.Attribute) and n.attr == "parent" \
                and isinstance(n.value, ast.Attribute) and n.value.attr == "parent" \
                and _mentions_file(n.value.value) or isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "dirname" and n.args and isinstance(n.args[0], ast.Call) \
                and isinstance(n.args[0].func, ast.Attribute) \
                and n.args[0].func.attr == "dirname" and _mentions_file(n.args[0]):
            hits.add(n.lineno)
    return sorted(hits)

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

def test_1080_each_shim_execs_its_engine_module_and_the_engine_carries_no_bootstrap():
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
        assert guard is not None, (
            f"{where} dropped its command block (the `__main__` guard that runs its `main`) "
            f"that the move must keep")

def test_1080_no_python_module_lands_in_the_lesson_content_folder():
    """The lesson content folder is a tenant's `agent/lessons/` (#1108 P4, decision 4: the
    product tree holds none — S-A's `tenant_1108_p4/test_layout.py` pins that absence, O1), so
    the content checked is the committed fixture tenant's: lessons and no code. The engines
    stay out of the content folder's spelling and out of `scripts/`."""
    from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

    content = FIXTURE_AGENT / "lessons"
    on_disk = [p for p in content.rglob("*")
               if p.is_file() and not set(p.relative_to(S.REPO_ROOT).parts) & S.JUNK_DIRS]
    assert [S.rel(p) for p in on_disk if p.suffix == ".py"] == []
    assert any(p.suffix == ".md" for p in on_disk), "the fixture tenant's lesson .md files are gone"
    for anchor in ("cmd_tags", "match_lessons"):
        engine = S.home_of(anchor)
        assert not S.under(engine, "defender/lessons")

def test_1080_no_moved_module_derives_a_path_from_its_own_file_depth():
    planted = textwrap.dedent('''\
        from pathlib import Path
        ASSETS = Path(__file__).parent / "assets"
        ROOT = Path(__file__).resolve().parents[2]
        UP = Path(__file__).parent.parent
    ''')
    assert file_depth_anchors(planted) == [3, 4]
    anchors = list(ANCHORS)
    homes = sorted({S.home_of(a) for a in anchors})
    found = {h: file_depth_anchors((S.REPO_ROOT / h).read_bytes(), h) for h in homes if h != S.VENV}
    # The venv bootstrap owns its checkout root; its dedicated subprocess tests pin that root.
    assert {h: lines for h, lines in found.items() if lines} == {}
