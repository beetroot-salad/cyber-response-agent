"""#1534 V-NOFILE: no code reaches the retired `report.md`: product, tests, evaluations; no shipped text names it.

Retirement is asserted as a class (the module, the layout classes and the handle's documents group have no `report`);
the AST walk covers only retired names, imports of `records._report`, the file-name literal or constant, and (in tests,
where the literal also names decoys) a read of a path that ends in the file's name.

The wire names `no_report` and `report_committed` stay; `docs/archive/` is history. The product line is
`tooling/lint/lint_shippable_surface.EXCLUDED_PREFIXES`. An exempted line carries `# lint-report-file: ok — <reason>`."""
from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

#: Reads the source tree (ast, mypy, a repo-wide walk) rather than running the product: CI's `lint` job runs it (`-m gate`).
pytestmark = pytest.mark.gate

REPO = Path(__file__).resolve().parents[4]
EXEMPT = "# lint-report-file: ok"
_PRODUCT_FLOOR = 300
_TEXT_FLOOR = 30
#: Left to the design's `LISTED` check (docs), to the tests, to `examples/` folders and to the three narrative files.
EXEMPT_PREFIXES = ("defender/docs/", "defender/tests/")
EXEMPT_NAMES = frozenset({"CLAUDE.md", "AGENTS.md", "README.md"})
NAMED_FILE = re.compile(r"report\.md")
#: Retired readers and types, reached by name (an import of one, a call of one, an attribute chain ending in one).
RETIRED_NAMES = frozenset({"read_report", "parse_report", "parse_report_text", "require_report", "render_report",
                           "validate_report", "read_archived_report", "_decide_report_write", "ReportUnreadable", "ReportRead"})
#: Retired constants for the file's name.
RETIRED_CONSTANTS = frozenset({"REPORT_NAME"})
#: A path literal that ends in the file's name (`"report.md"`, `"runs/x/report.md"`).
PATH_LITERAL = re.compile(r"(?:^|/)report\.md$")
#: The calls that read a path: `p.read_text()`, `p.read_bytes()`, `p.open()`, and `open(p)` / `os.open(p)`; a reader
#: function handed the path as its first argument is any call whose name starts with one of `READER_PREFIXES`
#: (`_io.read_guarded(p)`, `read_jsonl_rows(p)`, `parse_report(p)`).
READ_CALLS = frozenset({"read_text", "read_bytes", "open"})
READER_PREFIXES = ("read", "parse", "load")
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
#: The census file itself is the one exemption by path; every other deliberate decoy or absence line carries `EXEMPT`.
CENSUS_FILE = "defender/tests/storage/verdict_1534/test_report_file_gone.py"
RETIRED_MODULE = "defender.records._report"
#: Listed by the design's "Removal": docs, the records table, the stylesheet, the held-out README.
LISTED = ("defender/docs/run-records.md", "defender/docs/learning-loop.md", "defender/docs/runtime-development.md",
          "defender/docs/runtime-gates.md", "defender/docs/case-history-write-path.md", "defender/docs/run-records-kinds.tsv",
          "evaluations/fixtures/held_out/README.md", "defender/presentation/assets/styles.css",
          "tooling/lint/lint_ungated_artifact_write.py", "tooling/lint/lint_ungated_artifact_write_baseline.json")


def _excluded() -> tuple[str, ...]:
    lint = REPO / "tooling" / "lint"
    spec = importlib.util.spec_from_file_location("_shippable", lint / "lint_shippable_surface.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(lint))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(lint))
    return tuple(module.EXCLUDED_PREFIXES)


def _tracked(*patterns: str) -> list[str]:
    return subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", *patterns], cwd=REPO, check=True,
                          capture_output=True, text=True).stdout.split()


def _product(pattern: str) -> list[str]:
    excluded = _excluded()
    return [rel for rel in _tracked(pattern) if not rel.startswith(excluded)]


def named_lines(source: str) -> list[str]:
    """The lines of `source` that spell `report.md`, in code, docstring, comment or text, unless exempted."""
    return [ln for ln in source.splitlines() if NAMED_FILE.search(ln) and EXEMPT not in ln]


def reaches(source: str, *, constants: bool = False, tree: ast.Module | None = None) -> list[str]:
    """The lines of Python `source` that reach the retired file: an import of `records._report` or of a retired name, a
    retired reader or type by name, or (with `constants`) the file-name literal or constant."""
    lines = source.splitlines()
    tree = tree or ast.parse(source)
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and n.body
                  and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    found = set()
    for node in ast.walk(tree):
        hit = False
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            hit = (module == RETIRED_MODULE or module.endswith(".records._report")
                   or (module in ("defender.records", "records") and any(a.name == "_report" for a in node.names))
                   or (module == "" and node.level > 0 and any(a.name == "_report" for a in node.names))
                   or any(a.name in RETIRED_NAMES or a.name in RETIRED_CONSTANTS for a in node.names))
        elif isinstance(node, ast.Import):
            hit = any(a.name == RETIRED_MODULE or a.name.endswith(".records._report") for a in node.names)
        elif isinstance(node, ast.Name):
            hit = node.id in RETIRED_NAMES
        elif isinstance(node, ast.Attribute):
            hit = node.attr in RETIRED_NAMES or (node.attr in RETIRED_CONSTANTS and constants)
        elif constants and isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            hit = bool(NAMED_FILE.search(node.value))
        if hit:
            found.add(node.lineno)
    return [lines[n - 1] for n in sorted(found) if EXEMPT not in lines[n - 1]]


def _path_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(PATH_LITERAL.search(node.value))


def _joined(node: ast.AST) -> bool:
    """`base / "report.md"`, `base.joinpath(..., "report.md")`, `os.path.join(base, "report.md")` or
    `Path(".../report.md")`. A file name held in a string constant first (`NAME = "report.md"`; `base / NAME`) is not
    followed: no test spells it that way."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _path_literal(node.right)
    if isinstance(node, ast.Call) and node.args:
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr in ("joinpath", "join")) or (
                isinstance(func, ast.Name) and func.id in ("Path", "PurePath")):
            return _path_literal(node.args[-1])
    return False


def path_bindings(source: str, tree: ast.Module | None = None) -> set[str]:
    """The module-level names `source` binds to a path that ends in the file's name (`GOLDEN = base / "report.md"`):
    another module that imports one reads the file through it."""
    found: set[str] = set()
    for node in (tree or ast.parse(source)).body:
        if isinstance(node, ast.Assign) and _joined(node.value):
            found |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and node.value is not None and _joined(node.value) and isinstance(
                node.target, ast.Name):
            found.add(node.target.id)
    return found


def _enclosing_scopes(tree: ast.Module) -> Any:
    """`node -> [its enclosing functions, innermost first, then the module]`."""
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def scopes(node: ast.AST) -> list[ast.AST]:
        out: list[ast.AST] = []
        while node in parent:
            node = parent[node]
            if isinstance(node, _SCOPES):
                out.append(node)
        return [*out, tree]

    return scopes


def _read_target(call: ast.Call) -> ast.AST | None:
    """The path a call reads: `p` of `p.read_text()`, `p.read_bytes()`, `p.open()`, `open(p)`, `os.open(p)`, or a
    reader function's first argument (`READER_PREFIXES`)."""
    func = call.func
    module_open = isinstance(func, ast.Attribute) and func.attr == "open" and isinstance(
        func.value, ast.Name) and func.value.id in ("os", "io")
    if (module_open or (isinstance(func, ast.Name) and func.id == "open")) and call.args:
        return call.args[0]
    if isinstance(func, ast.Attribute) and func.attr in READ_CALLS and not module_open:
        return func.value
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
    if name.lstrip("_").startswith(READER_PREFIXES) and call.args:
        return call.args[0]
    return None


def reads_named_file(source: str, bound: frozenset[str] | set[str] = frozenset(), tree: ast.Module | None = None) -> list[str]:
    """The lines of Python `source` that read a path ending in the file's name: the join or literal read in place
    (`(run / "report.md").read_text()`, `open("report.md")`), or a name bound to one in the same or an enclosing scope,
    at module level, or in `bound` (another module's `path_bindings`), read later. Writes, links and existence checks
    are not reads: tests plant decoys and assert absences that way."""
    lines = source.splitlines()
    tree = tree or ast.parse(source)
    nodes = list(ast.walk(tree))
    joins = [n for n in nodes if isinstance(n, ast.Assign) and _joined(n.value)]
    scopes = _enclosing_scopes(tree) if joins else (lambda _node: [tree])  # the parent map only where a name is bound
    local: dict[ast.AST, set[str]] = {}
    for node in joins:
        local.setdefault(scopes(node)[0], set()).update(t.id for t in node.targets if isinstance(t, ast.Name))
    named = path_bindings(source, tree) | set(bound)
    any_local = set().union(*local.values())

    def a_path(node: ast.AST | None, at: ast.AST) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in named or (node.id in any_local and any(node.id in local.get(s, ()) for s in scopes(at)))
        if isinstance(node, ast.Attribute):
            return node.attr in named
        return _joined(node) or _path_literal(node)

    found = {node.lineno for node in nodes if isinstance(node, ast.Call) and a_path(_read_target(node), node)}
    return [lines[n - 1] for n in sorted(found) if EXEMPT not in lines[n - 1]]


def test_v_nofile_the_read_detector_finds_each_read_form_and_skips_writes_and_absence_checks():
    """Control: a read of a path ending in the file's name is found in each form (in place, through a local or module
    name, through another module's constant); a write, a link, an existence check, another file and an exempted line
    are not. (V-NOFILE)"""
    for source in ('x = (source_dir / "report.md").read_text(encoding="utf-8")',
                   'x = (run / "runs" / "report.md").read_bytes()',
                   'x = run.joinpath("report.md").read_text()',
                   'x = Path("w/report.md").read_text()',
                   'with open(run / "report.md") as f:\n    pass',
                   'x = os.open("report.md", os.O_RDONLY)',
                   'x = io.open(run / "report.md").read()',
                   'text, err = _io.read_guarded(looped / "report.md")',
                   'rows = read_jsonl_rows(os.path.join(run, "report.md"))',
                   'x = parse_report(run / "report.md")',
                   'with (run / "report.md").open() as f:\n    pass',
                   'def f(run):\n    p = run / "report.md"\n    return p.read_text()',
                   'def f(run):\n    p = run / "report.md"\n    def g():\n        return p.read_text()\n    return g',
                   'GOLDEN = base / "report.md"\ndef f():\n    return GOLDEN.read_text()'):
        assert reads_named_file(source), source
    assert reads_named_file("x = J.GOLDEN.read_text()", {"GOLDEN"}), "another module's constant"
    assert reads_named_file("from j import GOLDEN\nx = GOLDEN.read_bytes()", path_bindings('GOLDEN = b / "report.md"'))
    for source in ('(run / "report.md").write_text("decoy")',
                   'assert not (run / "report.md").exists()',
                   'assert (run / "report.md").is_file()',
                   'os.symlink(run / "report.md", other)',
                   'os.link(run / "report.md", run / "report.hardlink.md")',
                   'shutil.copy(run / "report.md", other)',
                   'x = (run / "investigation.md").read_text()',
                   'x = (run / "report.md.staged").read_text()',
                   'x = (run / "final-report.md").read_text()',
                   'x = _io.read_guarded(run / "investigation.md")',
                   'reader = run / "report.md"',
                   'def f(run):\n    p = run / "report.md"\n    p.write_text("x")\ndef g(p):\n    return p.read_text()',
                   'def f():\n    """Reads report.md."""\n    return 1',
                   f'x = (run / "report.md").read_text()  {EXEMPT} — a fixture file'):
        assert reads_named_file(source) == [], source


def test_v_nofile_the_detector_finds_each_form_and_skips_exempted_lines_and_wire_names():
    """Control: the file's name and each member form are found; `no_report`, `report_committed` and an exempted line are not. (V-NOFILE)"""
    for line in ("x = run / 'report.md'", "# writes report.md", "see `report.md` in the folder"):
        assert named_lines(line), line
    for line in ("from a import read_report", "x = m.parse_report_text(t)", "require_report(r)", "y: ReportUnreadable",
                 "validate_report(t)", "family.read_archived_report(b, p)", "from f import _decide_report_write",
                 "from defender.records._report import X", "from defender.records import _report",
                 "import defender.records._report", "from . import _report"):
        assert reaches(line), line
    for line in ("x = run / 'report.md'", "x = _layout.REPORT_NAME"):
        assert reaches(line, constants=True), line
    for line in ("x = other.report", "x = report", "report = 1", "y = world.report_text", "def f(report): return report",
                 "from defender.tooling.weekly_report import build", "import weekly_report", "from a._report import X"):
        assert reaches(line) == [], line
    assert reaches('def f():\n    """Mentions report.md."""\n', constants=True) == []
    for line in ("'no_report'", "committed = row.report_committed", "no_report = 1", "reporting = 2"):
        assert named_lines(line) == []
        assert reaches(line) == [], line
    assert reaches(f"x = read_report(r)  {EXEMPT} — decoy") == []


def test_v_nofile_no_product_python_names_the_file_or_a_report_member():
    """No product `.py` spells `report.md` or reaches the retired file's reader, type or module. (V-NOFILE)"""
    files = _product("defender/*.py")
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} product files"
    found = {}
    for rel in files:
        text = (REPO / rel).read_text(encoding="utf-8")
        if hits := [*named_lines(text), *reaches(text, constants=True)]:
            found[rel] = hits
    assert found == {}, f"{len(found)} product file(s) still name the retired file: {sorted(found)}"


def test_v_nofile_no_test_or_evaluation_code_reaches_the_retired_file():
    """No test or evaluation `.py` but this census imports the retired module, calls a retired reader, or reads a path
    ending in the file's name (in place, or through a name bound to one, this module's or another's). (V-NOFILE)
    The bare file-name literal is checked in product code only: in tests it plants decoys and arbitrary files."""
    files = [rel for rel in _tracked("defender/tests/*.py", "evaluations/*.py") if rel != CENSUS_FILE]
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} test and evaluation files"
    texts = {rel: (REPO / rel).read_text(encoding="utf-8") for rel in files}
    trees = {rel: ast.parse(text) for rel, text in texts.items()}
    bound = set().union(*(path_bindings(texts[rel], trees[rel]) for rel in texts))
    found = {}
    for rel, text in texts.items():
        if hits := [*reaches(text, tree=trees[rel]), *reads_named_file(text, bound, trees[rel])]:
            found[rel] = hits
    assert found == {}, f"{len(found)} test or evaluation file(s) still reach the retired file: {found}"


def _walked_text_files() -> list[str]:
    """Every tracked non-Python file under `defender/` that is shipped text: not the docs (checked from `LISTED`), the tests,
    an `examples/` folder, or a `CLAUDE.md`, `AGENTS.md` or `README.md`."""
    return [rel for rel in _tracked("defender/*")
            if not rel.endswith(".py") and not rel.startswith(EXEMPT_PREFIXES)
            and "examples" not in Path(rel).parts and Path(rel).name not in EXEMPT_NAMES]


def test_v_nofile_no_shipped_text_file_names_the_file():
    """No tracked non-Python file under `defender/` outside the exempt set (skills, handbook, role prompts, config, assets) names `report.md`. (V-NOFILE)"""
    files = _walked_text_files()
    assert len(files) >= _TEXT_FLOOR, f"the walk found only {len(files)} files"
    assert "defender/SKILL.md" in files
    assert len([rel for rel in files if rel.startswith("defender/skills/") and rel.endswith(".md")]) >= 10
    found = {rel: hits for rel in files if (hits := named_lines((REPO / rel).read_text(encoding="utf-8", errors="replace")))}
    assert found == {}, f"shipped text still names the file: {sorted(found)}"


def test_v_nofile_the_text_walk_is_not_limited_to_model_facing_pages():
    """Control: the walk reaches a role prompt, a stylesheet and a non-Markdown file, and skips docs, tests, examples and the three exempt names."""
    files = _walked_text_files()
    assert any(rel.startswith("defender/learning/judge/") and rel.endswith(".md") for rel in files)
    assert any(rel.endswith(".css") for rel in files)
    assert any(not rel.endswith((".md", ".css")) for rel in files)
    assert not [rel for rel in files if rel.startswith(EXEMPT_PREFIXES) or Path(rel).name in EXEMPT_NAMES]


@pytest.mark.parametrize("rel", LISTED)
def test_v_nofile_the_files_the_design_lists_for_removal_no_longer_name_it(rel):
    """Each doc, table, stylesheet, README, lint and baseline the design's removal list names is clean. (V-NOFILE)"""
    assert (REPO / rel).is_file(), f"{rel} is gone or renamed: update the list"
    assert named_lines((REPO / rel).read_text(encoding="utf-8")) == []


def test_v_nofile_the_wire_names_stay_in_product_code():
    """Control: `no_report` and `report_committed` are still spelled by product code, so the check bans the file, not the words. (V-NOFILE)"""
    files = _product("defender/*.py")
    text = "\n".join((REPO / rel).read_text(encoding="utf-8") for rel in files)
    assert "no_report" in text
    assert "report_committed" in text


def test_v_nofile_the_retired_module_is_gone():
    """`defender.records._report` no longer exists. (V-NOFILE)"""
    assert importlib.util.find_spec("defender.records._report") is None


def test_v_nofile_no_layout_class_or_documents_group_has_a_report_member():
    """`RunPaths`, the run layout, the episode world-paths classes, `WORLD_LEAVES` and the handle's documents group have no `report`. (V-NOFILE)"""
    import uuid

    from defender.records import RUN_LAYOUT, RunPaths
    from defender.records._episode_paths import LAYOUT, WORLD_LEAVES, EpisodePaths, WorldLayout, WorldPaths
    from defender.records._handle import GROUP_MEMBERS, MEMBER_ACCESSOR, _RecordHandleGroup

    layout_world = LAYOUT.world(str(uuid.uuid4()))
    assert type(layout_world) is WorldLayout
    for holder in (RunPaths, type(RUN_LAYOUT), WorldLayout, WorldPaths, EpisodePaths, type(WORLD_LEAVES), RUN_LAYOUT,
                   WORLD_LEAVES, layout_world):
        assert not hasattr(holder, "report"), holder
    assert "report" not in GROUP_MEMBERS["documents"]
    assert "report" not in MEMBER_ACCESSOR
    assert not hasattr(_RecordHandleGroup(None, "documents"), "report")  # type: ignore[arg-type]
