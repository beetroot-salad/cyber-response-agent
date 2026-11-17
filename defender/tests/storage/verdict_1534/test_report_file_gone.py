"""#1534 V-NOFILE: no code reaches the retired `report.md`: product, tests, evaluations; model-facing text does not name it.

Retirement is asserted as a class (the module, the layout classes and the handle's documents group have no `report`);
the AST walk covers only retired names, imports of `records._report` and the file-name literal or constant.

The wire names `no_report` and `report_committed` stay; `docs/archive/` is history. The product line is
`tooling/lint/lint_shippable_surface.EXCLUDED_PREFIXES`. An exempted line carries `# lint-report-file: ok — <reason>`."""
from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
EXEMPT = "# lint-report-file: ok"
_PRODUCT_FLOOR = 300
NAMED_FILE = re.compile(r"report\.md")
#: Retired readers and types, reached by name (an import of one, a call of one, an attribute chain ending in one).
RETIRED_NAMES = frozenset({"read_report", "parse_report", "parse_report_text", "require_report", "render_report",
                           "ReportUnreadable", "ReportRead"})
#: Retired constants for the file's name.
RETIRED_CONSTANTS = frozenset({"REPORT_NAME"})
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


def reaches(source: str, *, constants: bool = False) -> list[str]:
    """The lines of Python `source` that reach the retired file: an import of `records._report` or of a retired name, a
    retired reader or type by name, or (with `constants`) the file-name literal or constant."""
    lines = source.splitlines()
    tree = ast.parse(source)
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


def test_v_nofile_the_detector_finds_each_form_and_skips_exempted_lines_and_wire_names():
    """Control: the file's name and each member form are found; `no_report`, `report_committed` and an exempted line are not. (V-NOFILE)"""
    for line in ("x = run / 'report.md'", "# writes report.md", "see `report.md` in the folder"):
        assert named_lines(line), line
    for line in ("from a import read_report", "x = m.parse_report_text(t)", "require_report(r)", "y: ReportUnreadable",
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
    """No test or evaluation `.py` but this census imports the retired module or calls a retired reader. (V-NOFILE)
    The file-name literal is checked in product code only: in tests it plants decoys and arbitrary files."""
    files = [rel for rel in _tracked("defender/tests/*.py", "evaluations/*.py") if rel != CENSUS_FILE]
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} test and evaluation files"
    found = {}
    for rel in files:
        if hits := reaches((REPO / rel).read_text(encoding="utf-8")):
            found[rel] = hits
    assert found == {}, f"{len(found)} test or evaluation file(s) still reach the retired file: {sorted(found)}"


def test_v_nofile_no_model_facing_text_names_the_file():
    """`SKILL.md`, every skill page and the handbook no longer name `report.md`. (V-NOFILE)"""
    files = [rel for rel in _tracked("defender/SKILL.md", "defender/skills/**/*.md")]
    assert len(files) >= 10, f"the walk found only {len(files)} model-facing pages"
    found = {rel: hits for rel in files if (hits := named_lines((REPO / rel).read_text(encoding="utf-8")))}
    assert found == {}, f"model-facing text still names the file: {sorted(found)}"


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
