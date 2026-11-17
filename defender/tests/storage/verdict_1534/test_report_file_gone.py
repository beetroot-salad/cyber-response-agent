"""#1534 V-NOFILE: product code and model-facing text no longer name `report.md` or a report member.

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
#: Names whose use as code is a reach into the retired file: its layout member, its readers and writer.
REACH_NAMES = frozenset({"report", "report_text", "report_path", "REPORT", "read_report", "require_report",
                         "validate_report", "render_report", "normalize_disposition", "ReportRead"})
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


def reaches(source: str) -> list[str]:
    """The lines of Python `source` that use a report member's name as code (not prose), unless exempted."""
    lines = source.splitlines()
    found = set()
    for node in ast.walk(ast.parse(source)):
        name = (node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name)
                else node.name if isinstance(node, ast.alias | ast.FunctionDef | ast.ClassDef) else None)
        if name in REACH_NAMES or (isinstance(node, ast.ImportFrom) and (node.module or "").endswith("_report")):
            found.add(node.lineno)
    return [lines[n - 1] for n in sorted(found) if EXEMPT not in lines[n - 1]]


def test_v_nofile_the_detector_finds_each_form_and_skips_exempted_lines_and_wire_names():
    """Control: the file's name and each member form are found; `no_report`, `report_committed` and an exempted line are not. (V-NOFILE)"""
    for line in ("x = run / 'report.md'", "# writes report.md", "see `report.md` in the folder"):
        assert named_lines(line), line
    for line in ("x = RUN_LAYOUT.report", "x = documents.report", "from a import read_report", "def render_report(): ...",
                 "from defender.records._report import X", "y = world.report_text"):
        assert reaches(line), line
    for line in ("'no_report'", "committed = row.report_committed", "no_report = 1", "reporting = 2"):
        assert named_lines(line) == []
        assert reaches(line) == [], line
    assert reaches(f"x = RUN_LAYOUT.report  {EXEMPT} — a label") == []


def test_v_nofile_no_product_python_names_the_file_or_a_report_member():
    """No product `.py` spells `report.md` or uses a report member as code. (V-NOFILE)"""
    files = _product("defender/*.py")
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} product files"
    found = {}
    for rel in files:
        text = (REPO / rel).read_text(encoding="utf-8")
        if hits := [*named_lines(text), *reaches(text)]:
            found[rel] = hits
    assert found == {}, f"{len(found)} product file(s) still name the retired file: {sorted(found)}"


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


def test_v_nofile_the_layout_no_longer_names_report_md():
    """`report.md` is not named by the run layout any more. (V-NOFILE)"""
    from defender.records import RUN_LAYOUT

    assert not hasattr(RUN_LAYOUT, "report")
