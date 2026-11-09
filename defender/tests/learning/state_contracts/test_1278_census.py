"""#1278 A1 sketch, O10 census: after cutover no product code names the learning state handle or root.

The product line is `tooling/lint/lint_shippable_surface.EXCLUDED_PREFIXES` (tests, docs, evaluations,
integrations carved out). An exempted line carries `# lint-learning-state: ok — <reason>`.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
#: What the handle and root were reached by at base (C15): the handle, its raw-path verb, the root
#: accessors, and the commit record file kept under the root.
PATTERN = re.compile(r"\bLearningState\b|\bstage_dir\(|\bstate_root\b|\blearning_state_exists\b|\bcommit_record\b")
EXEMPT = "# lint-learning-state: ok"
_PRODUCT_FLOOR = 300


def _excluded() -> tuple[str, ...]:
    import importlib.util

    lint = REPO / "tooling" / "lint"
    spec = importlib.util.spec_from_file_location("_shippable", lint / "lint_shippable_surface.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(lint))  # the gate imports its sibling helpers by bare name
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(lint))
    return tuple(module.EXCLUDED_PREFIXES)


def _product_files() -> list[str]:
    tracked = subprocess.run(["git", "ls-files", "defender/*.py"], cwd=REPO, check=True,
                             capture_output=True, text=True).stdout.split()
    excluded = _excluded()
    return [rel for rel in tracked if not rel.startswith(excluded)]


def _hits(text: str) -> list[str]:
    return [line for line in text.splitlines() if PATTERN.search(line) and EXEMPT not in line]


def test_o10_the_census_pattern_finds_each_old_reach():
    """Control: every form the census claims to find, it finds; an exempted line it skips. (O10)"""
    for line in ("with LearningState.open(paths) as s:", "root = state.stage_dir(lane)", "paths.state_root",
                 "tenant.learning_state_exists()", "layout.commit_record"):
        assert _hits(line) == [line]
    assert _hits(f"x = paths.state_root  {EXEMPT} — the cutover import reads the old files") == []


def test_o10_no_product_code_reaches_the_learning_state_root():
    """No product file names the learning state handle, its stage_dir, the root or the commit record file. (O10, A1)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} product files"
    found = {rel: hits for rel in files if (hits := _hits((REPO / rel).read_text(encoding="utf-8")))}
    assert found == {}, f"{len(found)} product file(s) still reach the learning state: {sorted(found)}"
