"""#1278 A1/A2 O10: no product code writes under the tenant's `<T>/learning`, and the learning state handle is gone.

The product line is `tooling/lint/lint_shippable_surface.EXCLUDED_PREFIXES` (tests, docs, evaluations,
integrations carved out). The census reads each product file's syntax, not its words: a reach is a name the
old state was reached through (the handle, its raw-path verb, the root location type and accessors, the commit
record file kept under the root) used as code. A comment, docstring or string that mentions one is not a reach.
An exempted line carries `# lint-learning-state: ok — <reason>`. D10: the folder's contents move (commits to the
database, worktrees to the tenant scratch location); this is not a ban on the word "learning". What a tick
writes under `<T>/learning` is observed in `tests/learning/curation/test_1278_call_folders.py`.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
EXEMPT = "# lint-learning-state: ok"
_PRODUCT_FLOOR = 300
HANDLE = "LearningState"
#: Names whose use as code is a reach into the old root: the handle, the root's location type and its unwrap, the
#: commit record file's location type and its unwrap.
REACH_NAMES = frozenset({HANDLE, "LearningRoot", "unwrap_learning_root", "CommitRecord", "unwrap_commit_record"})
#: Attributes that name the root or the record file: the loop paths' root accessors, the handle's raw-path verb, the
#: existence check. (`commit_record` is one only on the old owners below: the store's verb of that name is not.)
REACH_ATTRS = frozenset({"state_root", "state_dir", "stage_dir", "learning_state_exists"})
#: `<tenant or layout>.learning` and `.commit_record`: the root and the record file, as locations.
_OWNERS = frozenset({"tenant", "layout", "_layout"})


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


def _owner(value: ast.expr) -> str | None:
    return value.id if isinstance(value, ast.Name) else value.attr if isinstance(value, ast.Attribute) else None


def _is_reach(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in REACH_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in REACH_NAMES | REACH_ATTRS or (node.attr in {"learning", "commit_record"} and _owner(node.value) in _OWNERS)
    if isinstance(node, ast.alias):
        return node.name in REACH_NAMES
    return isinstance(node, ast.FunctionDef | ast.ClassDef) and node.name in REACH_NAMES | {"stage_dir", "learning_state_exists"}


def reaches(source: str) -> list[str]:
    """Each line of `source` that uses a name of the old state as code (not in a comment, docstring or string), unless exempted."""
    lines = source.splitlines()
    found = {n.lineno for n in ast.walk(ast.parse(source)) if _is_reach(n) and getattr(n, "lineno", 0)}
    return [lines[n - 1] for n in sorted(found) if EXEMPT not in lines[n - 1]]


def _definitions(source: str) -> list[str]:
    """The handle and its raw-path verb, defined: a class `LearningState` or a function `stage_dir`."""
    return [f"{type(n).__name__} {n.name}" for n in ast.walk(ast.parse(source))
            if (isinstance(n, ast.ClassDef) and n.name == HANDLE) or (isinstance(n, ast.FunctionDef) and n.name == "stage_dir")]


def test_o10_the_census_finds_each_old_reach_and_skips_prose_and_exempted_lines():
    """Control: every form of reach the census claims is found as code; a docstring, a comment, a string and an exempted line are not. (O10)"""
    code = [
        "with LearningState.open(paths) as s:\n    pass", "root = state.stage_dir(lane)", "root = paths.state_root",
        "ok = tenant.learning_state_exists()", "log = layout.commit_record", "log = tenant.commit_record", "from x import LearningRoot",
        "where = self.tenant.learning", "class LearningState:\n    pass", "def stage_dir(self, lane):\n    pass",
    ]
    for line in code:
        assert reaches(line), line
    prose = ['"""The LearningState handle and its state_root."""', "# LearningState was deleted", "x = 'stage_dir(lane)'",
             "learning = load()", "n = batch.learning_rate", "await store.commit_record(batch, sha)", "x = batch.commit_record"]
    for line in prose:
        assert reaches(line) == [], line
    assert reaches(f"root = paths.state_root  {EXEMPT} — the cutover import reads the old files") == []
    assert _definitions("class LearningState:\n    pass\n") == ["ClassDef LearningState"]
    assert _definitions("def stage_dir(self, lane): ...") == ["FunctionDef stage_dir"]
    assert _definitions("class Other:\n    def f(self): ...") == []


def test_o10_no_product_code_reaches_the_learning_state_root_or_its_handle():
    """No product file uses the handle, `stage_dir`, the root's location type or accessors, or the commit record file as code. (O10, A1)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} product files"
    found = {rel: hits for rel in files if (hits := reaches((REPO / rel).read_text(encoding="utf-8")))}
    assert found == {}, f"{len(found)} product file(s) still reach the learning state: {sorted(found)}"


def test_o10_the_learning_state_handle_and_its_stage_dir_are_not_defined_anywhere_in_the_product():
    """Neither a class `LearningState` nor a `stage_dir` method is defined in any product file. (O10)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR
    defined = {rel: d for rel in files if (d := _definitions((REPO / rel).read_text(encoding="utf-8")))}
    assert defined == {}, defined


def test_o10_the_run_records_page_no_longer_documents_the_curator_traces_under_pending():
    """The records page stops documenting `_pending/wire_logs/` as where the curators' traces live. (A1 docs)"""
    page = (REPO / "defender" / "docs" / "run-records.md").read_text(encoding="utf-8")
    assert re.search(r"_pending\*?/wire_logs", page) is None
