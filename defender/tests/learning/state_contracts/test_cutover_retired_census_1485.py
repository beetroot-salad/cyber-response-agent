"""#1485 O5 goal: product code names none of the retired #1278 import and cutover surfaces, and the old `defender/CLAUDE.md`
upgrade note is one line. A name census over each product file's syntax (extends `test_1278_census`, which exempts these)."""
from __future__ import annotations

import ast
import re

from defender.tests.learning.state_contracts.test_1278_census import _PRODUCT_FLOOR, REPO, _product_files
from defender.tests.support.shared import _revisions1485 as revisions

RETIRED = frozenset({
    "cut_over_learning_state", "import_learning_state", "read_learning_state", "write_learning_state", "LearningImport",
    "ImportRefused", "delivery_for_cutover", "LearningRoot", "unwrap_learning_root", "request_learning_cutover",
})
#: A spelling inside any string (a Literal member, a dict key, an audit action, `__all__`) also names it.
ACTION = "learning_cutover"
MARKER = "lint-learning-state: ok"
_ACCESSOR_OWNERS = frozenset({"tenant", "layout", "_layout", "paths", "_paths", "self"})


def _docstrings(tree: ast.AST) -> set[int]:
    return {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}


def names_in(source: str, *, allow_action: bool = False) -> list[str]:
    """Each retired name `source` uses as code: a name, attribute, import, definition or string, not a docstring or comment."""
    tree = ast.parse(source)
    prose = _docstrings(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in RETIRED:
            found.append(node.id)
        elif isinstance(node, ast.Attribute) and (node.attr in RETIRED or (
                node.attr == "learning" and isinstance(node.value, ast.Name | ast.Attribute)
                and (node.value.id if isinstance(node.value, ast.Name) else node.value.attr) in _ACCESSOR_OWNERS - {"self"})):
            found.append(node.attr)
        elif isinstance(node, ast.alias | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.arg):
            spelled = node.arg if isinstance(node, ast.arg) else node.name
            if spelled.split(".")[-1] in RETIRED or (getattr(node, "asname", None) or "") in RETIRED or (
                    spelled == "learning" and isinstance(node, ast.FunctionDef) and _in_tenant_layout(tree, node)):
                found.append(spelled)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in prose:
            found += [w for w in re.findall(r"\w+", node.value) if w in RETIRED]
            if ACTION in node.value and not allow_action:
                found.append(ACTION)
    return found


def _in_tenant_layout(tree: ast.AST, fn: ast.AST) -> bool:
    return any(isinstance(c, ast.ClassDef) and c.name in {"Tenant", "_TenantLayout", "_TenantPaths"} and fn in c.body
               for c in ast.walk(tree))


def test_o5_the_name_census_finds_each_retired_spelling_and_skips_prose():
    """Control: every form of use is found as code; a docstring, a comment and a near name are not. (O5)"""
    code = [
        "from x import cut_over_learning_state", "import_learning_state(a)", "x = tenant.learning", "x = layout.learning",
        "from y import LearningRoot as R", "def delivery_for_cutover(): ...", "class ImportRefused(Exception): ...",
        "PendingAction = Literal['create', 'learning_cutover']", "ACTIONS = {'learning_cutover': 1}", "__all__ = ['LearningImport']",
        "await t.request_learning_cutover(x)", "def f(read_learning_state): ...", "x = unwrap_learning_root(t)",
        "class Tenant:\n    @property\n    def learning(self): ...", "x = 'defender.learning.store.write_learning_state'",
    ]
    for line in code:
        assert names_in(line), line
    prose = ['"""The import_learning_state and the learning_cutover job."""', "# LearningRoot was deleted", "def f():\n    '''read_learning_state'''",
             "x = tenant.learning_paths(1)", "learning = load()", "x = batch.learning", "class Other:\n    def learning(self): ...",
             "import_learning = 1", "x = 'learning cutover'"]
    for line in prose:
        assert names_in(line) == [], line
    assert names_in("x = 'learning_cutover'", allow_action=True) == []


def _revision_files() -> dict[str, str]:
    """Each migration's id and its repo-relative path."""
    return {r.revision: f"defender/migrations/versions/{r.path.rsplit('/', 1)[-1]}" for r in revisions.scripts().walk_revisions()}


def test_o5_no_product_code_names_a_retired_import_or_cutover_surface():
    """Outside tests and the revisions before the retirement, no product file names any retired surface (the retirement migration may name `learning_cutover`). (O5)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} product files"
    by_rev = _revision_files()
    old = {p for p in by_rev.values()} - revisions.new_files(by_rev)
    retire_path = by_rev.get(next((r for r in by_rev if r.endswith(revisions.RETIRE_SUFFIX)), ""), "")
    found = {}
    for rel in files:
        if rel in old:
            continue
        hits = names_in((REPO / rel).read_text(encoding="utf-8"), allow_action=rel == retire_path)
        if hits:
            found[rel] = sorted(set(hits))
    assert found == {}, f"{len(found)} product file(s) still name a retired surface: {found}"


def test_o5_no_product_line_keeps_the_old_folder_exemption_marker():
    """The cutover import was the only reader of the old folder that `# lint-learning-state: ok` excused; none remains. (O5)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR
    marked = {rel: n for rel in files for n, line in enumerate((REPO / rel).read_text(encoding="utf-8").splitlines(), 1) if MARKER in line}
    assert marked == {}, marked


def test_o5_the_upgrade_note_before_1278_is_replaced_by_one_line_naming_an_earlier_revision():
    """`defender/CLAUDE.md` has no `Upgrade from before #1278` section and no cutover command; one line says to cut over on an earlier revision first. (O5, D10)"""
    lines = (REPO / "defender" / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("## Upgrade from before #1454") for line in lines), "control: the neighbouring notes are read"
    assert not any("Upgrade from before #1278" in line for line in lines)
    assert not any("request-learning-cutover" in line for line in lines)
    notes = [line for line in lines if re.search(r"(?i)cut[ -]?over", line) and "#1485" in line]
    assert len(notes) == 1, notes
    assert re.search(r"(?i)(earlier|before|older|previous)\s+(revision|release|version)", notes[0]) or re.search(r"(?i)\bfirst\b", notes[0]), notes[0]
