"""#1485 O5 goal: neither product code nor tests name the retired #1278 import and cutover surfaces (outside the named ban
lists), and the old `defender/CLAUDE.md` upgrade note is one line. A name census over each file's syntax (extends
`test_1278_census`, which exempts these). The ban lists are module-level constants named in `BAN_LIST_CONSTANTS`:
the retirement tests' one list (`support/shared/_retired1485`) and `test_1278_census.REACH_NAMES`; the census skips an
assignment to such a constant only in its home file (`BAN_LIST_HOMES`), and nothing else."""
from __future__ import annotations

import ast
import re
import subprocess

from defender.tests.learning.state_contracts.test_1278_census import _PRODUCT_FLOOR, REPO, _product_files
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._retired1485 import BAN_LIST_CONSTANTS, BAN_LIST_HOMES, RETIRED_ACTION, RETIRED_COMMAND, RETIRED_NAMES

RETIRED = RETIRED_NAMES
#: A spelling inside any string (a Literal member, a dict key, an audit action, `__all__`) also names it.
ACTION = RETIRED_ACTION
MARKER = "lint-learning-state: ok"
_ACCESSOR_OWNERS = frozenset({"tenant", "layout", "_layout", "paths", "_paths", "self"})
_TESTS_FLOOR = 150


def _docstrings(tree: ast.AST) -> set[int]:
    return {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}


def _ban_lists(tree: ast.AST, constants: frozenset[str]) -> set[int]:
    """The nodes under a module-level assignment to one of `constants`, the ban lists this file is home to."""
    skipped: set[int] = set()
    for stmt in getattr(tree, "body", []):
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] if isinstance(stmt, ast.AnnAssign) else []
        if any(isinstance(t, ast.Name) and t.id in constants for t in targets):
            skipped |= {id(n) for n in ast.walk(stmt)}
    return skipped


def names_in(source: str, *, allow_action: bool = False, ban_lists: frozenset[str] = frozenset()) -> list[str]:
    """Each retired name `source` uses as code: a name, attribute, import, definition or string, not a docstring, a comment
    or a named ban list."""
    tree = ast.parse(source)
    prose = _docstrings(tree)
    banned = _ban_lists(tree, ban_lists)
    found: list[str] = []
    for node in ast.walk(tree):
        if id(node) in banned:
            continue
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
    a, b, c = sorted(RETIRED)[:3]
    code = [
        f"from x import {a}", f"{a}({b})", "x = tenant.learning", "x = layout.learning", f"from y import {b} as R",
        f"def {c}(): ...", f"class {a}(Exception): ...", f"PendingAction = Literal['create', '{ACTION}']", f"ACTIONS = {{'{ACTION}': 1}}",
        f"__all__ = ['{a}']", f"await t.{b}(x)", f"def f({c}): ...", f"x = {a}(t)",
        "class Tenant:\n    @property\n    def learning(self): ...", f"x = 'defender.learning.store.{c}'",
        *(f"x = {name}" for name in sorted(RETIRED)),
    ]
    for line in code:
        assert names_in(line), line
    prose = [f'"""The {a} and the {ACTION} job."""', f"# {b} was deleted", f"def f():\n    '''{c}'''",
             "x = tenant.learning_paths(1)", "learning = load()", "x = batch.learning", "class Other:\n    def learning(self): ...",
             "import_learning = 1", "x = 'learning cutover'", f"x = '{RETIRED_COMMAND}'"]
    for line in prose:
        assert names_in(line) == [], line
    assert names_in(f"x = '{ACTION}'", allow_action=True) == []


def test_o5_the_census_skips_a_named_ban_list_and_nothing_else():
    """Control: a module-level assignment to a named ban-list constant is skipped only in its home file; any other
    assignment, a copy of a ban list elsewhere, and a planted name in a test-like file are found. (O5, D13)"""
    a, b = sorted(RETIRED)[:2]
    for constant in sorted(BAN_LIST_CONSTANTS):
        assert names_in(f"{constant} = frozenset({{'{a}', '{b}', '{ACTION}'}})", ban_lists=BAN_LIST_CONSTANTS) == [], constant
    assert {c for home in BAN_LIST_HOMES.values() for c in home} == BAN_LIST_CONSTANTS, "every ban list has one home"
    assert names_in(f"OTHER_LIST = frozenset({{'{a}'}})") == [a]
    assert names_in(f"def test_x():\n    RETIRED_NAMES = {{'{a}'}}", ban_lists=BAN_LIST_CONSTANTS) == [a], "only a module-level constant is a ban list"
    planted = {"defender/tests/learning/test_planted.py": f"from defender.learning.store import {a}\n\ndef test_x():\n    assert {a}\n"}
    assert census(planted, allow=set()) == {"defender/tests/learning/test_planted.py": [a]}
    copy = f"RETIRED_NAMES = frozenset({{'{a}'}})\n"
    assert census({"defender/tests/support/shared/_ban.py": copy}, allow=set()) == {"defender/tests/support/shared/_ban.py": [a]}
    assert census({"defender/tests/support/shared/_retired1485.py": copy}, allow=set()) == {}


def _revision_files() -> dict[str, str]:
    """Each migration's id and its repo-relative path."""
    return {r.revision: f"defender/migrations/versions/{r.path.rsplit('/', 1)[-1]}" for r in revisions.scripts().walk_revisions()}


def census(sources: dict[str, str], *, allow: set[str]) -> dict[str, list[str]]:
    """Each file of `sources` (repo-relative path to text) that names a retired surface, with the names; `allow` may name `learning_cutover`."""
    return {rel: sorted(set(hits)) for rel, text in sources.items() if (hits := names_in(text, allow_action=rel in allow, ban_lists=BAN_LIST_HOMES.get(rel, frozenset())))}


def _test_files() -> list[str]:
    """Every Python file under `defender/tests`, tracked or new (a new file is not yet tracked)."""
    listed = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "defender/tests"], cwd=REPO, check=True,
                            capture_output=True, text=True).stdout.split()
    return [rel for rel in listed if rel.endswith(".py")]


def _read(rels: list[str]) -> dict[str, str]:
    return {rel: (REPO / rel).read_text(encoding="utf-8") for rel in rels if (REPO / rel).is_file()}


def test_o5_no_product_code_names_a_retired_import_or_cutover_surface():
    """Outside tests and the revisions before the retirement, no product file names any retired surface (the retirement migration may name `learning_cutover`). (O5)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR, f"the walk found only {len(files)} product files"
    by_rev = _revision_files()
    old = {p for p in by_rev.values()} - revisions.new_files(by_rev)
    retire_path = by_rev.get(next((r for r in by_rev if r.endswith(revisions.RETIRE_SUFFIX)), ""), "")
    found = census(_read([rel for rel in files if rel not in old]), allow={retire_path})
    assert found == {}, f"{len(found)} product file(s) still name a retired surface: {found}"


def test_o5_no_test_names_a_retired_import_or_cutover_surface_outside_a_named_ban_list():
    """Under `defender/tests`, no file names a retired surface as code except through a named ban-list constant (the
    retirement tests' one list, `REACH_NAMES`): a stale test, helper or fixture that still does is listed. (O5, D13)"""
    files = _test_files()
    assert len(files) >= _TESTS_FLOOR, f"the walk found only {len(files)} test files"
    found = census(_read(files), allow=set())
    assert found == {}, f"{len(found)} test file(s) still name a retired surface: {found}"


def test_o5_no_product_line_keeps_the_old_folder_exemption_marker():
    """The cutover import was the only reader of the old folder that `# lint-learning-state: ok` excused; none remains. (O5)"""
    files = _product_files()
    assert len(files) >= _PRODUCT_FLOOR
    marked = {rel: n for rel in files for n, line in enumerate((REPO / rel).read_text(encoding="utf-8").splitlines(), 1) if MARKER in line}
    assert marked == {}, marked


def _section(lines: list[str], title: str) -> list[str]:
    """The body of the `## <title>` section (up to the next `## `), or [] with none."""
    starts = [n for n, line in enumerate(lines) if line.startswith(f"## {title}")]
    assert len(starts) <= 1, starts
    if not starts:
        return []
    rest = lines[starts[0] + 1:]
    return rest[:next((n for n, line in enumerate(rest) if line.startswith("## ")), len(rest))]


def test_o5_the_upgrade_notes_say_to_cut_over_on_an_earlier_revision_and_to_stop_the_drains_before_migrating():
    """`defender/CLAUDE.md` has no `Upgrade from before #1278` section and no cutover command; one line names an earlier
    revision to cut over on and says a deployment that never did loses its old learning folder (D10); an `Upgrade from
    before #1485` section names its migrations and defers to the standing `Upgrading` section, which says to stop the
    learning drains and the API before migrating (D12: every upgrade stops the old code). Loose words. (O5)"""
    lines = (REPO / "defender" / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("## Upgrade from before #1454") for line in lines), "control: the neighbouring notes are read"
    assert not any("Upgrade from before #1278" in line for line in lines)
    assert not any(RETIRED_COMMAND in line for line in lines)
    notes = [line for line in lines if re.search(r"(?i)cut[ -]?over", line) and "#1485" in line]
    assert len(notes) == 1, notes
    note = notes[0]
    assert re.search(r"(?i)(earlier|older|previous|prior)\s+(revision|release|version)|(revision|release|version)\s+(from\s+)?(before|prior to|older than)|before\s+#1485", note), note
    assert re.search(r"(?i)\blearning\b", note), note
    assert re.search(r"(?i)\bfolder\b", note), note
    assert re.search(r"(?i)\blos[et]\b|\bdiscard|\bgone\b", note), note
    note_1485 = " ".join(_section(lines, "Upgrade from before #1485"))
    assert note_1485, "an `Upgrade from before #1485` section exists"
    assert re.search(r"(?i)\bmigrat", note_1485), note_1485
    assert "Upgrading" in note_1485, note_1485
    body = " ".join(_section(lines, "Upgrading"))
    assert body, "a standing `Upgrading` section exists"
    stop, migrate = re.search(r"(?i)\bstop", body), re.search(r"(?i)\bmigrat", body)
    assert stop, body
    assert migrate, body
    assert re.search(r"(?i)\bdrains?\b", body), body
    assert re.search(r"\bAPI\b", body), body
