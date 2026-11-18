"""Tests for the lint_learning_causes gate: one owner of the learning cause lists, and no bare `Why(...)` in product code."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_learning_causes")

OWNER_SRC = '''from typing import Literal
ItemCause = Literal["attempt_ceiling", "curator_held", "malformed_row", "unrecorded"]
BatchCause = Literal["forge_refused", "foreign_pr", "stopped", "unrecorded"]
class Why:
    @staticmethod
    def item(cause, detail): return Why(cause, detail)
'''


def _tree(tmp_path: Path, files: dict[str, str], *, owner: str | None = OWNER_SRC) -> Path:
    root = tmp_path / "defender"
    planted = dict(files)
    if owner is not None:
        planted.setdefault("records/learning_causes.py", owner)
    for rel, text in planted.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize("src", [
    'CAUSES = ("attempt_ceiling", "curator_held", "malformed_row")\n',
    'from typing import Literal\nC = Literal["forge_refused", "foreign_pr", "stopped", "other"]\n',
    'S = {"attempt_ceiling", "forge_refused", "stopped"}\n',
    'def f(c):\n    return c in ["curator_held", "malformed_row", "unrecorded"]\n',
], ids=["tuple", "literal", "set_across_tables", "list_in_a_function"])
def test_a_second_copy_of_a_cause_list_is_found(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, {"jobs/models.py": src}))
    assert len(found) == 1, found
    assert "second-list" in found[0] and "jobs/models.py:" in found[0], found


@pytest.mark.parametrize("src", [
    "from defender.records.learning_causes import Why\nw = Why('foreign_pr', 'x')\n",
    "from defender.learning_store import Why\nw = Why('foreign_pr', 'x')\n",
    "def f():\n    from defender.learning_store import Why as W\n    return W('stopped', 'x')\n",
    "import defender.records.learning_causes as lc\nw = lc.Why('stopped', 'x')\n",
], ids=["from_owner", "from_store_door", "aliased_in_a_function", "module_attribute"])
def test_a_bare_why_is_found_however_it_is_imported(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, {"learning/tick.py": src}))
    assert len(found) == 1, found
    assert "unchecked-why" in found[0], found


@pytest.mark.parametrize("rel, src", [
    ("learning/tick.py", "from defender.records.learning_causes import Why\nw = Why.batch('foreign_pr', 'x')\n"),
    ("learning/tick.py", "from defender.records.learning_causes import Why\nw = Why.item('curator_held', 'x')\n"),
    ("learning/tick.py", "from mine import Why\nw = Why('foreign_pr', 'x')\n"),
    ("learning/tick.py", 'PAIR = ("forge_refused", "foreign_pr")\n'),
    ("jobs/models.py", "from defender.records.learning_causes import ITEM_CAUSES\nC = ITEM_CAUSES\n"),
    ("migrations/versions/0021_x.py", 'ITEM_CAUSES = ("attempt_ceiling", "curator_held", "malformed_row")\n'),
    ("tests/test_x.py", 'C = ("attempt_ceiling", "curator_held", "malformed_row")\n'),
], ids=["why_batch", "why_item", "unrelated_why", "a_pair_is_not_a_list", "imported_list",
        "migration_frozen_copy", "tests_are_not_swept"])
def test_the_owner_s_spellings_and_out_of_scope_files_have_no_findings(tmp_path, rel, src):
    assert _GATE.scan(_tree(tmp_path, {rel: src})) == []


def test_the_owner_itself_is_not_a_second_list(tmp_path):
    assert _GATE.scan(_tree(tmp_path, {})) == []


#: The shapes #1537's first cut had, trimmed: the table module's tuple, the store's Literal beside its own `Why`, and the
#: tick's bare `Why(...)` behind a helper returning `Any`.
_OLD_MODELS = '''ITEM_CAUSES = (
    "attempt_ceiling", "curator_held", "malformed_row", "unrecorded")
'''
_OLD_STORE = '''from typing import Literal
ItemCause = Literal[
    "attempt_ceiling", "curator_held", "malformed_row", "unrecorded"]
'''
_OLD_TICK = '''from typing import Any
def _store_why(cause: str, detail: str) -> Any:
    from defender.learning_store import Why

    return Why(cause, detail)  # type: ignore[arg-type]
'''


def test_the_shapes_this_gate_was_made_for_are_each_a_finding(tmp_path):
    found = _GATE.scan(_tree(tmp_path, {"jobs/learning_models.py": _OLD_MODELS, "learning_store/_store.py": _OLD_STORE,
                                        "learning/core/store_tick.py": _OLD_TICK}))
    assert sorted(f.split(": ")[0].rsplit(":", 1)[0] + " " + f.split(": ")[1] for f in found) == [
        "jobs/learning_models.py second-list", "learning/core/store_tick.py unchecked-why",
        "learning_store/_store.py second-list"], found


def test_an_owner_without_its_lists_is_exit_2(tmp_path, capsys):
    root = _tree(tmp_path, {"x.py": "X = 1\n"}, owner="X = 1\n")
    assert _GATE.main(["--root", str(root)]) == 2
    assert "defines no" in capsys.readouterr().err


def test_a_missing_owner_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, {"x.py": "X = 1\n"}, owner=None))]) == 2


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, {"x.py": "def (:\n"}))]) == 2


def test_the_real_tree_is_clean():
    assert _GATE.scan(_GATE.DEFENDER) == []
