"""Tests for the lint_record_id_columns gate (#1382): an ORM table's own `id` is an `IdColumn`."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_record_id_columns")

_NEW = ("class AlertRow(Base):\n    __tablename__ = 'alerts'\n"
        "    id: Mapped[AlertId] = mapped_column(IdColumn(AlertId), primary_key=True)\n"
        "    title: Mapped[str] = mapped_column(Text)\n")
#: The pattern #1382 removed: a free-text record id.
_OLD = ("class AlertRow(Base):\n    __tablename__ = 'alerts'\n"
        "    id: Mapped[str] = mapped_column(Text, primary_key=True)\n")


def _tree(tmp_path: Path, **files: str) -> Path:
    root = tmp_path / "defender"
    for rel, text in files.items():
        path = root / rel.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_an_id_column_table_is_clean(tmp_path):
    assert _GATE.scan(_tree(tmp_path, **{"jobs__models.py": _NEW})) == []


def test_the_free_text_id_is_found(tmp_path):
    found = _GATE.scan(_tree(tmp_path, **{"jobs__models.py": _NEW, "other__models.py": _OLD}))
    assert len(found) == 1 and "other/models.py:3" in found[0] and "`Text`" in found[0], found


@pytest.mark.parametrize("column", ["String(36)", "Uuid(as_uuid=False)", "sa.Text()"])
def test_any_other_id_type_is_found(tmp_path, column):
    src = _OLD.replace("Text,", f"{column},")
    assert len(_GATE.scan(_tree(tmp_path, **{"m.py": _NEW, "n.py": src}))) == 1


def test_a_table_keyed_otherwise_and_tests_are_not_swept(tmp_path):
    keyed = ("class Session(Base):\n    __tablename__ = 's'\n"
             "    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)\n")
    assert _GATE.scan(_tree(tmp_path, **{"m.py": _NEW, "s.py": keyed, "tests__t.py": _OLD})) == []


def test_a_tree_with_no_table_is_a_finding(tmp_path):
    found = _GATE.scan(_tree(tmp_path, **{"m.py": "x = 1\n"}))
    assert found and "re-site" in found[0]


def test_this_checkout_is_clean():
    assert _GATE.scan(_GATE.DEFENDER) == []
