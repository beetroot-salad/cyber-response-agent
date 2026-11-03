"""Tests for the lint_record_id_columns gate (#1382): a column holding a record id is an `IdColumn` of its family."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_record_id_columns")

#: The id families the lint reads off `records/`: one directly under `UuidId`, one a level further.
_RECORDS = ("class UuidId(str):\n    pass\nclass AlertId(UuidId):\n    pass\n"
            "class Base2(UuidId):\n    pass\nclass TenantId(Base2):\n    pass\n")
_NEW = ("class AlertRow(Base):\n    __tablename__ = 'alerts'\n"
        "    id: Mapped[AlertId] = mapped_column(IdColumn(AlertId), primary_key=True)\n"
        "    title: Mapped[str] = mapped_column(Text)\n")
#: The pattern #1382 removed: a free-text record id.
_OLD = ("class AlertRow(Base):\n    __tablename__ = 'alerts'\n"
        "    id: Mapped[str] = mapped_column(Text, primary_key=True)\n")


def _tree(tmp_path: Path, **files: str) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"records__ids.py": _RECORDS, **files}.items():
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


#: A reference column, declared each way: (annotation, column, found?).
_REFERENCES = {
    "id-column": ("Mapped[TenantId]", "IdColumn(TenantId)", False),
    "optional": ("Mapped[TenantId | None]", "IdColumn(TenantId)", False),
    "text": ("Mapped[TenantId]", "Text", True),
    "optional-text": ("Mapped[TenantId | None]", "Text", True),
    "wrong-family": ("Mapped[TenantId]", "IdColumn(AlertId)", True),
    "free-text-not-an-id": ("Mapped[str]", "Text", False),
}


@pytest.mark.parametrize("case", sorted(_REFERENCES))
def test_a_reference_column_is_held_to_its_annotated_family(tmp_path, case):
    """Not only `id`: a column annotated with an id family, foreign key or not, is that family's
    `IdColumn` (a column referring to an id with no foreign key once escaped the rule)."""
    annotation, column, found = _REFERENCES[case]
    src = _NEW + f"    tenant_id: {annotation} = mapped_column({column})\n"
    findings = _GATE.scan(_tree(tmp_path, **{"m.py": src}))
    assert bool(findings) is found, findings
    if found:
        assert "`tenant_id`" in findings[0] and "IdColumn(TenantId)" in findings[0], findings


def test_a_family_is_found_through_an_intermediate_base(tmp_path):
    """`TenantId` descends from `UuidId` through another class: still a family."""
    assert _GATE._families(_tree(tmp_path)) == {"AlertId", "Base2", "TenantId"}


def test_a_tree_with_no_family_is_a_finding(tmp_path):
    root = tmp_path / "defender"
    (root / "records").mkdir(parents=True)
    (root / "m.py").write_text(_NEW, encoding="utf-8")
    found = _GATE.scan(root)
    assert found and "re-site" in found[0]


def test_a_tree_with_no_table_is_a_finding(tmp_path):
    found = _GATE.scan(_tree(tmp_path, **{"m.py": "x = 1\n"}))
    assert found and "re-site" in found[0]


def test_this_checkout_is_clean():
    assert _GATE.scan(_GATE.DEFENDER) == []
