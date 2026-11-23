# ruff: noqa: PT018
"""#1214 W4-3 (owner ruling): the tenant check itself parses the reviewed table, `verb-grants.yaml` (#1503 retired
`lead-zero.yaml`), not a consumer's own parse. #1618 K8: a tenant holds no knowledge folder, so `accept_tenant` judges `<T>`
alone; the table parse is one of the folder rules, which stand unchanged (K6) in `check_knowledge_folder`
(`tenant.py check --folder`), so this drives that over the placed `<T>/knowledge`."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.records._tenant_id import TenantRefused
from defender.tenancy import _tenant
from defender.tests.support.shared._locations_1210 import fixture_data_root
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: table -> (its one known top-level key, a value for it)
TABLES = {"verb-grants.yaml": "dispositions"}


def _damages(key: str) -> dict[str, str]:
    return {
        "torn": f"{key}:\n  a: {{b: [c\n",
        "not a mapping": "- one\n- two\n",
        "duplicate key": f"{key}: {{}}\n{key}: {{}}\n",
        "unknown top-level key": f"{key}: {{}}\natk2_unknown_key: 1\n",
    }


CASES = [pytest.param(table, damage, id=f"{table}:{damage}")
         for table, key in TABLES.items() for damage in _damages(key)]


def _accept(root: Path) -> object:
    return _tenant.accept_tenant(fixture_data_root(root), H.TID, defender_dir=H.DEFENDER, box_mounted=())


def _check(root: Path) -> None:
    """The folder rules over the placed `<T>/knowledge`, held to the tenant's id (#1618 K8, K6)."""
    _tenant.check_knowledge_folder(H.knowledge_dir(root), tenant_id=_tenant.TenantId(H.TID))


@pytest.mark.parametrize(("table", "damage"), CASES)
def test_the_folder_rules_refuse_a_damaged_reviewed_table_naming_the_file(data_root: Path, table: str, damage: str) -> None:
    """A torn, non-mapping, duplicate-key or unknown-key table is a `TenantRefused` naming it; the untouched folder
    passes first (control), and the tenant is accepted (#1618 K8: acceptance reads no table)."""
    H.adopted(data_root)
    assert _accept(data_root) is not None, "control: the placed tenant is accepted"
    assert _check(data_root) is None, "control: the untouched folder passes the folder rules"
    (H.settings_dir(data_root) / table).write_text(_damages(TABLES[table])[damage], encoding="utf-8")
    with pytest.raises(TenantRefused) as refused:
        _check(data_root)
    assert table in str(refused.value), str(refused.value)
