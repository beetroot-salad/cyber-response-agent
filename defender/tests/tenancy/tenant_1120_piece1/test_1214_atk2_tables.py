# ruff: noqa: PT018
"""#1214 W4-3 (owner ruling): `accept_tenant` itself parses the two reviewed tables, `verb-grants.yaml` and `lead-zero.yaml`;
`parse_tables=False` is the one opt-out (`validate_scaffold`). Asserted on `accept_tenant`, not through a consumer's own parse."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.records._tenant_id import TenantRefused
from defender.tenancy import _tenant
from defender.tests.support.shared._locations_1210 import fixture_data_root
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: table -> (its one known top-level key, a value for it)
TABLES = {"verb-grants.yaml": "dispositions", "lead-zero.yaml": "correlation_template"}


def _damages(key: str) -> dict[str, str]:
    return {
        "torn": f"{key}:\n  a: {{b: [c\n",
        "not a mapping": "- one\n- two\n",
        "duplicate key": f"{key}: {{}}\n{key}: {{}}\n",
        "unknown top-level key": f"{key}: {{}}\natk2_unknown_key: 1\n",
    }


CASES = [pytest.param(table, damage, id=f"{table}:{damage}")
         for table, key in TABLES.items() for damage in _damages(key)]


def _accept(root: Path, **kw: bool) -> object:
    return _tenant.accept_tenant(fixture_data_root(root), H.TID, defender_dir=H.DEFENDER, box_mounted=(), **kw)


@pytest.mark.parametrize(("table", "damage"), CASES)
def test_accept_tenant_refuses_a_damaged_reviewed_table_naming_the_file(data_root: Path, table: str, damage: str) -> None:
    """A torn, non-mapping, duplicate-key or unknown-key table is a `TenantRefused` naming it; the untouched tenant is
    accepted first (control), and `parse_tables=False` accepts the damaged one."""
    H.adopted(data_root)
    assert _accept(data_root) is not None, "control: the placed tenant is accepted"
    (H.settings_dir(data_root) / table).write_text(_damages(TABLES[table])[damage], encoding="utf-8")
    with pytest.raises(TenantRefused) as refused:
        _accept(data_root)
    assert table in str(refused.value), str(refused.value)
    assert _accept(data_root, parse_tables=False) is not None
