"""#1120 piece 1 — pass A's no-default-tenant (O1) and one-row-writer (O2) censuses see
#1120's API (code review, max; spec PD1's promised re-plumb).

O1 keyed on the removed `TenantPaths` and friends, so a hardcoded id handed to
`accept_tenant`, `accept_placed_knowledge`, `_TenantPaths`, `resolve_tenant` or as `raw_id=`
went unseen. O2 tainted only `.row`, so a write through `Tenant.row_path` went unseen.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.tenant_1078_pass_a import _census_1078 as C

_SPELLINGS = {
    "accept_tenant": 'accept_tenant(root, "playground", defender_dir=d)',
    "accept_placed_knowledge": 'accept_placed_knowledge(root, "playground", defender_dir=d)',
    "_TenantPaths": '_TenantPaths(root, "playground")',
    "resolve_tenant": 'resolve_tenant(root, "playground", defender_dir=d)',
    "raw_id": 'accept_tenant(root, raw_id="playground", defender_dir=d)',
}


def _plant(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("name", sorted(_SPELLINGS))
def test_o1_sees_a_literal_id_handed_to_the_new_entry_points(tmp_path: Path, name: str) -> None:
    """Each spelling planted alone is a finding; the same call threading a variable is not."""
    hit = _plant(tmp_path, f"defender/{name}.py", f"def f(root, d):\n    return {_SPELLINGS[name]}\n")
    threaded = _plant(tmp_path, "defender/threaded.py",
                      _SPELLINGS[name].replace('"playground"', "tid").join(
                          ["def f(root, d, tid):\n    return ", "\n"]))
    assert C.o1_python_findings(hit, f"defender/{name}.py"), f"O1 misses {_SPELLINGS[name]}"
    assert not C.o1_python_findings(threaded, "defender/threaded.py")


def test_o2_sees_a_write_through_row_path(tmp_path: Path) -> None:
    """A rogue writer of `tenant.row_path` is a finding; a reader of it is not."""
    writer = _plant(tmp_path, "defender/writer.py",
                    "from defender._io import write_guarded\n\ndef forge(tenant):\n"
                    "    write_guarded(tenant.row_path, '{}', mode='replace')\n")
    reader = _plant(tmp_path, "defender/reader.py",
                    "def look(tenant):\n    return tenant.row_path.read_text()\n")
    found = C.o2_row_writers([writer, reader], root=tmp_path)
    assert any("writer.py" in f for f in found), found
    assert not any("reader.py" in f for f in found), found
