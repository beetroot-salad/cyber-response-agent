"""#1359 the alert's `case_key` fact: read once at run start through the tenant's mapping and
recorded; a key that is not one URL path segment records none."""
from __future__ import annotations

from pathlib import Path

from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.support.shared._fixture_uuid import fixture_uuid

#: The design's fact name (not in `S.FACTS`, which is the three-fact contract).
CASE_KEY = "case_key"
MAPPING = {**S.DEFAULT_MAPPING_GENERIC, CASE_KEY: "ticket.key"}


def _case_key(tmp_path: Path, planted: S.Planted, key: str) -> str | None:
    d = S.run_alert(tmp_path / key.encode().hex()[:16], tenant=planted,
                    alert=S.generic_alert(ticket={"key": key}))
    assert d.run_dir is not None, f"the run got no folder: rc={d.rc} refusal={d.refusal} raised={d.raised}"
    value = S.read_record(d.run_dir).get(CASE_KEY)
    assert value is None or isinstance(value, str), value
    return value


def test_case_key_is_recorded_from_the_mapped_field_or_absent(tmp_path):
    """A key-shaped value is recorded as the run's case_key; one with a separator or whitespace records none. Fact case_key."""
    planted = S.plant_tenant(fixture_uuid("tenant:c1359"), alert_mapping=MAPPING)
    assert _case_key(tmp_path, planted, "SOC-4471") == "SOC-4471"
    assert _case_key(tmp_path, planted, "SOC/4471") is None
    assert _case_key(tmp_path, planted, "SOC 4471") is None
