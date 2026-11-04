"""#1345 machinery check: the default alert mapping every ready-made tenant is seeded with keeps today's four facts."""
from __future__ import annotations

from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING, PLANTED_ALERT_MAPPING
from defender.tests.support.tenancy._tenants1106 import ALERT_MAPPING_TEXT

SIX = ("signature", "event_time", "summary", "case_key", "title", "description")
FACTS = SIX[:4]


def test_the_default_mappings_name_the_six_entries_and_keep_the_planted_files_four_facts() -> None:
    """The seeded default means what the planted `alert-mapping.yaml` meant (its text parsed by the file parser). (#1345 Test notes)"""
    from defender.records._alert_input import parse_mapping

    assert tuple(PLANTED_ALERT_MAPPING) == tuple(FIXTURE_ALERT_MAPPING) == SIX
    assert {k: PLANTED_ALERT_MAPPING[k] for k in FACTS} == dict(parse_mapping(ALERT_MAPPING_TEXT).paths)
    assert {k: v for k, v in FIXTURE_ALERT_MAPPING.items() if PLANTED_ALERT_MAPPING[k] != v} == {"event_time": "alert_timestamp"}
