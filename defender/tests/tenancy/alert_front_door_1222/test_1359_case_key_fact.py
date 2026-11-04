"""#1359 the alert's `case_key` fact: read once at run start through the tenant's mapping and
recorded; a key that is not one URL path segment records none."""
from __future__ import annotations

import json
from typing import Any

import pytest

from defender.records import _alert_input as A
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

#: The design's fact name (not in `S.FACTS`, which is the three-fact contract).
CASE_KEY = "case_key"
MAPPING = {**S.DEFAULT_MAPPING_GENERIC, CASE_KEY: "ticket.key"}
MAPPING_TEXT = "signature: rule.id\ncase_key: ticket.key\n"
MAX_LEN = 128
#: r4 Data + D-1: printable ASCII (33..126) without `/`, `\` and `;` (the credential proxy refuses
#: any `;` in a decoded path, so such a key could never be sent); whitespace and controls are outside it.
SEGMENT_SAFE = {chr(c) for c in range(33, 127)} - {"/", "\\", ";"}
#: Characters outside ASCII that a lenient implementation might let through.
NON_ASCII = ("é", " ", " ", "​", "／")


def _record_of(alert: dict[str, Any], mapping_text: str = MAPPING_TEXT) -> dict[str, Any]:
    """The record the front door writes for `alert` through `mapping_text`, as its JSON."""
    admitted = A.admit(json.dumps(alert).encode("utf-8"))
    facts = A.derive_facts(admitted.document, A.parse_mapping(mapping_text))
    return json.loads(A.record_text(admitted.digest, facts))


def _recorded(key: object) -> object:
    return _record_of({"rule": {"id": "R-1"}, "ticket": {"key": key}}).get(CASE_KEY, "<absent>")


def test_case_key_is_recorded_from_the_mapped_field_or_absent(tmp_path):
    """Through `run.main`, a key-shaped value is the run's case_key; a separator or whitespace records none. Fact case_key."""
    planted = S.plant_tenant(fixture_uuid("tenant:c1359"), alert_mapping=MAPPING)
    seen = {}
    for label, alert in (("ok", S.generic_alert(ticket={"key": "SOC-4471"})),
                         ("slash", S.generic_alert(ticket={"key": "SOC/4471"})),
                         ("space", S.generic_alert(ticket={"key": "SOC 4471"})),
                         ("no field", S.generic_alert()),
                         ("decoy", S.generic_alert(alert_id="A-9", rule_id="R-1001"))):
        d = S.run_alert(tmp_path / label.replace(" ", "-"), tenant=planted, alert=alert)
        assert d.run_dir is not None, (
            f"[{label}] the run got no folder: rc={d.rc} refusal={d.refusal} raised={d.raised}")
        seen[label] = S.read_record(d.run_dir)
    assert seen["ok"].get(CASE_KEY) == "SOC-4471"
    for label in ("slash", "space", "no field", "decoy"):
        assert CASE_KEY not in seen[label], (label, seen[label])


def test_case_key_is_never_taken_from_an_unmapped_field(tmp_path):
    """With no `case_key` entry in the mapping the run records none, whatever the alert carries. Fact case_key."""
    planted = S.plant_tenant(fixture_uuid("tenant:c1359b"), alert_mapping=S.DEFAULT_MAPPING_GENERIC)
    d = S.run_alert(tmp_path, tenant=planted, alert=S.generic_alert(
        ticket={"key": "SOC-4471"}, case_key="SOC-1", alert_id="SOC-2"))
    assert d.run_dir is not None, f"rc={d.rc} refusal={d.refusal} raised={d.raised}"
    assert CASE_KEY not in S.read_record(d.run_dir)


@pytest.mark.parametrize("code", range(128))
def test_case_key_admits_exactly_the_segment_safe_ascii(code):
    """Every ASCII character, embedded in a key, is kept iff it is printable and not `/`, `\\`, `;` or space. Fact case_key (D-1)."""
    key = f"K{chr(code)}K"
    want = key if chr(code) in SEGMENT_SAFE else "<absent>"
    assert _recorded(key) == want


@pytest.mark.parametrize("char", NON_ASCII)
def test_case_key_refuses_non_ascii(char):
    """A key holding a non-ASCII character records none. Fact case_key."""
    assert _recorded(f"K{char}K") == "<absent>"


@pytest.mark.parametrize(("key", "kept"), [
    ("K", True), ("K" * MAX_LEN, True), ("K" * (MAX_LEN + 1), False), ("K" * 4096, False),
    ("", False),
    (".", False), ("..", False), ("...", False), ("." * MAX_LEN, False),
    (".a", True), ("a.", True), ("a..b", True), ("...x", True), ("v1.2.3", True),
])
def test_case_key_length_bound_and_dot_only_refusal(key, kept):
    """128 characters are kept, 129 are not; a key made only of dots is refused (curl collapses it). Fact case_key."""
    assert _recorded(key) == (key if kept else "<absent>")


@pytest.mark.parametrize("value", [True, False, None, 1.5, [], ["SOC-1"], {}, {"k": "SOC-1"}])
def test_case_key_refuses_a_value_that_is_not_text_or_an_integer(value):
    """A mapped boolean, float, null, list or object records no key. Fact case_key (D-3)."""
    assert _recorded(value) == "<absent>"


@pytest.mark.parametrize(("value", "text"), [(4471, "4471"), (0, "0"), (-5, "-5"),
                                             (10 ** 127, "1" + "0" * 127)])
def test_case_key_records_an_integer_as_its_decimal_text(value, text):
    """Alert ids are often numeric: an integer value is recorded as its decimal text, and held to
    the same shape rules (an integer too long to be a key records none). Fact case_key (D-3)."""
    assert _recorded(value) == text
    assert _recorded(10 ** 128) == "<absent>"


def test_older_records_carry_no_case_key_and_still_read():
    """A record written before the fact existed reads as a record; a run with no key writes none. Fact case_key."""
    digest = "a" * 64
    old = json.dumps({"digest": digest, "signature": "R-1"})
    assert A.parse_alert_record(old) is not None
    assert A.parse_alert_record(json.dumps({"digest": digest, CASE_KEY: "SOC-1"})) is not None
    assert CASE_KEY not in _record_of({"rule": {"id": "R-1"}})


def test_the_alert_mapping_accepts_the_fourth_fact_and_holds_it_to_the_path_rules():
    """`case_key` is a mapping key like the others: a dotted path is accepted, a malformed path or an unknown key is not. Fact case_key."""
    assert A.parse_mapping(MAPPING_TEXT).path_of(CASE_KEY) == "ticket.key"
    for bad in ('case_key: ""', "case_key: 42", "case_key: ticket..key", "case_key: [ticket.key]",
                "case_key: ' ticket.key'"):
        with pytest.raises(A.AlertMappingFault, match="alert-mapping.yaml"):
            A.parse_mapping(f"signature: rule.id\n{bad}\n")
    with pytest.raises(A.AlertMappingFault, match="alert-mapping.yaml"):
        A.parse_mapping(f"{MAPPING_TEXT}severity: rule.severity\n")
