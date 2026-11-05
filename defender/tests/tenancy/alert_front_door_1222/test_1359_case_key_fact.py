"""#1359 the alert's `case_key` fact: read once at run start through the tenant's mapping and
recorded; a key that is not one URL path segment records none."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.records import _alert_input as A
from defender.records._alert_mapping_file import parse_mapping
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
    facts = A.derive_facts(admitted.document, parse_mapping(mapping_text))
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
    """`case_key` is a mapping key like the others: a dotted path is accepted, a malformed path or an unknown key is not.
    Fact case_key. (r5: `parse_mapping` is now the file format of `tenant.py set-alert-mapping`, O6; the refusals name the entry, not the retired file.)"""
    assert parse_mapping(MAPPING_TEXT).path_of(CASE_KEY) == "ticket.key"
    for bad in ('case_key: ""', "case_key: 42", "case_key: ticket..key", "case_key: [ticket.key]",
                "case_key: ' ticket.key'"):
        with pytest.raises(A.AlertMappingFault, match="case_key"):
            parse_mapping(f"signature: rule.id\n{bad}\n")
    with pytest.raises(A.AlertMappingFault):
        parse_mapping(f"{MAPPING_TEXT}severity: rule.severity\n")


def test_the_alert_mapping_file_takes_the_six_entries_and_a_four_entry_file_leaves_the_new_two_unmapped():
    """r5 O6: `title` and `description` are file entries too (same path rules); a file without them, today's format, maps
    only what it names. (#1345 O6, D3)"""
    six = parse_mapping(f"{MAPPING_TEXT}title: rule.description\ndescription: rule.id\n")
    assert (six.path_of("title"), six.path_of("description")) == ("rule.description", "rule.id")
    four = parse_mapping(MAPPING_TEXT)
    assert (four.path_of("title"), four.path_of("description")) == (None, None)
    for bad in ("title: a..b", "description: ' x'", "title: 7", "description: ''"):
        entry = bad.split(":")[0]
        with pytest.raises(A.AlertMappingFault, match=entry):
            parse_mapping(f"{MAPPING_TEXT}{bad}\n")


#: Entry names the mapping takes, and others a lenient validator might let through.
OTHER_NAMES = ["", "Title", "title ", "case-key", "extra", "alert_mapping", "0"]
NON_TEXT = [0, 1, -1, True, False, 1.5, [], ["a"], {}, {"a": "b"}, b"a", ("a",), object]
#: Whitespace by Python's own definition, every one: in front of, behind, around and inside an otherwise good path.
WHITESPACE = [chr(c) for c in range(0x110000) if chr(c).isspace()]
BAD_SEGMENTS = ["", ".", "..", ".a", "a.", "a..b", "a.b.", "..a", "a...b"]
UNHOLDABLE = ["a\x00b", "\x00", "a.\x00", "\ud800", "a\udfffb", "a.\ud83d.b"]
GOOD = ["a", "a.b", "rule.id", "a b", "x.y.z", "\u00e9.\U0001d4b7", "0", "a-b.c_d"]


def _mapping_values() -> list[object]:
    values: list[object] = [None, *NON_TEXT, *BAD_SEGMENTS, *UNHOLDABLE, *GOOD]
    for space in WHITESPACE:
        values += [f"{space}a.b", f"a.b{space}", f"{space}a.b{space}", f"a{space}b", f"a.{space}.b", space]
    return values


def _oracle_accepts(key: object, value: object) -> bool:
    """The design's rule, written out: a known entry; unmapped, or text of at most 512 characters, with no control
    character, whose dot-segments are non-empty and not set in whitespace at either end, and that PostgreSQL can hold
    (no lone surrogate)."""
    if key not in A.MAPPING_KEYS:
        return False
    if value is None:
        return True
    if not isinstance(value, str) or not value or len(value) > 512:
        return False
    if any(part == "" or part[0].isspace() or part[-1].isspace() for part in value.split(".")):
        return False
    return not any(ord(c) < 0x20 or ord(c) == 0x7F or 0xD800 <= ord(c) <= 0xDFFF for c in value)


def test_the_mapping_check_accepts_exactly_the_rule_and_every_refusal_names_the_entry():
    """Over every entry name, none included, with every value shape and every whitespace, NUL, lone-surrogate and
    empty-segment path, `check_mapping` accepts what the rule does and names the entry in each refusal. (#1345 O1, M2)"""
    wrong: list[str] = []
    for key in [*A.MAPPING_KEYS, *OTHER_NAMES]:
        for value in _mapping_values():
            shown = f"{key!r}: {value!r}"[:80]
            try:
                got = A.check_mapping({key: value})
            except A.AlertMappingFault as refusal:
                if _oracle_accepts(key, value):
                    wrong.append(f"refused {shown}")
                elif key and key not in str(refusal):
                    wrong.append(f"refusal for {shown} does not name the entry: {refusal}")
                continue
            except Exception as error:  # noqa: BLE001 — any other failure is a defect to name
                wrong.append(f"{shown} raised {type(error).__name__}")
                continue
            if not _oracle_accepts(key, value):
                wrong.append(f"accepted {shown}")
            elif got.paths != ({} if value is None else {key: value}):
                wrong.append(f"accepted {shown} but kept {dict(got.paths)!r}")
    assert len(wrong) == 0, f"{len(wrong)} disagreements with the rule, first: {wrong[:5]}"


def test_1345_a_repeated_entry_in_the_mapping_file_is_refused_naming_it():
    """YAML would silently keep the last of the two, so an operator's first path would never be used. (#1345 O6)"""
    with pytest.raises(A.AlertMappingFault, match="signature"):
        parse_mapping("signature: rule.id\ntitle: rule.description\nsignature: other.path\n")


@pytest.mark.parametrize("path", [
    "rule. id", "rule .id", " rule", "rule ", "a\n.b", "a.b\n", "a\tb", "a\x00b", "a\x7fb", "..", "a.", ".a", "", "x" * 513,
])
def test_1345_a_path_with_whitespace_around_a_segment_a_control_character_or_too_long_is_refused(path):
    """One definition of a path: a typo that could never match is refused when it is saved, naming the entry. (#1345 O1)"""
    with pytest.raises(A.AlertMappingFault, match="title"):
        A.check_mapping({"title": path})


@pytest.mark.parametrize("path", ["rule.id", "Source IP", "event.Source IP.value", "règle.id", "a" * 512, "a-b_c/d:e"])
def test_1345_a_path_may_hold_a_space_inside_a_key_and_finds_that_key(path):
    """Alert keys can hold spaces, so a space inside a segment is a real path; a walk reaches the value. (#1345 O1)"""
    assert A.check_mapping({"title": path}).path_of("title") == path
    document: dict = {}
    *parents, leaf = path.split(".")
    node = document
    for parent in parents:
        node = node.setdefault(parent, {})
    node[leaf] = "found"
    assert A.derive_display(document, A.AlertMapping(paths={"title": path})) == ("found", None)


@pytest.mark.parametrize("blank", ["   ", "\n\t ", "\u00a0"])
def test_1345_whitespace_only_text_is_no_value_for_a_display_field_or_a_fact(blank):
    """A blank title would read as a title and show no name; it is no value, so the ticket id stands in. (#1345 O2)"""
    mapping = A.AlertMapping(paths={"title": "t", "description": "t", "summary": "t", "event_time": "t"})
    document = {"t": blank}
    assert A.derive_display(document, mapping) == (None, None)
    facts = A.derive_facts(document, mapping)
    assert (facts.summary, facts.event_time) == (None, None)


def test_1345_reading_alerts_and_tenant_records_does_not_load_a_yaml_parser():
    """The mapping file is read only by one command: what a run's start and the tenant records import stays free of YAML,
    and works with none installed, as `run.py` needs before it re-executes into the venv. (#1345, #1315)"""
    program = (
        "import sys\n"
        "class Refuse:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] == 'yaml':\n"
        "            raise ImportError('yaml refused')\n"
        "sys.meta_path.insert(0, Refuse())\n"
        "from defender.records.formats import ALERT_MAPPING_MISSING, AlertMapping, DataRoot, RunsBase, TenantId\n"
        "import defender.tenancy._directory\n"
        "assert 'yaml' not in sys.modules\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[4])}
    done = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True, timeout=60, check=False, env=env)
    assert done.returncode == 0, done.stderr
