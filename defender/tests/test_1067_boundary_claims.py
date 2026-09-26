"""Review hardening for the #1067 remainder port (found in review on PR #1075).

Three places where a value's declared type and its actual provenance disagreed. Under stdlib
`@dataclass` the records built from those values carried the disagreement in silence; under
`@model` each record checks its fields, so it surfaced as a `ValidationError` out of readers
documented to tolerate malformed input. Each fix is at the one place the claim is made:

1. `ReportRead.frontmatter` and `Lesson.fm` claimed `str` keys, but they hold the mapping AS
   YAML BUILT IT — `on:` is `True` under YAML 1.1, a bare date is a `date` — and the report write
   gate accepts such keys by test (`test_permission_report_629`: a `1:`/`"1":` pair and a date key
   both commit). The claim was the lie; the fields now say `Any`, and the readers stay total.
2. `oracle_golden.judge.load_lead_inputs` did `safe_load(...) or {}` and called it a `dict`; a
   list-rooted `environment.yaml` reached `LeadInputs.environment_notes: dict`. Refused at the
   load, naming the file.
3. `record_query.repeat_trip` kept `seq` values that pass `isinstance(_, int)` — which a `bool`
   does — and `RepeatTrip.first_seq: int | None` refuses `True`. `_text.as_int` is now the one
   spelling of "an int that is not a bool", beside `as_str`.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from defender._corpus import iter_lessons
from defender._report import parse_report_text
from defender._text import as_int
from defender.evals.oracle_golden import judge
from defender.scripts.gather_tools import record_query as rq
from defender.tests.test_826_deferred_defects import LEAD, _row

#: The keys YAML 1.1 builds as something other than `str`, each paired with what it builds.
_ODD_KEYS = (("on", True), ("2024-01-01", datetime.date(2024, 1, 1)), ("1", 1))


@pytest.mark.parametrize(("spelled", "built"), _ODD_KEYS)
def test_read_report_stays_total_over_a_non_string_frontmatter_key(spelled, built):
    """`parse_report_text` is documented "never raises", and the write gate lets these keys
    through — so the read must hand back the headline and the mapping as YAML built it, not a
    `ValidationError` from `ReportRead`'s constructor."""
    text = f"---\ndisposition: benign\n{spelled}: x\n---\nbody\n"
    read = parse_report_text(text)
    assert read.disposition == "benign"
    assert read.reason is None
    assert read.frontmatter[built] == "x"
    assert read.text == text


@pytest.mark.parametrize(("spelled", "built"), _ODD_KEYS)
def test_iter_lessons_yields_a_lesson_with_a_non_string_key(spelled, built, tmp_path, said):
    """The walk's contract is one bad file costs that row and never the walk (#584) — and a
    non-string key is not even a bad file to the parser, so the lesson is YIELDED, its mapping
    as YAML built it, with nothing on stderr."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "good.md").write_text("---\nname: good\n---\nbody\n")
    (d / "odd.md").write_text(f"---\nname: odd\n{spelled}: rotated\n---\nbody\n")
    yielded = list(iter_lessons(d))
    assert [lesson.path.name for lesson in yielded] == ["good.md", "odd.md"]
    assert yielded[1].fm[built] == "rotated"
    assert said.readouterr().err == ""


def test_as_int_is_an_int_that_is_not_a_bool():
    assert as_int(3) == 3
    assert as_int(0) == 0
    assert as_int(True) is None
    assert as_int(False) is None
    assert as_int("3") is None
    assert as_int(None) is None


def test_repeat_trip_ignores_a_boolean_seq_instead_of_refusing():
    """A planted `"seq": true` in the box-writable queries table is an `int` to `isinstance`;
    the guard must still trip (the repeat is real) and name the earliest INTEGER seq, exactly
    as it does for a row with no `seq` at all."""
    rows = [_row(0), _row(1)]
    rows[0]["seq"] = True
    trip = rq.repeat_trip(rows, LEAD, system="elastic", verb="query",
                          params={"native_query": "FROM logs"})
    assert trip == rq.RepeatTrip(first_seq=1, occurrence=rq.REPEAT_THRESHOLD)
    for r in rows:
        r["seq"] = True
    trip = rq.repeat_trip(rows, LEAD, system="elastic", verb="query",
                          params={"native_query": "FROM logs"})
    assert trip == rq.RepeatTrip(first_seq=None, occurrence=rq.REPEAT_THRESHOLD)


def _case(tmp_path: Path, environment: str) -> Path:
    case_dir = tmp_path / "case-001"
    visible = case_dir / "oracle_visible"
    visible.mkdir(parents=True)
    (visible / "leads.jsonl").write_text(json.dumps({"lead_id": "l-001", "goal": "g"}) + "\n")
    (visible / "story.md").write_text("story\n")
    (case_dir / "environment.yaml").write_text(environment)
    return case_dir


def test_lead_inputs_refuses_a_non_mapping_environment_naming_the_file(tmp_path):
    """`environment.yaml` is a mapping by contract (`validate_cases.check_environment` reads keys
    off it). A list-rooted file is refused at the load with the path in the message, before
    `LeadInputs` is built — and a mapping still flows through unchanged."""
    ok = judge.load_lead_inputs(_case(tmp_path, "capture_environment: lab\n"), "l-001")
    assert ok.environment_notes == {"capture_environment": "lab"}

    listed = _case(tmp_path / "listed", "- note one\n- note two\n")
    with pytest.raises(ValueError, match="environment.yaml must be a YAML mapping") as info:
        judge.load_lead_inputs(listed, "l-001")
    assert str(listed / "environment.yaml") in str(info.value)
    assert "list" in str(info.value)
