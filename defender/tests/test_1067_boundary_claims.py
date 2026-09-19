"""Review hardening for the #1067 remainder port (found in review on PR #1075).

Three places where a PRODUCER already declared the type of what it hands out and never checked
it. Under stdlib `@dataclass` the records built from those values carried the lie in silence;
under `@model` each record checks its fields, so the lie surfaced as a `ValidationError` out of
readers documented to tolerate malformed input. The fix each time is at the producer — one check
where the claim is made — not a loosened annotation on the record or a wrapper at each consumer:

1. `_frontmatter.split_frontmatter` returns `dict[str, Any]` but only checked "is a mapping". YAML
   hands a mapping non-string keys freely (`on:` is `True` under YAML 1.1, a bare date is a `date`),
   and `ReportRead.frontmatter` / `Lesson.fm` now refuse them. The parser refuses them first, as the
   `FrontmatterError` every frontmatter reader already handles.
2. `oracle_golden.judge.load_lead_inputs` did `safe_load(...) or {}` and called it a `dict`; a
   list-rooted `environment.yaml` reached `LeadInputs.environment_notes: dict`.
3. `record_query.repeat_trip` kept `seq` values that pass `isinstance(_, int)` — which a `bool`
   does — and `RepeatTrip.first_seq: int | None` refuses `True`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender._corpus import iter_lessons
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._report import parse_report_text
from defender.evals.oracle_golden import judge
from defender.scripts.gather_tools import record_query as rq
from defender.tests.test_826_deferred_defects import LEAD, _row


@pytest.mark.parametrize(("key", "spelled"), [
    ("on", "True"),                  # YAML 1.1 bool
    ("2024-01-01", "datetime.date"),  # timestamp scalar
    ("1", "1"),                       # int
])
def test_frontmatter_refuses_a_non_string_key_as_a_frontmatter_error(key, spelled):
    """The parser's own `dict[str, Any]` claim, enforced where it is made. Refused as
    `FrontmatterError` — the class every reader already treats as "malformed frontmatter" —
    and the message names the offending key so the author can quote it."""
    with pytest.raises(FrontmatterError, match="non-string key") as info:
        split_frontmatter(f"---\ndisposition: benign\n{key}: x\n---\nbody\n")
    assert spelled in str(info.value)
    # A quoted key is a string and parses; the check is on the KEY TYPE, not the spelling.
    fm, _raw, _body = split_frontmatter(f"---\n'{key}': x\n---\nbody\n")
    assert fm == {key: "x"}


def test_read_report_stays_total_over_a_non_string_frontmatter_key():
    """`parse_report_text` is documented "never raises". A report whose frontmatter carries a
    date key (it passes `validate_report`, which checks only `disposition`) must come back as a
    no-headline read with the reason, not as a `ValidationError` from `ReportRead`."""
    text = "---\ndisposition: benign\n2024-01-01: x\n---\nbody\n"
    read = parse_report_text(text)
    assert read.disposition is None
    assert read.reason is not None
    assert "non-string key" in read.reason
    assert read.text == text


def test_iter_lessons_warn_skips_a_lesson_with_a_non_string_key(tmp_path, capsys):
    """One bad lesson costs that row and never the walk (#584's contract): a date-keyed lesson
    is warn-skipped BY NAME alongside its well-formed sibling, and reaches `on_skip`."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "good.md").write_text("---\nname: good\n---\nbody\n")
    (d / "dated.md").write_text("---\nname: dated\n2024-05-01: rotated\n---\nbody\n")
    skipped: list[Path] = []
    yielded = [lesson.path.name for lesson in iter_lessons(d, on_skip=skipped.append)]
    assert yielded == ["good.md"]
    assert [p.name for p in skipped] == ["dated.md"]
    assert "dated.md" in capsys.readouterr().err


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
