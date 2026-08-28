"""#785 — one typed accessor for `report.md`'s frontmatter.

The report's frontmatter had one parser and six interpreters, and they disagreed on the same
bytes: three different reactions to a missing or invalid disposition, and only ONE of the six
still applied #722's zero-width strip. Alert data is attacker-influenced by definition, so a
disposition carrying an injected zero-width character read differently depending on which
consumer looked at it.

What these tests pin is the resolution, which is deliberately not "make all six identical":

  * INTERPRETATION is one decision — what a disposition value MEANS, strip included.
  * REACTION stays per-consumer, by kind — a gate that opens a real ticket or feeds a learning
    corpus must refuse; a view or a metric must degrade so one broken report costs its own row
    and not the page or the score.

The write gate is deliberately NOT folded in: it stays exact, because on write there is still
an author to send actionable retry text to.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests._by_path import load_trace_lesson

import pytest

from defender._artifact_schema import validate_report
from defender._report import (
    UNKNOWN_DISPOSITION,
    ReportUnreadable,
    read_report,
    require_report,
)
from defender._vocab import normalized_disposition
from defender.evals.held_out import predicted_disposition
from defender.learning.core.directions import directions_for
from defender.learning.core.validate import normalize_disposition
from defender.learning.core.config import RunUnprocessable
from defender.scripts.case_history.case_ticket import CaseTicketError, read_case_record
from defender.scripts.visualize.visualize_primitives import parse_report

# A trailing ZERO WIDTH SPACE — invisible, survives `.strip()`, and reachable from the
# attacker-influenced alert text the model was asked to analyze.
ZWSP = "​"


def _load_trace_lesson():
    return load_trace_lesson("trace_lesson_785")


def _run_dir(tmp_path: Path, name: str, report: str) -> Path:
    run = tmp_path / name
    run.mkdir(parents=True)
    (run / "report.md").write_text(report, encoding="utf-8")
    (run / "alert.json").write_text(json.dumps({"rule": {"id": "5710"}}), encoding="utf-8")
    return run


def _report_text(disposition: str) -> str:
    return f"---\ncase_id: c\ndisposition: {disposition}\nconfidence: high\n---\nThe body.\n"


def _every_consumers_reading(run: Path) -> dict[str, object]:
    """What each of the six consumers makes of one run's disposition, gates included — a gate
    that refuses reports `None` here, which is the same reading, not a different one."""
    trace_lesson = _load_trace_lesson()
    readings: dict[str, object] = {
        "eval": predicted_disposition(run),
        "transcript": parse_report(run).disposition,
        "tracer": trace_lesson._report_disposition(run),
    }
    if readings["tracer"] == UNKNOWN_DISPOSITION:
        readings["tracer"] = None
    try:
        readings["loop"] = normalize_disposition(run / "report.md")
    except RunUnprocessable:
        readings["loop"] = None
    try:
        readings["ticket"] = read_case_record(run).disposition
    except CaseTicketError:
        readings["ticket"] = None
    accessor = read_report(run / "report.md")
    readings["dispatch"] = (
        [d.name for d in directions_for(accessor.disposition_or_unknown)] or None
    )
    return readings


# the headline: the six consumers no longer disagree on attacker-shaped input

@pytest.mark.parametrize(
    ("tag", "written"),
    [
        ("clean", "benign"),
        ("trailing-zwsp", f"benign{ZWSP}"),
        ("bom", "﻿benign"),
        ("soft-hyphen", "be­nign"),
    ],
)
def test_every_consumer_reads_the_same_disposition(tmp_path, tag, written):
    """The #722 defence now reaches all six. A disposition that RENDERS as `benign` resolves
    to `benign` for the learning loop, the ticket bridge, the eval, the tracer, the transcript
    and the direction dispatch alike — before #785 only the loop stripped, so the same run was
    a `benign` case to it and an unreadable one to the other five."""
    run = _run_dir(tmp_path, f"case-{tag}", _report_text(written))
    assert _every_consumers_reading(run) == {
        "eval": "benign",
        "transcript": "benign",
        "tracer": "benign",
        "loop": "benign",
        "ticket": "benign",
        "dispatch": ["adversarial"],
    }


@pytest.mark.parametrize(
    ("tag", "written"),
    [
        ("not-a-keyword", "spicy"),
        ("content-less", ZWSP),
        ("empty", '""'),
        ("zero-width-inside-a-keyword", "beni​gn-ish"),
        ("non-str", "[benign, malicious]"),
        ("int", "123"),
    ],
)
def test_every_consumer_refuses_the_same_non_disposition(tmp_path, tag, written):
    """The guarded negative: agreeing does not mean accepting. Anything outside the enum is
    refused by all six, and the `non-str` case is the one that used to raise `TypeError` out
    of the ticket bridge and the eval — a YAML list is unhashable, so a bare membership test
    against the enum SET blew up instead of denying."""
    run = _run_dir(tmp_path, f"case-{tag}", _report_text(written))
    assert set(_every_consumers_reading(run).values()) == {None}


def test_a_missing_report_reads_the_same_way_everywhere(tmp_path):
    """The other end of the same demand — a run that never wrote a report."""
    run = tmp_path / "empty"
    run.mkdir()
    assert set(_every_consumers_reading(run).values()) == {None}


# reaction stays per-consumer, by kind

def test_the_gates_refuse_in_their_own_vocabulary(tmp_path):
    """Both gates raise a TYPED domain error rather than the accessor's own — the learning
    drain dead-letters on `RunUnprocessable` and the ticket lane catches `CaseTicketError`,
    and folding the read must not make either of them catch a stranger."""
    run = _run_dir(tmp_path, "bad", _report_text("spicy"))
    with pytest.raises(RunUnprocessable, match="disposition="):
        normalize_disposition(run / "report.md")
    with pytest.raises(CaseTicketError, match="disposition="):
        read_case_record(run)


def test_the_views_and_metrics_degrade_instead(tmp_path):
    """The other kind: one broken report costs its own row, never the page or the score. The
    transcript still renders the report's BYTES — an operator's only view of what the model
    actually wrote is worth more than a refusal to render."""
    malformed = "no frontmatter at all, just prose\n"
    run = _run_dir(tmp_path, "broken", malformed)
    read = parse_report(run)
    assert read.disposition is None
    assert read.disposition_or_unknown == UNKNOWN_DISPOSITION
    assert read.body == malformed
    assert predicted_disposition(run) is None


def test_the_tracer_reports_the_row_it_dropped(tmp_path, capsys):
    """A malformed report degrades that case to `?` AND says so on stderr, naming the case —
    a silent `?` reads as "this case never resolved", which is a different fact."""
    trace_lesson = _load_trace_lesson()
    run = _run_dir(tmp_path, "caseA", _report_text("spicy"))
    assert trace_lesson._report_disposition(run) == UNKNOWN_DISPOSITION
    assert "caseA/report.md" in capsys.readouterr().err


# the accessor's own contract

def test_require_report_carries_the_reason_the_others_report(tmp_path):
    run = _run_dir(tmp_path, "c", _report_text("spicy"))
    with pytest.raises(ReportUnreadable, match="disposition='spicy'"):
        require_report(run / "report.md")
    ok = _run_dir(tmp_path, "ok", _report_text("malicious"))
    report = require_report(ok / "report.md")
    assert (report.disposition, report.body) == ("malicious", "The body.")
    assert report.frontmatter["confidence"] == "high"


def test_every_reason_names_the_artifact(tmp_path):
    """The tracer prefixes the reason with the case id to say WHICH report failed, so every
    reason has to start with the file name for that sentence to parse."""
    reasons = [
        read_report(tmp_path / "gone" / "report.md").reason,
        read_report(_run_dir(tmp_path, "a", "prose only\n") / "report.md").reason,
        read_report(_run_dir(tmp_path, "b", _report_text("spicy")) / "report.md").reason,
    ]
    assert all(r is not None and r.startswith("report.md") for r in reasons)


def test_a_read_that_yields_a_disposition_carries_no_reason(tmp_path):
    """`reason` is set exactly when there is no headline — the invariant `require_report`
    relies on to decide whether to raise."""
    good = read_report(_run_dir(tmp_path, "g", _report_text("benign")) / "report.md")
    assert (good.disposition, good.reason) == ("benign", None)
    assert good.report is not None


def test_an_undecodable_report_costs_its_own_row(tmp_path):
    """`report.md` is model-authored and read once per case in whole-corpus walks: one
    undecodable byte must not kill the walk with a `UnicodeDecodeError` (#595)."""
    run = tmp_path / "u"
    run.mkdir()
    (run / "report.md").write_bytes(b"---\ndisposition: benign\n---\n\xff")
    read = read_report(run / "report.md")
    assert read.disposition is None
    assert read.reason is not None
    assert "unreadable" in read.reason


# the write gate is deliberately NOT folded in

def test_the_write_gate_stays_exact_where_the_read_normalizes():
    """The asymmetry is the design, not an oversight. On WRITE there is an author to ask: the
    gate denies a zero-width-laced disposition with retry text and the model fixes it. On READ
    there is not — the report may have arrived from an imported run dir or a hand edit — so
    what it renders as is what it means. Fold them together in either direction and one of the
    two lanes gets the wrong behavior."""
    laced = _report_text(f"benign{ZWSP}")
    assert validate_report(laced) is not None                  # write: denied, with a reason
    assert normalized_disposition(f"benign{ZWSP}") == "benign"  # read: understood

    clean = _report_text("benign")
    assert validate_report(clean) is None
