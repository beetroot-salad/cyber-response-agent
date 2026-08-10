"""§ Review gate on `runtime.html` — the write-time gate rendered as a GATE, not a phase.

The reviewer (#796) leaves `review_record.{turn}.json` and `review_{role}_trace.jsonl` in
every run dir that reached a confident close, and until now no viewer read either: a run
whose confident disposition the gate overrode to `inconclusive` rendered identically to one
the investigator called `inconclusive` itself. These tests pin the rendered surface, and —
more importantly — the two shapes that would silently render an empty panel:

  - the record number and the trace round differ by one (attempt N is round N-1), so
    filtering traces on the record's own number drops every role card;
  - a lens's framed reply is written as a line `read_jsonl_rows` deliberately SKIPS, so the
    ordinary row reader would show the metadata and none of the model's words.

Plus the negative that keeps the framing honest: the gate must not appear in the phase
machinery.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.runtime.challenge_gate import REVIEW_ROLES, review_record_path, review_trace_path
from defender.scripts.visualize import visualize_data as d
from defender.scripts.visualize.visualize_primitives import parse_report
from defender.scripts.visualize.visualize_runtime import render_review_gate

_SALT = "deadbeef"


def _framed(text: str) -> str:
    """A stage reply as the gate writes it — `_untrusted.wrap`'s framing, via the real one."""
    from defender._untrusted import wrap

    return wrap(text, "untrusted", _SALT)


def _write_report(run: Path, *, disposition: str, outcome: str, cause: str,
                  failure_kind: str | None = None) -> None:
    kind = f"failure_kind: {failure_kind}\n" if failure_kind else ""
    (run / "report.md").write_text(
        f"---\ndisposition: {disposition}\noutcome: {outcome}\ncause: {cause}\n{kind}---\n"
        f"Disposition recorded by the close gate. outcome={outcome}.\n",
        encoding="utf-8",
    )


def _trace_row(run: Path, role: str, round_no: int, row: dict, reply: str | None = None) -> None:
    """Append through the gate's OWN writer, so the on-disk shape under test is the shape
    production writes — including its decision about where a framed reply may live."""
    from defender.runtime.challenge_gate import _write_trace_row

    _write_trace_row(run, role, round_no, row, raw_reply=reply)


def _challenged_then_stands(tmp_path: Path) -> Path:
    """A run challenged once, then committed: records 1 and 2, trace rounds 0 and 1."""
    run = tmp_path / "run"
    run.mkdir()
    _write_report(
        run, disposition="malicious", outcome="stands",
        cause="the challenge review ran and left nothing about the finding unsettled",
    )
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "challenged", "reviewed_disposition": "malicious",
        "detail": _framed("the pivot rests on one edge nothing independently measured"),
        "failure_kind": None,
    }), encoding="utf-8")
    (run / review_record_path(run, 2).name).write_text(json.dumps({
        "verdict": "stands", "reviewed_disposition": "malicious",
        "detail": _framed("the second lead settles it"), "failure_kind": None,
    }), encoding="utf-8")
    for round_no, verdict in ((0, "gap on the authz edge"), (1, "holds")):
        _trace_row(run, "support", round_no, {"ok": True},
                   _framed(f"support reading r{round_no}: {verdict}"))
        _trace_row(run, "ablation", round_no, {"ok": True},
                   _framed(f"ablation reading r{round_no}"))
        _trace_row(run, "composer", round_no, {"ok": True},
                   _framed(json.dumps({"finding": "gap" if round_no == 0 else "holds",
                                       "review": f"composed r{round_no}"})))
    return run


def test_renders_every_attempt_with_its_verdict(tmp_path):
    run = _challenged_then_stands(tmp_path)
    html, n = render_review_gate(run, parse_report(run))

    assert n == 2, "both close attempts are reviewed attempts"
    assert "attempt 1" in html
    assert "attempt 2" in html
    assert "rv-challenged" in html, "the challenged attempt keeps its own verdict"
    assert "rv-stands" in html
    # The detail is stage-derived prose and must reach the page, not be dropped as untrusted.
    assert "rests on one edge" in html


def test_role_traces_land_under_their_attempt_despite_the_round_offset(tmp_path):
    """Attempt N is trace round N-1. Filtering on the record's own number would leave every
    role card empty — and empty reads as "the reviewer did not run", which is a different
    and much worse claim than the truth."""
    run = _challenged_then_stands(tmp_path)
    html, _ = render_review_gate(run, parse_report(run))

    for role in REVIEW_ROLES:
        assert f'>{role}<' in html, f"{role} has no card"
    # Round 0's reading belongs to attempt 1 and round 1's to attempt 2 — the text of each
    # appears, which it cannot if the filter dropped one side.
    assert "support reading r0" in html
    assert "support reading r1" in html
    first, second = html.split("attempt 2", 1)
    assert "support reading r0" in first
    assert "support reading r1" in second


def test_prose_reply_survives_the_row_reader(tmp_path):
    """A lens reply is framed prose written as its own physical line — one
    `read_jsonl_rows` skips by design. The panel walks lines with the writer's own predicate
    instead, so the model's words render rather than only its `ok` flag."""
    from defender._io import read_jsonl_rows

    run = _challenged_then_stands(tmp_path)
    rows = read_jsonl_rows(review_trace_path(run, "support"))
    assert rows, "fixture wrote no metadata rows at all"
    assert all("support reading" not in json.dumps(r) for r in rows), (
        "fixture no longer exercises the skipped-line path"
    )
    html, _ = render_review_gate(run, parse_report(run))
    assert "support reading r0" in html


def test_forced_inconclusive_shows_the_disposition_the_gate_moved(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_report(
        run, disposition="inconclusive", outcome="forced-inconclusive",
        cause="the forced-turn budget was spent without settling what the challenge review raised",
    )
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "forced-inconclusive", "reviewed_disposition": "malicious",
        "detail": _framed("the authz edge is still unmeasured"), "failure_kind": None,
    }), encoding="utf-8")
    _trace_row(run, "support", 0, {"ok": True}, _framed("support reading"))

    html, _ = render_review_gate(run, parse_report(run))
    assert "rv-forced" in html
    # Both halves of the move, so the page never implies the investigator chose inconclusive.
    assert "malicious" in html
    assert "inconclusive" in html
    assert "rv-arrow" in html


def test_failed_review_is_named_as_machinery_not_a_finding(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_report(
        run, disposition="inconclusive", outcome="forced-inconclusive",
        cause="the challenge review did not complete", failure_kind="timeout",
    )
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "forced-inconclusive", "reviewed_disposition": "benign",
        "detail": _framed("support: support timed out after 450s"), "failure_kind": "timeout",
    }), encoding="utf-8")
    for role in REVIEW_ROLES:
        _trace_row(run, role, 0, {"incomplete": True, "reason": _framed("support timed out")})

    html, _ = render_review_gate(run, parse_report(run))
    assert "failure_kind: timeout" in html
    assert "rv-failnote" in html, "a broken review must not read as a finding about the case"
    assert "incomplete" in html


def test_skipped_ablation_is_not_reported_as_ok(tmp_path):
    """`ok: true` means a stage ANSWERED. An ablation with no load-bearing edge to withhold
    was never dispatched and its row carries `skipped` and no `ok` — the panel must keep
    those apart, exactly as the gate's own writer does."""
    run = tmp_path / "run"
    run.mkdir()
    _write_report(run, disposition="benign", outcome="stands",
                  cause="the challenge review ran and left nothing about the finding unsettled")
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "stands", "reviewed_disposition": "benign", "detail": "", "failure_kind": None,
    }), encoding="utf-8")
    _trace_row(run, "ablation", 0, {"skipped": "no strong belief movement cites an edge to withhold"})
    _trace_row(run, "support", 0, {"ok": True}, _framed("support reading"))

    html, _ = render_review_gate(run, parse_report(run))
    assert "rr-skip" in html
    assert "no strong belief movement" in html


def test_inconclusive_close_says_it_was_never_reviewed(tmp_path):
    """An `inconclusive` close bypasses the gate. Its record is `stands` — which must not
    render as "a review ran and the disposition survived"."""
    run = tmp_path / "run"
    run.mkdir()
    _write_report(run, disposition="inconclusive", outcome="stands",
                  cause="the disposition was recorded without a challenge review")
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "stands", "reviewed_disposition": "inconclusive", "detail": "",
        "failure_kind": None,
    }), encoding="utf-8")

    html, n = render_review_gate(run, parse_report(run))
    assert n == 0
    assert "not reviewed" in html
    assert "confident closes only" in html


def test_a_bypassed_attempt_beside_a_reviewed_one_is_not_reported_as_stands(tmp_path):
    """A run challenged once and then closed `inconclusive` has one attempt of each kind.
    The bypassed one carries `verdict: stands` — the close tool's word for "committed
    unchanged" — and rendering that verbatim says a review ran and the disposition survived,
    which is the same claim the all-bypassed guard exists to refuse."""
    run = tmp_path / "run"
    run.mkdir()
    _write_report(run, disposition="inconclusive", outcome="stands",
                  cause="the disposition was recorded without a challenge review")
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "challenged", "reviewed_disposition": "malicious", "detail": "",
        "failure_kind": None,
    }), encoding="utf-8")
    (run / review_record_path(run, 2).name).write_text(json.dumps({
        "verdict": "stands", "reviewed_disposition": "inconclusive", "detail": "",
        "failure_kind": None,
    }), encoding="utf-8")
    _trace_row(run, "support", 0, {"ok": True}, _framed("support reading r0"))

    html, n = render_review_gate(run, parse_report(run))
    assert n == 1, "only the confident attempt was reviewed"
    second = html.split("attempt 2", 1)[1]
    assert "not reviewed" in second
    assert "rv-stands" not in second, "the bypassed attempt must not claim a review held"


def test_the_headline_badge_does_not_claim_a_review_that_never_ran(tmp_path):
    """`_gate_badge_html` and § Review gate read the same run and must not disagree: an
    `inconclusive` close writes `outcome: stands` with the not-reviewed cause."""
    from defender.scripts.visualize.visualize_run import _gate_badge_html

    run = tmp_path / "run"
    run.mkdir()
    _write_report(run, disposition="inconclusive", outcome="stands",
                  cause="the disposition was recorded without a challenge review")
    badge = _gate_badge_html(parse_report(run))
    assert "not reviewed" in badge
    assert "gate-stands" not in badge


def test_a_framed_reply_keeps_its_paragraph_breaks(tmp_path):
    """A blank line inside a framed reply is the model's own; dropping it reflows a
    multi-paragraph reading into one run-on block on the surface that exists to show it."""
    run = tmp_path / "run"
    run.mkdir()
    _write_report(run, disposition="benign", outcome="stands", cause="x")
    (run / review_record_path(run, 1).name).write_text(json.dumps({
        "verdict": "stands", "reviewed_disposition": "benign", "detail": "", "failure_kind": None,
    }), encoding="utf-8")
    _trace_row(run, "support", 0, {"ok": True}, _framed("para one\n\npara two"))

    html, _ = render_review_gate(run, parse_report(run))
    assert "para one\n\npara two" in html


def test_no_records_is_an_unfinished_run_not_a_clean_one(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_report(run, disposition="benign", outcome="stands", cause="x")
    html, n = render_review_gate(run, parse_report(run))
    assert n == 0
    assert "no review record" in html


def test_the_gate_is_not_a_phase(tmp_path):
    """The framing, as a test rather than a comment. The five phases are prompt-level and
    model-occupied; the gate is neither, and the moment it acquires a colour and a loop verb
    it starts rendering as a sixth one — in the cost bar, the wall bar and the transcript's
    phase groups, none of which it can honestly appear in."""
    assert "REVIEW" not in d._LOOP_VERBS
    # `phase_color` returns its own fallback grey for anything it does not know.
    assert d.phase_color("REVIEW") == d.phase_color("NOT-A-PHASE")

    run = _challenged_then_stands(tmp_path)
    (run / "investigation.md").write_text(
        "## ORIENT\n\nOriented.\n\n## ANALYZE\n\nAnalyzed.\n", encoding="utf-8")
    phases = d.normalize_phase_names(d.split_investigation_phases(run))
    assert all("REVIEW" not in p["name"].upper() for p in phases)
