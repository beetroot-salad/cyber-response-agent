from __future__ import annotations

import json
from pathlib import Path

from defender.tests.support.shared.filesystem import _spec1047 as T47
from defender.tests.runtime.providers import _spec1243 as P


def _run_end():
    return P.mod("records.run_end")


def test_o5_provider_down_is_a_member_of_the_run_end_vocabulary() -> None:
    """O5: `provider-down` is a `truncated_by` member and normalizes to itself — not to `None`,
    which every reader takes as "not cut short"."""
    rb = _run_end()
    assert P.PROVIDER_DOWN in rb.TRUNCATED_BY_VALUES
    assert rb.normalized_truncated_by(P.PROVIDER_DOWN) == P.PROVIDER_DOWN
    # Control on the same normalizer: an unlisted spelling still reads as None.
    assert rb.normalized_truncated_by("provider_down") is None


def test_o5_a_provider_down_run_end_record_parses(tmp_path: Path) -> None:
    """O5: the run-end record a provider-down run writes is read back by the production reader
    as provider-down — a record the reader refuses reads as "the host said nothing"."""
    rb = _run_end()
    rec = rb.parse_record({"truncated_by": P.PROVIDER_DOWN, "closed_before_cut": False})
    assert rec is not None, "parse_record refuses a provider-down run-end record"
    assert rec.truncated_by == P.PROVIDER_DOWN
    # Control: the same reader refuses an out-of-vocabulary value.
    assert rb.parse_record({"truncated_by": "provider_down", "closed_before_cut": False}) is None


def test_o4_provider_down_is_not_a_forced_close_exit() -> None:
    """O4: provider-down is an infrastructure end like budget and store — not in the forced
    unresolved-close set, so no report.md is written for it (C15)."""
    rb = _run_end()
    assert P.PROVIDER_DOWN not in rb.FORCED_CLOSE_EXITS
    assert rb.TRUNCATED_BY_BUDGET not in rb.FORCED_CLOSE_EXITS
    assert rb.TRUNCATED_BY_REQUEST_LIMIT in rb.FORCED_CLOSE_EXITS  # control: the set is not empty


def test_o5_the_ticket_lane_leaves_a_provider_down_ticket_open_with_no_call(tmp_path: Path) -> None:
    for report in (False, True):
        run_dir = T47.closed_run_dir(tmp_path / f"report-{report}", report=report)
        fake = T47.record_ticket(run_dir, truncated_by=P.PROVIDER_DOWN, closed_before_cut=False)
        assert fake.calls == [], (
            f"report={report}: the lane made {fake.calls} for a provider-down run — it must "
            "make no call at all")
        assert T47.receipt(run_dir) is None


def test_o5_the_ticket_lane_records_a_provider_down_run_whose_model_had_closed(tmp_path: Path) -> None:
    run_dir = T47.closed_run_dir(tmp_path, disposition="malicious")
    fake = T47.record_ticket(run_dir, truncated_by=P.PROVIDER_DOWN, closed_before_cut=True)
    assert len(fake.records) == 1, f"a closed-before-cut provider-down run recorded {fake.calls}"
    assert "malicious" in fake.records[0].text()
    assert fake.transitions == []


def test_o5_ticket_lane_control_an_uncut_run_still_records(tmp_path: Path) -> None:
    """O5 positive control on the same channel: an uncut run with a report records its comment,
    so "no call" above is the provider-down arm, not a lane that never calls."""
    run_dir = T47.closed_run_dir(tmp_path, disposition="malicious")
    fake = T47.record_ticket(run_dir, truncated_by=None)
    assert len(fake.records) == 1, f"an uncut run recorded {fake.records}"


def test_o5_curation_refuses_a_provider_down_run(tmp_path: Path) -> None:
    """O5: the learning refusal gate refuses a provider-down run because it was cut short — a
    truncated investigation never trains the corpus."""
    run_dir = T47.closed_run_dir(tmp_path, report=False)
    gate = P.sym("run_common", "learning_refusal_gate")
    reason = gate(run_dir, truncated_by=P.PROVIDER_DOWN)
    assert reason is not None, "curation was not refused for a provider-down run"
    assert P.PROVIDER_DOWN in reason, f"the refusal does not name the cut: {reason!r}"
    # Control: the same gate with no cut does not refuse for truncation.
    other = gate(run_dir, truncated_by=None)
    assert other is None or "truncated" not in other


def test_o5_the_run_end_record_written_for_provider_down_round_trips(tmp_path: Path) -> None:
    """O5: the production writer and reader agree on a provider-down record: written by
    `write_sidecar`'s document shape, read back by `parse_record` as the same value."""
    rb = _run_end()
    doc = rb.RunEnd(P.PROVIDER_DOWN, False).doc()
    assert rb.parse_record(json.loads(json.dumps(doc))) == rb.RunEnd(P.PROVIDER_DOWN, False)
