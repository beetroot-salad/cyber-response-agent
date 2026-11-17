"""#992 — what the closing record carries for a reviewed `inconclusive`: the ceiling receipts,
their caps, and the ticket egress."""
from __future__ import annotations

import pytest

from defender.skills.invlang.validate import validate_companion
from defender.tests.storage.verdict_1534 import _close_b as B
from defender.tests.support.runtime.engine import _spec923
from defender.tests.support.shared.contracts import _tacit983
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests.support.runtime.engine._spec992 import (
    CEILING_EXAMINED,
    CONFIDENT,
    GAP,
    UNRESOLVED,
    V2SSHD_NOTE,
    V2SSHD_RECEIPTS,
    bounds,
    ceiling_companion,
    close_with,
    deps_over,
    frontmatter,
    gap,
    holds,
    raises,
    recording,
    refusal,
    sparse_companion,
)

_ONE_TURN = "extra_turns"


def _closing():
    from defender.records import closing

    return closing


def _override_arms() -> list[tuple[str, object, dict]]:
    """The four arms on which review OVERRIDES an `inconclusive` to `unresolved`, as
    `(name, stages, close kwargs)`; a repeat and a spent pool need a challenged attempt first."""
    return [
        ("null-ask", recording(gap(None)), {}),
        ("repeat", recording(gap("l-004")), {"after": [recording(gap("l-004"))]}),
        ("spent-pool", recording(gap("l-005")), {"after": [recording(gap("l-004"))], _ONE_TURN: 1}),
        ("machinery-failure", recording(faults={"composer": raises(RuntimeError("down"))}), {}),
    ]


def _drive(deps, name: str, stages, kw: dict):
    limits = bounds(extra_turns=kw[_ONE_TURN]) if _ONE_TURN in kw else None
    for earlier in kw.get("after", []):
        assert close_with(deps, GAP, earlier, bounds=limits).outcome == "challenged", name
    return close_with(deps, GAP, stages, bounds=limits)


def _record_of(tmp_path, name, companion, disposition, stages, **kw):
    """The committed record of one close over `companion`, driven through `_drive`'s arms, read back through the lookup."""
    with B.opened(tmp_path / name, companion) as (deps, run_dir, store):
        result = _drive(deps, name, stages, {**kw, "after": kw.get("after", [])}) if disposition == GAP \
            else close_with(deps, disposition, stages)
        return result, B.committed_record(run_dir, store), run_dir


def test_reviewed_inconclusive_carries_receipts(tmp_path):
    """An `inconclusive` that stands carries its priced receipts in the record; one the review overrides commits `unresolved`
    with the receipts kept and the draft named. (V-FIELDS)"""
    golden = ceiling_companion()
    result, rec, _ = _record_of(tmp_path, "holds", golden, GAP, recording(holds()))
    assert result.outcome == _closing().STANDS
    assert (rec.disposition, rec.cause, rec.drafted_disposition) == (GAP, CEILING_EXAMINED, None)
    assert [(e.state, e.ref) for e in rec.ceiling_test] == list(V2SSHD_RECEIPTS)
    assert rec.ceiling_test[0].note.startswith(V2SSHD_NOTE)

    for name, stages, kw in _override_arms():
        result, rec, run_dir = _record_of(tmp_path, name, golden, GAP, stages, **kw)
        assert result.outcome == "forced-inconclusive", (name, result)
        assert (rec.disposition, rec.drafted_disposition) == (UNRESOLVED, GAP), name
        assert [(e.state, e.ref) for e in rec.ceiling_test] == list(V2SSHD_RECEIPTS), name

    # The baseline block rides beside the receipts.
    with_baseline = _tacit983.inconclusive_document(
        rows=_tacit983.consult_block(_tacit983.consultation_row()),
    )
    _, rec, _ = _record_of(tmp_path, "baseline", with_baseline, GAP, recording(holds()))
    assert B.baselines_of(rec) == [B.DOC_BASELINE]
    assert rec.ceiling_test

    # Identical whether the ablation lens ran (the golden) or was skipped (the sparse one).
    skipped = recording(holds())
    _, rec, _ = _record_of(tmp_path, "sparse", sparse_companion(), GAP, skipped)
    assert skipped.calls == ["support", "composer"]
    assert [(e.state, e.ref) for e in rec.ceiling_test] == [("query-failed", "l-002")]

    # Two rows citing one ref with different states: the inconsistent one is refused at the price gate, before any stage.
    conflicting = _spec923.paid(
        "state=query-failed ref=l-002 note=matches its fail_reason",
        "state=query-empty ref=l-002 note=contradicts its fail_reason",
    )
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path / "conflict", conflicting)
    text = refusal(deps, GAP, stages)
    assert "query-empty" in text
    assert "l-002" in text
    assert stages.calls == []


def test_confident_and_forced_commits_carry_the_receipts_of_their_parse(tmp_path):
    """Receipts follow the parse, not the committed disposition: a confident close and one the review overrides carry them
    too. (V-FIELDS)"""
    golden = ceiling_companion()

    confident = recording(holds())
    _, rec, _ = _record_of(tmp_path, "confident", golden, CONFIDENT, confident)
    assert rec.disposition == CONFIDENT
    assert [(e.state, e.ref) for e in rec.ceiling_test] == list(V2SSHD_RECEIPTS)
    assert "l-004" in confident.prompt("composer")

    result, rec, _ = _record_of(tmp_path, "forced", golden, CONFIDENT, recording(gap(None)))
    assert result.outcome == "forced-inconclusive"
    assert (rec.disposition, rec.drafted_disposition) == (UNRESOLVED, CONFIDENT)
    assert [(e.state, e.ref) for e in rec.ceiling_test] == list(V2SSHD_RECEIPTS)


MODEL = B.model_dispositions()


def _bound_errors(errors: list[str], bound: int, column: str = "ceiling_test") -> list[str]:
    """The refusals that name `column` and the bound number (their wording is the implementer's)."""
    return [e for e in errors if column in e and str(bound) in e]


def _rejected(count: int, note: str = "n") -> list[str]:
    """`count` distinct receipts no walker accepts (their `ref` is no lead of the document), `l-300` upward."""
    return [f"state=query-empty ref=l-{300 + i} note={note}" for i in range(count)]


@pytest.mark.parametrize("disposition", MODEL)
def test_ceiling_rows_the_walkers_reject_still_count_toward_the_count_cap_and_the_aggregate(disposition):
    """Rows the receipt walkers drop (their `ref=` is no lead of the document) are still parsed rows: sixteen in all
    are not refused for their number, seventeen are, and rows whose lines join past the aggregate are, at the write
    itself. (M3)"""
    from defender.records import closing as C

    paying = [_spec923.PAYING_ROW]

    def new_errors(rows: list[str], control: list[str], bound: int) -> list[str]:
        """What `rows` is refused for that `control` is not, naming the bound."""
        have = set(validate_companion(B.with_ceiling(disposition, control), None))
        return _bound_errors([e for e in validate_companion(B.with_ceiling(disposition, rows), None) if e not in have],
                             bound)

    within = paying + _rejected(C.CEILING_COUNT_CAP - 1)
    assert not _bound_errors(validate_companion(B.with_ceiling(disposition, within), None), C.CEILING_COUNT_CAP)
    over = paying + _rejected(C.CEILING_COUNT_CAP)
    assert new_errors(over, within, C.CEILING_COUNT_CAP), "a rejected row did not count toward the count cap"

    count = 5
    paying_line = C.ceiling_line(C.CeilingEntry("query-failed", "l-002", None, _spec923.PAYING_ROW.split("note=", 1)[1]))
    probes = [C.ceiling_line(C.CeilingEntry("query-empty", f"l-{300 + i}", None, "x")) for i in range(count)]

    def lined(extra: int) -> list[str]:
        sizes = B.fill_sizes(probes, C.CEILING_LINES_BOUND - len(paying_line) - 1, extra)
        assert max(sizes) <= C.NOTE_BOUND, "fixture control: each note fits its own bound"
        return paying + [f"state=query-empty ref=l-{300 + i} note={B.plain(n)}" for i, n in enumerate(sizes)]

    assert not _bound_errors(validate_companion(B.with_ceiling(disposition, lined(0)), None), C.CEILING_LINES_BOUND)
    assert new_errors(lined(1), lined(0), C.CEILING_LINES_BOUND), "a rejected row did not count toward the aggregate"


def _baseline_doc(*rows: str) -> str:
    return _tacit983.inconclusive_document(rows=_tacit983.consult_block(*rows))


def test_baseline_rows_the_walkers_reject_still_count_toward_the_field_bounds_and_the_aggregate():
    """A baseline the window guard drops (its window reaches the alert) is still a parsed row: an over-long field in it
    and lines that join past the aggregate through it are refused at the write itself. (M3)"""
    from defender.records import closing as C

    late = _tacit983.WINDOW_STARTING_AT_ALERT

    def fresh(before, after):
        return [e for e in after if e not in set(before)]

    control = validate_companion(_baseline_doc(_tacit983.consultation_row(anchor_id="tk-late", window=late)), None)
    assert control, "fixture control: the guard refuses the late window on its own"
    long = validate_companion(_baseline_doc(_tacit983.consultation_row(
        anchor_id="tk-late", window=late, result=B.expanding(C.RESULT_BOUND + 1))), None)
    assert _bound_errors(fresh(control, long), C.RESULT_BOUND, "result"), long

    def rows(count: int, *, late_last: bool) -> str:
        built = [_tacit983.consultation_row(anchor_id=f"tk-b-{i:03d}", result="n", reasoning="r") for i in range(count)]
        if late_last:
            built[-1] = _tacit983.consultation_row(anchor_id=f"tk-b-{count - 1:03d}", result="n", reasoning="r",
                                                   window=late)
        return _baseline_doc(*built)

    probe = C.baseline_line(C.BaselineEntry(
        "l-001", "runtime-evidence", "telemetry-baseline", "tk-b-000", "2026-04-04T00:00:00Z", "2026-05-04T00:00:00Z",
        "n", "r"))
    fit = (C.BASELINE_LINES_BOUND + 1) // (len(probe) + 1)
    assert fit > 1, "fixture control"
    assert not _bound_errors(validate_companion(rows(fit, late_last=True), None), C.BASELINE_LINES_BOUND, "runtime_evidence")
    errors = validate_companion(rows(fit + 1, late_last=True), None)
    assert _bound_errors(errors, C.BASELINE_LINES_BOUND, "runtime_evidence"), errors


def test_case_ticket_closing_comment_reads_a_reviewed_inconclusive_close(tmp_path, monkeypatch):
    """The ticket comment for a ceiling-held `inconclusive` carries the seventh cause verbatim; a
    machinery-failed one renders as the `unresolved` it committed, never as the ceiling claim.
    (#1359: read at the wire, the comment the record leg posts to the alert's ticket.)"""
    from defender.tests.support.runtime.engine import _spec767 as S767
    from defender.tests.support.storage._alert_plant import plant_alert

    S767.use_case_record(monkeypatch, tmp_path / "dfn")

    def posted(run_dir, n):
        plant_alert(run_dir, S767.ALERT, mapping=S767.ALERT_MAPPING)
        store = S767.FakeStore(tmp_path / f"store-{n}")
        S767.record(run_dir, store)
        return store.comment_body()

    deps, run_dir = deps_over(tmp_path / "held", ceiling_companion())
    assert close_with(deps, GAP, recording(holds())).outcome == _closing().STANDS
    fm = frontmatter(run_dir)
    assert (fm["disposition"], fm["outcome"], fm["cause"]) == (GAP, _closing().STANDS, CEILING_EXAMINED)
    assert posted(run_dir, 0).startswith(f"{GAP} — {CEILING_EXAMINED}")

    deps, run_dir = deps_over(tmp_path / "broken", ceiling_companion())
    broken = close_with(deps, GAP, recording(faults={"composer": raises(RuntimeError("down"))}))
    assert broken.outcome == "forced-inconclusive"
    assert broken.failure_kind is not None
    body = posted(run_dir, 1)
    assert body.startswith(f"{UNRESOLVED} — {_closing().CAUSE_REVIEW_INCOMPLETE}"), body
    assert CEILING_EXAMINED not in body
