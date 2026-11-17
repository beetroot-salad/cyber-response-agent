"""#992 — what the committed report carries for a reviewed `inconclusive`: the ceiling receipts,
their caps, and the ticket egress."""
from __future__ import annotations

import pytest

from defender.investigation.close_tool import CAUSE_REVIEW_INCOMPLETE, STANDS
from defender.skills.invlang.validate import validate_companion
from defender.tests.storage.verdict_1534 import _close_b as B
from defender.tests.storage.verdict_1534 import _spec1534 as V
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
    assert result.outcome == STANDS
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


def _note_doc(treated: int) -> str:
    return _spec923.paid(f"state=query-failed ref=l-002 note={B.expanding(treated)}")


@pytest.mark.parametrize(("treated", "accepted"), [(400, True), (401, False)])
def test_a_ceiling_note_is_bounded_by_its_treated_length_at_the_write_gate_and_the_close(tmp_path, treated, accepted):
    """A note whose treated text is exactly the note bound passes both gates; one character more is refused before any
    stage, though its raw text is shorter than the bound. (V-TEXT)"""
    companion = _note_doc(treated)
    at_write_gate = validate_companion(companion, None)
    stages = recording(holds())
    with B.opened(tmp_path, companion) as (deps, run_dir, store):
        if accepted:
            assert at_write_gate == []
            assert close_with(deps, GAP, stages).outcome == STANDS
            (entry,) = B.committed_record(run_dir, store).ceiling_test
            assert entry.note == B.expanding(treated).replace("ab.cd", "ab[.]cd")
        else:
            assert any("ceiling_test" in err for err in at_write_gate), at_write_gate
            text = refusal(deps, GAP, stages)
            assert "close blocked" in text
            assert "ceiling_test" in text
            assert stages.calls == []
            assert V.scalar_rows(store.path, run_dir.name) == []


def test_ceiling_receipts_are_bounded_by_count_and_by_their_rendered_lines(tmp_path):
    """Sixteen receipts pass the write gate and seventeen are refused; receipts whose lines join to exactly the aggregate
    pass and one character more is refused. (V-TEXT)"""
    from defender.records import closing as C

    def refused(companion: str) -> bool:
        return any("ceiling_test" in err for err in validate_companion(companion, None))

    assert validate_companion(_spec923.paid(*B.capability_rows(C.CEILING_COUNT_CAP, lambda _i: "n")), None) == []
    assert refused(_spec923.paid(*B.capability_rows(C.CEILING_COUNT_CAP + 1, lambda _i: "n")))

    count = 6
    overhead = sum(
        len(C.ceiling_line(C.CeilingEntry("nothing-to-try", None, f"fake-system-{i:03d}.fake-verb", "x"))) - 1
        for i in range(count))
    budget = C.CEILING_LINES_BOUND - (count - 1) - overhead

    def sized(total: int) -> str:
        sizes = [total // count + (1 if i < total % count else 0) for i in range(count)]
        assert max(sizes) <= C.NOTE_BOUND, "fixture control: each note fits its own bound"
        return _spec923.paid(*B.capability_rows(count, lambda i: B.plain(sizes[i])))

    assert validate_companion(sized(budget), None) == []
    assert refused(sized(budget + 1))


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
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    fm = frontmatter(run_dir)
    assert (fm["disposition"], fm["outcome"], fm["cause"]) == (GAP, STANDS, CEILING_EXAMINED)
    assert posted(run_dir, 0).startswith(f"{GAP} — {CEILING_EXAMINED}")

    deps, run_dir = deps_over(tmp_path / "broken", ceiling_companion())
    broken = close_with(deps, GAP, recording(faults={"composer": raises(RuntimeError("down"))}))
    assert broken.outcome == "forced-inconclusive"
    assert broken.failure_kind is not None
    body = posted(run_dir, 1)
    assert body.startswith(f"{UNRESOLVED} — {CAUSE_REVIEW_INCOMPLETE}"), body
    assert CEILING_EXAMINED not in body
