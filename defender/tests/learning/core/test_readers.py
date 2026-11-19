"""#923/#1534 - every reader of a finished run's closing record agrees on it: a disposition, an absence, or a fault in its own slot."""
from __future__ import annotations

import logging

import pytest

from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests.support.storage import _agreement1534 as A
from defender.tests.support.storage import _readers1534 as R


def test_the_plans_plant_every_lookup_kind_a_run_handle_can_meet():
    """The planted faults and the episode-only kinds are exactly the lookup's kinds, and every disposition is planted."""
    from defender._vocab import DISPOSITION_VALUES
    from defender.records import closing as C

    plans = [A.plan(label) for label in A.plan_labels()]
    planted = {R.LEGACY_LINK if p.fault == R.LEGACY_LINK else p.fault for p in plans if p.kind == A.ANSWER_FAULT}
    assert planted | set(A.EPISODE_ONLY) == set(C.FAULT_KINDS), "a lookup kind is neither planted nor placed on the episode route"
    assert not planted & set(A.EPISODE_ONLY)
    assert {p.disposition for p in plans if p.kind == A.ANSWER_DISPOSITION} == set(DISPOSITION_VALUES)
    drafted = [p for p in plans if p.extra.get("drafted_disposition") not in (None, p.disposition)]
    assert drafted, "no plan's drafted disposition differs from the committed one"


def _planted(plan: A.Plan, found) -> None:
    """The plant made what the plan means, read back through the lookup (a control on the fixture, not on the reader)."""
    from defender.records import closing as C

    if plan.kind == A.ANSWER_DISPOSITION:
        assert isinstance(found, C.Record), found
        assert found.record.disposition == plan.disposition, found
        assert found.record.drafted_disposition == plan.extra.get("drafted_disposition"), found
    elif plan.kind == A.ANSWER_NEVER:
        assert isinstance(found, C.NeverClosed), found
    else:
        assert isinstance(found, C.CouldNotLook), found
        assert found.kind == plan.fault, found
        assert found.detail, "a fault with an empty detail proves nothing about where the detail goes"


@pytest.mark.parametrize("label", A.plan_labels())
@pytest.mark.parametrize("reader", A.READERS)
def test_every_reader_of_a_run_agrees_with_the_lookup(reader, label, tmp_path, monkeypatch, capsys, caplog):
    """Each record, absence and fault kind reads the same in every reader; a fault in its slot by its wording, the lookup's
    own detail in no outward slot (and in the log of a reader that has one). (V-READERS, V-LOOK, OD19)"""
    from defender.records import closing as C

    caplog.set_level(logging.DEBUG)
    plan = A.plan(label)
    got = A.read(reader, tmp_path / reader, plan, monkeypatch, capsys)
    found = got.found if got.found is not None else C.for_run(got.run)
    _planted(plan, found)
    answer, seen = got.answer, f"{label} via {reader}: {got.answer}"
    if A.refused_before(reader, plan):
        assert answer[0] == A.ANSWER_FAULT, seen
    elif reader == "feedback" and plan.kind != A.ANSWER_DISPOSITION:
        assert answer == (A.ANSWER_UNREADABLE, ""), seen
    elif plan.kind == A.ANSWER_DISPOSITION:
        assert answer == (A.ANSWER_DISPOSITION, plan.disposition), seen
    elif plan.kind == A.ANSWER_NEVER:
        assert answer[0] == A.ANSWER_NEVER, seen
        assert not any(w in " ".join(got.slots) for w in C.FAULT_WORDING.values()), f"an absence was worded as a fault: {seen}"
    elif reader == "worker":
        assert answer == (A.ANSWER_FAULT, plan.fault), seen
    else:
        assert answer[0] == A.ANSWER_FAULT, seen
        assert R.names_only(plan.fault, answer[1]), seen
    if isinstance(found, C.CouldNotLook):
        for slot in got.slots:
            assert found.detail not in slot, f"the lookup's detail reached an outward slot: {seen}"
            assert R.DETAIL_MARK not in slot, f"the database's path reached an outward slot: {seen}"
        if reader in A.LOGGED and not A.refused_before(reader, plan):
            assert found.detail in caplog.text, f"the detail of {plan.fault} reached no log: {seen}"


@pytest.mark.parametrize("reader", A.READERS)
def test_a_malformed_committed_verdict_is_marked_not_coerced(reader, tmp_path, monkeypatch, capsys):
    """A stored disposition outside the vocabulary reads as any other invalid row, never as the member it resembles."""
    from defender.tests.support.runtime.engine._spec923 import MALFORMED_MEMBER_SPELLINGS, NOT_A_MEMBER

    def answer(label, spelling):
        plan = A.Plan(label, fault="row-invalid", invalid_as=spelling)
        got = A.read(reader, tmp_path / label, plan, monkeypatch, capsys).answer
        return got[0], A.fault_kinds_named(got[1]) if got[0] == A.ANSWER_FAULT and reader != "worker" else got[1]

    unknown = answer("unknown", NOT_A_MEMBER)
    assert unknown[0] != A.ANSWER_DISPOSITION, unknown
    for i, spelling in enumerate(MALFORMED_MEMBER_SPELLINGS):
        assert answer(f"malformed-{i}", spelling) == unknown, f"{spelling!r} reads differently from a value that was never a member"
