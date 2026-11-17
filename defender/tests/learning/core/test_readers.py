"""#923/#1534 - every reader of a finished run's closing record agrees on it: a disposition, an absence, or a fault in its own slot."""
from __future__ import annotations

import logging

from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests.support.storage import _agreement1534 as A
from defender.tests.support.storage import _readers1534 as R

#: Faults a run-handle reader can meet, from the lookup's own kinds less the episode view's.
FAULTS = ("database-missing", "pointer-unreadable", "store-unreadable", "schema-version", "recorded-before-1534",
          "legacy-link", "row-invalid")


def _plans() -> list[A.Plan]:
    from defender._vocab import DISPOSITION_VALUES
    from defender.records import closing as C

    assert set(FAULTS) | set(A.EPISODE_ONLY) == set(C.FAULT_KINDS), "a lookup kind is neither planted nor placed on the episode route"
    members = ["benign", "malicious", "unresolved"]
    members.append(next(d for d in DISPOSITION_VALUES if d not in members))
    plans = [A.Plan(f"is-{d}", disposition=d) for d in members]
    plans += [A.Plan("never-no-row", closed=False), A.Plan("never-no-pointer", fault=R.NO_POINTER)]
    plans += [A.Plan(f"fault-{k}", fault=k if k != "legacy-link" else R.LEGACY_LINK) for k in FAULTS]
    plans.append(A.Plan("fault-store-unreadable-at-query", fault="store-unreadable", at_query=True))  # reaches the run page too
    return plans


def _answers(tmp_path, plan, monkeypatch, capsys) -> dict[str, tuple[tuple[str, str], list[str]]]:
    def at(reader):
        return tmp_path / f"{reader}-{plan.label}"

    out = {"ticket": A.ticket(at("ticket"), plan), "trace": A.trace(at("trace"), plan, monkeypatch, capsys),
           "held_out": A.held_out(at("held"), plan), "feedback": A.feedback(at("feedback"), plan),
           "worker": A.worker(at("worker"), plan)}
    if A.applies("page", plan):
        out["page"] = A.page(at("page"), plan, monkeypatch)
    return out


def test_every_reader_of_a_run_agrees_with_the_lookup(tmp_path, monkeypatch, capsys, caplog):
    """Records, absences and each fault kind read the same in every run-handle reader and the worker; wording in each slot, the detail only in the log. (V-READERS, V-LOOK)"""
    from defender.records import closing as C

    caplog.set_level(logging.DEBUG)
    for plan in _plans():
        caplog.clear()
        answers = _answers(tmp_path, plan, monkeypatch, capsys)
        for reader, (answer, slots) in answers.items():
            seen = f"{plan.label} via {reader}: {answer}"
            if reader == "feedback" and plan.kind != A.ANSWER_DISPOSITION:
                assert answer == (A.ANSWER_UNREADABLE, ""), seen
            elif plan.kind == A.ANSWER_DISPOSITION:
                assert answer == (A.ANSWER_DISPOSITION, plan.disposition), seen
            elif plan.kind == A.ANSWER_NEVER:
                assert answer[0] == A.ANSWER_NEVER, seen
                assert not any(w in " ".join(slots) for w in C.FAULT_WORDING.values()), f"an absence was worded as a fault: {seen}"
            elif reader == "worker":
                assert answer == (A.ANSWER_FAULT, plan.fault), seen
            else:
                assert answer[0] == A.ANSWER_FAULT, seen
                assert R.names_only(plan.fault, answer[1]), seen
            if plan.kind == A.ANSWER_FAULT:
                assert not any(R.DETAIL_MARK in slot for slot in slots), f"the detail reached an outward slot: {seen}"
        if plan.fault in ("database-missing", "store-unreadable") and not plan.at_query:
            assert R.DETAIL_MARK in caplog.text, f"the detail of {plan.fault} reached no log"


def test_a_malformed_committed_verdict_is_marked_not_coerced(tmp_path, monkeypatch, capsys):
    """A stored disposition outside the vocabulary reads as any other invalid row in every reader, never as the member it resembles."""
    from defender.tests.support.runtime.engine._spec923 import MALFORMED_MEMBER_SPELLINGS, NOT_A_MEMBER

    def read(label, spelling):
        plan = A.Plan(label, fault="row-invalid", invalid_as=spelling)
        got = _answers(tmp_path / label, plan, monkeypatch, capsys)
        return {reader: answer for reader, (answer, _slots) in got.items()}

    unknown = read("unknown", NOT_A_MEMBER)
    for i, spelling in enumerate(MALFORMED_MEMBER_SPELLINGS):
        answers = read(f"malformed-{i}", spelling)
        assert answers == unknown, f"{spelling!r} reads differently from a value that was never a member"
        assert not any(a == (A.ANSWER_DISPOSITION, "malicious") for a in answers.values()), answers
