"""#672 §D — faults and the circuit breaker: refusals, store failures, breaker state.

Split out of `test_closed_ticket_tool_672.py` by #720; that module holds the spec
narrative and the registration/seam demands, and `_closed_ticket_672.py` holds the
drive harness these tests share.
"""
from __future__ import annotations

import asyncio
import re

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.learning.core.config import RunUnprocessable  # noqa: E402
from defender.runtime import circuit_breaker  # noqa: E402
from defender.scripts.adapters.faults import ConfigFault, TransportFault, UpstreamFault  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests._closed_ticket_672 import (  # noqa: E402
    CASE,
    DONE,
    OTHER_KEY,
    _case,
    _drive,
    _feedback,
    _get,
    _get_calls,
    _list,
    _list_calls,
    _ticket_registry,
)

pytestmark = pytest.mark.e2e



def test_open_ticket_refused_as_failed_result(tmp_path):
    """[d5_nonclosed_refused_as_fault] Driving get_closed_ticket on an open in-flight ticket
    (another case's — the self-case's key never reaches the store, d23) returns a FAILED
    tool result carrying the exit-1 class detail and none of the ticket's content: the
    answer key stays unreadable through the live-store read. A non-closed refusal is a
    BUSINESS refusal (Fork E's taxonomy line): it writes its capture row but never
    contributes to the breaker. Fault content cites c2/g5 (executed: UpstreamFault
    exit_code=1, no payload, on status != closed under require_closed=True)."""
    rec = VerbRecorder()
    other_inflight = "20260719T2300Z-concurrent-case"
    run = _drive(
        tmp_path, [_get(other_inflight), DONE],
        registry=_ticket_registry(
            rec,
            get=[("raise", UpstreamFault(
                f"{other_inflight} is status='open', not 'closed' (--require-closed)"))],
        ),
    )
    assert run.out.strip()                       # the judge run continues
    assert "exit=1" in run.all_text              # the query-error class, distinguishable
    assert "status='open'" in run.all_text       # the salt-wrapped detail
    (row,) = run.rows()
    assert row["exit_code"] == 1
    assert row["error_class"] == "agent-fixable"
    assert not run.breaker().get("systems", {}).get("ticket", {}).get("failures"), (
        "a business refusal must not contribute to the breaker"
    )
    (g,) = _get_calls(rec)
    assert g.params["require_closed"] is True    # positive control: the pin was on the wire


@pytest.mark.parametrize(
    "detail",
    [
        "SOC-9999 not found (404)",
        "SOC-1 is status='in_progress', not 'closed' (--require-closed)",
        "SOC-1 is status=None, not 'closed' (--require-closed)",
    ],
    ids=["not-found-404", "third-lifecycle-state", "status-less-200"],
)
def test_nonclosed_refusal_is_one_business_fault_class(tmp_path, detail):
    """[d5_nonclosed_refused_as_fault — dispositions consensus ×3] Key-not-found (404), an
    unenumerated third lifecycle state (`in_progress` — the store's REAL enum, executed by
    the Fork D probe against app.py:27), and a status-less 200 all collapse into the ONE
    refused (non-closed/404) class: a failed exit-1 result either way, free-text detail the
    only differentiator, no distinct never-existed path, and — Fork E's line — none of them
    contributes to the breaker (the affirmative closed check refusing them is a business
    refusal, not an infra fault). The design's contract is BINARY: closed is readable,
    everything else refuses like open."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [_get("SOC-1"), DONE],
                 registry=_ticket_registry(rec, get=[("raise", UpstreamFault(detail))]))
    assert run.out.strip()
    assert "exit=1" in run.all_text
    assert "TKT-CONTENT" not in run.all_text
    assert not run.breaker().get("systems", {}).get("ticket", {}).get("failures")


def test_unreachable_store_is_failed_result(tmp_path):
    """[d6_unreachable_store_fault] An unreachable/misconfigured ticket store surfaces as a
    failed tool result carrying the infra fault class (exit-2) detail — the judge run
    CONTINUES to its verdict — and (Fork E, amending this fixture) the fault is RECORDED
    against the breaker: one infra failure on `ticket`. Fault content cites c4/g8 (executed:
    ConfigFault/TransportFault → exit-2 class with stderr detail).

    # rejected: scale-dive tradeoff — no outer wall-clock budget; the transport's mandatory
    # inner timeout (x4) is the only kill, the same tradeoff the query tool accepted.
    """
    rec = VerbRecorder()
    run = _drive(
        tmp_path, [_get(OTHER_KEY), DONE],
        registry=_ticket_registry(
            rec, get=[("raise", ConfigFault("config file not found: ticket/config.env"))]),
    )
    assert run.out.strip()
    assert "exit=2" in run.all_text
    assert "config file not found" in run.all_text
    (row,) = run.rows()
    assert row["exit_code"] == 2
    assert row["error_class"] == "infra"
    assert run.breaker().get("systems", {}).get("ticket", {}).get("failures") == 1


def test_unmapped_fault_returns_envelope(tmp_path):
    """[d7_unmapped_fault_enveloped] A fault nobody mapped — a bare exception out of the
    transport thread — comes back as the fault-class envelope in a NORMAL tool result:
    nothing unwinds out of the agent loop, the judge reaches its verdict, and (Fork B/E,
    revising this entry) the attempt still writes its capture row and files as infra
    against the breaker — an unmapped fault must write a row, never delete one."""
    rec = VerbRecorder()
    run = _drive(
        tmp_path, [_get(OTHER_KEY), DONE],
        registry=_ticket_registry(
            rec, get=[("raise", RuntimeError("connection reset by peer mid-body"))]),
    )
    assert run.out.strip()                          # no unwind
    assert "connection reset by peer" in run.all_text
    (row,) = run.rows()
    assert row["exit_code"] != 0
    assert row["error_class"] == "infra"
    assert run.breaker().get("systems", {}).get("ticket", {}).get("failures") == 1


class _ResolutionFaultVerbs:
    """A registry whose verb RESOLUTION itself faults — the production shape when
    ``ModuleVerbRegistry.verbs('ticket')`` lazily imports a broken adapter (an import-time error,
    or a malformed/absent ``VERBS`` mapping → ``KeyError``). Every happy-path fake resolves
    cleanly, so this is the only way to drive the resolution seam."""

    def systems(self):
        return ("ticket",)

    def verbs(self, system):
        raise RuntimeError("ticket adapter failed to import: No module named 'httpx'")


def test_registry_resolution_fault_recorded_not_unwound(tmp_path):
    """[d7_unmapped_fault_enveloped — the registry-resolution seam] A fault RESOLVING the verb
    from the registry (not inside the verb body) faults-and-continues exactly like a body fault:
    a failed tool result, no unwind out of ``agent.iter()``, a capture row, and an infra
    contribution to the breaker. Regression for the finalize fix: before it, the resolution
    ``verbs.verbs(SYSTEM)[...]`` sat OUTSIDE ``_run_verb``'s fault seam, so a broken adapter
    unwound the judge stage with no row and no breaker record — invisible to the rest of the
    suite because every fake registry resolves cleanly. The 'write a row, never delete one'
    invariant this module documents must hold for the resolution too, not only the transport."""
    run = _drive(tmp_path, [_get(OTHER_KEY), DONE], registry=_ResolutionFaultVerbs())
    assert run.out.strip()                       # the judge run reaches its verdict, no unwind
    assert "ticket adapter failed to import" in run.all_text
    (row,) = run.rows()
    assert row["exit_code"] != 0
    assert row["error_class"] == "infra"
    assert run.breaker().get("systems", {}).get("ticket", {}).get("failures") == 1


def test_list_closed_tickets_malformed_store_response(tmp_path):
    """[d7_unmapped_fault_enveloped — dispositions consensus ×2] A store response whose shape
    defeats the tool — a listing whose `tickets` is not a list, or a get body that is not an
    object — lands in the same O4/M4 catch-all: a failed tool result carrying fault detail,
    never an unwind, never a retry loop, and (Fork E/B revision) the fault writes its
    capture row and CONTRIBUTES to the breaker (a store emitting garbage is a malformed-
    response infra fault, not the model's mistake). ROUND 3 (C5): the two malformed shapes
    are driven in SEPARATE runs, so the list-path breaker contribution is independently
    attributable to the list_closed_tickets call — the old single drive seeded a malformed
    get beside the malformed list, and its `failures >= 1` was satisfiable by the get
    alone, leaving list→breaker contribution unpinned in either direction. The malformed
    content itself must not be served as a success view."""
    # (1) The malformed LISTING alone: the breaker trip here is the list call's own.
    rec = VerbRecorder()
    run = _drive(
        tmp_path, [_list(label="x"), DONE],
        registry=_ticket_registry(
            rec, lst=[("return", {"tickets": "TKT-GARBAGE not-a-list", "total": "?"})]),
    )
    assert run.out.strip()                          # the run survived
    assert not _get_calls(rec), "attribution guard: no sibling get in this drive"
    assert len(run.rows()) == 1, "the malformed-list fault must still write its capture row"
    assert run.breaker().get("systems", {}).get("ticket", {}).get("failures", 0) >= 1, (
        "the malformed LIST response did not contribute to the breaker (Fork E, both tools)"
    )
    for chunk in re.findall(r"exit=0.*?(?=exit=|\Z)", run.all_text, re.S):
        assert "TKT-GARBAGE" not in chunk

    # (2) The malformed GET body in its own run: the same O4/M4 catch-all class.
    rec2 = VerbRecorder()
    run2 = _drive(
        tmp_path, [_get(OTHER_KEY), DONE],
        registry=_ticket_registry(rec2, get=[("return", ["TKT-GARBAGE", "not-an-object"])]),
        case=_case(tmp_path, name=CASE + "-malget"),
    )
    assert run2.out.strip()
    assert len(run2.rows()) == 1, "the malformed-get fault must still write its capture row"
    assert run2.breaker().get("systems", {}).get("ticket", {}).get("failures", 0) >= 1
    for chunk in re.findall(r"exit=0.*?(?=exit=|\Z)", run2.all_text, re.S):
        assert "TKT-GARBAGE" not in chunk


def test_store_fault_single_attempt(tmp_path):
    """[d8_single_attempt_no_retry] On a store fault the tool makes exactly ONE transport
    attempt — never a retry loop (minted from O4). Positive control: the single attempt is
    observed (the fake recorded it; its row is on disk). Fork F rider: an attempt the run
    never finishes still counts as the one attempt — no re-drive on any path (asserted for
    the cancellation shape in test_control_flow_exceptions_propagate)."""
    rec = VerbRecorder()
    run = _drive(
        tmp_path, [_get(OTHER_KEY), DONE],
        registry=_ticket_registry(rec, get=[("raise", TransportFault("service unreachable"))]),
    )
    assert run.out.strip()
    assert len(_get_calls(rec)) == 1, "the tool re-drove the transport on a fault"
    (row,) = run.rows()
    assert row["exit_code"] == 2


def test_control_flow_exceptions_propagate(tmp_path):
    """[d9_control_flow_reraise] Control-flow exceptions re-raise out of the tool body
    instead of being swallowed into a fault envelope: the breaker's RunAborted kills the
    stage (surfacing as the stage ladder's per-run quarantine, RunUnprocessable naming it —
    never a tool-result envelope the run talks past); CancelledError re-raises IMMEDIATELY
    (Fork F: cut loose, documented — no await-to-clean-stop, and the unfinished attempt
    still counts as the one attempt, d8); ModelRetry reaches the MODEL as retry feedback
    and the run continues."""
    # RunAborted — the kill switch must escape the tool, not become a result.
    rec = VerbRecorder()
    with pytest.raises(RunUnprocessable, match="RunAborted"):
        _drive(tmp_path, [_get(OTHER_KEY), DONE],
               registry=_ticket_registry(
                   rec, get=[("raise", circuit_breaker.RunAborted(5, ["ticket"]))]))
    assert len(_get_calls(rec)) == 1

    # CancelledError — re-raises immediately; the attempt is not re-driven.
    rec2 = VerbRecorder()
    with pytest.raises(asyncio.CancelledError):
        _drive(tmp_path, [_get(OTHER_KEY), DONE],
               registry=_ticket_registry(rec2, get=[("raise", asyncio.CancelledError())]),
               case=_case(tmp_path, name=CASE + "-cancel"))
    assert len(_get_calls(rec2)) == 1, "Fork F: the unfinished attempt is the one attempt"

    # ModelRetry — retry feedback, not a fault envelope; the run continues.
    from pydantic_ai.exceptions import ModelRetry
    rec3 = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), DONE],
                 registry=_ticket_registry(
                     rec3, get=[("raise", ModelRetry("TKT-RETRY narrow the key"))]),
                 case=_case(tmp_path, name=CASE + "-retry"))
    assert run.out.strip()
    assert "TKT-RETRY" in run.all_text


def test_store_breaker_open_when_judge_reads(tmp_path):
    """[d6_unreachable_store_fault — Fork E, §7: the isolation recommendation was REJECTED]
    An ALREADY-OPEN ticket breaker (tripped before the judge's first read) yields an
    immediate FAILED result with NO transport attempt — not a bypass, not a full-price
    call: the judge honors the same breaker the query tool's machinery keys on `ticket`.
    The breaker is seeded through the real primitive (circuit_breaker.record_outcome), so
    the test re-probes the trip threshold on every run. The observable is Fork E's honor
    arm itself (F-round rewrite of the blind reader's two near-vacuous greps — `"ticket"`
    and `"down"` were satisfiable by the ambient prompt and pinned wording, not behavior):
    the refusal REACHED the model on the post-prompt feedback channel, it is not a success
    view, and no ticket content crossed."""
    case = _case(tmp_path)
    lrd = case[3]
    for _ in range(circuit_breaker.PER_SYSTEM_FAIL_LIMIT):
        circuit_breaker.record_outcome(lrd, "ticket", 2)
    assert circuit_breaker.is_tripped(lrd, "ticket")

    rec = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), DONE], registry=_ticket_registry(rec), case=case)
    assert run.out.strip()                       # a failed result, not an unwind
    assert not rec.calls, "an open breaker must mean NO transport attempt"
    feedback = _feedback(run)
    assert feedback.strip(), "the breaker-open refusal never reached the model"
    assert "exit=0" not in feedback, "the breaker-open path returned a SUCCESS envelope"
    assert "ticket" in feedback, (
        "the refusal must name the tripped system IN the result content — the old grep was "
        "satisfied by the tool names in the ambient prompt"
    )
    assert "TKT-CONTENT-777" not in run.all_text


def test_store_breaker_open_blocks_list_path(tmp_path):
    """[d6_unreachable_store_fault — Fork E on the LIST path; ROUND 3, C5] Fork E's
    resolved wording is UNQUALIFIED over the tool — "an open breaker gives an immediate
    failed result with no transport attempt" — so the honor arm binds list_closed_tickets
    exactly as it binds get_closed_ticket: with the `ticket` breaker already tripped
    (seeded through the real primitive, circuit_breaker.record_outcome), a list call
    yields an immediate FAILED result with NO transport attempt — the injected registry
    records zero list-tickets calls — the refusal reaches the model on the post-prompt
    feedback channel, names the tripped system, is not a success envelope, and no ticket
    content crosses interacts(benign_judge->list_closed_tickets).response. Before this
    test, honor was pinned on get only, so an implementation wiring breaker honor into
    the get body rather than the shared seam greened the suite against Fork E's own
    wording — this test is the discriminator that fails it."""
    case = _case(tmp_path)
    lrd = case[3]
    for _ in range(circuit_breaker.PER_SYSTEM_FAIL_LIMIT):
        circuit_breaker.record_outcome(lrd, "ticket", 2)
    assert circuit_breaker.is_tripped(lrd, "ticket")

    rec = VerbRecorder()
    run = _drive(tmp_path, [_list(q="precedent"), DONE],
                 registry=_ticket_registry(rec), case=case)
    assert run.out.strip()                       # a failed result, not an unwind
    assert not _list_calls(rec), "an open breaker must mean NO list transport attempt"
    assert not rec.calls                         # no other verb was reached either
    feedback = _feedback(run)
    assert feedback.strip(), "the breaker-open refusal never reached the model"
    assert "exit=0" not in feedback, "the breaker-open list path returned a SUCCESS envelope"
    assert "ticket" in feedback, "the refusal must name the tripped system IN the result"
    assert "TKT-CONTENT-777" not in run.all_text, (
        "the registry's default listing crossed the envelope despite the open breaker"
    )


def test_repeated_store_failures_across_one_judge_run(tmp_path):
    """[d8_single_attempt_no_retry — Fork E's annexed premise, REWRITTEN by §7] Repeated
    judge-side store failures within one run TRIP the breaker: the converged "each call
    pays full price, no breaker participation, only the run request budget bounds it"
    assertion is rewritten, not confirmed. Two infra faults reach PER_SYSTEM_FAIL_LIMIT;
    the third read fails FAST — no transport attempt, no inner-timeout cost — and the run
    request budget is no longer the only bound. Judge-side faults CONTRIBUTE (they are the
    same machinery as the query tool's capture, Fork B)."""
    assert circuit_breaker.PER_SYSTEM_FAIL_LIMIT == 2  # the scenario is built on this
    rec = VerbRecorder()
    run = _drive(
        tmp_path,
        [_get("SOC-1"), _get("SOC-2"), _get("SOC-3"), DONE],
        registry=_ticket_registry(
            rec,
            get=[("raise", TransportFault("service unreachable")),
                 ("raise", TransportFault("service unreachable"))],
        ),
    )
    assert run.out.strip()
    assert len(_get_calls(rec)) == 2, (
        "the third call after the trip must fail fast with NO transport attempt"
    )
    sysrec = run.breaker().get("systems", {}).get("ticket", {})
    assert sysrec.get("failures") == 2
    assert "tripped_at" in sysrec
