"""#1579: each judge draw is ONE call through the real judge seam (`_default_judge_seam`) and the
real stage runner, its reply checked inside the call (M20, A5, scope, closed keys). Expected
values are design r3's: `malformed_replies` = requests - 1, or N + 1 for an exhausted draw."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.investigation import observe  # noqa: E402
from defender.records import WIRE_LOG_NAMES  # noqa: E402
from defender.tests.support.learning.core import _typed_output1579 as TY  # noqa: E402
from defender.tests.support.learning.judge import _judge_921 as J  # noqa: E402
from defender.tests.support.learning.judge._memory_store import MemoryStore  # noqa: E402

#: A `lead-set` world reply on a system the world's grant never reached (M20).
UNREACHABLE = {"systems": ["okta"]}


def _episode(tmp_path):
    return J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})


def _grade(ep, calls, *, draws=1):
    seam = J.mod("learning.judge")._default_judge_seam(ep, **{TY.SEAM_MAKE_MODEL: calls})
    with override_allow_model_requests(False):
        return J.grade_at(ep, judge=seam, draws=draws, store=MemoryStore())


def _row(ep, label="b"):
    return J.world_rows(J.judge_record(ep))[label]


def _trace(ep, agent_id):
    return observe.stage_trace_path(ep, WIRE_LOG_NAMES.agent_trace(agent_id))


def test_1579_m20_is_refused_in_the_call_and_the_corrected_reply_is_the_draw(tmp_path):
    """O1/O5/O6: world b's first reply files `lead-set` on a system its grant never reached; the
    reason goes back in the same call, the corrected reply is the draw, one trace holds both."""
    ep = _episode(tmp_path)
    b = J.world_id(ep, "b")
    calls = TY.ScriptedCalls([J.reply_doc(**UNREACHABLE), J.reply_doc()], [J.reply_doc()],
                             [J.family_reply()])

    _grade(ep, calls)

    assert calls.request_counts() == [2, 1, 1], "a re-ask became a call of its own"
    sent = " ".join(calls.reasons_sent(0))
    assert "lead-set" in sent
    assert "okta" in sent, calls.reasons_sent(0)
    assert J.draw_doc(ep, "b", 0)["systems"] == [J.HOLDING_SYSTEM]
    row = _row(ep)
    assert (row["completed_draws"], row["malformed_replies"]) == (1, 1), row
    assert TY.response_records(_trace(ep, f"judge:{b}:0")) == 2
    assert not _trace(ep, f"judge:{b}:0:1").exists(), "the retired per-attempt call id is back"
    traces = [p for p in J.wire_logs(ep) if "framed" not in p.name]
    assert len(traces) == 3, f"more than one trace per draw: {[p.name for p in traces]}"
    framed = ep / "wire_logs" / WIRE_LOG_NAMES.agent_framed_trace(f"judge:{b}:0")
    assert framed.is_file(), "the draw's framed wire log is gone"
    logged = json.loads(framed.read_text(encoding="utf-8").splitlines()[0])
    assert logged["agent_id"] == f"judge:{b}:0"
    assert logged["failure"] is None
    assert logged["reply"] == J.draw_doc(ep, "b", 0), "the wire log's reply is not the draw document"


def test_1579_an_unknown_top_level_key_is_refused_in_the_call(tmp_path):
    """D2/P1: an unknown key is refused with its name and re-asked; the same reply without it
    (world c's) is accepted at the first request."""
    ep = _episode(tmp_path)
    calls = TY.ScriptedCalls([J.reply_doc(side_note="a key the prompt never asks for"),
                              J.reply_doc()], [J.reply_doc()], [J.family_reply()])

    _grade(ep, calls)

    assert calls.request_counts() == [2, 1, 1]
    assert "side_note" in " ".join(calls.reasons_sent(0)), calls.reasons_sent(0)
    assert "side_note" not in json.dumps(J.draw_doc(ep, "b", 0))
    assert _row(ep, "c")["malformed_replies"] == 0


def test_1579_a_world_only_field_in_a_family_reply_is_refused_in_the_call(tmp_path):
    """Scope: the family call's reply carrying a world-only key is re-asked in-call with its name."""
    ep = _episode(tmp_path)
    calls = TY.ScriptedCalls(
        [J.reply_doc()], [J.reply_doc()],
        [J.family_reply(findings=[J.finding_doc()]), J.family_reply()])

    _grade(ep, calls)

    assert calls.request_counts() == [1, 1, 2]
    assert "investigator_findings" in " ".join(calls.reasons_sent(2)), calls.reasons_sent(2)
    family = J.judge_record(ep)["family"]
    assert (family["completed_draws"], family["malformed_replies"]) == (1, 1), family
    assert "investigator_findings" not in J.draw_doc(ep, "family", 0)


def test_1579_an_exhausted_draw_is_malformed_with_the_last_reason_and_no_draw_file(tmp_path):
    """O3/P5: three refused replies end the draw: no file (an earlier pass's is removed),
    `malformed_replies` = N + 1, the last reason named, no crash on the row; c is unaffected."""
    ep = _episode(tmp_path)
    stale = ep / "worlds" / J.world_id(ep, "b") / "judge" / "0.yaml"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("bucket: lead-set\n", encoding="utf-8")
    bad = J.reply_doc(**UNREACHABLE)
    calls = TY.ScriptedCalls([bad, bad, bad], [J.reply_doc()], [J.family_reply()])

    _grade(ep, calls)

    assert calls.request_counts() == [TY.MAX_REQUESTS, 1, 1]
    assert J.draw_files(ep, "b") == [], "an exhausted draw left a draw file"
    row = _row(ep)
    assert (row["completed_draws"], row["malformed_replies"]) == (0, TY.MAX_REQUESTS), row
    assert "okta" in str(row.get("not_measured_reason")), row
    assert "draws_failed_reason" not in row, "an unusable reply was counted as a crashed call"
    assert J.draw_files(ep, "c"), "one world's exhausted draw cost another world's"


def test_1579_an_unresolved_pointer_is_a_drop_not_a_refusal(tmp_path):
    """P4: a finding whose pointers all miss is accepted at the first request and dropped by the
    ledger as before; the draw is not malformed."""
    ep = _episode(tmp_path)
    reply = J.reply_doc(findings=[J.finding_doc(evidence=["there was no evidence, really"])])
    calls = TY.ScriptedCalls([reply], [J.reply_doc()], [J.family_reply()])

    _grade(ep, calls)

    assert calls.request_counts() == [1, 1, 1], "an unresolved pointer re-asked the call"
    assert _row(ep)["malformed_replies"] == 0
    assert len(J.draw_doc(ep, "b", 0)["investigator_findings"]) == 1
    lanes = {e["lane"] for e in J.judge_record(ep)["dispositions"] if "/b/0/" in e["finding_id"]}
    assert lanes == {"dropped_unresolved"}, lanes


def test_1579_a_size_failure_on_the_first_request_stops_the_later_draws(tmp_path):
    """A23: a 413 on request 1 (`requests == 1`) stops world b's later draws."""
    ep = _episode(tmp_path)
    ok = [J.reply_doc()]
    calls = TY.ScriptedCalls([TY.http_413()], ok, ok, [J.family_reply()], [J.family_reply()])

    _grade(ep, calls, draws=2)

    assert len(calls.requests) == 5, "b's second draw was asked after a size refusal"
    assert _row(ep)["completed_draws"] == 0
    assert _row(ep).get("draws_failed_reason")


def test_1579_a_size_failure_on_a_re_ask_fails_that_draw_alone(tmp_path):
    """A23 narrowed: a 413 on request 2 (longer history) is a transport failure of that draw;
    b's next draw still runs."""
    ep = _episode(tmp_path)
    ok = [J.reply_doc()]
    calls = TY.ScriptedCalls([J.reply_doc(**UNREACHABLE), TY.http_413()], ok, ok, ok,
                             [J.family_reply()], [J.family_reply()])

    _grade(ep, calls, draws=2)

    assert len(calls.requests) == 6, "b's second draw was not asked after a re-ask's size failure"
    row = _row(ep)
    assert row["completed_draws"] == 1, row
    assert row.get("draws_failed_reason"), row
    assert [p.name for p in J.draw_files(ep, "b")] == ["1.yaml"]
