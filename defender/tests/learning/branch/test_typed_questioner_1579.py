"""#1579: the questioner answers through an output tool, validated inside the call, through the REAL
production seam (`branch.seams.model_seam`) and the real stage runner, with a scripted model.

Only this layer tells an in-call re-ask from a call-site check: each case reads the reason the model
was sent, the call's request count, and the call's one trace. The rules' breadth is in the seam-fake
suites (`test_triplet_roles.py`, `test_premise_check_1561.py`). N = 2: at most 3 requests per call.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.investigation import observe  # noqa: E402
from defender.records import WIRE_LOG_NAMES  # noqa: E402
from defender.tests.support.learning.branch import _triplet_947 as T  # noqa: E402
from defender.tests.support.learning.core import _typed_output1579 as TY  # noqa: E402

PREBRANCH = [{"call": {"system": "elastic", "verb": "alerts", "params": {"limit": 10}},
              "answer": {"total": 6}}]
CONFLICT = {"label": "b", "fact_id": "f1", "evidence": "the pre-branch answer holds 6 alerts"}


def _plan(**over):
    """Call 1's reply as the prompt asks for it: no `axes`, no `base_label_basis`, no id."""
    doc = {"base_story": "the captured story", "base_disposition": "benign",
           "discriminator": {"predicate": "p"},
           "worlds": [{"label": "b", "axis": "who", "facts": [T.fact("f1")]},
                      {"label": "c", "axis": "when", "facts": [T.fact("f2")]}]}
    doc.update(over)
    return doc


def _seat(story: str = "story b", **over):
    return {"story": story, "axis": "who", "disposition_declared": "malicious",
            "label_basis": "policy-rule", **over}


def _revision(**over):
    return {**_seat("b rebuilt"), "facts": [T.fact("f1r")], **over}


def _check(*conflicts):
    return {"conflicts": list(conflicts)}


def _author(tmp_path, calls, *, checked: bool = False, **kw):
    episode = T.episode(tmp_path)
    seam = T.mod("learning.branch.seams").model_seam(episode, **{TY.SEAM_MAKE_MODEL: calls})
    with override_allow_model_requests(False):
        family = T.mod("learning.branch.questioner").author_family(
            source_run_dir=tmp_path, episode_dir=episode, invoke=seam, leads=[], alert={},
            frontier="", **({"premise_check": seam, "prebranch": PREBRANCH} if checked else {}), **kw)
    return family, episode


def _trace(episode, agent_id):
    return observe.stage_trace_path(episode, WIRE_LOG_NAMES.agent_trace(agent_id))


def _world(family, label):
    return next(w for w in family["worlds"] if w["label"] == label)


def _labels(family):
    return [w["label"] for w in family["worlds"]]


def _told(calls, call: int, token: str) -> bool:
    return any(token in reason for reason in calls.reasons_sent(call))


# call 1


def test_call_1_is_fixed_in_call_and_the_seats_are_shown_the_accepted_document_as_json(tmp_path):
    """O1/O5 at call 1: a plan missing `discriminator` is re-asked within the call with the reason;
    the seats see the accepted plan as JSON, never the refused attempt; the trace holds both requests."""
    refused = {k: v for k, v in _plan(base_story="REFUSED-ATTEMPT").items() if k != "discriminator"}
    calls = TY.ScriptedCalls([refused, _plan()], [_seat("story b")], [_seat("story c", axis="when")])

    family, episode = _author(tmp_path, calls)

    assert calls.request_counts() == [2, 1, 1]
    assert _told(calls, 0, "discriminator"), calls.reasons_sent(0)
    assert family["discriminator"] == {"predicate": "p"}
    assert (family["base_story"], _labels(family)) == ("the captured story", ["a", "b", "c"])
    b = _world(family, "b")
    assert (b["role"], b["story"], [f["fact_id"] for f in b["facts"]]) == ("B", "story b", ["f1"])
    for seat in (1, 2):
        prompt = calls.user_prompt(seat)
        assert '"base_story": "the captured story"' in prompt, "call 1 is not re-shown as its JSON document"
        assert '"predicate": "p"' in prompt
        assert "REFUSED-ATTEMPT" not in prompt, "the seat was shown the refused attempt"
    assert TY.response_records(_trace(episode, "questioner")) == 2


_REFUSED_PLANS = {
    "axes never asked for": (lambda: _plan(axes=["who", "when"]), "axes"),
    "base_label_basis never asked for": (lambda: _plan(base_label_basis="policy-rule"), "base_label_basis"),
    "world_id": (lambda: _plan(world_id=T.fixture_world_id("b")), "world_id"),
    "unknown key in a planned world": (lambda: _plan(worlds=[
        {"label": "b", "axis": "who", "facts": [T.fact("f1")], "zz_planned": "x"},
        {"label": "c", "axis": "when", "facts": [T.fact("f2")]}]), "zz_planned"),
    "duplicate labels": (lambda: _plan(worlds=[
        {"label": "b", "axis": "who", "facts": [T.fact("f1")]},
        {"label": "b", "axis": "when", "facts": [T.fact("f2")]}]), "twice"),
    "bad base disposition": (lambda: _plan(base_disposition="maybe"), "disposition"),
}


@pytest.mark.parametrize("case", list(_REFUSED_PLANS))
def test_call_1_refusals_are_re_asked_in_call_so_no_seat_is_paid_for_a_bad_plan(tmp_path, case):
    """P1/P2: each rule the manifest would refuse after two paid seats is the model's to fix in call 1."""
    build, token = _REFUSED_PLANS[case]
    calls = TY.ScriptedCalls([build(), _plan()], [_seat()], [_seat("story c", axis="when")])

    family, _episode = _author(tmp_path, calls)

    assert calls.request_counts() == [2, 1, 1]
    assert _told(calls, 0, token), calls.reasons_sent(0)
    assert _labels(family) == ["a", "b", "c"]


def test_a_call_1_that_never_comes_right_refuses_the_episode_after_one_plus_n_requests(tmp_path):
    """O2/O3/P3: three refused plans end `BranchError` naming the call and the last reason; no seat is called."""
    bad = _plan(base_story="")
    calls = TY.ScriptedCalls([bad, bad, bad], [_seat()], [_seat("story c")])

    with pytest.raises(T.mod("learning.branch.questioner").BranchError) as raised:
        _author(tmp_path, calls)

    assert calls.request_counts() == [TY.MAX_REQUESTS]
    assert "base_story" in str(raised.value), str(raised.value)
    assert not calls.exhausted(), "a seat's script was consumed after call 1 was refused"


# a seat


def test_a_seat_key_outside_the_four_is_re_asked_in_the_seat_call_and_not_discarded(tmp_path):
    """O1/P1 at a seat: `facts` is not a seat's to write — refused in-call with the reason, never
    dropped; the corrected reply composes; the seat's trace holds both requests (O5)."""
    calls = TY.ScriptedCalls([_plan()], [_seat("REFUSED", facts=[T.fact("f9")]), _seat("story b")],
                             [_seat("story c", axis="when")])

    family, episode = _author(tmp_path, calls)

    assert calls.request_counts() == [1, 2, 1]
    assert _told(calls, 1, "facts"), calls.reasons_sent(1)
    b = _world(family, "b")
    assert (b["story"], [f["fact_id"] for f in b["facts"]]) == ("story b", ["f1"])
    assert TY.response_records(_trace(episode, "questioner:b")) == 2


def test_a_seat_that_answers_in_prose_three_times_refuses_the_episode_and_seat_c_is_never_called(tmp_path):
    """O3/O4/P3: three text answers — the last a bare YAML document that parsed before #1579 — end
    `BranchError` naming the seat and the last reason, after 1 + N requests."""
    yaml_text = "story: b\naxis: who\ndisposition_declared: malicious\nlabel_basis: policy-rule\n"
    calls = TY.ScriptedCalls([_plan()], ["I think b is", "prose again", yaml_text], [_seat("story c")])

    with pytest.raises(T.mod("learning.branch.questioner").BranchError) as raised:
        _author(tmp_path, calls)

    assert calls.request_counts() == [1, TY.MAX_REQUESTS], "seat C was asked after B was refused"
    message = str(raised.value)
    assert "seat B" in message or "questioner:b" in message, message
    assert calls.reasons_sent(1)[-1].split("\n\n")[0] in message, (
        f"the last reason the model was sent is not in the refusal: {message}")


# the premise check, a revision and the re-check


def test_the_premise_check_refuses_a_malformed_conflicts_list_in_call(tmp_path):
    """O1 at the check: `conflicts` must be a list — re-asked once with the reason; the corrected
    reply (no conflict) is the call's result."""
    calls = TY.ScriptedCalls([_plan()], [_seat()], [_seat("story c", axis="when")],
                             [{"conflicts": "none"}, _check()])

    family, _episode = _author(tmp_path, calls, checked=True)

    assert calls.request_counts() == [1, 1, 1, 2]
    assert _told(calls, 3, "conflicts"), calls.reasons_sent(3)
    assert _labels(family) == ["a", "b", "c"]


def test_a_check_the_call_cannot_get_right_names_no_world(tmp_path):
    """P3 at a check: exhausted after 1 + N requests, no world is named, the family is as authored."""
    bad = {"conflicts": "none"}
    calls = TY.ScriptedCalls([_plan()], [_seat()], [_seat("story c", axis="when")], [bad, bad, bad])
    recorded: list = []

    family, _episode = _author(tmp_path, calls, checked=True, record_revisions=recorded.append)

    assert calls.request_counts() == [1, 1, 1, TY.MAX_REQUESTS]
    assert _labels(family) == ["a", "b", "c"]
    assert recorded == [[]]
    assert calls.exhausted()


def test_a_check_naming_a_real_and_an_unknown_world_is_one_request_z_dropped_b_revised(tmp_path):
    """P4: not a re-ask — `z` is dropped, `b` is revised, in ONE request to the check; a revision
    whose fact lacks `entities` is re-asked in its own call with the world rule's reason."""
    revision_bad = _revision(facts=[{"fact_id": "f1r", "statement": "s"}])
    calls = TY.ScriptedCalls(
        [_plan()], [_seat()], [_seat("story c", axis="when")],
        [_check({**CONFLICT, "label": "z"}, CONFLICT)],
        [revision_bad, _revision()],
        [_check()])
    recorded: list = []

    family, episode = _author(tmp_path, calls, checked=True, record_revisions=recorded.append)

    assert calls.request_counts() == [1, 1, 1, 1, 2, 1], "the check was re-asked about `z`"
    assert calls.reasons_sent(3) == []
    assert _told(calls, 4, "entities"), calls.reasons_sent(4)
    assert _labels(family) == ["a", "b", "c"]
    assert [f["fact_id"] for f in _world(family, "b")["facts"]] == ["f1r"]
    assert [(e["label"], e["revised"], e["dropped"]) for e in recorded[0]] == [("b", True, False)]
    assert TY.response_records(_trace(episode, "questioner:b:revise")) == 2


@pytest.mark.parametrize("bad", [{"story": "only a story"}, {**_revision(), "facts": []}],
                         ids=["facts absent", "facts empty"])
def test_a_revision_without_facts_is_re_asked_in_call_and_the_contradicted_facts_are_never_kept(tmp_path, bad):
    """P1 (review r2's `facts: []`): refused in the revision call with the reason, then fixed."""
    calls = TY.ScriptedCalls([_plan()], [_seat()], [_seat("story c", axis="when")],
                             [_check(CONFLICT)], [bad, _revision()], [_check()])

    family, _episode = _author(tmp_path, calls, checked=True)

    assert calls.request_counts() == [1, 1, 1, 1, 2, 1]
    assert _told(calls, 4, "facts"), calls.reasons_sent(4)
    assert [f["fact_id"] for f in _world(family, "b")["facts"]] == ["f1r"]


def test_an_exhausted_revision_drops_its_world_not_the_family(tmp_path):
    """P3 at a revision: retries run out after 1 + N requests; the world is dropped (#1561), the
    family stands, and nothing is re-checked."""
    bad = _revision(facts=[])
    calls = TY.ScriptedCalls([_plan()], [_seat()], [_seat("story c", axis="when")],
                             [_check(CONFLICT)], [bad, bad, bad])
    recorded: list = []

    family, _episode = _author(tmp_path, calls, checked=True, record_revisions=recorded.append)

    assert calls.request_counts() == [1, 1, 1, 1, TY.MAX_REQUESTS], "no re-check of nothing"
    assert _labels(family) == ["a", "c"]
    assert [(e["label"], e["revised"], e["dropped"]) for e in recorded[0]] == [("b", False, True)]


def test_an_exhausted_re_check_drops_the_rebuilt_world(tmp_path):
    """P3 at the re-check: a second check the call cannot get right confirms nothing, so the
    rebuilt world is dropped."""
    bad = {"conflicts": "none"}
    calls = TY.ScriptedCalls([_plan()], [_seat()], [_seat("story c", axis="when")],
                             [_check(CONFLICT)], [_revision()], [bad, bad, bad])
    recorded: list = []

    family, _episode = _author(tmp_path, calls, checked=True, record_revisions=recorded.append)

    assert calls.request_counts() == [1, 1, 1, 1, 1, TY.MAX_REQUESTS]
    assert _labels(family) == ["a", "c"]
    assert [(e["label"], e["revised"], e["dropped"]) for e in recorded[0]] == [("b", True, True)]
