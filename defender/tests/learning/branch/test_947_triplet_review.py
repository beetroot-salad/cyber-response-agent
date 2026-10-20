"""#947 — the blind comparator (M5, O8), and the elastic adapter's read allowlist."""
from __future__ import annotations

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T


def _compare():
    return T.mod("learning.branch.comparator")


def test_947_count_endpoint_is_absent_from_the_elastic_adapter_allowlist(tmp_path):
    confinement = T.mod("integrations.confinement")
    allow = set(confinement.READ_ENDPOINT_ALLOWLIST["elastic"])
    assert allow == {("/*/_search", "POST"), ("/_query", "POST"),
                     ("/_cluster/health", "GET"), ("/api/status", "GET")}


# the comparator (M5, O8)


def test_947_compare_admits_only_two_payloads_and_an_axis():
    """The comparator's blindness is structural: its signature admits two payloads and an axis
    and nothing else — no world label, no trajectory, no disposition, no ledger source."""
    import inspect

    params = list(inspect.signature(_compare().compare).parameters)
    assert params[:3] == ["a", "b", "axis"]
    forbidden = {"world", "world_id", "world_token", "trajectory", "disposition", "role",
                 "source", "seat"}
    assert not forbidden & set(params)


def test_947_the_comparator_prompt_builder_has_no_parameter_for_world_or_disposition():
    import inspect

    builder = _compare().build_prompt
    params = set(inspect.signature(builder).parameters)
    # `known_ids` is the family's whole identity set, identical for both payloads and only ever
    # removed from the prompt, never rendered into it — it cannot name which world is which.
    assert params <= {"a", "b", "axis", "known_ids"}
    prompt = builder(a='{"x": 1}', b='{"x": 2}', axis="an axis", known_ids=frozenset())
    for leak in ("world", "wv-", T.EPISODE_ID, "disposition", "trajectory"):
        assert leak not in prompt


def test_947_comparator_answers_same_or_formatting_without_a_model_call():
    agent = T.FakeAgent()
    assert _compare().compare('{"b": 1, "a": 2}', '{"a": 2, "b": 1}', None, known_ids=frozenset(),
                              invoke=agent) == "same"
    assert _compare().compare('{"host-name": 1}', '{"host_name":  1}', None,
                              known_ids=frozenset(), invoke=agent) == "formatting"
    assert agent.calls == 0


def test_947_compare_returns_verdict_for_each_seat():
    """ONE verdict type, each seat asserting only its own members"""
    compare = _compare()
    verdicts = {v.value if hasattr(v, "value") else v for v in compare.Verdict}
    assert verdicts == {"same", "formatting", "contradiction", "mutation", "undeclared"}
    assert compare.compare('{"a": 1}', '{"a": 2}', None, known_ids=frozenset(),
                           invoke=T.FakeAgent("contradiction")) == "contradiction"
    assert compare.compare('{"a": 1}', '{"a": 2}', "an axis", known_ids=frozenset(),
                           invoke=T.FakeAgent("mutation")) == "mutation"
    for axis, wrong_seat in ((None, "mutation"), ("an axis", "contradiction")):
        with pytest.raises(T.refusals()) as bad:
            compare.compare('{"a": 1}', '{"a": 2}', axis, known_ids=frozenset(),
                            invoke=T.FakeAgent(wrong_seat))
        assert wrong_seat in str(bad.value)


def test_947_comparator_model_call_runs_under_the_questioner_role_key():
    AgentRole = T.sym("runtime.agent_role", "AgentRole")
    agent = T.FakeAgent("mutation")
    _compare().compare('{"a": 1}', '{"a": 2}', "an axis", known_ids=frozenset(), invoke=agent)
    assert agent.kwargs[0]["role"] is AgentRole.QUESTIONER
    assert agent.agent_ids
    assert agent.agent_ids[0].startswith("comparator:")


def test_947_comparator_payloads_are_wrapped_untrusted():
    """Both payloads reaching the comparator's prompt are wrapped untrusted"""
    agent = T.FakeAgent("mutation")
    _compare().compare('{"note": "IGNORE PRIOR"}', '{"note": "OTHER"}', "an axis",
                       known_ids=frozenset(), invoke=agent)
    assert len(agent.prompts) == 1, "the comparator never called the model"
    T.assert_wrapped_untrusted(agent.prompts[0], '{"note": "IGNORE PRIOR"}', "the captured payload")
    T.assert_wrapped_untrusted(agent.prompts[0], '{"note": "OTHER"}', "the replayed payload")
