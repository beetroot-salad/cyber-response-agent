"""#1607: the judge's verdict tool, mapped the way the production model sends it to the provider,
accepts a reply carrying a full finding in every filed list.

The schema used to describe each finding as a bare `{"type": "object"}`, which the
OpenAI-compatible mapping closes to "no keys". The provider decodes to that schema, so the
model's world finding arrived as `{}` on every ask (refused: `bucket=None`) and no investigator
finding, world finding or gap could ever be filed."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")
jsonschema = pytest.importorskip("jsonschema")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models import ModelRequestParameters  # noqa: E402
from pydantic_ai.models.function import AgentInfo, FunctionModel  # noqa: E402

from defender.learning._pydantic_stage import TypedOutput, _Typed  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402
from defender.providers import build_for_effort  # noqa: E402

_WORLD_FINDING = {
    "bucket": "unreachable", "systems": ["cmdb"], "claim": "f2 was never built",
    "root_cause": "no forged row serves the cmdb record", "anchor": "family.yaml#worlds/x",
    "topic": "unbuilt fact", "evidence": ["oracle/w/forged.jsonl"]}
_TABLES = {"noise_floor_note": "none", "correlations": [{"run": "x"}],
           "scope_checks": [{"fact": "f2"}], "derivations": [{"step": 1}]}

#: What a model must be able to send, per scope: every filed list carrying a full entry.
REPLIES = {
    "world": {
        **_TABLES, "bucket": "lead-quality", "systems": ["cmdb"],
        "investigator_findings": [{
            "bucket": "lead-quality", "claim": "asked the wrong window", "root_cause": "window",
            "anchor": "worlds/w/closing", "topic": "window",
            "contrast_evidence": ["worlds/w/closing", "worlds/r/closing"],
            "on_verdict_path": True}],
        "world_findings": [_WORLD_FINDING],
        "gaps": [{"what": "cmdb refused", "how": "verb not granted",
                  "evidence": ["served/w.jsonl#3"], "kept_facts_from_investigator": False}],
    },
    "family": {**_TABLES, "world_findings": [_WORLD_FINDING]},
}


class _Requests:
    n_unanswered = 0


def _output_tools(scope: str) -> list:
    """The output tool definitions the production typed runner offers for the judge's verdict."""
    spec = TypedOutput(name="verdict", description="d", schema=run_mod.reply_schema(scope),
                       retries=0, check=lambda _reply: None)
    seen: dict = {}

    def capture(_messages, info: AgentInfo):
        seen["tools"] = info.output_tools
        raise _Captured

    agent = Agent(FunctionModel(capture), output_type=_Typed(spec, _Requests()).output_type())
    with pytest.raises(_Captured):
        agent.run_sync("judge")
    return seen["tools"]


class _Captured(Exception):
    pass


@pytest.mark.parametrize("scope", ["world", "family"])
@pytest.mark.parametrize("model_name", ["kimi-k3", "glm-5.3", "deepseek-v4.1-flash"])
def test_verdict_tool_schema_as_sent_accepts_a_full_finding_in_every_list(
        model_name, scope, monkeypatch):
    reply = REPLIES[scope]
    run_mod.validate_reply(reply, scope=scope)  # the fixture is a reply the host accepts
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    built = build_for_effort(model_name, "medium")
    params = built.model.customize_request_parameters(
        ModelRequestParameters(output_tools=_output_tools(scope)))
    sent = built.model._map_tool_definition(params.output_tools[0], built.settings or {})
    try:
        jsonschema.validate(reply, sent["function"]["parameters"])
    except jsonschema.ValidationError as refused:
        pytest.fail(f"{model_name}/{scope}: the verdict schema the provider receives refuses "
                    f"a full reply: {refused.message} at {list(refused.absolute_path)}")


@pytest.mark.parametrize("scope", ["world", "family"])
def test_verdict_tool_schema_names_every_finding_key_the_validator_takes(scope):
    """The item schemas are built from the validator's own key lists and bucket sets, so the
    model is shown each finding's fields and the allowed buckets."""
    properties = run_mod.reply_schema(scope)["properties"]
    lists = {run_mod.WORLD_FINDINGS: (run_mod._WORLD_FINDING_KEYS, run_mod.WORLD_FINDING_BUCKETS)}
    if scope == "world":
        lists[run_mod.INVESTIGATOR_FINDINGS] = (run_mod._INVESTIGATOR_KEYS,
                                                run_mod.INVESTIGATOR_BUCKETS)
        lists[run_mod.GAPS] = (run_mod._GAP_KEYS, None)
    for key, (keys, buckets) in lists.items():
        item = properties[key]["items"]
        assert set(item["properties"]) == set(keys), key
        assert set(item["required"]) == set(keys), key
        if buckets is not None:
            assert set(item["properties"]["bucket"]["enum"]) == set(buckets), key
