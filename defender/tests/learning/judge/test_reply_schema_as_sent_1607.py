"""#1607: the judge's verdict tool, as the production model sends it to the provider, refuses
exactly what the reply check refuses, apart from the rules a schema cannot state.

The provider decodes to the schema it is sent. The schema used to describe each finding as a bare
`{"type": "object"}`, which the OpenAI-compatible mapping closes to "no keys", so the model's
world finding arrived as `{}` on every ask and no finding could be filed. Any other place the
two disagree costs a re-ask (the check refuses what the schema let through) or makes a reply
impossible to send (the schema refuses what the check takes).

The corpus is hand-written replies and mechanical mutations of them, never derived from the
reply's own description."""
from __future__ import annotations

import copy
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")
jsonschema = pytest.importorskip("jsonschema")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models import ModelRequestParameters  # noqa: E402
from pydantic_ai.models.function import AgentInfo, FunctionModel  # noqa: E402

from defender.learning._pydantic_stage import TypedOutput, _Typed  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402
from defender.learning.judge._errors import JudgeRefused  # noqa: E402
from defender.providers import build_for_effort  # noqa: E402

MODELS = ("kimi-k3", "glm-5.3", "deepseek-v4.1-flash")
REACHED = ["cmdb", "change-mgmt"]

_WORLD_FINDING = {
    "bucket": "unreachable", "systems": ["cmdb"], "claim": "f2 was never built",
    "root_cause": "no forged row serves the cmdb record", "anchor": "family.yaml#worlds/x",
    "topic": "unbuilt fact", "evidence": ["oracle/w/forged.jsonl"]}
_TABLES = {"noise_floor_note": "none", "correlations": [{"run": "x"}],
           "scope_checks": [{"fact": "f2"}], "derivations": [{"step": 1}]}
_WORLD = {
    **_TABLES, "bucket": "lead-quality", "systems": ["cmdb"],
    "investigator_findings": [{
        "bucket": "lead-quality", "claim": "asked the wrong window", "root_cause": "window",
        "anchor": "worlds/w/closing", "topic": "window",
        "contrast_evidence": ["worlds/w/closing", "worlds/r/closing"],
        "on_verdict_path": True}],
    "world_findings": [_WORLD_FINDING],
    "gaps": [{"what": "cmdb refused", "how": "verb not granted",
              "evidence": ["served/w.jsonl#3"], "kept_facts_from_investigator": False}],
}
_FAMILY = {**_TABLES, "world_findings": [_WORLD_FINDING]}

#: The rules a schema cannot state (the system-name shape and repeats are not sent as schema
#: keywords the provider is known to take; whether a `lead-set` world's systems were reached
#: is per-world data). A mutant breaking one may pass the schema and be refused by the check —
#: never the other way round.
CHECK_ONLY = frozenset({"system name", "repeated system", "empty finding systems",
                        "lead-set unreached"})

_WRONG = {str: 7, list: "x", bool: "yes", dict: ["x"]}
_LOOKALIKES = ("Lead-Set", "lead_set", "unreachable ")


def _mutants(doc: Any, path: tuple = ()) -> list[tuple[str, tuple, Any]]:
    """(rule, path, mutated reply) for every mechanical fault at every level of `doc`."""
    out: list[tuple[str, tuple, Any]] = []
    if isinstance(doc, dict):
        out.append(("extra key", path, {**doc, "side_note": "x"}))
        for key, value in doc.items():
            out.append(("missing key", (*path, key), {k: v for k, v in doc.items() if k != key}))
            out.append(("wrong type", (*path, key), {**doc, key: _WRONG[type(value)]}))
            if key == "bucket":
                out += [("lookalike", (*path, key), {**doc, key: w}) for w in _LOOKALIKES]
            for rule, sub_path, sub in _mutants(value, (*path, key)):
                out.append((rule, sub_path, {**doc, key: sub}))
    elif isinstance(doc, list) and doc and isinstance(doc[0], dict) and path[-1] in (
            run_mod.INVESTIGATOR_FINDINGS, run_mod.WORLD_FINDINGS, run_mod.GAPS):
        out.append(("empty finding", path, [{}]))
        out += [(rule, sub_path, [sub]) for rule, sub_path, sub in _mutants(doc[0], (*path, 0))]
    return out


def _named(base: dict[str, Any], scope: str) -> list[tuple[str, Any]]:
    """The faults named by rule rather than generated."""
    def at_finding(**change):
        doc = copy.deepcopy(base)
        doc[run_mod.WORLD_FINDINGS][0].update(change)
        return doc
    named = [("system name", at_finding(systems=["IDP"])),
             ("repeated system", at_finding(systems=["cmdb", "cmdb"])),
             ("empty finding systems", at_finding(systems=[]))]
    if scope == "world":
        named += [("system name", {**base, "systems": ["IDP"]}),
                  ("repeated system", {**base, "systems": ["cmdb", "cmdb"]}),
                  ("lead-set unreached", {**base, "bucket": "lead-set", "systems": ["okta"]})]
        for word in sorted(run_mod.DISCIPLINE_BUCKETS):
            named.append(("discipline", {**base, "bucket": word}))
            doc = copy.deepcopy(base)
            doc[run_mod.INVESTIGATOR_FINDINGS][0]["bucket"] = word
            named.append(("discipline", doc))
    return named


class _Requests:
    n_unanswered = 0


class _Captured(Exception):
    pass


def _sent_schema(model_name: str, scope: str, shown: bool | None) -> dict[str, Any]:
    """The verdict tool's parameters as the production model sends them to the provider."""
    spec = TypedOutput(name="verdict", description="d",
                       schema=run_mod.reply_schema(scope, shown_its_facts=shown),
                       retries=0, check=lambda _reply: None)
    seen: dict = {}

    def capture(_messages, info: AgentInfo):
        seen["tools"] = info.output_tools
        raise _Captured

    agent = Agent(FunctionModel(capture), output_type=_Typed(spec, _Requests()).output_type())
    with pytest.raises(_Captured):
        agent.run_sync("judge")
    built = build_for_effort(model_name, "medium")
    params = built.model.customize_request_parameters(
        ModelRequestParameters(output_tools=seen["tools"]))
    sent = built.model._map_tool_definition(params.output_tools[0], built.settings or {})
    assert "strict" not in sent["function"] or not sent["function"]["strict"], sent
    return sent["function"]["parameters"]


def _check_takes(reply: Any, scope: str, shown: bool | None) -> bool:
    try:
        run_mod.validate_reply(reply, scope=scope, reachable_systems=REACHED,
                               shown_its_facts=shown)
    except JudgeRefused:
        return False
    return True


@pytest.mark.parametrize(("scope", "shown"), [("world", True), ("world", False),
                                              ("world", None), ("family", None)])
@pytest.mark.parametrize("model_name", MODELS)
def test_the_verdict_schema_as_sent_refuses_what_the_check_refuses(
        model_name, scope, shown, monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    base = _WORLD if scope == "world" else _FAMILY
    schema = _sent_schema(model_name, scope, shown)
    validator = jsonschema.Draft202012Validator(schema)
    assert _check_takes(base, scope, shown), "the hand-written reply is one the host accepts"
    corpus = [("base", (), base), *_mutants(base),
              *[(rule, (), doc) for rule, doc in _named(base, scope)]]
    disagree = []
    for rule, path, reply in corpus:
        check, sent = _check_takes(reply, scope, shown), validator.is_valid(reply)
        if check == sent or (not check and sent and rule in CHECK_ONLY):
            continue
        disagree.append(f"{rule} at {list(path)}: check {'takes' if check else 'refuses'}, "
                        f"schema {'takes' if sent else 'refuses'}")
    assert not disagree, f"{model_name}/{scope}/shown={shown}:\n" + "\n".join(disagree)
