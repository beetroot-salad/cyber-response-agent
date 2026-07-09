"""Hermetic tests for the in-process PydanticAI oracle engine (no API key, no network).

Drives the REAL `_run_oracle_pydantic` (deps build + deny-all gate + observe trace) with a
`FunctionModel` injected through the oracle's `make_model` DI seam, under
`override_allow_model_requests(False)` so any real provider call raises. Plus the oracle's
distinctive shape — a deny-all policy (it calls no tools), the GLM `reasoning_effort="none"`
lever this port ships ("thinking=None": reasoning DISABLED, not omitted), the InProcessSubagents
routing, and the per-lead concurrent fan-out contract that the shared harness does NOT cover.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

import yaml  # noqa: E402

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.core import config, subagents  # noqa: E402
from defender.learning.pipeline import _pydantic_stage  # noqa: E402
from defender.learning.pipeline import oracle_engine  # noqa: E402
from defender.learning.pipeline.oracle import run as oracle_run  # noqa: E402
from defender.learning.pipeline.oracle_engine import OracleDeps, _run_oracle_pydantic  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_DEFENDER_DIR = config.REPO_ROOT / "defender"

# A minimal, well-formed per-lead oracle reply (one distinguishable event) — the shape
# sample.parse_lead_events consumes downstream.
_ORACLE_YAML = 'events:\n  - Computer: "FINANCE-DB"\n    EventID: 4624\n'


def _replay(turns, *, seen=None):
    """A FunctionModel fn replaying scripted turns. Each turn is
    {"calls": [(tool, args)...], "text": str}."""
    state = {"i": 0}

    def fn(messages, info):
        if seen is not None:
            seen.append(messages)
        turn = turns[min(state["i"], len(turns) - 1)]
        state["i"] += 1
        parts = [ToolCallPart(tool_name=n, args=a) for n, a in turn.get("calls", [])]
        if turn.get("text"):
            parts.append(TextPart(content=turn["text"]))
        return ModelResponse(parts=parts)

    return fn


def _fake_model(fn):
    # settings=None — a FunctionModel needs no provider settings (mirrors _replay_harness).
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


def _lrd(tmp_path):
    lrd = tmp_path / "learning_run"
    lrd.mkdir()
    return lrd


def _prompt(tmp_path):
    p = tmp_path / "oracle.md"
    p.write_text("You are a telemetry oracle for a single lead. Emit the events YAML.\n")
    return p


# --- the engine returns the model's final YAML verbatim + writes its per-lead trace ---

def test_run_oracle_pydantic_returns_yaml_and_writes_trace(tmp_path):
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": _ORACLE_YAML}])
    with override_allow_model_requests(False):
        out = _run_oracle_pydantic(
            _prompt(tmp_path), "glm-5.2", "none",
            "oracle_l-001.trace.jsonl", "oracle:l-001",
            "project this lead", lrd, make_model=_fake_model(fn),
        )
    assert out == _ORACLE_YAML
    assert (lrd / "oracle_l-001.trace.jsonl").is_file()
    assert (lrd / "oracle_l-001.trace.jsonl").read_text().strip()  # at least one request logged


# --- the deny-all policy through the full gate (the oracle runs NO tools) --------------

def test_oracle_policy_denies_everything():
    pol = oracle_engine._ORACLE_POLICY
    assert pol.adapters is False
    assert pol.adapter_sql_pipe is False
    assert pol.raw_reads is False
    assert pol.read_roots == ()
    assert pol.bash_allow == ()
    # a data-source adapter, the adapter|defender-sql pipe, arbitrary python, and arbitrary shell
    # are all denied — the oracle's whole input is inlined in the prompt, so it needs none of them.
    assert not permission.decide_bash("defender-elastic query x --raw", policy=pol).allow
    assert not permission.decide_bash(
        "defender-elastic query x --raw | defender-sql 'SELECT 1'", policy=pol
    ).allow
    assert not permission.decide_bash("python3 -c 'print(1)'", policy=pol).allow
    assert not permission.decide_bash("rm -rf /tmp/x", policy=pol).allow


# --- read scope: under defender_dir / run_dir defaults, with NO read_roots -------------

def test_oracle_reads_under_defender_dir_without_read_roots(tmp_path):
    pol = oracle_engine._ORACLE_POLICY
    assert pol.read_roots == ()
    lrd = _lrd(tmp_path)
    # a file under defender_dir is allowed purely by the defender-corpus root (no read_roots)
    allowed = permission.decide_read(
        _DEFENDER_DIR / "SKILL.md", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    )
    assert allowed.allow
    # a file outside {run_dir, defender_dir} is refused (the oracle has no extra roots)
    denied = permission.decide_read(
        tmp_path / "elsewhere.txt", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    )
    assert not denied.allow


# --- the agent is read-only (no writers) + the GLM reasoning-DISABLED lever -------------

def test_oracle_agent_is_read_only_no_writers():
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-oracle-tools.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            OracleDeps, Path(__file__), "any-model", "none", logger, "oracle",
            make_model=_fake_model(_replay([{"text": ""}])),
        )
    finally:
        logger.close()
    # #538: the oracle is TOOL-FREE — ORACLE_DEF registers an empty ToolSet(), so there is no
    # read_file to peek at answer-bearing artifacts (nor any bash); the tool list is empty.
    assert list(agent._function_toolset.tools) == []


def test_build_oracle_agent_disables_glm_reasoning(monkeypatch):
    # The "thinking=None" lever this port ships: effort "none" flows model →
    # providers.build_for_effort → Fireworks extra_body.reasoning_effort="none" (reasoning
    # DISABLED, distinct from OMITTING the knob, which leaves GLM reasoning on). build_for_effort
    # constructs a REAL OpenAIChatModel (needs a key at construction; a fake key keeps it hermetic
    # — the settings make no request).
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-oracle-effort.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            OracleDeps, Path(__file__), "glm-5.2", "none", logger, "oracle",
        )
    finally:
        logger.close()
    assert agent.model_settings["extra_body"]["reasoning_effort"] == "none"


def test_oracle_ships_glm_reasoning_disabled_by_default():
    # Guard the shipped defaults (the headline of this port). config reads these from os.environ at
    # import, so only assert when an operator override is NOT set.
    import os

    if "ORACLE_MODEL" not in os.environ:
        assert config.ORACLE_MODEL == "glm-5.2"
    if "ORACLE_EFFORT" not in os.environ:
        assert config.ORACLE_EFFORT == "none"


# --- InProcessSubagents.oracle runs the in-process engine ----------------------------

def test_subagents_oracle_runs_pydantic_engine(monkeypatch, tmp_path):
    captured = {}

    def _spy_oracle(run_dir, actor_story_path, learning_run_dir, *, oracle_fn=None):
        captured["oracle_fn"] = oracle_fn
        captured["learning_run_dir"] = learning_run_dir
        return "projections: []\n"

    monkeypatch.setattr(subagents, "invoke_oracle", _spy_oracle)  # lint-monkeypatch: ok — spy the oracle_fn routing decision

    sub = subagents.InProcessSubagents()
    out = sub.oracle(tmp_path / "run", tmp_path / "story.md", tmp_path / "lrd")
    assert out == "projections: []\n"
    assert captured["oracle_fn"] is _run_oracle_pydantic
    assert captured["learning_run_dir"] == tmp_path / "lrd"


# --- the per-lead fan-out contract (NOT covered by the shared single-call harness) ------

def test_invoke_oracle_fans_out_per_lead_in_order(monkeypatch, tmp_path):
    """invoke_oracle fans one call per lead through oracle_fn, threads the learning_run_dir, gives
    each lead a DISTINCT per-lead trace name/label (so the concurrent RequestLoggers never collide
    on one file), and reassembles projections in LEAD ORDER regardless of completion order."""
    leads = [
        SimpleNamespace(lead_id=f"l-00{i}", queries=[], what_to_summarize=[])
        for i in (1, 2, 3)
    ]
    monkeypatch.setattr(oracle_run.lead_repository, "joined", lambda _rd: leads)  # lint-monkeypatch: ok — inject fake leads so the fan-out contract runs without a real run dir

    calls = []

    def fake_oracle_fn(prompt_path, model, effort, trace_name, label, user, learning_run_dir):
        calls.append((label, trace_name, learning_run_dir))
        # Echo the lead id back as this lead's single event, so a cross-lead scramble would show.
        lead_id = label.split(":", 1)[1]
        return f'events:\n  - lead: "{lead_id}"\n'

    story = tmp_path / "story.md"
    story.write_text("the story\n")
    lrd = tmp_path / "lrd"
    lrd.mkdir()

    doc = oracle_run.invoke_oracle(tmp_path, story, lrd, oracle_fn=fake_oracle_fn)
    parsed = yaml.safe_load(doc)

    # projections reassembled in lead order, each carrying its OWN lead's echoed event
    assert [p["lead_id"] for p in parsed["projections"]] == ["l-001", "l-002", "l-003"]
    assert [p["events"][0]["lead"] for p in parsed["projections"]] == ["l-001", "l-002", "l-003"]

    # one call per lead, with distinct per-lead labels + trace names; learning_run_dir threaded in.
    # The trace name carries the story stem ("story") so the two direction legs (which share
    # learning_run_dir and the same lead set) don't collide on one file — see the next test.
    assert sorted(c[0] for c in calls) == ["oracle:l-001", "oracle:l-002", "oracle:l-003"]
    assert sorted(c[1] for c in calls) == [
        "oracle_story_l-001.trace.jsonl", "oracle_story_l-002.trace.jsonl",
        "oracle_story_l-003.trace.jsonl",
    ]
    assert all(c[2] == lrd for c in calls)


def test_invoke_oracle_trace_name_is_per_direction(monkeypatch, tmp_path):
    """The two direction legs share one learning_run_dir and the SAME lead set (both read the same
    run_dir), so a lead-only trace name would collide on one RequestLogger file (opened mode "w").
    invoke_oracle keys the trace on the per-direction story stem, so the adversarial + benign legs
    write DISJOINT trace files for the same lead_id — no cross-leg truncation/interleave."""
    leads = [SimpleNamespace(lead_id="l-001", queries=[], what_to_summarize=[])]
    monkeypatch.setattr(oracle_run.lead_repository, "joined", lambda _rd: leads)  # lint-monkeypatch: ok — inject a shared lead set so both legs project the same lead_id
    lrd = tmp_path / "lrd"
    lrd.mkdir()

    def _trace_names_for(story_name: str) -> list[str]:
        seen = []
        story = tmp_path / story_name
        story.write_text("the story\n")

        def fake_oracle_fn(prompt_path, model, effort, trace_name, label, user, learning_run_dir):
            seen.append(trace_name)
            return 'events:\n  - lead: "l-001"\n'

        oracle_run.invoke_oracle(tmp_path, story, lrd, oracle_fn=fake_oracle_fn)
        return seen

    adversarial = _trace_names_for("actor_story.md")
    benign = _trace_names_for("actor_benign_story.md")
    # same lead_id, but the per-direction stem keeps the trace files disjoint across legs
    assert adversarial == ["oracle_actor_story_l-001.trace.jsonl"]
    assert benign == ["oracle_actor_benign_story_l-001.trace.jsonl"]
    assert set(adversarial).isdisjoint(benign)
