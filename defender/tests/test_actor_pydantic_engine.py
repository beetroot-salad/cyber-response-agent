"""Hermetic tests for the in-process PydanticAI actor engine (no API key, no network).

Drives the REAL `_run_actor_pydantic` (deps build + policy-driven gate + observe trace) with a
`FunctionModel` injected through the actor's `make_model` DI seam, under
`override_allow_model_requests(False)` so any real provider call raises. Plus the actor's
distinctive tool surface — the two pinned lessons-script matchers and the no-`read_roots`
read scope — and the ClaudePrintSubagents.actor routing.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.core import config, subagents  # noqa: E402
from defender.learning.pipeline import _pydantic_stage  # noqa: E402
from defender.learning.pipeline import actor_engine  # noqa: E402
from defender.learning.pipeline.actor_engine import ActorDeps, _ActorScope, _run_actor_pydantic  # noqa: E402
from defender.learning.pipeline.malicious_actor.run import is_skip_story  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_DEFENDER_DIR = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
# The malicious leg's read confine (both lesson corpora), as malicious_actor.run wires it.
_MALICIOUS_CONFINE = (_ACTOR_DIR, _ENV_DIR)


def _flatten(messages) -> str:
    out = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            c = getattr(part, "content", None)
            if isinstance(c, str):
                out.append(c)
    return "\n".join(out)


def _replay(turns, *, seen=None):
    """A FunctionModel fn replaying scripted turns. Each turn is
    {"calls": [(tool, args)...], "text": str}."""
    state = {"i": 0}

    def fn(messages, info):
        if seen is not None:
            seen.append(_flatten(messages))
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
    p = tmp_path / "actor.md"
    p.write_text("You are the adversarial actor. Emit a story or a SKIP line.\n")
    return p


_STORY = "0. Techniques used\n\n1. The adversary logged in with stolen creds and pivoted.\n"


# --- the engine returns the model's final text verbatim + writes its trace ---

def test_run_actor_pydantic_returns_story_and_writes_trace(tmp_path):
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": _STORY}])
    with override_allow_model_requests(False):
        out = _run_actor_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "actor_trace.jsonl", "actor",
            "write the story", lrd,
            scope=_ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE),
            make_model=_fake_model(fn),
        )
    assert out == _STORY
    assert (lrd / "actor_trace.jsonl").is_file()
    assert (lrd / "actor_trace.jsonl").read_text().strip()  # at least one request logged


def test_run_actor_pydantic_returns_skip_verbatim(tmp_path):
    # A SKIP short-circuit flows back verbatim so is_skip_story sees it (even behind a
    # GLM reasoning preamble — the hardened is_skip_story scans the first few lines).
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": "Let me consider the menu.\n\nSKIP: no covering initial-access technique"}])
    with override_allow_model_requests(False):
        out = _run_actor_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "actor_trace.jsonl", "actor",
            "write the story", lrd,
            scope=_ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE),
            make_model=_fake_model(fn),
        )
    assert out.startswith("Let me consider the menu.")
    assert is_skip_story(out)


# --- the two pinned lessons-script patterns -------------------------------------

def test_script_pattern_accepts_pinned_spellings():
    p = actor_engine._script_pattern(_ENV_RETRIEVE)
    # repo-relative (what the prompt types), absolute, and a bare `python` interpreter
    assert p.fullmatch("python3 defender/scripts/lessons/lessons_env_retrieve.py --alert-rule-ids 5712 --entities host:web")
    assert p.fullmatch(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712")
    assert p.fullmatch(f"python {_ENV_RETRIEVE} --alert-rule-ids 5712")


def test_script_pattern_rejects_wrong_shape():
    p = actor_engine._script_pattern(_ENV_RETRIEVE)
    assert not p.fullmatch(f"python3 {_ACTOR_INDEX} --techniques T1078")  # different pinned script
    assert not p.fullmatch("python3 -c print(1)")                         # arbitrary python
    assert not p.fullmatch("cat /etc/passwd")                             # non-python program


def test_actor_script_pipe_denied_through_gate():
    # a pipe re-opens no reader surface: the `| cat` stage matches no actor pattern → denied.
    pol = actor_engine._actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert not permission.decide_bash(
        f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712 | cat", policy=pol).allow


# --- the policy through the full gate -------------------------------------------

def test_actor_policy_allows_pinned_scripts_and_denies_offlist():
    pol = actor_engine._actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    # both pinned lesson scripts are allowed by the actor's matchers
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=pol).allow
    assert permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=pol).allow
    # arbitrary python, an unpinned script, a data-source adapter, and arbitrary shell are denied
    assert not permission.decide_bash("python3 -c 'print(1)'", policy=pol).allow
    assert not permission.decide_bash("python3 defender/scripts/lessons/other.py", policy=pol).allow
    assert not permission.decide_bash("defender-elastic query x --raw", policy=pol).allow
    assert not permission.decide_bash("rm -rf /tmp/x", policy=pol).allow


def test_benign_actor_policy_excludes_tradecraft_index():
    # The benign leg carries only the env-retrieve matcher; the tradecraft index stays a
    # malicious-only capability (the actor-settings.json boundary, now enforced by policy).
    benign = actor_engine._actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=benign).allow
    assert not permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=benign).allow


# --- read scope: CONFINED to the lesson corpora (#512) --------------------------

def test_actor_read_scope_is_confined_to_lessons(tmp_path):
    # #512: the actor's read_confine REPLACES the defender_dir base, so a defender_dir
    # file OUTSIDE the confine (SKILL.md, the judge rubric) is no longer readable — the
    # gray-box hole #510 opened. run_dir artifacts and in-confine lessons still are.
    pol = actor_engine._actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    assert set(pol.read_confine) == set(_MALICIOUS_CONFINE)
    assert pol.read_roots == ()          # confine replaces the corpus base; no widening
    assert pol.raw_reads is False        # gray-box: never touches gather_raw
    assert pol.adapters is False
    lrd = _lrd(tmp_path)
    # in-confine lesson: allowed
    assert permission.decide_read(
        _ACTOR_DIR / "T1078.md", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow
    # under defender_dir but OUTSIDE the confine (SKILL.md): now DENIED
    assert not permission.decide_read(
        _DEFENDER_DIR / "SKILL.md", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow
    # the actor's own run-dir artifact stays readable (run_dir remains a root)
    assert permission.decide_read(
        lrd / "actor_menu.txt", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow
    # a file outside {run_dir} ∪ confine is refused
    assert not permission.decide_read(
        tmp_path / "elsewhere.txt", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow


def test_actor_scope_requires_explicit_confine():
    # #512 fail-loud: read_confine is a required keyword-only field — building an actor scope
    # WITHOUT it is a construction-time TypeError, not a silent fall back to the full defender_dir
    # corpus (which would reopen the #510 gray-box hole). There is no unconfined actor.
    with pytest.raises(TypeError):
        _ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX))
    # …and naming the confine builds the confined scope as before.
    scope = _ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    assert scope.read_confine == _MALICIOUS_CONFINE


# --- the agent is read-only (no writers) + GLM@low effort plumbing --------------

def test_actor_agent_is_read_only_no_writers():
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-actor-tools.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            ActorDeps, Path(__file__), "any-model", "low", logger, "actor",
            make_model=_fake_model(_replay([{"text": ""}])),
        )
    finally:
        logger.close()
    # read-only: the actor reads lessons + retrieval scripts, never writes
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_build_actor_agent_applies_glm_low_effort(monkeypatch):
    # The GLM@low lever this migration ships: effort flows model → providers.build_for_effort →
    # Fireworks extra_body.reasoning_effort. build_for_effort constructs a REAL OpenAIChatModel
    # (needs a key at construction; a fake key keeps it hermetic — settings make no request).
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-actor-effort.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            ActorDeps, Path(__file__), "glm-5.2", "low", logger, "actor",
        )
    finally:
        logger.close()
    assert agent.model_settings["extra_body"]["reasoning_effort"] == "low"


# --- ClaudePrintSubagents.actor / .actor_benign run the in-process engine -------

def test_subagents_actor_runs_pydantic_engine(monkeypatch, tmp_path):
    captured = {}

    def _spy_actor(alert_path, actor_input_path, learning_run_dir, *, actor_fn=None):
        captured["actor_fn"] = actor_fn
        return _STORY

    def _spy_benign(alert_path, case_entities, alert_rule_key, learning_run_dir, *, actor_fn=None):
        captured["benign_fn"] = actor_fn
        return _STORY

    # render_actor_view_yaml / extract_case_entities read real run artifacts — stub them so the
    # routing decision is all that's exercised.
    monkeypatch.setattr(subagents.lead_repository, "render_actor_view_yaml", lambda _rd: "leads: []\n")  # lint-monkeypatch: ok — stub the actor-view projection
    monkeypatch.setattr(subagents, "extract_case_entities", lambda _p: "host:web")  # lint-monkeypatch: ok — stub the entity extraction
    monkeypatch.setattr(subagents, "invoke_actor", _spy_actor)  # lint-monkeypatch: ok — spy the actor_fn routing decision
    monkeypatch.setattr(subagents, "invoke_actor_benign", _spy_benign)  # lint-monkeypatch: ok — spy the actor_fn routing decision

    sub = subagents.ClaudePrintSubagents()
    sub.actor(tmp_path, tmp_path)
    assert captured["actor_fn"] is _run_actor_pydantic
    sub.actor_benign(tmp_path, tmp_path, "5712")
    assert captured["benign_fn"] is _run_actor_pydantic
