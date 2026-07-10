"""Hermetic tests for the in-process PydanticAI forward-check engine (no API key, no network).

The forward-check is the FOURTH consumer of the shared ``_pydantic_stage`` transport (after
judge/actor/oracle). These drive the REAL transport (``_run_verify_pydantic``: deps build +
deny-all gate + observe trace) with a ``FunctionModel`` injected through the ``make_model`` DI seam,
under ``override_allow_model_requests(False)`` so any real provider call raises — plus the
deny-all policy through the gate, the read-only agent surface + GLM effort plumbing, and the
``forward_check`` CLI orchestration (key sourcing + verdict parsing + fault mapping) that both
``forward.py`` and ``actor.py`` share.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.author.verify_forward.engine import (  # noqa: E402
    VERIFY_DEF,
    VerifierDeps,
    _run_verify_pydantic,
)
from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import RunUnprocessable  # noqa: E402
from defender.learning.pipeline import _pydantic_stage  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_DEFENDER_DIR = config.REPO_ROOT / "defender"
_VERDICT = "I reason about the counterfactual here.\n\nMore reasoning.\n\nVERDICT: GOOD"


def _replay(text: str, *, calls=()):
    """A FunctionModel fn returning one scripted turn: optional tool calls + a text part."""
    def fn(messages, info):
        parts = [ToolCallPart(tool_name=n, args=a) for n, a in calls]
        parts.append(TextPart(content=text))
        return ModelResponse(parts=parts)
    return fn


def _fake_model(fn):
    # settings=None — a FunctionModel needs no provider settings (mirrors _replay_harness).
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


def _prompt(tmp_path):
    p = tmp_path / "forward.md"
    p.write_text("Predict the disposition. End with VERDICT: GOOD or VERDICT: BAD.\n")
    return p


def _src(tmp_path):
    d = tmp_path / "runs" / "run-X"
    d.mkdir(parents=True)
    return d


# --- the transport returns the model's final text verbatim + writes its trace ----

def test_run_verify_pydantic_returns_text_verbatim_and_writes_trace(tmp_path):
    src = _src(tmp_path)
    with override_allow_model_requests(False):
        out = _run_verify_pydantic(
            _prompt(tmp_path), config.VERIFIER_MODEL, config.VERIFIER_EFFORT,
            "vf.run-X.trace.jsonl", "verify:X", "predict this case", src,
            make_model=_fake_model(_replay(_VERDICT)),
        )
    # verbatim — parsing is the caller's job (shared.parse_verdict), so the reasoning survives
    assert out == _VERDICT
    assert (src / "vf.run-X.trace.jsonl").is_file()
    assert (src / "vf.run-X.trace.jsonl").read_text().strip()  # at least one request logged


def test_run_verify_pydantic_empty_output_is_unprocessable(tmp_path):
    # A GLM reasoning model can burn its whole budget in the thinking channel and emit an EMPTY
    # final text part; an empty verdict is never valid, so run_stage quarantines the run — which
    # the CLI surfaces as a non-zero exit / batch ERROR, not a bogus GOOD/BAD.
    with override_allow_model_requests(False), pytest.raises(RunUnprocessable):
        _run_verify_pydantic(
            _prompt(tmp_path), config.VERIFIER_MODEL, config.VERIFIER_EFFORT,
            "vf.trace.jsonl", "verify:X", "predict this case", _src(tmp_path),
            make_model=_fake_model(_replay("")),
        )


# --- the deny-all policy through the full gate -----------------------------------

def test_verify_policy_denies_adapters_and_shell():
    # #551: the standalone `_VERIFY_POLICY` constant retired; `bind(VERIFY_DEF)` compiles the
    # same deny-all policy over VERIFY_DEF's empty ToolSet.
    pol = bind(VERIFY_DEF, Path("/tmp/verify-run")).policy
    assert pol.adapters is False
    assert pol.raw_reads is False
    assert pol.read_roots == ()
    # a data-source adapter, an aggregation pipe, and arbitrary shell are all denied
    assert not permission.decide_bash("defender-elastic query x --raw", policy=pol).allow
    assert not permission.decide_bash("defender-elastic query x --raw | defender-sql 'SELECT 1'", policy=pol).allow
    assert not permission.decide_bash("cat /etc/passwd", policy=pol).allow


def test_verify_deps_role_is_verifier():
    assert VerifierDeps.role is AgentRole.VERIFIER


# --- the agent is read-only (no writers) + GLM effort plumbing -------------------

def test_verify_agent_is_read_only_no_writers():
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-verify-tools.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            VerifierDeps, Path(__file__), "any-model", "medium", logger, "verify",
            make_model=_fake_model(_replay("")),
        )
    finally:
        logger.close()
    # #538: the verifier is TOOL-FREE — VERIFY_DEF registers an empty ToolSet(), so there is no
    # read_file to peek at the source run's source_refs.yaml answer key (nor any bash).
    assert list(agent._function_toolset.tools) == []


def test_build_verify_agent_applies_glm_effort(monkeypatch):
    # The GLM effort lever this migration ships (glm-5.2 @ the config default, `low`, to match the
    # defender's MAIN effort): effort flows model → providers.build_for_effort →
    # Fireworks extra_body.reasoning_effort. build_for_effort constructs a REAL OpenAIChatModel
    # (needs a key at construction; a fake key keeps it hermetic — settings make no request).
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-verify-effort.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            VerifierDeps, Path(__file__), config.VERIFIER_MODEL, config.VERIFIER_EFFORT, logger, "verify",
        )
    finally:
        logger.close()
    assert agent.model_settings["extra_body"]["reasoning_effort"] == config.VERIFIER_EFFORT


# --- forward_check: the CLI orchestration both forward.py + actor.py share -------
# forward_check owns two DI seams (`source_key` / `run_verify`) that default to the real
# collaborators, so these inject fakes rather than monkeypatching module globals.
