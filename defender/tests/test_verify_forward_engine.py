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

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402

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
from defender.tests._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests._engine_helpers import replay_once as _replay  # noqa: E402

_DEFENDER_DIR = config.REPO_ROOT / "defender"
_VERDICT = "I reason about the counterfactual here.\n\nMore reasoning.\n\nVERDICT: GOOD"




def _prompt(tmp_path):
    p = tmp_path / "forward.md"
    p.write_text("Predict the disposition. End with VERDICT: GOOD or VERDICT: BAD.\n")
    return p


def _src(tmp_path):
    d = tmp_path / "runs" / "run-X"
    d.mkdir(parents=True)
    return d



def test_run_verify_pydantic_returns_text_verbatim_and_writes_trace(tmp_path):
    src = _src(tmp_path)
    with override_allow_model_requests(False):
        out = _run_verify_pydantic(
            _prompt(tmp_path), config.VERIFIER_MODEL, config.VERIFIER_EFFORT,
            "vf.run-X.trace.jsonl", "verify:X", "predict this case", src,
            defender_dir=tmp_path / "wt" / "defender",
            make_model=_fake_model(_replay(_VERDICT)),
        )
    assert out == _VERDICT
    assert (src / "vf.run-X.trace.jsonl").is_file()
    assert (src / "vf.run-X.trace.jsonl").read_text().strip()


def test_run_verify_pydantic_empty_output_is_unprocessable(tmp_path):
    with override_allow_model_requests(False), pytest.raises(RunUnprocessable):
        _run_verify_pydantic(
            _prompt(tmp_path), config.VERIFIER_MODEL, config.VERIFIER_EFFORT,
            "vf.trace.jsonl", "verify:X", "predict this case", _src(tmp_path),
            defender_dir=tmp_path / "wt" / "defender",
            make_model=_fake_model(_replay("")),
        )



def test_verify_policy_denies_adapters_and_shell(tmp_path):
    pol = bind(VERIFY_DEF, Path("/tmp/verify-run"), defender_dir=tmp_path / "wt" / "defender").policy
    assert pol.bash_allow == ()
    assert pol.read_allow == ()
    assert pol.read_roots == ()
    assert not permission.decide_bash("defender-elastic query x", policy=pol).allow
    assert not permission.decide_bash("defender-elastic query x | defender-sql 'SELECT 1'", policy=pol).allow
    assert not permission.decide_bash("cat /etc/passwd", policy=pol).allow


def test_verify_deps_role_is_verifier():
    assert VerifierDeps.role is AgentRole.VERIFIER



def test_verify_agent_is_read_only_no_writers():
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-verify-tools.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            VerifierDeps, Path(__file__), "any-model", "medium", logger, "verify",
            make_model=_fake_model(_replay("")),
        )
    finally:
        logger.close()
    assert list(agent._function_toolset.tools) == []


def test_build_verify_agent_applies_glm_effort(monkeypatch):
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


