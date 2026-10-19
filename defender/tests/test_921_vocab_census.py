"""#921 — the outcome vocabulary, the 08-16 fixture, and the corrected write census."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _vocab():
    return J.mod("_vocab")


def test_921_the_wire_log_holding_the_framed_prompt_is_not_reachable_from_a_box(tmp_path):
    pytest.importorskip("pydantic_ai")
    from defender.agents import MAIN_DEF
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=1,
        state=_state1135.env_state())
    traces = J.wire_logs(ep)
    assert traces, "the judge left no wire log at all; there is nothing to deny"

    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True, exist_ok=True)
    env = SimpleNamespace(
        run=run_dir, dfn=dfn,
        main=compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=dfn),
        gather=compile_policy_for(T1106.fixture_gather_def(), run_dir=run_dir, defender_dir=dfn))

    for which in ("main", "gather"):
        policy = getattr(env, which)
        for trace in traces:
            assert not permission.decide_read(
                Path(trace), run_dir=env.run, defender_dir=env.dfn, policy=policy).allow
            assert not permission.decide_bash(
                f"cat {trace}", policy=policy, run_dir=env.run, defender_dir=env.dfn).allow
        assert permission.decide_read(
            run_dir / "investigation.md", run_dir=env.run, defender_dir=env.dfn,
            policy=policy).allow, "the positive control failed: nothing reads at all"
