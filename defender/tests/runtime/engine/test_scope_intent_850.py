"""Run-dir permission scopes agree with the lead-id alphabet the rest of the system accepts."""

from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

from defender.tests.support.shared.contracts._spec1077 import fixture_run

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender.agents import MAIN_DEF  # noqa: E402
from defender.hooks.record_lead import CLAIMED, claim_lead  # noqa: E402
from defender.learning.core import persist  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    compile_policy_for,
)
from defender.runtime.record_query import persist_payload  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106

LETTERED = "l-2b"
NUMERIC = "l-001"


@pytest.fixture
def env(tmp_path):
    """A run dir and a defender tree, both real on disk — `decide_read` resolves, so symlink and
    parent comparisons need files that exist."""
    run = tmp_path / "run"
    (run / "gather_summaries").mkdir(parents=True)
    for name in ("alert.json", "investigation.md", "report.md", "executed_queries.jsonl",
                 "source_refs.yaml"):
        (run / name).write_text("{}\n", encoding="utf-8")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "lessons" / "x.md").write_text("x\n", encoding="utf-8")
    return SimpleNamespace(run=run, dfn=dfn, tmp=tmp_path)


def _bash(env, cmd, policy):
    return permission.decide_bash(cmd, policy=policy, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, policy, *, run_dir=None):
    return permission.decide_read(
        Path(path), run_dir=run_dir if run_dir is not None else env.run,
        defender_dir=env.dfn, policy=policy,
    )


def _gather(env):
    return compile_policy_for(T1106.fixture_gather_def(), run_dir=env.run, defender_dir=env.dfn)


# F-09 — the payload shape and the lead-id validators are ONE alphabet

def test_f09_a_lettered_lead_id_survives_claim_persist_and_the_read_gate(env):
    """The end-to-end path the defect broke: a lettered id is CLAIMED, its payload is PERSISTED"""
    assert claim_lead({
        "run_dir": str(env.run), "lead_id": LETTERED,
        "goal": "who logged in", "what_to_summarize": ["actor"],
    }, run=fixture_run(env.run)) == CLAIMED, "the claim gate accepts a lettered id — that is the premise, not the defect"

    rel = persist_payload(_writer_run_1165(env.run), LETTERED, 0, '{"hits": []}')
    assert rel == f"gather_raw/{LETTERED}/0.json", (
        f"the payload the query tool tells gather to read is {rel!r}")
    payload = env.run / rel

    gather = _gather(env)
    assert _bash(env, f"cat {payload}", gather).allow, (
        "gather is denied the payload its own query tool just wrote for it (#850 F-09)")
    assert _read(env, payload, gather).allow, (
        "read_file and the cat grant share the shape OBJECT — they cannot disagree here")


def test_f09_the_widening_stays_shut(env):
    gather = _gather(env)
    for bad in (f"gather_raw/{NUMERIC}/evil.sh", "gather_raw/evil.json",
                f"gather_raw/{NUMERIC}/٣.json", "gather_raw/l-a b/0.json",
                f"gather_raw/{NUMERIC}/sub/0.json", "gather_raw/x-001/0.json"):
        target = env.run / bad
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{}\n", encoding="utf-8")
        assert not _read(env, target, gather).allow, f"{bad} is not a payload family member"
        assert not _bash(env, f"cat {target}", gather).allow, f"cat {bad} must deny too"


def test_f09_main_is_still_denied_the_payload_either_way(env):
    """The direction of the fix matters: it may not turn the fail-closed error into a fail-open
    one. MAIN never carries the raw shape, so the widened alphabet must not reach it."""
    main = compile_policy_for(MAIN_DEF, run_dir=env.run, defender_dir=env.dfn)
    rel = persist_payload(_writer_run_1165(env.run), LETTERED, 0, "{}")
    denial = _read(env, env.run / rel, main)
    assert not denial.allow
    assert "gather_raw" in denial.reason


# F-19 — a confined agent's own run dir is not a hole in its confine

def _staged(env, run_dir):
    """A learning run dir in the state the SECOND pass over a run id starts the actor in: the
    previous pass's `persist_run` already staged the case into it. Uses the real
    `_copy_shared_inputs`, so a change to what persist stages shows up here."""
    persist._copy_shared_inputs(env.run, run_dir)
    (run_dir / "source_refs.yaml").write_text("normalized_disposition: malicious\n",
                                              encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text("{}\n", encoding="utf-8")
    return run_dir


def test_f19_main_still_reads_its_own_run_artifacts(env):
    """The other control: the run's OWN agents write and re-read these files. MAIN declares no
    confine, so nothing about its access to its own investigation changed."""
    main = compile_policy_for(MAIN_DEF, run_dir=env.run, defender_dir=env.dfn)
    assert main.read_confine == ()
    for name in ("investigation.md", "report.md"):
        assert _read(env, env.run / name, main).allow
        assert _bash(env, f"cat {env.run / name}", main).allow
