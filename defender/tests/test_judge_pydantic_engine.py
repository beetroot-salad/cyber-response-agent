"""Hermetic tests for the in-process PydanticAI judge engine (no API key, no network).

Drives the REAL `_run_judge_pydantic` (deps build + policy-driven gate + real
read_file/bash tools + observe trace) with a `FunctionModel` injected through the
judge's `make_model` DI seam, under `override_allow_model_requests(False)` so any real
provider call raises. Plus the engine-flag routing in InProcessSubagents.judge.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.core import subagents  # noqa: E402
from defender.learning.core.directions import ADVERSARIAL_WIRING  # noqa: E402
from defender.learning.pipeline.judge import engine_pydantic  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import _run_judge_pydantic  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF  # noqa: E402
from defender.learning.pipeline.judge.run import _ToolScope  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import RunScope, compile_policy_for  # noqa: E402
from defender.runtime.permission.command_shape import SQL_SHIM  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_PY = "/venv/bin/python3"  # a full path, like sys.executable
_CLI = Path("/repo/defender/scripts/adapters/ticket_adapter.py")


def _judge_policy(tmp_path, *, read_roots=()):
    """The judge's compiled policy through the REAL seam.

    #575 deleted the module-private `_judge_policy(read_roots=…)` constructor: a definition now
    hangs its OWN grant builder (`_judge_bash_shapes`) on its OWN def, and the per-invocation
    inputs (the comparison roots) ride a `RunScope` that `compile_policy_for` folds into
    `ResolvedRoots`. So the policy is built the way production builds it — through the one compile
    seam — instead of through a private back door that could drift from it. `run_dir`/
    `defender_dir` matter now (the `cat` grant's scope anchors on the RESOLVED roots), so every
    caller threads a real tmp tree. #672: the benign closed-ticket read is a typed tool, not a
    bash grant, so both legs compile the identical bash lane (cat + defender-sql)."""
    return compile_policy_for(
        JUDGE_DEF, run_dir=tmp_path,
        scope=RunScope(add_dirs=tuple(read_roots)),
        defender_dir=tmp_path,
    )

_YAML = "outcome: skip-passthrough\ndefender_findings: []\n"


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
    {"calls": [(tool, args)...], "text": str}. Captures the messages it last saw into
    `seen` so a test can assert what a tool returned."""
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
    p = tmp_path / "judge.md"
    p.write_text("You are the judge. Emit one YAML document.\n")
    return p


def test_run_judge_pydantic_returns_yaml_and_writes_trace(tmp_path):
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": _YAML}])
    with override_allow_model_requests(False):
        out = _run_judge_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "judge_trace.jsonl", "judge",
            "score this", lrd, scope=_ToolScope(add_dir=[]), make_model=_fake_model(fn),
        )
    assert out == _YAML
    # The observability trace lands at learning_run_dir/{trace_name} (per-direction, so
    # concurrent legs don't collide) — the eval's cost/latency source.
    assert (lrd / "judge_trace.jsonl").is_file()
    assert (lrd / "judge_trace.jsonl").read_text().strip()  # at least one request logged


def test_run_judge_pydantic_reads_gather_raw_through_read_roots(tmp_path):
    # End-to-end proof that read_roots widening actually works: the judge reads a
    # gather_raw file that lives OUTSIDE {run_dir(=lrd), defender_dir} — under the
    # investigation run dir, not the learning run dir — so the read is allowed ONLY
    # because gather_raw is a declared policy.read_root (and raw_reads=True lets it past
    # the gather_raw clamp). A file under lrd would be allowed by the run_dir root
    # regardless of read_roots, proving nothing; this one is refused if read_roots is
    # dropped, so it genuinely exercises the widening.
    lrd = _lrd(tmp_path)
    gather_raw = tmp_path / "run" / "gather_raw"
    (gather_raw / "l-001").mkdir(parents=True)
    raw_file = gather_raw / "l-001" / "0.json"
    raw_file.write_text('{"GATHER_RAW_SENTINEL_XYZ": "projection vs actual"}\n')

    seen: list[str] = []
    fn = _replay(
        [{"calls": [("read_file", {"path": str(raw_file)})]}, {"text": _YAML}],
        seen=seen,
    )
    with override_allow_model_requests(False):
        out = _run_judge_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "judge_trace.jsonl", "judge",
            "score this", lrd,
            scope=_ToolScope(add_dir=[gather_raw]),
            make_model=_fake_model(fn),
        )
    assert out == _YAML
    # The file content came back to the model → the read was ALLOWED via read_roots.
    assert any("GATHER_RAW_SENTINEL_XYZ" in s for s in seen)


# --- #492: the preamble trim RELOCATED off the engine boundary ---------------------
# The old test_extract_yaml_doc_* unit tests moved to tests/test_judge_yaml_preamble.py
# (they now target the shared validate.strip_yaml_preamble primitive). What remains here
# is the engine-side half of the contract: the engine no longer trims, and a preamble'd
# verdict still survives once the shared downstream normalizer runs.

def test_extract_yaml_doc_symbol_removed():
    """#492 (E4): the engine-boundary trim is DELETED — `_extract_yaml_doc` and
    `_YAML_DOC_START` no longer exist on the engine module. Preamble handling is now owned
    by the shared validate.strip_yaml_preamble, for both engines at once."""
    assert getattr(engine_pydantic, "_extract_yaml_doc", None) is None
    assert getattr(engine_pydantic, "_YAML_DOC_START", None) is None


def test_run_judge_pydantic_returns_raw_preamble_untrimmed(tmp_path):
    """#492 (E4): after the fix `_run_judge_pydantic` returns the model's RAW final text
    with the prose preamble INTACT — no engine-level trim. The relocation is observable in
    the return value (it still carries the leading prose)."""
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": "Here is my analysis.\n\noutcome: refuted\ndefender_findings: []\n"}])
    with override_allow_model_requests(False):
        out = _run_judge_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "judge_benign_trace.jsonl",
            "judge-benign", "score this", lrd, scope=_ToolScope(add_dir=[]),
            make_model=_fake_model(fn),
        )
    assert out.startswith("Here is my analysis.")


def test_pydantic_engine_preamble_survives_end_to_end_via_shared_path(tmp_path):
    """#492 (E4 regression proof): a preamble'd verdict flows from `_run_judge_pydantic`
    (raw, untrimmed) through `parse_judge_verdict` and STILL yields outcome=='refuted' with
    parsed_ok — the shared normalizer picks up exactly what the engine stopped trimming,
    with no loss of behavior. (Was test_run_judge_pydantic_trims_model_preamble_end_to_end;
    the ENGINE no longer trims, so the name loses 'trims'.)"""
    lrd = _lrd(tmp_path)
    from defender.evals.judge_equivalence import parse_judge_verdict
    fn = _replay([{"text": "Here is my analysis.\nThe story is refuted.\n\n"
                           "outcome: refuted\ndefender_findings: []\n"}])
    with override_allow_model_requests(False):
        out = _run_judge_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "judge_benign_trace.jsonl",
            "judge-benign", "score this", lrd, scope=_ToolScope(add_dir=[]),
            make_model=_fake_model(fn),
        )
    v = parse_judge_verdict(out, case_id="c", direction="benign")
    assert v.parsed_ok
    assert v.outcome == "refuted"


def test_build_judge_agent_applies_effort_via_provider(monkeypatch):
    # Effort flows model → providers.build_for_effort → Anthropic anthropic_effort (the
    # claude -p --effort equivalence lever). build_for_effort constructs a REAL
    # AnthropicModel, which needs a key at construction time (see test_glm_fireworks's
    # build_model tests); a fake key keeps this hermetic — settings_for_effort (the
    # assertion target) makes no network request.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    import defender.runtime.observe as observe
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-judge-effort.jsonl"))
    try:
        agent = engine_pydantic.build_judge_agent(
            _prompt_path := Path(__file__),  # any readable file for instructions
            "claude-sonnet-4-6", "low", logger, "judge",
        )
    finally:
        logger.close()
    assert agent.model_settings["anthropic_effort"] == "low"


# --- the benign closed-ticket read moved off bash into a typed tool (#672) -------------
# The old `_ticket_grant` pattern-shape / --require-closed-spoof / grant-honored tests are
# RETIRED: the pinned `python3 <adapter> … --require-closed` bash grant no longer exists (its
# closed-only property now lives in the typed tool, closed-only by construction). What survives
# here is the judge's bash lane itself — cat + defender-sql — and that no ticket shape reaches
# the store through it on either leg. The tool's own contract is pinned in
# tests/test_closed_ticket_tool_672.py.

def test_judge_no_ticket_shape_on_bash_lane_either_leg(tmp_path):
    """#672: the judge grants exactly cat + defender-sql on BOTH legs, and the old adapter-shaped
    ticket command DENIES — the store is unreachable through the judge's bash lane."""
    benign = _judge_policy(tmp_path)

    def gate(cmd):
        return permission.decide_bash(
            cmd, policy=benign, run_dir=tmp_path, defender_dir=tmp_path).allow

    assert {g.program for g in benign.bash_allow} == {"cat", SQL_SHIM}
    assert not gate(f"{_PY} {_CLI} get-ticket CASE-9 --require-closed")
    assert not gate(f"{_PY} {_CLI} list-tickets --status closed --require-closed --label sig")
    assert not hasattr(engine_pydantic, "_ticket_grant"), "the deleted bash ticket grant survives"


def test_judge_pipe_and_arbitrary_denied_through_gate(tmp_path):
    """Through decide_bash: arbitrary python is denied, and no pipe composition widens the
    judge's READ SET beyond its roots. `| cat` / `| defender-sql` stages are in the lane; a pipe
    stage that OPENS a new file (`cat /etc/passwd`, caught by the SCOPE check on the resolved
    operand) or leaves the lane (`head`) stays denied.

    #575: the operand gate is no longer a judge-only special case (`AgentPolicy.operand_gated` is
    deleted). Every agent's `cat` grant carries a scope over the RESOLVED path, and the judge's
    scope names its roots — which is how it reaches a `gather_raw` under the INVESTIGATION run dir
    while its own run_dir is the LEARNING one."""
    benign = _judge_policy(tmp_path, read_roots=(tmp_path / "gather_raw",))
    raw = tmp_path / "gather_raw" / "l-001" / "0.json"

    def gate(cmd):
        return permission.decide_bash(cmd, policy=benign, run_dir=tmp_path, defender_dir=tmp_path).allow

    # inert composition over data the judge may already read
    assert gate(f"cat {raw} | cat")
    assert gate(f"cat {raw} | defender-sql 'SELECT 1'")
    # ...but a pipe stage may not OPEN a new file, nor leave the lane
    assert not gate(f"cat {raw} | cat /etc/passwd")   # the scope check bites inside the pipe
    assert not gate(f"cat {raw} | head")              # `head` matches no judge grant
    assert not gate(f"{_PY} -c 'print(1)'")


def test_judge_policy_reads_gather_raw_through_the_gate(tmp_path):
    """The judge's `cat | defender-sql` aggregation lane reaches an IN-SCOPE gather_raw payload
    while a cat of an out-of-scope file is refused, on BOTH legs (the bash lane is direction-
    independent now — #672 moved the one benign-only grant off bash).

    #575: `raw_reads` / `operand_gated` are gone as declared BITS. "The judge may read gather_raw"
    is now simply "the gather_raw path resolves inside the `cat` grant's scope" — positive
    enumeration, so there is no clamp that could disagree with the grant that admits it."""
    raw = tmp_path / "gather_raw" / "l-001" / "0.json"
    benign = _judge_policy(tmp_path, read_roots=(tmp_path / "gather_raw",))

    def gate(cmd, policy=None):
        return permission.decide_bash(
            cmd, policy=policy if policy is not None else benign,
            run_dir=tmp_path, defender_dir=tmp_path,
        ).allow

    # The judge (either direction) refuses data-source adapters + arbitrary shell, but MAY
    # aggregate an IN-SCOPE gather_raw payload through the `cat | defender-sql` lane.
    assert not gate("defender-elastic query x")
    assert not gate("rm -rf /tmp/x")
    assert gate(f"cat {raw} | defender-sql 'SELECT count(*) FROM data'")
    # …but a cat of an OUT-OF-SCOPE file is denied (the reader surface is path-gated).
    assert not gate("cat /etc/passwd | defender-sql 'SELECT 1'")
    # …and jq is gone from the judge's lane entirely.
    assert not gate(f"jq '.' {raw}")
    assert not gate(f"cat {raw} | jq '.'")   # not even as a stdin stage — jq is not granted here
    # The adversarial leg compiles the identical lane (no ticket grant to differ on).
    adversarial = _judge_policy(tmp_path, read_roots=(tmp_path / "gather_raw",))
    assert {g.program for g in adversarial.bash_allow} == {"cat", SQL_SHIM}


def test_judge_read_roots_reach_a_gather_raw_outside_the_run_dir(tmp_path):
    """The judge's distinctive containment problem, pinned on the bash lane (its read-tool twin is
    ::test_run_judge_pydantic_reads_gather_raw_through_read_roots).

    The judge's `gather_raw` lives under the INVESTIGATION run dir — a tree its OWN (learning)
    run_dir never contains — so it arrives only via `RunScope.add_dirs` → `read_roots`. The old
    textual anchors could not express that (they knew only the agent's own run dir), which is why
    the judge needed a bespoke resolve()-time operand gate (`operand_gated`, now deleted). One scope
    over the RESOLVED path expresses both roots, so the special case is gone — but the CAPABILITY
    must survive, and a scope built without the extra root would silently starve the judge of its
    evidence. Guarded negative: drop the root and the same cat DENIES."""
    investigation = tmp_path / "investigation-run"
    raw = investigation / "gather_raw" / "l-001" / "0.json"
    raw.parent.mkdir(parents=True)
    raw.write_text("{}\n")
    learning = tmp_path / "learning-run"
    learning.mkdir()

    def gate(policy):
        return permission.decide_bash(
            f"cat {raw} | defender-sql 'SELECT 1'", policy=policy,
            run_dir=learning, defender_dir=tmp_path / "defender",
        ).allow

    with_root = compile_policy_for(
        JUDGE_DEF, run_dir=learning,
        scope=RunScope(add_dirs=(investigation / "gather_raw",)),
        defender_dir=tmp_path / "defender",
    )
    without_root = compile_policy_for(
        JUDGE_DEF, run_dir=learning, defender_dir=tmp_path / "defender",
    )
    assert gate(with_root)
    assert not gate(without_root)   # the widening is what makes the read possible


# --- InProcessSubagents.judge always runs the in-process judge -----------

_SENTINEL = object()


def test_subagents_judge_runs_pydantic_engine(monkeypatch, tmp_path):
    # The judge is pydantic-only: .judge dispatches invoke_judge with
    # judge_fn=_run_judge_pydantic, whatever the wiring's model provider.
    captured = {}

    def _spy(wiring, run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
             *, judge_fn=_SENTINEL):
        captured["judge_fn"] = judge_fn
        return _YAML

    monkeypatch.setattr(subagents, "invoke_judge", _spy)  # lint-monkeypatch: ok — spy the judge_fn routing decision
    sub = subagents.InProcessSubagents()
    tail = (tmp_path, tmp_path / "story.md", tmp_path / "tel.yaml", tmp_path)

    sub.judge(ADVERSARIAL_WIRING, *tail)
    assert captured["judge_fn"] is _run_judge_pydantic

    # A claude-* judge model still runs in-process (no legacy claude -p fallback).
    sub.judge(dataclasses.replace(ADVERSARIAL_WIRING, model="claude-sonnet-4-6"), *tail)
    assert captured["judge_fn"] is _run_judge_pydantic
