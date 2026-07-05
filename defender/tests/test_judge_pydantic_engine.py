"""Hermetic tests for the in-process PydanticAI judge engine (no API key, no network).

Drives the REAL `_run_judge_pydantic` (deps build + policy-driven gate + real
read_file/bash tools + observe trace) with a `FunctionModel` injected through the
judge's `make_model` DI seam, under `override_allow_model_requests(False)` so any real
provider call raises. Plus the engine-flag routing in ClaudePrintSubagents.judge.
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
from defender.learning.pipeline.judge.run import _ToolScope  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_PY = "/venv/bin/python3"  # a full path, like sys.executable
_CLI = Path("/repo/defender/scripts/adapters/ticket_cli.py")

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


# --- the benign closed-ticket read (the judge's pinned bash_allow pattern, #338) -------

def test_ticket_pattern_shape():
    p = engine_pydantic._ticket_pattern(_PY, _CLI)
    # accepted: the pinned CLI, a ticket subcommand, and --require-closed present
    assert p.fullmatch(f"{_PY} {_CLI} get-ticket CASE-9 --require-closed --raw")
    assert p.fullmatch(f"{_PY} {_CLI} list-tickets --status closed --require-closed --label sig")
    # --require-closed REQUIRED (the security property: the open ticket stays unreachable)
    assert not p.fullmatch(f"{_PY} {_CLI} get-ticket CASE-9 --raw")
    # …and it must be a WHOLE space-delimited token, not a substring
    assert not p.fullmatch(f"{_PY} {_CLI} get-ticket --require-closed-not")
    # wrong subcommand / wrong CLI / arbitrary python — denied even WITH the flag
    assert not p.fullmatch(f"{_PY} {_CLI} delete-ticket CASE-9 --require-closed")
    assert not p.fullmatch(f"{_PY} /repo/defender/scripts/adapters/elastic_cli.py q --require-closed")
    assert not p.fullmatch(f"{_PY} -c print(1) --require-closed")


def test_judge_ticket_pipe_and_arbitrary_denied_through_gate():
    # Through decide_bash: the ticket read is a single approved shape; a pipe (its `| cat`
    # stage matches no judge pattern) and arbitrary python are denied.
    benign = engine_pydantic._judge_policy(read_roots=(), ticket_cli=(_PY, _CLI))
    assert not permission.decide_bash(
        f"{_PY} {_CLI} get-ticket CASE-9 --require-closed | cat", policy=benign).allow
    assert not permission.decide_bash(f"{_PY} -c 'print(1)'", policy=benign).allow


def test_judge_policy_ticket_read_through_the_gate(tmp_path):
    # The matcher, wired into the benign judge's AgentPolicy, is honored by decide_bash.
    benign = engine_pydantic._judge_policy(read_roots=(), ticket_cli=(_PY, _CLI))
    ok = f"{_PY} {_CLI} get-ticket CASE-9 --require-closed --raw"
    assert permission.decide_bash(ok, policy=benign).allow
    # Without --require-closed the matcher declines → generic gate denies (python not a viewer).
    assert not permission.decide_bash(f"{_PY} {_CLI} get-ticket CASE-9 --raw", policy=benign).allow
    # The adversarial judge has no matcher → even the pinned form is denied.
    adversarial = engine_pydantic._judge_policy(read_roots=(), ticket_cli=None)
    assert not permission.decide_bash(ok, policy=adversarial).allow
    # The judge (either direction) still refuses data-source adapters + arbitrary shell,
    # but MAY jq an IN-ROOTS gather_raw payload (raw_reads + the path-gated jq-only lane, #512).
    assert not permission.decide_bash("defender-elastic query x --raw", policy=benign).allow
    assert not permission.decide_bash("rm -rf /tmp/x", policy=benign).allow
    raw = tmp_path / "gather_raw" / "l-001" / "0.json"
    assert permission.decide_bash(
        f"jq '.' {raw}", policy=benign, run_dir=tmp_path, defender_dir=tmp_path
    ).allow
    # …but jq of an OUT-OF-ROOTS file is now denied (the reader surface is path-gated).
    assert not permission.decide_bash(
        "jq '.' /etc/passwd", policy=benign, run_dir=tmp_path, defender_dir=tmp_path
    ).allow


# --- ClaudePrintSubagents.judge always runs the in-process judge -----------

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
    sub = subagents.ClaudePrintSubagents()
    tail = (tmp_path, tmp_path / "story.md", tmp_path / "tel.yaml", tmp_path)

    sub.judge(ADVERSARIAL_WIRING, *tail)
    assert captured["judge_fn"] is _run_judge_pydantic

    # A claude-* judge model still runs in-process (no legacy claude -p fallback).
    sub.judge(dataclasses.replace(ADVERSARIAL_WIRING, model="claude-sonnet-4-6"), *tail)
    assert captured["judge_fn"] is _run_judge_pydantic
