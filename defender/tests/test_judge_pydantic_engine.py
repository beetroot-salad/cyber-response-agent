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

from defender.hooks._cmd_segments import unwrap  # noqa: E402
from defender.learning.core import subagents  # noqa: E402
from defender.learning.core.config import FatalConfigError  # noqa: E402
from defender.learning.core.directions import ADVERSARIAL_WIRING  # noqa: E402
from defender.learning.pipeline.judge import engine_pydantic  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import _run_judge_pydantic  # noqa: E402
from defender.learning.pipeline.judge.run import _ToolScope  # noqa: E402
from defender.runtime import bash_exec, permission  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_PY = "/venv/bin/python3"  # a full path, like sys.executable
_CLI = Path("/repo/defender/scripts/adapters/ticket_cli.py")


def _pipes(cmd):
    return bash_exec.parse(unwrap(cmd))

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


def test_extract_yaml_doc_trims_prose_preamble():
    # Reproduces the live-smoke failure: a reasoning model prepended analysis prose above
    # the YAML. The trim anchors on the top-level `outcome:` (col 0), NOT an indented
    # citation `outcome:`, so the whole doc parses.
    raw = (
        "The payload shows leg-2 is db-1, refuting the story.\n"
        "This is a clear refutation on the core claim.\n\n"
        "outcome: refuted\n"
        "defender_findings:\n"
        "  - type: disposition-confirmed\n"
        "    subject_anchor: l-001\n"
        "    citations:\n"
        "      - source: comparison\n"
        "        quote: |\n"
        "          outcome: success\n"
    )
    doc = engine_pydantic._extract_yaml_doc(raw)
    assert doc.startswith("outcome: refuted")
    import yaml
    assert yaml.safe_load(doc)["outcome"] == "refuted"


def test_extract_yaml_doc_passthrough_and_fallback():
    clean = "outcome: caught\ndefender_findings: []\n"
    assert engine_pydantic._extract_yaml_doc(clean) == clean
    assert engine_pydantic._extract_yaml_doc("just prose, no verdict") == "just prose, no verdict"


def test_run_judge_pydantic_trims_model_preamble_end_to_end(tmp_path):
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


# --- the benign closed-ticket matcher (the judge's custom logic, #338) -------

def test_ticket_matcher_allows_pinned_require_closed():
    m = engine_pydantic._make_ticket_matcher(_PY, _CLI)
    for cmd in (
        f"{_PY} {_CLI} get-ticket CASE-9 --require-closed --raw",
        f"{_PY} {_CLI} list-tickets --status closed --require-closed --label sig --raw",
    ):
        d = m(_pipes(cmd))
        assert d is not None, cmd
        assert d.allow, cmd


def test_ticket_matcher_declines_unsafe_or_wrong_shape():
    m = engine_pydantic._make_ticket_matcher(_PY, _CLI)
    # --require-closed REQUIRED (the security property: the open ticket stays unreachable)
    assert m(_pipes(f"{_PY} {_CLI} get-ticket CASE-9 --raw")) is None
    # a different CLI / arbitrary python / not the ticket subcommands
    assert m(_pipes(f"{_PY} /repo/defender/scripts/adapters/elastic_cli.py query x")) is None
    assert m(_pipes(f"{_PY} -c 'print(1)'")) is None
    assert m(_pipes(f"{_PY} {_CLI} delete-ticket CASE-9 --require-closed")) is None
    # a pipe/compound is never the single-stage ticket read
    assert m(_pipes(f"{_PY} {_CLI} get-ticket CASE-9 --require-closed | cat")) is None


def test_judge_policy_ticket_read_through_the_gate():
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
    # but MAY jq gather_raw (raw_reads).
    assert not permission.decide_bash("defender-elastic query x --raw", policy=benign).allow
    assert not permission.decide_bash("rm -rf /tmp/x", policy=benign).allow
    assert permission.decide_bash("jq '.' gather_raw/l-001/0.json", policy=benign).allow


# --- engine-flag routing in ClaudePrintSubagents.judge ---------------------

_SENTINEL = object()


def test_subagents_judge_routes_engine_by_flag(monkeypatch, tmp_path):
    # pydantic_ai (the default) → invoke_judge gets judge_fn=_run_judge_pydantic.
    # claude_print → invoke_judge is called with NO judge_fn (uses its own default
    # _run_judge_claude).
    captured = {}

    def _spy(wiring, run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
             *, judge_fn=_SENTINEL):
        captured["judge_fn"] = judge_fn
        return _YAML

    monkeypatch.setattr(subagents, "invoke_judge", _spy)  # lint-monkeypatch: ok — spy the judge_fn routing decision
    sub = subagents.ClaudePrintSubagents()
    tail = (tmp_path, tmp_path / "story.md", tmp_path / "tel.yaml", tmp_path)

    # Default (pydantic_ai): the glm wiring routes to the in-process judge.
    monkeypatch.delenv("LEARNING_JUDGE_ENGINE", raising=False)
    sub.judge(ADVERSARIAL_WIRING, *tail)
    assert captured["judge_fn"] is _run_judge_pydantic

    # claude_print with an Anthropic model routes to the claude -p judge (no judge_fn).
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", "claude_print")
    claude_wiring = dataclasses.replace(ADVERSARIAL_WIRING, model="claude-sonnet-4-6")
    sub.judge(claude_wiring, *tail)
    assert captured["judge_fn"] is _SENTINEL


def test_subagents_judge_claude_print_rejects_fireworks_model(monkeypatch, tmp_path):
    # The default JUDGE_MODEL is a Fireworks model (glm-5.2) that the legacy claude -p
    # transport can't serve — claude_print + a non-Anthropic model fails loud (a clear
    # config error), not with an opaque `claude -p --model glm-5.2` CLI failure.
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", "claude_print")
    sub = subagents.ClaudePrintSubagents()
    with pytest.raises(FatalConfigError):
        sub.judge(ADVERSARIAL_WIRING, tmp_path, tmp_path / "story.md",
                  tmp_path / "tel.yaml", tmp_path)
