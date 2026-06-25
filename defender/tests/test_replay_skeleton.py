"""Skeleton e2e replay test for the PydanticAI runtime — deterministic + hermetic.

Drives the REAL `driver.run_investigation` loop with a `FunctionModel` that
replays a scripted sequence of tool calls — NO API key, NO network, NO dollars
(belt-and-suspenders: ALLOW_MODEL_REQUESTS=False). It proves the whole-runtime
seam in one shot:

    FunctionModel(replay) -> driver.agent.iter loop -> real generic tools
      -> real permission gate (incl. invlang validation on investigation.md)
      -> real observe projection (tool_trace.jsonl) + budget hook -> run-dir artifacts

This is the corpus's first fixture: `fixtures-e2e/golden-v2sshd/`, a vendored
real run. The test replays that run's artifact-write subset and diffs the
produced run dir against the golden. Scaling to the full mined corpus =
`load_turns_from_trace` (below) over each run's `tool_trace.jsonl`, plus stubbed
adapter/gather deps for runs that call bash/gather (the next increment).
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

import pydantic_ai.models as pai_models  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.runtime import driver  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.skills.invlang.validate import validate_companion  # noqa: E402

pytestmark = pytest.mark.e2e

_DEFENDER = Path(__file__).resolve().parents[1]
_GOLDEN = _DEFENDER / "fixtures-e2e" / "golden-v2sshd"
_GOLDEN_AB3 = _DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3"
# The run dir the vendored ab3 trace was recorded under; rewritten to the temp
# run dir on replay (the context-reproduction step).
_AB3_ORIG_RUN_DIR = "/tmp/defender-runs/ab3-B"


# --- replay engine ---------------------------------------------------------

@dataclass
class Turn:
    """One scripted assistant turn. `tool_calls` is [(tool_name, args), ...]; a
    turn with no tool_calls is text-only and ENDS the agent loop."""
    tool_calls: list[tuple[str, dict]] = field(default_factory=list)
    text: str = ""


class ReplayFn:
    """Stateful FunctionModel callable: emits the next scripted turn per model
    request. Past the script it returns a text-only turn so the loop terminates
    rather than hanging (mirrors a real run hitting its stop condition)."""

    __name__ = "ReplayFn"  # FunctionModel derives its model_name from this

    def __init__(self, turns: list[Turn]):
        self._turns = turns
        self.calls = 0

    def __call__(self, messages, info) -> ModelResponse:
        if self.calls < len(self._turns):
            t = self._turns[self.calls]
            self.calls += 1
            parts: list = []
            if t.text:
                parts.append(TextPart(content=t.text))
            for name, args in t.tool_calls:
                parts.append(ToolCallPart(tool_name=name, args=args))
            return ModelResponse(parts=parts or [TextPart(content="(done)")])
        return ModelResponse(parts=[TextPart(content="(replay exhausted)")])


def _rewrite_paths(v, old: str | None, new: str | None):
    """Recursively rewrite `old`->`new` in string leaves of a tool-args value."""
    if isinstance(v, str):
        return v.replace(old, new) if old and new else v
    if isinstance(v, dict):
        return {k: _rewrite_paths(x, old, new) for k, x in v.items()}
    if isinstance(v, list):
        return [_rewrite_paths(x, old, new) for x in v]
    return v


def _turn_from_record(rec: dict, old_run_dir: str | None, new_run_dir: str | None) -> Turn:
    calls: list[tuple[str, dict]] = []
    text = ""
    for part in rec.get("message", {}).get("content", []):
        if part.get("type") == "tool_use":
            calls.append((part["name"], _rewrite_paths(part.get("input", {}), old_run_dir, new_run_dir)))
        elif part.get("type") == "text":
            text = part.get("text", "")
    return Turn(tool_calls=calls, text=text)


def load_turns_from_trace(
    trace_path: Path, *, old_run_dir: str | None = None, new_run_dir: str | None = None,
) -> list[Turn]:
    """Layer 2 (mining): parse a real `tool_trace.jsonl` into scripted Turns.

    Rewrites `old_run_dir`->`new_run_dir` in string args — the context-repro step
    (a recorded write/read names an absolute path into the ORIGINAL run dir). Full
    replay of the nested gather subagent additionally needs stubbed adapter deps;
    this loader is the foundation for that increment.
    """
    turns: list[Turn] = []
    for line in Path(trace_path).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("type") == "assistant":
            turns.append(_turn_from_record(rec, old_run_dir, new_run_dir))
    return turns


# --- fixture materialization + golden diffing ------------------------------

def _materialize(tmp_path: Path, golden: Path, *, run_id: str, salt: str) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(golden / "alert.json", run_dir / "alert.json")
    (run_dir / "meta.json").write_text(json.dumps({"run_id": run_id, "salt": salt}))
    return run_dir


def _normalize(text: str, *, run_dir: Path, salt: str, run_id: str) -> str:
    """Strip nondeterministic substrings so a replayed artifact diffs cleanly
    against a golden (the VCR/snapshot discipline: timestamps, salt, run id)."""
    return (text.replace(str(run_dir), "<RUN_DIR>")
                .replace(salt, "<SALT>")
                .replace(run_id, "<RUN_ID>"))


# --- the test --------------------------------------------------------------

def test_replay_golden_v2sshd(tmp_path, monkeypatch):
    run_id, salt = "replay-v2sshd", "deadbeefcafe0000"
    run_dir = _materialize(tmp_path, _GOLDEN, run_id=run_id, salt=salt)

    inv_text = (_GOLDEN / "investigation.md").read_text()
    rep_text = (_GOLDEN / "report.md").read_text()

    # The artifact-write subset of the run: write investigation.md (exercises
    # decide_write + invlang validation on REAL content), write report.md, then
    # end. No bash/gather, so a single script suffices.
    script = [
        Turn(tool_calls=[("write_file",
                          {"path": str(run_dir / "investigation.md"), "content": inv_text})]),
        Turn(tool_calls=[("write_file",
                          {"path": str(run_dir / "report.md"), "content": rep_text})]),
        Turn(text="Investigation complete."),
    ]
    replay = ReplayFn(script)

    # Seam: driver builds `Agent(AnthropicModel(model_name))`. Swap the model
    # constructor for our FunctionModel — touches no production code, fakes the
    # main loop (and the gather subagent, were it dispatched).
    monkeypatch.setattr(driver, "AnthropicModel", lambda *a, **k: FunctionModel(replay))
    # Any real provider request now raises — proves the run is hermetic.
    monkeypatch.setattr(pai_models, "ALLOW_MODEL_REQUESTS", False)

    asyncio.run(driver.run_investigation(
        alert_path=run_dir / "alert.json",
        run_dir=run_dir,
        run_id=run_id,
        defender_dir=_DEFENDER,
        salt=salt,
    ))

    # 1. The loop replayed our script exactly (3 model requests).
    assert replay.calls == 3, f"expected 3 model turns, got {replay.calls}"

    # 2. investigation.md passed the REAL invlang gate and is byte-identical to
    #    the golden (characterization of the write path + validator).
    produced_inv = (run_dir / "investigation.md").read_text()
    assert _normalize(produced_inv, run_dir=run_dir, salt=salt, run_id=run_id) == \
           _normalize(inv_text, run_dir=run_dir, salt=salt, run_id=run_id)

    # 3. report.md present + disposition parses (the learning-loop's headline).
    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "inconclusive"

    # 4. Deterministic side-effects fired: observe projected the trace; the live
    #    request log exists.
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert (run_dir / "llm_requests.jsonl").is_file()


def test_replay_full_run_ab3(tmp_path, monkeypatch):
    """Increment (a): replay a FULL real gather run (ab3-B, 10 turns) — bash,
    read_file, write_file AND gather dispatch — through the real driver loop.

    Scope: this is a MAIN-LOOP e2e test, so `gather` is faked at its return
    boundary (it's a separately-tested unit — test_runtime_gather /
    test_gather_capture own its internals; re-driving it would couple this test to
    them). Everything else is real: the bash/read/write tools and the permission
    gate's decide_bash / decide_read / decide_write / invlang paths all fire. We
    assert the authored artifact (investigation.md) reconstructs byte-for-byte and
    re-validates clean through the live gate. The two-table / gather_raw capture
    belongs to the deferred nested-gather increment.
    """
    run_id, salt = "replay-ab3", "0011223344556677"
    run_dir = _materialize(tmp_path, _GOLDEN_AB3, run_id=run_id, salt=salt)

    # Reconstruct the main-agent script from the vendored trace, rewriting the
    # recorded run-dir paths to this temp run dir.
    turns = load_turns_from_trace(
        _GOLDEN_AB3 / "tool_trace.jsonl",
        old_run_dir=_AB3_ORIG_RUN_DIR, new_run_dir=str(run_dir),
    )
    replay = ReplayFn(turns)

    # Fake the main model (replays the script) ...
    monkeypatch.setattr(driver, "AnthropicModel", lambda *a, **k: FunctionModel(replay))
    monkeypatch.setattr(pai_models, "ALLOW_MODEL_REQUESTS", False)

    # ... and fake `gather` at its boundary: a dispatched lead returns a recorded
    # summary string without re-driving the nested agent. Signature mirrors
    # tools._run_gather(deps, gather_factory, request_limit, lead_id, system, ...).
    async def _fake_run_gather(deps, gather_factory, request_limit,
                               lead_id, system, goal, what_to_summarize):
        return f"[replayed gather summary: lead={lead_id} system={system}]"

    monkeypatch.setattr(runtime_tools, "_run_gather", _fake_run_gather)

    asyncio.run(driver.run_investigation(
        alert_path=run_dir / "alert.json",
        run_dir=run_dir,
        run_id=run_id,
        defender_dir=_DEFENDER,
        salt=salt,
    ))

    # 1. The whole trace replayed — no early termination from an unexpected deny.
    assert replay.calls == len(turns), \
        f"replayed {replay.calls}/{len(turns)} turns (early stop = an unexpected gate deny)"

    # 2. investigation.md reconstructed byte-for-byte through the real write path
    #    + invlang validation on every intermediate write.
    produced = (run_dir / "investigation.md").read_text()
    golden = (_GOLDEN_AB3 / "investigation.md").read_text()
    assert _normalize(produced, run_dir=run_dir, salt=salt, run_id=run_id) == \
           _normalize(golden, run_dir=run_dir, salt=salt, run_id=run_id)

    # 3. The reconstruction is independently invlang-valid (the live gate accepted it).
    assert validate_companion(produced, None) == []

    # 4. report.md disposition reconstructed; trace projected.
    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(), re.M)
    assert m is not None
    assert m.group(1) == "malicious"
    assert (run_dir / "tool_trace.jsonl").is_file()


# --- deny-tail fixtures (synthesized; spec-anchored) -----------------------
# These verdicts NEVER appear in an organic run — a well-behaved agent doesn't
# try to run an adapter from the main loop or write outside the run dir. So they
# can't be mined; the golden is the SPEC verdict (deny), asserted once here. They
# guard the security boundary, so a future change that flips them must be a loud,
# reviewed event — not a silent re-record.

def _messages_text(messages) -> str:
    """Flatten every message part's content to one string — used to assert the
    deny reason bounced back to the model as retry feedback."""
    out: list[str] = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            content = getattr(part, "content", None)
            if content is not None:
                out.append(content if isinstance(content, str) else str(content))
    return "\n".join(out)


class _DenyProbe:
    """A model that emits one offending tool call, then text. Records the message
    history of each request so the test can assert the deny reason came back."""

    __name__ = "DenyProbe"

    def __init__(self, tool_name: str, args: dict):
        self._offending = (tool_name, args)
        self.calls = 0
        self.seen: list[str] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.calls += 1
        self.seen.append(_messages_text(messages))
        if self.calls == 1:
            name, args = self._offending
            return ModelResponse(parts=[ToolCallPart(tool_name=name, args=args)])
        return ModelResponse(parts=[TextPart(content="Acknowledged; stopping.")])


@pytest.mark.parametrize(("label", "tool_name", "args_fn", "reason_substr", "escape_name"), [
    # D1 — the breach: the main loop must NOT run a data-source adapter directly
    # (that's the exfil lane; the gather subagent is the only data-access role).
    ("adapter-from-main", "bash",
     lambda rd: {"command": "defender-elastic query foo --raw"},
     "data-source CLIs directly", None),
    # D6 — a write escaping the run dir must be refused.
    ("write-escape", "write_file",
     lambda rd: {"path": str(rd.parent / "ESCAPE_OUTSIDE_RUNDIR.txt"), "content": "x"},
     "stay inside the run dir", "ESCAPE_OUTSIDE_RUNDIR.txt"),
])
def test_main_loop_deny_bounces(tmp_path, monkeypatch, label, tool_name, args_fn,
                                reason_substr, escape_name):
    run_id, salt = f"deny-{label}", "8899aabbccddeeff"
    run_dir = _materialize(tmp_path, _GOLDEN_AB3, run_id=run_id, salt=salt)

    probe = _DenyProbe(tool_name, args_fn(run_dir))
    monkeypatch.setattr(driver, "AnthropicModel", lambda *a, **k: FunctionModel(probe))
    monkeypatch.setattr(pai_models, "ALLOW_MODEL_REQUESTS", False)

    asyncio.run(driver.run_investigation(
        alert_path=run_dir / "alert.json", run_dir=run_dir, run_id=run_id,
        defender_dir=_DEFENDER, salt=salt,
    ))

    # 1. The deny BOUNCED the agent (ModelRetry → re-prompt), not crashed it: the
    #    model was called again after the offending turn.
    assert probe.calls >= 2, "deny did not bounce the agent back into the loop"

    # 2. The spec deny reason reached the model as retry feedback (the in-process
    #    twin of the claude -p exit-2). Proves the driver wired role/run_dir into
    #    the gate — the unit test of decide_* can't see this.
    assert reason_substr in probe.seen[-1]

    # 3. The breach did not happen: a write-escape never created the file outside
    #    the run dir.
    if escape_name is not None:
        assert not (run_dir.parent / escape_name).exists()


def test_role_flip_adapter_is_role_dependent():
    """The crown-jewel contrast, asserted directly: the SAME adapter command is
    DENIED from the main loop (wired-and-bounced by test_main_loop_deny_bounces
    above) but ALLOWED for the gather subagent. Full GATHER-role e2e wiring is the
    deferred nested-gather increment; this pins the role-dependence the driver
    must thread."""
    cmd = "defender-elastic query foo --raw"
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow
