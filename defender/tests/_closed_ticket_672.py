"""Shared drive harness for the #672 closed-ticket suite (split out by #720).

The spec narrative — the forks, the demands, and why each observation channel is the
one it is — stays in `test_closed_ticket_tool_672.py`, which remains the spine of the
suite. This module holds only what every part of it drives through: the frozen names
the spec graph joins to by name, the injected ticket-verb registry, and `_drive`, the
entry into the REAL judge leg.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
import re
from collections import deque
from functools import partial
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender.learning.core.config import JudgeWiring  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import _run_judge_pydantic  # noqa: E402
from defender.learning.pipeline.judge.run import invoke_judge  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs, ReplayFn, Turn, VerbRecorder  # noqa: E402

pytestmark = pytest.mark.e2e

# fork f2 (§7): names FROZEN — the graph joins to code by name.
TOOL_GET = "get_closed_ticket"
TOOL_LIST = "list_closed_tickets"
BIT = "closed_tickets"

# The key grammar this environment DECLARES (TICKET_KEY_PATTERN in the ticket system's
# config.env — a REQUIRED key of ticket_adapter.REQUIRED_CONFIG_KEYS). Held here as a literal
# so every drive stays hermetic, and pinned against the shipped file by
# test_shipped_ticket_config_declares_the_key_grammar (d30's currency half).
SHIPPED_KEY_PATTERN = "[A-Za-z0-9][A-Za-z0-9._-]*"

_YAML = "outcome: skip-passthrough\ndefender_findings: []\n"
DONE = Turn(text=_YAML)

# The case id doubles as the in-flight ticket key: the learning run dir's basename is the
# key the judge's deps carry (run_id); the closed-ticket tools refuse it structurally.
CASE = "20260720T0000Z-sshd-672"

# One well-known closed ticket every happy-path fake returns. The marker strings are what
# the assertions grep for in the model-visible channel.
OTHER_KEY = "SOC-777"
CLOSED_TKT = {
    "key": OTHER_KEY,
    "status": "closed",
    "summary": "nightly scan cleared TKT-CONTENT-777",
    "resolution": "benign — [grounded: approved-window] TKT-RESOLUTION-777",
}

WRAP_RE = re.compile(r"<run-([0-9a-f]{32})-untrusted>")


def _get(key) -> Turn:
    return Turn(tool_calls=[(TOOL_GET, {"key": key})])


def _list(**filters) -> Turn:
    return Turn(tool_calls=[(TOOL_LIST, filters)])


# ── the injected ticket-verb registry (the #611 FakeVerbs idiom, ticket-shaped) ──────────


def _outcome(spec_queue: deque, default):
    kind, val = spec_queue.popleft() if spec_queue else default
    if kind == "raise":
        raise val
    return val


def _ticket_registry(
    recorder: VerbRecorder,
    *,
    get=(),
    lst=(),
    get_default=("return", CLOSED_TKT),
    lst_default=None,
    key_pattern=("return", SHIPPED_KEY_PATTERN),
    declare_key_pattern=True,
) -> FakeVerbs:
    """A fake `ticket` verb table with the REAL declared param surfaces (the Fork D probe's
    executed `declared_params`: get-ticket {key, require_closed=False}; list-tickets
    {status, label, q, require_closed=False}), plus the `key-pattern` verb the key screen
    resolves this environment's grammar through. Each fake records what it was HANDED and then
    returns/raises its declarative outcome spec — it never inspects the params to decide.

    `key_pattern` serves the grammar (default: the value the shipped config declares, so every
    other test drives the real screen); `declare_key_pattern=False` builds a registry whose
    adapter declares NO such verb — the misconfigured-store shape, which must fail closed."""
    lst_default = lst_default or ("return", {"tickets": [dict(CLOSED_TKT)], "total": 1})
    get_q, lst_q = deque(get), deque(lst)

    def get_ticket(ctx, *, key: str, require_closed: bool = False):
        recorder.record("get-ticket", ctx, {"key": key, "require_closed": require_closed})
        return _outcome(get_q, get_default)

    def list_tickets(ctx, *, status=None, label=None, q=None, require_closed: bool = False):
        recorder.record(
            "list-tickets", ctx,
            {"status": status, "label": label, "q": q, "require_closed": require_closed},
        )
        return _outcome(lst_q, lst_default)

    def health_check(ctx):
        recorder.record("health-check", ctx, {})
        return {"status": "ok"}

    def key_pattern_verb(ctx):
        recorder.record("key-pattern", ctx, {})
        return _outcome(deque(), key_pattern)

    table = {
        "get-ticket": get_ticket, "list-tickets": list_tickets, "health-check": health_check,
    }
    if declare_key_pattern:
        table["key-pattern"] = key_pattern_verb
    return FakeVerbs({"ticket": table})


# ── the drive: the REAL judge leg entry, fakes through its injection seams ───────────────


class _Script(ReplayFn):
    """ReplayFn + capture of the model-visible tool roster (AgentInfo.function_tools) —
    the observation channel for registration and schema demands: what the MODEL is offered,
    not what some registry claims."""

    def __init__(self, turns):
        super().__init__(turns)
        self.tool_defs = None

    def __call__(self, messages, info):
        if self.tool_defs is None:
            self.tool_defs = list(info.function_tools)
        return super().__call__(messages, info)


def _case(tmp_path: Path, name: str = CASE):
    """A minimal real case on disk: the investigation run dir (alert + gather_raw), the
    benign story/telemetry, and the learning run dir whose BASENAME is the in-flight key."""
    run_dir = tmp_path / name
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_text(json.dumps(
        {"rule": {"id": "5710", "description": "sshd brute force"},
         "timestamp": "2026-07-20T00:00:00+00:00"}
    ))
    story = run_dir / "actor_benign_story.md"
    story.write_text(f"1. Routine story\nciting {OTHER_KEY} as covering policy\n")
    telem = run_dir / "projected_telemetry_benign.yaml"
    telem.write_text("projections: []\n")
    lrd = tmp_path / "learn" / run_dir.name
    lrd.mkdir(parents=True, exist_ok=True)
    (lrd / "past_tickets.txt").write_text(f"- {OTHER_KEY}: benign — nightly scan\n")
    return run_dir, story, telem, lrd


def _wiring(tmp_path: Path, *, benign: bool = True) -> JudgeWiring:
    prompt = tmp_path / "judge_prompt.md"
    prompt.write_text("You are the judge. Emit one YAML document.\n")
    if benign:
        return JudgeWiring(
            prompt, "claude-sonnet-4-6", "low", "judge_benign_trace.jsonl",
            "judge-benign", "comparison_benign", closed_ticket_read=True,
        )
    return JudgeWiring(
        prompt, "claude-sonnet-4-6", "low", "judge_trace.jsonl", "judge", "comparison",
    )


class _Driven:
    def __init__(self, out: str, script: _Script, run_dir: Path, lrd: Path):
        self.out, self.script, self.run_dir, self.lrd = out, script, run_dir, lrd

    @property
    def last(self) -> str:
        """The final model request's flattened messages — where the last tool result lands."""
        return self.script.seen[-1] if self.script.seen else ""

    @property
    def all_text(self) -> str:
        """Every string the MODEL ever saw across the run, plus its final output."""
        return "\n".join([*self.script.seen, self.out])

    def rows(self) -> list[dict]:
        p = self.lrd / "executed_queries.jsonl"
        return read_jsonl_rows(p) if p.is_file() else []

    def breaker(self) -> dict:
        p = self.lrd / "circuit_breaker.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    def tool_names(self) -> set[str]:
        assert self.script.tool_defs is not None, "the model was never called"
        return {t.name for t in self.script.tool_defs}


def _drive(tmp_path, turns, *, registry, benign=True, case=None, wiring=None) -> _Driven:
    """Drive the REAL judge leg — ``invoke_judge`` → ``_run_judge_pydantic`` → the shared
    stage build → the registered tools — with the two fakes entering through the entry
    point's injection seams: ``make_model`` (the FunctionModel replay) and ``verbs=`` (the
    ticket registry). ``verbs=`` is the seam this spec DEMANDS on ``_run_judge_pydantic``
    (it mirrors #611's `run_investigation(verbs=…)`); against today's tree the drive fails
    on exactly that missing seam, which is this suite's honest red."""
    run_dir, story, telem, lrd = case if case is not None else _case(tmp_path)
    script = _Script(turns)

    def make_model(name, effort):
        return BuiltModel(FunctionModel(script), None)

    judge_fn = partial(_run_judge_pydantic, make_model=make_model, verbs=registry)
    with override_allow_model_requests(False):
        out = invoke_judge(
            wiring if wiring is not None else _wiring(tmp_path, benign=benign),
            run_dir, story, telem, lrd, judge_fn=judge_fn, box=None,
        )
    return _Driven(out, script, run_dir, lrd)


def _feedback(run: _Driven) -> str:
    """The model-visible text APPENDED after the first request — the channel a tool result,
    retry prompt, or refusal comes back on. ``seen`` entries are cumulative flattened
    histories (the replay harness re-flattens the whole history per request), so the delta
    past ``seen[0]`` is exactly what the drive added: assertions on it cannot be satisfied
    by the ambient prompt (the blind reader's finding on the old ``in all_text`` greps)."""
    assert run.script.seen, "the model was never called"
    return run.script.seen[-1][len(run.script.seen[0]):]


def _tool_delta(run: _Driven) -> str:
    """The model-visible text the LAST tool call added — ``seen[-1]`` past ``seen[-2]``.
    ``seen`` entries are cumulative flattened histories, so this delta is exactly one
    response: an assertion on it cannot be satisfied by a DIFFERENT tool path's output
    earlier in the run (#684/F2 — the whole-run greps let a listing that faulted or
    dropped everything pass a per-item demand)."""
    assert len(run.script.seen) >= 2, "the drive never issued a second model request"
    # The whole guarantee above rests on the histories being APPEND-ONLY. Assert it rather
    # than assume it: if the harness ever re-flattens non-additively (a compaction, a retry
    # rewriting history), the slice below silently starts mid-message and every conjunction
    # built on this delta goes non-discriminating again — the failure mode #684 exists to end.
    assert run.script.seen[-1].startswith(run.script.seen[-2]), (
        "the flattened history is not append-only — the delta is not one response"
    )
    return run.script.seen[-1][len(run.script.seen[-2]):]


def _get_calls(rec: VerbRecorder) -> list:
    return [c for c in rec.calls if c.verb == "get-ticket"]


def _list_calls(rec: VerbRecorder) -> list:
    return [c for c in rec.calls if c.verb == "list-tickets"]


def _store_calls(rec: VerbRecorder) -> list:
    """Every call that REACHED THE STORE. The `key-pattern` verb reads this environment's
    config to build the screen and touches no ticket, so "zero store attempts" is a claim
    about everything but it."""
    return [c for c in rec.calls if c.verb != "key-pattern"]
