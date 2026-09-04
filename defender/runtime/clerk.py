"""The clerk role (#996): a zero-grant text-in/text-out role that compiles MAIN's prose into
invlang rows.

`ClerkCaller` is the ONE per-run object this design adds: it holds the run's queue of
uncompiled prose (`pending`), the previous call's unanswered questions (`last_gaps`), and the
two identity counters neither of which may collide across a resume (`n` — the wire log's
`clerk:{n}` namespace; `record_n` — the `clerk_trace.jsonl` row's own `n` field). Built once,
at the composition root, beside the review bundle (`driver/__init__.py`).

The RAW clerk seam `run_investigation(clerk=…)` takes mirrors `review_stages=` exactly: one
async callable, handed the rendered turn, answering with text. The harness DEFAULTS a scripted
one (same layer, same shape as the review bundle's own default); only a PRODUCTION run built
with none reaches the live caller here. `ClerkCaller` wraps whichever one it is handed — or
builds the live one itself when none is supplied — and is what `record` (`tools/_clerk.py`)
is actually threaded.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar

from defender._env import env_int, env_str

from .agent_definition import AgentDefinition, ToolSet
from .agent_role import CLERK_AGENT_ID_PREFIX, AgentRole
from .tools import AgentDeps

CLERK_MODEL_ENV = "DEFENDER_CLERK_MODEL"
CLERK_EFFORT_ENV = "DEFENDER_CLERK_EFFORT"
#: The clerk call's own deadline, read at CALL time — the seam `70-resolutions.md` leaves the
#: design with no number for; derived from the review's own sibling knob
#: (`DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS`) rather than a free-standing constant, and read
#: fresh on every call so an operator's override reaches a call already in flight from the
#: next one on.
CLERK_TIMEOUT_ENV = "DEFENDER_CLERK_TIMEOUT_SECONDS"
DEFAULT_CLERK_MODEL = "glm-5p3-flash"
DEFAULT_CLERK_EFFORT = "low"
DEFAULT_CLERK_TIMEOUT_SECONDS = 120

#: D2/D7's shared budget: repair rounds and round-loop rounds draw from ONE pool of six clerk
#: invocations per `record` call — never two independent pools of six. HD-4 also fixes
#: `pending`'s own cap at this same number.
CLERK_ROUND_BUDGET = 6
#: HD-4: `pending` holds at most six entries; the oldest is dropped on overflow, with a
#: receipt line naming what was lost.
PENDING_CAP = 6

_DENY_REASON = (
    "Blocked: the clerk is a pure projection — it receives text and returns text. Its "
    "entire input is inlined in the prompt and its entire output is one document. It "
    "holds no read grant and no bash grant of any kind."
)


def resolve_clerk_model() -> str:
    return env_str(CLERK_MODEL_ENV, DEFAULT_CLERK_MODEL)


def resolve_clerk_effort() -> str:
    return env_str(CLERK_EFFORT_ENV, DEFAULT_CLERK_EFFORT)


def clerk_deadline_seconds() -> int:
    return env_int(CLERK_TIMEOUT_ENV, DEFAULT_CLERK_TIMEOUT_SECONDS)


@dataclass(frozen=True)
class ClerkDeps(AgentDeps):
    """Exists only to carry the `role` ClassVar, the same reason every zero-grant role's deps
    subtype does — without the override a clerk deps bound through the base class would hold
    MAIN's default role identity."""

    role: ClassVar[AgentRole] = AgentRole.CLERK


CLERK_DEF = AgentDefinition(
    role=AgentRole.CLERK,
    model=resolve_clerk_model,
    # A LITERAL on the definition, never the provider table's role branch — D4. Read at CALL
    # time via `.effort()`, exactly like `.model()`, so an operator's override reaches the next
    # call rather than only a process that re-imports this module.
    effort=resolve_clerk_effort,
    tools=ToolSet(),
    deps_cls=ClerkDeps,
    deny_reason=_DENY_REASON,
)


#: `(prose, held_block, owed)` — a provider fault pushes `(prose, None, [])`; a D7 judgment
#: stop or an S6 conclude-drop pushes `(prose, block, owed)`.
PendingCompile = tuple[str, "str | None", tuple[str, ...]]


class ClerkMalformedReply(Exception):
    """The clerk answered with text the round loop cannot split into fences OR a `GAPS:`
    section at all — what a model that lost the format and answered in prose produces.
    Treated identically to a transport fault: pend the prose, write the trace, return."""


@dataclass
class ClerkCaller:
    """One per run, built at the composition root. `n` is the wire log's own counter — every
    underlying clerk model call gets `agent_id=f"clerk:{n}"` — and `record_n` is the trace
    file's own call counter, incremented once per `record()` call (not per underlying model
    call: one `record()` may retry the clerk across several rounds). Both are SEEDED from
    on-disk state at construction (`make_clerk_caller`), the one exception HD-2 carries across
    a resume: a counter that restarted at zero would re-issue an id a prior process already
    used.

    `pending` and `last_gaps` are NOT seeded across a resume — HD-2's examined loss: they are
    scoped to one process lifetime, and persisting them was considered and rejected as a
    second durable mechanism beside the document, with no recovery contract of its own.
    """

    run_dir: Path
    defender_dir: Path
    logger: Any
    instructions: str
    raw: Any = None
    make_model: Any = None
    build: Any = None
    call_ceiling: int | None = None
    n: int = 0
    record_n: int = 0
    pending: list[PendingCompile] = field(default_factory=list)
    last_gaps: list[str] = field(default_factory=list)

    def allowed(self) -> bool:
        """O10's derived ceiling: `record` is metered, never refused, past it — so a caller
        checks this before spending an underlying clerk call, and degrades to no clerk call at
        all rather than raising."""
        return self.call_ceiling is None or self.n < self.call_ceiling

    def push_pending(self, entry: PendingCompile) -> str | None:
        """Append `entry`, dropping the OLDEST on overflow past `PENDING_CAP`. Returns the
        dropped prose's lead (for the receipt's drop line) or `None`."""
        self.pending.append(entry)
        if len(self.pending) > PENDING_CAP:
            dropped = self.pending.pop(0)
            return dropped[0]
        return None

    async def call(self, prompt: str) -> str:
        self.n += 1
        agent_id = f"{CLERK_AGENT_ID_PREFIX}{self.n}"
        deadline = clerk_deadline_seconds()
        if self.raw is not None:
            text = await asyncio.wait_for(self.raw(prompt), timeout=deadline)
            self._log_scripted(agent_id, prompt, text)
            return text
        # The LIVE path: built through the run's own composition-root builder so its request
        # lands on the run's own logger through the SAME hook every other role's calls do
        # (`_make_hooks`'s `model_request` hook) — nothing here logs by hand.
        from .driver import build_agent_core
        from .review_roles import bind_review_role

        build = self.build if self.build is not None else build_agent_core
        effort_value = CLERK_DEF.effort() if callable(CLERK_DEF.effort) else CLERK_DEF.effort
        defn = replace(CLERK_DEF, effort=effort_value)
        assert defn.deps_cls is not None, "CLERK_DEF declares no deps_cls"
        kwargs: dict[str, Any] = {}
        if self.make_model is not None:
            kwargs["make_model"] = self.make_model
        agent = build(
            defn, deps_type=defn.deps_cls, instructions=self.instructions,
            logger=self.logger, agent_id=agent_id, **kwargs,
        )
        deps = bind_review_role(defn, self.run_dir, defender_dir=self.defender_dir)
        result = await asyncio.wait_for(agent.run(prompt, deps=deps), timeout=deadline)
        return str(result.output or "")

    def _log_scripted(self, agent_id: str, prompt: str, text: str) -> None:
        """A scripted clerk bypasses the Agent/hooks machinery entirely (it is a bare
        text-to-text callable, not a `Model`), so nothing else logs its call — yet the run's
        wire log is the ONE place every clerk call's identity lands (O5), scripted or live, so
        it is logged here by hand."""
        from pydantic_ai.messages import ModelResponse, TextPart

        # EMPTY request_messages, deliberately: `RequestLogger.log` emits one row per element
        # of `request_messages` PLUS one response row, all under the same `agent_id` — so a
        # non-empty list here would give this ONE clerk call two rows sharing one identity,
        # which is exactly the shape the trace's own identity-uniqueness demand refuses. The
        # prompt itself is not the observable this log exists for; the call's identity is.
        response = ModelResponse(parts=[TextPart(content=text)], model_name="scripted-clerk")
        try:
            self.logger.log(request_messages=[], response=response, agent_id=agent_id)
        except Exception as e:  # noqa: BLE001 — the trace/receipt still carry the call; logging is observability
            print(f"[clerk] wire-log append failed for {agent_id}: {e!r}")


def _clerk_call_ceiling(limits: dict | None) -> int | None:
    """O10's derivation: one clerk call per analyst tool call, read off the run's own
    `max_tool_calls` rather than stated as a free-standing constant — so the ceiling retunes
    automatically when that cap moves, which is the discriminator a constant could not have."""
    if not limits:
        return None
    cap = limits.get("max_tool_calls")
    return int(cap) if isinstance(cap, int) else None


def _count_clerk_wire_calls(run_dir: Path) -> int:
    """How many `clerk:` agent ids the run's wire log already carries — the seed for `n` so a
    resumed process cannot re-issue an id a prior pass already used (HD-2's one exception)."""
    from defender._io import read_jsonl_rows
    from defender._run_paths import RunPaths

    path = RunPaths(Path(run_dir)).wire_log
    if not path.is_file():
        return 0
    seen: set[str] = set()
    for row in read_jsonl_rows(path):
        agent_id = str(row.get("agent_id", ""))
        if agent_id.startswith(CLERK_AGENT_ID_PREFIX):
            seen.add(agent_id)
    return len(seen)


def _count_clerk_trace_rows(run_dir: Path) -> int:
    """How many `clerk_trace.jsonl` rows already exist — the seed for `record_n`, HD-2's other
    identity cell over the same counter."""
    from defender._io import read_jsonl_rows

    path = Path(run_dir) / "wire_logs" / "clerk_trace.jsonl"
    if not path.is_file():
        return 0
    return sum(1 for _ in read_jsonl_rows(path))


def make_clerk_caller(
    run_dir: Path, defender_dir: Path, logger: Any, *,
    raw: Any = None, make_model: Any = None, limits: dict | None = None, build: Any = None,
) -> ClerkCaller:
    """The composition root's factory. `raw` is the injection seam
    (`run_investigation(clerk=…)`) — `None` builds the live caller, threading the run's own
    `make_model` through so a test overriding it reaches the clerk's model too."""
    instructions_path = defender_dir / "skills" / "clerk" / "SKILL.md"
    instructions = instructions_path.read_text(encoding="utf-8")
    return ClerkCaller(
        run_dir=Path(run_dir), defender_dir=Path(defender_dir), logger=logger,
        instructions=instructions, raw=raw, make_model=make_model, build=build,
        call_ceiling=_clerk_call_ceiling(limits),
        n=_count_clerk_wire_calls(run_dir), record_n=_count_clerk_trace_rows(run_dir),
    )


__all__ = [
    "CLERK_DEF",
    "CLERK_EFFORT_ENV",
    "CLERK_MODEL_ENV",
    "CLERK_ROUND_BUDGET",
    "CLERK_TIMEOUT_ENV",
    "DEFAULT_CLERK_EFFORT",
    "DEFAULT_CLERK_MODEL",
    "DEFAULT_CLERK_TIMEOUT_SECONDS",
    "PENDING_CAP",
    "ClerkCaller",
    "ClerkDeps",
    "ClerkMalformedReply",
    "PendingCompile",
    "clerk_deadline_seconds",
    "make_clerk_caller",
    "resolve_clerk_effort",
    "resolve_clerk_model",
]
