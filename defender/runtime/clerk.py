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

from ._clerk_contract import (
    CLERK_ROUND_BUDGET,
    PENDING_CAP,
    ClerkMalformedReply,
    PendingCompile,
    clerk_trace_path,
)
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

#: `CLERK_ROUND_BUDGET`, `PENDING_CAP`, `ClerkMalformedReply`, `PendingCompile` and
#: `clerk_trace_path` are RE-EXPORTS from `_clerk_contract`, the leaf both this module and
#: `tools/_clerk.py` read them from — see that module's own docstring for the cycle they
#: would otherwise close. This is still where a reader imports them.

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
    #: The clerk's grammar + closed-slot catalog, built lazily on first use by
    #: `tools/_clerk._grammar_and_catalog` and then held for the life of the run — the same
    #: read-once treatment `instructions` gets above, for the same reason: it is a shipped
    #: asset plus a walk of a closed vocabulary, constant for the run, and otherwise rebuilt
    #: at the top of every single `record` call.
    grammar_catalog: str | None = None
    #: Per-run cache of the BUILT MODEL, keyed on the `(name, effort)` pair actually resolved
    #: at call time. Not the built Agent: `build_agent_core` bakes `agent_id` into the request
    #: hooks and into the prompt-cache affinity key, and every clerk call needs its own
    #: `clerk:{n}` identity in the run's ONE wire log (O5) — so the agent is per-call BY
    #: CONTRACT and the model, which is identical for every call resolving the same pair, is
    #: the part a cache may hold. One `record` spends up to six clerk calls and a run up to
    #: `max_tool_calls` of them, so this is a provider build per call otherwise. An operator
    #: moving either knob mid-run resolves a different pair and builds again, which is exactly
    #: the "read fresh on every call" property both env seams exist for.
    _models: dict[tuple[str, str | None], Any] = field(default_factory=dict)

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
        agent = build(
            defn, deps_type=defn.deps_cls, instructions=self.instructions,
            logger=self.logger, agent_id=agent_id, make_model=self._make_model,
        )
        deps = bind_review_role(defn, self.run_dir, defender_dir=self.defender_dir)
        result = await asyncio.wait_for(agent.run(prompt, deps=deps), timeout=deadline)
        return str(result.output or "")

    def _make_model(self, name: str, effort: str | None):
        """The builder's `make_model` seam, memoized per `(name, effort)` on this run — see
        `_models`. Wraps whichever seam the caller was constructed with (a test's injected one,
        or the shipped provider table), so the injection point is unchanged and only the
        rebuild is removed."""
        key = (name, effort)
        if key not in self._models:
            from . import providers

            base = self.make_model if self.make_model is not None else providers.build_for_effort
            self._models[key] = base(name, effort)
        return self._models[key]

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


def _highest_clerk_wire_call(run_dir: Path) -> int:
    """The HIGHEST `clerk:{n}` the run's wire log already carries — the seed for `n`, so a
    resumed process cannot re-issue an id a prior pass already used (HD-2's one exception).

    THE MAXIMUM, NOT THE COUNT. `ClerkCaller.call` increments `n` before it awaits, and the
    scripted lane logs only after a successful reply while the live lane logs through the
    request hook — so a faulted call spends an id and leaves no row for it. With `clerk:1` and
    `clerk:3` on disk, a count seeds 2 and the resumed process issues `clerk:3` again, which
    is precisely the collision this seeding exists to prevent, and it fails silently: the two
    calls become one identity and the run's clerk spend stops being attributable per call.

    A malformed or non-numeric suffix contributes nothing rather than raising: this runs at
    composition-root construction, where a torn last line must not stop a resume."""
    from defender._io import read_jsonl_rows
    from defender._run_paths import RunPaths

    path = RunPaths(Path(run_dir)).wire_log
    if not path.is_file():
        return 0
    highest = 0
    for row in read_jsonl_rows(path):
        agent_id = str(row.get("agent_id", ""))
        if not agent_id.startswith(CLERK_AGENT_ID_PREFIX):
            continue
        suffix = agent_id[len(CLERK_AGENT_ID_PREFIX):]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return highest


def _highest_clerk_trace_n(run_dir: Path) -> int:
    """The HIGHEST `n` in `clerk_trace.jsonl` — the seed for `record_n`, HD-2's other identity
    cell over the same counter, and the maximum for the reason above.

    `_append_trace` is best effort: it reports an `OSError` in the receipt and returns, so
    `record_n` can already have run ahead of the rows on disk. A count then seeds low and the
    resume re-issues a trace `n` a prior process used, which is the same silent collision."""
    from defender._io import read_jsonl_rows

    path = clerk_trace_path(Path(run_dir))
    if not path.is_file():
        return 0
    highest = 0
    for row in read_jsonl_rows(path):
        n = row.get("n")
        if isinstance(n, int):
            highest = max(highest, n)
    return highest


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
        n=_highest_clerk_wire_call(run_dir), record_n=_highest_clerk_trace_n(run_dir),
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
