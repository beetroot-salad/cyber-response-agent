
from __future__ import annotations

from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Self

from pydantic import SkipValidation

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    from defender.systems.run_tenant import RunTenant as _RunTenant
else:
    _RunTenant = Any  # `run_tenant` sits above this module in the import graph

from defender._paths import PATHS


from defender.records import Run
from defender import box as box_mod
from ..run_state import RunState, run_time_iso
from .. import permission
from ..agent_definition import ResolvedRoots
from defender._agent_role import AgentRole
from defender._model_view import ModelView

from defender.configuration._env import env_int
from defender.knowledge._knowledge import KnowledgePaths
from defender.investigation.payload_view import (
    passthrough_max_bytes as _capture_view_cap,
)
from defender.knowledge._knowledge import RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA
from defender.hooks.record_lesson_load import (
    LOAD_KINDS as _LOAD_KINDS,
    lesson_name as _lesson_name,
)


#: The queries table's infra exit code (a member of `circuit_breaker.INFRA_EXIT_CODES`).
_INFRA_EXIT_CODE = 2

_BASH_TIMEOUT_S = 120

#: The `verb` a bash-lane row carries. Not a registry verb, so an observational shim row can
#: never trip `repeat_trip`'s `(system, verb, params)` guard.
_BASH_VERB = "bash"



def _lane_admits(policy: permission.AgentPolicy, probe: str) -> bool:
    return permission.decide_bash(probe, policy=policy).allow


def _overflow_filter_hint(
    path: str, policy: permission.AgentPolicy, read_tool: str = "read_file"
) -> str:
    sql_shim = permission.command_shape.SQL_SHIM
    if _lane_admits(policy, f"{sql_shim} 'SELECT 1'"):
        reducer = f'{sql_shim} "DESCRIBE data"'
    else:
        return (
            "You have no bash reducer for this. Narrow it with the read tool's substring "
            f"search instead:\n  {read_tool}({path!r}, pattern='<substring>')"
        )
    sink = ", write the result to a file, then read that" if policy.write_allow else ""
    return f"Reduce it in a pipe{sink}:\n  cat {path} | {reducer}"


def _read_char_cap() -> int:
    """The cap on reading an authored file — a SKILL, a lesson, a design doc.

    Separate from the 8 KB capture ceiling, which only needs to apply when a captured payload
    is re-read (so a read cannot recover what the capture view withheld); authored docs are
    often larger."""
    return env_int("DEFENDER_AUTHORED_READ_MAX_CHARS", 65536)


def _cap_for(p: Path) -> int:
    return _capture_view_cap() if permission.is_captured_payload(p) else _read_char_cap()


def _bounded_read(
    # `path` is unused; kept for positional callers and defaulted for the bash lane.
    text: str, path: str = "", *, cap: int, filter_hint: str, read_tool: str = "read_file",
    subject: str = "This file",
) -> str:
    if len(text) <= cap:
        return text
    total_lines = text.count("\n") + 1
    note = (
        f"\n\n[{read_tool}] {len(text)} chars / {total_lines} line(s); showing the "
        f"first {cap}. {subject} is too large to read whole — do not "
        f"treat this head as complete. {filter_hint}"
    )
    return text[:cap] + note


def _format_bash_result(exit_code: int, stdout: str, stderr: str, note: str = "") -> str:
    out = stdout if stdout else ""
    err = f"\n--- stderr ---\n{stderr}" if stderr.strip() else ""
    return f"exit={exit_code}\n--- stdout ---\n{out}{err}{note}"




@model(frozen=True)
class AgentDeps:

    run_dir: Path
    defender_dir: Path
    run_id: str
    policy: permission.AgentPolicy = field(kw_only=True)
    cwd_anchor: Path = field(kw_only=True)
    #: `BoxLike`, not `BoxExecutor`: only `run_parsed(...)` is called, and a strict concrete
    #: type would refuse duck-typed test doubles.
    box: box_mod.BoxLike = field(kw_only=True, default_factory=box_mod.BoxExecutor)
    #: `SkipValidation` on this and `review_state`: mutable containers shared across
    #: `dataclasses.replace` copies. Validation would rebuild them, silently forking state.
    authored_paths: Annotated[set[Path], SkipValidation] = field(
        kw_only=True, default_factory=set, compare=False, repr=False
    )
    #: The review gate's per-run mutable state; `challenge_gate.ReviewState.of(deps)` owns its
    #: contents. A container because `AgentDeps` is frozen.
    review_state: Annotated[dict, SkipValidation] = field(
        kw_only=True, default_factory=dict, compare=False, repr=False
    )
    roots: ResolvedRoots | None = field(kw_only=True, default=None)
    tool_config: Any = field(kw_only=True, default=None)
    #: The run's tenant record (#1107) — handed to every verb this role dispatches
    #: (`VerbContext.tenant`). Set by the run (`run_investigation` onto
    #: MAIN's deps, carried onto each gather lead's), never derived from `defender_dir`: the
    #: settings left the code tree. `None` for a role that dispatches no verb; a verb built over
    #: `None` is refused by `VerbContext`'s own validation. `SkipValidation`: the record is a
    #: frozen value built once at resolve, never rebuilt by a deps copy.
    tenant: Annotated[_RunTenant | None, SkipValidation] = field(kw_only=True, default=None)
    #: The run's one live state (#1235): its budget and clock, its breaker, its queries rows.
    #: Set by the run (`run_investigation` onto MAIN's deps, carried onto each gather lead's by
    #: reference), so every role of one run counts into one object. `None` for a role with no
    #: run (the learning stages, the review roles), whose calls the budget hooks leave alone; a
    #: live operation over it is refused (`run_state.run_state_of`). `SkipValidation`, like
    #: `tenant`: the object is shared, never rebuilt by a deps copy.
    run: Annotated[Run | None, SkipValidation] = field(kw_only=True, default=None)
    run_state: Annotated[RunState | None, SkipValidation] = field(kw_only=True, default=None)

    role: ClassVar[AgentRole] = AgentRole.MAIN

    @property
    def view(self) -> ModelView:
        """Every filesystem role uses the same mapping; roots and cwd determine its layout.
        Learning identity remains explicit in the role's instructions (#1262)."""
        # The agent tree is the one `knowledge` reads (`agent_root`), so every corpus path the
        # role is shown has a model spelling.
        return ModelView.for_scope(
            Path(self.run_dir), Path(self.defender_dir), self.cwd_anchor, self.agent_root,
            extra_roots=self.roots.model_roots if self.roots is not None else (),
        )

    @property
    def agent_root(self) -> Path | None:
        """The run's agent root (its run copy's `agent/`, #1108 P4), or `None` for a role whose
        scope names none: the resolved roots' tenant agent half, else the run tenant's."""
        if self.roots is not None and self.roots.tenant_agent is not None:
            return Path(self.roots.tenant_agent)
        return Path(self.tenant.agent) if self.tenant is not None else None

    @property
    def knowledge(self) -> KnowledgePaths:
        """The agent knowledge this role reads (#1108 P4): its run's agent root, never the code
        tree. A role with no agent root reads no knowledge, so asking is a wiring fault."""
        agent = self.agent_root
        if agent is None:
            raise RuntimeError(
                f"{type(self).__name__} has no agent root (no run tenant and no tenant agent "
                "root): it reads no tenant knowledge")
        return KnowledgePaths(agent)

    @classmethod
    def _for_run(
        cls, run_dir: Path, policy: permission.AgentPolicy,
        *, cwd_anchor: Path, defender_dir: Path = PATHS.defender_dir,
        box: box_mod.BoxLike | None = None,
        roots: ResolvedRoots | None = None,
        tool_config: Any = None,
        **subtype_fields: Any,
    ) -> Self:
        return cls(
            run_dir=run_dir, defender_dir=defender_dir,
            run_id=run_dir.name, policy=policy,
            box=box if box is not None else box_mod.BoxExecutor(),
            cwd_anchor=cwd_anchor,
            roots=roots, tool_config=tool_config,
            **subtype_fields,
        )


@model(frozen=True)
class DeadEnd:
    """A guard's stop, as the two strings main is shown: the refused request (`reason`) and
    the sentence handing the decision to main (`escape`). Strings rather than the exception,
    whose traceback would pin the tripping frames for the rest of the lead."""

    reason: str
    escape: str


@model
class LeadStop:
    """Whether the harness stopped this lead's querying, and by which of its two stops.

    One mutable object per lead, read once by `_run_gather` after the run. A guard sets
    `dead_end` from the query tool (repeat or rejection budget) and answers later `query`
    calls from it; the request ceiling sets `ceiling` when it tells the model its final
    request is the summary. Mutable because hooks have no other way to hand a fact back up."""

    dead_end: DeadEnd | None = None
    ceiling: int | None = None
    #: The system whose circuit breaker refused one of this lead's calls, if any. The harness's
    #: correlation lead reads it to tell "the system was marked down" from "every call failed".
    breaker_refused: str | None = None

    @property
    def door_closed(self) -> bool:
        """The query tool's question: does a `query` call still run on this lead?"""
        return self.dead_end is not None

    def close_door(self, dead_end: DeadEnd) -> None:
        """First close wins, so main's notice names the request that actually stopped the lead."""
        if self.dead_end is None:
            self.dead_end = dead_end

    def mark_ceiling(self, request_limit: int) -> None:
        if self.ceiling is None:
            self.ceiling = request_limit

    def mark_breaker_refused(self, system: str) -> None:
        if self.breaker_refused is None:
            self.breaker_refused = system


@model(frozen=True)
class GatherDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.GATHER

    lead_id: str | None = None
    #: Made and read by `_run_gather`. `None` outside a dispatch (e.g. lead zero's harness
    #: calls), where a guard's dead end unwinds as an exception instead.
    stop: LeadStop | None = field(kw_only=True, default=None, compare=False, repr=False)
    #: True only for the lead the HARNESS dispatches (`l-00c`, #1222), never for a lead MAIN
    #: dispatches under the same id: its failures mark its system down but are not counted
    #: toward the run-level failure kill.
    harness_lead: bool = field(kw_only=True, default=False)


def _record_lesson_load(
    deps: AgentDeps, path: Path, corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA, *, kind: str,
) -> None:
    """The one writer of `lessons_loaded.jsonl` — a row per lesson that reached an agent.

    @owns kind — `LOAD_KIND_READ` when the model opened the lesson, `LOAD_KIND_PUSH` when the
    runtime pushed it. Keyword-only with no default, so a new call site must choose.
    @owns role — the calling deps' `AgentRole` value, so a row says which agent it reached.

    Older rows carry neither key; `cli/learning/trace_lesson.py` reads them as `unknown`.
    """
    if kind not in _LOAD_KINDS:
        raise ValueError(f"lessons_loaded row kind must be one of {sorted(_LOAD_KINDS)}: {kind!r}")
    name = _lesson_name(str(path), corpora, agent_root=deps.agent_root)
    if name is None:
        return
    try:
        run: Run = run_of(deps)
        row = {"lesson_name": name, "ts": run_time_iso(deps), "kind": kind,
               "role": deps.role.value}
        run.observability.lessons_loaded.append([row])  # lint-run-records: ok — run_of requires the handed repository Run; the resolver does not trace its return type
    except Exception:  # noqa: BLE001 — best-effort observability
        pass


def run_of(deps: Any) -> Run:
    """The repository handle bound to a live role; durable operations require it."""
    run = getattr(deps, "run", None)
    if run is None:
        raise RuntimeError("a durable run record operation requires a Run")
    return run
