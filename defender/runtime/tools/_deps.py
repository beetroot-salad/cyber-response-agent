
from __future__ import annotations

import json
import time
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Self

from pydantic import SkipValidation

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    pass

from defender._clock import now_iso
from defender._paths import PATHS


from defender._io import write_guarded
from defender._run_paths import RunPaths
from .. import box as box_mod
from .. import permission
from ..agent_definition import ResolvedRoots
from ..agent_role import AgentRole

from defender._env import env_int
from defender.scripts.gather_tools.payload_view import (
    passthrough_max_bytes as _capture_view_cap,
)
from defender.hooks.record_lesson_load import (
    LOAD_KINDS as _LOAD_KINDS,
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
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
        reducer = f'{sql_shim} "SELECT count(*) FROM data"'
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
    budget_started_monotonic: float = field(kw_only=True, default_factory=time.monotonic)
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
    #: The run's tenant `settings/` folder, handed to every verb this role dispatches. Set by
    #: the run, never derived from `defender_dir`. `None` for a role that dispatches no verb
    #: (`VerbContext` refuses `None`).
    settings_dir: Path | None = field(kw_only=True, default=None)

    role: ClassVar[AgentRole] = AgentRole.MAIN

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


@model(frozen=True)
class GatherDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.GATHER

    lead_id: str | None = None
    #: Made and read by `_run_gather`. `None` outside a dispatch (e.g. lead zero's harness
    #: calls), where a guard's dead end unwinds as an exception instead.
    stop: LeadStop | None = field(kw_only=True, default=None, compare=False, repr=False)


def _record_lesson_load(
    deps: AgentDeps, path: Path, corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA, *, kind: str,
) -> None:
    """The one writer of `lessons_loaded.jsonl` — a row per lesson that reached an agent.

    @owns kind — `LOAD_KIND_READ` when the model opened the lesson, `LOAD_KIND_PUSH` when the
    runtime pushed it. Keyword-only with no default, so a new call site must choose.
    @owns role — the calling deps' `AgentRole` value, so a row says which agent it reached.

    Older rows carry neither key; `learning/ops/trace_lesson.py` reads them as `unknown`.
    """
    if kind not in _LOAD_KINDS:
        raise ValueError(f"lessons_loaded row kind must be one of {sorted(_LOAD_KINDS)}: {kind!r}")
    name = _lesson_name(str(path), corpora)
    if name is None:
        return
    try:
        row = {"lesson_name": name, "ts": now_iso(), "kind": kind, "role": deps.role.value}
        write_guarded(RunPaths(deps.run_dir).lessons_loaded, json.dumps(row) + "\n", mode="append")
    except Exception:  # noqa: BLE001 — best-effort observability
        pass
