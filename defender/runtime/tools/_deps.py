
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Self

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    from defender.scripts.gather_tools.record_query import GatherDeadEnd

from defender._clock import now_iso
from defender._paths import PATHS


from defender._io import write_guarded
from .. import box as box_mod
from .. import permission
from ..agent_definition import ResolvedRoots
from ..agent_role import AgentRole

# The SAME byte ruler the artifact bounds are measured with — a write tool that reports
# "bytes" must report the number the gate will judge, not a codepoint count that under-reads it.
from defender._env import env_int
from defender.scripts.gather_tools.payload_view import (
    passthrough_max_bytes as _capture_view_cap,
)
from defender.hooks.record_lesson_load import (
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
    lesson_name as _lesson_name,
)


#: The queries table's infra code — `circuit_breaker.INFRA_EXIT_CODES`' member for a fault
#: that is the environment's, not the caller's. Named so a reader of `_shim_exit_code` sees
#: WHICH taxonomy the number belongs to.
_INFRA_EXIT_CODE = 2

_BASH_TIMEOUT_S = 120

#: The `verb` a bash-lane row carries. Deliberately not a registry verb: it keeps a shim row
#: outside `repeat_trip`'s `(system, verb, params)` key by construction, so an observational
#: row can never be mistaken for a dispatch attempt and trip the guard.
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
    """The cap on reading an AUTHORED file — a SKILL, a lesson, a design doc.

    Deliberately its OWN number, not the 8 KB capture ceiling. The property that matters is
    one-directional: a lead must not `read_file` a persisted payload and recover what the
    capture view withheld. Sharing one constant over-serves it — `defender/SKILL.md` is 33 KB
    and most of `docs/` clears 8 KB — so `_cap_for` applies the capture ceiling only where a
    capture is being re-read."""
    return env_int("DEFENDER_AUTHORED_READ_MAX_CHARS", 65536)


def _cap_for(p: Path) -> int:
    return _capture_view_cap() if permission.is_captured_payload(p) else _read_char_cap()


def _bounded_read(
    # `path` is not read by this body — it is kept for the call sites that pass it
    # positionally, and defaulted so a lane with no file to name (the bash return) does not
    # have to invent one.
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




@dataclass(frozen=True)
class AgentDeps:

    run_dir: Path
    defender_dir: Path
    run_id: str
    policy: permission.AgentPolicy = field(kw_only=True)
    cwd_anchor: Path = field(kw_only=True)
    box: box_mod.BoxExecutor = field(kw_only=True, default_factory=box_mod.BoxExecutor)
    budget_started_monotonic: float = field(kw_only=True, default_factory=time.monotonic)
    authored_paths: set[Path] = field(
        kw_only=True, default_factory=set, compare=False, repr=False
    )
    #: The gate's per-run mutable state (turn count, raised-lead ids, the terminal-close
    #: flag) — ONE mutable container, following the `authored_paths` precedent, since
    #: `AgentDeps` is frozen and cannot carry a plain int counter.
    #: `defender.runtime.challenge_gate.ReviewState.of(deps)` owns what lives inside it.
    review_state: dict = field(
        kw_only=True, default_factory=dict, compare=False, repr=False
    )
    roots: ResolvedRoots | None = field(kw_only=True, default=None)
    tool_config: Any = field(kw_only=True, default=None)

    role: ClassVar[AgentRole] = AgentRole.MAIN

    @classmethod
    def _for_run(
        cls, run_dir: Path, policy: permission.AgentPolicy,
        *, cwd_anchor: Path, defender_dir: Path = PATHS.defender_dir,
        box: box_mod.BoxExecutor | None = None,
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


@dataclass
class QueryDoor:
    """Whether the harness has told this lead's gather model to stop querying, and why.

    ONE MUTABLE OBJECT PER LEAD, shared by the two frames that must agree about it: the query
    tool CLOSES it — on a guard's dead end, or on the last query round the ceiling allows —
    and answers every later call from it; `_run_gather` READS it after the run to stamp the
    session's terminator and put the right notice above the summary. Mutable inside a frozen
    `GatherDeps` for the reason `review_state` is: the deps are copied by `replace`, and
    pydantic-ai's hook signatures give a tool no other way to hand a fact back up.

    `request_limit` is the lead's own ceiling; `None` when the deps were bound outside a
    dispatch, and a door with no ceiling never closes on the budget. `closed_at` is the run's
    request count when the door closed: a call on the SAME count is a sibling in the closing
    round (answered "closed", never executed), a call on a LATER count is the model querying
    after being told to write the summary — #987's one grace turn, forfeited. `dead_end` is
    set when a guard closed the door, and stays `None` for a ceiling close."""

    request_limit: int | None = None
    closed_at: int | None = None
    dead_end: GatherDeadEnd | None = None

    @property
    def closed(self) -> bool:
        return self.closed_at is not None

    def close(self, *, at: int, dead_end: GatherDeadEnd | None = None) -> None:
        """First close wins, with one exception: a dead end outranks a ceiling close from the
        SAME round — two siblings, one spending the last permitted query and one tripping a
        guard — because the guard's sentence names the request being repeated and the
        ceiling's can only say "spent". (The reason `_rejection_guard` asks repeat first.)"""
        if self.closed_at is None:
            self.closed_at, self.dead_end = at, dead_end
        elif dead_end is not None and self.dead_end is None and at == self.closed_at:
            self.dead_end = dead_end

    def is_last_query_round(self, requests: int) -> bool:
        """`requests` is the run's count DURING a round's tool calls (pydantic-ai bumps it when
        the response arrives), so the round whose calls see `request_limit - 1` is the last
        whose results the model can be shown before its final request — the one #987 leaves
        for the summary."""
        return self.request_limit is not None and requests >= self.request_limit - 1


@dataclass(frozen=True)
class GatherDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.GATHER

    lead_id: str | None = None
    door: QueryDoor = field(kw_only=True, default_factory=QueryDoor, compare=False, repr=False)


def _record_lesson_load(
    deps: AgentDeps, path: Path, corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA
) -> None:
    name = _lesson_name(str(path), corpora)
    if name is None:
        return
    try:
        row = {"lesson_name": name, "ts": now_iso()}
        write_guarded(deps.run_dir / "lessons_loaded.jsonl", json.dumps(row) + "\n", mode="append")
    except Exception:  # noqa: BLE001 — best-effort observability
        pass
