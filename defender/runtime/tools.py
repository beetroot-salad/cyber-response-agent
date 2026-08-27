
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Self

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    from defender.skills.invlang.validate import Diagnostic

from defender._clock import now_iso
from defender._paths import PATHS

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import guarded_mkdir, read_text_utf8, write_guarded
from . import box as box_mod
from . import permission
from .agent_definition import ResolvedRoots, ToolSet
from .agent_role import AgentRole
from .permission.files import RESOLVE_ERRORS

from defender._untrusted import wrap_fresh
# The SAME byte ruler the artifact bounds are measured with — a write tool that reports
# "bytes" must report the number the gate will judge, not a codepoint count that under-reads it.
from defender._artifact_schema import _utf8_len
from defender._env import FatalConfigError, env_int
from defender.scripts.adapters.faults import USAGE_EXIT_CODE
from defender.scripts.gather_tools import sql as defender_sql
from defender.scripts.gather_tools import record_query
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


@dataclass(frozen=True)
class GatherDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.GATHER

    lead_id: str | None = None


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


def _bash_env(deps: AgentDeps) -> dict[str, str]:
    from defender import run_common
    return run_common.run_env(deps.defender_dir, deps.run_dir)


def _shim_exit_code(rc: int) -> int:
    """Translate `defender-sql`'s exit codes into the dialect the queries table speaks.

    Two dialects meet here and they disagree on the number 2. The shim spends
    `EXIT_INPUT_ERROR` (2) on the AGENT's mistakes — an empty pipe, a non-JSON payload, a
    malformed argv — while 2 in this table means INFRA (`circuit_breaker.INFRA_EXIT_CODES`),
    and `collect_general_failures` drops every infra row: untranslated, the commonest reduce
    mistakes are recorded and then silently discarded.

    So an input error becomes `USAGE_EXIT_CODE` ("the caller's request was refused"), a missing
    runtime (`EXIT_NO_RUNTIME`) becomes the table's infra code — a broken deployment is not a
    lesson any `execution.md` should carry — and a query error (1) is already agent-fixable and
    passes through. `payload_digest` still records the raw `exit=N` and its stderr.

    A code the shim does not spend is a THIRD meaning, and it is infra too. The shim's own
    failure vocabulary is exactly {1, 2, 69}; anything else — 137 from a SIGKILL, 127 from a
    missing binary — came from the kernel or the shell, not from the reducer judging its input,
    and `error_class_for_exit` calls every unlisted non-zero code agent-fixable. Untranslated,
    a reduce the box killed reaches the queue as a lesson about SQL the agent should have
    written differently, which it is not.
    """
    if rc == defender_sql.EXIT_INPUT_ERROR:
        return USAGE_EXIT_CODE
    if rc == defender_sql.EXIT_NO_RUNTIME:
        return _INFRA_EXIT_CODE
    if rc in (defender_sql.EXIT_OK, defender_sql.EXIT_QUERY_ERROR):
        return rc
    return _INFRA_EXIT_CODE


def _record_shim_failure(
    deps: AgentDeps, decision: permission.BashDecision, command: str, result: Any,
) -> None:
    """A FAILED reducer shim writes its own queries-table row, so the reduce step gather's
    prompt tells the subagent to run (`cat <payload> | defender-sql …`) leaves a trace the
    pitfalls curator can fold into `skills/{system}/execution.md`.

    FOUR conditions, none incidental:

    * `lead_id` — GATHER ONLY. It lives on `GatherDeps`, not `AgentDeps`, so main's bash lane
      structurally cannot produce one; the record is per-lead and joins on that key, and main's
      bash is investigation authoring, not gathering. Narrowed with `isinstance` rather than
      `getattr(deps, "lead_id", None)`, whose `Any` erases the type of a value that feeds
      `append_query_row(lead_id: str)` and becomes a `gather_raw/{lead_id}/` path component.
    * a non-zero exit — the trigger is a FAILURE, not a shim call. Recording the sanctioned
      happy path would make the pitfalls queue a transcript.
    * a TERMINAL REDUCER stage (`command_shape.terminal_reducer`), not bash in general:
      `_tool_bash` serves `grep`, `cat` and `wc` too, and a failing `wc` teaches nothing. The
      box reports one exit code, the last stage's, so a reducer piped into `head` has its
      failure hidden behind that stage's 0 and a healthy reducer piped into a non-matching
      `grep` is handed its 1. Only when the reducer IS the reported stage can the rc be
      attributed to it, and an unattributable record reaches the curator as a false lesson.
    * best-effort — an observation channel bolted beside the bash lane's real job must not turn
      a working command into a `ModelRetry`.
    """
    if not isinstance(deps, GatherDeps) or deps.lead_id is None or result.rc == 0:
        return
    lead_id: str = deps.lead_id
    if not permission.command_shape.terminal_reducer(list(decision.pipelines or ())):
        return
    stderr = result.err.decode("utf-8", "replace")
    recorded_command = command[:record_query.SHIM_COMMAND_MAX_CHARS]
    try:
        record_query.append_query_row(
            deps.run_dir,
            lead_id=lead_id,
            # The system of the PAYLOAD the reducer read, never one parsed out of the argv:
            # the argv names `defender-sql`, and `system: "sql"` would send the curator at a
            # `skills/sql/execution.md` that must never exist. `""` when the command opened no
            # run payload; the attribution does not decide the row's fate either way —
            # `collect_general_failures` routes it by its sentinel `query_id` onto the reducer
            # surface and normalizes this field to `""` there.
            system=record_query.system_for_payload_operands(
                deps.run_dir, _opened_operands(deps, decision),
            ),
            verb=_BASH_VERB,
            query_id=record_query.BASH_SHIM_QUERY_ID,
            params={"command": recorded_command},
            raw_command=recorded_command,
            # Empty, like every other failed row's sidecar: the file must EXIST or
            # `extract_from_joined` drops the row, but a failure has no evidence to persist and
            # the shim's stdout is attacker-influenced bytes.
            payload_text="",
            exit_code=_shim_exit_code(result.rc),
            payload_status="error",
            payload_digest=f"exit={result.rc}; {stderr.strip()[:160]}",
        )
    # `Exception`, not `OSError`: the write is not the only thing that can raise in here, and
    # catching narrower than the best-effort posture claimed above is how an observation
    # channel starts failing the command it observes.
    except Exception:  # noqa: BLE001 — best-effort observability
        return


def _tool_bash(deps: AgentDeps, command: str) -> str:
    decision = permission.decide_bash(
        command, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        cwd_anchor=deps.cwd_anchor,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    # Walked ONCE and threaded: the operand set decides the authored-read denial, the ceiling
    # and its hint, and the frame, and re-deriving it per question re-ran the argv extractor
    # and the path resolution three extra times per command.
    operands = tuple(_opened_operands(deps, decision))
    _deny_authored_bash_read(deps, operands)
    try:
        result = deps.box.run_parsed(
            list(decision.pipelines or ()),
            command=command,
            cwd=deps.cwd_anchor,
            timeout=_BASH_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as e:
        raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}") from e
    except box_mod.BoxFault as e:
        raise ModelRetry(f"the sandbox could not run this command: {e}") from e
    # Belt-and-braces behind the gate's NUL deny. `encode_request` sits ABOVE `run_parsed`'s own
    # try (box.py) and raises a bare `ValueError` for a frame it cannot encode; nothing between
    # here and `run.py::main` catches that type, so an unencodable argv would take the whole
    # investigation down with a traceback and no disposition. The encoder's exception TYPE is
    # left alone: `test_540_exec_seam.py` pins `pytest.raises(ValueError)` on `run_parsed`.
    #
    # `FatalConfigError` is re-raised AHEAD of it: it subclasses `ValueError` while meaning the
    # opposite of a correctable command fault — a misconfigured run that must stop, not retry.
    # A blanket arm that swallowed it would hand the model "the command cannot cross the box
    # wire" for an operator's bad env var, forever.
    except FatalConfigError:
        raise
    except ValueError as e:
        raise ModelRetry(f"the command cannot cross the box wire: {e}") from e
    _record_shim_failure(deps, decision, command, result)
    capping = min(operands, key=_cap_for, default=None)
    formatted = _format_bash_result(
        result.rc,
        # Bounded BEFORE the frame below, matching the read lane: the head and its notice land
        # inside the delimiters, never a dump whose closing tag was cut off.
        _bounded_bash_stream(
            deps, decision, capping,
            result.out.decode("utf-8", "replace"), subject="This output",
        ),
        # BOTH streams, not just stdout: `defender-sql` writes payload-derived text to stderr
        # (duckdb's parse error quotes the offending JSON; `_shape_hint` names the payload's own
        # columns), so a ceiling that covered only stdout was a ceiling the data could step over.
        _bounded_bash_stream(
            deps, decision, capping,
            result.err.decode("utf-8", "replace"), subject="This error output",
        ),
    )
    if _is_learning_role(deps) or _opens_untrusted_read(operands):
        return wrap_fresh(formatted, "untrusted")
    return formatted


def _grep_lines(text: str, pattern: str) -> str:
    return "\n".join(line for line in text.splitlines() if pattern in line)


def _resolve_operand(deps: AgentDeps, path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else deps.cwd_anchor / p


def _tree_root_for(deps: AgentDeps, p: Path) -> Path:
    """Which shared tree `p` sits in — the anchor `guarded_mkdir` walks down from.

    The write gate has already confined `p` to the run dir or the defender dir (`write ⊆ read
    roots`), so this only has to say WHICH, because the component guard needs to know where the
    box's reach begins. The run dir is tried first: it is the narrower of the two and, in the
    drain lane, sits inside a checkout of the defender dir, so root order keeps the anchor at
    the tighter tree.

    Each root is tried in BOTH its raw and its resolved spelling, because the gate above
    matched on `resolve()`d paths and this check does not: with a symlinked runs base the model
    can legitimately name the already-resolved spelling, `decide_write` resolves both sides and
    allows it, and a raw-spelling-only comparison here would refuse what the gate just
    admitted. `p` itself is never resolved — that would collapse the very component symlink the
    guard exists to refuse — and the spelling RETURNED is whichever prefixes `p`, since
    `guarded_mkdir` needs the anchor to be a lexical prefix of the target.

    Failing to classify means the gate admitted a path not lexically under either root under
    either spelling — a path reached THROUGH a symlink, the hazard the guard exists for.
    `ModelRetry` rather than a bare raise: the operand is model-supplied, so a correctable
    refusal beats an exception that ends the run."""
    for root in (deps.run_dir, deps.defender_dir):
        for spelling in (root, _resolved(root)):
            if p == spelling or spelling in p.parents:
                return spelling
    raise ModelRetry(
        f"{p} is not inside a writable tree; name a path under the run directory or the "
        f"defender directory (a path that only reaches one through a symlink is refused)"
    )


def _guarded_parents(deps: AgentDeps, p: Path) -> None:
    """`guarded_mkdir` at the model-facing altitude: its containment refusal is a `ValueError`,
    and the operand it judges is model-supplied, so it reaches the model as a correctable
    refusal rather than an exception that ends the run — the same posture `_tree_root_for`
    already takes one line above."""
    try:
        guarded_mkdir(p.parent, base=_tree_root_for(deps, p))
    except ValueError as e:
        raise ModelRetry(
            f"{p} does not stay inside the writable tree it names: {e}"
        ) from None


def _is_learning_role(deps: AgentDeps) -> bool:
    return deps.role not in {AgentRole.MAIN, AgentRole.GATHER}


def _resolved(path: Path) -> Path:
    return path.resolve()


def _deny_authored_read(deps: AgentDeps, path: Path) -> None:
    if _is_learning_role(deps) and _resolved(path) in deps.authored_paths:
        raise ModelRetry(
            "cannot read content authored by this learning invocation after its "
            "stage salt was disclosed"
        )


def _opened_operands(deps: AgentDeps, decision: permission.BashDecision) -> Iterator[Path]:
    stages = permission.command_shape.flat_stages(list(decision.pipelines or ()))
    for argv, grant in zip(stages, decision.grants, strict=True):
        opened = permission.PROGRAMS[grant.program](argv)
        for operand in opened or ():
            yield _resolve_operand(deps, operand)


def _opens_untrusted_read(operands: Iterable[Path]) -> bool:
    """Does this command open a file the read tool would have salt-tag wrapped?

    The trust boundary is a property of the DATA, not of who is reading it. Keying the bash
    lane's frame on the ROLE instead excluded main and gather — the two roles that read
    attacker-influenced payloads through it. Gather is the bulk of the exposure: the reduce
    step its prompt tells it to use (`cat <payload> | defender-sql`) is the single channel
    delivering full attacker-chosen field values, and it arrived bare while the same bytes read
    through `read_file` or the `query` tool arrived framed.

    `is_untrusted_read` is the predicate that already decides this for every other read
    surface, so the three routes to the same file agree."""
    return any(permission.is_untrusted_read(p) for p in operands)


#: What the bash lane's overflow notice says when no file operand set the ceiling.
#: `_overflow_filter_hint` reduces a NAMED file (`cat <path> | <reducer>`), and a command that
#: opened none — `ls`, a shim that takes no path — has no name to give it. It does NOT say
#: "there is nothing to re-read a smaller slice of": `defender-invlang` and `defender-lessons`
#: open nothing on the argv and still read files, so the true statement is about the OPERAND.
_BASH_NO_OPERAND_HINT = (
    "Narrow the command itself — a tighter filter or selector — and run it again. This return "
    "is a command's output and names no file operand, so there is no path to re-read a "
    "smaller slice of."
)

#: …and when the command ALREADY reduced. `_overflow_filter_hint`'s answer is the reduce pipe
#: — which is the command that just overflowed, so handing it back is an instruction loop. The
#: loop is reachable: a payload sets the 8 KB capture ceiling for the WHOLE pipeline, including
#: a legitimately larger aggregate the reducer computed from it.
_BASH_REDUCED_HINT = (
    "This return is already a reduction, so re-running the same pipe returns the same "
    "oversized result. Narrow the reduction itself — aggregate further, select fewer columns, "
    "or add a LIMIT — and run it again."
)


def _bash_overflow_hint(
    deps: AgentDeps, decision: permission.BashDecision, capping: Path | None
) -> str:
    """The reduction the caller can run when the bash return overflowed its ceiling.

    Three cases. No operand: nothing to re-read. A TERMINAL reducer: the reduce pipe IS the
    command, so the generic hint would name it back. Otherwise the file the ceiling came from,
    through the read lane's hint — whose `read_tool` stays at its DEFAULT on purpose: that
    argument names the tool whose substring search the no-reducer branch falls back to
    (`read_file(p, pattern=…)`), not the tool that overflowed, and `read_tool="bash"` there
    spells a `bash(p, pattern=…)` call no agent has."""
    if capping is None:
        return _BASH_NO_OPERAND_HINT
    if permission.command_shape.terminal_reducer(list(decision.pipelines or ())):
        return _BASH_REDUCED_HINT
    return _overflow_filter_hint(str(capping), deps.policy)


def _bounded_bash_stream(
    deps: AgentDeps, decision: permission.BashDecision, capping: Path | None,
    text: str, *, subject: str,
) -> str:
    """One bash output stream, held to the ceiling its DATA chose.

    `read_file` bounds a captured payload at the capture ceiling precisely so a later read
    cannot recover what the capture view withheld; the same file read through `cat` must share
    that bound, or it is a `read_file`-LANE property and the uncapped lane is the one gather's
    own prompt tells it to use.

    `capping` is the operand with the SMALLEST cap: a pipeline may open several files, and a
    ceiling any one operand can raise is not a ceiling. A command that opens no file still gets
    the authored cap. The hint is built only when the stream actually overflows, because
    building it probes the policy (`_overflow_filter_hint` → `_lane_admits` → a full
    `decide_bash`) and the overwhelming majority of returns fit."""
    cap = _read_char_cap() if capping is None else _cap_for(capping)
    if len(text) <= cap:
        return text
    return _bounded_read(
        text, cap=cap, filter_hint=_bash_overflow_hint(deps, decision, capping),
        read_tool="bash", subject=subject,
    )


def _deny_authored_bash_read(deps: AgentDeps, operands: Iterable[Path]) -> None:
    if not _is_learning_role(deps):
        return
    for operand in operands:
        _deny_authored_read(deps, operand)


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_cross_agent_read(deps: AgentDeps, path: Path) -> bool:
    """Whether a learning stage is reading text some OTHER agent produced — the predicate that
    decides the salt frame for reads `is_untrusted_read` does not already claim.

    The agent's own run dir is in the root set: for a runtime agent it is its own workspace,
    but for a learning stage it is the SHARED cross-stage directory (the host's
    `past_tickets.txt`, the sibling leg's `actor_*_story.md`, the judge's
    `ticket_reads/{seq}.json`) — all produced by someone else. MAIN and GATHER are unaffected:
    `_bound_and_wrap` consults this only under `_is_learning_role`."""
    resolved = _resolved(path)
    roots = (deps.run_dir, *deps.policy.read_roots, *deps.policy.read_confine)
    corpus_dir = getattr(deps, "corpus_dir", None)
    if corpus_dir is not None:
        roots = (*roots, Path(corpus_dir))
    if any(_under(resolved, _resolved(root)) for root in roots):
        return True
    role_name = str(getattr(deps.role, "value", "")).replace("_", "-")
    return bool(role_name) and resolved.name == f"{role_name}.md"


def _probe_is_file(p: Path, path: str) -> bool:
    """`p.is_file()` over a MODEL-AUTHORED path, as a refusal rather than a traceback.

    `pathlib` swallows only `_IGNORED_ERRNOS` — ENOENT/ENOTDIR/EBADF/ELOOP — and every other
    `os.stat` error comes back out. The reachable one is ENAMETOOLONG: the read gate ALLOWS a
    basename over `NAME_MAX`, because MAIN's and GATHER's run-root read shape is
    `under(run, SEG)` with `SEG = [\\w.@=+-]+`, which places no length bound, and
    `Path.resolve()` does not stat. So an allowed path reaches the probe and raises — outside
    every `try`, past `on_tool_execute_error`, past `_drive_agent`'s handlers and out of
    `asyncio.run` — ending the run with no disposition and no `report.md`.

    Bounding `SEG` is deliberately NOT the fix: the probe has to survive an allowed path
    whatever its shape."""
    try:
        return p.is_file()
    except OSError as e:
        raise ModelRetry(f"could not read {path}: {e}") from None


def _probe_read_text(p: Path, path: str) -> str:
    """`read_text_utf8(p)` over a MODEL-AUTHORED path, as a refusal rather than a traceback.

    The other half of `_probe_is_file`, and ONE copy: `_gated_read` and `_tool_edit_file` both
    read the same operand under the same two fault classes (undecodable, unreadable) and owe
    the model the same two refusals."""
    try:
        return read_text_utf8(p)
    except UnicodeDecodeError:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)") from None
    except OSError as e:
        raise ModelRetry(f"could not read {path}: {e}") from None


def _gated_read(
    deps: AgentDeps, path: str, *, lesson_corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA
) -> tuple[Path, str]:
    p = _resolve_operand(deps, path)
    decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    if not _probe_is_file(p, path):
        raise ModelRetry(f"file not found: {path}")
    _deny_authored_read(deps, p)
    text = _probe_read_text(p, path)
    _record_lesson_load(deps, p, lesson_corpora)
    return p, text


def _bound_and_wrap(
    deps: AgentDeps, p: Path, path: str, text: str, *, read_tool: str
) -> str:
    text = _bounded_read(
        text, path, cap=_cap_for(p),
        filter_hint=_overflow_filter_hint(path, deps.policy, read_tool),
        read_tool=read_tool,
    )
    if permission.is_untrusted_read(p) or (
        _is_learning_role(deps) and _is_cross_agent_read(deps, p)
    ):
        return wrap_fresh(text, "untrusted")
    return text


def _tail_chars(text: str, n: int) -> str:
    """The last `n` characters, trimmed FORWARD to the next line start so a `|`-delimited
    invlang row never arrives cut in half and reads as truncated data. `n` is a ceiling, not a
    target. `n <= 0` yields nothing; a file shorter than `n` is returned whole; text with no
    newline in the window is cut at `n`.

    Its own fold rather than a reuse of `_bounded_read`, whose overflow path keeps the HEAD —
    the wrong end of an append-only log."""
    if n <= 0:
        return ""
    if len(text) <= n:
        return text
    cut = len(text) - n  # >= 1, since the whole-file case returned above
    nl = text.find("\n", cut - 1)
    return text[nl + 1:] if nl != -1 else text[cut:]


def _tool_read_file(
    deps: AgentDeps, path: str, pattern: str | None = None, tail: int | None = None
) -> str:
    p, text = _gated_read(deps, path)
    if pattern is not None:
        text = _grep_lines(text, pattern)
    if tail is not None:
        text = _tail_chars(text, tail)
    return _bound_and_wrap(deps, p, path, text, read_tool="read_file")


def _closed_for_investigation_write(deps: AgentDeps, p: Path) -> bool:
    """RS15. `investigation.md` becomes review-state-aware AFTER a close commits, so no
    post-close write can silently move the recorded disposition. Up to the close the document
    stays model-writable; this is the ONE gate on it.

    The `resolve()` here runs one line AHEAD of `decide_write`/`decide_read`, so an operand it
    cannot resolve (an embedded NUL — `ValueError`; a symlink cycle — `RuntimeError`) would
    escape the write/edit tool as an unhandled exception, routing around the fail-closed
    `Decision(False)` the gate's `RESOLVE_ERRORS` rule produces. An unresolvable operand is
    certainly not `<run_dir>/investigation.md`, so answering False is honest — and it hands the
    operand to the gate, which denies it with a correctable reason."""
    try:
        if p.resolve() != (deps.run_dir / "investigation.md").resolve():
            return False
    except RESOLVE_ERRORS:
        return False
    from .challenge_gate import ReviewState

    return ReviewState.of(deps).closed


def _tool_write_file(deps: AgentDeps, path: str, content: str) -> str:
    p = _resolve_operand(deps, path)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further write could silently "
            "move it. The case is closed."
        )
    decision = permission.decide_write(
        p, content, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, content)
    deps.authored_paths.add(_resolved(p))
    return f"wrote {path} ({len(content)} bytes)"


def _tool_edit_file(deps: AgentDeps, path: str, old_string: str, new_string: str) -> str:
    p = _resolve_operand(deps, path)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further edit could silently "
            "move it. The case is closed."
        )
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    # ONE probe, not one here and another in the empty-`old_string` check below: they ask the
    # same question about the same path, and a second stat could answer it differently.
    exists = _probe_is_file(p, path)
    current = _probe_read_text(p, path) if exists else ""
    if not old_string and exists:
        raise ModelRetry(
            f"{path} already exists; an empty old_string would overwrite it. "
            "Pass a unique old_string to edit, or use write_file to replace it."
        )
    if old_string and old_string not in current:
        raise ModelRetry(f"old_string not found in {path}")
    if old_string and current.count(old_string) > 1:
        raise ModelRetry(
            f"old_string is not unique in {path} ({current.count(old_string)} "
            "occurrences); include enough surrounding context to match exactly "
            "one, or use write_file to replace the whole file."
        )
    new_text = current.replace(old_string, new_string, 1) if old_string else new_string
    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, new_text)
    deps.authored_paths.add(_resolved(p))
    return f"edited {path} ({len(new_text)} bytes)"


# --------------------------------------------------------------------------------------
# The repair window. A warn-family `:R attr_updates` row LANDS instead of costing a whole
# re-emitted block, and then gates the next write until it is repaired.
#
# The window is DERIVED, never stored: `warn_diagnostics` over whatever `investigation.md`
# holds right now IS the state. Nothing caches it and no `AgentDeps` field carries it, so it
# cannot go stale or disagree with the file.
# --------------------------------------------------------------------------------------

def _investigation_path(deps: AgentDeps) -> Path:
    return deps.run_dir / "investigation.md"


def flagged_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """The run's currently-open repair window, re-derived from disk on every call.

    FAILS OPEN on all three paths that read it (`prepare=`, the write gate, the close gate).
    An unreadable or undecodable `investigation.md` is an unrelated fault; converting it into
    "every write and the close are refused" would manufacture the unclosable run this mechanism
    exists to avoid. `append_block` still refuses an undecodable document for its own reason.

    A warn diagnostic carrying NO `locus` is not in the window: the window is the set of rows
    `fix_row` can address, so counting a locus-less finding would refuse the append AND the
    close with no row the repair verb could ever clear. No family emits one today; this keeps
    that from being load-bearing."""
    from defender.skills.invlang.validate import warn_diagnostics

    p = _investigation_path(deps)
    # ABSENCE is the ordinary "no window open" case, not a fault: `prepare=` runs on EVERY
    # model request, including turn 1 before any write verb has created the file.
    if not p.is_file():
        return ()
    try:
        return _addressable(warn_diagnostics(read_text_utf8(p)))
    except Exception as e:  # noqa: BLE001 — fail open; a wedged run is the worse failure
        print(
            f"[tools] repair-window derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return ()


def committed_document_refusal(deps: AgentDeps) -> str | None:
    """The close's structural verdict on `investigation.md` as it stands — the refusal text,
    or `None` when the document is publishable. #961.

    Lives beside `flagged_diagnostics` and not in the close because the two are ONE reading of
    one document, taken at the same moment, and they have to agree about what "cannot look"
    means. Splitting them put that agreement in two files the first time and it did not
    survive the trip.

    THE READ IS STRICT, and that is the whole subtlety. Two conditions look alike from the
    close and are not:

      * the document DECODES and does not validate — the author wrote something malformed,
        the close is what publishes it, and it is refused (#961);
      * the document's BYTES do not decode — nothing can be derived from it at all. That is
        H7's condition, and #836 settled it: fail OPEN, because converting an unrelated read
        fault into an unclosable run is the wedge class that mechanism exists to remove.

    Reading leniently (`errors="replace"`) collapses the two and answers the second with the
    first: the replacement character lands mid-header, the validator reports a broken block
    the author never wrote, and the run can no longer close. So the strict read is what keeps
    this gate's `None` meaning "publishable" rather than "unreadable", and the fail-open arm
    below is what keeps H7 true. A document that never decodes is still gated on the way IN —
    `append_block` refuses it for its own pre-existing reason — so nothing gated can create
    one.

    ABSENCE is not a fault: a close on a run with no companion is the entry-price gate's
    question, not this one's, and it asks it separately."""
    from defender._artifact_schema import committed_investigation_reason

    p = _investigation_path(deps)
    if not p.is_file():
        return None
    try:
        text = read_text_utf8(p)
    except Exception as e:  # noqa: BLE001 — fail open (H7); a wedged run is the worse failure
        print(
            f"[tools] investigation.md could not be read for the close's structure check, "
            f"treating it as publishable: {e!r}",
            file=sys.stderr,
        )
        return None
    return committed_investigation_reason(text)


def repairable_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """Every row `fix_row` may address — the REPAIR set, which is wider than the repair WINDOW.

    `flagged_diagnostics` above is the warn-severity window: the rows whose presence BLOCKS an
    append and a close. This is the set the repair verb is allowed to touch, and the two are
    not the same question. An ERROR-severity row blocks just as hard — `append_block` validates
    the whole document, so a committed error refuses every later write — but it was not in the
    window, so `fix_row` refused it and was not even offered. That left a document carrying one
    with NO legal move: the close refuses and names `fix_row`, `fix_row` says nothing is
    flagged, `append_block` refuses the same bytes, and append-only puts them out of reach. The
    model then spends its whole retry budget before the framework force-closes `inconclusive`,
    discarding the disposition the run actually reached.

    Reachable because a document valid when written can stop being valid later: a rule that
    ships after a run's bytes landed (#962 is exactly one) judges what is already committed.

    Widening the REPAIR set cannot widen what the model may write. `fix_row` still faces
    `decide_write` on the resulting document, so a repair that does not actually fix the row is
    refused like any other write.

    A diagnostic naming NO ROW stays out — no locus, and equally an EMPTY `row_text`. The
    empty case is not hypothetical: the repeated-lead-id family reports at block scope
    (`_warn(block, -1, "")`), so it carries a locus whose row is the empty string, and `fix_row`
    reads an empty `old_row` as DELETE. Admitting it would offer the model a repair that names
    nothing and deletes on sight, and it would quietly reverse #954's decision that a document
    holding that repeat is refused at every write verb with no legacy exemption. The rule is
    the one `flagged_diagnostics` already states for a locus-less finding: the set is the rows
    `fix_row` can ADDRESS, and a row nobody can quote back is not one.

    FAILS OPEN like its sibling, for the same reason and via the same reader — a wedged run is
    the worse failure."""
    from defender.skills.invlang.validate import diagnose

    p = _investigation_path(deps)
    if not p.is_file():
        return ()
    try:
        return tuple(
            d for d in _addressable(diagnose(read_text_utf8(p)))
            if d.locus is not None and d.locus.row_text
        )
    except Exception as e:  # noqa: BLE001 — fail open; a wedged run is the worse failure
        print(
            f"[tools] repair-set derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return ()


def _addressable(diags: Iterable[Diagnostic]) -> tuple[Diagnostic, ...]:
    return tuple(d for d in diags if d.locus is not None)


def _flagged_rows(diags: tuple[Diagnostic, ...]) -> tuple[str, ...]:
    return tuple(d.locus.row_text for d in diags if d.locus is not None)


def flagged_write_refusal(
    verb: str, diags: tuple[Diagnostic, ...], *, offered_text: bool = True
) -> str:
    """The gate's refusal, naming EVERY currently-flagged row and its `use:` alternatives.

    It carries the whole set rather than the most recent row because after a frontier fold the
    model holds only a truncated PREFIX of the document (`driver._fold_decision`), so a flagged
    row below the cut is absent from its view and this refusal is the recovery channel.

    `offered_text=False` for the CLOSE, which proposed no `investigation.md` bytes of its own:
    the full notice's "does not contain your text" would be a claim about nothing. Both
    spellings LEAD with the same fragment, so the model still tells a refusal from an accept by
    the first sentence."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE, render_diagnostic

    # The close's opening states what the CLOSE did not do — no disposition recorded — never
    # "nothing was committed for this run", which flatly contradicts the next sentence ("the
    # row LANDED and is committed") and reads as "your whole investigation was discarded".
    opening = (
        UNCHANGED_NOTICE if offered_text
        else f"{UNCHANGED_LEAD} — no disposition was recorded for this run."
    )
    return (
        f"{opening} `{verb}` is blocked while investigation.md carries a flagged "
        f"row. The row LANDED and is committed, so re-sending the block cannot help; repair "
        f"it in place with `fix_row(old_row, new_row)`, or delete it with "
        f'`fix_row(old_row, "")`.\n\n'
        + "\n".join(render_diagnostic(d) for d in diags)
        + "\n\nRepair every row above, then retry."
    )


def _warning_return(lead: str, diags: tuple[Diagnostic, ...]) -> str:
    """An ACCEPT that carries a warning. It LEADS with the bytes and says the block landed, and
    never carries the unchanged-notice wording: a model that reads "warning" as "refusal"
    re-emits the whole block, which is the cost the repair window exists to remove."""
    from defender._artifact_schema import render_diagnostic

    if not diags:
        return lead
    return (
        lead
        + "\n\nBut one or more rows are FLAGGED and now block the next write:\n\n"
        + "\n".join(render_diagnostic(d) for d in diags)
        + "\n\nRepair each flagged row with `fix_row(old_row, new_row)` — or delete it with "
        '`fix_row(old_row, "")` — before the next append_block or close_investigation.'
    )


def _tool_append_block(deps: AgentDeps, text: str) -> str:
    """Append to `investigation.md` — main's only write.

    No path: the run has one model-authored transcript and this is its writer, the way
    `close_investigation` is `report.md`'s. No anchor and no position either: the document is
    validator-enforced append-only (`_check_append_only` refuses a dropped fence, a dropped
    record, or an in-place mutation), so the anchored replace `edit_file` offers is a capability
    the artifact never had.

    Faces the identical gate the other two verbs do — same `decide_write`, same content schema,
    same RS15 post-close refusal — on the resulting full document."""
    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further append could silently "
            "move it. The case is closed."
        )
    # The gate is FORCED, not chosen: `_check_closed_vocab` walks the FULL proposed document,
    # so a landed warn row re-fires on every subsequent append anyway. Without the gate the
    # choices are grandfathering — which dead-letters the run at persist — or a wedged document.
    flagged = flagged_diagnostics(deps)
    if flagged:
        raise ModelRetry(flagged_write_refusal("append_block", flagged))
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    try:
        current = read_text_utf8(p) if p.is_file() else ""
    except UnicodeDecodeError:
        raise ModelRetry(
            "investigation.md is not valid UTF-8 text (binary or corrupt)"
        ) from None
    # Separate with a newline only when the document does not already end in one. Existing
    # bytes are never rewritten — not even trailing whitespace — so an append cannot itself
    # trip the append-only check it is about to face. An EMPTY append gets no separator: the
    # separator alone would be a byte the model never sent, on a call reporting zero bytes.
    sep = "\n" if current and text and not current.endswith("\n") else ""
    new_text = current + sep + text
    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, new_text)
    deps.authored_paths.add(_resolved(p))
    # UTF-8 BYTES, not characters: the SKILL tells the model this return IS a byte count, and
    # the 65536-byte cap it must stay under is measured the same way. invlang rows carry
    # `⟂ → ⟺` freely, so `len(str)` under-reports against the bound the gate applies.
    lead = (
        f"appended {_utf8_len(text)} bytes to investigation.md "
        f"({_utf8_len(new_text)} total)"
    )
    # The gate ACCEPTED a warn-only document and returned no text to reuse, so the warning can
    # only come from a SECOND derivation here, over the bytes just written. Deriving in memory
    # keeps it deterministic without a re-read.
    warn = _warn_over(new_text)
    recall = _frontier_recall(deps, current, new_text)
    if warn:
        # INSIDE the warning return, not stapled after it. `_warning_return` ends with the
        # `fix_row` instruction, and on this path that is the only legal next call — the next
        # `append_block` is hard-refused by `flagged_diagnostics`. Appending the lessons block
        # after it would put ~30 lines of precedent between the model and the one action it
        # can take.
        return _warning_return(f"{lead} — the block LANDED.{recall}", warn)
    return lead + recall


def _frontier_recall(deps: AgentDeps, before: str, after: str) -> str:
    """Lessons for what this append left OPEN — appended to the return, or "" (#919).

    Keyed on the invlang FRONTIER (`skills/invlang/frontier.py`), not on the alert
    signature. A lesson about what a field licenses is relevant once the field is in hand,
    which is a fact about the document at loop N, not about which rule fired at loop 0 —
    `runtime/orient.py` keys the cold-start block on the signature because at that point no
    document exists yet, and that is the only place the signature is the best available key.

    ON CHANGE, not on every write. The pre- and post-append documents are both already in
    hand here, so the diff costs nothing and needs no state to remember what was said last:
    the model gets a lessons block exactly when its own append moved the frontier, instead
    of the same three lines re-stapled to every write until it stops reading them.

    DERIVED, NEVER STORED, like the repair window above — nothing caches this, so it cannot
    go stale or disagree with the file.

    NOT gated by `permission.decide_read`, deliberately. The gate governs what the MODEL may
    read; this is the runtime composing text to hand it, the same way `runtime/orient.py`
    assembles the cold-start lessons block without one. The corpus is a fixed internal path
    under `defender_dir`, never an operand the model supplies, so there is no path here for
    it to steer — and the model receives rendered text, not a read capability it can reuse.

    FAILS OPEN, and that is not optional: every caller reaches here AFTER the bytes have
    landed, so an exception raised for a missing corpus or an unreadable frontier would
    surface to the model as a failed tool call on a write that actually succeeded — the
    exact lie `_warn_over` fails open to avoid.
    """
    try:
        from defender._corpus import iter_lessons
        from defender.scripts.lessons.lessons_frontier import (
            match_loaded,
            render,
        )
        from defender.skills.invlang.frontier import frontier_from_text

        corpus = deps.defender_dir / "lessons"
        if not corpus.is_dir():
            # LOUD, on the same terms `frontier_from_text` states: a corpus that is not there
            # produces the same silence as a corpus that matched nothing, and SKILL.md tells
            # the model to read that silence as "nothing NEW matched". A mis-resolved
            # `defender_dir` would otherwise disable the lane for the whole run with no
            # exception, no test red, and no operator signal.
            print(f"[tools] no lessons corpus at {corpus}; omitting recall", file=sys.stderr)
            return ""
        # THE FRONTIER is the cheap gate, and it is also the one SKILL.md states ("appears
        # only when your append *changed* what is open"). `Frontier` is a frozen dataclass of
        # tuples of frozen dataclasses, so `==` is exact, and `match_lessons`/`render` are
        # pure functions of `(frontier, corpus)` — an unchanged frontier cannot change the
        # block. Checking it first skips the corpus walk, which is the dominant cost here:
        # `iter_lessons` re-reads and re-YAML-parses every lesson file on every call. It skips
        # it on a MINORITY of appends, though, not "most" — `held` accumulates, so any append
        # declaring a `:V` row moves the frontier. Replaying the repo's own investigations
        # fence-by-fence, it fires on roughly half.
        #
        # The fence test below is the gate that actually is cheap, and it is exact:
        # `parse_dense_companion` reads ONLY ```invlang fences and ignores every other
        # byte, so an append that adds no fence delimiter cannot add, close, or alter one —
        # the parse, and therefore the frontier, is identical. Prose narration between blocks
        # is an ordinary shape on this loop and an empty `text` is an explicitly supported
        # one; both would otherwise pay two full parses of a document
        # growing toward the 65536-byte cap to discover they changed nothing. Guarded on
        # `after` EXTENDING `before` so it can only fire for `append_block` — `fix_row` rewrites
        # in place and is never a prefix extension.
        #
        # The window reaches TWO BYTES BACK into `before`, so a delimiter that straddled the
        # seam — an on-disk document ending in a truncated ``` and an append supplying the last
        # backtick — could not close a fence behind a gate that said it could not.
        #
        # BELT AND BRACES, not a live case: `_tool_append_block` inserts `sep = "\n"` whenever
        # `current` does not already end in a newline, so today no ``` can span the join at
        # all. The two bytes cost nothing and are what keeps this gate correct if that
        # separator rule is ever relaxed; do not read them as evidence the straddle happens.
        if before and after.startswith(before) and "```" not in after[max(0, len(before) - 2):]:
            return ""
        now_frontier = frontier_from_text(after)
        was_frontier = frontier_from_text(before)
        if now_frontier == was_frontier:
            return ""
        if now_frontier.is_empty():
            return ""
        # ONE walk for the two frontiers below. `iter_lessons` re-opens and re-YAML-parses
        # every file in the corpus per call, and it is the dominant cost here — the two scores
        # are pure functions of the same bytes, which cannot change between them.
        lessons = list(iter_lessons(corpus))
        hits = match_loaded(now_frontier, lessons)
        # The second gate is what keeps a MOVE that changed no lesson quiet — the frontier can
        # open a slot no selector speaks to, and re-stapling the same three lines then teaches
        # the model to stop reading them.
        #
        # Compared on `(path, score)` — WHICH lessons and in what order — rather than on the
        # rendered text, which would cost a `yaml.safe_dump` of three lessons' frontmatter plus
        # three `Path.resolve()` realpath syscalls built and thrown away one expression later,
        # on every frontier-moving write.
        #
        # NOT on `matched`, which is the trap: it names whichever frontier item won
        # `_best_match`'s `max`, and `max` returns the FIRST maximal element — so declaring a
        # second, equally-scoring vertex flips the winner and re-emits a block whose lesson set,
        # ranking and frontmatter are byte-identical. Executed against
        # `learning/runs/fresh-01/investigation.md`, fences 3 and 7 differ in exactly one line
        # (`matched v-003 compute class=ip-only/??/??` -> `matched v-004 compute
        # class=ip-only/??/known-corp`) and re-staple ~1.5KB of precedent the model already
        # holds — the churn this gate exists to prevent. `matched` still RENDERS, because it is
        # the model's only account of why a lesson was pushed; it just does not decide.
        shape = [(h.path, h.score) for h in hits]
        if not shape or shape == [
            (h.path, h.score) for h in match_loaded(was_frontier, lessons)
        ]:
            return ""
        now = render(hits)
        # RECORDED, on the same terms a Read is. `lessons_loaded.jsonl` is the loop's only
        # "was this lesson in context" signal and the post-merge control `learning/ops/
        # trace_lesson.py` reasons from — and this block puts a lesson's description and
        # dimensions in front of MAIN with enough to act on, since SKILL.md tells it to judge
        # relevance from `description` and NOT to open the file to decide. A push that left no
        # row would make a merged lesson look inert to the human reviewing its impact.
        for hit in hits:
            # RESOLVED, the same spelling `render` hands the model and the same one
            # `_gated_read` records (it passes the post-`_resolve_operand` path).
            # `record_lesson_load.lesson_name` gates on `p.parent.parent.name == "defender"`,
            # so an unresolved `defender_dir` carrying a symlink or a `..` shows the block and
            # writes no row — the lesson then reads as never-in-context to `trace_lesson`.
            _record_lesson_load(deps, hit.path.resolve())
        return "\n\n" + now
    except Exception as e:  # noqa: BLE001 — fail open; the write already landed
        print(f"[tools] frontier recall failed, omitting it: {e!r}", file=sys.stderr)
        return ""


def _warn_over(text: str) -> tuple[Diagnostic, ...]:
    """The window over text held in memory. FAILS OPEN for the same reason
    `flagged_diagnostics` does, and for one more: both call sites derive AFTER the bytes have
    landed, so a validator error raised here would surface as a failed tool call on a write
    that succeeded."""
    from defender.skills.invlang.validate import warn_diagnostics

    try:
        return _addressable(warn_diagnostics(text))
    except Exception as e:  # noqa: BLE001 — fail open; the write already landed
        print(
            f"[tools] repair-window derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return ()


#: EVERY separator `str.splitlines()` honours, which is what `_tokenize_fence` splits a fence
#: body on — so it decides where a ROW ends, and therefore what `Locus.row_text` holds.
#: `split("\n")` alone left a row sitting after a `\v` `\f` `\x1c` `\x1d` `\x1e` `\x85`
#: `\u2028` or `\u2029` FLAGGED but UNADDRESSABLE: `old_row` matched no whole line, so the
#: repair refused while `append_block` and the close both refused for that same flagged row —
#: a permanently wedged run, reachable from one `append_block` carrying one of those bytes.
#: `\r\n` / `\r` never reach here: `read_text_utf8` translates them on read.
#: Spelled as ESCAPES, never literal codepoints: two of them are invisible line breaks and
#: would split THIS file for anything that reads it the way the tokenizer reads a fence.
#: Captured, not consumed, so every untouched line keeps the separator the model wrote.
_LINE_SEP_RE = re.compile("([\n\v\f\x1c\x1d\x1e\x85\u2028\u2029])")


def _split_lines(text: str) -> tuple[list[str], list[str]]:
    """`text` as the tokenizer sees it: its lines, and the separator that FOLLOWED each one
    (`""` for the last). `lines[i] + seps[i]` reassembles the document byte for byte."""
    parts = _LINE_SEP_RE.split(text)
    return parts[0::2], parts[1::2] + [""]


def _attr_block_columns(text: str, row: str) -> int | None:
    """How many cells the block carrying `row` declares. `None` when no `:R attr_updates`
    block holds it — which cannot happen for a flagged row, since that is the only block the
    warn family walks."""
    from defender.skills.invlang.parser import iter_blocks

    for block in iter_blocks(text):
        if block.name == "attr_updates" and block.columns and row in block.rows:
            return len(block.columns)
    return None


def _new_row_shape_reason(new_row: str, cells: int | None) -> str | None:
    """`new_row` is ONE row of the SAME block, or it is refused.

    `fix_row` is the only verb that rewrites a line INSIDE an already-open fence, and every
    other guard on it is on `old_row` — so without this, `new_row` is the whole write surface.
    Not belt-and-braces: `_check_append_only` never inspects `:R` rows, so a `:V` declaration
    substituted for a flagged row draws ZERO diagnostics; an embedded newline forges a
    well-formed second row; a fence delimiter makes the injected row vanish by closing the
    block early; and one cell too FEW is silently padded. Only "too many cells" is caught
    anywhere else, and by the parser rather than a guard. This is what makes "no verb mutates
    or removes a committed :V/:E record" true by construction."""
    from defender.skills.invlang._cells import _split_cells
    from defender.skills.invlang.parser import HEADER_RE

    # EVERY line break `str.splitlines()` honours, not just `\n`: a `new_row` carrying a \v \f
    # \x1c \x1d \x1e or \x85 is a SECOND row (or a whole second block) to the parser while
    # looking like one line to a `"\n" in ...` check, and its pipe count is unchanged so the
    # cell-count arm never fires either.
    lines = new_row.splitlines()
    if len(lines) != 1 or lines[0] != new_row:
        return "it spans more than one line"
    if "```" in new_row:
        return "it carries a fence delimiter (```), which would close the block early"
    if HEADER_RE.match(new_row.strip()):
        return "it is a block header, not a row"
    # `cells is None` means the declaring block could not be located. Only the CELL-COUNT arm
    # needs it, so an unlocatable block narrows the guard by one check instead of switching
    # the whole write surface off.
    if cells is None:
        return None
    got = len(_split_cells(new_row))
    if got != cells:
        return f"it has {got} cells but the block declares {cells}"
    return None


def _tool_fix_row(deps: AgentDeps, old_row: str, new_row: str) -> str:
    """Repair ONE flagged row of `investigation.md` in place.

    No path and no free-form anchor: `old_row` must be one of the rows the repair window is
    currently open on, which puts every committed `:V`/`:E` record out of reach (the warn
    family walks `:R attr_updates` blocks and nothing else). An empty `new_row` DELETES the
    line — the always-available escape that keeps the window closable, and the only move left
    when the document is at its size bound.

    The window is re-derived here at call time. Being OFFERED the verb is never evidence the
    window is still open: `prepare=` filters per-request offers and is ergonomics, so the body
    is the guard. The resulting full document faces the same `decide_write` chain every other
    write on this artifact faces."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE

    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            f"{UNCHANGED_LEAD} — investigation.md is no longer writable: the close already "
            "committed a recorded disposition for this run, and a further repair could "
            "silently move it. The case is closed."
        )
    # The REPAIR set, not the warn window: an error-severity row blocks every write just as
    # hard and used to be unreachable by the one verb that could clear it. See
    # `repairable_diagnostics`.
    diags = repairable_diagnostics(deps)
    flagged = _flagged_rows(diags)
    if not flagged:
        # Deliberately the SAME refusal a never-flagged `old_row` earns once the window has
        # emptied: a repeated identical repair is idempotent-safe by construction, and a
        # "you already did this" branch would need stored state this design avoids.
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} Nothing is currently flagged in investigation.md, so there "
            f"is no row to repair."
        )
    if old_row not in flagged:
        # Scope, not merely match: `old_row` is confined to the flagged set, and the flagged
        # set is `:R attr_updates`-only. A verb that refused only when the text was ABSENT
        # would happily rewrite a committed vertex row that is present.
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} `old_row` must be one of the rows currently flagged in "
            f"investigation.md, quoted exactly as the warning printed it."
            "\n\nCurrently flagged:\n"
            + "\n".join(f"  {row}" for row in flagged)
        )

    current = read_text_utf8(p)
    lines, seps = _split_lines(current)
    whole = [i for i, line in enumerate(lines) if line.strip() == old_row]
    if not whole:
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} `old_row` matches no line in investigation.md."
        )
    # The repair applies to EVERY flagged occurrence — a flagged row whose text is not unique
    # would otherwise be neither repairable nor deletable, and with the write gate the run
    # would be unclosable. The rider keeps that safe: if the text also stands as a WHOLE LINE
    # the window did not flag, the repair refuses rather than rewriting that too.
    #
    # WHOLE-LINE, not substring. The rebuild below only touches lines where
    # `line.strip() == old_row`, so a line that merely CONTAINS the row is already out of reach
    # and a substring count guards nothing — while refusing on one wedges the window shut (a
    # `:T conclude` summary quoting its own flagged row makes both `fix_row(row, new)` and
    # `fix_row(row, "")` refuse) and fires falsely when one flagged row's text is a PREFIX of
    # another (`…|owner|svc` inside `…|owner|svc2`).
    occurrences = flagged.count(old_row)
    if len(whole) != occurrences:
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} That row's text also stands as a whole line the repair "
            f"window did not flag ({len(whole)} line(s) match, {occurrences} flagged), and "
            f"`fix_row` will not rewrite a line it never flagged."
        )

    if new_row:
        cells = _attr_block_columns(current, old_row)
        reason = _new_row_shape_reason(new_row, cells) if cells is not None else None
        if reason is not None:
            raise ModelRetry(
                f"{UNCHANGED_NOTICE} `new_row` must be a single row of the same "
                f":R attr_updates block: {reason}. Send one row with the same columns, or "
                'an empty `new_row` to delete the line instead.'
            )

    # The whole on-disk LINE is what gets rewritten — leading/trailing whitespace included —
    # because `old_row` is matched against the STRIPPED row text the warning printed, and a
    # padded line would otherwise survive its own repair.
    hit = set(whole)
    if new_row:
        rebuilt = [
            (new_row if i in hit else line) + sep
            for i, (line, sep) in enumerate(zip(lines, seps, strict=True))
        ]
    else:
        rebuilt = [
            line + sep
            for i, (line, sep) in enumerate(zip(lines, seps, strict=True))
            if i not in hit
        ]
    new_text = "".join(rebuilt)

    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, new_text)
    deps.authored_paths.add(_resolved(p))
    verb = "deleted" if not new_row else "repaired"
    lead = (
        f"{verb} {len(whole)} flagged row(s) in investigation.md "
        f"({_utf8_len(new_text)} bytes total) — the change LANDED."
    )
    # `fix_row` is a first-class FRONTIER MUTATOR, not a cosmetic repair: the window is
    # `:R attr_updates`-only, and those rows are exactly what closes an open slot — so a
    # repair can close one and a delete re-opens it. Without this the move goes unannounced
    # AND unannounceable: the next `append_block` reads the repair as part of its `before`,
    # the two frontiers match, and the block is suppressed for good.
    return _warning_return(
        lead + _frontier_recall(deps, current, new_text), _warn_over(new_text)
    )


def register_tools(agent, tools: ToolSet, verbs: Any = None) -> None:

    if tools.bash:
        @agent.tool
        async def bash(ctx: RunContext[AgentDeps], command: str) -> str:
            """Run a shell command. Use the `defender-*` shims (defender-invlang,
            defender-lessons, …) for first-party tooling. Data-source adapters are
            not runnable from the main loop — dispatch gather instead."""
            return _tool_bash(ctx.deps, command)

    if tools.read:
        @agent.tool
        async def read_file(
            ctx: RunContext[AgentDeps],
            path: str,
            pattern: str | None = None,
            tail: int | None = None,
        ) -> str:
            """Read a file's contents (e.g. alert.json, a SKILL, a lesson). Pass
            `pattern` to return only the lines containing that substring — the grep
            fold, for scanning a large file (or when the read-only bash grep/cat
            viewers are not available to this agent). Pass `tail` for at most the last
            N characters instead of the whole file, never starting mid-row — the cheap
            way to re-sync with `investigation.md` after a frontier fold. Both compose:
            `pattern` narrows first, then `tail` takes the end of what is left."""
            return _tool_read_file(ctx.deps, path, pattern, tail)

    if tools.write:
        # `sequential=True` on BOTH, the same rule `append_block`/`fix_row` carry below and the
        # close tool carries in close_tool.py: these two write a SHARED ARTIFACT, so two
        # `ToolCallPart`s in one model response would otherwise run as concurrent tasks and one
        # write would be lost. `edit_file` is the worse of the two — it is a read-modify-write
        # (`_probe_read_text`, splice, `write_guarded`), so two concurrent edits on one file both
        # read the same pre-image and one splice vanishes while both calls report success. These
        # are granted to CORPUS_AUTHOR and LEAD_AUTHOR, whose lesson files the learning corpus is
        # built from.
        @agent.tool(sequential=True)
        async def write_file(ctx: RunContext[AgentDeps], path: str, content: str) -> str:
            """Write a file within this agent's declared write scope, replacing it whole.
            Content is validated against the schema for whatever artifact the path names."""
            return _tool_write_file(ctx.deps, path, content)

        @agent.tool(sequential=True)
        async def edit_file(
            ctx: RunContext[AgentDeps], path: str, old_string: str, new_string: str
        ) -> str:
            """Replace the first occurrence of old_string with new_string in a file within
            this agent's declared write scope. old_string must match exactly once. The
            resulting full text is validated."""
            return _tool_edit_file(ctx.deps, path, old_string, new_string)

    if tools.append:
        _register_investigation_verbs(agent)

    _register_deferred_tools(agent, tools, verbs)


def _register_investigation_verbs(agent) -> None:
    """The two verbs bound to `investigation.md` — the append and the repair.

    One grant, one registration site: `fix_row` rides `append=True` rather than minting a
    capability bit, so an agent that may grow the transcript may also repair a row it landed
    in it. Split out of `register_tools` to keep that function under the complexity gate."""
    # `sequential=True`: two `ToolCallPart`s in ONE model response otherwise run concurrently,
    # and against the real write primitive that is a genuine LOST UPDATE — both calls read the
    # same pre-image, one change reaches disk, and both report success. A `fix_row` paired with
    # an `append_block` could discard the repair while telling the model it landed, leaving a
    # window that looks shut and is not.
    @agent.tool(sequential=True)
    async def append_block(ctx: RunContext[AgentDeps], text: str) -> str:
        """Append to investigation.md, the invlang work log — no path and no anchor,
        because the run has one transcript and it only ever grows. Send ONE invlang
        block per call. The resulting full document is validated (invlang); if it is
        refused, nothing is written and the file still does not contain your text. A
        WARNING is different: the block DID land, and the flagged row blocks the next
        write until you repair it with fix_row. To record a disposition use
        close_investigation, the report's only writer."""
        return _tool_append_block(ctx.deps, text)

    @agent.tool(prepare=_prepare_fix_row, sequential=True)
    async def fix_row(ctx: RunContext[AgentDeps], old_row: str, new_row: str) -> str:
        """Repair ONE flagged row of investigation.md in place — offered only while a
        row is flagged. `old_row` must be a currently-flagged row, copied exactly as the
        warning printed it; it is matched as a whole line, never as a substring, and
        never outside the flagged set. `new_row` replaces it and must be a single row of
        the same block with the same columns; an EMPTY `new_row` deletes the line. This
        is not a general editor: nothing else in the document is reachable through it."""
        return _tool_fix_row(ctx.deps, old_row, new_row)


async def _prepare_fix_row(ctx: RunContext[AgentDeps], tool_def: Any) -> Any:
    """Offer `fix_row` only while the repair window is open.

    ERGONOMICS, not a control. The offer is computed once per model REQUEST, so a model that
    saw the definition on an earlier turn can still emit the call after the window closed;
    `_tool_fix_row` re-derives and refuses. The security property rests on that body.

    Offered on the REPAIR set, which the body also gates on: a document whose only defect is
    error-severity has no warn window, and offering on that would hide the verb in exactly the
    case the close is about to demand it."""
    return tool_def if repairable_diagnostics(ctx.deps) else None


def _register_deferred_tools(agent, tools: ToolSet, verbs: Any = None) -> None:
    if tools.forward_check:
        from defender.learning.author.verify_forward.tool import register_forward_check_tool

        register_forward_check_tool(agent)

    if tools.lesson_read:
        from defender.learning.author.lesson_read import register_lesson_read_tool

        register_lesson_read_tool(agent)

    if tools.template_search:
        from defender.runtime.tools_gather import register_template_search_tool

        register_template_search_tool(agent)

    if tools.query:
        from defender.runtime.query_tool import register_query_tool

        if verbs is None:
            raise ValueError(
                "ToolSet(query=True) needs a verb registry — thread one from "
                "run_investigation(verbs=…); a query tool with no registry has no allowlist."
            )
        register_query_tool(agent, verbs)

    if tools.list_verbs:
        from defender.runtime.query_tool import register_list_verbs_tool

        if verbs is None:
            raise ValueError(
                "ToolSet(list_verbs=True) needs a verb registry — thread one from "
                "run_investigation(verbs=…); the tool answers off the registry's grant, and "
                "with no registry it has no surface to report and no allowlist to filter by."
            )
        register_list_verbs_tool(agent, verbs)

    if tools.closed_tickets:
        from defender.learning.pipeline.judge.closed_ticket_tool import (
            register_closed_ticket_tools,
        )

        register_closed_ticket_tools(agent, verbs)


from .tools_gather import (  # noqa: E402, F401  (re-exported — public surface)
    GatherRequest,
    _gather_prompt,
    _payload_note,
    _persist_gather_summary,
    _run_gather,
    _tripped_message,
    register_gather_tool,
)
