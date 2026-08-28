
from __future__ import annotations

import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    pass


from pydantic_ai.exceptions import ModelRetry

from defender._io import guarded_mkdir
from . import box as box_mod
from . import permission
from .agent_role import AgentRole

from defender._untrusted import wrap_fresh
# The SAME byte ruler the artifact bounds are measured with — a write tool that reports
# "bytes" must report the number the gate will judge, not a codepoint count that under-reads it.
from defender._env import FatalConfigError
from defender.scripts.adapters.faults import USAGE_EXIT_CODE
from defender.scripts.gather_tools import sql as defender_sql
from defender.scripts.gather_tools import record_query
from ._deps import AgentDeps, GatherDeps, _BASH_TIMEOUT_S, _BASH_VERB, _INFRA_EXIT_CODE, _bounded_read, _cap_for, _format_bash_result, _overflow_filter_hint, _read_char_cap


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
