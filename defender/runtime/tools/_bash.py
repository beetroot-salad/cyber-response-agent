
from __future__ import annotations

import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    pass


from pydantic_ai.exceptions import ModelRetry

from .. import box as box_mod
from .. import permission
from ..permission.files import RESOLVE_ERRORS
from ..agent_role import AgentRole

from defender._untrusted import wrap_fresh
from defender._env import FatalConfigError
from defender.scripts.adapters.faults import USAGE_EXIT_CODE
from defender.runtime.sql_engine import sql as defender_sql
from defender.scripts.gather_tools import record_query
from defender._query_rules import BASH_SHIM_QUERY_ID
from ._deps import AgentDeps, GatherDeps, _BASH_TIMEOUT_S, _BASH_VERB, _INFRA_EXIT_CODE, _bounded_read, _cap_for, _format_bash_result, _overflow_filter_hint, _read_char_cap


def _bash_env(deps: AgentDeps) -> dict[str, str]:
    from defender import run_common
    return run_common.run_env(deps.defender_dir, deps.run_dir)


def _shim_exit_code(rc: int) -> int:
    """Translate `defender-sql`'s exit codes into the dialect the queries table speaks.

    The shim's 2 is an agent input error, but 2 in the table means infra (whose rows are
    dropped), so it becomes `USAGE_EXIT_CODE`. A missing runtime is infra, not a lesson. A query
    error (1) passes through. Any other code (SIGKILL, missing binary) came from the kernel or
    shell, not the reducer, so it is infra too rather than an agent-fixable lesson.
    `payload_digest` still records the raw exit code.
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
    """Record a failed reducer shim (`cat <payload> | defender-sql …`) as a queries-table row
    for the pitfalls curator.

    Only when all hold:

    * gather only (`GatherDeps.lead_id`): the row is per-lead;
    * a non-zero exit — failures, not every call;
    * the reducer is the terminal stage: the box reports only the last stage's exit code, so
      otherwise the code cannot be attributed to the reducer;
    * best-effort — it must never fail the command it observes.
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
            # The payload's system, not the argv's (`sql` is not a system). `""` when no run
            # payload was opened; routing uses the sentinel `query_id` either way.
            system=record_query.system_for_payload_operands(
                deps.run_dir, _opened_operands(deps, decision),
            ),
            verb=_BASH_VERB,
            # Nothing to fingerprint: `system` comes from a path this run wrote, not the model.
            system_key="",
            query_id=BASH_SHIM_QUERY_ID,
            params={"command": recorded_command},
            raw_command=recorded_command,
            # Empty but present (`extract_from_joined` drops rows without a sidecar); the
            # shim's stdout is attacker-influenced and not evidence.
            payload_text="",
            exit_code=_shim_exit_code(result.rc),
            payload_status="error",
            payload_digest=f"exit={result.rc}; {stderr.strip()[:160]}",
        )
    # `Exception`, not `OSError`: more than the write can raise, and this must stay best-effort.
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
    # Computed once; used for the authored-read denial, the ceiling and hint, and the frame.
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
    # Behind the gate's NUL deny: the box encoder raises a bare `ValueError` for an argv it
    # cannot encode, which nothing upstream catches. `FatalConfigError` subclasses `ValueError`
    # but is a misconfigured run that must stop, so it is re-raised first.
    except FatalConfigError:
        raise
    except ValueError as e:
        raise ModelRetry(f"the command cannot cross the box wire: {e}") from e
    _record_shim_failure(deps, decision, command, result)
    capping = min(operands, key=_cap_for, default=None)
    formatted = _format_bash_result(
        result.rc,
        # Bounded before framing, so the closing delimiter is never cut off.
        _bounded_bash_stream(
            deps, decision, capping,
            result.out.decode("utf-8", "replace"), subject="This output",
        ),
        # Stderr too: `defender-sql` writes payload-derived text there.
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


def _root_spellings(deps: AgentDeps, root: Path) -> tuple[Path, ...]:
    """The spellings an operand may reach `root` by: as given, resolved, and, for a root inside
    the defender tree, the same tail under `deps.defender_dir`'s own spelling. A curator's read
    confine is stored resolved while its `cwd_anchor` keeps the operator's spelling, so without
    that last one a relative lesson path under a symlinked repo root would match no root. Every
    spelling is host-chosen; nothing the model names is resolved here."""
    spellings = [root]
    try:
        resolved, tree = _resolved(root), _resolved(deps.defender_dir)
    except RESOLVE_ERRORS:
        return tuple(spellings)
    spellings.append(resolved)
    if resolved.is_relative_to(tree):
        spellings.append(deps.defender_dir / resolved.relative_to(tree))
    return tuple(spellings)


def _rooted_operand(
    deps: AgentDeps, p: Path, roots: Iterable[Path], *, path: str,
) -> tuple[Path, str]:
    """The operand `p` (as `_resolve_operand` spells it) as the trust root it sits in and its
    POSIX name below that root, for the rooted core: the root is opened following its spelling,
    and nothing below it is followed.

    The innermost root `p` sits under lexically wins (the run dir may sit inside the defender
    dir). `p` itself is never resolved, which would collapse the links the core exists to
    refuse. A `..` component, or no root at all (a path that reaches one only through a
    symlink), is refused as `ModelRetry`: the operand is model-supplied."""
    if ".." in p.parts:
        raise ModelRetry(
            f"{path} has a '..' component; name the file by a path without '..'"
        )
    best: Path | None = None
    for root in roots:
        for spelling in _root_spellings(deps, Path(root)):
            if spelling in p.parents and (best is None or len(spelling.parts) > len(best.parts)):
                best = spelling
    if best is None:
        raise ModelRetry(
            f"{p} is not inside a tree this agent may use; name a path under the run directory "
            f"or the defender directory (a path that only reaches one through a symlink is "
            f"refused)"
        )
    return best, p.relative_to(best).as_posix()


def _write_roots(deps: AgentDeps) -> tuple[Path, ...]:
    """The trees a file-tool write is rooted in. The write gate decides what may be written;
    this only names where the walk starts."""
    return (deps.run_dir, deps.defender_dir)


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

    Keyed on the data, not the role: main and gather read attacker-influenced payloads through
    bash. Uses `is_untrusted_read` so every route to the same file agrees."""
    return any(permission.is_untrusted_read(p) for p in operands)


#: The overflow hint when no file operand set the ceiling (e.g. `ls`, or a shim that reads files
#: without naming them on the argv), so there is no path to suggest.
_BASH_NO_OPERAND_HINT = (
    "Narrow the command itself — a tighter filter or selector — and run it again. This return "
    "is a command's output and names no file operand, so there is no path to re-read a "
    "smaller slice of."
)

#: The overflow hint when the command already ends in a reducer; suggesting the reduce pipe
#: again would loop (a payload's ceiling applies to the whole pipeline's output).
_BASH_REDUCED_HINT = (
    "This return is already a reduction, so re-running the same pipe returns the same "
    "oversized result. Narrow the reduction itself — aggregate further, select fewer columns, "
    "or add a LIMIT — and run it again."
)


def _bash_overflow_hint(
    deps: AgentDeps, decision: permission.BashDecision, capping: Path | None
) -> str:
    """The reduction the caller can run when the bash return overflowed its ceiling.

    No operand, or a terminal reducer, gets a fixed hint. Otherwise the read lane's hint for
    the capping file, with `read_tool` left at its
    default: it names the fallback substring-search tool (`read_file`), not the one that
    overflowed."""
    if capping is None:
        return _BASH_NO_OPERAND_HINT
    if permission.command_shape.terminal_reducer(list(decision.pipelines or ())):
        return _BASH_REDUCED_HINT
    return _overflow_filter_hint(str(capping), deps.policy)


def _bounded_bash_stream(
    deps: AgentDeps, decision: permission.BashDecision, capping: Path | None,
    text: str, *, subject: str,
) -> str:
    """One bash output stream, held to the ceiling its data chose.

    The same bound `read_file` applies, so `cat` cannot recover what the capture view withheld.
    `capping` is the operand with the smallest cap; with none, the authored cap applies. The
    hint is built only on overflow, since it runs a full policy probe."""
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
    """Whether a learning stage is reading text some other agent produced — decides the salt
    frame for reads `is_untrusted_read` does not already claim.

    The run dir counts: for a learning stage it is a shared cross-stage directory. Only
    consulted for learning roles."""
    resolved = _resolved(path)
    roots = (deps.run_dir, *deps.policy.read_roots, *deps.policy.read_confine)
    corpus_dir = getattr(deps, "corpus_dir", None)
    if corpus_dir is not None:
        roots = (*roots, Path(corpus_dir))
    if any(_under(resolved, _resolved(root)) for root in roots):
        return True
    role_name = str(getattr(deps.role, "value", "")).replace("_", "-")
    return bool(role_name) and resolved.name == f"{role_name}.md"
