
from __future__ import annotations

import json
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Self

from defender._clock import now_iso
from defender._paths import PATHS

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import guarded_mkdir, read_text_utf8, write_guarded
from . import box as box_mod
from . import permission
from .agent_definition import ResolvedRoots, ToolSet
from .agent_role import AgentRole

from defender._untrusted import wrap as _wrap
# The SAME byte ruler the #629 bounds are measured with — a write tool that reports "bytes"
# has to report the number the gate will judge, not a codepoint count that under-reads it.
from defender._artifact_schema import _utf8_len
from defender.scripts.adapters.faults import USAGE_EXIT_CODE
from defender.scripts.gather_tools import sql as defender_sql
from defender.scripts.gather_tools import record_query
from defender.scripts.gather_tools.record_query import (
    _passthrough_max_bytes as _read_char_cap,
)
from defender.hooks.record_lesson_load import (
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
    lesson_name as _lesson_name,
)

#: The queries table's own infra code — `circuit_breaker.INFRA_EXIT_CODES`' member for a
#: fault that is the environment's, not the caller's. Named rather than spelled `2` at the
#: use site, so a reader of `_shim_exit_code` sees WHICH taxonomy the number belongs to.
_INFRA_EXIT_CODE = 2

_BASH_TIMEOUT_S = 120

#: The `verb` a bash-lane row carries. Not a registry verb and deliberately unlike one: it keeps
#: a shim row outside `repeat_trip`'s `(system, verb, params)` key by construction, so an
#: observational row can never be mistaken for a dispatch attempt and trip the guard (#823 N3).
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


def _bounded_read(
    text: str, path: str, *, filter_hint: str, read_tool: str = "read_file"
) -> str:
    cap = _read_char_cap()
    if len(text) <= cap:
        return text
    total_lines = text.count("\n") + 1
    note = (
        f"\n\n[{read_tool}] {len(text)} chars / {total_lines} line(s); showing the "
        f"first {cap}. This file is too large to read whole — do not "
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
    salt: str
    policy: permission.AgentPolicy = field(kw_only=True)
    cwd_anchor: Path = field(kw_only=True)
    box: box_mod.BoxExecutor = field(kw_only=True, default_factory=box_mod.BoxExecutor)
    budget_started_monotonic: float = field(kw_only=True, default_factory=time.monotonic)
    authored_paths: set[Path] = field(
        kw_only=True, default_factory=set, compare=False, repr=False
    )
    #: #774 K9. The gate's per-run mutable state (turn count, raised-lead ids, the
    #: terminal-close flag) — ONE mutable container, following the `authored_paths`
    #: precedent, since `AgentDeps` is frozen and cannot carry a plain int counter.
    #: `defender.runtime.challenge_gate.ReviewState.of(deps)` owns what lives inside it;
    #: this field is just the box.
    review_state: dict = field(
        kw_only=True, default_factory=dict, compare=False, repr=False
    )
    roots: ResolvedRoots | None = field(kw_only=True, default=None)
    tool_config: Any = field(kw_only=True, default=None)

    role: ClassVar[AgentRole] = AgentRole.MAIN

    @classmethod
    def _for_run(
        cls, run_dir: Path, policy: permission.AgentPolicy,
        *, cwd_anchor: Path, defender_dir: Path = PATHS.defender_dir, salt: str | None = None,
        box: box_mod.BoxExecutor | None = None,
        roots: ResolvedRoots | None = None,
        tool_config: Any = None,
        **subtype_fields: Any,
    ) -> Self:
        resolved_salt = salt if salt is not None else uuid.uuid4().hex
        return cls(
            run_dir=run_dir, defender_dir=defender_dir,
            run_id=run_dir.name, salt=resolved_salt, policy=policy,
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
    `EXIT_INPUT_ERROR` (2) on the AGENT's mistakes — an empty pipe, a payload that is not JSON,
    a malformed argv — while 2 in this table means INFRA (`circuit_breaker.INFRA_EXIT_CODES`,
    where it is the adapter-load fault), and `collect_general_failures` drops every infra row.
    Left untranslated, the commonest reduce mistakes were recorded and then silently discarded
    — the exact failure M1 exists to end.

    So the two genuinely different meanings are separated at the boundary rather than averaged:
    an input error becomes `USAGE_EXIT_CODE`, this table's own "the caller's request was
    refused"; a missing runtime (`EXIT_NO_RUNTIME`, which #823 split out of the shim's exit-2
    bucket precisely so this mapping could be exact) becomes the table's infra code, because a
    broken deployment is not a lesson any `execution.md` should carry. A query error (1) is
    already agent-fixable and passes through. The shim's real status stays legible either way —
    `payload_digest` records the raw `exit=N` and its stderr.
    """
    if rc == defender_sql.EXIT_INPUT_ERROR:
        return USAGE_EXIT_CODE
    if rc == defender_sql.EXIT_NO_RUNTIME:
        return _INFRA_EXIT_CODE
    return rc


def _record_shim_failure(
    deps: AgentDeps, decision: permission.BashDecision, command: str, result: Any,
) -> None:
    """#823 M1 — a FAILED reducer shim writes its own queries-table row.

    `executed_queries.jsonl` was the query tool's alone, so the reduce step gather's own prompt
    tells the subagent to run (`cat <payload> | defender-sql …`) left no trace anywhere the
    offline loop reads. One measured lead spent its whole session brute-forcing DuckDB `unnest`
    against a nested-envelope payload, and the pitfalls curator — whose entire job is folding
    exactly that lesson into `skills/{system}/execution.md` — saw nothing.

    FOUR conditions, each of them a demand of the spec and none of them incidental:

    * `lead_id` — GATHER ONLY. `lead_id` lives on `GatherDeps`, not `AgentDeps`, so main's bash
      lane structurally cannot produce one; the record is per-lead and joins on that key, and
      main's bash is investigation authoring, not gathering. Narrowed with `isinstance` rather
      than `getattr(deps, "lead_id", None)`: the getattr returns `Any`, which silently erased
      the type of the value feeding `append_query_row(lead_id: str)` — and that value becomes a
      `gather_raw/{lead_id}/` path component.
    * a non-zero exit — the trigger is a FAILURE, not a shim call. Recording the sanctioned
      happy path would make the pitfalls queue a transcript.
    * a REDUCER stage — not bash in general. `_tool_bash` serves `grep`, `cat` and `wc` too, and
      a failing `wc` teaches a system nothing. `bin/` carries exactly one reducer. And it must
      be the TERMINAL stage (`command_shape.terminal_reducer`): the box reports one exit code,
      the last stage's, so a reducer piped into `head` has its failure hidden behind that
      stage's 0 and a healthy reducer piped into a non-matching `grep` is handed its 1. Only
      when the reducer IS the reported stage can the rc be attributed to it, and a record no
      one can attribute is worse than no record — it reaches the curator as a lesson.
    * best-effort — this is an observation channel bolted beside the bash lane's real job, so a
      broken table must not turn a working command into a `ModelRetry`. The same posture
      `lead_rows` takes on its own read.
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
            # The system of the PAYLOAD the reducer read, never one parsed out of the argv —
            # the argv names `defender-sql`, and a row saying `system: "sql"` would send the
            # curator at a `skills/sql/execution.md` that must never exist. `""` when the
            # command opened no run payload: `collect_general_failures` skips a systemless row.
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
    # `Exception`, not `OSError`: the fourth condition above is the whole point of this call,
    # and the write is not the only thing that can raise inside it. Narrower than the posture
    # it claims is how an observation channel starts failing the command it observes.
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
    _deny_authored_bash_read(deps, decision)
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
    _record_shim_failure(deps, decision, command, result)
    formatted = _format_bash_result(
        result.rc, result.out.decode("utf-8", "replace"), result.err.decode("utf-8", "replace"),
    )
    if _is_learning_role(deps) or _opens_untrusted_read(deps, decision):
        return _wrap(formatted, "untrusted", deps.salt)
    return formatted


def _grep_lines(text: str, pattern: str) -> str:
    return "\n".join(line for line in text.splitlines() if pattern in line)


def _resolve_operand(deps: AgentDeps, path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else deps.cwd_anchor / p


def _tree_root_for(deps: AgentDeps, p: Path) -> Path:
    """Which shared tree `p` sits in — the anchor `guarded_mkdir` walks down from.

    The write gate has already confined `p` to the run dir or the defender dir (its `write ⊆
    read roots` invariant), so one of the two contains it; this only has to say WHICH, because
    the component guard needs to know where the box's reach begins. The run dir is tried first:
    it is the narrower of the two and, in the drain lane, sits inside a checkout of the
    defender dir, so root order is what keeps the anchor at the tighter tree.

    Each root is tried in BOTH its raw and its resolved spelling, because the gate above
    matched on `resolve()`d paths and this check does not: with a symlinked runs base (the
    macOS `/tmp` case the anchor decision was made for) the model can legitimately name the
    already-resolved spelling, `decide_write` resolves both sides and allows it, and a
    raw-spelling-only comparison here would then refuse what the gate just admitted. `p`
    itself is never resolved — `resolve()` would collapse the very component symlink the
    guard exists to refuse — and the spelling RETURNED is whichever one actually prefixes
    `p`, since `guarded_mkdir` needs the anchor to be a lexical prefix of the target.

    Failing to classify means the gate admitted a path that is not lexically under either
    root under either spelling — a path reached THROUGH a symlink, which is the hazard the
    guard exists for. `ModelRetry` rather than a bare raise: the operand is model-supplied,
    so a refusal it can read and correct beats an exception that ends the run."""
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


def _opens_untrusted_read(deps: AgentDeps, decision: permission.BashDecision) -> bool:
    """Does this command open a file the read tool would have salt-tag wrapped?

    The trust boundary is a property of the DATA, not of who is reading it — but until
    #776 the bash lane keyed its frame on the ROLE instead, and the two roles it excluded
    (main and gather) were the two that read attacker-influenced payloads through it.

    Gather was the whole exposure: the reduce step its own prompt tells it to use
    (`cat <payload> | defender-sql`) is the single channel delivering full attacker-chosen
    field values, and it arrived bare while the same bytes read through `read_file`, or
    returned by the `query` tool, arrived framed. Main's exposure is narrower — bound
    `raw=False` it cannot reach a payload at all — but not empty: `cat alert.json` was
    unframed on this lane while `read_file('alert.json')` was framed, for the same bytes.

    Keying on `is_untrusted_read` — the one predicate that already decides this for every
    other read surface — makes the frame a property of the channel rather than of the
    caller, so the three routes to the same file now agree."""
    return any(permission.is_untrusted_read(p) for p in _opened_operands(deps, decision))


def _deny_authored_bash_read(
    deps: AgentDeps, decision: permission.BashDecision
) -> None:
    if not _is_learning_role(deps):
        return
    for operand in _opened_operands(deps, decision):
        _deny_authored_read(deps, operand)


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_cross_agent_read(deps: AgentDeps, path: Path) -> bool:
    resolved = _resolved(path)
    roots = (*deps.policy.read_roots, *deps.policy.read_confine)
    corpus_dir = getattr(deps, "corpus_dir", None)
    if corpus_dir is not None:
        roots = (*roots, Path(corpus_dir))
    if any(_under(resolved, _resolved(root)) for root in roots):
        return True
    role_name = str(getattr(deps.role, "value", "")).replace("_", "-")
    return bool(role_name) and resolved.name == f"{role_name}.md"


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
    if not p.is_file():
        raise ModelRetry(f"file not found: {path}")
    _deny_authored_read(deps, p)
    try:
        text = read_text_utf8(p)
    except UnicodeDecodeError:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)") from None
    except OSError as e:
        raise ModelRetry(f"could not read {path}: {e}") from None
    _record_lesson_load(deps, p, lesson_corpora)
    return p, text


def _bound_and_wrap(
    deps: AgentDeps, p: Path, path: str, text: str, *, read_tool: str
) -> str:
    text = _bounded_read(
        text, path,
        filter_hint=_overflow_filter_hint(path, deps.policy, read_tool),
        read_tool=read_tool,
    )
    if permission.is_untrusted_read(p) or (
        _is_learning_role(deps) and _is_cross_agent_read(deps, p)
    ):
        return _wrap(text, "untrusted", deps.salt)
    return text


def _tail_chars(text: str, n: int) -> str:
    """The last `n` characters, trimmed FORWARD to the next line start so a `|`-delimited
    invlang row never arrives cut in half and gets read as truncated data. `n` is therefore
    a ceiling, not a target: the result is at most `n` characters, which is what a caller
    asking for a bounded read wants. `n <= 0` yields nothing; a file shorter than `n` is
    returned whole; text with no newline in the window is cut at `n`.

    Its own fold rather than a reuse of `_bounded_read`, whose overflow path keeps the
    HEAD — the wrong end of an append-only log (#810)."""
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
    """RS15. `investigation.md` becomes review-state-aware AFTER a close commits — no
    post-close write can silently move the recorded disposition. The working document
    itself stays otherwise model-writable throughout the investigation (untouched by
    this change up to the close); this is the ONE new gate on it."""
    if p.resolve() != (deps.run_dir / "investigation.md").resolve():
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
    try:
        current = read_text_utf8(p) if p.is_file() else ""
    except UnicodeDecodeError:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)") from None
    if not old_string and p.is_file():
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


def _tool_append_block(deps: AgentDeps, text: str) -> str:
    """Append to `investigation.md` — main's only write (#810).

    No path: the run has one model-authored transcript and this is its writer, the way
    `close_investigation` is `report.md`'s (#774). No anchor and no position either: the
    document is validator-enforced append-only (`_check_append_only` refuses a dropped
    fence, a dropped record, or an in-place mutation), so the anchored replace that
    `edit_file` offers is a capability the artifact never had. Measured over three runs,
    seven of the eight non-append `edit_file` calls failed.

    Faces the identical gate the other two verbs do — same `decide_write`, same content
    schema, same RS15 post-close refusal — on the resulting full document."""
    p = deps.run_dir / "investigation.md"
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further append could silently "
            "move it. The case is closed."
        )
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
    # Separate with a newline when the document does not already end in one. Existing
    # bytes are never rewritten — not even trailing whitespace — so an append cannot
    # itself trip the append-only check it is about to face. An EMPTY append gets no
    # separator either: appending nothing must not mutate the document (the separator
    # alone would be a byte the model never sent, on a call reporting zero bytes).
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
    # UTF-8 BYTES, not characters: the SKILL tells the model this return IS a byte count and
    # the 65536-byte cap it has to stay under is measured the same way. invlang rows carry
    # `⟂ → ⟺` freely, so `len(str)` under-reports against the bound the gate applies.
    return (
        f"appended {_utf8_len(text)} bytes to investigation.md "
        f"({_utf8_len(new_text)} total)"
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
        @agent.tool
        async def write_file(ctx: RunContext[AgentDeps], path: str, content: str) -> str:
            """Write a file within this agent's declared write scope, replacing it whole.
            Content is validated against the schema for whatever artifact the path names."""
            return _tool_write_file(ctx.deps, path, content)

        @agent.tool
        async def edit_file(
            ctx: RunContext[AgentDeps], path: str, old_string: str, new_string: str
        ) -> str:
            """Replace the first occurrence of old_string with new_string in a file within
            this agent's declared write scope. old_string must match exactly once. The
            resulting full text is validated."""
            return _tool_edit_file(ctx.deps, path, old_string, new_string)

    if tools.append:
        @agent.tool
        async def append_block(ctx: RunContext[AgentDeps], text: str) -> str:
            """Append to investigation.md, the invlang work log — no path and no anchor,
            because the run has one transcript and it only ever grows. Send ONE invlang
            block per call. The resulting full document is validated (invlang); if it is
            refused, nothing is written and the file still does not contain your text.
            To record a disposition use close_investigation, the report's only writer."""
            return _tool_append_block(ctx.deps, text)

    _register_deferred_tools(agent, tools, verbs)


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
