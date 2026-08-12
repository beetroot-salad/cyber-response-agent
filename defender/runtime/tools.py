
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import uuid
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

from defender._untrusted import wrap as _wrap
# The SAME byte ruler the #629 bounds are measured with — a write tool that reports "bytes"
# has to report the number the gate will judge, not a codepoint count that under-reads it.
from defender._artifact_schema import _utf8_len
from defender._env import env_int
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


def _read_char_cap() -> int:
    """The cap on reading an AUTHORED file — a SKILL, a lesson, a design doc.

    Its own number since #832, where the capture ceiling dropped to 8 KB. The two used to be one
    constant, and the sharing was load-bearing in one direction only: a lead must not be able to
    `read_file` a persisted payload and recover what the capture view withheld. But equality
    over-served that property — `defender/SKILL.md` is 33,590 bytes and 16 of 20 files under
    `docs/` clear 8 KB, so lowering the shared value would have truncated the runtime agent's own
    spec to serve a bound on payload reads. `_cap_for` keeps the property and drops the equality:
    the capture ceiling applies where a capture is being re-read, and nowhere else."""
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
    # #851 F-07/F-10, belt-and-braces behind the gate's NUL deny. `encode_request` sits ABOVE
    # `run_parsed`'s own try (box.py) and raises a bare `ValueError` for a frame it cannot
    # encode; nothing between here and `run.py::main` catches that type — not this handler
    # stack, not `_drive_agent`'s five named arms, not the gather lane's — so an unencodable
    # argv took the whole investigation down with a traceback and no disposition. It becomes a
    # refusal the model can act on instead. The encoder's exception TYPE is left alone
    # deliberately: `test_540_exec_seam.py` pins `pytest.raises(ValueError)` on `run_parsed`.
    except ValueError as e:
        raise ModelRetry(f"the command cannot cross the box wire: {e}") from e
    _record_shim_failure(deps, decision, command, result)
    capping = min(operands, key=_cap_for, default=None)
    formatted = _format_bash_result(
        result.rc,
        # Bounded BEFORE the frame below, matching the ordering
        # `test_oversized_untrusted_read_caps_before_wrapping` pins for the read lane: the head
        # and its notice land inside the delimiters, never a dump whose closing tag was cut off.
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


def _opens_untrusted_read(operands: Iterable[Path]) -> bool:
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

#: …and when the command ALREADY reduced. `_overflow_filter_hint` answers "how do I shrink a
#: file I just read whole", and its answer is the reduce pipe — which is the command that just
#: overflowed. Handing that back is an instruction loop, and the loop is reachable: a payload
#: sets the 8 KB capture ceiling for the WHOLE pipeline, including a legitimately larger
#: aggregate the reducer computed from it.
_BASH_REDUCED_HINT = (
    "This return is already a reduction, so re-running the same pipe returns the same "
    "oversized result. Narrow the reduction itself — aggregate further, select fewer columns, "
    "or add a LIMIT — and run it again."
)


def _bash_overflow_hint(
    deps: AgentDeps, decision: permission.BashDecision, capping: Path | None
) -> str:
    """The reduction the caller can run when the bash return overflowed its ceiling.

    Three cases, because one answer does not serve them. No operand: nothing to re-read.
    A TERMINAL reducer (`command_shape.terminal_reducer` — the same predicate
    `_record_shim_failure` attributes an rc with): the reduce pipe IS the command, so the
    generic hint would name it back. Otherwise the file the ceiling came from, through the read
    lane's own hint — which keeps `read_tool` at its default on purpose: that argument names the
    tool whose SUBSTRING SEARCH the no-reducer branch falls back to (`read_file(p, pattern=…)`),
    not the tool that overflowed, and `read_tool="bash"` there spelled a `bash(p, pattern=…)`
    call no agent has."""
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

    Keyed on the DATA, the way #776 keyed the untrusted wrap. `read_file` bounds a captured
    payload at the capture ceiling precisely so a later read cannot recover what the capture view
    withheld (#832 O7) — but until #849 the same file read through `cat` had no ceiling at all,
    which made the bound a `read_file`-LANE property rather than a per-file one, and left the
    uncapped lane the one gather's own prompt tells it to use. `_opened_operands` + `_cap_for`
    already answer the per-path question; this only has to ask it of the right path.

    `capping` is the operand with the SMALLEST cap: a pipeline may open several files, and a
    ceiling any one operand can raise is not a ceiling. A command that opens no file still gets
    the authored cap — a bound on the return, just not one a file chose. The hint is built only
    when the stream actually overflows, because building it probes the policy
    (`_overflow_filter_hint` → `_lane_admits` → a full `decide_bash`) and the overwhelming
    majority of returns fit."""
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
    decides the salt frame for reads that `is_untrusted_read` does not already claim.

    The agent's own run dir is in the root set (#849). For a runtime agent the run dir is its
    own workspace, but for a learning stage it is the SHARED cross-stage directory: the host
    writes `past_tickets.txt` into it, the sibling leg leaves its `actor_*_story.md` there, and
    the judge's own closed-ticket capture lands at `ticket_reads/{seq}.json` — all of it produced
    by someone else, and all of it bare here while `_tool_bash` framed the same file. MAIN and
    GATHER are unaffected: `_bound_and_wrap` consults this only under `_is_learning_role`, so
    their same-agent run-dir reads stay unframed."""
    resolved = _resolved(path)
    roots = (deps.run_dir, *deps.policy.read_roots, *deps.policy.read_confine)
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
        text, path, cap=_cap_for(p),
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
    this change up to the close); this is the ONE new gate on it.

    #851 F-25: the `resolve()` here runs one line AHEAD of `decide_write`/`decide_read`, so an
    operand it cannot resolve (an embedded NUL — `ValueError`; a symlink cycle — `RuntimeError`)
    escaped the write/edit tool as an unhandled exception and quarantined the whole authoring
    spawn, routing around the fail-closed `Decision(False)` the gate's `RESOLVE_ERRORS` rule
    exists to produce. An unresolvable operand is certainly not `<run_dir>/investigation.md`, so
    answering False is honest — and it hands the operand straight to the gate, which denies it
    with the correctable "could not be resolved (failing closed)" reason."""
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


# --------------------------------------------------------------------------------------
# #836 — the repair window. A warn-family `:R attr_updates` row LANDS instead of costing a
# whole re-emitted block, and then gates the next write until it is repaired.
#
# The window is DERIVED, never stored: `warn_diagnostics` over whatever `investigation.md`
# holds right now IS the state. Nothing here caches it, and no `AgentDeps` field carries it,
# so it cannot go stale and cannot disagree with the file.
# --------------------------------------------------------------------------------------

def _investigation_path(deps: AgentDeps) -> Path:
    return deps.run_dir / "investigation.md"


def flagged_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """The run's currently-open repair window, re-derived from disk on every call.

    FAILS OPEN, deliberately and on all three paths that read it (`prepare=`, the write gate,
    the close gate). An unreadable or undecodable `investigation.md` is an unrelated fault;
    converting it into "every write and the close are refused" would manufacture exactly the
    unclosable run this mechanism exists to avoid. `append_block` still refuses an undecodable
    document for its own pre-existing reason — that refusal is not this gate.

    A warn diagnostic carrying NO `locus` is not in the window. The window is the set of rows
    `fix_row` can address, and a locus-less finding names none — counting it would refuse the
    append AND the close with no row the repair verb could ever clear, which is precisely the
    unclosable run above. No family emits one today; this keeps that from being load-bearing."""
    from defender.skills.invlang.validate import warn_diagnostics

    p = _investigation_path(deps)
    # ABSENCE is the ordinary "no window open" case, not a fault: `prepare=` runs on EVERY
    # model request, including turn 1 before any write verb has created the file. Logging it
    # would put a line on stderr for every request of every run.
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


def _addressable(diags: Iterable[Diagnostic]) -> tuple[Diagnostic, ...]:
    return tuple(d for d in diags if d.locus is not None)


def _flagged_rows(diags: tuple[Diagnostic, ...]) -> tuple[str, ...]:
    return tuple(d.locus.row_text for d in diags if d.locus is not None)


def flagged_write_refusal(
    verb: str, diags: tuple[Diagnostic, ...], *, offered_text: bool = True
) -> str:
    """The gate's refusal, naming EVERY currently-flagged row and its `use:` alternatives.

    Re-derived rather than remembered: after a frontier fold the model is handed a truncated
    PREFIX of the document (`driver._fold_decision`), so a flagged row below the cut is simply
    absent from its view. The refusal is the recovery channel, which is why it carries the
    whole set rather than the most recent row.

    `offered_text=False` for the CLOSE, which proposed no `investigation.md` bytes of its own:
    the full notice's "does not contain your text" would be a claim about nothing. Both
    spellings LEAD with the same fragment, so the model still tells a refusal from an accept
    by the first sentence."""
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
    """An ACCEPT that carries a warning. It LEADS with the bytes and says the block landed —
    a model that reads "warning" as "refusal" re-emits the whole block, which is the cost
    #836 exists to remove — and it never carries the unchanged-notice wording."""
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
    """Append to `investigation.md` — main's only write (#810).

    No path: the run has one model-authored transcript and this is its writer, the way
    `close_investigation` is `report.md`'s (#774). No anchor and no position either: the
    document is validator-enforced append-only (`_check_append_only` refuses a dropped
    fence, a dropped record, or an in-place mutation), so the anchored replace that
    `edit_file` offers is a capability the artifact never had. Measured over three runs,
    seven of the eight non-append `edit_file` calls failed.

    Faces the identical gate the other two verbs do — same `decide_write`, same content
    schema, same RS15 post-close refusal — on the resulting full document."""
    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further append could silently "
            "move it. The case is closed."
        )
    # #836/M5. The gate is FORCED, not chosen: `_check_closed_vocab` walks the FULL proposed
    # document, so a landed warn row re-fires on every subsequent append anyway. Without the
    # gate the choices are grandfathering — which dead-letters the run at persist — or a
    # wedged document.
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
    lead = (
        f"appended {_utf8_len(text)} bytes to investigation.md "
        f"({_utf8_len(new_text)} total)"
    )
    # The gate ACCEPTED a warn-only document, which means it returned no text to reuse — so
    # the warning can only come from a SECOND derivation here, over the bytes just written.
    # Two `diagnose` passes per accepted append is the expected cost of the accept channel,
    # and deriving in memory keeps it deterministic without a re-read.
    warn = _warn_over(new_text)
    if warn:
        return _warning_return(f"{lead} — the block LANDED.", warn)
    return lead


def _warn_over(text: str) -> tuple[Diagnostic, ...]:
    """The window over text held in memory. FAILS OPEN for the same reason
    `flagged_diagnostics` does, and for one more: both call sites derive AFTER the bytes have
    already landed, so a validator error raised here would surface as a failed tool call on a
    write that succeeded — the one wrong answer #810 measured the cost of."""
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
#: body on — so it is what decides where a ROW ends, and therefore what `Locus.row_text` holds.
#: `split("\n")` alone left a row sitting after a `\v` `\f` `\x1c` `\x1d` `\x1e` `\x85`
#: `\u2028` or `\u2029` FLAGGED but UNADDRESSABLE: `old_row` matched no whole line, so the
#: repair refused while `append_block` and the close both refused for that same flagged row —
#: a permanently wedged run, reachable from one `append_block` carrying one of those bytes.
#: `\r\n` / `\r` never reach here: `read_text_utf8` translates them on read.
#: Spelled as ESCAPES, never as the literal codepoints: two of them are invisible line breaks
#: and would split THIS file for anything that reads it the way the tokenizer reads a fence.
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
    """H3's guard: `new_row` is ONE row of the SAME block, or it is refused.

    `fix_row` is the first verb that rewrites a line INSIDE an already-open fence, and every
    other guard M4 states is on `old_row` — so without this, `new_row` is the whole write
    surface. It is not a belt-and-braces check: `_check_append_only` never inspects `:R` rows,
    so a `:V` declaration substituted for a flagged row draws ZERO diagnostics; an embedded
    newline forges a well-formed second row; a fence delimiter makes the injected row vanish
    by closing the block early; and one cell too FEW is silently padded. Only "too many cells"
    is caught by anything today, and by the parser rather than by a guard. This is what makes
    "no verb mutates or removes a committed :V/:E record" true by construction."""
    from defender.skills.invlang._cells import _split_cells
    from defender.skills.invlang.parser import HEADER_RE

    # EVERY line break `str.splitlines()` honours, not just `\n`. `_tokenize_fence` splits the
    # fence body with `splitlines()`, which breaks on \v \f \x1c \x1d \x1e \x85
    # as well — so a `new_row` carrying one of those is a SECOND row (or a whole second block)
    # to the parser while looking like one line to a `"\n" in ...` check, and its pipe count is
    # unchanged so the cell-count arm never fires either.
    lines = new_row.splitlines()
    if len(lines) != 1 or lines[0] != new_row:
        return "it spans more than one line"
    if "```" in new_row:
        return "it carries a fence delimiter (```), which would close the block early"
    if HEADER_RE.match(new_row.strip()):
        return "it is a block header, not a row"
    # `cells is None` means the declaring block could not be located. Only the CELL-COUNT arm
    # needs it — the three arms above are unconditional, so an unlocatable block narrows the
    # guard by one check instead of switching the whole write surface off.
    if cells is None:
        return None
    got = len(_split_cells(new_row))
    if got != cells:
        return f"it has {got} cells but the block declares {cells}"
    return None


def _tool_fix_row(deps: AgentDeps, old_row: str, new_row: str) -> str:
    """#836/M4 — repair ONE flagged row of `investigation.md` in place.

    No path and no free-form anchor: `old_row` must be one of the rows the repair window is
    currently open on, which is what puts every committed `:V`/`:E` record out of reach (the
    warn family walks `:R attr_updates` blocks and nothing else). `new_row` empty DELETES the
    line — the always-available escape that keeps the window closable, and the only move that
    is still available when the document is at its size bound.

    The window is re-derived here at call time. Being OFFERED the verb is never evidence the
    window is still open: `prepare=` filters per-request offers and is ergonomics, so the body
    is the guard. And the resulting full document faces the same `decide_write` chain every
    other write on this artifact faces — the verb sits behind the validator, not beside it."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE

    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            f"{UNCHANGED_LEAD} — investigation.md is no longer writable: the close already "
            "committed a recorded disposition for this run, and a further repair could "
            "silently move it. The case is closed."
        )
    diags = flagged_diagnostics(deps)
    flagged = _flagged_rows(diags)
    if not flagged:
        # Deliberately the SAME refusal a never-flagged `old_row` earns once the window has
        # emptied: a repeated identical repair is idempotent-safe by construction, and a
        # "you already did this" branch would need the stored state M3 exists to avoid.
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
    # H4: the repair applies to EVERY flagged occurrence — a flagged row whose text is not
    # unique would otherwise be neither repairable nor deletable, and with the M5 gate the run
    # would be unclosable. The rider is what keeps that safe: if the text also stands as a
    # WHOLE LINE the window did not flag, the repair refuses rather than rewriting that too.
    #
    # WHOLE-LINE, not substring. The rebuild below only ever touches lines where
    # `line.strip() == old_row`, so a line that merely CONTAINS the row is already out of
    # reach and a substring count guards nothing — while refusing on one wedged the window
    # shut: a `:T conclude` summary quoting its own flagged row made both `fix_row(row, new)`
    # and `fix_row(row, "")` refuse, and with the M5 gate the run could not close. It also
    # fired when one flagged row's text was a PREFIX of another (`…|owner|svc` inside
    # `…|owner|svc2`), where the refusal's own claim — that a match lay somewhere unflagged —
    # was simply false.
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
    return _warning_return(lead, _warn_over(new_text))


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
        _register_investigation_verbs(agent)

    _register_deferred_tools(agent, tools, verbs)


def _register_investigation_verbs(agent) -> None:
    """The two verbs bound to `investigation.md` — the append and, since #836, the repair.

    One grant, one registration site: `fix_row` rides `append=True` rather than minting a
    capability bit, so an agent that may grow the transcript may also repair a row it landed
    in it. Split out of `register_tools` to keep that function under the complexity gate."""
    # `sequential=True` (#836/H6): two `ToolCallPart`s in ONE model response otherwise run
    # concurrently, and against the real write primitive that is a genuine LOST UPDATE —
    # both calls read the same pre-image, exactly one change reaches disk, and both report
    # success. A `fix_row` paired with an `append_block` could discard the repair while
    # telling the model it landed, leaving a window that looks shut and is not.
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

    ERGONOMICS, not a control — the model is not shown a verb it has nothing to use it on,
    and is shown it the moment it does. The offer is computed once per model REQUEST, so a
    model that saw the definition on an earlier turn can still emit the call after the window
    closed; `_tool_fix_row` re-derives and refuses. SEC3 rests on that body, never on this."""
    return tool_def if flagged_diagnostics(ctx.deps) else None


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
