"""Generic agent tools: bash, read_file, write_file, edit_file.

These four small tools are the agent's whole surface — stable across every
future adapter (a new data source is a shim + skill, never a new tool). They
mirror Claude Code's Read/Write/Edit/Bash so SKILL.md transfers verbatim. Each
tool enforces its own contract by calling the single `permission` gate and
raising `ModelRetry` on a deny (the in-process equivalent of a PreToolUse hook's
exit-2 feedback). Untrusted reads are wrapped in the salted tag in-process — the
clean version of the `tag_tool_results` annotation.
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Self

from defender._clock import now_iso
from defender._paths import PATHS

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import append_jsonl
from . import bash_exec
from . import permission
from .agent_definition import ToolSet
from .agent_role import AgentRole

# Reuse the hook/wrapper helpers in-process (the clean version of the claude -p
# PreToolUse hooks + the gather capture core). The workspace root is on sys.path
# via the entry-point bootstrap (run.py) / pytest's `pythonpath = [".."]`.
from defender.hooks.tag_tool_results import wrap as _wrap
from defender.scripts.gather_tools.record_query import (
    derive_system as _derive_system,
    _passthrough_max_bytes as _read_char_cap,
)
from defender.hooks.record_lesson_load import lesson_name as _lesson_name

_BASH_TIMEOUT_S = 120

# read_file char ceiling: the SAME source that caps the gather capture's
# passthrough (record_query._passthrough_max_bytes, imported here as
# _read_char_cap).
# A gather payload is persisted whole on disk, but the in-context VIEW of it —
# whether seen through the capture passthrough OR a later read_file of the same
# file — must stay bounded, or a multi-MB dump overflows the model's context
# window (#303). Sharing one source is the point: the on-disk read can never
# defeat the passthrough cap. Compared against str length (chars), matching
# record_query's own check.


def _bounded_read(text: str, path: str) -> str:
    """Bound a file read to the shared char cap (read at call time via
    `_read_char_cap()`). Under the cap → verbatim (the common case: every
    SKILL/lesson/doc fits with room to spare). Over it → the head, plus a notice
    carrying the FULL size (chars + lines, so the model knows the true scale it
    can't see) and the only resolution that works on a payload this big: filter
    on disk and read the filtered result. No paging — the files that overflow are
    single-document JSON dumps (one giant line), so an offset/limit window is a
    no-op; jq/grep is the way through. Slices by char, not byte, so a multibyte
    sequence is never split."""
    cap = _read_char_cap()
    if len(text) <= cap:
        return text
    total_lines = text.count("\n") + 1
    note = (
        f"\n\n[read_file] {len(text)} chars / {total_lines} line(s); showing the "
        f"first {cap}. This file is too large to read whole — do not "
        "treat this head as complete. Filter it on disk (jq, grep, the Grep tool), "
        f"write the result to a file, then read that:\n  jq '<filter>' {path}"
    )
    return text[:cap] + note


def _format_bash_result(exit_code: int, stdout: str, stderr: str, note: str = "") -> str:
    """The bash tool's result envelope, shared by the plain shell path and the
    transparent adapter-capture path so both surface results in one shape."""
    out = stdout if stdout else ""
    err = f"\n--- stderr ---\n{stderr}" if stderr.strip() else ""
    return f"exit={exit_code}\n--- stdout ---\n{out}{err}{note}"


# Per-agent gate policy is DATA, not a role branch: the gate keys on `deps.policy`.
# Every agent's policy is compiled PER-RUN through the single `bind`/`compile_policy`
# seam (#551) from its `AgentDefinition`: the runtime agents via `bind(MAIN_DEF/GATHER_DEF,
# run_dir, defender_dir=…)` (#535 anchors the reader lane to the run's roots — there is no
# module-level MAIN/GATHER default to inherit unconfined), the learning stages via
# `bind(<ROLE>_DEF, …)` in their own engine modules.


@dataclass(frozen=True)
class AgentDeps:
    """Per-run state threaded into every tool via `ctx.deps`. This base type is
    the main orchestrator's deps; each subagent gets an `AgentDeps` subtype. The
    permission gate keys on `policy` (the agent's declared capability, DATA — not a
    role branch), so adding an agent is a new policy value, not a new gate method.
    `role` remains only as an identity label (observability + the gather-capture
    `isinstance` narrow). Code that needs a subtype's fields narrows with
    `isinstance`.

    `policy` is REQUIRED (keyword-only, no inheritable default): a security-critical
    subtype can no longer be born MAIN-shaped by omitting it. Every subtype's `policy` is
    compiled at its construction site through the single `bind` seam (#551) — the per-run
    runtime agents (`GatherDeps`, and the main loop's bare `AgentDeps`) via
    `bind(MAIN_DEF/GATHER_DEF, run_dir, defender_dir=…)` (#535 anchors their reader lane
    per-run, so there is no static default), and the learning stages (`JudgeDeps`,
    `ActorDeps`, …) via `bind(<ROLE>_DEF, …)` in their engines. A subtype supplying none is a
    construction-time `TypeError`, not a silent MAIN."""

    run_dir: Path
    defender_dir: Path
    run_id: str
    salt: str
    policy: permission.AgentPolicy = field(kw_only=True)
    # The shared learning-state root, threaded into the bash tool's subprocess env as
    # DEFENDER_LEARNING_STATE_DIR (via `run_common.run_env`) so a curator's forward-check
    # resolves the real source-case bundle off it, not the throwaway worktree's empty runs/
    # (#425). None for the runtime agents (main/gather) that never spawn a state-root-bound
    # subprocess — the in-process twin of the retired `curator_agent_env`, carried on the deps
    # instead of mutating the process-global `os.environ`.
    state_root: Path | None = field(default=None, kw_only=True)

    role: ClassVar[AgentRole] = AgentRole.MAIN

    @classmethod
    def _for_run(
        cls, run_dir: Path, policy: permission.AgentPolicy,
        *, defender_dir: Path = PATHS.defender_dir, salt: str | None = None,
        state_root: Path | None = None,
    ) -> Self:
        """Build a per-run deps of this subtype: wire the identity fields (run_id as the
        run dir's basename, the salt) and stamp the caller's `policy`. The shared spine
        behind each subtype's `for_scope` and `bind`. `salt` is the untrusted-data trust
        token: `None` mints a FRESH uuid4 (the stages' behaviour, distinct per call), a
        carried value is threaded verbatim — the MAIN/GATHER reroute passes the run's ONE
        persisted salt so the tool-output wrapper and orient's alert wrapper stay coherent
        (a fresh uuid4 would split the tag and fail the injection defence open). `defender_dir`
        defaults to the `PATHS` primitive (the MAIN checkout's `<repo>/defender` — the
        read-only predictors + main loop), but a writer that edits a throwaway git WORKTREE
        (the lead author) overrides it with its worktree `<wt>/defender` so the gate resolves
        reads/writes against the right tree."""
        resolved_salt = salt if salt is not None else uuid.uuid4().hex
        return cls(
            run_dir=run_dir, defender_dir=defender_dir,
            run_id=run_dir.name, salt=resolved_salt, policy=policy,
            state_root=state_root,
        )


@dataclass(frozen=True)
class GatherDeps(AgentDeps):
    """Gather subagent deps: an AgentDeps + the lead being gathered. The harness reads
    `lead_id` here to attribute captured queries (it is never model-supplied to
    the capture path). The `GATHER` role drives the permission policy; code that
    needs the gather-only fields narrows with `isinstance(deps, GatherDeps)`.

    `query_id` is a fallback capture id stamped on the lead's queries when the
    model doesn't tag a call with `--query-id`; the gather leaves it unset
    (None) and tags per query, so capture falls back to record_query's
    `{system}.{verb}` default."""

    role: ClassVar[AgentRole] = AgentRole.GATHER

    # Since #535 the gather reader lane is anchored PER-RUN, so gather has no static
    # policy default (like the per-scope judge/actor): `policy` is REQUIRED from the
    # base (kw_only), built via `bind(GATHER_DEF, run_dir, defender_dir=…)` (#551)
    # at the construction site. A bare `GatherDeps(run_dir, defender_dir, run_id, salt)`
    # is now a construction-time TypeError, not a silent unconfined MAIN/GATHER.
    #
    # `lead_id` is the PER-DISPATCH capture id — UNSET (None) until the dispatch stamps it
    # (#538): `bind(GATHER_DEF, run_dir)` yields a per-run gather deps with `lead_id=None`
    # (bind is scope-only, no lead param), and the gather dispatch (`register_gather_tool`)
    # constructs/stamps the real id before any adapter capture runs. The capture path
    # asserts it is stamped.
    lead_id: str | None = None
    query_id: str | None = None


def _record_lesson_load(deps: AgentDeps, path: Path) -> None:
    """Append a `lessons_loaded.jsonl` row when a runtime lesson is read into
    context — the in-process equivalent of the `record_lesson_load` PostToolUse
    hook (reusing its `lesson_name` matcher), feeding learning/trace_lesson.py's
    lesson→outcome surface. Records loads into context, not demonstrable influence
    (same caveat as the hook). Best-effort — never breaks a read."""
    name = _lesson_name(str(path))
    if name is None:
        return
    try:
        row = {"lesson_name": name, "ts": now_iso()}
        append_jsonl(deps.run_dir / "lessons_loaded.jsonl", [row])
    except Exception:  # noqa: BLE001 — best-effort observability
        pass


def _bash_env(deps: AgentDeps) -> dict[str, str]:
    """The runtime agent's shell environment — defined once in run_common.py. `state_root`
    (set only by the curator deps) reaches the forward-check subprocess as
    DEFENDER_LEARNING_STATE_DIR through the deps, not a process-global env mutation."""
    from defender import run_common
    return run_common.run_env(deps.defender_dir, deps.run_dir, state_root=deps.state_root)


def _tool_bash(deps: AgentDeps, command: str) -> str:
    """Logic for the `bash` tool (see the closure's docstring). Module-level so the
    tool closure stays thin; the gather-vs-main adapter-capture path lives here."""
    decision = permission.decide_bash(
        command, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    # The gate parsed the command exactly once and stashed everything on the
    # decision (#456): the adapter/pipe routing the gather capture path needs and
    # the `Pipeline` list the executor runs — so neither dispatch nor execution
    # re-decomposes the string.
    #
    # Gather subagent (not the main session): a standalone adapter call is
    # captured transparently (the queries table + payload are written by the
    # harness), so the model never wraps it in record-query — it just runs the
    # adapter. `GatherDeps` IS the gather context and carries the lead_id/
    # query_id `_capture_adapter` records, so the isinstance narrow is both the
    # not-main-session test and the type evidence the capture path needs.
    if isinstance(deps, GatherDeps):
        if decision.adapter_argv is not None:
            tripped = _tripped_message(deps, _derive_system(decision.adapter_argv))
            if tripped is not None:
                return tripped
            return _capture_adapter(deps, decision.adapter_argv)
        # The sanctioned `adapter --raw | defender-sql '<SQL>'` aggregation pipe:
        # capture the adapter payload (queries table + by-ref file), then run the
        # captured bytes through the sandboxed defender-sql.
        if decision.sql_pipe is not None:
            adapter_av, sql_av = decision.sql_pipe
            tripped = _tripped_message(deps, _derive_system(adapter_av))
            if tripped is not None:
                return tripped
            return _capture_adapter_sql(deps, adapter_av, sql_av)
    # Execute the *validated* command without a shell: run the token structure the
    # gate already decomposed (shell=False) instead of re-handing the string to
    # bash. This collapses the validator/executor parser differential — `$VAR`,
    # globs, `$(...)`, and fused redirects never expand, because bash never
    # re-parses. See bash_exec for the rationale.
    try:
        rc, out, err = bash_exec.run_parsed(
            list(decision.pipelines or ()),
            command=command,
            env=_bash_env(deps),
            cwd=deps.defender_dir.parent,
            timeout=_BASH_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as e:
        raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}") from e
    return _format_bash_result(rc, out, err)


def _grep_lines(text: str, pattern: str) -> str:
    """The grep fold behind `read_file(pattern=)`: the lines of `text` that CONTAIN
    `pattern` (a plain substring match, like the read-only `grep` it replaces for a
    confined agent), newline-joined. Zero matches → `''` — a valid "nothing here"
    outcome, NOT an error (the caller returns it as-is)."""
    return "\n".join(line for line in text.splitlines() if pattern in line)


def _resolve_operand(deps: AgentDeps, path: str) -> Path:
    """Resolve a file-tool operand against the agent's repo root (`deps.defender_dir.parent`),
    matching the bash lane's cwd (`_tool_bash` runs the executor at `deps.defender_dir.parent`).
    A repo-relative operand — the lead-author writer's handoff paths (`defender/skills/…`) —
    then lands in the agent's own tree (its worktree), not the ambient process cwd; an absolute
    operand is unchanged (the read-only stages + the main loop pass absolute run-dir paths, so
    this is inert for them). Closes the file-vs-bash resolution differential the bash lane never
    had — the gate still `resolve()`s the result, so a `..` escape past the confine is still denied."""
    p = Path(path)
    return p if p.is_absolute() else deps.defender_dir.parent / p


def _tool_read_file(deps: AgentDeps, path: str, pattern: str | None = None) -> str:
    """Logic for the `read_file` tool: permission → (optional grep fold) → bound →
    untrusted-wrap. The gate runs FIRST, before any existence check, so a denied
    read raises the policy denial for an existing and an absent path alike — no
    existence oracle. An optional `pattern` folds grep into the read (return only
    the matching lines): search never widens the read surface — the confine gates
    the PATH before any scan — so a `pattern` over a denied path still raises."""
    p = _resolve_operand(deps, path)
    decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    if not p.is_file():
        raise ModelRetry(f"file not found: {path}")
    text = p.read_text()
    _record_lesson_load(deps, p)  # lesson→outcome traceability (best-effort)
    if pattern is not None:
        # grep fold: only the matching lines reach the model (the read-only bash
        # grep viewer a confined agent no longer has). No-match → '' (not an error).
        text = _grep_lines(text, pattern)
    # Bound the in-context view BEFORE wrapping: an oversized payload read
    # whole would overflow the model's window (#303). Cap first so the head is
    # what gets tag-wrapped (injected text in it stays inert), not the full dump.
    text = _bounded_read(text, path)
    if permission.is_untrusted_read(p):
        # Attacker-influenced data — wrap so injected instructions inside it
        # are inert. Same delimiter as the rest of the system.
        return _wrap(text, "untrusted", deps.salt)
    return text


def _tool_write_file(deps: AgentDeps, path: str, content: str) -> str:
    """Logic for the `write_file` tool: a validated write against the policy's
    `write_allow` (the agent's declared paths — the main loop's run dir, the
    lead-author writer's `defender/skills/**.md` corpus)."""
    p = _resolve_operand(deps, path)
    decision = permission.decide_write(
        p, content, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    # Mirror Claude Code's Write (which the claude -p stages used): create missing
    # parent dirs so a write into a not-yet-existing corpus subtree (the lead author
    # promoting/lifting into a new system dir) succeeds instead of raising an uncaught
    # FileNotFoundError — which run_stage maps to RunUnprocessable, quarantining the
    # whole run and discarding every valid in-tree edit already made. The gate ran
    # first, so we only ever mkdir under an allowed (write_allow) path.
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {path} ({len(content)} bytes)"


def _tool_edit_file(deps: AgentDeps, path: str, old_string: str, new_string: str) -> str:
    """Logic for the `edit_file` tool: gate the READ first, then the create-only /
    not-found / non-unique guards, then a validated write.

    The read gate (`decide_read`) runs BEFORE `p.read_text()` — parity with `read_file`.
    Without it, edit_file's differential `ModelRetry`s ("old_string not found" vs "not
    unique (N)") plus `p.is_file()` would be an existence / substring / occurrence-count
    oracle over ANY path the process can read (a `.env`, the eval `ground_truth.yaml`),
    bypassing the read confine + secret denylist that `read_file` enforces. Every path an
    agent may WRITE it may also READ (write_allow ⊆ read roots), so this denies no legit
    edit — it only closes the probe of files outside the agent's read surface."""
    p = _resolve_operand(deps, path)
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    current = p.read_text() if p.is_file() else ""
    if not old_string and p.is_file():
        # Empty old_string against an existing file would replace the WHOLE
        # file with new_string (silent clobber). Mirror Claude Code's Edit:
        # empty old_string is create-only. Use write_file for a full replace.
        raise ModelRetry(
            f"{path} already exists; an empty old_string would overwrite it. "
            "Pass a unique old_string to edit, or use write_file to replace it."
        )
    if old_string and old_string not in current:
        raise ModelRetry(f"old_string not found in {path}")
    if old_string and current.count(old_string) > 1:
        # Mirror Claude Code's Edit: a non-unique old_string is ambiguous.
        # Replacing the first match silently would edit the wrong occurrence
        # (e.g. a repeated invlang row marker) and can pass invlang validation.
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
    # Create-into-a-new-subtree parity with write_file (and Claude Code's Edit): mkdir
    # the parents of an approved path so a create edit into a fresh dir doesn't raise an
    # uncaught FileNotFoundError that quarantines the run. No-op on the common in-place
    # edit (parent already exists); only runs after the gate approved the path.
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(new_text)
    return f"edited {path} ({len(new_text)} bytes)"


def register_tools(agent, tools: ToolSet) -> None:
    """Register EXACTLY the tools `tools` declares present on `agent` (deps_type must
    be AgentDeps) — the single toolset-registration site (#538). There is no always-on
    pair: a tool exists iff its `ToolSet` bit is set, so the pure-prediction stages
    (`ToolSet()`) register NOTHING (structural tool-freeness, not a runtime gate), while
    main keeps all four. Registration order is fixed — `bash, read_file, write_file,
    edit_file` — independent of the `ToolSet` field order, so the pinned tool ordering
    the e2e suite asserts is stable. `bash` is present iff `tools.bash is not None`
    (a `BashGrammar()` with no programs still REGISTERS the tool — the gate then denies
    every command); the file writers are the `tools.write` opt-in (MAIN only)."""

    if tools.bash is not None:
        @agent.tool
        async def bash(ctx: RunContext[AgentDeps], command: str) -> str:
            """Run a shell command. Use the `defender-*` shims (defender-invlang,
            defender-lessons, …) for first-party tooling. Data-source adapters are
            not runnable from the main loop — dispatch gather instead."""
            return _tool_bash(ctx.deps, command)

    if tools.read:
        @agent.tool
        async def read_file(
            ctx: RunContext[AgentDeps], path: str, pattern: str | None = None
        ) -> str:
            """Read a file's contents (e.g. alert.json, a SKILL, a lesson). Pass
            `pattern` to return only the lines containing that substring — the grep
            fold, for scanning a large file (or when the read-only bash grep/cat
            viewers are not available to this agent)."""
            return _tool_read_file(ctx.deps, path, pattern)

    if tools.write:
        @agent.tool
        async def write_file(ctx: RunContext[AgentDeps], path: str, content: str) -> str:
            """Write a file in the run dir (investigation.md, report.md). Writes of
            investigation.md are validated against the invlang schema."""
            return _tool_write_file(ctx.deps, path, content)

        @agent.tool
        async def edit_file(
            ctx: RunContext[AgentDeps], path: str, old_string: str, new_string: str
        ) -> str:
            """Replace the first occurrence of old_string with new_string in a run-dir
            file. The resulting full text is validated (invlang for investigation.md)."""
            return _tool_edit_file(ctx.deps, path, old_string, new_string)


# --- gather dispatch & in-process adapter capture ----------------------------
# Lives in tools_gather.py (imports the foundation above). Re-exported here so
# the historical public surface holds: driver.py imports `register_gather_tool`
# from `.tools`, and tests/_tool_bash reach `tools._capture_adapter*`,
# `tools._run_gather`, etc. as attributes of THIS module (the e2e replay test
# monkeypatches `tools._run_gather`). Imported at the BOTTOM, after the
# foundation is defined, so the tools_gather → tools import resolves without a
# cycle.
from .tools_gather import (  # noqa: E402, F401  (re-exported — public surface)
    GatherRequest,
    _capture_adapter,
    _capture_adapter_sql,
    _capture_query,
    _extract_query_id,
    _gather_prompt,
    _payload_note,
    _persist_gather_summary,
    _run_gather,
    _tripped_message,
    register_gather_tool,
)
