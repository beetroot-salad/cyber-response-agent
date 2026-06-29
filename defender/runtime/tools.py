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
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender._clock import now_iso

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import append_jsonl
from . import bash_exec
from . import permission
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


@dataclass(frozen=True)
class RunDeps:
    """Per-run state threaded into every tool via `ctx.deps`. This base type is
    the main orchestrator's deps; each subagent gets a `RunDeps` subtype. The
    agent's identity lives in one place — the `role` class constant — so the
    permission gate keys on it (not a main/not-main bool, which would cap the
    runtime at two agents); code that needs a subtype's fields narrows with
    `isinstance`."""

    run_dir: Path
    defender_dir: Path
    run_id: str
    salt: str

    role: ClassVar[AgentRole] = AgentRole.MAIN


@dataclass(frozen=True)
class GatherDeps(RunDeps):
    """Gather subagent deps: RunDeps + the lead being gathered. The harness reads
    `lead_id` here to attribute captured queries (it is never model-supplied to
    the capture path). The `GATHER` role drives the permission policy; code that
    needs the gather-only fields narrows with `isinstance(deps, GatherDeps)`.

    `query_id` is a fallback capture id stamped on the lead's queries when the
    model doesn't tag a call with `--query-id`; the gather leaves it unset
    (None) and tags per query, so capture falls back to record_query's
    `{system}.{verb}` default."""

    role: ClassVar[AgentRole] = AgentRole.GATHER

    lead_id: str = ""
    query_id: str | None = None


def _record_lesson_load(deps: RunDeps, path: Path) -> None:
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


def _bash_env(deps: RunDeps) -> dict[str, str]:
    """The runtime agent's shell environment — defined once in run_common.py."""
    from defender import run_common
    return run_common.run_env(deps.defender_dir, deps.run_dir)


def _tool_bash(deps: RunDeps, command: str) -> str:
    """Logic for the `bash` tool (see the closure's docstring). Module-level so the
    tool closure stays thin; the gather-vs-main adapter-capture path lives here."""
    decision = permission.decide_bash(
        command, role=deps.role,
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


def _tool_read_file(deps: RunDeps, path: str) -> str:
    """Logic for the `read_file` tool: permission → bound → untrusted-wrap."""
    decision = permission.decide_read(
        Path(path), run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        role=deps.role,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    p = Path(path)
    if not p.is_file():
        raise ModelRetry(f"file not found: {path}")
    text = p.read_text()
    _record_lesson_load(deps, p)  # lesson→outcome traceability (best-effort)
    # Bound the in-context view BEFORE wrapping: an oversized payload read
    # whole would overflow the model's window (#303). Cap first so the head is
    # what gets tag-wrapped (injected text in it stays inert), not the full dump.
    text = _bounded_read(text, path)
    if permission.is_untrusted_read(p):
        # Attacker-influenced data — wrap so injected instructions inside it
        # are inert. Same delimiter as the rest of the system.
        return _wrap(text, "untrusted", deps.salt)
    return text


def _tool_write_file(deps: RunDeps, path: str, content: str) -> str:
    """Logic for the `write_file` tool: a validated run-dir write."""
    decision = permission.decide_write(
        Path(path), content, run_dir=deps.run_dir
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    Path(path).write_text(content)
    return f"wrote {path} ({len(content)} bytes)"


def _tool_edit_file(deps: RunDeps, path: str, old_string: str, new_string: str) -> str:
    """Logic for the `edit_file` tool: the create-only / not-found / non-unique
    guards, then a validated write."""
    p = Path(path)
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
    decision = permission.decide_write(p, new_text, run_dir=deps.run_dir)
    if not decision.allow:
        raise ModelRetry(decision.reason)
    p.write_text(new_text)
    return f"edited {path} ({len(new_text)} bytes)"


def register_tools(agent, *, writers: bool = True) -> None:
    """Register the generic tools on `agent` (deps_type must be RunDeps).

    `writers=True` (the main agent) registers all four: bash, read_file,
    write_file, edit_file. `writers=False` (the gather subagent) registers only
    the read-only pair (bash + read_file) — gather's contract is to measure and
    return a summary, never to author run-dir artifacts, so it gets no file
    writers at all (the gate would block its investigation.md writes anyway, but
    not the stray summary.md / gather_summary.md ones; withholding the tools is
    the clean lane boundary)."""

    @agent.tool
    async def bash(ctx: RunContext[RunDeps], command: str) -> str:
        """Run a shell command. Use the `defender-*` shims (defender-invlang,
        defender-lessons, …) for first-party tooling. Data-source adapters are
        not runnable from the main loop — dispatch gather instead."""
        return _tool_bash(ctx.deps, command)

    @agent.tool
    async def read_file(ctx: RunContext[RunDeps], path: str) -> str:
        """Read a file's contents (e.g. alert.json, a SKILL, a lesson)."""
        return _tool_read_file(ctx.deps, path)

    # Gather stops here: read-only surface (bash + read_file), no file writers.
    if not writers:
        return

    @agent.tool
    async def write_file(ctx: RunContext[RunDeps], path: str, content: str) -> str:
        """Write a file in the run dir (investigation.md, report.md). Writes of
        investigation.md are validated against the invlang schema."""
        return _tool_write_file(ctx.deps, path, content)

    @agent.tool
    async def edit_file(
        ctx: RunContext[RunDeps], path: str, old_string: str, new_string: str
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
