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
import sys
from dataclasses import dataclass
from pathlib import Path

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry, UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

from . import permission

# `permission` import above bootstrapped defender/hooks onto sys.path; add
# scripts/tools/ for the capture core. Reuse the hook/wrapper helpers in-process
# (the clean version of the claude -p PreToolUse hooks).
_SCRIPTS_TOOLS = Path(__file__).resolve().parents[1] / "scripts" / "tools"
if str(_SCRIPTS_TOOLS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_TOOLS))

from tag_tool_results import wrap as _wrap  # noqa: E402
from record_lead import claim_lead as _claim_lead  # noqa: E402
from inject_system_skill_description import read_description as _read_description  # noqa: E402
from record_query import capture as _capture  # noqa: E402

_BASH_TIMEOUT_S = 120


@dataclass(frozen=True)
class RunDeps:
    """Per-run state threaded into every tool via `ctx.deps`."""

    run_dir: Path
    defender_dir: Path
    run_id: str
    salt: str
    is_main_session: bool = True


@dataclass(frozen=True)
class GatherDeps(RunDeps):
    """Gather subagent deps: RunDeps + the lead being gathered. The harness reads
    `lead_id` here to attribute captured queries (it is never model-supplied to
    the capture path). Always constructed with `is_main_session=False`."""

    lead_id: str = ""


def _bash_env(deps: RunDeps) -> dict[str, str]:
    """The runtime agent's shell environment — defined once in run.py and shared
    with the `claude -p` engine (defender/ is on sys.path[0] under run_pai)."""
    import run  # noqa: E402
    return run.run_env(deps.defender_dir, deps.run_dir)


def register_tools(agent) -> None:
    """Register the four generic tools on `agent` (deps_type must be RunDeps)."""

    @agent.tool
    async def bash(ctx: RunContext[RunDeps], command: str) -> str:
        """Run a shell command. Use the `defender-*` shims (defender-invlang,
        defender-lessons, …) for first-party tooling. Data-source adapters are
        not runnable from the main loop — dispatch gather instead."""
        decision = permission.decide_bash(
            command, is_main_session=ctx.deps.is_main_session
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        # Gather: a standalone adapter call is captured transparently (the queries
        # table + payload are written by the harness), so the model never wraps it
        # in record-query — it just runs the adapter.
        if not ctx.deps.is_main_session:
            argv = permission.adapter_argv(command)
            if argv is not None:
                return _capture_adapter(ctx.deps, argv)
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                env=_bash_env(ctx.deps), cwd=str(ctx.deps.defender_dir.parent),
                timeout=_BASH_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}")
        out = proc.stdout if proc.stdout else ""
        err = f"\n--- stderr ---\n{proc.stderr}" if proc.stderr.strip() else ""
        return f"exit={proc.returncode}\n--- stdout ---\n{out}{err}"

    @agent.tool
    async def read_file(ctx: RunContext[RunDeps], path: str) -> str:
        """Read a file's contents (e.g. alert.json, a SKILL, a lesson)."""
        decision = permission.decide_read(
            Path(path), is_main_session=ctx.deps.is_main_session
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        p = Path(path)
        if not p.is_file():
            raise ModelRetry(f"file not found: {path}")
        text = p.read_text()
        if permission.is_untrusted_read(p):
            # Attacker-influenced data — wrap so injected instructions inside it
            # are inert. Same delimiter as the rest of the system.
            return _wrap(text, "untrusted", ctx.deps.salt)
        return text

    @agent.tool
    async def write_file(ctx: RunContext[RunDeps], path: str, content: str) -> str:
        """Write a file in the run dir (investigation.md, report.md). Writes of
        investigation.md are validated against the invlang schema."""
        decision = permission.decide_write(
            Path(path), content, run_dir=ctx.deps.run_dir
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        Path(path).write_text(content)
        return f"wrote {path} ({len(content)} bytes)"

    @agent.tool
    async def edit_file(
        ctx: RunContext[RunDeps], path: str, old_string: str, new_string: str
    ) -> str:
        """Replace the first occurrence of old_string with new_string in a run-dir
        file. The resulting full text is validated (invlang for investigation.md)."""
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
        new_text = current.replace(old_string, new_string, 1) if old_string else new_string
        decision = permission.decide_write(p, new_text, run_dir=ctx.deps.run_dir)
        if not decision.allow:
            raise ModelRetry(decision.reason)
        p.write_text(new_text)
        return f"edited {path} ({len(new_text)} bytes)"


# --- gather dispatch (slice 2): main agent → nested Haiku gather agent --------

def _capture_adapter(deps: GatherDeps, argv: list[str]) -> str:
    """Run a standalone adapter command through the transparent capture (queries
    table + payload), returning the same shape the bash tool would. lead_id comes
    from deps — the harness owns capture; the model never supplies it."""
    try:
        passthrough, stderr, record = _capture(
            deps.run_dir, getattr(deps, "lead_id", ""), argv, env=_bash_env(deps)
        )
    except ValueError as e:
        raise ModelRetry(str(e))
    err = f"\n--- stderr ---\n{stderr}" if stderr.strip() else ""
    # Surface the persisted payload path (the gather SKILL filters against it for
    # large payloads) — mirrors the record_query CLI's stderr note.
    note = (
        f"\n[record_query] raw payload: {record['payload_path']}"
        if record.get("payload_path") else ""
    )
    return f"exit={record['exit_code']}\n--- stdout ---\n{passthrough}{err}{note}"


def _gather_prompt(
    deps: RunDeps, lead_id: str, system: str, goal: str,
    what_to_summarize: list[str], desc: str | None,
) -> str:
    """The gather subagent's user prompt: the dispatch block its SKILL reads,
    plus the injected system-SKILL description (relevance + where to read more)."""
    wts = "\n".join(f"  - {d}" for d in what_to_summarize) or "  - (unspecified)"
    block = (
        "Begin gathering this lead.\n\n"
        "## Dispatch\n```yaml\n"
        f"defender_dir: {deps.defender_dir}\n"
        f"run_dir: {deps.run_dir}\n"
        f"lead_id: {lead_id}\n"
        f"system: {system}\n"
        f"goal: {goal}\n"
        f"what_to_summarize:\n{wts}\n"
        "```\n"
    )
    if desc:
        block += f"\n## System `{system}` (from its SKILL frontmatter)\n{desc}\n"
    return block


_LEAD_REUSE_RETRY = (
    "lead_id {lead_id!r} is already dispatched — a retry is a NEW lead: append a "
    "fresh :L findings row and echo its new id (the :L set is append-only, never "
    "reuse an id)."
)


async def _run_gather(
    deps: RunDeps, usage, gather_factory, request_limit: int,
    lead_id: str, system: str, goal: str, what_to_summarize: list[str],
) -> str:
    """The gather dispatch, factored out of the tool closure so it's testable
    without the main model: claim the lead → inject the system description → run
    the nested gather agent → wrap the summary."""
    # 1. Claim the lead id (atomic O_EXCL); a reused id bounces back to PLAN.
    if _claim_lead({
        "run_dir": str(deps.run_dir), "lead_id": lead_id,
        "goal": goal, "what_to_summarize": what_to_summarize,
    }) == 2:
        raise ModelRetry(_LEAD_REUSE_RETRY.format(lead_id=lead_id))

    # 2. Inject the target system's SKILL description (relevance + pointer).
    desc = _read_description(system)

    # 3. Run the nested gather agent; fold its usage into the run total.
    gagent = gather_factory(f"gather:{lead_id}")
    gdeps = GatherDeps(
        run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        run_id=deps.run_id, salt=deps.salt, is_main_session=False, lead_id=lead_id,
    )
    prompt = _gather_prompt(deps, lead_id, system, goal, what_to_summarize, desc)
    try:
        result = await gagent.run(
            prompt, deps=gdeps, usage=usage,
            usage_limits=UsageLimits(request_limit=request_limit),
        )
        output = str(result.output or "")
    except UsageLimitExceeded as e:
        output = (
            f"gather for {lead_id} hit its request limit ({e}) before finishing; "
            "any queries it ran are in the queries table. Treat this lead as "
            "incomplete and reason from what was captured."
        )

    # 4. Wrap the summary as untrusted — it's the primary attacker-influenced
    # channel into the main loop. Same salt as the rest of the run.
    return _wrap(output, "untrusted", deps.salt)


def register_gather_tool(main_agent, gather_factory, request_limit: int) -> None:
    """Register the `gather` dispatch tool on the MAIN agent only (the gather
    subagent must not self-dispatch). `gather_factory(agent_id)` builds a fresh
    nested gather Agent (Haiku, with the gather SKILL as its instructions) bound
    to that observability id."""

    @main_agent.tool
    async def gather(
        ctx: RunContext[RunDeps], lead_id: str, system: str,
        goal: str, what_to_summarize: list[str],
    ) -> str:
        """Dispatch the gather subagent (Haiku) to measure one lead against a
        system of record. `lead_id` echoes this lead's `:L` row id (append-only —
        a retry is a new row with a new id). `system` is the `:L` row's system,
        `goal` a one-sentence measurement contract, `what_to_summarize` the
        dimensions the summary must cover. Returns a measurements-only summary;
        the queries it runs are captured to the queries table automatically. Issue
        multiple `gather` calls in one turn to dispatch sibling leads in parallel."""
        return await _run_gather(
            ctx.deps, ctx.usage, gather_factory, request_limit,
            lead_id, system, goal, what_to_summarize,
        )
