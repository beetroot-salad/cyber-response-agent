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

import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry, UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

from . import circuit_breaker
from . import permission

# `permission` import above bootstrapped defender/hooks onto sys.path; add
# scripts/tools/ for the capture core. Reuse the hook/wrapper helpers in-process
# (the clean version of the claude -p PreToolUse hooks).
_SCRIPTS_TOOLS = Path(__file__).resolve().parents[1] / "scripts" / "tools"
if str(_SCRIPTS_TOOLS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_TOOLS))

from tag_tool_results import wrap as _wrap  # noqa: E402
from record_lead import claim_lead as _claim_lead  # noqa: E402
from inject_system_skill_description import descriptor_catalog as _descriptor_catalog  # noqa: E402
from record_query import capture as _capture, derive_system as _derive_system, LEAD_ID_RE as _LEAD_ID_RE  # noqa: E402
from record_lesson_load import lesson_name as _lesson_name  # noqa: E402

_BASH_TIMEOUT_S = 120


def _format_bash_result(exit_code: int, stdout: str, stderr: str, note: str = "") -> str:
    """The bash tool's result envelope, shared by the plain shell path and the
    transparent adapter-capture path so both surface results in one shape."""
    out = stdout if stdout else ""
    err = f"\n--- stderr ---\n{stderr}" if stderr.strip() else ""
    return f"exit={exit_code}\n--- stdout ---\n{out}{err}{note}"


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
        row = {"lesson_name": name, "ts": datetime.now(UTC).isoformat(timespec="seconds")}
        with (deps.run_dir / "lessons_loaded.jsonl").open("a") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception:  # noqa: BLE001 — best-effort observability
        pass


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
                # Circuit-breaker in-gather gate: refuse a call to a system already
                # tripped this run before it runs again, so one dispatch can't keep
                # hammering a dead source. RETURN the down-message (don't raise
                # ModelRetry): a tripped system won't recover within the run, so a
                # retry is pointless, and if the model re-issued the same call it
                # would burn the bash tool's retry budget into an UnexpectedModel-
                # Behavior that crashes the run instead of writing a partial trace.
                # Returning mirrors the dispatch gate in _run_gather.
                system = _derive_system(argv)
                if system and circuit_breaker.is_tripped(ctx.deps.run_dir, system):
                    return circuit_breaker.down_message(ctx.deps.run_dir, system)
                return _capture_adapter(ctx.deps, argv)
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                env=_bash_env(ctx.deps), cwd=str(ctx.deps.defender_dir.parent),
                timeout=_BASH_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}")
        return _format_bash_result(proc.returncode, proc.stdout, proc.stderr)

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
        _record_lesson_load(ctx.deps, p)  # lesson→outcome traceability (best-effort)
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
            deps.run_dir, deps.lead_id, argv, env=_bash_env(deps)
        )
    except ValueError as e:
        raise ModelRetry(str(e))
    # Circuit breaker: record this system call's outcome. An infra failure
    # (connectivity/auth exit, or timeout) advances the per-system counter and may
    # raise RunAborted via the run-wide kill switch (caught by the driver, which
    # writes the partial trace). record['system'] is the system the capture bound
    # the query to — authoritative over re-deriving from argv.
    circuit_breaker.record_outcome(
        deps.run_dir, record.get("system", ""), record["exit_code"]
    )
    # Surface the persisted payload path (the gather SKILL filters against it for
    # large payloads). Report it ABSOLUTE: the bash/read tools resolve relative to
    # the repo root, not run_dir, so the relative table FK (record['payload_path'])
    # would be unresolvable. Matches build_truncated_view's absolute path.
    note = (
        f"\n[record_query] raw payload: {deps.run_dir / record['payload_path']}"
        if record.get("payload_path") else ""
    )
    return _format_bash_result(record["exit_code"], passthrough, stderr, note)


def _gather_prompt(
    deps: RunDeps, lead_id: str, system: str, goal: str,
    what_to_summarize: list[str], catalog: str | None,
) -> str:
    """The gather subagent's user prompt: the dispatch block its SKILL reads, plus
    the descriptor catalog (every data-source system + its one-line description) —
    the progressive-disclosure index. Gather confirms its target (`system:` above)
    from the catalog, then Reads that system's full SKILL.md + execution.md on
    demand. Falls back to no catalog when it can't be built."""
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
    if catalog:
        block += (
            "\n## Systems of record (descriptor index — your target is "
            f"`system: {system}` above; confirm it here, then Read that system's "
            "full SKILL.md + execution.md before querying)\n\n"
            f"{catalog}\n"
        )
    return block


_LEAD_REUSE_RETRY = (
    "lead_id {lead_id!r} is already dispatched — a retry is a NEW lead: append a "
    "fresh :L findings row and echo its new id (the :L set is append-only, never "
    "reuse an id)."
)


async def _run_gather(
    deps: RunDeps, gather_factory, request_limit: int,
    lead_id: str, system: str, goal: str, what_to_summarize: list[str],
) -> str:
    """The gather dispatch, factored out of the tool closure so it's testable
    without the main model: claim the lead → inject the system description → run
    the nested gather agent → wrap the summary."""
    # 0. Fail fast on a malformed lead_id. claim_lead treats a bad id as a benign
    # skip (returns 0, no sidecar), which would otherwise half-dispatch the lead
    # (nested agent spawned, no leads-table row) until capture() later rejects the
    # same id mid-run. Reject it here, with the grammar the FK actually uses.
    if not _LEAD_ID_RE.match(lead_id):
        raise ModelRetry(
            f"invalid lead_id {lead_id!r}: echo the :L findings row id (an `l-` id) "
            "verbatim — it is the FK joining the leads and queries tables."
        )
    # 1. Claim the lead id (atomic O_EXCL); a reused id bounces back to PLAN.
    if _claim_lead({
        "run_dir": str(deps.run_dir), "lead_id": lead_id,
        "goal": goal, "what_to_summarize": what_to_summarize,
    }) == 2:
        raise ModelRetry(_LEAD_REUSE_RETRY.format(lead_id=lead_id))

    # 1b. Circuit-breaker dispatch gate: if this system is down for the run, do
    # not spawn gather and do not inject its SKILL — the block is transparent to
    # the main loop, which gets a measurement-shaped "system down" summary it can
    # reason from (and must not re-dispatch). The lead is already claimed above, so
    # it shows in the leads table as planned-but-unmeasured. Returned UNWRAPPED:
    # this is a trusted harness control message, not attacker-influenced data, so
    # the "do not re-dispatch" directive must survive the untrusted-content rule.
    # Generalizes to MCP — a tripped system's server/toolset simply isn't attached.
    if circuit_breaker.is_tripped(deps.run_dir, system):
        return circuit_breaker.down_message(deps.run_dir, system)

    # 2. Inject the descriptor catalog (all data-source systems + descriptions) —
    # the progressive-disclosure index. Gather confirms its target from it, then
    # Reads that system's full SKILL.md + execution.md on demand.
    catalog = _descriptor_catalog()

    # 3. Run the nested gather agent. It gets its OWN usage object: sharing the
    # main run's usage would make request_limit (a cumulative check) abort gather
    # the moment the main loop has already issued `request_limit` requests, so the
    # per-lead cap would not bound gather's own requests. Cost still folds in — the
    # request log (observe.write_trace) sums every instance's usage independently.
    gagent = gather_factory(f"gather:{lead_id}")
    gdeps = GatherDeps(
        run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        run_id=deps.run_id, salt=deps.salt, is_main_session=False, lead_id=lead_id,
    )
    prompt = _gather_prompt(deps, lead_id, system, goal, what_to_summarize, catalog)
    try:
        result = await gagent.run(
            prompt, deps=gdeps,
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
            ctx.deps, gather_factory, request_limit,
            lead_id, system, goal, what_to_summarize,
        )
