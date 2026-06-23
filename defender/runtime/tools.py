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

from . import bash_exec
from . import circuit_breaker
from . import permission

# Reuse the hook/wrapper helpers in-process (the clean version of the claude -p
# PreToolUse hooks + the gather capture core). The workspace root is on sys.path
# via the entry-point bootstrap (run.py) / pytest's `pythonpath = [".."]`.
from defender.hooks.tag_tool_results import wrap as _wrap
from defender.hooks.record_lead import claim_lead as _claim_lead
from defender.hooks.inject_system_skill_description import descriptor_catalog as _descriptor_catalog
from defender.scripts.gather_tools.record_query import (
    capture as _capture,
    derive_system as _derive_system,
    LEAD_ID_RE as _LEAD_ID_RE,
    PASSTHROUGH_MAX_BYTES as _READ_CHAR_CAP,
)
from defender.hooks.record_lesson_load import lesson_name as _lesson_name

_BASH_TIMEOUT_S = 120

# read_file char ceiling: the SAME constant that caps the gather capture's
# passthrough (record_query.PASSTHROUGH_MAX_BYTES). A gather payload is persisted
# whole on disk, but the in-context VIEW of it — whether seen through the capture
# passthrough OR a later read_file of the same file — must stay bounded, or a
# multi-MB dump overflows the model's context window (#303). Sharing one constant
# is the point: the on-disk read can never defeat the passthrough cap. Compared
# against str length (chars), matching record_query's own check.


def _bounded_read(text: str, path: str) -> str:
    """Bound a file read to `_READ_CHAR_CAP` chars. Under the cap → verbatim (the
    common case: every SKILL/lesson/doc fits with room to spare). Over it → the
    head, plus a notice carrying the FULL size (chars + lines, so the model knows
    the true scale it can't see) and the only resolution that works on a payload
    this big: filter on disk and read the filtered result. No paging — the files
    that overflow are single-document JSON dumps (one giant line), so an
    offset/limit window is a no-op; jq/grep is the way through. Slices by char,
    not byte, so a multibyte sequence is never split."""
    if len(text) <= _READ_CHAR_CAP:
        return text
    total_lines = text.count("\n") + 1
    note = (
        f"\n\n[read_file] {len(text)} chars / {total_lines} line(s); showing the "
        f"first {_READ_CHAR_CAP}. This file is too large to read whole — do not "
        "treat this head as complete. Filter it on disk (jq, grep, the Grep tool), "
        f"write the result to a file, then read that:\n  jq '<filter>' {path}"
    )
    return text[:_READ_CHAR_CAP] + note


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
    the capture path). Always constructed with `is_main_session=False`.

    `query_id` is a fallback capture id stamped on the lead's queries when the
    model doesn't tag a call with `--query-id`; the gather leaves it unset
    (None) and tags per query, so capture falls back to record_query's
    `{system}.{verb}` default."""

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
        row = {"lesson_name": name, "ts": datetime.now(UTC).isoformat(timespec="seconds")}
        with (deps.run_dir / "lessons_loaded.jsonl").open("a") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception:  # noqa: BLE001 — best-effort observability
        pass


def _bash_env(deps: RunDeps) -> dict[str, str]:
    """The runtime agent's shell environment — defined once in run_common.py."""
    from defender import run_common
    return run_common.run_env(deps.defender_dir, deps.run_dir)


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
        decision = permission.decide_bash(
            command, is_main_session=ctx.deps.is_main_session,
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        # Gather subagent (not the main session): a standalone adapter call is
        # captured transparently (the queries table + payload are written by the
        # harness), so the model never wraps it in record-query — it just runs the
        # adapter.
        if not ctx.deps.is_main_session:
            argv = permission.adapter_argv(command)
            if argv is not None:
                system = _derive_system(argv)
                # Circuit-breaker in-gather gate: refuse a call to a system already
                # tripped this run before it runs again, so one dispatch can't keep
                # hammering a dead source. RETURN the down-message (don't raise
                # ModelRetry): a tripped system won't recover within the run, so a
                # retry is pointless, and if the model re-issued the same call it
                # would burn the bash tool's retry budget into an UnexpectedModel-
                # Behavior that crashes the run instead of writing a partial trace.
                # Returning mirrors the dispatch gate in _run_gather.
                if system and circuit_breaker.is_tripped(ctx.deps.run_dir, system):
                    return circuit_breaker.down_message(ctx.deps.run_dir, system)
                return _capture_adapter(ctx.deps, argv)
        # Execute the *validated* command without a shell: the gate already
        # decomposed it with shlex, so run that token structure directly
        # (shell=False) instead of re-handing the string to bash. This collapses
        # the validator/executor parser differential — `$VAR`, globs, `$(...)`,
        # and fused redirects never expand, because bash never re-parses. See
        # bash_exec for the rationale.
        try:
            rc, out, err = bash_exec.run_pipeline(
                command,
                env=_bash_env(ctx.deps),
                cwd=ctx.deps.defender_dir.parent,
                timeout=_BASH_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired as e:
            raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}") from e
        return _format_bash_result(rc, out, err)

    @agent.tool
    async def read_file(ctx: RunContext[RunDeps], path: str) -> str:
        """Read a file's contents (e.g. alert.json, a SKILL, a lesson)."""
        decision = permission.decide_read(
            Path(path), is_main_session=ctx.deps.is_main_session,
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        p = Path(path)
        if not p.is_file():
            raise ModelRetry(f"file not found: {path}")
        text = p.read_text()
        _record_lesson_load(ctx.deps, p)  # lesson→outcome traceability (best-effort)
        # Bound the in-context view BEFORE wrapping: an oversized payload read
        # whole would overflow the model's window (#303). Cap first so the head is
        # what gets tag-wrapped (injected text in it stays inert), not the full dump.
        text = _bounded_read(text, path)
        if permission.is_untrusted_read(p):
            # Attacker-influenced data — wrap so injected instructions inside it
            # are inert. Same delimiter as the rest of the system.
            return _wrap(text, "untrusted", ctx.deps.salt)
        return text

    # Gather stops here: read-only surface (bash + read_file), no file writers.
    if not writers:
        return

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

def _extract_query_id(argv: list[str]) -> tuple[list[str], str | None]:
    """Pull a model-supplied ``--query-id <id>`` (or ``--query-id=<id>``) off an
    adapter argv, returning (cleaned argv the adapter actually runs, the id).

    The single-agent gather annotates each bare adapter call with the catalog
    id it bound (e.g. ``elastic.sshd-auth-history``) or a coined id, because one
    lead can run several queries with different bindings and a single
    ``deps.query_id`` can't carry them. The harness strips the flag so the adapter
    never sees it; capture records it as the queries-table ``query_id`` (the
    ``(query_id, params)`` join the offline lead-author relies on). Position-
    independent; absent → None, and capture falls back to ``deps.query_id`` then
    record_query's ``{system}.{verb}`` default."""
    out: list[str] = []
    qid: str | None = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--query-id":
            # `--query-id <id>` consumes its value; a trailing `--query-id` with
            # no value is still consumed (dropped), never passed through — the
            # adapter's argparse would reject the unknown flag and fail the query.
            if i + 1 < len(argv):
                qid = argv[i + 1]
                i += 2
            else:
                i += 1
            continue
        if a.startswith("--query-id="):
            qid = a.split("=", 1)[1]
            i += 1
            continue
        out.append(a)
        i += 1
    return out, qid


def _capture_adapter(deps: GatherDeps, argv: list[str]) -> str:
    """Run a standalone adapter command through the transparent capture (queries
    table + payload), returning the same shape the bash tool would. lead_id comes
    from deps — the harness owns capture; the model never supplies it. The model
    MAY tag the call with ``--query-id <id>`` (stripped here) to bind the query to
    a catalog id; otherwise ``deps.query_id`` (the finder/executor split's bound
    id) or record_query's default applies."""
    argv, model_query_id = _extract_query_id(argv)
    try:
        passthrough, stderr, record = _capture(
            deps.run_dir, deps.lead_id, argv, env=_bash_env(deps),
            query_id=model_query_id or deps.query_id,
        )
    except ValueError as e:
        raise ModelRetry(str(e)) from e
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
            "\n## Systems of record (descriptor index — frontmatter only, "
            f"progressive disclosure). Your target is `system: {system}` above; "
            "confirm it here. These descriptions are usually enough to pick a "
            f"template or name a measurement — Read the target's full "
            f"`{deps.defender_dir}/skills/{system}/SKILL.md` (and execution.md if "
            "present) ONLY on demand, when you need field vocab or CLI specifics the "
            "descriptor lacks; not on every dispatch.\n\n"
            f"{catalog}\n"
        )
    return block


_LEAD_REUSE_RETRY = (
    "lead_id {lead_id!r} is already dispatched — a retry is a NEW lead: append a "
    "fresh :L findings row and echo its new id (the :L set is append-only, never "
    "reuse an id)."
)


def _persist_gather_summary(run_dir: Path, lead_id: str, wrapped: str) -> None:
    """Persist the wrapped gather summary to `{run_dir}/gather_summaries/{lead_id}.md`.

    The recovery surface for per-loop compaction (design doc §Recovery): when
    the main loop's history is compacted to the invlang frontier, a summary it
    later needs is a cheap Read away instead of a gather re-dispatch. Best-effort
    — a failed persist must never break the run (the in-context summary is still
    returned)."""
    try:
        d = run_dir / "gather_summaries"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{lead_id}.md").write_text(wrapped)
    except Exception as e:  # noqa: BLE001 — persistence must never break the run
        print(f"[run.py] gather-summary persist skipped for {lead_id}: {e!r}",
              file=sys.stderr)


async def _run_gather(
    deps: RunDeps, gather_factory, request_limit: int,
    lead_id: str, system: str, goal: str, what_to_summarize: list[str],
) -> str:
    """The gather dispatch, factored out of the tool closure so it's testable
    without the main model: claim the lead → inject the descriptor catalog → run
    the nested gather agent → wrap the summary. The single-agent gather
    (#340) auto-captures its own adapter calls; there is no finder/assay layer."""
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
    wrapped = _wrap(output, "untrusted", deps.salt)
    # 5. Persist the wrapped summary so the main loop can re-read it if per-loop
    # compaction later drops it from context (recovery path, design doc
    # §Recovery). It's the summary, not raw payloads, so this respects the #264
    # isolation invariant — and it lives OUTSIDE gather_raw/, so decide_read
    # permits the main-loop read; stored pre-wrapped so a re-read stays
    # untrusted-tagged (is_untrusted_read keys on gather_raw/, so no double-wrap).
    _persist_gather_summary(deps.run_dir, lead_id, wrapped)
    return wrapped


def register_gather_tool(
    main_agent, gather_factory, request_limit: int,
) -> None:
    """Register the `gather` dispatch tool on the MAIN agent only (the gather
    subagent must not self-dispatch). `gather_factory(agent_id)` builds a fresh
    nested gather Agent bound to that observability id."""

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
