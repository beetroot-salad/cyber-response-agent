"""Gather dispatch & in-process adapter capture: the main agent → nested gather
subagent path, factored out of the generic-tools foundation in `tools.py`.

The transparent adapter-capture core (`_capture_adapter`, `_capture_adapter_sql`
and their `_capture_query` prelude) is what `tools._tool_bash` reaches for when a
`GatherDeps`-scoped bash call runs a standalone adapter; `register_gather_tool`
installs the main agent's `gather` dispatch tool, whose `_run_gather` drives the
nested subagent. These import the shared foundation (`RunDeps`, `GatherDeps`,
`_format_bash_result`, `_bash_env`, `_BASH_TIMEOUT_S`) from `tools.py`; `tools.py`
re-exports the names back at its own module bottom (after the foundation is
defined), so there is no import cycle.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry, UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

from . import circuit_breaker
# Import the `tools` MODULE (not just the names) so the gather tool closure can
# resolve `_run_gather` as a module attribute at call time — that is the
# reference tests/e2e/test_replay_skeleton.py monkeypatches
# (`setattr(runtime_tools, "_run_gather", …)`). A bare same-module call would not
# be interceptable.
from . import tools
from .tools import (
    GatherDeps,
    RunDeps,
    _BASH_TIMEOUT_S,
    _bash_env,
    _format_bash_result,
)

from defender.hooks.record_lead import claim_lead as _claim_lead
from defender.hooks.inject_system_skill_description import descriptor_catalog as _descriptor_catalog
from defender.hooks.tag_tool_results import wrap as _wrap
from defender.scripts.gather_tools.record_query import (
    capture as _capture,
    LEAD_ID_RE as _LEAD_ID_RE,
)


# --- gather dispatch (slice 2): main agent → nested Haiku gather agent --------

@dataclass(frozen=True)
class GatherRequest:
    """The one lead the model dispatches `gather` to measure: the four
    model-supplied dimensions as a single value object, threaded by reference
    through the dispatch chain (closure → `_run_gather` → `_gather_prompt`)
    instead of four loose positional args.

    Built INSIDE the `gather` tool closure from its params — the closure's
    signature is the model-facing tool schema, so the model still emits the four
    fields separately; this object never reaches the schema. `what_to_summarize`
    is stored as a tuple (the schema's `list[str]`, frozen at the boundary) so the
    value object is fully immutable + hashable, matching the lead value object in
    `learning/leads/lead_extraction.py`. `GatherDeps.lead_id` (the gather
    subagent's capture-path deps) is a distinct layer, constructed from `lead_id`
    here."""

    lead_id: str
    system: str
    goal: str
    what_to_summarize: tuple[str, ...]


def _extract_query_id(argv: list[str]) -> tuple[list[str], str | None]:
    """Pull a model-supplied ``--query-id <id>`` (or ``--query-id=<id>``) off an
    adapter argv, returning (cleaned argv the adapter actually runs, the id).

    The single-agent gather annotates each bare adapter call with the catalog
    id it bound (e.g. ``{system}.sshd-auth-history``) or a coined id, because one
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


def _tripped_message(deps: GatherDeps, system: str | None) -> str | None:
    """Circuit-breaker in-gather gate: if `system` is already tripped this run,
    return its down-message so one dispatch can't keep hammering a dead source;
    else None (proceed). RETURN the message (don't raise ModelRetry): a tripped
    system won't recover within the run, so a retry is pointless, and a re-issued
    call would burn the bash tool's retry budget into an UnexpectedModelBehavior
    that crashes the run instead of writing a partial trace. Mirrors the dispatch
    gate in _run_gather."""
    if system and circuit_breaker.is_tripped(deps.run_dir, system):
        return circuit_breaker.down_message(deps.run_dir, system)
    return None


def _capture_query(
    deps: GatherDeps, argv: list[str], env: dict[str, str]
) -> tuple[str, str, dict]:
    """Shared adapter-capture prelude for the gather bash tool: strip a model
    ``--query-id``, run the transparent capture (queries table + by-ref payload),
    and record the circuit-breaker outcome. Returns ``(passthrough, stderr,
    record)``. Raises ``ModelRetry`` on the structural ``ValueError`` capture raises
    (undetectable system / malformed lead id) so the model can correct and retry.

    The circuit breaker keys on ``record['system']`` (the system the capture bound
    the query to — authoritative over re-deriving from argv); an infra failure
    advances the per-system counter and may raise RunAborted via the run-wide kill
    switch (caught by the driver, which writes the partial trace)."""
    argv, model_query_id = _extract_query_id(argv)
    try:
        passthrough, stderr, record = _capture(
            deps.run_dir, deps.lead_id, argv, env=env,
            query_id=model_query_id or deps.query_id,
        )
    except ValueError as e:
        raise ModelRetry(str(e)) from e
    circuit_breaker.record_outcome(
        deps.run_dir, record.get("system", ""), record["exit_code"]
    )
    return passthrough, stderr, record


def _payload_note(deps: GatherDeps, record: dict) -> str:
    """The ``[record_query] raw payload: <path>`` line the gather SKILL filters
    against for large payloads, or "" when no payload was persisted. Report it
    ABSOLUTE: the bash/read tools resolve relative to the repo root, not run_dir, so
    the relative table FK (``record['payload_path']``) would be unresolvable.
    Matches build_truncated_view's absolute path."""
    return (
        f"\n[record_query] raw payload: {deps.run_dir / record['payload_path']}"
        if record.get("payload_path") else ""
    )


def _capture_adapter_sql(
    deps: GatherDeps, adapter_argv: list[str], sql_argv: list[str]
) -> str:
    """The `adapter --raw | defender-sql '<SQL>'` pipe (gather only). Capture the
    adapter's raw payload (queries table + by-ref file), then aggregate that
    payload through the sandboxed defender-sql on stdin. The queries-table row
    records the adapter query (audited); defender-sql is a local, self-sandboxed
    transform over the captured bytes — not a second data-source query, so it is
    not separately recorded."""
    env = _bash_env(deps)
    passthrough, stderr, record = _capture_query(deps, adapter_argv, env)
    note = _payload_note(deps, record)
    # The adapter itself failed → surface ITS error (exit code + stderr), exactly as
    # the standalone _capture_adapter path does, instead of piping an empty/partial
    # payload into defender-sql and returning its confusing "no input on stdin"
    # error. capture() writes an (empty) payload file even on a non-zero adapter
    # exit, so a payload path alone does NOT mean the query succeeded — gate on the
    # exit code, not on payload_path, to decide whether there is anything to
    # aggregate.
    if record["exit_code"] != 0 or not record.get("payload_path"):
        return _format_bash_result(record["exit_code"], passthrough, stderr, note)
    # Aggregate the FULL captured payload: the passthrough view is truncated for
    # the model's context, but defender-sql must see every row, so read it back
    # from the by-ref file.
    raw = (deps.run_dir / record["payload_path"]).read_text()
    try:
        proc = subprocess.run(
            sql_argv, input=raw, capture_output=True, text=True,
            env=env, timeout=_BASH_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as e:
        raise ModelRetry(f"defender-sql timed out after {_BASH_TIMEOUT_S}s") from e
    return _format_bash_result(proc.returncode, proc.stdout, proc.stderr, note)


def _capture_adapter(deps: GatherDeps, argv: list[str]) -> str:
    """Run a standalone adapter command through the transparent capture (queries
    table + payload), returning the same shape the bash tool would. lead_id comes
    from deps — the harness owns capture; the model never supplies it. The model
    MAY tag the call with ``--query-id <id>`` (stripped here) to bind the query to
    a catalog id; otherwise ``deps.query_id`` (the finder/executor split's bound
    id) or record_query's default applies."""
    passthrough, stderr, record = _capture_query(deps, argv, _bash_env(deps))
    return _format_bash_result(
        record["exit_code"], passthrough, stderr, _payload_note(deps, record)
    )


def _gather_prompt(
    deps: RunDeps, request: GatherRequest, catalog: str | None,
) -> str:
    """The gather subagent's user prompt: the dispatch block its SKILL reads, plus
    the descriptor catalog (every data-source system + its one-line description) —
    the progressive-disclosure index. Gather confirms its target (`system:` above)
    from the catalog, then Reads that system's full SKILL.md + execution.md on
    demand. Falls back to no catalog when it can't be built."""
    wts = "\n".join(f"  - {d}" for d in request.what_to_summarize) or "  - (unspecified)"
    block = (
        "Begin gathering this lead.\n\n"
        "## Dispatch\n```yaml\n"
        f"defender_dir: {deps.defender_dir}\n"
        f"run_dir: {deps.run_dir}\n"
        f"lead_id: {request.lead_id}\n"
        f"system: {request.system}\n"
        f"goal: {request.goal}\n"
        f"what_to_summarize:\n{wts}\n"
        "```\n"
    )
    if catalog:
        block += (
            "\n## Systems of record (descriptor index — frontmatter only, "
            f"progressive disclosure). Your target is `system: {request.system}` above; "
            "confirm it here. These descriptions are usually enough to pick a "
            f"template or name a measurement — Read the target's full "
            f"`{deps.defender_dir}/skills/{request.system}/SKILL.md` (and execution.md if "
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
    deps: RunDeps, gather_factory, request_limit: int, request: GatherRequest,
) -> str:
    """The gather dispatch, factored out of the tool closure so it's testable
    without the main model: claim the lead → inject the descriptor catalog → run
    the nested gather agent → wrap the summary. The single-agent gather
    (#340) auto-captures its own adapter calls; there is no finder/assay layer."""
    lead_id, system = request.lead_id, request.system
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
    # `claim_lead` requires a list (it guards `isinstance(wtc, list)` and skips
    # otherwise), so unfreeze the request's tuple back to a list at this boundary.
    if _claim_lead({
        "run_dir": str(deps.run_dir), "lead_id": lead_id,
        "goal": request.goal, "what_to_summarize": list(request.what_to_summarize),
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
        run_id=deps.run_id, salt=deps.salt, lead_id=lead_id,
    )
    prompt = _gather_prompt(deps, request, catalog)
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
        # Bundle the four model-supplied params into the value object at the tool
        # boundary; everything inward takes the one object (rationale: GatherRequest).
        # `what_to_summarize` arrives as the schema's `list[str]`; freeze it to a
        # tuple so the value object is fully immutable + hashable.
        request = GatherRequest(lead_id, system, goal, tuple(what_to_summarize))
        # Resolve `_run_gather` through the `tools` module (not the bare name) so
        # the e2e replay test's `setattr(tools, "_run_gather", fake)` intercepts
        # this dispatch — the call site must read the patched module attribute.
        return await tools._run_gather(
            ctx.deps, gather_factory, request_limit, request,
        )
