"""The investigation loop: drive one alert end to end.

What it takes to BUILD a run was split out of this module when it reached 1221 lines,
leaving the loop itself:

  * `_prompts` — the opening prompt and the per-turn user message, including the resume.
  * `_budget`  — the spend ceiling, the short-circuit, and the hooks that account a call.
  * `_build`   — the composition roots: which model, which grants, which tools each role
                 gets, for the main agent and for gather.

`run_investigation` at the bottom is still the entry point, and still the only frame that
holds everything a live run needs at once.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelResponse
from pydantic_ai.usage import UsageLimits

from defender._io import write_guarded
from defender._vocab import HOST_ONLY_DISPOSITION

from .. import branch
from .. import compaction
from .. import observe
from .. import orient
from .. import permission
from .. import providers
from .. import selection
from .. import session_store
from .. import toon_gate as toon_gate_mod
from ..agent_definition import AgentDefinition, ResolvedRoots, ToolSet, bind
from ..agent_role import GATHER_AGENT_ID_PREFIX, AgentRole
from .. import challenge_gate
from .. import review_roles
from ..close_tool import register_close_tool
from ..circuit_breaker import RunAborted
from ..permission.policies import _common
from ..providers import BuiltModel
from ..tools import (
    AgentDeps,
    GatherDeps,
    register_gather_tool,
    register_tools,
)
from ..verb_grant import VerbGrant
from ..verbs import ModuleVerbRegistry

from defender import _clock
from defender._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender._run_paths import RunPaths
from ._prompts import (
    BUDGET_ENFORCE_FLAG,
    DEFAULT_GATHER_MODEL,
    DEFAULT_MODEL,
    DEFAULT_REQUEST_LIMIT,
    DEFAULT_TOOL_RETRIES,
    GATHER_REQUEST_LIMIT,
    _branch_clock,
    _coordinates,
    _main_instructions,
    _opening_prompt,
    _user_prompt,
    enforcement_enabled,
)
from ._budget import (
    _account_executed_call,
    _budget_short_circuit,
    _budget_state_for_enforcement,
    _make_hooks,
    _stamp_duration,
)
from ._build import (
    GATHER_DEF,
    GATHER_PAIRS,
    MAIN_DEF,
    MakeModel,
    _CORPUS_DIRS,
    _affinity_key,
    _compaction_enabled,
    _fold_decision,
    _gather_bash_shapes,
    _gather_extra_capabilities,
    _gather_instructions,
    _gather_verb_grant,
    _main_bash_shapes,
    _main_extra_capabilities,
    _main_write_shape,
    _make_gather_recorder,
    _make_store_render_processor,
    _summary_pointers,
    build_agent,
    build_agent_core,
    build_gather_agent,
    gather_model,
    resolve_main_model,
)
from defender.hooks.budget_enforcer import (
    BUDGET_EXEMPT_TOOLS,
    DEFAULT_LIMITS,
    BudgetKill,
    account_call,
    check_budgets,
    open_budget,
    read_budget,
    refusal_message,
    should_refuse,
    tail_exhausted,
    tier,
    update_budget_locked,
)


def _log_node(node: Any) -> None:
    if Agent.is_model_request_node(node):
        print("[run.py] · model request", file=sys.stderr)
    elif Agent.is_call_tools_node(node):
        print("[run.py] · tool calls", file=sys.stderr)
    elif Agent.is_end_node(node):
        print("[run.py] · end", file=sys.stderr)


StoreFactory = Callable[[str, Path], Any]


def _default_store_factory(case_id: str, run_dir: Path) -> Any:
    return session_store.open_store(case_id=case_id, runs_base=run_dir.parent)


def _resolve_store_factory(resume: Any, store_factory: StoreFactory | None) -> StoreFactory:
    """Which store this run opens, DERIVED from whether it is a resume.

    A fresh run mints its own (or takes the injected seam's); a resume joins the source run's,
    because that is where the prefix rows live and `fork` walks parents inside one connection.

    THE RESUME WINS, and that ordering is the whole point. Deciding it here rather than letting
    the caller supply both a `resume=` and a matching `store_factory=` is what stops the two
    from disagreeing — a spec pointing at run X beside a factory opening run Y's store forks
    against a database that does not hold the branch point, and `_walk_parents` terminates
    cleanly on an id it cannot resolve, so the result is a silently truncated prefix rather
    than an error. Asking the caller and then preferring the caller's answer would leave that
    disagreement reachable, which is exactly what this function claims to close.
    """
    if resume is not None:
        return branch.store_factory_for(resume)
    if store_factory is not None:  # lint-default: ok — DI seam owning its default (R12's fifth seam)
        return store_factory
    return _default_store_factory


def _run_summary(  # noqa: PLR0913 — one dict literal's full field set, named once
    *, output: Any, model_name: str | None, requests: int, truncated_by: str | None,
    exit_reason: str | None, case_id: str, store_path: Any,
) -> dict:
    """The one shape `run_investigation` returns through, on every exit — setup-failure
    and the normal end alike — so the two exits cannot drift apart on a field name."""
    return {
        "output": output, "model": model_name, "requests": requests,
        "truncated_by": truncated_by, "exit_reason": exit_reason,
        "case_id": case_id, "store_path": store_path,
    }


def _flush_run_end(run: Any, store: Any, session_id: str, truncated_by: str | None) -> None:
    """Capture the terminal exchange (whatever `run` holds on ANY exit, clean or not) and
    stamp `truncated_by`, both best-effort so a broken store cannot mask the exit that got us
    here."""
    if run is not None:
        try:
            live = run.ctx.state.message_history
            confirmed_len = store.last_render_len(session_id) or 0
            if len(live) <= confirmed_len:
                # A prior round's processor already committed everything `live` holds, or more
                # — the request-limit check withholds a doomed round's continuation, so `live`
                # can be SHORTER than what is confirmed. Either way there is nothing to add,
                # and truncating here would re-add content the store correctly declined.
                pass
            else:
                # New content past the last confirmed round: drop a trailing incomplete
                # continuation (built but never confirmed by a processor call) so the tail
                # ends on a confirmed response.
                for i in range(len(live) - 1, -1, -1):
                    if isinstance(live[i], ModelResponse):
                        live = live[: i + 1]
                        break
                if len(live) > confirmed_len:
                    selection.ingest(store, session_id, live, agent_id="main")
        except Exception as e:  # noqa: BLE001 — the run-end flush is best-effort
            print(f"[run.py] run-end flush skipped: {e!r}", file=sys.stderr)
    if truncated_by is not None:
        try:
            store.set_truncated_by(session_id, truncated_by)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] truncated_by write skipped: {e!r}", file=sys.stderr)


async def _reap_correlation_task(task: Any) -> None:
    """`correlation_task` (item 3's fire-and-forget dispatch) is only ever awaited by
    `_inject_correlation`, itself only reached when MAIN prepares a SECOND model request. A run
    that closes after one request — or exits `_drive_agent` through any other handled exception
    first — would otherwise leave the task running past `run_investigation`'s return: still
    issuing backend/model calls and writing the run dir (queries table, `gather_raw/l-00c/*`,
    `budget.json`, the session store) concurrently with `run.py`'s post-run steps on that same
    tree, with any exception it raises never retrieved. Called unconditionally after
    `_drive_agent` returns; a no-op if `_inject_correlation` already consumed it."""
    if task is None:
        return
    if not task.done():
        task.cancel()
    try:
        await task
    except Exception as e:  # noqa: BLE001 — this cleanup step must not itself break the run
        print(f"[run.py] correlation task reaped with an unretrieved fault: {e!r}",
              file=sys.stderr)
    except asyncio.CancelledError:
        pass


async def _drive_agent(  # noqa: PLR0913 — the loop's own inputs: agent, prompt, deps, store, bounds
    agent: Agent[AgentDeps, str], prompt: str, deps: AgentDeps, store: Any, session_id: str,
    bounds: challenge_gate.Bounds, message_history: list | None = None,
) -> tuple[Any, str | None, str | None]:
    """Runs the `async for node in run` loop and classifies its caught exits into
    `(truncated_by, exit_reason)`; returns the (possibly unfinished) `run` alongside them so
    the caller can still read `run.result`/`run.ctx` on a clean exit."""
    truncated_by: str | None = None
    exit_reason: str | None = None
    run: Any = None
    try:
        async with agent.iter(
            prompt, deps=deps,
            # A RESUMED run's inherited prefix, or None for a fresh one. The store's render
            # processor rebuilds history from the store on every request and `selection.ingest`
            # compares the live list against `last_render_len` — which a fork has ALREADY
            # seeded to its inherited prefix. So a fresh `agent.iter`, whose list starts empty,
            # underflows against a store that is correct. Handing the prefix back here is what
            # closes that, and it is exact rather than approximate: `fork` and
            # `hydrate(role="send")` both truncate through `_complete_prefix_len`.
            message_history=message_history,
            # RS7: the ceiling that terminates a run is raised by the gate's own forced-turn
            # cap, read FROM the bound rather than restated as a literal. Every run pays it
            # whether or not the gate ever fires — a property of the run, not of a review.
            usage_limits=UsageLimits(request_limit=challenge_gate.raised_request_limit(bounds)),
        ) as run:
            async for node in run:
                _log_node(node)
    except UsageLimitExceeded as e:
        print(f"[run.py] request limit reached ({e}); writing partial trace",
              file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_REQUEST_LIMIT
        exit_reason = "UsageLimitExceeded"
    except UnexpectedModelBehavior as e:
        # RS6: a stubborn model that keeps retrying a call the gate refuses (e.g. a write of
        # report.md) exhausts the framework's shared tool-retry budget (`DEFAULT_TOOL_RETRIES`)
        # and pydantic_ai raises this; no other handler here catches it, so uncaught it takes
        # the process down. Force the unresolved close directly, bypassing the model — which
        # is exactly what got stuck — rather than end with no disposition at all.
        print(f"[run.py] {e}; forcing an unresolved close (retry budget exhausted)",
              file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_RETRY_EXHAUSTED
        exit_reason = "UnexpectedModelBehavior"
        # R4: this handler bypasses the gate and commits through the same path, so on a run
        # whose disposition ALREADY committed it would replace a confident finding with the
        # unresolved one it forces and destroy that close's review record. A run that errors
        # AFTER closing keeps what it decided; the error survives in the logs above.
        if challenge_gate.ReviewState.of(deps).closed:
            print("[run.py] the investigation already closed; keeping its disposition",
                  file=sys.stderr)
        else:
            try:
                from ..close_tool import _close_investigation_async

                # #923: the HOST's own verdict, not the model's — `unresolved` short-circuits
                # ahead of the gate exactly as `inconclusive` used to (both are in
                # `close_tool.NO_REVIEW_DISPOSITIONS`), so no stage and no bound is ever
                # consumed here; the run's own bounds are threaded anyway rather than
                # re-resolved, so this limb cannot end up acting on a different value from the
                # one the rest of the run was built with. It also carries no entry price
                # (`inconclusive` does, and a forced caller has no model left to pay it with).
                #: `forced=True`: the framework's own close is exempt from BOTH document
                #: gates — the flagged-row window and the invlang structure check (#961). No
                #: model is left to repair either, and refusing here would end the run with NO
                #: report.md — dead-lettering it at persist for the wrong reason. A malformed
                #: companion is worse to publish than a well-formed one; a run with no
                #: disposition at all is worse than either. Every close the MODEL invokes is
                #: still gated by both.
                await _close_investigation_async(
                    deps, HOST_ONLY_DISPOSITION, stages=None, bounds=bounds, forced=True,
                )
            except Exception as close_err:  # noqa: BLE001 — this exit must not itself raise
                # ...but it must not SWALLOW it either: logging alone left a forced close that
                # failed indistinguishable downstream from one that committed (same
                # truncated_by, same exit_reason), and the run dead-lettered at persist for a
                # missing artifact, invisibly. The exit reason carries the failure.
                print(f"[run.py] forced close after retry exhaustion also failed "
                      f"({close_err!r})", file=sys.stderr)
                exit_reason = "ForcedCloseFailed"
    except RunAborted as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_ABORTED
        exit_reason = "RunAborted"
    except BudgetKill as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_BUDGET
        exit_reason = "BudgetKill"
    except (sqlite3.Error, session_store.StoreError) as e:
        # StoreError, not StoreAppendError: PayloadNotRepresentable / IngestTailUnderflow /
        # CyclicParentChain / UnknownSchemaVersion all reach here from inside the
        # ProcessHistory hook, and any one escaping takes the whole run.py process down
        # instead of writing the partial trace this handler exists for.
        print(f"[run.py] store append failed ({e!r}); stopping the run", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_STORE
        exit_reason = "StoreAppendError"
    finally:
        _flush_run_end(run, store, session_id, truncated_by)
    return run, truncated_by, exit_reason


async def run_investigation(  # noqa: PLR0913 — a composition root: every parameter is a
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    model_name: str | None = None,
    make_model: MakeModel | None = None,
    verbs: Any = None,
    limits: dict | None = None,
    box: Any = None,
    store_factory: StoreFactory | None = None,
    review_stages: Any = None,
    bounds: challenge_gate.Bounds | None = None,
    model_override: str | None = None,
    toolset: Any = None,
    resume: Any = None,
    clerk: Any = None,
) -> dict:
    model_name = resolve_main_model(model_name)
    # Lead-0's OWN registry seam: a scenario that injected no `verbs=` at all must not have
    # lead-0 acquire one via the MAIN-gather default resolved below. Captured before it.
    lead_zero_verbs = verbs
    # lint-default: ok — DI seam owning its default (the gate's bounds, carrying the request
    # ceiling's BASE), resolved once at the entry point and threaded inward as a concrete value.
    gate_bounds = bounds if bounds is not None else challenge_gate.default_bounds()
    make_model = make_model or providers.build_for_effort
    adapters = defender_dir / "scripts" / "adapters"
    verbs = verbs if verbs is not None else ModuleVerbRegistry(adapters, GATHER_DEF.verb_grant)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    budget_started_monotonic = time.monotonic()
    open_budget(run_dir, run_id)
    # `<run_dir>/wire_logs/llm_requests.jsonl`, one level down and NOT at the run root: the
    # subdirectory is what keeps this log out of every reader agent's `under(run, SEG)` read
    # shape, MAIN's and GATHER's alike. `observe.wire_log_path` owns the location.
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))

    # THE one place a live review bundle can honestly be built, and it sits BELOW the logger:
    # the entry point is the only frame holding all three things a live stage needs — the run
    # dir it anchors its policies on, the operator's model choice, and the run's own
    # `RequestLogger`. Built above the logger, every stage mints a private one and writes to a
    # file no reader opens, so the review's model calls charge a provider and land in no
    # accounted total.
    #
    # `model_override` is the operator's RAW `--model`, deliberately not `model_name` above,
    # which is already resolved against the investigator's default. Handing the resolved one
    # over would give the review a non-`None` explicit model on every run, making its own
    # pinned default unreachable in production.
    #
    # Guarded, because this sits BELOW the open: `live_review_stages` reads three prompt assets
    # off the tree and `role_prompt` raises `FileNotFoundError` on a missing one, which would
    # leave `llm_requests.jsonl` open AND permanently registered in `observe._ACTIVE_PATHS`, so
    # a second `run_investigation` in the same process could never reopen that path. Its own
    # handler rather than the store-setup one below: a missing prompt asset is not a store
    # fault and must not be reported as one.
    try:
        stages = (
            review_stages if review_stages is not None
            else review_roles.live_review_stages(  # lint-default: ok — DI seam owning its default (the live bundle, buildable only where the run dir and the run's logger are)
                run_dir, defender_dir, logger=logger, model_override=model_override,
            )
        )
    except BaseException:
        logger.close()
        raise

    # #996: the clerk, mirroring the review bundle immediately above — same frame, same reason
    # (the run dir, `defender_dir` and the run's own logger at once). `clerk` here is the RAW
    # seam (`run_investigation(clerk=…)`): `None` unless a caller injected one, in which case
    # `make_clerk_caller` wraps it; a production run with none builds and wraps the live caller,
    # threading this run's own `make_model` through so it reaches the clerk's model too.
    from .. import clerk as clerk_mod

    try:
        clerk_caller = clerk_mod.make_clerk_caller(
            run_dir, defender_dir, logger, raw=clerk, make_model=make_model, limits=limits,
        )
    except BaseException:
        logger.close()
        raise

    case_id = uuid.uuid4().hex
    # R12's fifth DI seam, and a resume derives its own store and outranks it — the default and
    # the precedence both live in `_resolve_store_factory`, which is where the `lint-default`
    # site moved to as well.
    factory = _resolve_store_factory(resume, store_factory)
    store = None
    try:
        store = factory(case_id, run_dir)
        # #996, D6: attached on the HANDLE the store factory returned — NEVER inside
        # `_default_store_factory` itself — so a resumed or replay-injected run gets stamped
        # too. Set unconditionally and before any session opens on this handle: `append` reads
        # `store.document_reader` on every call from here on.
        store.document_reader = session_store.document_reader_for(run_dir)
        # A resume JOINS a case rather than minting one: the store the factory hands back is
        # the SOURCE run's, and the prefix rows live in it. So the pointer is written from the
        # STORE's own case id rather than from the uuid minted above — on a fresh run they are
        # the same string, and on a resume the minted one names no session in that database,
        # because `fork` inherits its parent row's `case_id`.
        #
        # That mismatch was not cosmetic. `branch.open_source_store` re-derives the store path
        # from the recorded case id and refuses when it disagrees, so a branch could never be
        # taken FROM a branch; and a reader resolving run_dir -> store -> `main_session_id`
        # landed on the ROOT of the lineage, rendering the source run's transcript for the
        # sibling. The session id below is the other half of that second one.
        # `run_dir` rides along because a resumed MAIN inherits a DOCUMENT as well as a
        # message history, and the document is a run-dir artifact — see `open_main_session`.
        session_id, resume_history = branch.open_main_session(store, resume, run_dir)
        # WRITTEN AFTER the session opens, so a REFUSED branch leaves no pointer behind. The
        # pointer is what resolves a run dir to a store, and on a resume it names the SOURCE
        # run's database — so a sibling dir that got one and then never started would hand any
        # reader (`visualize_run`, and anything built to the "resolve the pointer, then clean up
        # what it names" shape) the source run's store as if it were its own.
        # REBOUND to what the pointer recorded, so `_run_summary` names the case this run
        # joined rather than the uuid minted for a case it never opened. On a fresh run the
        # two are the same string; on a resume the minted one names no session in the source
        # database, and a reader joining the summary back to the store (or through
        # `store_path_for`, which is exactly `open_source_store`'s derive-and-compare) resolves
        # nothing.
        case_id = branch.attach_case_pointer(
            store, resume, run_dir, case_id=case_id, session_id=session_id)
    # `branch.BranchError` rides here with the store faults: a refused branch point (message 0,
    # no captured evidence, an empty or snapped frontier, a pointer that names another store)
    # is a SETUP failure, and without it the raise escapes `run_investigation` entirely —
    # leaving the sqlite connection open AND `llm_requests.jsonl` permanently registered in
    # `observe._ACTIVE_PATHS`, so the next sibling in an in-process sweep can never reopen it.
    except (sqlite3.Error, session_store.StoreError, branch.BranchError, OSError) as e:
        # The store is opened during SETUP, outside `_drive_agent`'s handler — so without
        # this, a stale-version file (or a plain filesystem fault: an unwritable
        # run_dir/runs_base for the pointer write or the store's own mkdir) takes the whole
        # process down instead of ending the run through the handled `truncated_by="store"`
        # exit. Not one model turn is driven.
        print(f"[run.py] store setup failed ({e!r}); ending the run", file=sys.stderr)
        if store is not None:
            # `factory()` can succeed — a live connection, DDL already run — and a LATER
            # call in this same try (`write_case_pointer`, `new_session`) still fail;
            # without this the connection (and its WAL/-shm sidecars) is never closed.
            try:
                store.close()
            except Exception as close_err:  # noqa: BLE001 — best-effort on an already-failing path
                print(f"[run.py] store close after setup failure also failed "
                      f"({close_err!r})", file=sys.stderr)
        logger.close()
        return _run_summary(
            output=None, model_name=model_name, requests=logger.n_requests,
            truncated_by="store", exit_reason=type(e).__name__,
            case_id=case_id, store_path=None,
        )

    prompt, lead_zero_block, lead_zero_status = _opening_prompt(
        resume, run_dir, alert_path, defender_dir,
        verbs=lead_zero_verbs, limits=limits, run_id=run_id,
    )

    # Item 3's async frame: scheduled here (after item 1 has resolved synchronously) and
    # awaited later, inside the store's render processor, right before MAIN's SECOND request.
    # A scenario with no injected registry dispatches nothing.
    correlation_task: Any = None
    # `resume is None` is stated here rather than carried by a nulled `lead_zero_verbs`: a
    # resume skipping turn-0 work is a fact about the run, and a reader at this line must be
    # able to see it without tracing where the registry was set to `None` and why.
    if resume is None and lead_zero_verbs is not None:
        from .. import lead_zero as lead_zero_mod

        try:
            alert_doc = json.loads(alert_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            alert_doc = {}
        contract = lead_zero_mod.prepare_correlation_lead(
            run_dir, alert_doc, lead_zero_block, lead_zero_status,
        )
        if contract is not None:
            goal, what_to_summarize = contract
            # Chain the budget hooks around lead-0's OWN dispatch: routing through
            # QueryCapture/the gather machinery does not by itself move `budget.json` —
            # `subagent_spawns` is gated on the literal tool name "gather", which a harness
            # dispatch never emits.
            lead_zero_mod._budget_account(run_dir, run_id, "gather", limits)
            correlation_task = asyncio.ensure_future(lead_zero_mod.dispatch_correlation(
                run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
                goal=goal, what_to_summarize=what_to_summarize, verbs=lead_zero_verbs,
                limits=limits, make_model=make_model, logger=logger, box=box, store=store,
                # Share the RUN's own budget-clock origin rather than letting it default to a
                # fresh `time.monotonic()` stamp taken whenever this task happens to start.
                budget_started_monotonic=budget_started_monotonic,
            ))

    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
        store=store, session_id=session_id, review_stages=stages, bounds=gate_bounds,
        correlation_task=correlation_task, toolset=toolset, clerk=clerk_caller,
    )
    deps = replace(
        bind(MAIN_DEF, run_dir, defender_dir=defender_dir, box=box),
        run_id=run_id,
        budget_started_monotonic=budget_started_monotonic,
    )

    t0 = time.time()
    run, truncated_by, exit_reason = await _drive_agent(
        agent, prompt, deps, store, session_id, gate_bounds, resume_history,
    )
    wall_ms = (time.time() - t0) * 1000.0
    await _reap_correlation_task(correlation_task)

    result = run.result if run is not None else None
    try:
        observe.write_trace(run_dir, store=store, session_id=session_id, wall_ms=wall_ms)
    except Exception as e:  # noqa: BLE001 — a broken store must not swallow the artifact entirely
        print(f"[run.py] write_trace failed ({e!r}); writing an empty trace", file=sys.stderr)
        try:
            write_guarded(run_dir / "tool_trace.jsonl", "")
        except OSError as fallback_err:
            # The fallback runs while an exception is already being handled, and its target is
            # a name the box can plant an alias at — unguarded, one planted entry converts "the
            # trace could not be built" into an uncaught OSError that ends the run at its last
            # step, discarding the summary and every artifact already written. The trace is
            # observability; the run's result is not.
            print(f"[run.py] the empty-trace fallback also failed ({fallback_err!r}); "
                  f"{run_dir} has no tool_trace.jsonl", file=sys.stderr)
    logger.close()
    output = result.output if result is not None else None
    return _run_summary(
        output=output, model_name=model_name, requests=logger.n_requests,
        truncated_by=truncated_by, exit_reason=exit_reason,
        case_id=case_id, store_path=store.path,
    )


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "Agent",
    "AgentDefinition",
    "AgentDeps",
    "AgentRole",
    "Any",
    "BUDGET_ENFORCE_FLAG",
    "BUDGET_EXEMPT_TOOLS",
    "BudgetKill",
    "BuiltModel",
    "Callable",
    "DEFAULT_GATHER_MODEL",
    "DEFAULT_LIMITS",
    "DEFAULT_MODEL",
    "DEFAULT_REQUEST_LIMIT",
    "DEFAULT_TOOL_RETRIES",
    "GATHER_AGENT_ID_PREFIX",
    "GATHER_DEF",
    "GATHER_PAIRS",
    "GATHER_REQUEST_LIMIT",
    "GatherDeps",
    "Hooks",
    "MAIN_DEF",
    "MakeModel",
    "ModelResponse",
    "ModuleVerbRegistry",
    "Path",
    "ProcessHistory",
    "ResolvedRoots",
    "RunAborted",
    "RunContext",
    "RunPaths",
    "Sequence",
    "ToolSet",
    "UnexpectedModelBehavior",
    "UsageLimitExceeded",
    "UsageLimits",
    "VerbGrant",
    "_CORPUS_DIRS",
    "_account_executed_call",
    "_affinity_key",
    "_branch_clock",
    "_budget_short_circuit",
    "_budget_state_for_enforcement",
    "_clock",
    "_common",
    "_compaction_enabled",
    "_coordinates",
    "_default_store_factory",
    "_drive_agent",
    "_flush_run_end",
    "_fold_decision",
    "_gather_bash_shapes",
    "_gather_extra_capabilities",
    "_gather_instructions",
    "_gather_verb_grant",
    "_log_node",
    "_main_bash_shapes",
    "_main_extra_capabilities",
    "_main_instructions",
    "_main_write_shape",
    "_make_gather_recorder",
    "_make_hooks",
    "_make_store_render_processor",
    "_opening_prompt",
    "_reap_correlation_task",
    "_resolve_store_factory",
    "_run_summary",
    "_stamp_duration",
    "_summary_pointers",
    "_user_prompt",
    "account_call",
    "asyncio",
    "bind",
    "branch",
    "build_agent",
    "build_agent_core",
    "build_gather_agent",
    "challenge_gate",
    "check_budgets",
    "compaction",
    "enforcement_enabled",
    "env_bool",
    "gather_model",
    "json",
    "observe",
    "open_budget",
    "orient",
    "os",
    "permission",
    "providers",
    "read_budget",
    "refusal_message",
    "register_close_tool",
    "register_gather_tool",
    "register_tools",
    "replace",
    "resolve_main_model",
    "review_roles",
    "run_investigation",
    "selection",
    "session_store",
    "should_refuse",
    "sqlite3",
    "strip_frontmatter",
    "sys",
    "tail_exhausted",
    "tier",
    "time",
    "toon_gate_mod",
    "update_budget_locked",
    "uuid",
    "write_guarded",
]
