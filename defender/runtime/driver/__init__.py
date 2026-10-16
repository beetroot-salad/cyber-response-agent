"""The investigation loop: drive one alert end to end.

Building a run lives in sibling modules:

  * `_prompts` — the opening prompt and the per-turn user message, including the resume.
  * `_budget`  — the spend ceiling, the short-circuit, and the hooks that account a call.
  * `_build`   — the composition roots: which model, which grants, which tools each role
                 gets, for the main agent and for gather.

`run_investigation` is the entry point and the only frame that holds everything a live run
needs at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelResponse
from pydantic_ai.usage import UsageLimits

from defender.runtime.tools._deps import run_of
from defender._io import write_guarded
from defender import _git
from defender._knowledge import KnowledgePaths
from defender._paths import DefenderPaths, adapters_under
from defender._vocab import HOST_ONLY_DISPOSITION

from .. import branch
from .. import compaction
from .. import observe
from .. import orient
from .. import permission
from .. import providers
from .. import run_end
from .. import selection
from .. import session_store
from .. import toon_gate as toon_gate_mod
from ..agent_definition import AgentDefinition, ResolvedRoots, RunScope, ToolSet, bind
from ..agent_role import GATHER_AGENT_ID_PREFIX, AgentRole
from .. import challenge_gate
from ..exception_groups import carried, carried_unless_overridden
from .. import review_roles
from ..close_tool import register_close_tool
from ..circuit_breaker import RunAborted
from ..permission.policies import _common
from ..providers import BuiltModel
from ..run_state import RunState
from ..tools import (
    AgentDeps,
    GatherDeps,
    register_gather_tool,
    register_tools,
)
from ..verb_grant import VerbGrant
from ..verb_dispositions import RunGrants
from ..verbs import ModuleVerbRegistry, RosterRead, read_roster
from defender.skills.invlang.validate import hold_capabilities
from defender.hooks.inject_system_skill_description import descriptor_catalog

from defender import _clock
from defender._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender.run_repository import Run, RunPaths
from ..run_tenant import RunTenant
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
    _make_hooks,
    _stamp_duration,
)
from ._build import (
    GATHER_DEF,
    MAIN_DEF,
    MakeModel,
    _CORPUS_DIRS,
    _affinity_key,
    _compaction_enabled,
    _fold_decision,
    _gather_bash_shapes,
    _gather_extra_capabilities,
    _gather_instructions,
    _main_bash_shapes,
    _main_extra_capabilities,
    _main_write_shape,
    _make_gather_recorder,
    _make_store_render_processor,
    _summary_pointers,
    build_agent,
    build_agent_core,
    gather_def_for,
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
    refusal_message,
    should_refuse,
    tail_exhausted,
    tier,
)

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..lead_zero import CorrelationDispatch


def _log_node(node: Any) -> None:
    if Agent.is_model_request_node(node):
        _logger.info("· model request")
    elif Agent.is_call_tools_node(node):
        _logger.info("· tool calls")
    elif Agent.is_end_node(node):
        _logger.info("· end")


StoreFactory = Callable[[str, Path], Any]


def _default_store_factory(case_id: str, run_dir: Path) -> Any:
    return session_store.open_store(case_id=case_id, sessions=RunPaths(run_dir).session_paths())


def _resolve_store_factory(resume: Any, store_factory: StoreFactory | None, *, source_run: Run | None = None) -> StoreFactory:
    """Which store this run opens, derived from whether it is a resume.

    A fresh run mints its own (or takes the injected one); a resume joins the source run's,
    where the prefix rows live. The resume wins over an injected factory: a factory opening a
    different store would fork against a database without the branch point, and the parent walk
    would silently truncate the prefix instead of erroring.
    """
    if resume is not None:
        if source_run is None:
            raise branch.BranchError("a resumed run requires its source Run")
        return branch.store_factory_for(resume, source_run=source_run)
    if store_factory is not None:  # lint-default: ok — DI seam owning its default
        return store_factory
    return _default_store_factory


def _run_summary(  # noqa: PLR0913 — one dict literal's full field set, named once
    *, output: Any, model_name: str | None, requests: int, end: run_end.RunEnd,
    exit_reason: str | None, case_id: str, store_path: Any,
) -> dict:
    """The one shape `run_investigation` returns on every exit, so exits cannot drift apart.

    `end` (exit class, and whether the model had already closed) is flattened on so `run.py`'s
    post-steps read it in-process rather than off disk. The run's live state is not on it
    (#1235): a caller that wants it hands it in (`run_investigation(run_state=…)`) and keeps its
    own reference."""
    return {
        "output": output, "model": model_name, "requests": requests,
        "truncated_by": end.truncated_by, "closed_before_cut": end.closed_before_cut,
        "exit_reason": exit_reason, "case_id": case_id, "store_path": store_path,
    }


def _run_state_at_boundary(run_state: RunState | None, run_dir: Path, run_id: str) -> RunState:
    """The run's one live state (#1235), resolved once: the one the caller handed in, which
    must be this run's — started for this folder, as spelled, under this run id — or, when
    handed none, a new one for the run (production's path: `run.py` hands none). Another
    run's state is a `ValueError`: counting this run on it would charge that run's budget
    and breaker, and leave this one's decisions reading a state they never wrote."""
    if run_state is None:
        return RunState(run_dir, run_id)
    if (run_state.run_dir, run_state.run_id) != (Path(run_dir), run_id):
        raise ValueError(
            f"run_investigation was handed the state of run {run_state.run_id!r} on "
            f"{run_state.run_dir}, not this run's ({run_id!r} on {run_dir})")
    return run_state


def _flush_run_end(run: Any, store: Any, session_id: str, truncated_by: str | None) -> None:
    """Capture the terminal exchange and stamp `truncated_by`, both best-effort so a broken
    store cannot mask the exit that got us here."""
    if run is not None:
        try:
            live = run.ctx.state.message_history
            confirmed_len = store.last_render_len(session_id) or 0
            if len(live) <= confirmed_len:
                # Already committed (`live` can be shorter: the request-limit check withholds a
                # doomed round's continuation). Nothing to add.
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
            _logger.warning(f"run-end flush skipped: {e!r}")
    if truncated_by is not None:
        try:
            store.set_truncated_by(session_id, truncated_by)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            _logger.warning(f"truncated_by write skipped: {e!r}")


async def _drive_agent(  # noqa: PLR0913, C901 — the loop's own inputs: agent, prompt, deps, store, bounds
    agent: Agent[AgentDeps, str], prompt: str, deps: AgentDeps, store: Any, session_id: str,
    bounds: challenge_gate.Bounds, message_history: list | None = None,
) -> tuple[Any, run_end.RunEnd, str | None]:
    """@owns truncated_by, @owns closed_before_cut — runs the agent loop, classifies its caught
    exits into the run-end record and an exit reason, and returns them with the (possibly
    unfinished) `run`. The sole producer of a MAIN session's exit class."""
    truncated_by: str | None = None
    exit_reason: str | None = None
    run: Any = None
    try:
        async with agent.iter(
            prompt, deps=deps,
            # A resumed run's inherited prefix, or None. A fork has already seeded
            # `last_render_len` to the prefix, so starting from an empty list would underflow
            # `selection.ingest`.
            message_history=message_history,
            # The ceiling includes the review gate's forced-turn headroom, read from the bound,
            # whether or not the gate fires.
            usage_limits=UsageLimits(request_limit=challenge_gate.raised_request_limit(bounds)),
        ) as run:
            async for node in run:
                _log_node(node)
    except UsageLimitExceeded as e:
        _logger.warning(f"request limit reached ({e}); writing partial trace")
        truncated_by = session_store.TRUNCATED_BY_REQUEST_LIMIT
        exit_reason = "UsageLimitExceeded"
    except UnexpectedModelBehavior as e:
        # A model that keeps retrying a refused call exhausts the shared tool-retry budget.
        _logger.warning(f"{e}; writing partial trace (retry budget exhausted)")
        truncated_by = session_store.TRUNCATED_BY_RETRY_EXHAUSTED
        exit_reason = "UnexpectedModelBehavior"
    except RunAborted as e:
        _logger.warning(f"{e}; writing partial trace")
        truncated_by = session_store.TRUNCATED_BY_ABORTED
        exit_reason = "RunAborted"
    except BudgetKill as e:
        _logger.warning(f"{e}; writing partial trace")
        truncated_by = session_store.TRUNCATED_BY_BUDGET
        exit_reason = "BudgetKill"
    except (sqlite3.Error, session_store.StoreError) as e:
        # The `StoreError` base: every store fault can surface from the ProcessHistory hook.
        _logger.error(f"store append failed ({e!r}); stopping the run")
        truncated_by = session_store.TRUNCATED_BY_STORE
        exit_reason = "StoreAppendError"
    except (run_end.CallRecordWriteFailed, providers.ProviderDown, BaseExceptionGroup) as e:
        # Two failures end the run by name. Concurrent leads may deliver either inside an
        # exception group; a group that carries neither propagates as itself.
        failed = carried(e, run_end.CallRecordWriteFailed)
        down = _provider_down_in(e)
        if failed is not None:
            # A call record the run could not write (A12, #1234), stamped with the record that
            # failed.
            _logger.error(f"{failed}")
            truncated_by = failed.record
            exit_reason = "CallRecordWriteFailed"
        elif down is not None:
            # A model request kept failing temporarily past the retrier (#1243): an
            # infrastructure end, so like the budget kill it writes no report.
            _logger.error(f"{down}; ending the run")
            truncated_by = session_store.TRUNCATED_BY_PROVIDER_DOWN
            exit_reason = "ProviderDown"
        else:
            raise
    finally:
        _flush_run_end(run, store, session_id, truncated_by)
    # The run-end record is taken before the forced close sets `closed`, and written always
    # (a clean run records `truncated_by: null`). It is how readers tell a model verdict from a
    # host-forced one, so if it cannot be written no forced report is written either; that is
    # named in the exit reason only when a forced close was actually owed.
    end = run_end.RunEnd(truncated_by, challenge_gate.ReviewState.of(deps).closed)
    written = _write_run_end_sidecar(deps, end)
    if truncated_by in _CUT_SHORT_WITH_A_MODEL_STILL_OWED_A_CLOSE:
        if written:
            exit_reason = await _close_a_run_cut_short(deps, bounds, exit_reason)
        elif not end.closed_before_cut:
            _logger.error("the run-end record could not be written; not forcing a close")
            exit_reason = f"{exit_reason}+RunEndRecordFailed"
    return run, end, exit_reason


def _bind_call_ids(state: RunState, verbs: Any, run_id: str) -> None:
    """Name the run in every call id its writers allocate (A12, #1234): the registry's own
    `call_run` when it serves a branched world (the world token its served-ledger rows carry
    as `world_id`), else the run id. Bound before any writer runs, lead zero's included."""
    from ..query_tool import bind_call_ids

    run = getattr(verbs, "call_run", None)
    bind_call_ids(state, run if isinstance(run, str) and run else run_id)


def _provider_down_in(exc: BaseException) -> providers.ProviderDown | None:
    """The `ProviderDown` that should end the run on `exc` (bare, or carried by a group that
    holds no interrupt, kill or abort), else `None`."""
    return carried_unless_overridden(exc, providers.ProviderDown, (BudgetKill, RunAborted))


def _write_run_end_sidecar(deps: AgentDeps, end: run_end.RunEnd) -> bool:
    """Write the host-side run-end sidecar beside `deps.run_dir`; `True` on success.

    Best-effort: a failure is logged and reported so the forced close can refuse to write a
    report with no record beside it.
    """
    try:
        run_end.write_sidecar(run_of(deps), end)
        return True
    except OSError as e:
        _logger.warning(f"run-end record write skipped: {e!r}")
        return False


#: Exits where the model was stopped before closing but the run still says something about the
#: case (request ceiling, tool-retry budget): the host closes `unresolved` so a report.md exists.
#:
#: Circuit-breaker, budget-kill, store and failed call-record (`served_ledger`,
#: `executed_queries`) exits are excluded: they are infrastructure faults,
#: not findings, and downstream readers treat any report.md as a verdict (the ticket lane
#: closes the ticket, the scorer counts `unresolved` as wrong). Those runs end with no report.
#: The set lives in `run_end` because the ticket lane keys on it without importing this module.
_CUT_SHORT_WITH_A_MODEL_STILL_OWED_A_CLOSE = run_end.FORCED_CLOSE_EXITS


async def _close_a_run_cut_short(
    deps: AgentDeps, bounds: challenge_gate.Bounds, exit_reason: str | None,
) -> str | None:
    """The host's `unresolved` close for a run cut short on a model-owned exit, so every such
    run ends with a report.md. Keyed on the exit class in one place rather than per handler.

    Returns the exit reason to record: the caller's, or `ForcedCloseFailed` so a failed forced
    close is distinguishable downstream. A run that already closed keeps its decision.

    `forced=True`, `stages=None`: `unresolved` is not reviewed, and a forced close is exempt
    from the document gates since no model is left to repair anything."""
    if challenge_gate.ReviewState.of(deps).closed:
        _logger.info("the investigation already closed; keeping its disposition")
        return exit_reason
    _logger.warning("forcing an unresolved close")
    try:
        from ..close_tool import _close_investigation_async

        await _close_investigation_async(
            deps, HOST_ONLY_DISPOSITION, stages=None, bounds=bounds, forced=True,
        )
    except Exception as close_err:  # noqa: BLE001 — this exit must not itself raise
        _logger.error(f"the forced close also failed ({close_err!r})")
        return "ForcedCloseFailed"
    return exit_reason


def _dispatch_catalogs(
    defender_dir: Path, roster: RosterRead, grants: RunGrants,
) -> tuple[str | None, str | None]:
    """The descriptor index each dispatch prompt opens with: MAIN's (narrowed to the gather
    grant) and lead-0's (narrowed to the correlation grant).

    Built once at run start so a roster fault fails here, not mid-tool. Uses the run's grants,
    not the injected `verbs=` registry, so a narrower registry does not narrow the catalog."""
    skills = KnowledgePaths.of_defender_dir(defender_dir).skills_dir
    return (
        descriptor_catalog(skills, roster, grants.gather),
        descriptor_catalog(skills, roster, grants.correlation),
    )


def _correlation_dispatch_at_run_start(
    *, tenant: RunTenant, resume: Any, lead_zero_verbs: Any,
) -> CorrelationDispatch | None:
    """Item 3's dispatch identity for a run that will dispatch the lead, else `None`.

    A resume or a scenario with no injected registry dispatches nothing; deciding that here
    means a run is never refused for a lead it would not consult. The identity itself was
    resolved and checked by `run_tenant.resolve_run_tenant` and is carried on the tenant; a
    tenant resolved without it, handed to a dispatching run, is a caller bug and raises."""
    if resume is not None or lead_zero_verbs is None:
        return None
    if tenant.correlation is None:
        raise TypeError(
            "this run dispatches the lead-zero correlation lead, but its tenant was resolved "
            "without it (`resolve_run_tenant(dispatches_lead_zero=False)`)")
    return tenant.correlation


def _adapters_at_run_start(
    defender_dir: Path, roster: RosterRead | None, verbs: Any, tenant: RunTenant,
) -> tuple[RosterRead, Any]:
    """Everything a run resolves from an adapters tree, resolved first — before the budget,
    logger or any model — so an unreadable tree fails here as `RegistryError`, not mid-tool.

    The roster is read here only if the caller injected none; consumers take the value.

    The invlang `nothing-to-try` gate is handed the checkout's roster (`hold_capabilities`)
    rather than reading lazily, so a read fault is not misfiled as a document fault by the
    gates that call it. When the run's tree is the checkout, the same read is reused."""
    roster = roster if roster is not None else read_roster(adapters_under(defender_dir))  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    # Built over the run's gather grant; there is no process-level one.
    verbs = verbs if verbs is not None else ModuleVerbRegistry(  # lint-default: ok — DI seam owning its default (built over the run's own grant)
        roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    checkout = DefenderPaths(_git.REPO_ROOT).adapters_dir
    hold_capabilities(
        roster if Path(roster.root).resolve() == checkout.resolve() else read_roster(checkout)
    )
    return roster, verbs


def _stop_before_main(  # noqa: PLR0913 — the early stop's own facts
    *, run: Run, run_dir: Path, logger: Any, store: Any, session_id: str, truncated_by: str,
    exit_reason: str, model_name: str | None, case_id: str, wall_ms: float,
) -> dict:
    """End a run whose cause of death arrived BEFORE MAIN's first request (a run-level kill
    while the correlation lead ran): the same exit MAIN's own kill takes — the session and the
    run-end record name the class, the trace is written, the log is released — with the agent
    never started, so no output and no forced close."""
    _flush_run_end(None, store, session_id, truncated_by)
    end = run_end.RunEnd(truncated_by, closed_before_cut=False)
    try:
        run_end.write_sidecar(run, end)
    except OSError as e:
        _logger.warning(f"run-end record write skipped: {e!r}")
    try:
        observe.write_trace(run_dir, store=store, session_id=session_id, wall_ms=wall_ms)
    except Exception as e:  # noqa: BLE001 — a broken store must not swallow the artifact entirely
        _logger.error(f"write_trace failed ({e!r}); writing an empty trace")
        try:
            write_guarded(RunPaths(run_dir).tool_trace, "")
        except OSError as fallback_err:
            _logger.error(f"the empty-trace fallback also failed ({fallback_err!r})")  # lint-run-records: ok — an operator diagnostic naming the missing record
    logger.close()
    return _run_summary(
        output=None, model_name=model_name, requests=logger.n_requests, end=end,
        exit_reason=exit_reason, case_id=case_id, store_path=store.path,
    )


async def _correlation_phase(  # noqa: PLR0913 — the dispatch seams plus the run's identity for an early stop
    correlation: CorrelationDispatch, *, run: Run, run_dir: Path, defender_dir: Path, run_id: str,
    verbs: Any, limits: dict, make_model: MakeModel, logger: Any, box: Any, store: Any,
    session_id: str, case_id: str, model_name: str | None, run_state: RunState,
    catalog: str | None, tenant: RunTenant, deadline: float, run_started: float,
) -> tuple[str | None, dict | None]:
    """Run the correlation lead to its end and return `(the correlation section of MAIN's
    opening message, None)`, or `(None, the run summary)` when a run-level stop arrived first.

    A run-level kill or a store fault while the lead runs ends the run the way MAIN's own would,
    with the agent never started. An interrupt, a cancellation or a run folder that refuses the
    lead's summary releases the wire log and the store, then propagates."""
    from .. import lead_zero as lead_zero_mod

    def stop(truncated_by: str, exit_reason: str) -> dict:
        return _stop_before_main(
            run=run, run_dir=run_dir, logger=logger, store=store, session_id=session_id,
            truncated_by=truncated_by, exit_reason=exit_reason, model_name=model_name,
            case_id=case_id, wall_ms=(time.monotonic() - run_started) * 1000.0)

    try:
        outcome = await lead_zero_mod.run_correlation(
            run=run, run_state=run_state, defender_dir=defender_dir, verbs=verbs,
            limits=limits, make_model=make_model, logger=logger, box=box, store=store,
            catalog=catalog,
            dispatch=correlation, tenant=tenant, deadline=deadline)
    except (BudgetKill, RunAborted) as kill:
        _logger.warning(f"{kill}; stopping before the agent starts")
        return None, stop(
            session_store.TRUNCATED_BY_BUDGET if isinstance(kill, BudgetKill)
            else session_store.TRUNCATED_BY_ABORTED, type(kill).__name__)
    except (sqlite3.Error, session_store.StoreError) as e:
        _logger.error(f"store fault during the correlation lead ({e!r}); ending the run")
        return None, stop(session_store.TRUNCATED_BY_STORE, "StoreAppendError")
    except BaseException as e:
        # A provider that stayed down (#1243) may arrive inside an exception group.
        down = _provider_down_in(e)
        if down is not None:
            _logger.error(f"{down}; stopping before the agent starts")
            return None, stop(session_store.TRUNCATED_BY_PROVIDER_DOWN, "ProviderDown")
        logger.close()
        with contextlib.suppress(Exception):
            store.close()
        raise
    return lead_zero_mod.render_correlation_section(
        outcome, grant_home=tenant.table_pointer), None


async def _drive_releasing_log(logger: Any, *args: Any) -> Any:
    """`_drive_agent`, releasing the wire log when the run ends by an escaping exception (a
    world that went unservable, #1224), so a resume into the same run dir can open it again."""
    try:
        return await _drive_agent(*args)
    except BaseException:
        logger.close()
        raise


async def run_investigation(  # noqa: PLR0913 — a composition root: every parameter is a
    *,
    alert_path: Path,
    run: Run,
    source_run: Run | None = None,
    defender_dir: Path,
    model_name: str | None = None,
    make_model: MakeModel | None = None,
    verbs: Any = None,
    roster: RosterRead | None = None,
    limits: dict | None = None,
    box: Any = None,
    store_factory: StoreFactory | None = None,
    review_stages: Any = None,
    bounds: challenge_gate.Bounds | None = None,
    model_override: str | None = None,
    toolset: Any = None,
    resume: Any = None,
    tenant: RunTenant,
    orient_shim: orient.ShimRunner | None = None,
    run_state: RunState | None = None,
) -> dict:
    # `tenant` is resolved once at the entry point (settings folder, permissions, item 3's
    # dispatch identity). Required: there is no process-level fallback.
    #
    # The run's live decision state (#1235): its budget and clock, its breaker, its queries
    # rows. Resolved first — a state for another run is refused before anything is read or
    # driven — and carried by reference to every role of the run; a branch sibling's seeding
    # records its inherited rows into it. The summary does not hand it out: a caller that wants
    # it passes its own.
    run_dir, run_id = run.run_dir, str(run.id)
    state = _run_state_at_boundary(run_state, run_dir, run_id)
    model_name = resolve_main_model(model_name)
    # Captured before the default is resolved below: with no injected `verbs=`, lead-0 must not
    # inherit MAIN-gather's default registry.
    lead_zero_verbs = verbs
    # lint-default: ok — DI seam owning its default (the gate's bounds), resolved once here and
    # threaded inward.
    gate_bounds = bounds if bounds is not None else challenge_gate.default_bounds()
    make_model = make_model or providers.build_for_effort
    roster, verbs = _adapters_at_run_start(defender_dir, roster, verbs, tenant)
    _bind_call_ids(state, verbs, run_id)
    correlation = _correlation_dispatch_at_run_start(
        tenant=tenant, resume=resume, lead_zero_verbs=lead_zero_verbs,
    )
    catalog, correlation_catalog = _dispatch_catalogs(defender_dir, roster, tenant.grants)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    # A usable deadline or no run: checked before the run folder is touched, never replaced by a
    # fallback. A lead the table withholds is never run, so it owes no deadline.
    from ..lead_zero import correlation_deadline as lead_zero_deadline

    correlation_deadline = (
        lead_zero_deadline(limits) if correlation is not None and correlation.system is not None
        else 0.0)
    # Under `wire_logs/`, not the run root, so it is outside the agents' one-segment run-dir
    # read shape.
    logger = observe.RequestLogger.from_record(run.observability.wire_log)

    # The live review bundle is built here, after the logger, so review calls are logged and
    # priced with the run's own `RequestLogger`.
    #
    # `model_override` is the operator's raw `--model`, not the resolved `model_name`, so the
    # review's own pinned default stays reachable.
    #
    # A missing prompt asset raises here; close the logger so its path is not left registered
    # in `observe._ACTIVE_PATHS` (which would block a later run in this process).
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

    case_id = uuid.uuid4().hex
    # Default and resume precedence live in `_resolve_store_factory`.
    store = None
    try:
        factory = _resolve_store_factory(resume, store_factory, source_run=source_run)
        store = factory(case_id, run_dir)
        # A resume joins the source run's case, so the case pointer comes from the store, not
        # the uuid minted above (they match on a fresh run). `run_dir` is passed because a
        # resumed MAIN inherits the investigation document as well as the message history.
        session_id, resume_history = branch.open_main_session(store, resume, state, run=run, source_run=source_run)
        # Written after the session opens, so a refused branch leaves no pointer naming the
        # source run's store. Rebound so `_run_summary` names the case this run joined.
        case_id = branch.attach_case_pointer(
            store, resume, run, case_id=case_id, session_id=session_id)
    # A refused branch point (`BranchError`) is a setup failure like a store fault; letting it
    # escape would leave the connection and the wire log open.
    except (sqlite3.Error, session_store.StoreError, branch.BranchError, OSError) as e:
        # Setup is outside `_drive_agent`'s handler; end the run through the
        # `truncated_by="store"` exit without driving a turn.
        _logger.error(f"store setup failed ({e!r}); ending the run")
        if store is not None:
            # `factory()` may have succeeded before a later call failed.
            try:
                store.close()
            except Exception as close_err:  # noqa: BLE001 — best-effort on an already-failing path
                _logger.error(f"store close after setup failure also failed "
                              f"({close_err!r})")
        logger.close()
        return _run_summary(
            output=None, model_name=model_name, requests=logger.n_requests,
            end=run_end.RunEnd(session_store.TRUNCATED_BY_STORE, closed_before_cut=False),
            exit_reason=type(e).__name__, case_id=case_id, store_path=None,
        )

    # One execution clock covers correlation and MAIN, including a stop before MAIN.
    run_started = time.monotonic()

    # The correlation lead runs to its end BEFORE the opening message is built (A4): the message
    # carries its framed summary or the one sentence naming its ending, and nothing about
    # correlation arrives later. `correlation` is `None` when this run dispatches none.
    correlation_section: str | None = None
    if correlation is None and resume is None:
        # A fresh drive with no verb registry runs no lead: there is no third state between
        # "dispatched" and "withheld", so MAIN is told the lead was withheld.
        from ..lead_zero import CorrelationOutcome, render_correlation_section
        from ..lead_zero._spec import ENDING_WITHHELD

        correlation_section = render_correlation_section(
            CorrelationOutcome(ending=ENDING_WITHHELD), grant_home=tenant.table_pointer)
    if correlation is not None:
        correlation_section, stopped = await _correlation_phase(
            correlation, run=run, run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
            verbs=lead_zero_verbs, limits=limits, make_model=make_model, logger=logger, box=box,
            store=store, session_id=session_id, case_id=case_id, model_name=model_name,
            catalog=correlation_catalog,
            tenant=tenant, run_state=state, deadline=correlation_deadline, run_started=run_started)
        if stopped is not None:
            return stopped
    prompt = _opening_prompt(
        resume, run_dir, alert_path, defender_dir,
        systems=tuple(roster.accepted), correlation_section=correlation_section,
        orient_shim=orient_shim, tenant_agent=tenant.agent,
    )

    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
        store=store, session_id=session_id, review_stages=stages, bounds=gate_bounds,
        toolset=toolset, catalog=catalog, gather_grant=tenant.grants.gather,
    )
    deps = replace(
        bind(MAIN_DEF, run_dir, defender_dir=defender_dir, box=box,
             scope=RunScope(tenant_agent=tenant.agent)),
        run_id=run_id,
        # The run's tenant record and its state ride on MAIN's deps so every gather lead it
        # dispatches inherits them (`_run_gather` carries both onto the lead's deps) —
        # #1106 M3, #1107, #1235.
        tenant=tenant,
        run_state=state,
        run=run,
    )

    agent_run, end, exit_reason = await _drive_releasing_log(
        logger, agent, prompt, deps, store, session_id, gate_bounds, resume_history,
    )
    wall_ms = (time.monotonic() - run_started) * 1000.0

    result = agent_run.result if agent_run is not None else None
    try:
        observe.write_trace(run_dir, store=store, session_id=session_id, wall_ms=wall_ms)
    except Exception as e:  # noqa: BLE001 — a broken store must not swallow the artifact entirely
        _logger.error(f"write_trace failed ({e!r}); writing an empty trace")
        try:
            write_guarded(RunPaths(run_dir).tool_trace, "")
        except OSError as fallback_err:
            # The target can be a planted alias; the trace is observability and must not
            # discard the run's result.
            _logger.error(f"the empty-trace fallback also failed ({fallback_err!r}); "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                          f"{run_dir} has no tool_trace.jsonl")  # lint-run-records: ok — an operator diagnostic naming the missing record
    logger.close()
    output = result.output if result is not None else None
    return _run_summary(
        output=output, model_name=model_name, requests=logger.n_requests,
        end=end, exit_reason=exit_reason, case_id=case_id, store_path=store.path,
    )


#: Re-exports; each name's home is the module it is imported from.
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
    "gather_def_for",
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
    "_log_node",
    "_main_bash_shapes",
    "_main_extra_capabilities",
    "_main_instructions",
    "_main_write_shape",
    "_make_gather_recorder",
    "_make_hooks",
    "_make_store_render_processor",
    "_opening_prompt",
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
    "orient",
    "os",
    "permission",
    "providers",
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
    "uuid",
    "write_guarded",
]
