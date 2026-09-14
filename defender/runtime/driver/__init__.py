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
from typing import TYPE_CHECKING, Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelResponse
from pydantic_ai.usage import UsageLimits

from defender._corpus import iter_query_templates
from defender._io import write_guarded
from defender import _git
from defender._paths import DefenderPaths, adapters_under
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
from ..verbs import ModuleVerbRegistry, RosterRead, read_roster
from defender.skills.invlang.validate import hold_capabilities
from defender.hooks.inject_system_skill_description import descriptor_catalog

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

if TYPE_CHECKING:
    from ..lead_zero import CorrelationDispatch


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
        # the process down.
        print(f"[run.py] {e}; writing partial trace (retry budget exhausted)", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_RETRY_EXHAUSTED
        exit_reason = "UnexpectedModelBehavior"
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
    if truncated_by in _CUT_SHORT_WITH_A_MODEL_STILL_OWED_A_CLOSE:
        exit_reason = await _close_a_run_cut_short(deps, bounds, exit_reason)
    return run, truncated_by, exit_reason


#: The exits on which the MODEL was stopped before it could close — by the request ceiling,
#: the tool-retry budget, the tool-call budget or the circuit breaker. Each ends with no
#: report.md unless the host writes one, and a run with no report.md dead-letters at persist
#: for a missing artifact. The store arm is deliberately absent: a run whose history store
#: failed stops without writing another word against it, by that arm's own fail-closed rule.
_CUT_SHORT_WITH_A_MODEL_STILL_OWED_A_CLOSE = frozenset({
    session_store.TRUNCATED_BY_REQUEST_LIMIT,
    session_store.TRUNCATED_BY_RETRY_EXHAUSTED,
    session_store.TRUNCATED_BY_BUDGET,
    session_store.TRUNCATED_BY_ABORTED,
})


async def _close_a_run_cut_short(
    deps: AgentDeps, bounds: challenge_gate.Bounds, exit_reason: str,
) -> str:
    """The host's own `unresolved` close for a run the framework cut short, so every such run
    ends with a report.md. ONE place, after the loop, keyed on the exit class rather than
    written into each arm — an arm that forgot it (the request-limit arm did, until #992 let
    a challenged `inconclusive` reach that ceiling) reopened the dead-letter.

    Returns the exit reason to record: the caller's, or `ForcedCloseFailed` when this close
    itself failed — logging alone left a forced close that failed indistinguishable
    downstream from one that committed, and the run dead-lettered invisibly.

    R4: a run that was cut short AFTER closing keeps what it decided; forcing here would
    replace a confident finding with `unresolved` and destroy that close's review record.

    `forced=True` and `stages=None`: `unresolved` is the host's verdict, the one disposition
    the gate does not review (`close_tool.NO_REVIEW_DISPOSITIONS`), and a forced close is
    exempt from both document gates — no model is left to repair anything, and refusing
    would end the run with no report.md for the wrong reason. The run's own bounds are
    threaded so this limb cannot act on a different value from the rest of the run."""
    if challenge_gate.ReviewState.of(deps).closed:
        print("[run.py] the investigation already closed; keeping its disposition",
              file=sys.stderr)
        return exit_reason
    print("[run.py] forcing an unresolved close", file=sys.stderr)
    try:
        from ..close_tool import _close_investigation_async

        await _close_investigation_async(
            deps, HOST_ONLY_DISPOSITION, stages=None, bounds=bounds, forced=True,
        )
    except Exception as close_err:  # noqa: BLE001 — this exit must not itself raise
        print(f"[run.py] the forced close also failed ({close_err!r})", file=sys.stderr)
        return "ForcedCloseFailed"
    return exit_reason


def _dispatch_catalogs(defender_dir: Path, roster: RosterRead) -> tuple[str | None, str | None]:
    """The descriptor index each dispatch prompt opens with — MAIN's, narrowed to the gather
    role's committed grant, and lead-0's, narrowed to the correlation grant — built HERE,
    once, at run start, over the roster the run read, and handed down to the two dispatch
    sites rather than built inside them per dispatch. The one read that can fail for the
    tree is `read_roster`, and it ran at `run_investigation`'s own frame before any model
    call, so neither catalog can fail for it — not on the first dispatch inside a tool the
    model is mid-run on, and not inside item 3's task, which swallows its own failures into
    "injection skipped".

    The ROLE's committed grant, never the injected `verbs=` registry's: a registry scoped
    narrower than GATHER_DEF's real grant must not narrow what the catalog advertises (the
    same decoupling `build_agent` states at the dispatch tool's registration)."""
    from .. import lead_zero as lead_zero_mod

    skills = defender_dir / "skills"
    return (
        descriptor_catalog(skills, roster, GATHER_DEF.verb_grant),
        descriptor_catalog(skills, roster, lead_zero_mod.CORRELATION_GRANT),
    )


def _correlation_dispatch_at_run_start(
    defender_dir: Path, *, resume: Any, lead_zero_verbs: Any,
) -> CorrelationDispatch | None:
    """Item 3's dispatch identity, resolved FIRST — before the budget opens, the logger opens
    or any model exists — for a run that WILL dispatch the lead (#1003), and `None` for one
    that will not.

    WHETHER this run dispatches item 3 at all is decided here, once, on the two facts the
    dispatch frame itself keys on: a resume skips turn-0 work, and a scenario with no
    injected registry dispatches nothing. The dispatch frame then keys on the VALUE (`None`
    means "not this run"), so the check cannot refuse a run for a lead that run would never
    have consulted — a branch episode resuming every sibling world after an operator demoted
    the template — and the dispatch cannot run unchecked.

    Three inputs, each from where it is authored: the id from the run's own `lead-zero.yaml`
    (`load_correlation_template`, read here and nowhere earlier — there is no process-cached
    copy to fall behind the tree), the catalog of the run's own tree (walked, not linted,
    because the operator who can author the mismatch never runs repo CI), and the table's
    projection for the holder (`CORRELATION_GRANT`, process-level like every role's grant).
    An unresolvable, misfiled, malformed or disagreeing template raises
    `CorrelationDispatchError` out of `run_investigation`'s own frame, naming both sides, and
    nothing downstream is spent; an unusable config raises `LeadZeroConfigError` naming the
    file. A withheld lead (`system is None`) consults no template and degrades as before.

    The value is CARRIED to `prepare_correlation_lead` and `dispatch_correlation` rather than
    re-derived there: the system the lead is labelled with, dispatched on and cache-keyed by
    is the one this frame checked the template against, by construction.

    A sibling of `_adapters_at_run_start`, and the same shape: the one place a refusing read
    of the tree happens is a frame named for it at the entry point, not a builder's side
    effect."""
    if resume is not None or lead_zero_verbs is None:
        return None
    from .. import lead_zero as lead_zero_mod
    from ..lead_zero_config import lead_zero_config_path, load_correlation_template
    from ..tools_gather import _catalog_dir

    return lead_zero_mod.resolve_correlation_dispatch(
        load_correlation_template(lead_zero_config_path(defender_dir)),
        iter_query_templates(_catalog_dir(defender_dir)),
        lead_zero_mod.CORRELATION_GRANT,
    )


def _adapters_at_run_start(
    defender_dir: Path, roster: RosterRead | None, verbs: Any,
) -> tuple[RosterRead, Any]:
    """Everything a run resolves from an adapters tree, resolved FIRST — before the budget
    opens, the logger opens, or any model exists — so an adapters tree this process cannot
    read fails at `run_investigation`'s own frame as `RegistryError` naming it (#1031,
    #1035), never inside a tool the model is mid-run on.

    THE ROSTER is `run.py`'s one read, handed in beside the registry it built over it; it is
    read here, once, only for a caller that injected neither. Every consumer in this process
    takes the VALUE — the gather registry, both dispatch catalogs, the workspace map's
    Adapters section — and none holds a directory to go back to.

    The invlang `nothing-to-try` gate is priced against the CHECKOUT's roster (a closed
    universe this repo owns, not the run's tree), and it is HANDED that roster here
    (`hold_capabilities`) rather than reading for itself: in production the run's tree IS the
    checkout (`run.py` passes `DEFENDER_DIR`), so the one read above is the value the gate
    holds and the tree is read once; a caller whose `defender_dir` is another tree (the
    hermetic suite's fixtures) costs one more read, of the checkout, still here, still before
    any model call. Either way the read that can fail fails at this frame as `RegistryError`,
    never inside a guard on the document's path — the write gate's fail-closed wrap, the
    close's price wrap and the prepare-time readers each re-filed the host's fault as the
    document's when the gate read lazily on first use."""
    roster = roster if roster is not None else read_roster(adapters_under(defender_dir))  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    verbs = verbs if verbs is not None else ModuleVerbRegistry(roster, GATHER_DEF.verb_grant)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    checkout = DefenderPaths(_git.REPO_ROOT).adapters_dir
    hold_capabilities(
        roster if Path(roster.root).resolve() == checkout.resolve() else read_roster(checkout)
    )
    return roster, verbs


def _alert_doc_soft(alert_path: Path) -> dict:
    """The alert as item 3's contract reads it — `{}` when the file is unreadable or not
    JSON, because the contract's own gate (`_correlation_contract`: no usable timestamp, no
    dispatch) is the refusal, and item 1 has already said what it could about the file."""
    try:
        doc = json.loads(alert_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


async def run_investigation(  # noqa: PLR0913 — a composition root: every parameter is a
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
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
) -> dict:
    model_name = resolve_main_model(model_name)
    # Lead-0's OWN registry seam: a scenario that injected no `verbs=` at all must not have
    # lead-0 acquire one via the MAIN-gather default resolved below. Captured before it.
    lead_zero_verbs = verbs
    # lint-default: ok — DI seam owning its default (the gate's bounds, carrying the request
    # ceiling's BASE), resolved once at the entry point and threaded inward as a concrete value.
    gate_bounds = bounds if bounds is not None else challenge_gate.default_bounds()
    make_model = make_model or providers.build_for_effort
    roster, verbs = _adapters_at_run_start(defender_dir, roster, verbs)
    correlation = _correlation_dispatch_at_run_start(
        defender_dir, resume=resume, lead_zero_verbs=lead_zero_verbs,
    )
    catalog, correlation_catalog = _dispatch_catalogs(defender_dir, roster)
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

    case_id = uuid.uuid4().hex
    # R12's fifth DI seam, and a resume derives its own store and outranks it — the default and
    # the precedence both live in `_resolve_store_factory`, which is where the `lint-default`
    # site moved to as well.
    factory = _resolve_store_factory(resume, store_factory)
    store = None
    try:
        store = factory(case_id, run_dir)
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
        systems=tuple(roster.accepted), verbs=lead_zero_verbs, limits=limits, run_id=run_id,
    )

    # Item 3's async frame: scheduled here (after item 1 has resolved synchronously) and
    # awaited later, inside the store's render processor, right before MAIN's SECOND request.
    # A scenario with no injected registry dispatches nothing.
    correlation_task: Any = None
    # `correlation` is `None` exactly for a run that dispatches no item 3 (a resume, or no
    # injected registry — `_correlation_dispatch_at_run_start` decides that, once, and this
    # frame keys on its value); otherwise it is the identity the run-start check stood behind.
    if correlation is not None:
        from .. import lead_zero as lead_zero_mod

        contract = lead_zero_mod.prepare_correlation_lead(
            run_dir, _alert_doc_soft(alert_path), lead_zero_block, lead_zero_status,
            dispatch=correlation,
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
                catalog=correlation_catalog, dispatch=correlation,
            ))

    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
        store=store, session_id=session_id, review_stages=stages, bounds=gate_bounds,
        correlation_task=correlation_task, toolset=toolset, catalog=catalog,
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
