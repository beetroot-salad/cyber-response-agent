from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, NoReturn

from pydantic import ValidationError
from pydantic_ai import RunContext
from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.exceptions import (
    ModelRetry,
    ToolFailed,
)

from defender.runtime.tools._deps import run_of
from defender.hooks.budget_enforcer import BudgetKill
from defender._text import as_str
from defender._untrusted import wrap_fresh
from defender.learning.branch.redaction import redact_model_visible
from defender.integrations.faults import USAGE_EXIT_CODE, AdapterFault, ConfigFault
from defender.runtime.payload_view import payload_text_of, render as _render_payload
from defender.runtime.request_ceiling import WRITE_SUMMARY_NOW
from defender.runtime.tools import DeadEnd
from defender.runtime.record_query import (
    REPEAT_ESCAPE,
    GatherDeadEnd,
    RejectionBudgetTrip,
    RepeatTrip,
    append_query_row,
    bind_call_ids,  # noqa: F401 — driver binds the call identity through the query-tool seam
    next_call_id,
    dead_end_reason,
    names_something_readable,
    payload_digest,
    payload_status,
    persist_payload as _persist_payload,  # noqa: F401
    raw_command,
    rejection_budget_trip,
    rejection_dead_end,
    rejection_detail,
    rejection_trip,
    repeat_note,
    repeat_trip,
    repeat_trip_detail,
    system_fingerprint,
)
from defender.knowledge._query_rules import (
    ABOVE_GUARD_QUERY_ID,
    DENIED_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
    ParamsTooDeep,
    call_args_too_deep,
    _QID_FORBIDDEN,
    resolve_query_id,
)

from . import circuit_breaker
from . import system_status
from .run_state import run_state_of, run_time_iso
from .verbs import (
    CALL_DELIVERY,
    CALL_ID,
    DENIED,
    GRANTED,
    CallDelivery,
    VerbContext,
    validate_params,
)

from defender.runtime.query_catalog import (
    CONTROL_FLOW_EXCEPTIONS as CONTROL_FLOW_EXCEPTIONS,
    UNENFORCED_TYPE as UNENFORCED_TYPE,
    _LIST_VERBS_DOWN as _LIST_VERBS_DOWN,
    _LIST_VERBS_HEADER as _LIST_VERBS_HEADER,
    _LIST_VERBS_LEGEND as _LIST_VERBS_LEGEND,
    _LIST_VERBS_NONE_GRANTED as _LIST_VERBS_NONE_GRANTED,
    _LIST_VERBS_NO_VERBS as _LIST_VERBS_NO_VERBS,
    _LIST_VERBS_UNDERIVABLE as _LIST_VERBS_UNDERIVABLE,
    _LIST_VERBS_UNENFORCED_NOTE as _LIST_VERBS_UNENFORCED_NOTE,
    _LIST_VERBS_UNKNOWN_SYSTEM as _LIST_VERBS_UNKNOWN_SYSTEM,
    _LIST_VERBS_UNLOADABLE as _LIST_VERBS_UNLOADABLE,
    _LIST_VERBS_UNREACHABLE as _LIST_VERBS_UNREACHABLE,
    _RERAISE as _RERAISE,
    _SKILLS_REL as _SKILLS_REL,
    _echoed_system as _echoed_system,
    _granted_systems as _granted_systems,
    _json_default as _json_default,
    _list_verbs_declared as _list_verbs_declared,
    _list_verbs_line as _list_verbs_line,
    _logger as _logger,
    _registry_declares as _registry_declares,
    _rendered_param as _rendered_param,
    _tool_list_verbs as _tool_list_verbs,
    register_list_verbs_tool as register_list_verbs_tool,
)


TOOL_NAME = "query"

DEFAULT_FAULT_EXIT = 2

# ---------------------------------------------------------------------------------------------
# The door. A lead a guard stops is told so in the tool result, in gather's own vocabulary, and
# writes its summary on the next turn; nothing is raised out of the run. These sentences are
# what the gather model reads. The request ceiling is handled separately by `request_ceiling`,
# which withholds the tools on the final request.
# ---------------------------------------------------------------------------------------------

#: After a guard's dead end (`GatherDeadEnd.reason` precedes it): a FAILED tool result.
QUERY_DOOR_CLOSED = "No further queries can be issued on this lead. " + WRITE_SUMMARY_NOW
#: Any `query` after the door closed (a sibling in the closing round, or a later call). The
#: reason is in the tool result of the call that closed the door.
QUERY_NOT_RUN = (
    "This call was not executed: the lead was stopped by an earlier query. " + QUERY_DOOR_CLOSED
)


def _door_closed(deps: Any) -> bool:
    """A deps with no stop record (lead zero's harness-driven calls) has no door to close."""
    stop = getattr(deps, "stop", None)
    return stop is not None and stop.door_closed

#: How the host names a system it withheld, shared by the dead-end message and the row detail
#: so operators joining the two see one name.
UNDECLARED_SYSTEM = "an undeclared system"

#: The row detail for the grant check's unresolvable-verb rejection when the system was
#: coarsened away. A literal because the row already carries `system_key`, `verb` and `params`.
#: Unlike `_undeclared_target`, it does not ask whether the name was readable.
UNDECLARED_SYSTEM_DETAIL = "unresolvable: " + UNDECLARED_SYSTEM

#: The `query` tool's own parameter names (host material), used to tell a schema complaint about
#: a real argument from one quoting a key the model invented; others render as `argument`.
#: Hand-copied from `register_query_tool`'s closure, so it can drift; `_coarse_schema_detail`
#: also excludes `extra_forbidden` so a stale entry degrades rather than leaks.
DECLARED_ARGS = frozenset({"system", "verb", "params", "query_id"})

#: What the model is told, and the row records, for a call whose arguments nest too deep to
#: store. Fixed host text: pydantic's own error would echo the input.
PARAMS_TOO_DEEP = (
    str(ParamsTooDeep(field="the call's arguments"))
    + " — the call was not run. Send flatter arguments."
)

#: What a refused too-deep call's arguments become in the lead's history. Host text, shallow,
#: and still an argument object, as every provider requires of a tool call.
_REFUSED_ARGS = {"refused": "arguments nested too deep to keep; see the retry that follows"}

def _fault_exit(e: BaseException) -> int:
    if isinstance(e, SystemExit) and isinstance(e.code, int) and e.code != 0:
        return e.code
    return DEFAULT_FAULT_EXIT


def _dispatched_lead(deps: Any) -> str:
    """The lead this call was dispatched inside; its absence is an internal error, since every
    production `GatherDeps` binds one and every queries-table frame is lead-scoped."""
    if deps.lead_id is None:
        raise RuntimeError("internal: query reached capture without a dispatched lead_id")
    return deps.lead_id


def _model_visible(deps: Any, detail: str, known_ids: frozenset[str]) -> str:
    """`detail` as the model may read it: world ids removed (`known_ids` is the serving
    registry's `branch_identities()`, bound on the `QueryCapture`), and the tenant settings
    folder named rather than located. Both model-visible fault channels use this, so no
    adapter's error wording can put a host path in front of the model."""
    text = redact_model_visible(detail, known_ids)
    tenant = getattr(deps, "tenant", None)
    if tenant is None:
        return text
    from .verbs import redact_settings_path

    return redact_settings_path(text, tenant.settings)


class QueryCapture(AbstractCapability[Any]):

    def __init__(self, registry: Any, role: str = "gather", *, known_ids: frozenset[str]):
        """`known_ids`: every branch identity this run's process knows, removed from the fault
        text this capability shows the model or writes to the queries table. Required, with
        no default meaning "none": the run's builder passes its registry's
        `branch_identities()`, which is empty only for a natural run."""
        self._registry = registry
        self._role = role
        self._known_ids = frozenset(known_ids)

    def _denial_logger_for(self, run_dir: Any) -> Any:
        # Per run dir, not per capability: each gather lead has its own QueryCapture over one
        # shared run dir.
        from . import observe

        return observe.denial_logger(run_dir)

    def _resolve_guarded(
        self, system: str, verb: str, params: dict,
    ) -> tuple[Any, str | None]:
        """Resolve an admitted, runnable call, preserving registry fault accounting."""
        try:
            return self._registry.resolve_call(system, verb, params), None
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except BaseException as e:  # noqa: BLE001 — the registry could not LOAD this system's module
            return None, f"{system} adapter failed to load: {type(e).__name__}: {e}"

    def _system_of_record(self, system: str) -> str:
        """The `system` an above-guard row may carry: the model's string if the registry declares
        it, else `""`.

        Nothing downstream re-checks these rows, and the pitfalls channel uses an
        `agent-fixable` row's `system` verbatim as `defender/skills/<system>/execution.md`, so an
        undeclared name must not reach it. `""` rows are already skipped by
        `collect_general_failures`.

        Applies to the rejection guard's identity as well as the row, since the guard counts
        from the rows it wrote. `system_fingerprint` keeps distinct ghost names distinct in
        `system_key` without exposing them."""
        return system if system in self._registry.systems() else ""

    def _coarsen(self, raw_system: str) -> tuple[str, str]:
        """The above-guard pair `(system of record, system_key)`, computed together so the two
        halves cannot come from different inputs or have their `str` arguments transposed."""
        recorded = self._system_of_record(raw_system)
        return recorded, system_fingerprint(raw_system, recorded)

    @staticmethod
    def _was_coarsened(recorded: str) -> bool:
        """Did this row lose the model's `system` argument? Only such rows get a host-composed
        detail.

        Asked of the recorded value alone: `_system_of_record` returns its input unchanged or
        `""`, so emptiness is the whole predicate. A model-sent `system=""` (or a non-`str` or
        missing one) counts too, since its row is indistinguishable from a coarsened one and its
        detail would otherwise carry model text (a `loc` key, or a refusal naming the verb)."""
        return not recorded

    @staticmethod
    def _coarse_schema_detail(e: BaseException) -> str:
        """The detail a coarsened schema rejection records, built from host material only.

        `str(e)`, or a scrub of it, would carry model text via `input_value`, an invented `loc`
        key, and repr-escaping. So the sentence is built from: the error count; the field, which
        is `loc[0]` only if it is in `DECLARED_ARGS` and the error is not `extra_forbidden`
        (else `argument`; deeper `loc` elements are keys inside `params`); and pydantic's `msg`,
        which quotes no input (a `json_invalid` message names a position, which is kept).
        `include_input=False` alone is not enough, since it leaves `loc`.

        A non-`ValidationError` (`ModelRetry`) keeps `str(e)`: no retry that reaches this hook
        formats an argument, because `query` has no per-tool args validator. Adding one that
        does would make this unsafe."""
        if not isinstance(e, ValidationError):
            return str(e)
        errs = e.errors(include_input=False, include_url=False)
        parts = []
        for err in errs:
            # Nothing here may raise: an exception would replace the rejection and lose its row,
            # unbounding the repeat guard. Hence `.get`, and `isinstance` before the membership
            # test, since `in frozenset` hashes an unhashable `loc` element and raises.
            head = next(iter(err.get("loc") or ()), None)
            field = (
                head if isinstance(head, str) and head in DECLARED_ARGS
                and err.get("type") != "extra_forbidden"
                else "argument"
            )
            parts.append(f"{field}: {err.get('msg', '')}")
        return f"{len(errs)} validation error(s): " + "; ".join(parts)

    @staticmethod
    def _undeclared_target(*, recorded: str, raw: str) -> str:
        """What the dead-end message calls the request's target.

        The raw string is unbounded model text bound for MAIN's context, so it is never echoed;
        a readable undeclared name becomes `UNDECLARED_SYSTEM` (a bare `""` would wrongly say
        the call named nothing readable). Keyword-only because swapping the two `str` halves
        would leak the model's string into MAIN. Readability uses the same predicate as
        `system_fingerprint`, so every member of a repeat group gets one answer."""
        return recorded or (UNDECLARED_SYSTEM if names_something_readable(raw) else "")

    def _forbidden_reject(self, model_query_id: Any) -> str | None:
        # Names every forbidden character, not just the path ones, so the caller can act on it.
        if model_query_id and any(t in str(model_query_id) for t in _QID_FORBIDDEN):
            return (
                f"invalid query_id {model_query_id!r}: no '/', '\\', '..', NUL, newline or '#' "
                "— it becomes a catalog path segment and a markdown span the offline collectors "
                "render. Coin a `{system}.{kebab-name}` id."
            )
        return None

    def _rejection_guard(
        self, deps, system: str, verb: str, params: dict, *, system_key: str,
    ) -> RepeatTrip | RejectionBudgetTrip | None:
        """The two guards on calls rejected above `wrap_tool_execute`'s own guard (argument
        schema, and the grant check's unresolvable-verb branch); the domains do not overlap.

        Identity and `system_key` are extracted by the caller, which holds the right argument
        surface and the raw string. One read of the lead's rows on the run's state feeds both
        predicates so they answer over the same rows. Repeat is asked first because its message
        is more specific (it names the repeated request). The budget is identity-blind, which is
        how it catches loops the repeat guard cannot (a new undeclared name each turn,
        whitespace drift)."""
        lead_id = _dispatched_lead(deps)
        rows = run_state_of(deps).lead_rows(lead_id)
        trip = rejection_trip(
            rows, lead_id,
            system=system, verb=verb, params=params, system_key=system_key,
        )
        if trip is not None:
            return trip
        return rejection_budget_trip(rows, lead_id)

    async def wrap_tool_validate(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)
        # Too deep to store is a schema rejection, decided before pydantic parses anything;
        # judged on the call as sent, since text too deep to decode would read as `{}` once
        # decoded.
        if call_args_too_deep(args):
            # The refused call stays in the lead's history, which is stored, logged and re-sent
            # with every later request: its arguments must not. Past the session store's bound
            # its next write refused the history and ended the lead.
            call.args = (dict(_REFUSED_ARGS) if isinstance(call.args, dict)
                         else json.dumps(_REFUSED_ARGS))
            await self._reject(ctx, args, None)
        try:
            return await handler(args)
        except (ValidationError, ModelRetry) as refused:
            await self._reject(ctx, args, refused)

    async def _reject(
        self, ctx, args: Any, refused: ValidationError | ModelRetry | None,  # noqa: ANN001 — the framework's run context
    ) -> NoReturn:
        """Row a schema-rejected `query` call, charge it to the lead's guards, and raise what
        the model is told. `refused` is pydantic's (or a validator's) refusal; `None` for a
        call too deep to store, which pydantic is never shown."""
        # After the door closed, a schema-refused call is neither retried (that would charge
        # the retry budget on a stopped lead) nor rowed.
        if _door_closed(ctx.deps):
            raise ToolFailed(QUERY_NOT_RUN) from refused
        raw = _raw_args(args)
        # Raw arguments, since validation failed. A non-dict `params` becomes `{}`, matching
        # what the row stores, so live and replayed counts agree. Too-deep params become `{}`
        # before the guard too: the guard's identity is then the stored one (keying the deep
        # value itself can exhaust the stack), and the row stays readable. Text too deep for
        # `json.loads` (about 1000 levels) decodes to nothing, so its system and verb read as
        # `""` as well: every such call shares one identity, which trips the repeat guard
        # sooner, not later.
        raw_system = as_str(raw.get("system"))
        verb = as_str(raw.get("verb"))
        params = {} if refused is None else _as_dict(raw.get("params"))
        system, system_key = self._coarsen(raw_system)
        trip = self._rejection_guard(ctx.deps, system, verb, params, system_key=system_key)
        # `str(refused)` carries model text, so a coarsened row gets a host-composed detail,
        # and a too-deep call the fixed host sentence (pydantic's error echoes the input).
        if refused is None:
            rejection = PARAMS_TOO_DEEP
        elif self._was_coarsened(system):
            rejection = self._coarse_schema_detail(refused)
        else:
            rejection = str(refused)
        # The trip phrase wraps the already-coarsened detail, so the coarsening also holds on
        # the trip row. `rejection_detail` dispatches over both guards' trip types.
        detail = rejection if trip is None else rejection_detail(trip, rejection)
        await self._record(
            ctx.deps,
            system=system, verb=verb, system_key=system_key,
            query_id=ABOVE_GUARD_QUERY_ID,
            params=params,
            payload=None,
            exit_code=USAGE_EXIT_CODE,
            detail=detail,
        )
        if trip is not None:
            raise self._stop(ctx, rejection_dead_end(
                trip,
                target=self._undeclared_target(recorded=system, raw=raw_system),
                verb=verb,
            )) from refused
        if refused is None:
            raise ModelRetry(PARAMS_TOO_DEEP)
        raise refused

    async def _record_denied(
        self, deps, *, system: str, verb: str, params: dict, refusal: str,
    ) -> None:
        """Write the `∅.denied` sentinel row, so the refused attempt is in the lead's table.

        It charges nothing: not an infra exit code (no breaker), and outside both guards'
        domains. `system_key=""` because DENIED only occurs for a system the grant names.

        A failed row write is logged and dropped rather than raised: the denial is a business
        outcome the model must see and continue past, and the audit record already holds it."""
        try:
            await self._record(
                deps, system=system, verb=verb, query_id=DENIED_QUERY_ID, params=params,
                payload=None, exit_code=circuit_breaker.DENIED_EXIT_CODE, detail=refusal,
                system_key="",
            )
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except Exception as write_failed:  # noqa: BLE001 — see the docstring
            _logger.warning(f"could not record the denied row for {system}.{verb} "
                            f"({write_failed!r}); the refusal itself is what the model sees")

    async def _grant_check(
        self, deps, system: str, verb: str, params: dict,
    ) -> tuple[Any, str | None]:
        """The grant check, ahead of everything else: a denied call always produces its denial
        record (and a `∅.denied` sentinel row), never an evidence row. Returns
        `(decision, early_result)`; `early_result` is set when the caller must return early."""
        decision = self._registry.authorize_call(system, verb, params)
        if decision.outcome == DENIED:
            refusal = decision.refusal or f"denied: {system}.{verb}"
            # Audit record first, above the door: a stopped lead does not get a quieter audit
            # trail, and a failed row write below has already left it behind.
            self._denial_logger_for(run_of(deps)).log_policy_denial(
                role=self._role, system=system, verb=verb,
                call_id=f"{system}.{verb}", params=params, ts=run_time_iso(deps),
            )
            # A closed door withholds only the row; the denial is still answered as a denial,
            # not as `QUERY_NOT_RUN`.
            if not _door_closed(deps):
                await self._record_denied(deps, system=system, verb=verb, params=params,
                                          refusal=refusal)
            # Not `_model_view`, which prepends repeat coaching: retrying cannot fix a denial.
            return None, _format_bash_result(
                circuit_breaker.DENIED_EXIT_CODE, "", wrap_fresh(refusal, "untrusted"), "",
            )

        # The door sits below the grant decision (denials are always recorded) and above every
        # row: a call after the door closed, whether a sibling in the closing round or a later
        # call, never runs and is not counted.
        if _door_closed(deps):
            raise ToolFailed(QUERY_NOT_RUN)

        if decision.outcome != GRANTED:
            await self._reject_unresolved(deps, decision, system, verb, params)

        return decision, None

    async def _reject_unresolved(self, deps, decision, system: str, verb: str, params: dict):
        """Record and reject an undeclared call at either decision stage."""
        # Unresolvable verb: same guard and coarsening as the schema placement. A declared
        # system with an unknown verb still records its name.
        refusal = decision.refusal or f"unresolvable: {system}.{verb}"
        recorded_system, system_key = self._coarsen(system)
        trip = self._rejection_guard(
            deps, recorded_system, verb, params, system_key=system_key,
        )
        # The model gets the full refusal; a coarsened row gets a host literal instead, since
        # the refusal names the model's system. A declared system keeps the refusal, which
        # the pitfalls channel needs.
        rejection = (
            UNDECLARED_SYSTEM_DETAIL
            if self._was_coarsened(recorded_system)
            else (decision.refusal or "unresolvable")
        )
        # The trip phrase wraps the coarsened detail, as at the schema placement.
        detail = rejection if trip is None else rejection_detail(trip, rejection)
        await self._record(
            deps, system=recorded_system, verb=verb, system_key=system_key,
            query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
            exit_code=USAGE_EXIT_CODE,
            detail=detail,
        )
        if trip is not None:
            raise rejection_dead_end(
                trip,
                target=self._undeclared_target(recorded=recorded_system, raw=system),
                verb=verb,
            )
        raise ModelRetry(refusal)

    async def _resolve_check(self, deps, system: str, verb: str, params: dict):
        """Gate down systems before resolution, then file load faults or declaration failures."""
        # A down system answers before callable resolution, parameter screens or adapter I/O.
        refused = _down_refusal(deps, system)
        if refused is not None:
            return None, refused

        decision, load_error = self._resolve_guarded(system, verb, params)
        if load_error is not None:
            row, text = await self._record(
                deps, system=system, verb=verb,
                query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
                exit_code=DEFAULT_FAULT_EXIT, detail=load_error,
                # `infra` rows are outside `rejection_trip`, so there is no count for a
                # fingerprint to separate.
                system_key="",
            )
            return None, self._model_view(deps, row, text, DEFAULT_FAULT_EXIT, load_error)

        if decision.outcome != GRANTED:
            await self._reject_unresolved(deps, decision, system, verb, params)

        return decision, None

    async def _screen(
        self, deps, decision: Any, system: str, verb: str, params: dict,
        model_query_id: Any,
    ) -> None:
        """The per-call screens below the grant and the breaker (query_id, params).
        Raises `ModelRetry` after writing a usage row when one refuses."""
        reason = self._forbidden_reject(model_query_id)
        if reason is None:
            reason = validate_params(decision.fn, params)
        if reason is not None:
            await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None),
                params=params, payload=None,
                exit_code=USAGE_EXIT_CODE, detail=reason, system_key="",
            )
            raise ModelRetry(reason)

    @staticmethod
    def _stop(ctx, dead_end: GatherDeadEnd) -> BaseException:
        """Close the lead's door and return what this call raises instead: a `ToolFailed` with
        the guard's reason and the closing sentence. Not `ModelRetry`, which would say "try
        again" and charge the retry budget. Without a stop record (lead zero's harness-driven
        calls), the dead end itself."""
        stop = getattr(ctx.deps, "stop", None)
        if stop is None:
            return dead_end
        stop.close_door(DeadEnd(dead_end.reason, dead_end.escape))
        return ToolFailed(f"{dead_end.reason} {QUERY_DOOR_CLOSED}")

    async def wrap_tool_execute(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)
        # Validation refuses a model's too-deep call before it gets here. A call that skipped
        # validation (lead zero issues host-built calls straight to this hook) is held to the
        # same rule, loudly and first: host-built params are shallow by construction, and past
        # here the grant check, the breaker and every row assume params a row can carry.
        if call_args_too_deep(args):
            raise ParamsTooDeep(field="the call's arguments")
        token = CALL_ID.set(next_call_id(run_state_of(ctx.deps)))
        try:
            return await self._execute(ctx, args, handler)
        except GatherDeadEnd as e:
            failed = self._stop(ctx, e)
            if failed is e:
                raise
            raise failed from e
        finally:
            CALL_ID.reset(token)

    async def _execute(self, ctx, args, handler):  # noqa: ANN001
        """The call itself. Raises `GatherDeadEnd` for a guard's stop; `wrap_tool_execute` owns
        the door."""
        deps = ctx.deps
        system = as_str(args.get("system"))
        verb = as_str(args.get("verb"))
        params = _as_dict(args.get("params"))
        model_query_id = args.get("query_id")

        decision, early_result = await self._grant_check(deps, system, verb, params)
        if early_result is not None:
            return early_result

        decision, early_result = await self._resolve_check(deps, system, verb, params)
        if early_result is not None:
            return early_result

        # Repeat guard above `_screen`, so a repeated bad call trips instead of earning yet
        # another identical `ModelRetry`.
        rows = run_state_of(deps).lead_rows(deps.lead_id)
        trip = repeat_trip(rows, deps.lead_id, system=system, verb=verb, params=params)
        if trip is not None:
            # A sentinel id, not the model's: offline collectors partition on `query_id`, and a
            # coined or catalog id would misfile the trip row as a draft template or a template
            # failure.
            await self._record(
                deps, system=system, verb=verb, query_id=REPEAT_TRIP_QUERY_ID, params=params,
                payload=None, exit_code=USAGE_EXIT_CODE, detail=repeat_trip_detail(trip),
                system_key="",
            )
            executed = sum(1 for r in rows if r.get("exit_code") == 0)
            raise GatherDeadEnd(
                reason=dead_end_reason(system, verb, trip, executed),
                escape=REPEAT_ESCAPE,
            )

        await self._screen(
            deps, decision, system, verb, params, model_query_id,
        )

        query_id = resolve_query_id(system, verb, as_str(model_query_id) or None)

        payload: Any = None
        escaped = False
        try:
            payload = await handler(args)
            exit_code, detail = 0, ""
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except ConfigFault as e:
            # A settings fault the system's start check did not catch (#1256 O-5b, DP3): the
            # system is not configured for this run, from this call on.
            exit_code, detail, escaped = e.exit_code, e.detail, True
        except AdapterFault as e:
            exit_code, detail = e.exit_code, e.detail
        except BaseException as e:  # noqa: BLE001 — the point: an unmapped fault still writes a row
            exit_code, detail = _fault_exit(e), str(e) or type(e).__name__

        if escaped:
            # Marked down before the row, so a sibling lead's call racing this one is refused;
            # the row records the call that ran, uncharged (the breaker counts only what can
            # change during a run, DP2), and the answer is the not-configured refusal every
            # later call gets, naming the fault's reason.
            defender_dir = getattr(deps, "defender_dir", None)
            system_status.mark_escaped(
                run_state_of(deps), system, detail, tenant=getattr(deps, "tenant", None),
                defender_dir=Path(defender_dir) if defender_dir is not None else None)
            await self._record(
                deps, system=system, verb=verb, query_id=query_id, params=params,
                payload=payload, exit_code=exit_code, detail=detail, system_key="",
                charged=False,
            )
            refused = _down_refusal(deps, system)
            assert refused is not None, "a system just marked down is down"
            return refused
        row, text = await self._record(
            deps, system=system, verb=verb, query_id=query_id, params=params,
            payload=payload, exit_code=exit_code, detail=detail, system_key="",
        )
        return self._model_view(deps, row, text, exit_code, detail)

    async def _record(  # noqa: PLR0913 — one per row column the CALLER decides, plus `deps`
        self, deps, *, system: str, verb: str, query_id: str, params: dict,
        payload: Any, exit_code: int, detail: str, system_key: str, charged: bool = True,
    ) -> tuple[dict, str]:
        """Append the row and charge the circuit breaker to its `system`.

        The charge is the call's outcome, not the view's: it lands whether or not the row's
        view line could be written. A refused write (`append_query_row` has already recorded
        the row in the run's state) is charged first and then propagates; the run is not told
        the call was viewed. `charged=False` writes the row only: a call whose `ConfigFault`
        escaped the start check marks its system not configured, which the breaker never
        counts (#1256 O-5b).

        A coarsened row charges `""`, which `record_outcome` skips; the rejection guards bound
        those instead. `system_key` has no default so every writer must state it explicitly.

        No lock of its own: `append_query_row` takes the seq and records the row under the
        run state's lock, and nothing here awaits between the two."""
        lead_id = _dispatched_lead(deps)
        state = run_state_of(deps)

        text = "" if exit_code != 0 else payload_text_of(payload)

        try:
            row = append_query_row(
                state,
                run=run_of(deps),
                lead_id=lead_id,
                system=system,
                verb=verb,
                query_id=query_id,
                params=params,
                raw_command=raw_command(system, verb, params),
                payload_text=text,
                exit_code=exit_code,
                payload_status=payload_status(exit_code, payload),
                # Redacted: this table is in gather's read scope, so a staged name here would
                # reach the model on a second channel. Redacted before truncation so the cut
                # cannot split a name. The failure envelope is composed here, as in the other
                # writers; `payload_digest` is only called for success.
                payload_digest=(
                    payload_digest(text, "", 0) if exit_code == 0
                    else f"exit={exit_code}; "
                    f"{_model_visible(deps, detail, self._known_ids).strip()[:160]}"
                ),
                system_key=system_key,
                call_id=CALL_ID.get(),
            )
        finally:
            if charged:
                circuit_breaker.record_outcome(
                    state, system, exit_code,
                    counts_toward_run=not getattr(deps, "harness_lead", False))
        return row, text

    def _model_view(self, deps, row: dict, text: str, exit_code: int, detail: str) -> str:
        note = _payload_note(deps, row)
        # Computed for failures too: a lead repeating a failing call is the most likely to loop.
        repeat = repeat_note(
            run_state_of(deps), deps.lead_id, seq=row["seq"], system=row["system"],
            verb=row["verb"], params=row["params"],
            payload_digest=row["payload_digest"], payload_sha256=row["payload_sha256"],
            exit_code=exit_code,
        )
        if exit_code != 0:
            # The repeat note goes inside the untrusted wrap so the result stays one span.
            # Redacted here at the boundary because fault details also arrive verbatim from the
            # backend, which we do not author.
            visible = _model_visible(deps, detail, self._known_ids)
            body = visible if repeat is None else f"{repeat}\n{visible}"
            return _format_bash_result(exit_code, "", wrap_fresh(body, "untrusted"), note)
        # `render` decides whether the payload fits; callers do not.
        view = _render_payload(text, row["payload_path"], deps.run_dir)
        if repeat is not None:
            view = f"{repeat}\n{view}"
        return _format_bash_result(0, wrap_fresh(view, "untrusted"), "", note)


def register_query_tool(agent, registry) -> None:

    @agent.tool
    async def query(
        ctx: RunContext[Any], system: str, verb: str,
        params: dict[str, Any], query_id: str | None = None,
    ) -> Any:
        """Run one data-source query. `system` and `verb` name a declared verb — `list_verbs`
        answers which verbs this role holds on a system and what each one binds; `params` binds
        that verb's declared params by NAME (a verb declares exactly what it takes — there are
        no flags, no shell, and no `--help`).
        `query_id` binds this call to a catalog template id (`{system}.{template}`), or a fresh
        `{system}.{kebab-name}` you coin for a query no template covers; omit it and it derives
        as `{system}.{verb}`. The payload is captured to the queries table and persisted whole on
        disk automatically — you get a field-shape view plus the path to compute over."""
        deps = ctx.deps
        fn = registry.verbs(system)[verb]
        vctx = VerbContext(
            defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=_bash_env(deps),
            tenant=deps.tenant, run_state=deps.run_state,
        )
        delivery = CallDelivery()
        token = CALL_DELIVERY.set(delivery)
        try:
            return await asyncio.to_thread(fn, vctx, **params)
        except asyncio.CancelledError:
            # The worker runs on; whatever it would record as delivered, it was not.
            delivery.abandoned = True
            raise
        finally:
            CALL_DELIVERY.reset(token)


def _raw_args(args: Any) -> dict:
    """The call's arguments as the model sent them, coerced to a dict; never raises.

    `RecursionError` is caught because a deeply nested body that pydantic just refused also
    exhausts `json.loads`, and escaping would lose the rejection's row."""
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except (json.JSONDecodeError, ValueError, RecursionError):
            return {}
    return args if isinstance(args, dict) else {}


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


from .tools import _bash_env, _format_bash_result  # noqa: E402
from .tools_gather import _down_refusal, _payload_note  # noqa: E402


__all__ = [
    "CONTROL_FLOW_EXCEPTIONS",
    "DEFAULT_FAULT_EXIT",
    "QueryCapture",
    "TOOL_NAME",
    "UNENFORCED_TYPE",
    "register_list_verbs_tool",
    "register_query_tool",
    "resolve_query_id",
]
