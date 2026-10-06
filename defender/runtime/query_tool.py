
from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Mapping
from typing import Any, NoReturn

from pydantic import ValidationError
from pydantic_ai import RunContext
from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.exceptions import (
    ApprovalRequired,
    CallDeferred,
    ModelRetry,
    SkipToolExecution,
    ToolFailed,
    ToolRetryError,
)

from defender.hooks.budget_enforcer import BudgetKill
from defender._text import as_str
from defender._untrusted import wrap_fresh
from defender.learning.branch.redaction import redact_model_visible
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault
from defender.runtime.payload_view import render as _render_payload
from defender.runtime import case_ticket
from defender.runtime.request_ceiling import WRITE_SUMMARY_NOW
from defender.runtime.tools import DeadEnd
from defender.scripts.gather_tools.record_query import (
    REPEAT_ESCAPE,
    GatherDeadEnd,
    RejectionBudgetTrip,
    RepeatTrip,
    append_query_row,
    dead_end_reason,
    lead_rows,
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
from defender._query_rules import (
    ABOVE_GUARD_QUERY_ID,
    DENIED_QUERY_ID,
    REPEAT_TRIP_QUERY_ID,
    ParamsTooDeep,
    call_args_too_deep,
    _QID_FORBIDDEN,
    resolve_query_id,
)

from . import circuit_breaker
from .ticket_screen import (
    TICKET_GET,
    TICKET_LIST,
    TICKET_SYSTEM,
    screen_get,
    screen_list,
    screen_release_get,
    screen_release_list,
    self_case_key,
)
from .verbs import (
    DENIED,
    GRANTED,
    VerbContext,
    _ann_name,
    _resolved_hints,
    SYSTEM_MAX_LEN,
    is_system_name,
    model_facing_params,
    validate_params,
)

_logger = logging.getLogger(__name__)

TOOL_NAME = "query"

CONTROL_FLOW_EXCEPTIONS: tuple[type[BaseException], ...] = (
    circuit_breaker.RunAborted,
    ModelRetry,
    SkipToolExecution,
    CallDeferred,
    ApprovalRequired,
    ToolRetryError,
)

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


def _self_ticket_reject_reason(
    self_key: str, system: str, verb: str, params: dict,
) -> str | None:
    """Reject a direct gather read of its own case before the ticket store is contacted.

    Gather keeps access to other tickets, including open ones used for correlation. The case key
    is carried on deps (``ticket_screen.self_case_key``), not inferred from a path.
    """
    if system == TICKET_SYSTEM and verb == TICKET_GET and params.get("key") == self_key:
        return (
            "that key is the current investigation's own ticket and cannot be read through "
            "gather. Correlate a different ticket; open and in-progress related cases remain "
            "available."
        )
    return None


def _release_predicate(tenant: Any) -> Any:
    """The ticket release predicate, built per call from the run's record (#1107: the mapping
    is the one resolved when the run began, so a mid-run file edit changes nothing).

    Any construction failure (no mapping, or a mapping the loader kept as its error) degrades to
    "nothing released", so no comment is served (fail closed), rather than refusing the query as
    infra and charging the `ticket` breaker for a config defect. The warning is logged because
    otherwise a broken mapping looks like a store with no comments."""
    try:
        return case_ticket.release_predicate(tenant.ticket_mapping).is_released
    except Exception as e:  # noqa: BLE001 — degrade on every construction failure, see docstring
        _logger.warning(
            f"ticket release predicate unavailable ({e}); serving no "
            "ticket comments this call",
        )
        return lambda _ticket: False


def _screen_ticket_payload(
    self_key: str, system: str, verb: str, payload: Any, *, tenant: Any,
) -> tuple[Any, int, str]:
    """Apply gather's current-case exclusion, then the per-ticket release step, before capture
    and model display.

    The exclusion is identity-only: another ticket mentioning ``self_key`` is still useful
    correlation evidence, since gather is not scoring the case. A record whose key cannot be
    established is withheld. The release step runs only after a served payload (``code == 0``),
    so a malformed envelope is never patched. `tenant` is the run's record (#1107): the
    released status is that tenant's mapping's, as of the run's start.
    """
    if system != TICKET_SYSTEM:
        return payload, 0, ""

    if verb == TICKET_GET:
        payload, code, detail = screen_get(
            payload,
            require_key=True,
            withhold=lambda ticket: (
                "the ticket store returned the current investigation's own ticket; its "
                "content was withheld from gather."
                if ticket["key"] == self_key else None
            ),
        )
        if code != 0:
            return payload, code, detail
        return screen_release_get(payload, is_released=_release_predicate(tenant)), 0, ""

    if verb == TICKET_LIST:
        payload, code, detail = screen_list(
            payload,
            keep=lambda ticket: (
                isinstance(ticket.get("key"), str) and ticket["key"] != self_key
            ),
        )
        if code != 0:
            return payload, code, detail
        return screen_release_list(payload, is_released=_release_predicate(tenant)), 0, ""

    return payload, 0, ""


def _dispatched_lead(deps: Any) -> str:
    """The lead this call was dispatched inside; its absence is an internal error, since every
    production `GatherDeps` binds one and every queries-table frame is lead-scoped."""
    if deps.lead_id is None:
        raise RuntimeError("internal: query reached capture without a dispatched lead_id")
    return deps.lead_id


def _model_visible(deps: Any, detail: str) -> str:
    """`detail` as the model may read it: staged names and world ids removed, and the tenant
    settings folder named rather than located. Both model-visible fault channels use this, so
    no adapter's error wording can put a host path in front of the model."""
    text = redact_model_visible(detail)
    tenant = getattr(deps, "tenant", None)
    if tenant is None:
        return text
    from .verbs import redact_settings_path

    return redact_settings_path(text, tenant.settings)


class QueryCapture(AbstractCapability[Any]):

    def __init__(self, registry: Any, role: str = "gather"):
        self._registry = registry
        self._role = role
        self._seq_lock = asyncio.Lock()

    def _denial_logger_for(self, run_dir: Any) -> Any:
        # Per run dir, not per capability: each gather lead has its own QueryCapture over one
        # shared run dir.
        from . import observe

        return observe.denial_logger(run_dir)

    def _decide_guarded(
        self, system: str, verb: str, params: dict,
    ) -> tuple[Any, str | None]:
        """The grant decision, guarded so a broken adapter import degrades instead of unwinding
        the stage. Uses `decide_call` so a registry that records served calls records this one."""
        try:
            return self._registry.decide_call(system, verb, params), None
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
        surface and the raw string. One `lead_rows` read feeds both predicates so they answer
        over the same table state. Repeat is asked first because its message is more specific
        (it names the repeated request). The budget is identity-blind, which is how it catches
        loops the repeat guard cannot (a new undeclared name each turn, whitespace drift)."""
        lead_id = _dispatched_lead(deps)
        rows = lead_rows(deps.run_dir, lead_id)
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
        decision, load_error = self._decide_guarded(system, verb, params)
        if load_error is None and decision.outcome == DENIED:
            refusal = decision.refusal or f"denied: {system}.{verb}"
            # Audit record first, above the door: a stopped lead does not get a quieter audit
            # trail, and a failed row write below has already left it behind.
            self._denial_logger_for(deps.run_dir).log_policy_denial(
                role=self._role, system=system, verb=verb,
                call_id=f"{system}.{verb}", params=params,
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

        if load_error is not None:
            # Breaker check here too: these `infra` rows are outside `rejection_trip`, so the
            # breaker must bound a failing import (retried every call, since only successes are
            # cached). Before `_record`, so a down answer writes no row. Not hoisted above the
            # DENIED branch, which always owes its denial record.
            tripped = _tripped_message(deps, system)
            if tripped is not None:
                return None, tripped
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

        return decision, None

    async def _screen(
        self, deps, decision: Any, system: str, verb: str, params: dict,
        model_query_id: Any, self_key: str,
    ) -> None:
        """The per-call screens below the grant and the breaker (query_id, params, self-ticket).
        Raises `ModelRetry` after writing a usage row when one refuses."""
        reason = self._forbidden_reject(model_query_id)
        if reason is None:
            reason = validate_params(decision.fn, params)
        if reason is None:
            reason = _self_ticket_reject_reason(self_key, system, verb, params)
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
        try:
            return await self._execute(ctx, args, handler)
        except GatherDeadEnd as e:
            failed = self._stop(ctx, e)
            if failed is e:
                raise
            raise failed from e

    async def _execute(self, ctx, args, handler):  # noqa: ANN001
        """The call itself. Raises `GatherDeadEnd` for a guard's stop; `wrap_tool_execute` owns
        the door."""
        # Validation refuses a model's too-deep call before it gets here. A call that skipped
        # validation (lead zero issues host-built calls straight to this hook) is held to the
        # same rule, loudly and first: host-built params are shallow by construction, and past
        # here the grant check, the breaker and every row assume params a row can carry.
        if call_args_too_deep(args):
            raise ParamsTooDeep(field="the call's arguments")
        deps = ctx.deps
        system = as_str(args.get("system"))
        verb = as_str(args.get("verb"))
        params = _as_dict(args.get("params"))
        model_query_id = args.get("query_id")
        self_key = self_case_key(deps)

        decision, early_result = await self._grant_check(deps, system, verb, params)
        if early_result is not None:
            return early_result

        # Breaker before the screens: a system known down answers "down", not a param complaint.
        tripped = _tripped_message(deps, system)
        if tripped is not None:
            return tripped

        # Repeat guard above `_screen`, so a repeated bad call trips instead of earning yet
        # another identical `ModelRetry`.
        rows = lead_rows(deps.run_dir, deps.lead_id)
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
            deps, decision, system, verb, params, model_query_id, self_key,
        )

        query_id = resolve_query_id(system, verb, as_str(model_query_id) or None)

        payload: Any = None
        try:
            payload = await handler(args)
            payload, exit_code, detail = _screen_ticket_payload(
                self_key, system, verb, payload, tenant=deps.tenant,
            )
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except AdapterFault as e:
            exit_code, detail = e.exit_code, e.detail
        except BaseException as e:  # noqa: BLE001 — the point: an unmapped fault still writes a row
            exit_code, detail = _fault_exit(e), str(e) or type(e).__name__

        row, text = await self._record(
            deps, system=system, verb=verb, query_id=query_id, params=params,
            payload=payload, exit_code=exit_code, detail=detail, system_key="",
        )
        return self._model_view(deps, row, text, exit_code, detail)

    async def _record(  # noqa: PLR0913 — one per row column the CALLER decides, plus `deps`
        self, deps, *, system: str, verb: str, query_id: str, params: dict,
        payload: Any, exit_code: int, detail: str, system_key: str,
    ) -> tuple[dict, str]:
        """Append the row and charge the circuit breaker to its `system`.

        A coarsened row charges `""`, which `record_outcome` skips; the rejection guards bound
        those instead. `system_key` has no default so every writer must state it explicitly."""
        lead_id = _dispatched_lead(deps)

        text = "" if exit_code != 0 else json.dumps(payload, default=str)
        run_dir = deps.run_dir

        async with self._seq_lock:
            # Kept locked in case an `await` is ever added inside.
            row = append_query_row(
                run_dir,
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
                    else f"exit={exit_code}; {_model_visible(deps, detail).strip()[:160]}"
                ),
                system_key=system_key,
            )

        circuit_breaker.record_outcome(run_dir, system, exit_code)
        return row, text

    def _model_view(self, deps, row: dict, text: str, exit_code: int, detail: str) -> str:
        note = _payload_note(deps, row)
        # Computed for failures too: a lead repeating a failing call is the most likely to loop.
        repeat = repeat_note(
            deps.run_dir, deps.lead_id, seq=row["seq"], system=row["system"],
            verb=row["verb"], params=row["params"],
            payload_digest=row["payload_digest"], payload_sha256=row["payload_sha256"],
            exit_code=exit_code,
        )
        if exit_code != 0:
            # The repeat note goes inside the untrusted wrap so the result stays one span.
            # Redacted here at the boundary because fault details also arrive verbatim from the
            # backend, which we do not author.
            visible = _model_visible(deps, detail)
            body = visible if repeat is None else f"{repeat}\n{visible}"
            return _format_bash_result(exit_code, "", wrap_fresh(body, "untrusted"), note)
        # `render` decides whether the payload fits; callers do not.
        view = _render_payload(text, row["payload_path"], deps.run_dir)
        if repeat is not None:
            view = f"{repeat}\n{view}"
        return _format_bash_result(0, wrap_fresh(view, "untrusted"), "", note)



#: What a param renders as when its annotation could not be resolved. `_resolved_hints` then
#: returns `{}` for the whole verb and `validate_params` type-checks nothing, so printing the
#: annotation would promise a check that is not made.
UNENFORCED_TYPE = "type unenforced"

#: The grant-first answer: absent and withheld systems read the same, so discovery neither
#: imports an ungranted adapter nor becomes an oracle over the on-disk roster. Listing the
#: reachable systems discloses nothing new (the dispatch prompt lists them) and fixes typos.
_LIST_VERBS_UNREACHABLE = (
    "`{system}` — your grant reaches no verb on any system by that name, so there is nothing "
    "here you may run and no surface to show you.{roster} Measure this lead against a system "
    "you do hold, or say so in your summary rather than reporting a measurement you could not "
    "take."
)

_LIST_VERBS_UNKNOWN_SYSTEM = (
    "`{system}` — no adapter is registered under that name, so no verb surface can be derived "
    "for it. The Dispatch block at the end of your prompt names the system you were dispatched "
    "to; confirm it there and call this again with that name."
)

#: Reached only for a name that passed `_adapter_path_under`'s checks, so interpolating it into
#: a path is safe. `execution.md` holds only value constraints and pitfalls, not verbs.
_LIST_VERBS_UNLOADABLE = (
    "`{system}` — UNAVAILABLE: its adapter could not be loaded ({err}). No verb surface can be "
    "derived for it right now, and no file carries a copy — the verb roster and its params are "
    "read from the live signatures and nowhere else. "
    "`defender/skills/{system}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)

#: The adapter loaded but its surface could not be derived (e.g. a grant/declaration class
#: disagreement out of `decide`): a defender-side fault the lead cannot route around.
_LIST_VERBS_UNDERIVABLE = (
    "`{system}` — UNAVAILABLE: its verb surface could not be derived ({err}). That is a "
    "defender-side fault, not something your call can fix, and no file carries a copy of the "
    "surface. `defender/skills/{system}/execution.md` still states this system's value "
    "constraints and recorded pitfalls; report the failure in your summary rather than guessing "
    "a verb or a param name."
)

#: A missing or malformed `VERBS` table (read as `{}`): a broken adapter, not a withheld grant.
_LIST_VERBS_NO_VERBS = (
    "`{system}` — UNAVAILABLE: its adapter declares no verbs at all, so no verb surface can be "
    "derived for it, and no file carries a copy. "
    "`defender/skills/{system}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)

#: Every declared verb is withheld from this role; distinct from a broken adapter, which calls
#: for the opposite response.
_LIST_VERBS_NONE_GRANTED = (
    "`{system}` — its adapter declares verbs, but your grant admits none of them. This is not "
    "an empty system and not a read failure: there is nothing here you may run. Measure this "
    "lead against a system you do hold, or say so in your summary rather than reporting a "
    "measurement you could not take."
)

_LIST_VERBS_HEADER = (
    "`{system}` — the {count} verb(s) your grant admits, read from the adapter's live "
    "signatures. Copy a line and bind the values in place of each `<…>`:\n"
)

_LIST_VERBS_LEGEND = (
    "\nParams bind **by name**; there are no flags and no positional args. Types are literal "
    "JSON: a number is a number (`20`, never `\"20\"`), a boolean is `true`/`false` (never "
    "`\"false\"`, which is truthy and would have meant the opposite). A param whose descriptor "
    "carries a `default` is OPTIONAL — drop it to take that default; every other param is "
    "REQUIRED.\n"
    "\nAdd `query_id=\"{system}.<id>\"` to the call — a catalog template's id when you reused "
    "one, or a coined `{system}.<descriptive-kebab>` when none fit.\n"
)

#: Quotes the marker as a prefix: a param with a default renders `<type unenforced, default …>`.
_LIST_VERBS_UNENFORCED_NOTE = (
    "\nA descriptor opening `<{marker}` marks a param whose declared annotation could not be "
    "resolved, so the boundary does NOT type-check it — a wrong-typed value there reaches the "
    "adapter instead of being refused. Bind it to the value constraint this system's "
    "`execution.md` states, and treat a surprising answer as suspect rather than as data.\n"
)


def _json_default(value: Any) -> str:
    """A param default in JSON spelling (`null`/`true`), never `repr`'s, so a copied call is valid."""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return json.dumps(repr(value))


def _rendered_param(param: inspect.Parameter, hints: Mapping[str, Any]) -> str:
    """One declared param as a `"name": <descriptor>` entry of a `params={…}` body."""
    inner = _ann_name(hints[param.name]) if param.name in hints else UNENFORCED_TYPE
    if param.default is not inspect.Parameter.empty:
        inner = f"{inner}, default {_json_default(param.default)}"
    return f'"{param.name}": <{inner}>'


def _echoed_system(system: str) -> str:
    """The `system` string a degradation message may interpolate.

    A well-formed name is echoed verbatim. Anything else is a bounded `repr` with backticks
    removed, so it cannot forge markdown structure or close the backticked span early.
    """
    if is_system_name(system):
        return system
    return repr(system[:SYSTEM_MAX_LEN]).replace("`", "")


#: What every guarded read below re-raises rather than degrading: framework control flow plus
#: process kills.
_RERAISE: tuple[type[BaseException], ...] = (
    *CONTROL_FLOW_EXCEPTIONS,
    BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError,
)


def _registry_declares(registry: Any, system: str) -> bool:
    """Does the registry list `system`? `systems()` never raises, so there is no "cannot say"."""
    return system in registry.systems()


def _granted_systems(registry: Any) -> tuple[str, ...]:
    """The systems this role's grant reaches, or `()` when the registry cannot say."""
    try:
        return tuple(sorted(registry.grant.systems))
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a registry that cannot name its grant reaches nothing
        # Logged because the lead sees only an empty grant, indistinguishable from a real one.
        _logger.warning(f"verb registry could not name its grant "
                        f"({type(e).__name__}: {e}); list_verbs will answer 'no system reached'")
        return ()


def _list_verbs_declared(
    registry: Any, system: str, shown: str,
) -> tuple[Mapping[str, Any], str | None]:
    """`(declared_verbs, degradation)`: the registry's table for `system`, or the message to
    answer instead. Never both, and never an exception out of the tool."""
    try:
        declared = registry.verbs(system)
    except KeyError as e:
        # `KeyError` means either "no such adapter" or an import-time `KeyError` in the adapter
        # (e.g. `os.environ[...]`); the system list tells them apart. The key is the diagnosis.
        if _registry_declares(registry, system):
            return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"KeyError: {e}")
        return {}, _LIST_VERBS_UNKNOWN_SYSTEM.format(system=shown)
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — an adapter that will not import is a degradation
        return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"{type(e).__name__}: {e}")
    if not declared:
        # `{}` here is a broken adapter (no usable `VERBS`), not a withheld grant.
        return {}, _LIST_VERBS_NO_VERBS.format(system=shown)
    return declared, None


def _list_verbs_line(
    registry: Any, system: str, verb: Any, shown: str,
) -> tuple[tuple[str, bool] | None, str | None]:
    """`((rendered_call, any_param_unenforced), degradation)` for one verb — `(None, None)`
    when the grant withholds it.

    Decision and render are guarded together: both can raise on a broken adapter, and an
    exception out of a discovery tool would end the lead's turn.
    """
    try:
        decision = registry.decide(system, verb)
        if decision.outcome != GRANTED or decision.fn is None:
            return None, None
        # `model_facing_params`: wrapper-only params are refused, so they are not published.
        params = model_facing_params(decision.fn)
        hints = _resolved_hints(decision.fn)
        rendered = ", ".join(_rendered_param(p, hints) for p in params.values())
        # `shown`, not raw `system`: the line the lead copies must not carry an unescaped name.
        line = f'query(system="{shown}", verb="{verb}", params={{{rendered}}})'
        return (line, any(name not in hints for name in params)), None
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a surface that cannot be derived degrades loud
        return None, _LIST_VERBS_UNDERIVABLE.format(
            system=shown, err=f"{shown}.{verb}: {type(e).__name__}: {e}",
        )


def _tool_list_verbs(registry: Any, system: str) -> str:
    """`system`'s granted verbs and their declared params, derived at call time.

    Uses the same readers `validate_params` enforces with, and filters through
    `registry.decide`, so what is published is what `query` admits. The system-level grant
    check runs first because `decide` would import the adapter.

    Nothing is persisted (no row, breaker, or repeat guard): it reads our own adapter
    signatures, so the output is first-party and carries no untrusted frame.
    """
    shown = _echoed_system(system)
    # Grant first, before anything resolves an adapter.
    reachable = _granted_systems(registry)
    if system not in reachable:
        roster = f" The systems your grant reaches: {', '.join(reachable)}." if reachable else ""
        return _LIST_VERBS_UNREACHABLE.format(system=shown, roster=roster)

    declared, degradation = _list_verbs_declared(registry, system, shown)
    if degradation is not None:
        return degradation

    lines: list[str] = []
    any_unenforced = False
    # `key=str` so a broken adapter's mixed key types cannot raise here; non-string keys are
    # then withheld by the grant filter.
    for verb in sorted(declared, key=str):
        rendered, failure = _list_verbs_line(registry, system, verb, shown)
        if failure is not None:
            return failure
        if rendered is None:
            continue
        line, unenforced = rendered
        any_unenforced = any_unenforced or unenforced
        lines.append(line)

    if not lines:
        return _LIST_VERBS_NONE_GRANTED.format(system=shown)

    out = (
        _LIST_VERBS_HEADER.format(system=shown, count=len(lines))
        + "\n" + "\n".join(f"    {line}" for line in lines) + "\n"
        + _LIST_VERBS_LEGEND.format(system=shown)
    )
    if any_unenforced:
        out += _LIST_VERBS_UNENFORCED_NOTE.format(marker=UNENFORCED_TYPE)
    return out


def register_list_verbs_tool(agent, registry) -> None:

    @agent.tool
    async def list_verbs(ctx: RunContext[Any], system: str) -> str:
        """The verbs one system of record declares and the params each one binds — read from
        the adapter's live signatures, filtered to what your grant admits. Call it before you
        coin a query no template covers: it is the same surface the `query` tool enforces, so
        a param it names is a param that will bind and one it omits will be refused. `system`
        is the system you were dispatched to (the Dispatch block names it); call it again for
        another system if this lead crosses one. It runs nothing against the system of record
        and is not recorded as a query."""
        # Off the event loop: the first call imports the adapter module, which would otherwise
        # stall sibling leads.
        return await asyncio.to_thread(_tool_list_verbs, registry, system)


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
            tenant=deps.tenant,
        )
        return await asyncio.to_thread(fn, vctx, **params)



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
from .tools_gather import _payload_note, _tripped_message  # noqa: E402


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
