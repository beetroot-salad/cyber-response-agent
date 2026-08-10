
from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

from pydantic import ValidationError
from pydantic_ai import RunContext
from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.exceptions import (
    ApprovalRequired,
    CallDeferred,
    ModelRetry,
    SkipToolExecution,
    ToolRetryError,
)

from defender._io import guarded_mkdir, write_guarded
from defender._run_paths import RunPaths
from defender.hooks.budget_enforcer import BudgetKill
from defender._untrusted import wrap as _wrap
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    REPEAT_ESCAPE,
    GatherDeadEnd,
    RepeatTrip,
    _is_event_payload,
    _json_safe_params,
    _next_seq,
    _passthrough_max_bytes,
    build_truncated_view,
    dead_end_reason,
    lead_rows,
    payload_digest,
    rejection_dead_end_reason,
    rejection_trip,
    rejection_trip_detail,
    repeat_note,
    repeat_trip,
    repeat_trip_detail,
)

from . import circuit_breaker
from .ticket_screen import (
    TICKET_GET,
    TICKET_LIST,
    TICKET_SYSTEM,
    screen_get,
    screen_list,
    self_case_key,
)
from .verbs import DENIED, GRANTED, VerbContext, validate_params

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

_QID_TRAVERSAL = ("/", "\\", "..", "\x00")


def resolve_query_id(system: str, verb: str, model_query_id: str | None) -> str:
    # ABOVE_GUARD_QUERY_ID is reserved for the three writer sites that pass it directly
    # (never through here) to mark a row the repeat guard must never count. A model-supplied
    # `query_id` equal to that literal string — or carrying a traversal character the
    # below-guard `_screen` would otherwise reject — must not reach a real row through this
    # path: on the repeat-trip's own record (which sits ABOVE `_screen`), nothing else
    # screens it, and letting it through would either forge the sentinel (permanently
    # exempting that request from the repeat count) or persist an unscreened id.
    if (
        model_query_id
        and model_query_id != ABOVE_GUARD_QUERY_ID
        and not any(t in model_query_id for t in _QID_TRAVERSAL)
    ):
        return model_query_id
    return f"{system}.{verb}" if verb else f"{system}.ad-hoc"


def _fault_exit(e: BaseException) -> int:
    if isinstance(e, SystemExit) and isinstance(e.code, int) and e.code != 0:
        return e.code
    return DEFAULT_FAULT_EXIT


def _payload_status(exit_code: int, payload: Any) -> str:
    if exit_code != 0:
        return "error"
    if payload is None:
        return "empty"
    if isinstance(payload, (dict, list, tuple, set, str)) and len(payload) == 0:
        return "empty"
    return "ok"


def _raw_command(system: str, verb: str, params: dict) -> str:
    return shlex.join([system, verb, *(f"{k}={v}" for k, v in params.items())])


def _self_ticket_reject_reason(
    self_key: str, system: str, verb: str, params: dict,
) -> str | None:
    """Reject a direct gather read of its own case before the ticket store is contacted.

    Gather deliberately retains unrestricted access to OTHER tickets — including open and
    in-progress records used for correlation. The protected identity is only this run's case
    key, which is carried explicitly on deps rather than inferred from a filesystem path
    (``ticket_screen.self_case_key``).
    """
    if system == TICKET_SYSTEM and verb == TICKET_GET and params.get("key") == self_key:
        return (
            "that key is the current investigation's own ticket and cannot be read through "
            "gather. Correlate a different ticket; open and in-progress related cases remain "
            "available."
        )
    return None


def _screen_ticket_payload(
    self_key: str, system: str, verb: str, payload: Any,
) -> tuple[Any, int, str]:
    """Apply gather's current-case exclusion before capture and model display.

    The shape checks and the ``(payload, exit_code, detail)`` contract are the shared ticket
    screen (``ticket_screen``); what is bound here is gather's own predicate, which is
    intentionally IDENTITY-ONLY. Another ticket may mention ``self_key`` in its free text and
    remains useful correlation evidence — unlike the judge, gather is not scoring the case, so
    a mention is not an answer key. Lifecycle state is likewise untouched. A record whose key
    cannot be established is withheld, because it cannot be proved distinct from this case.
    """
    if system != TICKET_SYSTEM:
        return payload, 0, ""

    if verb == TICKET_GET:
        return screen_get(
            payload,
            require_key=True,
            withhold=lambda ticket: (
                "the ticket store returned the current investigation's own ticket; its "
                "content was withheld from gather."
                if ticket["key"] == self_key else None
            ),
        )

    if verb == TICKET_LIST:
        return screen_list(
            payload,
            keep=lambda ticket: (
                isinstance(ticket.get("key"), str) and ticket["key"] != self_key
            ),
        )

    return payload, 0, ""


class QueryCapture(AbstractCapability[Any]):

    def __init__(self, registry: Any, role: str = "gather"):
        self._registry = registry
        self._role = role
        self._seq_lock = asyncio.Lock()

    def _denial_logger_for(self, run_dir: Any) -> Any:
        # Process-wide per run dir, NOT per capability: one QueryCapture is built per gather
        # lead against one shared run dir, and RequestLogger refuses a second open of a path
        # it already holds — a per-capability logger makes the run's SECOND denial raise
        # FileExistsError out of the tool wrapper instead of returning the refusal.
        from . import observe

        return observe.denial_logger(run_dir)

    def _decide_guarded(self, system: str, verb: str) -> tuple[Any, str | None]:
        """THE grant decision, guarded against a broken adapter import — mirroring the old
        `_reject_guarded`'s load-error treatment (§7 R2's O3 timing: the agreement check is
        deferred to first resolution, not policy compile, so a broken sibling adapter must
        not unwind the stage)."""
        try:
            return self._registry.decide(system, verb), None
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except BaseException as e:  # noqa: BLE001 — the registry could not LOAD this system's module
            return None, f"{system} adapter failed to load: {type(e).__name__}: {e}"

    def _traversal_reject(self, model_query_id: Any) -> str | None:
        if model_query_id and any(t in str(model_query_id) for t in _QID_TRAVERSAL):
            return (
                f"invalid query_id {model_query_id!r}: no '/', '\\', '..' or NUL — it becomes a "
                "catalog path segment. Coin a `{system}.{kebab-name}` id."
            )
        return None

    def _rejection_guard(self, deps, system: str, verb: str, params: dict) -> RepeatTrip | None:
        """The companion repeat guard (#826 item 4), shared by the two placements that reject a
        call ABOVE `wrap_tool_execute`'s guard: the argument schema, and the grant check's
        unresolvable-verb branch. Returns the `RepeatTrip` when this call is the `threshold`th
        identical rejection, else `None`.

        Its counted domain (`rejection_trip`) is the complement of the first guard's, so the
        two can never both own one call. The identity is extracted at the CALLER, because the
        two placements read different argument surfaces — raw pre-validation arguments up at
        the schema, validated ones at the grant check — which is exactly why one guard could
        not serve both."""
        if deps.lead_id is None:
            return None
        return rejection_trip(
            lead_rows(deps.run_dir, deps.lead_id), deps.lead_id,
            system=system, verb=verb, params=params,
        )

    async def wrap_tool_validate(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)
        try:
            return await handler(args)
        except (ValidationError, ModelRetry) as e:
            raw = _raw_args(args)
            system, verb = _as_str(raw.get("system")), _as_str(raw.get("verb"))
            # THE SECOND IDENTITY EXTRACTION (P-a). These are the RAW arguments: this frame
            # runs precisely because the schema refused to produce validated ones, so there is
            # nothing else to key on. A `params` that is not a dict at all coarsens to `{}`
            # here — that is what the row already stores, so the live count and a replay over
            # the recorded table read the same identity, which is the property that matters.
            params = _as_dict(raw.get("params"))
            trip = self._rejection_guard(ctx.deps, system, verb, params)
            await self._record(
                ctx.deps,
                system=system, verb=verb,
                query_id=ABOVE_GUARD_QUERY_ID,
                params=params,
                payload=None,
                exit_code=USAGE_EXIT_CODE,
                detail=str(e) if trip is None else rejection_trip_detail(trip, str(e)),
            )
            if trip is not None:
                raise GatherDeadEnd(
                    reason=rejection_dead_end_reason(system, verb, trip),
                    escape=REPEAT_ESCAPE,
                ) from e
            raise

    async def _grant_check(
        self, deps, system: str, verb: str, params: dict,
    ) -> tuple[Any, str | None]:
        """THE GRANT CHECK, ahead of everything else (§7 R3/R23, reversed at phase F — a denied
        call always produces its denial record and never an evidence row, whatever else is
        wrong with it). Returns `(decision, early_result)`; `early_result` is set when the
        caller must return without ever reaching execution."""
        decision, load_error = self._decide_guarded(system, verb)
        if load_error is not None:
            row, text = await self._record(
                deps, system=system, verb=verb,
                query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
                exit_code=DEFAULT_FAULT_EXIT, detail=load_error,
            )
            return None, self._model_view(deps, row, text, DEFAULT_FAULT_EXIT, load_error)

        if decision.outcome == DENIED:
            self._denial_logger_for(deps.run_dir).log_policy_denial(
                role=self._role, system=system, verb=verb,
                call_id=f"{system}.{verb}", params=params,
            )
            return None, _format_bash_result(
                DEFAULT_FAULT_EXIT, "", _wrap(decision.refusal or "", "untrusted", deps.salt), "",
            )

        if decision.outcome != GRANTED:
            # The unresolvable-verb repeat class — the same shape as the schema class at a
            # different placement (#826 item 4), and the reason the companion guard is reached
            # from both. The load-error branch above is deliberately NOT guarded: its rows are
            # `infra`, outside `rejection_trip`'s domain, and `circuit_breaker` already owns
            # that repeat end to end.
            trip = self._rejection_guard(deps, system, verb, params)
            refusal = decision.refusal or "unresolvable"
            await self._record(
                deps, system=system, verb=verb,
                query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
                exit_code=USAGE_EXIT_CODE,
                detail=(
                    refusal if trip is None else rejection_trip_detail(trip, refusal)
                ),
            )
            if trip is not None:
                raise GatherDeadEnd(
                    reason=rejection_dead_end_reason(system, verb, trip),
                    escape=REPEAT_ESCAPE,
                )
            raise ModelRetry(decision.refusal or f"unresolvable: {system}.{verb}")

        return decision, None

    async def _screen(
        self, deps, decision: Any, system: str, verb: str, params: dict,
        model_query_id: Any, self_key: str,
    ) -> None:
        """The per-call screens BELOW the grant and the breaker: the traversal screen, param
        validation, and the self-ticket screen. Raises `ModelRetry` (after its usage row) when
        one of them refuses."""
        reason = self._traversal_reject(model_query_id)
        if reason is None:
            reason = validate_params(decision.fn, params)
        if reason is None:
            reason = _self_ticket_reject_reason(self_key, system, verb, params)
        if reason is not None:
            await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None),
                params=params, payload=None,
                exit_code=USAGE_EXIT_CODE, detail=reason,
            )
            raise ModelRetry(reason)

    async def wrap_tool_execute(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)

        deps = ctx.deps
        system = _as_str(args.get("system"))
        verb = _as_str(args.get("verb"))
        params = _as_dict(args.get("params"))
        model_query_id = args.get("query_id")
        self_key = self_case_key(deps)

        decision, early_result = await self._grant_check(deps, system, verb, params)
        if early_result is not None:
            return early_result

        # The breaker sits between the grant and the screens, where it sat before the grant
        # landed: a system already known down answers "down" rather than a param complaint
        # plus a usage row for a call that was never going to reach it.
        tripped = _tripped_message(deps, system)
        if tripped is not None:
            return tripped

        # The repeat guard sits ABOVE `_screen`, so it owns every repeat it can see —
        # including a call the verb's own parameter check would refuse — rather than earning a
        # third identical corrective `ModelRetry` the model already ignored twice. Its read is
        # the count itself is derived from: no new persisted state.
        rows = lead_rows(deps.run_dir, deps.lead_id)
        trip = repeat_trip(rows, deps.lead_id, system=system, verb=verb, params=params)
        if trip is not None:
            query_id = resolve_query_id(system, verb, _as_str(model_query_id) or None)
            await self._record(
                deps, system=system, verb=verb, query_id=query_id, params=params,
                payload=None, exit_code=USAGE_EXIT_CODE, detail=repeat_trip_detail(trip),
            )
            executed = sum(1 for r in rows if r.get("exit_code") == 0)
            raise GatherDeadEnd(
                reason=dead_end_reason(system, verb, trip, executed),
                escape=REPEAT_ESCAPE,
            )

        await self._screen(
            deps, decision, system, verb, params, model_query_id, self_key,
        )

        query_id = resolve_query_id(system, verb, _as_str(model_query_id) or None)

        payload: Any = None
        try:
            payload = await handler(args)
            payload, exit_code, detail = _screen_ticket_payload(
                self_key, system, verb, payload,
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
            payload=payload, exit_code=exit_code, detail=detail,
        )
        return self._model_view(deps, row, text, exit_code, detail)


    async def _record(
        self, deps, *, system: str, verb: str, query_id: str, params: dict,
        payload: Any, exit_code: int, detail: str,
    ) -> tuple[dict, str]:
        if deps.lead_id is None:
            raise RuntimeError("internal: query reached capture without a dispatched lead_id")

        text = "" if exit_code != 0 else json.dumps(payload, default=str)
        run_dir = deps.run_dir

        async with self._seq_lock:
            seq = _next_seq(run_dir, deps.lead_id)
            payload_rel = _persist_payload(run_dir, deps.lead_id, seq, text)
            row = {
                "lead_id": deps.lead_id,
                "seq": seq,
                "system": system,
                "verb": verb,
                "query_id": query_id,
                "params": _json_safe_params(dict(params)),
                "raw_command": _raw_command(system, verb, params),
                "payload_path": payload_rel,
                "exit_code": exit_code,
                "error_class": circuit_breaker.error_class_for_exit(exit_code),
                "payload_status": _payload_status(exit_code, payload),
                "payload_digest": (
                    payload_digest(text, "", 0) if exit_code == 0
                    else f"exit={exit_code}; {detail.strip()[:160]}"
                ),
            }
            write_guarded(RunPaths(run_dir).executed_queries, json.dumps(row) + "\n", mode="append")

        circuit_breaker.record_outcome(run_dir, system, exit_code)
        return row, text

    def _model_view(self, deps, row: dict, text: str, exit_code: int, detail: str) -> str:
        note = _payload_note(deps, row)
        # ABOVE the exit-code split, not inside the success arm (#826 item 3). The early
        # return used to sit here, so a lead repeating a request whose calls keep FAILING was
        # the one population that never got the "you are repeating yourself" signal — the
        # exact population most likely to loop, since a failure gives it nothing new to reason
        # from either. Ahead of the view for the same reason it is on the success path: the
        # repeat is what the caller most needs to read first.
        repeat = repeat_note(
            deps.run_dir, deps.lead_id, seq=row["seq"], system=row["system"],
            verb=row["verb"], params=row["params"],
            payload_digest=row["payload_digest"], exit_code=exit_code,
        )
        if exit_code != 0:
            # Prepended to `detail` INSIDE the wrap, mirroring the success arm: the wrap is
            # the untrusted boundary for this whole stream, and lifting one defender-authored
            # line out of it would put a second, differently-trusted region in a result the
            # main loop reads as one span.
            body = detail if repeat is None else f"{repeat}\n{detail}"
            return _format_bash_result(exit_code, "", _wrap(body, "untrusted", deps.salt), note)
        view = (
            build_truncated_view(text, row["payload_path"], deps.run_dir)
            if (_is_event_payload(text) or len(text) > _passthrough_max_bytes())
            else text
        )
        if repeat is not None:
            view = f"{repeat}\n{view}"
        return _format_bash_result(0, _wrap(view, "untrusted", deps.salt), "", note)



def register_query_tool(agent, registry) -> None:

    @agent.tool
    async def query(
        ctx: RunContext[Any], system: str, verb: str,
        params: dict[str, Any], query_id: str | None = None,
    ) -> Any:
        """Run one data-source query. `system` and `verb` name a declared verb from the systems
        catalog in your dispatch prompt; `params` binds that verb's declared params by NAME (a
        verb declares exactly what it takes — there are no flags, no shell, and no `--help`).
        `query_id` binds this call to a catalog template id (`{system}.{template}`), or a fresh
        `{system}.{kebab-name}` you coin for a query no template covers; omit it and it derives
        as `{system}.{verb}`. The payload is captured to the queries table and persisted whole on
        disk automatically — you get a field-shape view plus the path to compute over."""
        deps = ctx.deps
        fn = registry.verbs(system)[verb]
        vctx = VerbContext(
            defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=_bash_env(deps),
        )
        return await asyncio.to_thread(fn, vctx, **params)



def _raw_args(args: Any) -> dict:
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except (json.JSONDecodeError, ValueError):
            return {}
    return args if isinstance(args, dict) else {}


def _as_str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _persist_payload(run_dir, lead_id: str, seq: int, text: str) -> str | None:
    lead_dir = RunPaths(run_dir).gather_raw / lead_id
    payload_path = lead_dir / f"{seq}.json"
    try:
        guarded_mkdir(lead_dir, base=run_dir)
        write_guarded(payload_path, text)
    except (OSError, ValueError):
        # ValueError as well as OSError: `guarded_mkdir` raises it for a target that is not
        # inside the tree the anchor names, which a `lead_id` carrying path separators or `..`
        # produces here. Best-effort persistence must not become the run's crash.
        return None
    return str(payload_path.relative_to(run_dir))


from .tools import _bash_env, _format_bash_result  # noqa: E402
from .tools_gather import _payload_note, _tripped_message  # noqa: E402


__all__ = [
    "CONTROL_FLOW_EXCEPTIONS",
    "DEFAULT_FAULT_EXIT",
    "QueryCapture",
    "TOOL_NAME",
    "register_query_tool",
    "resolve_query_id",
]
