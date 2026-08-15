
from __future__ import annotations

import asyncio
import inspect
import json
import re
import shlex
import sys
from collections.abc import Mapping
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

from defender.hooks.budget_enforcer import BudgetKill
from defender._untrusted import wrap_fresh
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault
from defender.scripts.gather_tools.payload_view import render as _render_payload
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    REPEAT_ESCAPE,
    REPEAT_TRIP_QUERY_ID,
    GatherDeadEnd,
    RepeatTrip,
    _json_safe_params,  # noqa: F401 — re-export: test_repeat_breaker_807 imports it from here
    append_query_row,
    dead_end_reason,
    is_reserved_query_id,
    lead_rows,
    payload_digest,
    # Re-exported under its old private name: `_spec771` measures the site
    # `query_tool._persist_payload` by that name (its X5 return-none MeasuredSite).
    persist_payload as _persist_payload,  # noqa: F401
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
from .verbs import (
    DENIED,
    GRANTED,
    VerbContext,
    _ann_name,
    _resolved_hints,
    _SYSTEM_RE,
    model_facing_params,
    validate_params,
)

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

#: Characters a `query_id` may not carry. The first four are PATH shapes — a traversal that
#: would walk the id out of the directory it names a file in. The last two are RENDER shapes
#: (#875 F-8): a catalog id is interpolated into markdown three offline collectors read, and a
#: newline or a heading marker in it forges document structure inside the judge's per-lead
#: comparison — which lead a section describes, which sample event is the run's real one. Both
#: families are here for one reason, so they screen as one rule: a `query_id` is a catalog
#: IDENTIFIER the collectors partition on, not free text, and neither shape belongs in one.
_QID_FORBIDDEN = ("/", "\\", "..", "\x00", "\n", "\r", "#")

#: M3/FK-7's kebab half: the remainder after the first `.` in a coined `query_id`. No dot —
#: a second dot lets `'system.foo.bar'` slip past a prefix-only check and become a SECOND
#: unvalidated model-supplied path component at the host-side draft writer
#: (`draft_synthesis._draft_candidate_segments`'s `split('.', 1)`).
_KEBAB_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def resolve_query_id(system: str, verb: str, model_query_id: str | None) -> str:
    # The `∅.` sentinels are reserved for the writer sites that pass them directly (never
    # through here) to mark a row whose ROUTING the offline collectors take on trust — the
    # rows the repeat guard must never count, the guard's own trip record, the bash lane's
    # shim record. A model-supplied `query_id` spelling one of them — or carrying a traversal
    # character the below-guard `_screen` would otherwise reject — must not reach a real row
    # through this path: on the repeat-trip's own record (which sits ABOVE `_screen`), nothing
    # else screens it, and letting it through would either forge a sentinel or persist an
    # unscreened id. The screen is on the whole PREFIX, not on each literal, so it cannot fall
    # behind the set (`record_query.is_reserved_query_id`).
    if (
        model_query_id
        and not is_reserved_query_id(model_query_id)
        and not any(t in model_query_id for t in _QID_FORBIDDEN)
    ):
        # FK-7 (§7): the WHOLE `{system}.{kebab-name}` shape, not only the prefix. The prefix
        # must EXACTLY equal the dispatched system (no case folding, no NFC — FK-6), and the
        # remainder must be a single well-formed segment. A foreign prefix, a missing
        # separator, an empty remainder, or a remainder carrying a second `.` all fall back to
        # the untagged value — the same one an ordinary call already records.
        prefix, sep, remainder = model_query_id.partition(".")
        if sep and prefix == system and remainder and _KEBAB_SEGMENT.match(remainder):
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

    def _system_of_record(self, system: str) -> str:
        """The `system` an ABOVE-GUARD row is allowed to carry: the model's own string when the
        registry declares that system, `""` when it does not (#855 F-06).

        The two writers up here — the argument schema's rejection and the grant check's
        unresolvable branch — record what the MODEL named, and nothing between there and the
        offline collectors re-checks it: the call never reached the grant, so no other party on
        the path ever formed an opinion about the string. It is not inert. An exit-64
        `agent-fixable` row IS the pitfalls channel's input, and `_build_pitfalls_handoffs`
        spends its `system` verbatim as `defender/skills/<system>/execution.md` and points the
        curator at that path — so a schema the model can fail on purpose (any extra or mistyped
        argument does it, no grant required) was a route to naming a corpus write.

        `""` rather than a drop, and it needs no new branch downstream: `collect_general_
        failures` already skips a systemless row, exactly as `record_query.system_for_payload_
        operands` returning `""` does for the bash shim's writer — the sibling this closes for
        the same reason, that a bad `system` "would send the curator at a `skills/sql/
        execution.md` that must never exist".

        Spent on the rejection guard's identity as well as on the row, never on one and not the
        other: the guard recovers its count from the rows it wrote, so a live identity keyed on
        the raw string over a table holding `""` would match nothing and the repeat class this
        guard exists to bound would stop being bounded.

        THE IDENTITY CONSEQUENCE, stated because it is a real behaviour change and not an
        oversight: every undeclared system now keys the SAME, so three rejections naming
        `ghostone`, `ghosttwo` and `ghostthree` under one verb and params are one repeat group
        and the third ends the lead. That is the reading this coarsening commits to — the
        request identity below the grant is "a call to no system this run declares", and a
        model that issues three of those in a row has repeated one mistake, not made three. It
        is also the only reading available: the guard's identity is recovered from the frozen
        frozen row keys, so a `system` the row does not carry cannot separate them. What must
        NOT follow is a dead-end that tells main those calls named one system —
        `_undeclared_target` is why the message says an undeclared system instead."""
        try:
            declared = self._registry.systems()
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except BaseException as e:  # noqa: BLE001 — a registry that cannot list declares nothing
            # Fail closed, but never SILENTLY: a registry that cannot answer coarsens every
            # above-guard row in the run, real systems included, and `collect_general_failures`
            # then drops the lot. `_decide_guarded` turns its own load failure into a visible
            # row; this path has no row of its own to carry one, so it says so on stderr.
            print(f"[query_tool] system registry could not list its systems "
                  f"({type(e).__name__}: {e}); above-guard rows will carry no system",
                  file=sys.stderr)
            return ""
        return system if system in declared else ""

    @staticmethod
    def _undeclared_target(recorded: str, raw: str) -> str:
        """What the dead-end message calls the request's target.

        The coarsened value is what the row and the guard agree on, but rendering `""` there
        makes `rejection_dead_end_reason` say "system/verb unreadable in the call's own
        arguments" — which is false for a call that named a system perfectly readably, just not
        one that exists. And the raw string cannot be echoed: it is unbounded model text on a
        path that crosses into MAIN's context. So neither, and a third thing that is true of
        every member of this repeat group."""
        return recorded or ("an undeclared system" if raw.strip() else "")

    def _forbidden_reject(self, model_query_id: Any) -> str | None:
        # The message names the WHOLE screen, not the path half of it: a refusal that lists
        # four characters the caller did not use is one the caller cannot act on, and #875 F-8
        # widened `_QID_FORBIDDEN` past the traversal set.
        if model_query_id and any(t in str(model_query_id) for t in _QID_FORBIDDEN):
            return (
                f"invalid query_id {model_query_id!r}: no '/', '\\', '..', NUL, newline or '#' "
                "— it becomes a catalog path segment and a markdown span the offline collectors "
                "render. Coin a `{system}.{kebab-name}` id."
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
            # THE SECOND IDENTITY EXTRACTION (P-a). These are the RAW arguments: this frame
            # runs precisely because the schema refused to produce validated ones, so there is
            # nothing else to key on. A `params` that is not a dict at all coarsens to `{}`
            # here — that is what the row already stores, so the live count and a replay over
            # the recorded table read the same identity, which is the property that matters.
            # `system` coarsens the same way when the registry does not declare it, and for a
            # stronger reason: this row's `system` steers an offline corpus write
            # (`_system_of_record`).
            raw_system = _as_str(raw.get("system"))
            system = self._system_of_record(raw_system)
            verb = _as_str(raw.get("verb"))
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
                    reason=rejection_dead_end_reason(
                        self._undeclared_target(system, raw_system), verb, trip),
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
            # THE BREAKER CHECK, consulted HERE rather than only at `wrap_tool_execute:429`
            # (#878 F-07). Two modules promise this class's repeat is owned end to end by
            # `circuit_breaker` — `rejection_trip`'s docstring excludes these `infra` rows from
            # the companion guard on exactly that promise, and the comment at the unresolvable
            # branch below repeats it. The promise was false for as long as the check sat
            # BELOW this return: `verbs._load_adapter_module` caches only on success, so the
            # same import re-failed on every call, `_record`'s tail fed each one to
            # `record_outcome`, and no call of this class was ever answered by the
            # down-message. The second failure marked the system down and nothing read it; the
            # fifth crossed `RUN_FAIL_KILL_LIMIT` and `RunAborted` ended the run with no
            # disposition. Ahead of `_record`, so the down-answer neither writes a third row
            # nor counts a third failure — the point of a tripped breaker is that the call did
            # not happen. NOT hoisted above `_grant_check` entirely: the DENIED branch below
            # owes its denial record whatever else is wrong with the call (§7 R3/R23), and a
            # breaker answer ahead of the grant would swallow it.
            tripped = _tripped_message(deps, system)
            if tripped is not None:
                return None, tripped
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
                DEFAULT_FAULT_EXIT, "", wrap_fresh(decision.refusal or "", "untrusted"), "",
            )

        if decision.outcome != GRANTED:
            # The unresolvable-verb repeat class — the same shape as the schema class at a
            # different placement (#826 item 4), and the reason the companion guard is reached
            # from both. The load-error branch above is deliberately NOT guarded by THIS
            # guard: its rows are `infra`, outside `rejection_trip`'s domain, and
            # `circuit_breaker` owns that repeat end to end — which since #878 F-07 it
            # actually does, by consulting the breaker in the branch itself.
            # The same coarsening the schema placement applies, for the same reason (#855
            # F-06) and with the same domain: an unresolvable call is unresolvable precisely
            # because the grant reached no system by that name, so the string it names is the
            # one least entitled to become a `skills/<system>/` path. A REAL system with an
            # unknown verb — the ordinary shape here — is untouched and still records itself.
            recorded_system = self._system_of_record(system)
            trip = self._rejection_guard(deps, recorded_system, verb, params)
            refusal = decision.refusal or "unresolvable"
            await self._record(
                deps, system=recorded_system, verb=verb,
                query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
                exit_code=USAGE_EXIT_CODE,
                detail=(
                    refusal if trip is None else rejection_trip_detail(trip, refusal)
                ),
            )
            if trip is not None:
                raise GatherDeadEnd(
                    reason=rejection_dead_end_reason(
                        self._undeclared_target(recorded_system, system), verb, trip),
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
            # REPEAT_TRIP_QUERY_ID, not `resolve_query_id(...)` (#823 M3). The refusal is
            # recorded under its own identity rather than under whatever the model called the
            # request it was refused, because three offline collectors partition this table on
            # `query_id` and the model's id sent the trip row to the wrong two: a coined id was
            # minted as a `_draft/` template proposing the refused query, and a catalog id was
            # handed to the lead-author as a failure of that template. The guard's own counted
            # domain is untouched — it keys on ABOVE_GUARD_QUERY_ID alone, and #807 pins that
            # this row still counts on replay.
            await self._record(
                deps, system=system, verb=verb, query_id=REPEAT_TRIP_QUERY_ID, params=params,
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
            # The thirteen keys are assembled by `append_query_row` (#823 F1), which the gather
            # bash lane's shim recorder also calls. The lock stays: it is this path's, and it
            # is cheaper to keep than to argue that nothing will ever add an `await` here.
            row = append_query_row(
                run_dir,
                lead_id=deps.lead_id,
                system=system,
                verb=verb,
                query_id=query_id,
                params=params,
                raw_command=_raw_command(system, verb, params),
                payload_text=text,
                exit_code=exit_code,
                payload_status=_payload_status(exit_code, payload),
                payload_digest=(
                    payload_digest(text, "", 0) if exit_code == 0
                    else f"exit={exit_code}; {detail.strip()[:160]}"
                ),
            )

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
            payload_digest=row["payload_digest"], payload_sha256=row["payload_sha256"],
            exit_code=exit_code,
        )
        if exit_code != 0:
            # Prepended to `detail` INSIDE the wrap, mirroring the success arm: the wrap is
            # the untrusted boundary for this whole stream, and lifting one defender-authored
            # line out of it would put a second, differently-trusted region in a result the
            # main loop reads as one span.
            body = detail if repeat is None else f"{repeat}\n{detail}"
            return _format_bash_result(exit_code, "", wrap_fresh(body, "untrusted"), note)
        # ONE call, no condition: `render` returns the payload verbatim when it fits and a
        # bounded view when it does not (#832). The condition used to live here AND at the
        # judge's mirror of this method, so "what counts as too big" was stated twice and could
        # drift; the size test that replaced it belongs to the renderer, not to its callers.
        view = _render_payload(text, row["payload_path"], deps.run_dir)
        if repeat is not None:
            view = f"{repeat}\n{view}"
        return _format_bash_result(0, wrap_fresh(view, "untrusted"), "", note)



#: What a param renders as when its declared annotation could not be resolved. NOT cosmetic:
#: `_resolved_hints` swallows an unresolvable annotation and returns `{}` (verbs.py:166-170),
#: after which `validate_params` type-checks NOTHING and accepts any value. A surface that
#: printed the annotation there would promise a check the boundary does not make — the one way
#: this tool could lie about the thing it exists to report (#900 O3).
#:
#: The blast radius is the whole VERB, not the one bad param: `typing.get_type_hints` resolves
#: a signature as a unit and raises on the first name it cannot see, so `_resolved_hints`
#: returns `{}` for ALL of them. A verb with one unresolvable annotation therefore has every
#: param unenforced, and every one of them must say so — which is why this marker is applied
#: from the absence of a hint rather than from the presence of a bad one.
UNENFORCED_TYPE = "type unenforced"

#: The GRANT-FIRST answer, and the one branch that deliberately refuses to distinguish two
#: conditions (#900 review R2). `VerbRegistry.decide` decides "from the grant ALONE first — no
#: adapter is resolved (no import) unless the grant admits the call" (§7 R11); a discovery tool
#: that resolved first would both execute an ungranted adapter's import-time code and turn its
#: own four degradations into an oracle over the on-disk roster — "no such adapter" vs "present
#: but broken" vs "present and healthy", read across the grant boundary. So a system the grant
#: does not reach is answered here, before any import, and absent is spelled exactly like
#: withheld.
#:
#: Naming the reachable systems costs nothing: the dispatch prompt's descriptor index already
#: lists every system in this role's grant, so this discloses nothing the lead was not handed
#: on turn one — and it is a BETTER correction than the "no adapter by that name" it replaces
#: for the overwhelmingly common cause, a mistyped name.
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

#: Reached only for a name that already passed `_adapter_path`'s `_SYSTEM_RE` match AND its
#: containment check under the adapters dir — an unmatched name raises `KeyError` into the
#: branch above — so interpolating it into a path here cannot mint an arbitrary model-named
#: one (the #855 F-06 concern, which is about a model string reaching a corpus WRITE).
#:
#: THE FALLBACK NAMES WHAT THAT FILE STILL HOLDS, and no more (#900): the same change that
#: added this tool deleted the hand-authored verb/param blocks from every `execution.md`, so
#: sending the lead there for "its documented surface" would send it to a file whose `## Verbs`
#: section now says "call `list_verbs`" — the call that just failed. Value constraints and
#: recorded pitfalls DO still live there, and those are what it is offered for.
_LIST_VERBS_UNLOADABLE = (
    "`{system}` — UNAVAILABLE: its adapter could not be loaded ({err}). No verb surface can be "
    "derived for it right now, and no file carries a copy — the verb roster and its params are "
    "read from the live signatures and nowhere else. "
    "`defender/skills/{system}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)

#: A THIRD failure, distinct from both of the above: the adapter loaded and the grant is not
#: the question — the surface itself could not be derived (a grant/declaration class
#: disagreement raised out of `decide`, say). Saying "could not be loaded" there would be
#: false, and saying "your grant admits none" would send the lead to re-dispatch over a
#: defender-side fault it cannot route around.
_LIST_VERBS_UNDERIVABLE = (
    "`{system}` — UNAVAILABLE: its verb surface could not be derived ({err}). That is a "
    "defender-side fault, not something your call can fix, and no file carries a copy of the "
    "surface. `defender/skills/{system}/execution.md` still states this system's value "
    "constraints and recorded pitfalls; report the failure in your summary rather than guessing "
    "a verb or a param name."
)

#: A system whose registry answer carries NO verb at all — a missing or malformed `VERBS`
#: table reads as `{}` through `ModuleVerbRegistry.verbs`, which is a broken adapter and not a
#: withheld grant. It must not fall into `_LIST_VERBS_NONE_GRANTED` below, whose whole point is
#: that the two emptinesses call for opposite responses.
_LIST_VERBS_NO_VERBS = (
    "`{system}` — UNAVAILABLE: its adapter declares no verbs at all, so no verb surface can be "
    "derived for it, and no file carries a copy. "
    "`defender/skills/{system}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)

#: The OTHER emptiness, and it is not the one above — the same split `_INDEX_NONE_GRANTED`
#: draws for the template index. A system that will not load and a system whose every verb
#: this role is refused both render "nothing to show", and they call for opposite responses.
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

#: Names the marker as a PREFIX, not as the whole descriptor: an unenforced param that also
#: declares a default renders `<type unenforced, default …>`, so a note quoting `<{marker}>`
#: whole would name a string that appears nowhere in the answer it is annotating.
_LIST_VERBS_UNENFORCED_NOTE = (
    "\nA descriptor opening `<{marker}` marks a param whose declared annotation could not be "
    "resolved, so the boundary does NOT type-check it — a wrong-typed value there reaches the "
    "adapter instead of being refused. Bind it to the value constraint this system's "
    "`execution.md` states, and treat a surprising answer as suspect rather than as data.\n"
)


def _json_default(value: Any) -> str:
    """A param default in the JSON spelling the legend demands, never `repr`'s python one.

    `repr` renders `None`/`True`/`'desc'` where the call the model must emit needs
    `null`/`true`/`"desc"` — and a lead that copies the descriptor verbatim then sends invalid
    JSON, or (for a quoted `"false"`) the exact truthiness inversion the legend warns about.
    This tool exists to stop param guesswork; publishing a default in a syntax the call cannot
    carry reintroduces it at the last step.
    """
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return json.dumps(repr(value))


def _rendered_param(param: inspect.Parameter, hints: Mapping[str, Any]) -> str:
    """One declared param as a `"name": <descriptor>` entry of a `params={…}` body.

    Keyed on the param, never on `hints`: `_resolved_hints` also returns `ctx` and `return`,
    neither of which is a param the model may bind.
    """
    inner = _ann_name(hints[param.name]) if param.name in hints else UNENFORCED_TYPE
    if param.default is not inspect.Parameter.empty:
        inner = f"{inner}, default {_json_default(param.default)}"
    return f'"{param.name}": <{inner}>'


#: The longest model-named system this tool will echo back verbatim. The same bound as
#: `tools_gather._SYSTEM_MAX_LEN` and for the same underlying fact — the name is unbounded
#: model text — but NOT for the same downstream reason, so the two are stated separately
#: rather than shared: that one bounds a string #835 routes into a provider request field
#: (`openai_prompt_cache_key`), this one bounds a string that lands in a markdown answer.
_ECHO_SYSTEM_MAX_LEN = 64


def _echoed_system(system: str) -> str:
    """The `system` string a degradation message may interpolate.

    A well-formed name goes back verbatim — that is what makes the correction actionable. Any
    other string is a model-authored blob that would otherwise land unescaped inside a
    backticked span of a markdown answer, where a newline or a `#` forges document structure
    in the lead's own context (`_QID_FORBIDDEN`'s render half, and the reason
    `_undeclared_target` refuses to echo one at all). `repr` on a bounded slice keeps the
    string legible without letting it carry structure.

    The BACKTICK is dropped rather than left to `repr`, which escapes newlines and quotes and
    passes a backtick through untouched: every interpolation site wraps this value in a `` ` ``
    span, so one backtick inside closes the span early and the rest of the model's string lands
    as prose in the lead's context. Dropping it costs nothing a debug echo needs.
    """
    if _SYSTEM_RE.match(system) and len(system) <= _ECHO_SYSTEM_MAX_LEN:
        return system
    return repr(system[:_ECHO_SYSTEM_MAX_LEN]).replace("`", "")


#: What every guarded read below RE-RAISES rather than degrading: the framework's own control
#: flow plus the kills that end the process. Named once because the four readers below repeated
#: the same two `except` clauses verbatim, and a fifth reader added later must not be able to
#: copy half of them.
_RERAISE: tuple[type[BaseException], ...] = (
    *CONTROL_FLOW_EXCEPTIONS,
    BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError,
)


def _registry_declares(registry: Any, system: str) -> bool:
    """Does the registry list `system` among the systems it knows? `False` when it cannot say.

    Fails toward "unknown", which is the answer the caller already gave before this split
    existed — a registry that cannot list its systems must not be read as evidence that a
    system exists.
    """
    try:
        return system in registry.systems()
    except _RERAISE:
        raise
    except BaseException:  # noqa: BLE001 — a registry that cannot list declares nothing
        return False


def _granted_systems(registry: Any) -> tuple[str, ...]:
    """The systems this role's grant reaches, or `()` when the registry cannot say."""
    try:
        return tuple(sorted(registry.grant.systems))
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a registry that cannot name its grant reaches nothing
        # LOUD on the operator channel, for the same reason `_system_of_record` is: this arm
        # answers "your grant reaches nothing" for EVERY system in the run, which reads to the
        # lead as a correctly-empty grant rather than as a broken registry. The tool's own
        # answer cannot carry the distinction without turning a defender fault into a routing
        # instruction, so the transcript is where it has to land.
        print(f"[query_tool] verb registry could not name its grant "
              f"({type(e).__name__}: {e}); list_verbs will answer 'no system reached'",
              file=sys.stderr)
        return ()


def _list_verbs_declared(
    registry: Any, system: str, shown: str,
) -> tuple[Mapping[str, Any], str | None]:
    """`(declared_verbs, degradation)` — the registry's own table for `system`, or the message
    that must be answered instead. Never both, and never an exception out of the tool."""
    try:
        declared = registry.verbs(system)
    except KeyError as e:
        # A bare `KeyError` is `ModuleVerbRegistry.verbs`' "no adapter under that name" — but it
        # is ALSO whatever a broken adapter raises while importing (a module-scope
        # `os.environ[...]`, a missing dict key). Answering the second with "confirm the name
        # and call again" sends the lead to re-ask a question that will keep failing, so the
        # registry's own system list decides which of the two this is.
        #
        # The KEY is carried into the message, exactly as the general arm below carries its
        # exception's text: this arm is reached for the import-time `KeyError`, where the
        # missing name (`TICKET_URL`, say) is the whole of the diagnosis, and a bare
        # "(KeyError)" hands the operator reading the transcript nothing to act on.
        if _registry_declares(registry, system):
            return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"KeyError: {e}")
        return {}, _LIST_VERBS_UNKNOWN_SYSTEM.format(system=shown)
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — an adapter that will not import is a degradation
        return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"{type(e).__name__}: {e}")
    if not declared:
        # NOT the grant's emptiness: `ModuleVerbRegistry.verbs` answers `{}` for a module whose
        # `VERBS` is absent or is not a Mapping, which is a broken adapter wearing the shape of
        # a fully-withheld one.
        return {}, _LIST_VERBS_NO_VERBS.format(system=shown)
    return declared, None


def _list_verbs_line(
    registry: Any, system: str, verb: Any, shown: str,
) -> tuple[tuple[str, bool] | None, str | None]:
    """`((rendered_call, any_param_unenforced), degradation)` for one verb — `(None, None)`
    when the grant withholds it, which is a skip and not a failure.

    GUARDED END TO END, exactly as `QueryCapture._decide_guarded` guards the dispatch path's
    own call, and over the RENDER as much as over the decision: `decide` raises `GrantError` on
    a grant/declaration class disagreement, and the render raises just as readily on a
    malformed `VERBS` table — `ModuleVerbRegistry.verbs` checks only that the table is a
    Mapping, so a non-callable body reaches `inspect.signature` inside `model_facing_params`
    and comes back as `TypeError`. An exception out of a discovery tool ends the lead's turn,
    the one thing O4 forbids of every branch here; deciding and rendering are one guarded unit
    because a broken adapter can fail either half and the lead reads the same answer for both.
    """
    try:
        decision = registry.decide(system, verb)
        if decision.outcome != GRANTED or decision.fn is None:
            return None, None
        # `model_facing_params`, not `declared_params`: a `wrapper_only` param is refused by
        # `validate_params`, so publishing it would advertise a binding that cannot be made.
        params = model_facing_params(decision.fn)
        hints = _resolved_hints(decision.fn)
        rendered = ", ".join(_rendered_param(p, hints) for p in params.values())
        # `shown`, not the raw `system` (`_echoed_system`): every other span of this answer
        # goes through that bound, and the one line the lead is told to COPY is the last place
        # an unbounded model-authored name should land unescaped.
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

    The two readers are `model_facing_params` and `_resolved_hints` — the SAME pair
    `validate_params` enforces on (verbs.py:196-232) — so what this publishes and what the
    boundary accepts cannot drift apart. The grant filter goes through `registry.decide`
    rather than `grant.allows` for the same reason one layer up: `decide` is the dispatch
    path's own decision point, so a verb this names is a verb `query` would admit.

    The SYSTEM-level grant check runs first and separately, because `decide` is per-verb and
    reaching it already costs the adapter import this ordering exists to withhold.

    Nothing is persisted. This writes no queries-table row, touches no circuit breaker and no
    repeat guard — it is a read of our own adapter signatures, not a measurement of a system
    of record, and the offline loop's `.queries` must keep meaning "what the defender ran".
    Its output is trusted for the same reason: the text is derived from first-party source, so
    it carries no `wrap_fresh` untrusted frame the way a payload does.
    """
    shown = _echoed_system(system)
    # GRANT FIRST, before anything resolves an adapter — `decide`'s own ordering (§7 R11).
    reachable = _granted_systems(registry)
    if system not in reachable:
        roster = f" The systems your grant reaches: {', '.join(reachable)}." if reachable else ""
        return _LIST_VERBS_UNREACHABLE.format(system=shown, roster=roster)

    declared, degradation = _list_verbs_declared(registry, system, shown)
    if degradation is not None:
        return degradation

    lines: list[str] = []
    any_unenforced = False
    # `key=str`, because the sort must not be the branch that raises: a broken adapter's
    # `VERBS` may mix key types (`{"a": …, 7: …}`), and a bare `sorted` over that is the
    # TypeError that ends the lead's turn before any degradation can be composed. A non-string
    # key survives the sort and is then withheld by the grant filter below, where a name no
    # grant can name belongs.
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
        # OFF THE EVENT LOOP, for the same reason the `query` tool's own dispatch is: this
        # reads no system of record, but it does import the adapter MODULE on first use and
        # re-read/re-parse its source per withheld verb (`declared_verb_names`) — synchronous
        # filesystem work that would otherwise stall every sibling lead's turn in the process.
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
