
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
    _is_event_payload,
    _next_seq,
    _passthrough_max_bytes,
    build_truncated_view,
    payload_digest,
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
    if model_query_id:
        return model_query_id
    return f"{system}.{verb}" if verb else f"{system}.ad-hoc"


def _fault_exit(e: BaseException) -> int:
    if isinstance(e, SystemExit) and isinstance(e.code, int) and e.code != 0:
        return e.code
    return DEFAULT_FAULT_EXIT


def _json_safe_params(value: Any) -> Any:
    import math

    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, dict):
        return {k: _json_safe_params(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_params(v) for v in value]
    return value


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

    async def wrap_tool_validate(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)
        try:
            return await handler(args)
        except (ValidationError, ModelRetry) as e:
            raw = _raw_args(args)
            system, verb = _as_str(raw.get("system")), _as_str(raw.get("verb"))
            await self._record(
                ctx.deps,
                system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None),
                params=_as_dict(raw.get("params")),
                payload=None,
                exit_code=USAGE_EXIT_CODE,
                detail=str(e),
            )
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
                query_id=resolve_query_id(system, verb, None), params=params, payload=None,
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
            await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None), params=params, payload=None,
                exit_code=USAGE_EXIT_CODE, detail=decision.refusal or "unresolvable",
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
        if exit_code != 0:
            return _format_bash_result(exit_code, "", _wrap(detail, "untrusted", deps.salt), note)
        view = (
            build_truncated_view(text, row["payload_path"], deps.run_dir)
            if (_is_event_payload(text) or len(text) > _passthrough_max_bytes())
            else text
        )
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
