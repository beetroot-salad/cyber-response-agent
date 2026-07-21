
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

from defender._io import append_jsonl
from defender._run_paths import RunPaths
from defender.hooks.budget_enforcer import BudgetKill
from defender.runtime.untrusted import wrap as _wrap
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault
from defender.scripts.gather_tools.record_query import (
    _is_event_payload,
    _next_seq,
    _passthrough_max_bytes,
    build_truncated_view,
    payload_digest,
)

from . import circuit_breaker
from .verbs import VerbContext, validate_params

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


class QueryCapture(AbstractCapability[Any]):

    def __init__(self, registry: Any):
        self._registry = registry
        self._seq_lock = asyncio.Lock()


    def _reject(
        self, system: str, verb: str, params: dict, model_query_id: Any = None,
    ) -> str | None:
        try:
            verbs = self._registry.verbs(system)
        except KeyError:
            return (
                f"unknown system {system!r}. Pick one the dispatch catalog names; a system is "
                "not a path and not a program."
            )
        if not verbs:
            return f"system {system!r} declares no verbs — it is unreachable, not unfiltered."
        if verb not in verbs:
            return f"unknown verb {verb!r} for {system}. Declared verbs: {sorted(verbs)}."
        if model_query_id and any(t in str(model_query_id) for t in _QID_TRAVERSAL):
            return (
                f"invalid query_id {model_query_id!r}: no '/', '\\', '..' or NUL — it becomes a "
                "catalog path segment. Coin a `{system}.{kebab-name}` id."
            )
        return validate_params(verbs[verb], params)

    def _reject_guarded(
        self, system: str, verb: str, params: dict, model_query_id: Any = None,
    ) -> tuple[str | None, str | None]:
        try:
            return self._reject(system, verb, params, model_query_id), None
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except BaseException as e:  # noqa: BLE001 — the registry could not LOAD this system's module
            return None, f"{system} adapter failed to load: {type(e).__name__}: {e}"


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

    async def wrap_tool_execute(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)

        deps = ctx.deps
        system = _as_str(args.get("system"))
        verb = _as_str(args.get("verb"))
        params = _as_dict(args.get("params"))
        model_query_id = args.get("query_id")

        tripped = _tripped_message(deps, system)
        if tripped is not None:
            return tripped

        reason, load_error = self._reject_guarded(system, verb, params, model_query_id)
        if load_error is not None:
            row, text = await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None), params=params, payload=None,
                exit_code=DEFAULT_FAULT_EXIT, detail=load_error,
            )
            return self._model_view(deps, row, text, DEFAULT_FAULT_EXIT, load_error)
        if reason is not None:
            await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None),
                params=params, payload=None,
                exit_code=USAGE_EXIT_CODE, detail=reason,
            )
            raise ModelRetry(reason)

        query_id = resolve_query_id(system, verb, _as_str(model_query_id) or None)

        payload: Any = None
        try:
            payload = await handler(args)
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except AdapterFault as e:
            exit_code, detail = e.exit_code, e.detail
        except BaseException as e:  # noqa: BLE001 — the point: an unmapped fault still writes a row
            exit_code, detail = _fault_exit(e), str(e) or type(e).__name__
        else:
            exit_code, detail = 0, ""

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
            append_jsonl(RunPaths(run_dir).executed_queries, [row])

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
        lead_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(text, encoding="utf-8")
    except OSError:
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
