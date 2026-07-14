"""The `query` tool and its capture capability — the typed replacement for the bash lane's
adapter route (#611).

    query(system, verb, query_id, params)

`params` is a `dict[str, Any]` **validated at the tool boundary** against
`VERBS[system][verb]`'s signature. Be precise about what that is: the registry signature is
the allowlist, and enforcement is a runtime VALIDATOR, not the JSON schema — a per-verb
`params` cannot be one schema, so the model sees no per-verb affordance in the tool schema and
learns the roster from the injected catalog instead. What structurally cannot happen any more
is the thing that mattered: no verb can name a **program** or a **command**, and none names a
path in the driver's namespace.

Capture is a CAPABILITY, not a tool-body call
---------------------------------------------
Persist-by-ref, the queries-table row, and the circuit-breaker outcome all live in
`QueryCapture` rather than in the tool body, and the hook is **`wrap_tool_execute`** — which is
not a detail. `tool_manager._run_execute_hooks` is the whole dispatch:

    args = await cap.before_tool_execute(...)
    try:
        tool_result = await cap.wrap_tool_execute(..., handler=do_execute)
    except (SkipToolExecution, CallDeferred, ApprovalRequired, ToolRetryError):
        raise
    except ModelRetry:
        raise                                        # ← bypasses BOTH hooks
    except Exception as e:
        tool_result = await cap.on_tool_execute_error(...)   # default: re-raises
    tool_result = await cap.after_tool_execute(...)          # ← skipped if the above raised

So a verb that RAISES — the whole exit 1 / 2 class — never reaches `after_tool_execute`: no
row, no `payload_status="error"`, no `error_class`, and `circuit_breaker.record_outcome` never
runs, which makes the breaker and its run-wide `RunAborted` kill switch dead code. Picking the
obvious hook would have silently deleted the exact property the change exists to protect.
`wrap_tool_execute` is the only execute-family hook that sees the pre-call, both outcomes AND
the exception — and the only one that can skip `handler()` and RETURN a value, which is what
the breaker's pre-call trip requires (it deliberately returns the down-message as the tool
result without executing and without `ModelRetry`: a tripped system never recovers, so a retry
would burn the budget into an `UnexpectedModelBehavior` crash).

Arg-shape validation runs in a SEPARATE hook family that fires FIRST (`_run_validate_hooks`), so
a malformed tool CALL — `verb` as an int, a missing field — fails there and the execute hooks
never run. Capture therefore installs `wrap_tool_validate` too, or half the exit-64 class
vanishes from the table that the pitfalls-curation lane learns from.

An `AbstractCapability` hook method fires for EVERY tool (the `tools=[…]` filter exists only on
the `Hooks` decorator API), so both hooks name-gate on `call.tool_name` first.

The catch-all catches `BaseException`
-------------------------------------
A transport that `sys.exit`s raises `SystemExit`, which is NOT an `Exception`: pydantic-ai's
`except Exception` misses it and `asyncio.to_thread` re-raises it to the awaiter, so it unwinds
straight out of `agent.iter()` — no row, no breaker outcome, run dead. The transports no longer
exit (`scripts/adapters/faults.py`), but the seam must still hold for a fault nobody mapped: an
unmapped fault has to WRITE a row, not DELETE one.

The carve-out is the other half, and it is not symmetric with intuition: `RunAborted` (the
breaker's run-wide kill switch), `ModelRetry`, and pydantic-ai's control-flow exceptions are all
plain `Exception` subclasses. A broad catch would swallow the kill switch — so
`CONTROL_FLOW_EXCEPTIONS` is re-raised before anything is recorded.
"""

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
from defender.hooks.tag_tool_results import wrap as _wrap
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

#: Exceptions the capture catch-all must RE-RAISE rather than record. Every one is a plain
#: `Exception` subclass — which is precisely why the list has to exist: the broad catch that
#: stops a transport's `SystemExit` from killing the run would otherwise silently swallow the
#: circuit breaker's run-wide kill switch, and the failure would be invisible (the run just
#: keeps querying a dead environment).
CONTROL_FLOW_EXCEPTIONS: tuple[type[BaseException], ...] = (
    circuit_breaker.RunAborted,
    ModelRetry,
    SkipToolExecution,
    CallDeferred,
    ApprovalRequired,
    ToolRetryError,
)

#: The exit code an UNMAPPED fault records. Infra (2), not "agent-fixable": a verb that dies in
#: a way nobody anticipated is a broken data source, and filing it as the model's mistake would
#: send the agent back to re-word a query against a system that cannot answer.
DEFAULT_FAULT_EXIT = 2

#: A `query_id` becomes a `{system}/_draft/{verb}.md` path segment in the offline lead-author,
#: and it is now MODEL-AUTHORED input arriving at a NEW boundary. Narrow on purpose, so a
#: normally coined `{system}.{kebab}` id is never rejected.
_QID_TRAVERSAL = ("/", "\\", "..", "\x00")


def resolve_query_id(system: str, verb: str, model_query_id: str | None) -> str:
    """model-supplied → `{system}.{verb}` → `{system}.ad-hoc`.

    `query_id` was already model-declared before this change: gather appended `--query-id <id>`
    as a pseudo-flag that the harness stripped before exec (the adapter never saw it; argparse
    would have rejected it). This promotes it from a smuggled fake flag to a real param.
    """
    if model_query_id:
        return model_query_id
    return f"{system}.{verb}" if verb else f"{system}.ad-hoc"


def _fault_exit(e: BaseException) -> int:
    """The exit code for a fault the transports did not classify. A `SystemExit` carries one
    (a transport that still exits, or a library that does); anything else lands on the default."""
    if isinstance(e, SystemExit) and isinstance(e.code, int) and e.code != 0:
        return e.code
    return DEFAULT_FAULT_EXIT


def _payload_status(exit_code: int, payload: Any) -> str:
    """The structural status, tested against the RETURNED OBJECT — not the serialized bytes.

    `json.dumps({})` is `'{}'`, which is non-blank, so a byte-level emptiness test would read a
    zero-results verb as `ok` and silently kill the signal the lead-author treats as one of the
    strongest folds it gets ("we looked and there was nothing there")."""
    if exit_code != 0:
        return "error"
    if payload is None:
        return "empty"
    if isinstance(payload, (dict, list, tuple, set, str)) and len(payload) == 0:
        return "empty"
    return "ok"


def _raw_command(system: str, verb: str, params: dict) -> str:
    """The row's `raw_command` — a DERIVED audit string, not a shell command anyone can run.

    Post-cutover there is no argv: this records WHAT ran, for audit, and nothing else. A draft's
    `## Query` fence must come from the declared params, never from here — fencing this would
    teach a command that does not exist."""
    return shlex.join([system, verb, *(f"{k}={v}" for k, v in params.items())])


class QueryCapture(AbstractCapability[Any]):
    """Capture, as a capability: the queries row, the by-ref payload, the breaker outcome, and
    the model-visible result swap. Constructed by DECLARING the tool (`ToolSet.query`), so the
    tool and its capture cannot be separated — a query that ran without a queries row would make
    that table a suggestion rather than the integrity gate it is."""

    def __init__(self, registry: Any):
        self._registry = registry
        # `query` is the FIRST tool that can run concurrently with itself: pydantic-ai's default
        # parallelism is 'parallel', and the verb is thread-offloaded. Today's atomicity is an
        # accident of the bash tool blocking the event loop, and that accident is gone — two
        # calls in one turn would otherwise read the same `_next_seq` (which COUNTS ROWS),
        # overwrite one payload, and mint a duplicate `(lead_id, seq)`. The harm lands two
        # subsystems away: `judge/compare._payload_paths` falls back to `gather_raw/{lead}/0.json`
        # for a row with no payload path, and hands the judge another query's evidence.
        self._seq_lock = asyncio.Lock()

    # --- validation ---------------------------------------------------------

    def _reject(
        self, system: str, verb: str, params: dict, model_query_id: Any = None,
    ) -> str | None:
        """The whole admission check, in one place: unknown system / unknown verb / unknown,
        missing or MISTYPED param / a `query_id` that is not a path segment. `None` when the
        call is admissible.

        `KeyError` from the registry means the system does not exist. Anything else it raises
        means the system exists but its module will not LOAD — a broken data source, not a model
        mistake — so that one is deliberately NOT caught here; the caller files it as infra."""
        try:
            verbs = self._registry.verbs(system)
        except KeyError:
            return (
                f"unknown system {system!r}. Pick one the dispatch catalog names; a system is "
                "not a path and not a program."
            )
        if not verbs:
            # An empty declaration must not read as "no filter". This tree already fails OPEN
            # twice in exactly this shape (`adapter_shims()`'s empty set makes the shim regex
            # None; `descriptor_catalog`'s `or None` degrades an empty roster to no-catalog), so
            # the emptiness is decided here rather than smoothed into an absence.
            return f"system {system!r} declares no verbs — it is unreachable, not unfiltered."
        if verb not in verbs:
            return f"unknown verb {verb!r} for {system}. Declared verbs: {sorted(verbs)}."
        if model_query_id and any(t in str(model_query_id) for t in _QID_TRAVERSAL):
            return (
                f"invalid query_id {model_query_id!r}: no '/', '\\', '..' or NUL — it becomes a "
                "catalog path segment. Coin a `{system}.{kebab-name}` id."
            )
        return validate_params(verbs[verb], params)

    # --- the two hooks ------------------------------------------------------

    async def wrap_tool_validate(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        """The VALIDATE family fires BEFORE the execute family, and a malformed tool CALL (a
        `verb` that is not a string, a missing field, unparseable args) fails HERE. Without this
        hook that whole class writes no row — and `lead_author.md` calls `payload_status: error`
        the strongest signal it sees for a fold, so losing half of exit-64 would quietly halve a
        shipped learning signal."""
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

        # 1. The breaker's PRE-CALL trip: return the down-message as the tool RESULT, without
        # executing and without ModelRetry. Only `wrap_tool_execute` can express this —
        # `before_tool_execute` may only return args or raise. No row: nothing ran.
        tripped = _tripped_message(deps, system)
        if tripped is not None:
            return tripped

        # 2. Our own validation (the registry + the query_id shape). It writes its row BEFORE it
        # raises: `ModelRetry` bypasses `on_tool_execute_error` AND `after_tool_execute`, so a
        # write placed after the raise would simply never happen.
        try:
            reason = self._reject(system, verb, params, model_query_id)
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except BaseException as e:  # noqa: BLE001 — the registry could not LOAD this system's module
            # BaseException, not Exception: `_reject` IMPORTS the adapter module, and a module
            # whose import body calls `sys.exit()` (a top-level `parse_args()` — what every one
            # of these files looked like before #611, and what `connect` scaffolds from) raises
            # SystemExit, which is not an Exception. Catching only Exception would let it unwind
            # out of `agent.iter()`: no row, no breaker outcome, run dead — the exact failure the
            # execute catch-all below exists to prevent, one seam earlier.
            # A `{system}_cli.py` that will not import is a BROKEN DATA SOURCE: not the model's
            # mistake (it cannot fix it, so exit 64 would loop it), and not a reason to kill the
            # run. File it as infra (2) — the breaker takes that ONE system down and the
            # investigation continues against the others, which is exactly what the taxonomy
            # already means by "the system is down".
            #
            # It has to be caught HERE because this call sits outside the handler's catch-all:
            # the resolution+import happens during validation, so an ImportError escaped
            # `wrap_tool_execute` entirely and unwound the run. The registry only imports a
            # module at first use, so this is also the first place the failure can surface.
            detail = f"{system} adapter failed to load: {type(e).__name__}: {e}"
            row, text = await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None), params=params, payload=None,
                exit_code=DEFAULT_FAULT_EXIT, detail=detail,
            )
            return self._model_view(deps, row, text, DEFAULT_FAULT_EXIT, detail)
        if reason is not None:
            await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None),   # never the rejected id
                params=params, payload=None,
                exit_code=USAGE_EXIT_CODE, detail=reason,
            )
            raise ModelRetry(reason)

        query_id = resolve_query_id(system, verb, _as_str(model_query_id) or None)

        # 3. Execute. The catch-all is BaseException minus the control flow (see the module
        # docstring): an unmapped fault must write a row, never delete one.
        payload: Any = None
        try:
            payload = await handler(args)
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
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

    # --- capture ------------------------------------------------------------

    async def _record(
        self, deps, *, system: str, verb: str, query_id: str, params: dict,
        payload: Any, exit_code: int, detail: str,
    ) -> tuple[dict, str]:
        """Write the payload by ref + the queries row, then record the breaker outcome. Returns
        the row and the serialized payload (the model view is built from both).

        Row first, breaker second: `record_outcome` RAISES `RunAborted` when the run-wide kill
        limit is crossed, and the row for the failure that crossed it must already be on disk."""
        if deps.lead_id is None:
            # A bind-produced gather deps is per-run (lead unset); the dispatch stamps the real
            # lead before any query runs. An unstamped deps here is a WIRING bug, not model
            # input — a ModelRetry would be unfixable by the model and would burn the retry
            # budget into an UnexpectedModelBehavior crash.
            raise RuntimeError("internal: query reached capture without a dispatched lead_id")

        text = "" if exit_code != 0 else json.dumps(payload, default=str)
        run_dir = deps.run_dir

        # The seq → write → append window holds no `await`, and the lock makes that structural
        # rather than incidental (see `_seq_lock`).
        async with self._seq_lock:
            seq = _next_seq(run_dir, deps.lead_id)
            payload_rel = _persist_payload(run_dir, deps.lead_id, seq, text)
            row = {
                "lead_id": deps.lead_id,
                "seq": seq,
                "system": system,
                # The real verb, at last. The column held the query_id SUFFIX before this change
                # (`record_query.py:452`) — a checked-in fixture has `verb: sshd-failed-by-srcip`
                # for what was an `esql` call — and it has zero production readers, so putting the
                # honest value in costs nothing and ends the lie.
                "verb": verb,
                "query_id": query_id,
                "params": dict(params),
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
        """What the model sees: the exit-code envelope the bash lane always used, the payload
        view SALT-WRAPPED as untrusted, and the absolute `[record_query] raw payload:` note the
        gather SKILL filters on.

        The wrap is NEW behaviour, not parity: adapter payloads entered gather's context BARE
        before this change (`tag_tool_results._bash_is_untrusted` lives in a hook whose `main()`
        is never called). It uses `deps.salt` — the run's ONE token — never a freshly minted one:
        a fresh salt lets the model forge the closing tag and the injection defense fails open.
        The note stays OUTSIDE the wrap and stays ABSOLUTE: bash and the read tool resolve a
        relative operand against the repo root, not the run dir, so the relative table FK would
        be un-`cat`-able."""
        note = _payload_note(deps, row)
        if exit_code != 0:
            # The vendor's own diagnosis is data too — it is the far side's text.
            return _format_bash_result(exit_code, "", _wrap(detail, "untrusted", deps.salt), note)
        view = (
            build_truncated_view(text, row["payload_path"], deps.run_dir)
            if (_is_event_payload(text) or len(text) > _passthrough_max_bytes())
            else text
        )
        return _format_bash_result(0, _wrap(view, "untrusted", deps.salt), "", note)


# --- registration ------------------------------------------------------------

def register_query_tool(agent, registry) -> None:
    """Register `query` as a PLAIN agent tool — it lands in `agent._function_toolset.tools`.

    Deliberately not a capability-owned toolset: those land in `_cap_toolsets` instead, which is
    invisible to #538's "registers NOTHING" tool-freeness assertions — they would stay green
    while the invariant they encode was false. It would also move "which agent may reach a data
    source" out of policy-as-data (`GATHER_DEF` + its `ToolSet`) and into a call-site
    `capabilities=` argument that `compile_policy` and `defender-policy explain` cannot see."""

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
        # Off the event loop: a transport blocks on `docker exec` for seconds, and blocking the
        # loop here is what made today's `_next_seq` accidentally atomic. The outer wall-clock
        # budget the capture subprocess used to enforce does NOT come back —
        # `asyncio.wait_for` cancels the AWAIT, not the thread, so a hung verb would leak a
        # thread and a synthesized exit-124 row would report a kill that never happened. The
        # transport's own inner timeout is the real one, and it is mandatory.
        return await asyncio.to_thread(fn, vctx, **params)


# --- small local helpers ------------------------------------------------------

def _raw_args(args: Any) -> dict:
    """The best-effort dict view of PRE-validation args (they may still be a JSON string), so a
    malformed call can still name its system/verb in the row it writes."""
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
    """Write `gather_raw/{lead_id}/{seq}.json` and return the run-dir-relative path (the row's
    FK), or None if the write failed. Written even for a FAILED query — a row whose
    `payload_path` is null makes `judge/compare._payload_paths` fall back to
    `gather_raw/{lead}/0.json` and read another query's payload."""
    lead_dir = RunPaths(run_dir).gather_raw / lead_id
    payload_path = lead_dir / f"{seq}.json"
    try:
        lead_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(text, encoding="utf-8")
    except OSError:
        return None
    return str(payload_path.relative_to(run_dir))


# Imported at the BOTTOM: `tools`/`tools_gather` carry the run-env + result-envelope + breaker
# helpers this module reuses, and they import the agent build chain that registers this tool. The
# cycle is closed at call time, never at import.
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
