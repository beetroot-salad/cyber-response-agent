from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import append_jsonl, read_jsonl_rows
from defender.runtime import circuit_breaker
from defender.runtime.query_tool import (
    CONTROL_FLOW_EXCEPTIONS,
    DEFAULT_FAULT_EXIT,
    _fault_exit,
)
from defender.runtime.tools import AgentDeps, _bash_env, _format_bash_result
from defender.runtime.untrusted import wrap as _wrap
from defender.runtime.verbs import VerbContext
from defender.scripts.adapters.faults import AdapterFault
from defender.scripts.gather_tools.record_query import (
    _is_event_payload,
    _passthrough_max_bytes,
    build_truncated_view,
)

SYSTEM = "ticket"
TOOL_GET = "get_closed_ticket"
TOOL_LIST = "list_closed_tickets"

_QUERIES_TABLE = "executed_queries.jsonl"
_PAYLOAD_DIR = "ticket_reads"

_KEY_PATTERN_VERB = "key-pattern"


def _self_key(deps: AgentDeps) -> str:
    return Path(deps.run_dir).name


def _key_reject_reason(key: str, grammar: re.Pattern[str]) -> str | None:
    if not key.strip():
        return (
            "closed-ticket key must be a non-empty, non-blank case id (e.g. SOC-1042). "
            "Cite the closed case from the seed menu."
        )
    if grammar.match(key) is None:
        return (
            f"closed-ticket key {key!r} does not match this ticket store's key grammar "
            f"({grammar.pattern}) — pass a bare case id (e.g. SOC-1042, "
            "20260720T0000Z-sshd-672), not a path, URL, or free text."
        )
    return None


async def _key_grammar(
    deps: AgentDeps, verbs: Any,
) -> tuple[re.Pattern[str] | None, int, str]:
    pattern, exit_code, detail = await _run_verb(deps, verbs, _KEY_PATTERN_VERB, {})
    if exit_code != 0:
        return None, exit_code, f"ticket key grammar unavailable: {detail}"
    if not isinstance(pattern, str) or not pattern:
        return None, DEFAULT_FAULT_EXIT, (
            f"ticket key grammar unavailable: {_KEY_PATTERN_VERB} returned "
            f"{type(pattern).__name__}, not a non-empty pattern string"
        )
    try:
        return re.compile(rf"\A(?:{pattern})\Z"), 0, ""
    except (re.error, RecursionError, OverflowError) as e:
        # `re.error` is NOT the whole of "will not compile": a repeat count the compiler
        # cannot hold (`a{99999999999}`) raises OverflowError and a deeply nested pattern
        # raises RecursionError. Both escape a bare `except re.error` — and this compile
        # sits OUTSIDE `_run_verb`'s seam, so one would unwind the whole judge stage and
        # leave no row, the exact hole this module documents closing.
        return None, DEFAULT_FAULT_EXIT, (
            f"ticket key grammar unusable: TICKET_KEY_PATTERN {pattern!r} does not "
            f"compile ({type(e).__name__}: {e})"
        )


async def _run_verb(deps: AgentDeps, verbs: Any, verb: str, params: dict) -> tuple[Any, int, str]:
    vctx = VerbContext(
        defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=_bash_env(deps),
    )
    try:
        fn = verbs.verbs(SYSTEM)[verb]
        payload = await asyncio.to_thread(fn, vctx, **params)
    except CONTROL_FLOW_EXCEPTIONS:
        raise
    except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
        raise
    except AdapterFault as e:
        return None, e.exit_code, e.detail
    except BaseException as e:  # noqa: BLE001 — an unmapped fault still writes a row, never unwinds
        return None, _fault_exit(e), str(e) or type(e).__name__
    return payload, 0, ""


def _next_capture_seq(run_dir: Path) -> int:
    table = run_dir / _QUERIES_TABLE
    try:
        return len(read_jsonl_rows(table)) if table.is_file() else 0
    except OSError:
        return 0


def _persist_capture_payload(run_dir: Path, seq: int, text: str) -> str | None:
    payload_dir = run_dir / _PAYLOAD_DIR
    payload_path = payload_dir / f"{seq}.json"
    try:
        payload_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(text, encoding="utf-8")
    except OSError:
        return None
    return str(payload_path.relative_to(run_dir))


def _capture_payload_note(run_dir: Path, payload_rel: str | None) -> str:
    return (
        f"\n[record_query] raw payload: {run_dir / payload_rel}" if payload_rel else ""
    )


def _capture_and_view(
    deps: AgentDeps, lock: asyncio.Lock, verb: str, params: dict,
    payload: Any, exit_code: int, detail: str,
) -> Any:
    run_dir = deps.run_dir
    text = "" if exit_code != 0 else json.dumps(payload, default=str)

    async def _go() -> str:
        async with lock:
            seq = _next_capture_seq(run_dir)
            payload_rel = _persist_capture_payload(run_dir, seq, text)
            row = {
                "seq": seq,
                "system": SYSTEM,
                "verb": verb,
                "params": dict(params),
                "payload_path": payload_rel,
                "exit_code": exit_code,
                "error_class": circuit_breaker.error_class_for_exit(exit_code),
            }
            append_jsonl(run_dir / _QUERIES_TABLE, [row])
        circuit_breaker.record_outcome(run_dir, SYSTEM, exit_code)
        note = _capture_payload_note(run_dir, payload_rel)
        if exit_code != 0:
            return _format_bash_result(
                exit_code, "", _wrap(detail, "untrusted", deps.salt), note,
            )
        view = (
            build_truncated_view(text, payload_rel, run_dir)
            if (_is_event_payload(text) or len(text) > _passthrough_max_bytes())
            else text
        )
        return _format_bash_result(0, _wrap(view, "untrusted", deps.salt), "", note)

    return _go()


def _screen_listing(payload: dict, self_key: str) -> dict:
    kept = [
        t for t in payload.get("tickets", [])
        if isinstance(t, dict) and t.get("status") == "closed" and t.get("key") != self_key
    ]
    return {**payload, "tickets": kept}


async def _list_body(deps: AgentDeps, lock: asyncio.Lock, verbs: Any,
                     label: str | None, q: str | None) -> str:
    if circuit_breaker.is_tripped(deps.run_dir, SYSTEM):
        return circuit_breaker.down_message(deps.run_dir, SYSTEM)
    payload, exit_code, detail = await _run_verb(
        deps, verbs, "list-tickets", {"label": label, "q": q, "require_closed": True},
    )
    if exit_code == 0:
        if not (isinstance(payload, dict) and isinstance(payload.get("tickets"), list)):
            payload, exit_code, detail = (
                None, DEFAULT_FAULT_EXIT,
                "malformed ticket store response: 'tickets' is not a list",
            )
        else:
            payload = _screen_listing(payload, _self_key(deps))
    return await _capture_and_view(
        deps, lock, "list-tickets", {"label": label, "q": q}, payload, exit_code, detail,
    )


async def _get_body(deps: AgentDeps, lock: asyncio.Lock, verbs: Any, key: str) -> str:
    if circuit_breaker.is_tripped(deps.run_dir, SYSTEM):
        return circuit_breaker.down_message(deps.run_dir, SYSTEM)
    grammar, cfg_exit, cfg_detail = await _key_grammar(deps, verbs)
    if grammar is None:
        return await _capture_and_view(
            deps, lock, "get-ticket", {"key": key}, None, cfg_exit, cfg_detail,
        )
    reason = _key_reject_reason(key, grammar)
    if reason is not None:
        raise ModelRetry(reason)
    if key == _self_key(deps):
        raise ModelRetry(
            "that key is the in-flight ticket for the case you are scoring — it is the answer "
            "key, never readable through this confirm. Cite a past CLOSED case."
        )
    payload, exit_code, detail = await _run_verb(
        deps, verbs, "get-ticket", {"key": key, "require_closed": True},
    )
    if exit_code == 0:
        payload, exit_code, detail = _screen_fetched_ticket(deps, payload)
    return await _capture_and_view(
        deps, lock, "get-ticket", {"key": key}, payload, exit_code, detail,
    )


def _screen_fetched_ticket(deps: AgentDeps, payload: Any) -> tuple[Any, int, str]:
    if not isinstance(payload, dict):
        return None, DEFAULT_FAULT_EXIT, "malformed ticket store response: expected a ticket object"
    if _self_key(deps) in json.dumps(payload, default=str):
        return (
            None, 1,
            "the fetched ticket references the case under judgment; its content is withheld "
            "to keep the answer key unreadable.",
        )
    return payload, 0, ""


def register_closed_ticket_tools(agent: Any, verbs: Any) -> None:
    if verbs is None:
        raise ValueError(
            "ToolSet(closed_tickets=True) needs a verb registry — thread one from "
            "the judge engine's `verbs=` seam; a ticket tool with no registry has no store."
        )
    seq_lock = asyncio.Lock()

    @agent.tool
    async def list_closed_tickets(
        ctx: RunContext[Any], label: str | None = None, q: str | None = None
    ) -> str:
        """List CLOSED past cases from the case-history store (closed-only, by construction).
        `label` filters by signature label; `q` is a free-text search. Use it to find the
        precedent a survive-verdict would rest on, then confirm the one you cite with
        get_closed_ticket. The in-flight ticket for the alert you are scoring is never
        returned."""
        return await _list_body(ctx.deps, seq_lock, verbs, label, q)

    @agent.tool
    async def get_closed_ticket(ctx: RunContext[Any], key: str) -> str:
        """Confirm one CITED closed past case by its case id `key` (closed-only, by
        construction — a non-closed or missing ticket refuses). Never returns the open
        in-flight ticket for the alert you are scoring. A cited seed the store can't confirm,
        or whose grounded conditions these actuals contradict, does not survive on that basis."""
        return await _get_body(ctx.deps, seq_lock, verbs, key)


__all__ = ["TOOL_GET", "TOOL_LIST", "register_closed_ticket_tools"]
