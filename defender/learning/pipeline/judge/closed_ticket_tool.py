"""The benign judge's two closed-ticket tools — the typed, host-side replacement for the
removed bash ticket lane (#672, superseding #338's ``python3 ticket_adapter … --require-closed``
grant).

    list_closed_tickets(label, q)   — the precedent search
    get_closed_ticket(key)          — confirm one cited closed case

Both drive the SAME ``ticket`` verb bodies the surviving CLI callers use
(``scripts/adapters/ticket_adapter.py``), in-process off the event loop with
``require_closed=True`` HARD-CODED — so *closed-only* moves from *mandatory in the argv
grammar* (a flag a mechanical migration could drop) to *unreachable by construction*: no
``status`` / ``require_closed`` slot exists on either model-facing schema.

The security property is the answer-key defense (O2/O3): the benign judge must never read the
*open in-flight ticket* for the case it is scoring. This module realizes it four ways, none of
which is a runtime direction check (the adversarial leg simply never registers these tools —
absence by registration, N3):

  - **Closed-pin** — ``require_closed=True`` on the wire; the verb body pins the outgoing
    ``status=closed`` and refuses a non-closed body as a business fault (exit 1).
  - **Key schema** (Fork A, tightened by #684) — ``get`` screens ``key`` against a defined
    grammar before any store attempt: anything outside it — empty, whitespace-only,
    path/URL-significant characters, whitespace and CR/LF — draws a retry-class response with
    ZERO store attempts. The grammar is an ENVIRONMENT fact, not a constant here: it is the
    ticket system's REQUIRED ``TICKET_KEY_PATTERN`` config value, reached through the same
    ``verbs=`` registry seam as the store itself, and a store that declares none FAILS CLOSED
    AND LOUD (no read, a recorded infra fault, a breaker contribution) rather than falling
    back to a built-in guess.

    This screen is DEFENSE IN DEPTH, not the only control: #684's follow-up percent-encodes
    the key into ``/tickets/{key}`` at the adapter (as the ticket WRITER always has), so no
    key value can reshape the request even unscreened. What the screen still buys is
    retry-class feedback the model can act on, a store never asked for a key this environment
    says cannot exist, and an audit trail without garbage in it. ``label``/``q`` need no
    screen for the same reason they never did — ``list_tickets`` urlencodes them — so the two
    paths are now symmetric rather than the deliberate asymmetry #672 recorded.
  - **Self-key exclusion** (Fork C/H) — the case-under-judgment's own key (the judge's learning
    run-dir basename) is refused pre-store on ``get``, filtered per-item by identity on ``list``,
    and — on ``get`` only — screened out of a fetched closed ticket whose free text NAMES it
    (Fork H is ``get``-scoped; the ``list`` path carries the status + identity screens only, so a
    listed sibling's free text that names the self-case is NOT redacted — the graph's N-note).
  - **Item re-check** (Fork G) — ``list`` re-checks each returned item's status client-side and
    drops non-closed (or self-key) records before the envelope.

Capture + breaker mirror the ``query`` tool FULLY (Fork B/E): every store attempt writes one
capture row to the JUDGE's ``executed_queries.jsonl`` with its payload persisted by-ref, an
oversized view is bounded at the query tool's own passthrough ceiling with a truncation note,
and the ``ticket`` circuit breaker is both honored (an open breaker → an immediate failed result
with no transport attempt) and contributed to (an infra fault records against it; a business
refusal never does). The error seam mirrors the query tool's catch-all: control-flow exceptions
re-raise, ``AdapterFault`` → its ``(exit_code, detail)``, an unmapped ``BaseException`` → the
fault-class envelope (write a row, never delete one). Every model-visible string — success view
and fault detail alike — rides inside the per-bind salted untrusted envelope.
"""
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

#: The queries-table sink for the judge's ticket reads and the by-ref payload dir, both under
#: the JUDGE's own learning run dir (never gather's investigation run dir — the two tables stay
#: distinct writers' tables, d27).
_QUERIES_TABLE = "executed_queries.jsonl"
_PAYLOAD_DIR = "ticket_reads"

#: The verb that yields this environment's ticket-key grammar (``TICKET_KEY_PATTERN``, a
#: REQUIRED key of the ticket system's config — ticket_adapter.REQUIRED_CONFIG_KEYS). It is
#: resolved through the SAME registry seam as the store reads, so the screen has no second
#: route to the environment and tests drive it with the same fake.
_KEY_PATTERN_VERB = "key-pattern"


def _self_key(deps: AgentDeps) -> str:
    """The case-under-judgment's key — the judge's learning run-dir basename, which is also the
    open in-flight ticket's key (``run_id``). The leg's deps already identify it, so the
    self-exclusion is state-independent (Fork C)."""
    return Path(deps.run_dir).name


def _key_reject_reason(key: str, grammar: re.Pattern[str]) -> str | None:
    """Fork A's key schema, checked against THIS environment's declared grammar. ``None`` when
    the key clears it.

    ``grammar`` comes from the store's own config (``TICKET_KEY_PATTERN``) and is anchored by
    the caller: the environment declares the key SHAPE, this module decides that a key must
    match it WHOLE. Rejecting an off-grammar key costs no readable ticket — a key this store
    cannot mint is a key it cannot hold — and the model gets a retry it can act on rather than
    a 404 it must interpret. Length is an explicit non-clause; #684 dropped #672's separate
    "clean non-ASCII flows opaquely" carve-out — whether non-ASCII keys exist is now the
    environment's statement to make, in its pattern.
    """
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
    """This environment's ticket-key grammar, compiled and ANCHORED, or the fault that stands
    in for it — ``(None, exit_code, detail)``.

    FAIL CLOSED AND LOUD is the whole contract here. The grammar is a required config key, so
    an absent one (``ConfigFault``), an adapter that declares no such verb (``KeyError``), or
    a value that will not compile all resolve to a fault the caller turns into a FAILED tool
    result with ZERO store attempts — the read stops rather than proceeding on a built-in
    guess about what this store's keys look like. Loud, in the three channels the tool already
    owns: the model sees the failure, the capture row records it, and the infra class
    contributes to the ``ticket`` breaker, so a persistently misconfigured store trips it
    instead of paying full price on every judgment.
    """
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
    except re.error as e:
        return None, DEFAULT_FAULT_EXIT, (
            f"ticket key grammar unusable: TICKET_KEY_PATTERN {pattern!r} does not "
            f"compile ({e})"
        )


async def _run_verb(deps: AgentDeps, verbs: Any, verb: str, params: dict) -> tuple[Any, int, str]:
    """Resolve one ticket verb from the registry and drive its body in-process, off the event
    loop, mirroring the query tool's error seam: control-flow exceptions re-raise; ``AdapterFault``
    maps to its ``(exit_code, detail)``; an unmapped ``BaseException`` still returns (as infra) so
    the caller can write a row rather than unwind out of ``agent.iter()``.

    The registry lookup is INSIDE the seam too: ``verbs.verbs(SYSTEM)[verb]`` lazily imports the
    real adapter on first use (``ModuleVerbRegistry``), so a broken adapter — an import-time fault,
    a malformed/absent ``VERBS`` mapping (→ ``KeyError``) — faults-and-continues like any other
    infra fault (a row is written, the breaker records it) rather than unwinding the stage. A
    resolution fault escaping here was the one hole in the 'write a row, never delete one'
    invariant this module documents; keeping it inside the try closes it."""
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
    """The next capture-row seq = the number of rows already in the judge's queries table.
    Counting rows keeps the seq (and the by-ref payload path) distinct across calls and across
    repeated judgments of the same case (the audit trail accumulates)."""
    table = run_dir / _QUERIES_TABLE
    try:
        return len(read_jsonl_rows(table)) if table.is_file() else 0
    except OSError:
        return 0


def _persist_capture_payload(run_dir: Path, seq: int, text: str) -> str | None:
    """Write ``ticket_reads/{seq}.json`` under the judge run dir and return the run-dir-relative
    path (the row's by-ref FK), or ``None`` on a write failure."""
    payload_dir = run_dir / _PAYLOAD_DIR
    payload_path = payload_dir / f"{seq}.json"
    try:
        payload_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(text, encoding="utf-8")
    except OSError:
        return None
    return str(payload_path.relative_to(run_dir))


def _capture_payload_note(run_dir: Path, payload_rel: str | None) -> str:
    """The ``[record_query] raw payload: <abs path>`` line, ABSOLUTE so the read/bash lanes can
    open it (they resolve relative operands against the repo root, not the run dir)."""
    return (
        f"\n[record_query] raw payload: {run_dir / payload_rel}" if payload_rel else ""
    )


def _capture_and_view(
    deps: AgentDeps, lock: asyncio.Lock, verb: str, params: dict,
    payload: Any, exit_code: int, detail: str,
) -> Any:
    """Write the by-ref payload + the capture row, record the breaker outcome, and build the
    model-visible view — the query tool's ``_record`` + ``_model_view``, judge-shaped.

    Returns a coroutine to await (the seq→write→append window holds no ``await`` and runs under
    ``lock`` so two calls in one turn cannot collide on the seq or clobber a payload)."""
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
        # Breaker second: record_outcome RAISES RunAborted at the run-wide kill limit, and the
        # row for the failure that crossed it must already be on disk (it is a control-flow
        # exception the tool must NOT swallow — it kills the stage).
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
    """Fork G + V-A: keep only genuinely-closed items that are not the self-case's own record,
    per-item, before the envelope. Duplicates survive (the re-check is status + self-key
    identity, never a dedup). A non-dict item is dropped as unreadable."""
    kept = [
        t for t in payload.get("tickets", [])
        if isinstance(t, dict) and t.get("status") == "closed" and t.get("key") != self_key
    ]
    return {**payload, "tickets": kept}


async def _list_body(deps: AgentDeps, lock: asyncio.Lock, verbs: Any,
                     label: str | None, q: str | None) -> str:
    """``list_closed_tickets`` end-to-end: honor the breaker, drive the verb closed-only,
    re-check each returned item client-side (Fork G/V-A), then capture + view."""
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
    """``get_closed_ticket`` end-to-end: honor the breaker, resolve the environment's key
    grammar (fail closed if it is missing), screen the key against it (Fork A) and against the
    self-case's own key (Fork C), drive the verb closed-only, screen a self-key-naming payload
    (Fork H), then capture + view."""
    if circuit_breaker.is_tripped(deps.run_dir, SYSTEM):
        return circuit_breaker.down_message(deps.run_dir, SYSTEM)
    grammar, cfg_exit, cfg_detail = await _key_grammar(deps, verbs)
    if grammar is None:
        # No grammar, no read: the screen cannot run, so the store is never asked. The row
        # and the breaker contribution are what make that refusal loud.
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
    """A successfully-fetched ``get`` payload → its (payload, exit_code, detail): a non-object
    body is a malformed infra fault, and a genuinely-closed ticket whose free text NAMES the
    case's own key is withheld (Fork H — a business refusal, so it never trips the breaker; the
    one transitive answer-key path whose identifier this seam knows)."""
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
    """Register the two closed-ticket tools on ``agent``, in the fixed tail order the e2e suite
    pins — ``list_closed_tickets`` then ``get_closed_ticket`` (d28). ``verbs`` is the ticket
    verb registry (the real ``ModuleVerbRegistry`` in production, a ``FakeVerbs`` in tests) —
    required, so a def declaring the bit with no registry fails LOUD at build like ``query``."""
    if verbs is None:
        raise ValueError(
            "ToolSet(closed_tickets=True) needs a verb registry — thread one from "
            "the judge engine's `verbs=` seam; a ticket tool with no registry has no store."
        )
    # One lock per built agent: the two tools share the capture sink (seq counts rows), so a
    # one-turn parallel pair must not race the seq→write window (the query tool's `_seq_lock`).
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
