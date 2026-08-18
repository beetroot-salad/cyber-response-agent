"""The benign judge's two closed-ticket tools — the typed, host-side ticket lane.

    list_closed_tickets(label, q)   — the precedent search
    get_closed_ticket(key)          — confirm one cited closed case

Both drive the SAME ``ticket`` verb bodies the CLI callers use
(``scripts/adapters/ticket_adapter.py``), in-process off the event loop with
``require_closed=True`` HARD-CODED — no ``status`` / ``require_closed`` slot exists on either
model-facing schema, so *closed-only* is unreachable by construction rather than a flag.

The security property is the answer-key defense: the benign judge must never read the *open
in-flight ticket* for the case it is scoring, nor anything written about that case while it was
live. Five arms realize it, none a runtime direction check — the adversarial leg simply never
registers these tools (absence by registration):

  - **Closed-pin** — ``require_closed=True`` on the wire; the verb body pins the outgoing
    ``status=closed`` and refuses a non-closed body as a business fault (exit 1).
  - **Key schema** (Fork A) — ``get`` screens ``key`` against a defined grammar before any
    store attempt; anything outside it draws a retry-class response with ZERO store attempts.
    The grammar is an ENVIRONMENT fact, not a constant here: the ticket system's REQUIRED
    ``TICKET_KEY_PATTERN`` config value, reached through the same ``verbs=`` registry seam as
    the store itself. A store that declares none FAILS CLOSED AND LOUD (no read, a recorded
    infra fault, a breaker contribution) rather than falling back to a built-in guess. This is
    DEFENSE IN DEPTH — the adapter percent-encodes the key into ``/tickets/{key}``, so no key
    value can reshape the request even unscreened; the screen buys retry-class feedback and a
    clean audit trail. ``label``/``q`` need no screen — ``list_tickets`` urlencodes them.
  - **Self-key exclusion** (Fork C/H) — the case-under-judgment's own key (``deps.run_id``, via
    the shared ``runtime.ticket_screen.self_case_key`` — the SAME definition gather screens on,
    so the two answer-key defenses cannot drift apart) is refused pre-store on ``get``, filtered
    per-item by identity on ``list``, and screened out of a genuinely-closed ticket whose free
    text NAMES it on BOTH surfaces. The surfaces differ only in HOW they withhold (see
    ``_screen_fetched_ticket`` / ``_screen_listing``).

    What stays accepted is the TRANSITIVE path, on both surfaces: a closed ticket quoting some
    OTHER non-closed ticket rides the salted untrusted envelope unredacted. Only the self-case's
    identifier is an identifier this seam knows.
  - **Item re-check** (Fork G) — ``list`` re-checks each returned item's status client-side and
    drops non-closed records before the envelope, alongside the two self-case arms above. All
    are conjuncts of one per-item predicate; none replaced another.
  - **Recency** (Fork J) — every arm above screens on what a record SAYS, so all are defeated by
    a sibling describing the live case in prose without spelling its key. This arm screens on
    WHEN the record was last written, withholding anything not provably older than the case.
    Precedent is by definition older, contamination by definition newer. The boundary comes from
    the store's OWN ``created`` for the in-flight ticket via the ``case-opened-at`` verb, whose
    return type is a bare timestamp — the record is unreachable through it by construction, and
    a judge-carried clock would make the boundary depend on skew (see ``_case_opened_at``).

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
import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import append_jsonl, read_jsonl_rows
from defender.runtime import circuit_breaker, observe
from defender.runtime.query_tool import (
    CONTROL_FLOW_EXCEPTIONS,
    DEFAULT_FAULT_EXIT,
    _fault_exit,
)
from defender.runtime.ticket_screen import screen_get, screen_list, self_case_key
from defender.runtime.tools import AgentDeps, _bash_env, _format_bash_result
from defender._untrusted import wrap_fresh
from defender.runtime.verbs import DENIED, GRANTED, VerbContext
from defender.scripts.adapters.faults import AdapterFault
from defender.scripts.gather_tools.payload_view import render as _render_payload
from defender._clock import parse_iso_utc

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

#: The verb that yields the instant the case under judgment was opened — the ticket store's own
#: ``created`` for the in-flight ticket, and nothing else from it. Reached through the SAME
#: registry seam as the store reads and the key grammar, so the recency screen has no second
#: route to the environment.
_CASE_OPENED_VERB = "case-opened-at"


def _predates_case(record: Any, opened_at: _dt.datetime) -> bool:
    """Fork J's predicate: is EVERY word of this record provably older than the case?

    Screened on ``updated``, falling back to ``created`` — the LAST write, not the first,
    because the leak this arm closes rides in content APPENDED to an old ticket after the case
    opened (a comment on a three-year-old record naming the live incident). Dating such a
    record by its creation would admit it.

    A record whose timestamp is missing or unparseable is not older, it is UNDATED, and is
    dropped: unprovable is not the same as safe. The accepted, one-directional cost is that a
    ticket the investigating agent itself touched during the run goes invisible to the judge —
    that content is the agent's own writing, not independent precedent.
    """
    if not isinstance(record, dict):
        return False
    stamped = record.get("updated")
    instant = parse_iso_utc(stamped if stamped is not None else record.get("created"))
    return instant is not None and instant < opened_at


async def _case_opened_at(
    deps: AgentDeps, verbs: Any,
) -> tuple[_dt.datetime | None, int, str]:
    """The instant the case under judgment was opened → ``(boundary, exit_code, detail)``.

    Three outcomes, and the split between them is the whole design:

      - a usable timestamp → the recency arm runs;
      - the store answers that no such ticket exists (a business fault — a 404 for a case the
        agent never filed) → ``(None, 0, "")``: no boundary to screen against, the other
        conjuncts stand alone, and the read PROCEEDS. Failing here would make the precedent
        search unusable for every case that never opened a ticket;
      - anything else — an unreachable store, a malformed ``created``, an adapter declaring no
        such verb → the fault is returned and the caller FAILS THE READ, loud. An arm that
        stops running when the environment breaks protects nothing.

    Mirroring ``_key_grammar``, a SUCCESSFUL resolution writes no capture row — it is a
    boundary lookup, not a precedent read — while every non-success is recorded by the caller.
    """
    opened, exit_code, detail = await _run_verb(
        deps, verbs, _CASE_OPENED_VERB, {"key": self_case_key(deps)},
    )
    if exit_code == 1:
        return None, 0, ""
    if exit_code != 0:
        return None, exit_code, f"case-opened boundary unavailable: {detail}"
    instant = parse_iso_utc(opened)
    if instant is None:
        return None, DEFAULT_FAULT_EXIT, (
            f"case-opened boundary unusable: {_CASE_OPENED_VERB} returned "
            f"{type(opened).__name__} {opened!r}, not an ISO-8601 instant"
        )
    return instant, 0, ""


def _key_reject_reason(key: str, grammar: re.Pattern[str]) -> str | None:
    """Fork A's key schema, checked against THIS environment's declared grammar. ``None`` when
    the key clears it.

    ``grammar`` comes from the store's own config (``TICKET_KEY_PATTERN``) and is anchored by
    the caller: the environment declares the key SHAPE, this module decides that a key must
    match it WHOLE. Rejecting an off-grammar key costs no readable ticket — a key this store
    cannot mint is a key it cannot hold — and the model gets a retry it can act on rather than
    a 404 it must interpret. Length and non-ASCII are explicit non-clauses: whether such keys
    exist is the environment's statement to make, in its pattern.
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

    FAIL CLOSED AND LOUD is the whole contract. An absent config key (``ConfigFault``), an
    adapter declaring no such verb (``KeyError``), or a value that will not compile all resolve
    to a fault the caller turns into a FAILED tool result with ZERO store attempts — the read
    stops rather than guessing at this store's key shape. Loud in three channels: the model
    sees the failure, the capture row records it, and the infra class contributes to the
    ``ticket`` breaker, so a persistently misconfigured store trips it instead of paying full
    price on every judgment.
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
    except (re.error, RecursionError, OverflowError) as e:
        # ``re.error`` is NOT the whole of "will not compile": a repeat count the compiler
        # cannot hold (``a{99999999999}``) raises ``OverflowError``, a deeply nested pattern
        # raises ``RecursionError``. This compile sits OUTSIDE ``_run_verb``'s seam, so one
        # escaping would unwind the whole judge stage and write NO row.
        return None, DEFAULT_FAULT_EXIT, (
            f"ticket key grammar unusable: TICKET_KEY_PATTERN {pattern!r} does not "
            f"compile ({type(e).__name__}: {e})"
        )


async def _run_verb(deps: AgentDeps, verbs: Any, verb: str, params: dict) -> tuple[Any, int, str]:
    """Resolve one ticket verb from the registry and drive its body in-process, off the event
    loop, mirroring the query tool's error seam: control-flow exceptions re-raise; ``AdapterFault``
    maps to its ``(exit_code, detail)``; an unmapped ``BaseException`` still returns (as infra) so
    the caller can write a row rather than unwind out of ``agent.iter()``.

    The registry lookup is INSIDE the seam too: ``verbs.verbs(SYSTEM)[verb]`` lazily imports the
    real adapter on first use (``ModuleVerbRegistry``), so a broken adapter — an import-time fault,
    a malformed/absent ``VERBS`` mapping (→ ``KeyError``) — faults-and-continues like any other
    infra fault rather than unwinding the stage and breaking 'write a row, never delete one'."""
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
                exit_code, "", wrap_fresh(detail, "untrusted"), note,
            )
        view = _render_payload(text, payload_rel, run_dir)
        return _format_bash_result(0, wrap_fresh(view, "untrusted"), "", note)

    return _go()


def _names_self_case(record: Any, self_key: str) -> bool:
    """Fork H's predicate: does this record NAME the case under judgment anywhere in its content?

    Serialized WHOLE rather than field-by-field, because the self-key may ride in a resolution, a
    nested comment, or the key itself. Strictly wider than gather's identity-only screen, and
    deliberately so — gather correlates, the judge scores. Shared by both surfaces so the ``get``
    withhold and the ``list`` drop cannot answer differently about the same payload.

    ``ensure_ascii=False`` is load-bearing. Under the default the encoder rewrites every
    non-ASCII character as ``\\uXXXX``, so a self-key carrying one would never appear literally
    in the serialization and a sibling naming it in free text would slip the test silently.
    Today ``self_case_key`` is a run id ``_run_id.is_valid_run_id`` forces ASCII, so the two
    spellings coincide; pinning the encoder means a later widening of what a case id may
    contain cannot quietly reopen the leak.
    """
    return self_key in json.dumps(record, default=str, ensure_ascii=False)


def _screen_listing(
    deps: AgentDeps, payload: Any, opened_at: _dt.datetime | None,
) -> tuple[Any, int, str]:
    """Fork G + V-A + Fork H + Fork J: keep only genuinely-closed items that neither ARE nor
    NAME the self-case's record AND were last written before the case opened, per-item, before
    the envelope.

    The envelope shape check and the ``(payload, exit_code, detail)`` contract are the shared
    ticket screen (``runtime.ticket_screen``); bound here is the judge's own predicate, whose
    CLOSED-only half is the judge's alone — gather keeps every lifecycle state because it is
    correlating, not scoring. Duplicates survive (the screen is status + self-reference, never a
    dedup); a non-dict item is dropped as unreadable.

    The four conjuncts do not substitute for one another. Identity owes nothing to a
    serializer — it compares the record's own key value, so however ``_names_self_case`` renders
    a record the self-case's OWN entry is excluded. Free text is wider and is what catches a
    SIBLING naming the case. Recency is wider still and the only arm not depending on the case
    being NAMED at all. ``opened_at`` is ``None`` only when the store says the case has no
    ticket, in which case there is no boundary and the other three stand alone."""
    self_key = self_case_key(deps)
    return screen_list(
        payload,
        keep=lambda t: (
            t.get("status") == "closed"
            and t.get("key") != self_key
            and not _names_self_case(t, self_key)
            and (opened_at is None or _predates_case(t, opened_at))
        ),
    )


def _log_denial(run_dir: Path, *, verb: str, params: dict) -> None:
    """The fixed `POLICY_DENIALS` stream under the JUDGE's own run dir, opened lazily (a run
    with nothing denied must leave no such file) and owned per RUN DIR rather than per built
    stage — `RequestLogger` refuses a second open of a path it already holds, so a per-stage
    writer turns a second stage's first denial into an uncaught `FileExistsError`."""
    observe.denial_logger(run_dir).log_policy_denial(
        role="judge", system=SYSTEM, verb=verb, call_id=f"{SYSTEM}.{verb}", params=params,
    )


async def _grant_gate(
    deps: AgentDeps, verbs: Any, lock: asyncio.Lock, verb: str,
) -> str | None:
    """THE grant decision, ahead of every one of the judge site's own screens (key grammar,
    key schema, self-case-key) — the runtime's own ordering, mirrored at this second
    model-facing site.

    A fault RESOLVING the verb (``decide()`` importing a broken adapter to check its declared
    class) faults-and-continues like any other resolution fault — a row, an infra breaker
    contribution, no unwind out of ``agent.iter()`` — rather than propagating out uncaught."""
    try:
        decision = verbs.decide(SYSTEM, verb)
    except CONTROL_FLOW_EXCEPTIONS:
        raise
    except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
        raise
    except BaseException as e:  # noqa: BLE001 — the registry could not resolve this verb
        return await _capture_and_view(
            deps, lock, verb, {}, None, _fault_exit(e), str(e) or type(e).__name__,
        )
    if decision.outcome == DENIED:
        _log_denial(deps.run_dir, verb=verb, params={})
        return _format_bash_result(
            DEFAULT_FAULT_EXIT, "", wrap_fresh(decision.refusal or "", "untrusted"), "",
        )
    if decision.outcome != GRANTED:
        return _format_bash_result(
            DEFAULT_FAULT_EXIT, "",
            wrap_fresh(decision.refusal or f"unresolvable: {SYSTEM}.{verb}", "untrusted"),
            "",
        )
    return None


async def _list_body(deps: AgentDeps, lock: asyncio.Lock, verbs: Any,
                     label: str | None, q: str | None) -> str:
    """``list_closed_tickets`` end-to-end: honor the breaker, drive the verb closed-only,
    re-check each returned item client-side (Fork G/V-A/J), then capture + view."""
    if circuit_breaker.is_tripped(deps.run_dir, SYSTEM):
        return circuit_breaker.down_message(deps.run_dir, SYSTEM)
    opened_at, boundary_exit, boundary_detail = await _case_opened_at(deps, verbs)
    if boundary_exit != 0:
        # No boundary, no listing — and the row is filed under the verb that actually ran and
        # FAILED: the store was never asked for precedent, so a row naming `list-tickets`
        # would put an attempt that never happened into the trail evidencing what was.
        return await _capture_and_view(
            deps, lock, _CASE_OPENED_VERB, {}, None, boundary_exit, boundary_detail,
        )
    payload, exit_code, detail = await _run_verb(
        deps, verbs, "list-tickets", {"label": label, "q": q, "require_closed": True},
    )
    if exit_code == 0:
        payload, exit_code, detail = _screen_listing(deps, payload, opened_at)
    return await _capture_and_view(
        deps, lock, "list-tickets", {"label": label, "q": q}, payload, exit_code, detail,
    )


async def _get_body(deps: AgentDeps, lock: asyncio.Lock, verbs: Any, key: str) -> str:
    """``get_closed_ticket`` end-to-end: honor the breaker, resolve the environment's key
    grammar (fail closed if it is missing), screen the key against it (Fork A) and against the
    self-case's own key (Fork C), resolve the case-opened boundary (fail closed if the store
    cannot supply it), drive the verb closed-only, screen a self-key-naming or
    written-after-the-case payload (Fork H/J), then capture + view."""
    if circuit_breaker.is_tripped(deps.run_dir, SYSTEM):
        return circuit_breaker.down_message(deps.run_dir, SYSTEM)
    grammar, cfg_exit, cfg_detail = await _key_grammar(deps, verbs)
    if grammar is None:
        # No grammar, no read: the screen cannot run, so the store is never asked. The row and
        # the breaker contribution make that refusal loud — filed under the verb that actually
        # ran and FAILED (`key-pattern`, no params). Filing it as a `get-ticket` carrying the
        # model's key would put a store attempt that never happened into the audit trail that
        # EVIDENCES zero store attempts, and land an unscreened key in the queries table.
        return await _capture_and_view(
            deps, lock, _KEY_PATTERN_VERB, {}, None, cfg_exit, cfg_detail,
        )
    reason = _key_reject_reason(key, grammar)
    if reason is not None:
        raise ModelRetry(reason)
    if key == self_case_key(deps):
        raise ModelRetry(
            "that key is the in-flight ticket for the case you are scoring — it is the answer "
            "key, never readable through this confirm. Cite a past CLOSED case."
        )
    opened_at, boundary_exit, boundary_detail = await _case_opened_at(deps, verbs)
    if boundary_exit != 0:
        return await _capture_and_view(
            deps, lock, _CASE_OPENED_VERB, {}, None, boundary_exit, boundary_detail,
        )
    payload, exit_code, detail = await _run_verb(
        deps, verbs, "get-ticket", {"key": key, "require_closed": True},
    )
    if exit_code == 0:
        payload, exit_code, detail = _screen_fetched_ticket(deps, payload, opened_at)
    return await _capture_and_view(
        deps, lock, "get-ticket", {"key": key}, payload, exit_code, detail,
    )


def _screen_fetched_ticket(
    deps: AgentDeps, payload: Any, opened_at: _dt.datetime | None,
) -> tuple[Any, int, str]:
    """A successfully-fetched ``get`` payload → its (payload, exit_code, detail): a non-object
    body is a malformed infra fault, and a genuinely-closed ticket whose free text NAMES the
    case's own key is withheld (Fork H — a business refusal, so it never trips the breaker; the
    one transitive answer-key path whose identifier this seam knows).

    Where ``list`` drops such an item and serves the rest, ``get`` has a single record to answer
    with, so the whole read fails — under the distinguishable policy code, which is what buys the
    audit trail its withhold-vs-404 split. The recency arm (Fork J) rides the SAME withhold, so a
    confirm and a listing cannot answer differently about one record."""
    self_key = self_case_key(deps)

    def _withhold(ticket: dict[str, Any]) -> str | None:
        if _names_self_case(ticket, self_key):
            return (
                "the fetched ticket references the case under judgment; its content is "
                "withheld to keep the answer key unreadable."
            )
        if opened_at is not None and not _predates_case(ticket, opened_at):
            return (
                "that ticket was last written after the case you are scoring was opened, so "
                "it cannot be precedent for it — its content is withheld. Cite a case closed "
                "before this one began."
            )
        return None

    return screen_get(payload, withhold=_withhold)


def register_closed_ticket_tools(agent: Any, verbs: Any) -> None:
    """Register the two closed-ticket tools on ``agent``, in the fixed tail order the e2e suite
    pins — ``list_closed_tickets`` then ``get_closed_ticket``. ``verbs`` (the ticket verb
    registry) is required, so a def declaring the bit with no registry fails LOUD at build."""
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
        get_closed_ticket. Only cases already closed BEFORE the alert you are scoring was
        opened are returned: the in-flight ticket is never returned, and neither is anything
        written while this case was live."""
        refusal = await _grant_gate(ctx.deps, verbs, seq_lock, "list-tickets")
        if refusal is not None:
            return refusal
        return await _list_body(ctx.deps, seq_lock, verbs, label, q)

    @agent.tool
    async def get_closed_ticket(ctx: RunContext[Any], key: str) -> str:
        """Confirm one CITED closed past case by its case id `key` (closed-only, by
        construction — a non-closed or missing ticket refuses). Never returns the open
        in-flight ticket for the alert you are scoring, nor a ticket last written after that
        alert was opened. A cited seed the store can't confirm,
        or whose grounded conditions these actuals contradict, does not survive on that basis."""
        refusal = await _grant_gate(ctx.deps, verbs, seq_lock, "get-ticket")
        if refusal is not None:
            return refusal
        return await _get_body(ctx.deps, seq_lock, verbs, key)


__all__ = ["TOOL_GET", "TOOL_LIST", "register_closed_ticket_tools"]
