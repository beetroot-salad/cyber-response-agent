"""Harness-executed lead-0 (#808).

Before MAIN's first ORIENT turn, the runtime (item 1) resolves the alert's ancestor
documents and (item 2 -- SKIPPED, an explicit non-obligation, #808) and (item 3) dispatches
one tightly-bounded correlation gather lead, both writing into the run's leads/queries
tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and the review gate
cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch item 1/item 3 add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender._io import read_jsonl_rows, read_text_soft
from defender._run_paths import RunPaths
from defender._untrusted import wrap as _wrap
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
    read_budget,
    tail_exhausted,
    update_budget_locked,
)
from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime import circuit_breaker
from defender.runtime.verb_grant import GrantError, VerbGrant
from defender.runtime.verbs import VerbContext

# ─── the names this spec mints on the production side ───────────────────────────────────
L0 = "l-000"
L3 = "l-00c"
RESERVED_LEAD_IDS = (L0, L3)
CORRELATION_REQUEST_LIMIT = 8

#: Item 3's grant, hoisted to module scope so it is the SINGLE authored home for the vendor
#: name on the correlation path (#808 follow-up). `dispatch_correlation` used to build this
#: inline and then hardcode `"elastic"` a second and third time — in `GatherRequest` and in
#: the `:L findings` row — which made the dispatched system a literal that could drift away
#: from the grant that actually confines the lead. `CORRELATION_SYSTEM` derives from the
#: grant instead, so the two cannot disagree: the grant is already the authority (it is what
#: `decide` consults), and `system` is only ever a rendering/routing key.
CORRELATION_GRANT = VerbGrant(
    role="lead-zero-correlation",
    entries=(("elastic", "alerts", "r"), ("elastic", "health-check", "r")),
)

#: The catalog template item 3's contract names outright. It exists because the grant admits
#: exactly one query verb (`alerts`) and, before it was authored, the catalog held ZERO
#: templates binding that verb — every elastic template is `esql` or `query`, so grant ∩
#: catalog was empty by construction and the dispatch rendered `_INDEX_NONE_GRANTED`. A lead
#: told only that nothing is runnable spends its whole budget discovering why.
CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"


def _sole_system(grant: VerbGrant) -> str:
    """The one system a single-system grant reaches. Raises rather than picking, because a
    two-system correlation grant is an authoring change whose dispatched-system choice must be
    made deliberately (it selects the template index's on-target tier and the prompt-cache
    lane), not silently resolved by `sorted(...)[0]` at run time."""
    systems = sorted(grant.systems)
    if len(systems) != 1:
        raise GrantError(
            f"the correlation grant for role {grant.role!r} reaches {len(systems)} systems "
            f"({systems}) — `system` is derived from it and only a single-system grant "
            "determines one. Name the dispatched system explicitly if this is intended."
        )
    return systems[0]


CORRELATION_SYSTEM = _sole_system(CORRELATION_GRANT)

#: Item 1's OWN system, and deliberately not `CORRELATION_SYSTEM`. Every backend call item 1
#: issues names this string directly — `_capture_issue`'s `args`, `_record_manual_row`'s row +
#: `query_id` + `raw_command`, `_breaker_failures`' per-system state read, `_CallLedger.call`'s
#: registry lookup — so its `:L findings` row must be labelled from the SAME anchor those calls
#: use. Labelling it from the correlation grant's derived system reads as a dedup while the two
#: are the same string, and mislabels item 1's row the moment `CORRELATION_GRANT` names a
#: different vendor: the row would say one system while the queries it joins say another.
ITEM1_SYSTEM = "elastic"

PROVENANCE_KEY = "provenance"
HARNESS_PROVENANCE = "harness"

LEAD_ZERO_HEADING = "## Alert ancestors"

STATUS_FAILED = "failed"
STATUS_EMPTY = "succeeded-empty"
STATUS_TRUNCATED = "succeeded-truncated"
#: Every requested ancestor document resolved. Named `STATUS_WITH_ENTITIES` until #867, which
#: is the name lying about its own arm: the status block below derives this value from
#: `saw_success` / `docs` / `requested` and has never consulted an extracted entity at all. The
#: gate in `prepare_correlation_lead` reads it as "item 1 resolved documents" and always did —
#: #867 deletes the extraction without touching that gate, because the predicate was already
#: the right one.
STATUS_RESOLVED = "succeeded-resolved"

UNAVAILABLE = "_(unavailable:"
SHORTFALL = "_(incomplete:"
ELIDED = "_(elided:"

#: The per-document `message` rendering budget (K17). Any value that keeps the block
#: materially smaller than a large payload satisfies the demand; no magic number is
#: mandated by the spec.
MESSAGE_CHAR_BUDGET = 4000

ALERT_ID_FIELD = "kibana.alert.uuid"
GROUP_ID_FIELD = "kibana.alert.group.id"
BUILDING_BLOCK_FIELD = "kibana.alert.building_block_type"

ITEM1_GOAL = (
    "Resolve this alert's ancestor documents (the constituent events of its EQL sequence, "
    "or the ancestor_events batch) so MAIN has their timestamp/message/structured fields at "
    "ORIENT without spending a lead or a gather round on it."
)
ITEM1_WHAT_TO_SUMMARIZE = [
    "each resolved ancestor document's timestamp, message and structured fields",
]

_ANY_RUN_TAG = re.compile(r"</?run-[0-9a-zA-Z]*-[a-z-]+>")
#: A markdown code-fence run. Neutralized for the same reason as the wrap delimiter, and
#: since #867 for a second one: item 1's rendered block is interpolated into item 3's goal,
#: which `tools_gather._gather_prompt` emits INSIDE a fenced block. A fence run in an
#: attacker-authored `message` (a captured command line, a shell transcript) closes that fence
#: early, so the harness's own `what_to_summarize` block renders as free prose the lead reads
#: as document content.
_FENCE_RUN = re.compile(r"`{3,}")


# ─── the return contract (F1) ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LeadZeroResult:
    """#867 retired the third field. It was `entities: Entities` — a `host.name`/`user.name`/
    `source.ip` triple extracted from the resolved documents by the harness and interpolated
    into item 3's contract. A fixed field list is the right shape for exactly one class of
    alert source (host-level auth logs, where those three fields are the activity) and produces
    noise on any source that carries its entities elsewhere: a container-runtime source names
    every alert with the shared host the runtime itself runs on, nests the real actor under a
    vendor-specific field namespace the extractor never reads, and has no source address at
    all. Which entities matter is a property of the alert, not of a schema.

    Nothing typed replaced it. `text` — item 1's rendered block, already sanitized, elided and
    wrapped — IS what item 3's contract now carries, so the correlation lead reads the same
    bytes MAIN reads at ORIENT and picks its own correlation axes off them. Choosing what to
    filter on is what every other gather lead already does; `l-00c` was the only lead in this
    tree handed a predicate it could not inspect."""

    text: str
    status: str


# ─── small sync/async bridge ─────────────────────────────────────────────────────────────

def _run_sync(coro: Any) -> Any:
    """Run an async coroutine from a SYNCHRONOUS caller, whether or not an event loop is
    already running on this thread. `resolve_lead_zero` is a synchronous entry point
    (r9/r10) called both from bare pytest functions (no loop) and from inside
    `run_investigation` (already inside a running loop) — the latter cannot call
    `asyncio.run()` directly, so it hands the coroutine to a fresh thread with its own loop
    instead."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


# ─── sanitizing wrap-delimiter shapes (K1 round 2 + F4) ─────────────────────────────────

def _sanitize(text: Any) -> str:
    """Neutralize any `<run-…-…>`-shaped delimiter, and any markdown code-fence run, in
    externally-sourced content BEFORE it is wrapped or interpolated. `wrap()` performs no
    escaping of its own delimiter shape, so an attacker-authored `message`/`user.name`/
    `source.ip` carrying a byte-exact close tag would otherwise end the untrusted frame (or
    item 3's contract) early; a ``` run would likewise end the fenced block whichever
    consumer put the text inside one.

    DEFANGED, NEVER DELETED — the same rule both surfaces' tests assert: the evidence has to
    survive in a form the reader can still see, or the sanitizer passes by destroying what it
    was protecting."""
    if not isinstance(text, str):
        text = str(text)
    text = _ANY_RUN_TAG.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
    return _FENCE_RUN.sub(lambda m: "ˋ" * len(m.group(0)), text)


# ─── deps for routing through the real QueryCapture (K7/d10) ────────────────────────────

@dataclass(frozen=True)
class _CaptureDeps:
    run_dir: Path
    defender_dir: Path
    salt: str
    run_id: str
    lead_id: str
    box: Any = None
    budget_started_monotonic: float = 0.0


def _rows_for(run_dir: Path, lead_id: str) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead_id]


def _last_row_seq(run_dir: Path, lead_id: str) -> int:
    """The queries-table `seq` the LAST call under `lead_id` wrote — the payload sidecar a
    document resolved by that call is elided against (#867 review fix).

    Item 1 issues several calls and one batched call returns many documents, so a document's
    position in the rendered block is not its payload's seq. The block used to print the
    position: with four documents off one fetch, the first pointed at the SHELL fetch's payload
    and the last two at `gather_raw/l-000/{2,3}.json`, files no writer ever produced. `-1` when
    no row exists (a screened call, or a table write that could not land)."""
    rows = _rows_for(run_dir, lead_id)
    seq = rows[-1].get("seq") if rows else None
    return seq if isinstance(seq, int) else -1


async def _capture_issue(
    capture: Any, deps: _CaptureDeps, verb: str, params: dict, env: dict,
) -> tuple[dict | None, str]:
    """Issue ONE call through the REAL `QueryCapture.wrap_tool_execute` — the model's own
    routing (K7/d10): all eight screens (grant, breaker, repeat-guard, traversal, param
    validation, self-ticket, confine_index, guard_outbound) run exactly as they do for a
    model-dispatched query.

    Returns `(envelope_or_None, raw_result_text)`. `None` covers both "screened" (breaker
    trip, repeat trip, grant denial — no row written at all) and "attempted but failed"
    (a row IS written, with a nonzero exit code)."""
    before = len(_rows_for(deps.run_dir, deps.lead_id))
    call = SimpleNamespace(tool_name="query")
    args = {"system": ITEM1_SYSTEM, "verb": verb, "params": params}
    # #808 review fix — stash the in-memory result as `handler` produces it, so a later
    # write failure (below) can recover it WITHOUT re-issuing the same backend call a
    # second time. `wrap_tool_execute` runs `handler` at most once per call.
    captured: list[Any] = []

    async def handler(_args: dict) -> Any:
        fn = capture._registry.verbs(ITEM1_SYSTEM)[verb]
        vctx = VerbContext(defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=env)
        result = await asyncio.to_thread(fn, vctx, **params)
        captured.append(result)
        return result

    ctx = SimpleNamespace(deps=deps)
    try:
        text = await capture.wrap_tool_execute(ctx, call=call, args=args, handler=handler)
    except (OSError, ValueError):
        # K8(iii)/d62 — RENDER FROM THE IN-MEMORY RESULT: a queries-table write that cannot
        # land (a directory squatting the table's own name) must cost the run its evidence
        # ROW, never its evidence — and (review fix) never a second real backend call for
        # the same logical fetch: `captured` already holds whatever `handler` returned
        # before `QueryCapture._record`'s write raised.
        envelope = captured[0] if captured else None
        return (envelope if isinstance(envelope, dict) else None), ""
    after = _rows_for(deps.run_dir, deps.lead_id)
    if len(after) <= before:
        return None, text
    row = after[-1]
    if row.get("exit_code") != 0:
        return None, text
    payload_path = row.get("payload_path")
    if not isinstance(payload_path, str):
        # #808 review fix — a successful call (exit_code == 0) whose sidecar payload
        # failed to PERSIST (a disk-full/permission fault on the write, distinct from the
        # write-failure branch above) leaves `payload_path` None; falling back to the
        # in-memory result this same call already produced beats crashing on
        # `Path(...) / None`.
        envelope = captured[0] if captured else None
        return (envelope if isinstance(envelope, dict) else None), text
    try:
        data = json.loads((deps.run_dir / payload_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, text
    if not isinstance(data, dict):
        return None, text
    return data, text


#: The capped path's own default exit code for an UNMAPPED fault — mirrors
#: `query_tool.DEFAULT_FAULT_EXIT` (not imported directly: that module's constant is an
#: internal implementation detail of the model-facing capture, not a shared contract).
_UNMAPPED_FAULT_EXIT = 2


def _record_manual_row(
    deps: _CaptureDeps, verb: str, params: dict, payload: Any, *, exit_code: int,
) -> None:
    """Write a queries-table row with the SAME thirteen-key shape `QueryCapture._record`
    writes — including `error_class`/`payload_status` derived the SAME way
    (`circuit_breaker.error_class_for_exit`, `query_tool._payload_status`'s own rule), not
    hardcoded (#808 review fix: a hardcoded `error_class="infra"` mis-filed a genuinely
    agent-fixable capped-path fault out of `lead_extraction.collect_general_failures`'
    pitfalls curation) — WITHOUT feeding `circuit_breaker.record_outcome` — the mechanism
    that lets item 1's own calls PAST its first recorded failure keep running (`d63`)
    without letting the breaker's per-system counter cross the trip boundary on lead-0's
    behalf (`d61`, K8(ii)/R2-F1: the cap bounds RECORDED failures, not calls)."""
    import shlex

    from defender._io import guarded_mkdir, write_guarded
    from defender.runtime.circuit_breaker import error_class_for_exit
    from defender.scripts.gather_tools.record_query import (
        _json_safe_params,
        _next_seq,
        payload_digest,
        payload_sha256,
    )

    seq = _next_seq(deps.run_dir, deps.lead_id)
    lead_dir = RunPaths(deps.run_dir).gather_raw / deps.lead_id
    payload_name = f"gather_raw/{deps.lead_id}/{seq}.json"
    payload_rel: str | None = payload_name
    text = json.dumps(payload, default=str) if exit_code == 0 else ""
    try:
        guarded_mkdir(lead_dir, base=deps.run_dir)
        write_guarded(deps.run_dir / payload_name, text)
    except (OSError, ValueError):
        payload_rel = None
    if exit_code != 0:
        payload_status = "error"
    elif payload is None or (isinstance(payload, (dict, list, tuple, set, str)) and len(payload) == 0):
        payload_status = "empty"
    else:
        payload_status = "ok"
    row = {
        "lead_id": deps.lead_id, "seq": seq, "system": ITEM1_SYSTEM, "verb": verb,
        "query_id": f"{ITEM1_SYSTEM}.{verb}", "params": _json_safe_params(dict(params)),
        "raw_command": shlex.join(
            [ITEM1_SYSTEM, verb, *(f"{k}={v}" for k, v in params.items())]
        ),
        "payload_path": payload_rel, "exit_code": exit_code,
        "error_class": error_class_for_exit(exit_code),
        "payload_status": payload_status,
        "payload_digest": (
            payload_digest(text, "", 0) if exit_code == 0 else f"exit={exit_code}; capped"
        ),
        # Over the SAME text the sidecar above holds — the content identity `repeat_note`
        # keys byte-identity on (#877 F-9), derived here rather than defaulted so this second
        # writer's rows can never read as "no payload evidence" beside `_record`'s.
        "payload_sha256": payload_sha256(text),
    }
    write_guarded(RunPaths(deps.run_dir).executed_queries, json.dumps(row) + "\n", mode="append")


def _breaker_failures(run_dir: Path) -> int:
    path = Path(run_dir) / "circuit_breaker.json"
    if not path.is_file():
        return 0
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    # #808 review fix — `3`, `"x"` and `[…]` are all valid JSON and none of them is a
    # breaker state (the same "parsed fine, wrong shape" case `circuit_breaker._load`
    # guards explicitly); without these isinstance checks a corrupted or adversarially
    # planted `circuit_breaker.json` raises `AttributeError`/`ValueError` here, uncaught,
    # degrading item 1's WHOLE resolution instead of just this one state read.
    if not isinstance(state, dict):
        return 0
    systems = state.get("systems")
    if not isinstance(systems, dict):
        return 0
    sysrec = systems.get(ITEM1_SYSTEM)
    if not isinstance(sysrec, dict):
        return 0
    try:
        return int(sysrec.get("failures", 0) or 0)
    except (TypeError, ValueError):
        return 0


class _CallLedger:
    """Tracks item 1's OWN contribution to the elastic per-system breaker across a
    resolution, so a second (and later) infra failure can still be ISSUED (`d63`,
    fall-through on every fault class) without being RECORDED past the cap (`d61`)."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.capped = False

    async def call(self, capture, deps, verb, params, env):
        from defender.scripts.adapters.faults import AdapterFault

        before = _breaker_failures(self.run_dir)
        if self.capped:
            # Past the cap: issue the call directly (bypassing QueryCapture's own automatic
            # `record_outcome`), still writing a queries-table row of the same shape.
            try:
                fn = capture._registry.verbs(ITEM1_SYSTEM)[verb]
                vctx = VerbContext(defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=env)
                envelope = await asyncio.to_thread(fn, vctx, **params)
                _record_manual_row(deps, verb, params, envelope, exit_code=0)
                return envelope, ""
            except (circuit_breaker.RunAborted, asyncio.CancelledError,
                    KeyboardInterrupt, GeneratorExit):
                # #808 review fix — cancellation/control-flow signals must propagate, not be
                # absorbed as "a capped call's own fault": swallowing `CancelledError` here
                # breaks task cancellation (the caller's `task.cancel()` would silently do
                # nothing) and `KeyboardInterrupt`/`GeneratorExit` are never a query's own
                # fault to begin with.
                raise
            except AdapterFault as e:
                # #808 review fix — a MAPPED fault keeps its own exit code/class (matching
                # `QueryCapture._record`'s own `except AdapterFault` arm) instead of always
                # being filed as `error_class="infra"`.
                _record_manual_row(deps, verb, params, None, exit_code=e.exit_code)
                return None, ""
            except BaseException:  # noqa: BLE001 — an unmapped capped-call fault must not raise
                _record_manual_row(deps, verb, params, None, exit_code=_UNMAPPED_FAULT_EXIT)
                return None, ""
        envelope, text = await _capture_issue(capture, deps, verb, params, env)
        after = _breaker_failures(self.run_dir)
        if after > before:
            self.capped = True
        return envelope, text


def _build_deps(run_dir: Path, defender_dir: Path, salt: str, run_id: str, lead_id: str) -> _CaptureDeps:
    return _CaptureDeps(
        run_dir=run_dir, defender_dir=defender_dir, salt=salt, run_id=run_id, lead_id=lead_id,
    )


# ─── budget chaining (K23) ────────────────────────────────────────────────────────────

def _budget_gate(run_dir: Path, limits: dict) -> None:
    """Unconditional (not gated on `DEFENDER_BUDGET_ENFORCE`): lead-0 is harness pre-turn
    work, and its own wall-clock discipline is not a product toggle the way the model's own
    tool refusals are."""
    state = read_budget(run_dir)
    if tail_exhausted(state, limits):
        raise BudgetKill("lead-0's own call refused: the run's budget tail is exhausted")


def _budget_account(run_dir: Path, run_id: str, tool_name: str, limits: dict) -> None:
    import contextlib

    with contextlib.suppress(Exception):  # accounting must never break the run
        update_budget_locked(run_dir, run_id, tool_name, limits=limits)


# ─── item 1 rendering ─────────────────────────────────────────────────────────────────

def _elide(value: Any, lead_id: str, seq: int) -> str:
    """Bound ONE rendered leaf, with a pointer to the payload that holds it whole.

    `seq` is the QUERIES-TABLE seq of the call that returned the document (`_last_row_seq`),
    never the document's position in the block — those are different numbers and the block
    used to print the second (#867 review fix). A negative `seq` means the call wrote no row
    at all (screened, or the table write failed), and the note then says so rather than naming
    a payload that was never persisted."""
    if not isinstance(value, str) or len(value) <= MESSAGE_CHAR_BUDGET:
        return value if isinstance(value, str) else str(value)
    where = (
        f", full text at gather_raw/{lead_id}/{seq}.json"
        if seq >= 0 else ", and the call that returned it persisted no payload"
    )
    return f"{value[:MESSAGE_CHAR_BUDGET]}\n{ELIDED} {len(value)} chars{where})"


def _flatten_doc(doc: dict) -> dict[str, Any]:
    """A document's leaves, keyed by their DOTTED ECS path.

    #867 review fix. The adapter hands `_source` back UNMODIFIED, and real ECS `_source` is
    NESTED (`{"host": {"name": …}}`, and a per-source namespace nests its own actor two or
    three levels deeper) while the alerting namespace and this suite's test doubles arrive as
    flat dotted keys. Rendering the top level alone printed a nested document as one line per
    top-level object holding a PYTHON DICT REPR — `host: {'name': 'ws-1'}` — which is not a
    field name anything can be queried on.

    That was survivable while the harness extracted the entities itself (the retired
    `_ecs_field` read both shapes). It stopped being survivable when #867 made this block
    the correlation lead's whole entity evidence and asked it to name "the field each came
    from": on production-shaped documents the lead had to reverse-engineer a dotted path out
    of a repr, and the very source class the change exists for is the one that nests."""
    out: dict[str, Any] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict) and node:
            for k, v in node.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                walk(v, key)
        elif isinstance(node, list) and any(isinstance(x, dict) for x in node):
            # An ARRAY OF OBJECTS is the same defect one level down, and it is not exotic:
            # every Kibana alert document carries `kibana.alert.ancestors`, and on the group-id
            # path the documents this block renders ARE alert documents. Rendering the array
            # whole prints `[{'id': …, 'index': …}]` — a Python repr, not a field name anything
            # can be queried on. Indexed (`…ancestors.0.id`) so two elements' same-named leaves
            # stay distinguishable; an array of SCALARS stays whole, since `['a', 'b']` already
            # reads as the multi-valued field it is.
            for i, item in enumerate(node):
                walk(item, f"{prefix}.{i}" if prefix else str(i))
        elif prefix:
            out[prefix] = node

    walk(doc, "")
    return out


def _render_doc(doc: dict, lead_id: str, seq: int) -> str:
    flat = _flatten_doc(doc)
    lines = []
    ts = flat.get("@timestamp")
    if ts:
        lines.append(f"- @timestamp: {_sanitize(ts)}")
    for key in sorted(flat):
        if key in ("@timestamp", "message"):
            continue
        # A null leaf is DROPPED, not rendered (#867 review fix). `_sanitize(None)` is the
        # literal string `"None"`, and this block is now what the correlation lead picks its
        # correlation axes off — `host.name: None` reads as a bindable value and invites
        # `host.name:"None"`, a predicate that matches nothing and reports as a real zero.
        # An absent field and a null one are the same thing to the index anyway.
        if flat[key] is None:
            continue
        # #808 review fix — the field NAME, not just its value, must be neutralized: an
        # attacker-influenced document whose key itself carries a `<run-…-…>`-shaped
        # delimiter would otherwise end the untrusted frame early, exactly the class of
        # forgery this module's value-side `_sanitize` calls already exist to close.
        #
        # EVERY leaf is elided, not just `message` (#867 review fix). The rendering budget was
        # written when a nested object rendered as ONE line, so `message` was the only leaf that
        # could be large; flattening makes every leaf of every namespace its own line, and a
        # captured command line or a rule's stored query is exactly as unbounded as a message.
        lines.append(f"  {_sanitize(key)}: {_sanitize(_elide(flat[key], lead_id, seq))}")
    if flat.get("message") is not None:
        lines.append(f"  message: {_sanitize(_elide(flat['message'], lead_id, seq))}")
    return "\n".join(lines)


def _sort_chrono(docs: list[tuple[dict, int]]) -> list[tuple[dict, int]]:
    """Chronological by each document's own `@timestamp`. Each entry is `(doc, seq)` — the
    queries-table seq of the call that returned it, which the elision pointer names."""
    def key(entry: tuple[dict, int]) -> str:
        return str(entry[0].get("@timestamp") or "")
    return sorted(docs, key=key)


def _unavailable(reason: str) -> str:
    """#867 review fix — the reason is SANITIZED. `_unavailable(f"{e!r}")` interpolates the repr
    of an exception whose message can carry attacker-influenced text (this suite's own `d13`
    docstring says exactly that), and the note lands INSIDE `wrap()`'s frame with everything
    else — the one text path into item 1's frame the module's threat model covers and its code
    did not."""
    return f"{UNAVAILABLE} {_sanitize(reason)})"


# ─── item 1: ancestor resolution ─────────────────────────────────────────────────────

_DS_RE = re.compile(r"^\.ds-(?P<name>.+)-[^-]+-\d{4}\.\d{2}\.\d{2}-\d+$")


def _map_backing_index(index: str) -> str:
    """K2 — an open, bounded rewrite from a concrete `.ds-<name>-<namespace>-<date>-
    <generation>` backing index to the datastream pattern it belongs to, never a hardcoded
    substring table. A no-match passes the string through UNCHANGED so `confine_index`'s own
    gate refuses it."""
    if not isinstance(index, str):
        return index
    m = _DS_RE.match(index)
    if not m:
        return index
    return f"{m.group('name')}-*"


async def _fetch_batched(ancestors: list[dict], issue) -> tuple[list[tuple[dict, int]], int, bool]:
    """Batch ancestor ids by MAPPED backing index — one call per distinct index, never one
    per ancestor (d5). Returns `(docs, requested_count, truncated_any)` where each doc is
    paired with the queries-table `seq` of the call that returned it (#867 review fix — the
    elision pointer's target); `issue` is the caller's own budget-gated, success-tracking call
    wrapper, which returns `(envelope, seq)` and is told whether this call could produce an
    ancestor at all (#880 F-14)."""
    by_index: dict[str, list[str]] = {}
    for a in ancestors:
        aid = a.get("id")
        idx = a.get("index")
        if not isinstance(aid, str) or not aid.strip():
            continue
        if not isinstance(idx, str) or not idx.strip():
            continue
        mapped = _map_backing_index(idx)
        by_index.setdefault(mapped, []).append(aid)

    if not by_index:
        return [], 0, False

    docs: list[tuple[dict, int]] = []
    truncated_any = False
    for mapped_index, ids in sorted(by_index.items()):
        predicate = " OR ".join(f'"{i}"' for i in ids)
        params = {"native_query": f"_id: ({predicate})", "limit": 20,
                  "index": mapped_index, "sort": "desc"}
        envelope, seq = await issue("query", params, ancestor=True)
        if envelope is None:
            continue
        docs.extend((h, seq) for h in (envelope.get("hits") or []))
        truncated_any = truncated_any or bool(envelope.get("truncated"))
    return docs, sum(len(v) for v in by_index.values()), truncated_any


async def _resolve_item1(  # noqa: C901, PLR0912, PLR0915 — item 1's own branch/call census: the shell fetch, the group/fallback branch, the empty/no-group fallback, per-call budget gating — see the module docstring
    *, run_dir: Path, defender_dir: Path, salt: str, run_id: str, alert: dict,
    capture: Any, env: dict, limits: dict,
) -> tuple[str, str]:
    from defender.scripts.adapters.elastic_adapter import load_config

    deps = _build_deps(run_dir, defender_dir, salt, run_id, L0)
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L0, "goal": ITEM1_GOAL,
        "what_to_summarize": ITEM1_WHAT_TO_SUMMARIZE, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # #808 review fix — someone else already owns L0 (a planted collision, the exact
        # shape `test_a_harness_side_reclaim_takes_claim_leads_return_two_arm` exercises
        # for L3): degrade rather than issue backend calls or append a second, inconsistent
        # `:L findings` row under an id this call does not own. Mirrors
        # `prepare_correlation_lead`'s own L3 collision arm — previously item 1 discarded
        # `claim_lead`'s return value entirely and proceeded regardless.
        #
        # `!= CLAIMED` and not `== ALREADY_CLAIMED` (#855 F-12): a claim that could not be
        # WRITTEN leaves this frame owning exactly as little as a collision does, and the
        # harness has no more right than the model to run a lead with no leads row.
        return (_unavailable(
            f"{L0} is already claimed by something else on this run dir"
            if claimed == ALREADY_CLAIMED else f"{L0}'s leads row could not be claimed"
        ), STATUS_FAILED)
    _declare_l_finding(run_dir, L0, "ancestor resolution", ITEM1_SYSTEM)

    alert_id = alert.get("alert_id")
    signal_index = alert.get("signal_index")
    if not isinstance(signal_index, str) or not signal_index.strip():
        try:
            cfg = load_config(VerbContext(defender_dir=defender_dir, run_dir=run_dir, env=env))
            signal_index = cfg["ELASTIC_ALERTS_INDEX"]
        except Exception:  # noqa: BLE001 — degrade the whole item, never the run
            return (_unavailable("could not resolve this alert's signal_index"),
                    STATUS_FAILED)

    ancestor_events = alert.get("ancestor_events") or []
    if not isinstance(ancestor_events, list):
        ancestor_events = []

    ledger = _CallLedger(run_dir)
    issued_any = False
    answered_any = False
    ancestor_attempted = False
    ancestor_answered = False

    async def _issue(verb: str, params: dict, *, ancestor: bool) -> tuple[dict | None, int]:
        """`ancestor=False` marks a call that CANNOT produce an ancestor document — item 1's
        opening by-`alert_id` fetch of the alert's own shell, which resolves the alert and no
        ancestor.

        #880 F-14: one `saw_success` flag used to be set from every call, and both its readers
        spend it as "a call that could have resolved an ancestor reached the backend". The
        shell fetch answers on every alert with a resolvable `alert_id`, so it alone kept the
        flag true — `STATUS_FAILED` was unreachable however the ancestor calls ended, and an
        outage on them rendered as `_(unavailable: … found nothing)`: an absence of ancestors,
        which is triage evidence, asserted over a backend that never answered.

        `ancestor` has no default deliberately: the omitted discriminator is exactly what was
        wrong, and a call site added later that forgets it must not silently read as an
        ancestor call.

        `answered_any` is tracked beside it because "no ancestor call was made" is NOT by
        itself a resolved absence: when the shell fetch is the ONLY call and it failed, the
        group-id branch was never even reachable, so nothing was established — least of all
        that this alert has no ancestors."""
        nonlocal issued_any, answered_any, ancestor_attempted, ancestor_answered
        issued_any = True
        ancestor_attempted = ancestor_attempted or ancestor
        _budget_gate(run_dir, limits)
        envelope, _text = await ledger.call(capture, deps, verb, params, env)
        _budget_account(run_dir, run_id, "query", limits)
        if envelope is not None:
            answered_any = True
            if ancestor:
                ancestor_answered = True
        # The seq is read AFTER the call, off the row that call just wrote: a document's
        # elision pointer has to name the payload of the fetch that returned it, not its own
        # position in the block (#867 review fix).
        return envelope, _last_row_seq(run_dir, L0)

    shell: dict | None = None
    if isinstance(alert_id, str) and alert_id.strip():
        shell_envelope, _ = await _issue("alerts", {
            "native_query": f'{ALERT_ID_FIELD}:"{alert_id}"', "limit": 1,
            "index": signal_index, "sort": "desc",
        }, ancestor=False)
        if isinstance(shell_envelope, dict):
            hits = shell_envelope.get("hits") or []
            shell = hits[0] if hits else None

    group_id = shell.get(GROUP_ID_FIELD) if isinstance(shell, dict) else None
    docs: list[tuple[dict, int]] = []
    requested = len(ancestor_events)
    truncated = False

    if isinstance(group_id, str) and group_id.strip():
        envelope, group_seq = await _issue("alerts", {
            "native_query": f'{GROUP_ID_FIELD}:"{group_id}"', "limit": 20,
            "index": signal_index, "sort": "desc",
        }, ancestor=True)
        hits = [h for h in ((envelope or {}).get("hits") or []) if h.get(BUILDING_BLOCK_FIELD)]
        if hits:
            docs = [(h, group_seq) for h in hits]
            requested = max(requested, len(hits))
            truncated = bool((envelope or {}).get("truncated"))
        else:
            # F10 — no group, or a group resolving to zero building blocks: fall back.
            docs, requested2, truncated = await _fetch_batched(ancestor_events, _issue)
            requested = max(requested, requested2)
    else:
        docs, requested2, truncated = await _fetch_batched(ancestor_events, _issue)
        requested = max(requested, requested2)

    if not issued_any:
        return (_unavailable("no usable ancestor identifier or alert id survived — no "
                              "fetch was issued"), STATUS_EMPTY)

    docs = _sort_chrono(docs)

    body_lines = []
    if docs:
        for doc, seq in docs:
            body_lines.append(_render_doc(doc, L0, seq))
    elif ancestor_attempted and not ancestor_answered:
        # Reworded with the flag it now reads (#880 F-14). "every backend call this
        # resolution attempted failed" is itself false in the newly reachable case: the shell
        # fetch answered, and only the calls that could have produced an ancestor did not.
        body_lines.append(_unavailable(
            "every backend call that could have resolved an ancestor failed"))
    elif not answered_any:
        # No ancestor call was ISSUED and the only call this resolution made — the shell
        # fetch whose group id decides whether an ancestor branch exists at all — failed. The
        # original sentence, and it is the true one here: nothing answered, so the group
        # branch was never reachable and no absence was established. Splitting the flag
        # without this arm turns exactly this run into `_(unavailable: … found nothing)`, the
        # false claim over a silent backend F-14 exists to remove.
        body_lines.append(_unavailable("every backend call this resolution attempted failed"))
    else:
        # Either an ancestor call answered and matched nothing, or — the alert declaring no
        # usable ancestor and its shell answering with no group id — there was no ancestor
        # call to make. Both are a resolved absence, which is what this sentence says.
        body_lines.append(_unavailable("the resolution reached the backend and found nothing"))

    if requested and (len(docs) < requested or truncated):
        body_lines.append(
            f"{SHORTFALL} resolved {len(docs)} of {requested} requested ancestor "
            "document(s))"
        )

    text = "\n\n".join(body_lines)

    # FAILED when no call that could have contributed answered. `ancestor_attempted` guards
    # the ancestor half so an alert with nothing to ask for stays EMPTY (#880 F-14): a
    # resolution that issued no ancestor call has no failed call to report. The `answered_any`
    # half is what keeps a resolution whose SHELL FETCH was its only call, and failed, out of
    # EMPTY — it asked nothing further because the answer that would have told it what to ask
    # never came, which is a failure and not an absence.
    if not ancestor_answered and (ancestor_attempted or not answered_any):
        status = STATUS_FAILED
    elif not docs:
        status = STATUS_EMPTY
    elif requested and (len(docs) < requested or truncated):
        status = STATUS_TRUNCATED
    else:
        status = STATUS_RESOLVED

    return text, status


# ─── item 3: the correlation lead's harness-authored contract ───────────────────────────

def _correlation_contract(alert: dict, ancestor_block: str) -> tuple[str, list[str]] | None:
    """#867 — the contract carries item 1's RESOLVED DOCUMENTS and the lead chooses the
    correlation axes off them.

    It used to carry a `host.name`/`user.name`/`source.ip` triple the harness extracted, and
    the entity-emptiness arm that used to live here (return `None` when the triple came back
    empty) went with the extraction: what gates the dispatch is item 1 resolving documents,
    which `prepare_correlation_lead`'s status check already decides. `GatherRequest` carries
    `goal` and `what_to_summarize` and nothing else, so before this change the lead was asked
    to correlate on entities it had never seen — the only lead in this tree whose predicate was
    handed to it rather than written by it."""
    ts = alert.get("alert_timestamp")
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None

    goal = (
        "Correlate ANY signature of alert already on the SOC's radar for THIS alert's key "
        f"entities over a bounded window around {_sanitize(ts)}.\n\n"
        "The alert's resolved ancestor documents follow. Read them first and judge which "
        "entities actually discriminate this alert — the ones that would pick it out of the "
        "environment's traffic rather than match everything in it. A container id, a process "
        "name, a destination host named inside a command line, a file path, a user, a source "
        "IP are all candidates; which of them matter is a property of THIS alert, not a fixed "
        "list. Prefer an entity that is specific to the activity over one every document in "
        "the environment carries: a host name that names the shared VPS every containerized "
        "alert reports from selects the whole environment and measures nothing.\n\n"
        f"{ancestor_block}\n\n"
        "Search the alerts index ONLY (this is a correlation over prior alerts, not raw "
        "telemetry). Do not narrow to this alert's own rule. The documents above may NAME that "
        "rule — on a sequence alert they are themselves alert documents, carrying "
        "`kibana.alert.rule.*` — and it is still not an axis to bind: a different rule firing "
        "on the same entity is exactly the related behaviour this lead exists to surface, and "
        "narrowing to the signature that already fired is the one result guaranteed to teach "
        "nothing. Bind "
        f"`{CORRELATION_TEMPLATE}` — read it first: it is named by your grant-filtered template "
        "index, and it carries the window params and the substitutable entity filter this "
        "contract needs. Each count is the result envelope's `total`, which the `hits` cap does "
        "not bound — a `truncated` result still carries a complete count."
    )
    # Two COUNT dimensions, both answerable by ONE `alerts` call each (#867 adds a third line
    # that is not a count — see below). A different third — "whether any correlated alert is
    # already benign-explained" — was struck: `kibana.alert.workflow_status`
    # is `"open"` on every alert this environment produces (nothing in the environment's own
    # provisioning ever writes it), and the systems that could carry a benign explanation
    # (`ticket`, `change-mgmt`) are outside this lead's grant. It had exactly one possible
    # answer, so it bought no information and cost the lead a dimension it had to spend calls
    # failing to meet.
    #
    # "across any rule", not "same-signature": the goal above says do NOT narrow to this
    # alert's own rule, and the dimensions used to say "same-signature" — read literally, a
    # per-rule breakdown over the 8 installed rules is 8-16 `alerts` calls against a request
    # limit of 8, and the one verb that could group-by in a single call (`esql`) is exactly
    # what this lead's grant withholds for index confinement (g6/r19). The contract now asks
    # for what the granted verb can actually return.
    #
    # Each dimension names its ENTITY SCOPE. "on-host"/"fleet-wide" alone do not: read
    # literally, "the count of alerts fleet-wide" is every alert the environment emitted in
    # the window — a number about the SOC, not about this alert — while the narrowing it meant
    # counts THESE entities anywhere. Two different numbers, and the lead's prose summary is
    # the only thing MAIN sees, so the contract has to say which one it wants.
    #
    # #867 re-spelled the pair from "on-host"/"fleet-wide" to SCOPED/UNSCOPED. The old spelling
    # was host-centric — it presumed the resolved host was the thing worth scoping to, which
    # holds for host-level auth sources and collapses on any source whose alerts all report the
    # same shared host: there the on-host count degenerates to "every alert this source
    # emitted" and the fleet-wide one, defined as "drop the host predicate and keep the rest",
    # has nothing left to bind at all. Scoped/unscoped asks for the same two measurements
    # without naming which field carries them.
    #
    # The third line is not a count. It exists because the lead now CHOOSES what the first two
    # are counted over: a number whose predicate MAIN cannot see is not a measurement MAIN can
    # weigh, and the prose summary is the only thing that reaches it.
    what = [
        "the count of alerts in the window scoped to the entities you judged central — one "
        "call, across any rule (the envelope's `total`)",
        "the count for those same entities UNSCOPED — the same window with the narrowing "
        "predicate dropped, across any rule (the envelope's `total`)",
        "which entities you correlated on, the field each came from, and why you judged them "
        "the discriminating ones for this alert",
    ]
    return goal, what


async def dispatch_correlation(  # noqa: C901, PLR0913 — item 3's own dispatch: the narrowed registry, the session/terminator wiring, the pre-claimed seam call — one composition frame
    *, run_dir: Path, defender_dir: Path, salt: str, run_id: str,
    goal: str, what_to_summarize: list[str], verbs: Any, limits: dict,
    make_model: Any, logger: Any, box: Any, store: Any = None,
    budget_started_monotonic: float = 0.0,
) -> str | None:
    """The ASYNC half of item 3: dispatch the real gather subagent for `l-00c`, reusing the
    shared terminator/bookkeeping seam (`tools_gather._run_gather`, K15) with
    `pre_claimed=True` (F5/F3 — the leads row was already claimed synchronously, before
    MAIN's first turn, by `resolve_lead_zero`/`prepare_correlation_lead`)."""
    from .agent_definition import bind
    from .agent_role import GATHER_AGENT_ID_PREFIX
    from .driver import GATHER_DEF, build_gather_agent
    from .tools import GatherDeps
    from .tools_gather import GatherRequest, _run_gather

    # A thin re-grant wrapper: same verb resolution, a narrower grant object — so `esql`
    # (never `confine_index`'d, g6/r19) is denied at the grant check rather than reaching a
    # transport (F3/K7/d19).
    from .verbs import VerbRegistry

    class _Narrowed(VerbRegistry):
        def __init__(self, inner):
            super().__init__(CORRELATION_GRANT)
            self._inner = inner

        def systems(self):
            return self._inner.systems()

        def verbs(self, system):
            return self._inner.verbs(system)

        def _cold_verb_names(self, system):
            return self._inner._cold_verb_names(system)

    registry = _Narrowed(verbs)

    # The SAME spelling `_run_gather` derives for the agent id it hands `gather_factory` and
    # `stamp_terminator` (`f"{GATHER_AGENT_ID_PREFIX}{lead_id}"`). Spelled literally here, the
    # session this frame opens and the session those two callbacks key would drift apart the
    # moment the prefix moved, with nothing to catch it — the store would carry an orphan row.
    agent_id = f"{GATHER_AGENT_ID_PREFIX}{L3}"
    gather_session_id: str | None = None
    if store is not None:
        gather_session_id = store.new_session(agent_id=agent_id)

    def gather_factory(_agent_id: str, system: str):
        from .driver import _gather_extra_capabilities

        extra: list = []
        if store is not None and gather_session_id is not None:
            # THIS dispatch's ceiling, not the module constant the model-dispatched path
            # uses — the same value handed to `_run_gather` below (#880 F-19). The recorder
            # withholds the doomed round by comparing against it; handed 40 while this lead
            # stops at 8, it withheld nothing and stored an unanswered final request.
            extra = _gather_extra_capabilities(
                store, gather_session_id, _agent_id,
                request_limit=CORRELATION_REQUEST_LIMIT,
            )
        return build_gather_agent(
            defender_dir, logger, _agent_id, make_model, registry, limits,
            extra_capabilities=extra, session_id=gather_session_id,
            # #835 — same per-system cache-key convention as the model-dispatched path
            # (`driver.py::_build_gather`): item 3 is bound to the alerts index only, so its
            # own template-catalog prefix stays the grant's system regardless of what
            # `request.system` says (they are now the same value — `CORRELATION_SYSTEM` is
            # derived from the grant — but the key does not depend on that).
            #
            # KNOWN MISMATCH, not fixed here: this key is shared with MAIN's own gather leads
            # on the same system, and the prefix behind it is NOT the same text — the template
            # index is grant-filtered, so this role renders one template where role `gather`
            # renders fourteen. One lane, two prefixes. The fix is to key on role as well as
            # system; it is a change to `driver.py`'s convention too, so it is not made here.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def stamp_terminator(_agent_id: str, reason: str) -> None:
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] correlation lead truncated_by write skipped: {e!r}")

    gbase = bind(GATHER_DEF, run_dir, salt=salt, defender_dir=defender_dir, box=box)
    assert isinstance(gbase, GatherDeps)
    # #808 review fix — thread the RUN's own budget-clock origin through, the same way
    # `_run_gather`'s own model-dispatched path does (`gdeps = replace(gbase, ...,
    # budget_started_monotonic=deps.budget_started_monotonic)`, tools_gather.py). Without
    # this, `bind`'s own `AgentDeps` default (`default_factory=time.monotonic`) stamps a
    # FRESH origin at whenever this coroutine happens to start, so under
    # `DEFENDER_BUDGET_ENFORCE` the correlation lead's wall-clock enforcement measures
    # elapsed time from its own start rather than sharing the run's true remaining budget.
    gdeps = replace(
        gbase, run_id=run_id, lead_id=L3, budget_started_monotonic=budget_started_monotonic,
    )

    request = GatherRequest(L3, CORRELATION_SYSTEM, goal, tuple(what_to_summarize))
    try:
        return await _run_gather(
            gdeps, gather_factory, CORRELATION_REQUEST_LIMIT, request, CORRELATION_GRANT,
            stamp_terminator, pre_claimed=True,
        )
    except (BudgetKill, circuit_breaker.RunAborted):
        raise
    except Exception as e:  # noqa: BLE001 — item 3's own dispatch must never break the run
        print(f"[run.py] correlation lead dispatch failed ({e!r}); skipping its summary",
              file=sys.stderr)
        return None


def _declare_l_finding(run_dir: Path, lead_id: str, name: str, system: str) -> None:
    """K11/N6 — the HARNESS writes lead-0's declaring `:L findings` row into
    `investigation.md`, before MAIN's first turn: with no such row, `invlang_validate`
    refuses any citation of the reserved id as an "undeclared lead" (P6, executed).

    `system` is the CALLER's, not a module constant: this frame serves both reserved ids and
    they do not share an authority for it — item 1's is the literal its own backend calls name
    (`ITEM1_SYSTEM`), item 3's is derived from the grant that confines it (`CORRELATION_SYSTEM`).
    The two are the same string today; a shared constant would silently mislabel one of the two
    rows the moment they stop being."""
    from defender._io import write_guarded

    path = RunPaths(run_dir).investigation
    block = (
        f"## lead-0 ({lead_id}) — harness-authored, declared before the investigation begins\n\n"
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        f"{lead_id}|0|{name}|||{system}|n/a\n"
        "```\n\n"
    )
    try:
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        write_guarded(path, existing + block)
    except (OSError, ValueError) as e:  # noqa: BLE001 — best-effort; never breaks the run
        print(f"[lead_zero] could not declare {lead_id} in investigation.md: {e!r}")


def prepare_correlation_lead(
    run_dir: Path, alert: dict, ancestor_block: str, status: str,
) -> tuple[str, list[str]] | None:
    """The SYNCHRONOUS half of item 3: gate on the resolution status (d22 — dispatches on
    RESOLVED and TRUNCATED, not on FAILED/EMPTY), build the harness-authored contract, and
    claim `l-00c`'s leads row BEFORE MAIN's first turn (F5). Returns `(goal,
    what_to_summarize)` when item 3 should actually dispatch, else `None`.

    #867 CHANGED THE OBLIGATION THIS GATE DISCHARGES, and deliberately. `d22` used to read
    "dispatches only when item 1 resolved at least one non-empty ENTITY SET"; it now reads "at
    least one ancestor DOCUMENT". The line below is untouched by that change — it always
    tested the status, and the status was always about documents — but a resolution whose
    documents yielded no host/user/source-ip used to be turned away downstream, inside
    `_correlation_contract`, and no longer is. That arm was not a degenerate case: it was every
    alert source that carries its entities outside those three fields — real documents, nothing
    the triple could see. `STATUS_EMPTY` and `STATUS_FAILED` still dispatch nothing.

    `ancestor_block` is item 1's rendered block as `LeadZeroResult.text` carries it — already
    sanitized, elided and wrapped — so the lead reads the same bytes MAIN reads at ORIENT."""
    if status not in (STATUS_RESOLVED, STATUS_TRUNCATED):
        return None
    contract = _correlation_contract(alert, ancestor_block)
    if contract is None:
        return None
    goal, what = contract
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L3, "goal": goal,
        "what_to_summarize": what, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # Someone else already owns this id (a planted collision), or the row could not be
        # written at all (#855 F-12) — either way this frame owns nothing, so it dispatches
        # nothing and touches the id no further.
        return None
    _declare_l_finding(run_dir, L3, "correlation lead", CORRELATION_SYSTEM)
    return goal, what


# ─── the wrap + section assembly ─────────────────────────────────────────────────────

def _render_section(body: str, salt: str) -> str:
    """`LeadZeroResult.text` (d0): item 1's rendered block IN ITS ENTIRETY inside ONE
    `wrap(text, "untrusted", salt)` frame — nothing outside it. The ORIENT heading is a
    separate, TRUSTED line `render_orient_section` prepends when assembling the section
    text `orient.py` appends; it is not part of the entry point's own return value."""
    return _wrap(body, "untrusted", salt)


def render_orient_section(result: LeadZeroResult) -> str:
    """The ORIENT-time section text: the trusted heading (naming the reserved ids MAIN must
    not reuse — R7 `interacts(main_agent->lead_id)`) followed by item 1's whole untrusted
    frame, unmodified."""
    return (
        f"{LEAD_ZERO_HEADING} (resolved by the harness before your first turn — reserved "
        f"lead ids {L0} (this resolution) and {L3} (a correlation lead dispatched off it, "
        "if any) are already claimed; do not reuse them)\n\n" + result.text
    )


# ─── the entry point (F1) ─────────────────────────────────────────────────────────────

def resolve_lead_zero(
    *, run_dir: Path, defender_dir: Path, alert_path: Path, salt: str, verbs: Any,
    limits: dict = DEFAULT_LIMITS, run_id: str | None = None,
) -> LeadZeroResult:
    run_dir = Path(run_dir)
    defender_dir = Path(defender_dir)
    resolved_run_id = run_id or run_dir.name

    if verbs is None:
        unavailable_text = _render_section(
            _unavailable("no verb registry was injected into this run"), salt)
        return LeadZeroResult(text=unavailable_text, status=STATUS_FAILED)

    alert_text, err = read_text_soft(Path(alert_path))
    if alert_text is None:
        body = _unavailable(f"could not read the alert: {err}")
        return LeadZeroResult(text=_render_section(body, salt), status=STATUS_FAILED)
    try:
        alert = json.loads(alert_text)
    except (ValueError, TypeError) as e:
        body = _unavailable(f"the alert is not valid JSON: {e!r}")
        return LeadZeroResult(text=_render_section(body, salt), status=STATUS_FAILED)
    if not isinstance(alert, dict):
        body = _unavailable("the alert is not a JSON object")
        return LeadZeroResult(text=_render_section(body, salt), status=STATUS_FAILED)

    from defender import run_common
    from .query_tool import QueryCapture

    try:
        env = run_common.run_env(defender_dir, run_dir)
    except Exception:  # noqa: BLE001 — orientation-adjacent work must never break the run
        env = {}

    capture = QueryCapture(verbs, "gather")

    async def _go():
        try:
            return await _resolve_item1(
                run_dir=run_dir, defender_dir=defender_dir, salt=salt, run_id=resolved_run_id,
                alert=alert, capture=capture, env=env, limits=limits,
            )
        except (BudgetKill, circuit_breaker.RunAborted, asyncio.CancelledError,
                KeyboardInterrupt, GeneratorExit):
            # #808 review fix — cancellation/control-flow signals must propagate rather than
            # degrade into a plain "item 1 failed" result: swallowing `CancelledError` here
            # breaks task cancellation semantics for whatever is running this coroutine.
            raise
        except BaseException as e:  # noqa: BLE001 — item 1's own faults degrade, never raise
            return _unavailable(f"{e!r}"), STATUS_FAILED

    body, status = _run_sync(_go())
    return LeadZeroResult(text=_render_section(body, salt), status=status)


__all__ = [
    "CORRELATION_GRANT",
    "CORRELATION_REQUEST_LIMIT",
    "CORRELATION_SYSTEM",
    "CORRELATION_TEMPLATE",
    "ELIDED",
    "HARNESS_PROVENANCE",
    "ITEM1_SYSTEM",
    "L0",
    "L3",
    "LEAD_ZERO_HEADING",
    "PROVENANCE_KEY",
    "RESERVED_LEAD_IDS",
    "SHORTFALL",
    "STATUS_EMPTY",
    "STATUS_FAILED",
    "STATUS_RESOLVED",
    "STATUS_TRUNCATED",
    "UNAVAILABLE",
    "LeadZeroResult",
    "dispatch_correlation",
    "prepare_correlation_lead",
    "resolve_lead_zero",
]
