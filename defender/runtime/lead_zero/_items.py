"""The two turn-zero lead-0 items: ancestor resolution (item 1) and correlation (item 3).

Both write into the run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so
the learning loop and the review gate cite them like any model-dispatched lead.
"""
from __future__ import annotations

import logging
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from defender.hooks.budget_enforcer import (
    BudgetKill,
)
from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime import circuit_breaker
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import VerbContext, VerbRegistry
from ._agreement import CorrelationDispatch
from ._spec import ALERT_ID_FIELD, BUILDING_BLOCK_FIELD, CORRELATION_REQUEST_LIMIT, GROUP_ID_FIELD, HARNESS_PROVENANCE, ITEM1_GOAL, ITEM1_SYSTEM, ITEM1_WHAT_TO_SUMMARIZE, L0, L3, SHORTFALL, STATUS_EMPTY, STATUS_FAILED, STATUS_RESOLVED, STATUS_TRUNCATED
from ._capture import _CallLedger, _budget_account, _budget_gate, _build_deps, _last_row_seq, _sanitize
from ._render import _render_doc, _sort_chrono, _unavailable
from ._capture import _declare_l_finding

_logger = logging.getLogger(__name__)


_DS_RE = re.compile(r"^\.ds-(?P<name>.+)-[^-]+-\d{4}\.\d{2}\.\d{2}-\d+$")


class _NarrowedRegistry(VerbRegistry):
    """Item 3's registry: the production registry's verb resolution under the correlation
    lead's narrower grant, so `esql` (never `confine_index`'d) is denied at the grant check
    rather than reaching a transport.

    `grant_home` is the inner registry's pointer to the run's resolved table, so a refusal
    names the one place that can widen the grant.
    """

    def __init__(self, inner: VerbRegistry, grant: VerbGrant):
        super().__init__(grant)
        self._inner = inner
        self.grant_home = getattr(inner, "grant_home", None)

    def systems(self):
        return self._inner.systems()

    def verbs(self, system):
        return self._inner.verbs(system)

    def _cold_verb_names(self, system):
        return self._inner._cold_verb_names(system)


def _map_backing_index(index: str) -> str:
    """Map a `.ds-<name>-<namespace>-<date>-<generation>` backing index to its datastream
    pattern. A no-match passes through unchanged so `confine_index`'s gate refuses it."""
    if not isinstance(index, str):
        return index
    m = _DS_RE.match(index)
    if not m:
        return index
    return f"{m.group('name')}-*"


async def _fetch_batched(ancestors: list[dict], issue) -> tuple[list[tuple[dict, int]], int, bool]:
    """Fetch ancestors with one call per distinct mapped backing index. Returns
    `(docs, requested_count, truncated_any)`, each doc paired with the queries-table `seq` of
    the call that returned it. `issue` is the caller's budget-gated call wrapper."""
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


async def _resolve_item1(  # noqa: C901, PLR0912, PLR0915 — shell fetch, group/fallback branches and per-call budget gating are one resolution
    *, run_dir: Path, defender_dir: Path, run_id: str, alert: dict,
    capture: Any, env: dict, limits: dict, settings_dir: Path,
) -> tuple[str, str]:
    from defender.scripts.adapters.elastic_adapter import load_config

    deps = _build_deps(run_dir, defender_dir, run_id, L0, settings_dir)
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L0, "goal": ITEM1_GOAL,
        "what_to_summarize": ITEM1_WHAT_TO_SUMMARIZE, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # Degrade rather than issue calls or append rows under an id this call does not own.
        # A claim that failed to write is treated the same as a collision.
        return (_unavailable(
            f"{L0} is already claimed by something else on this run dir"
            if claimed == ALREADY_CLAIMED else f"{L0}'s leads row could not be claimed"
        ), STATUS_FAILED)
    _declare_l_finding(run_dir, L0, "ancestor resolution", ITEM1_SYSTEM)

    alert_id = alert.get("alert_id")
    signal_index = alert.get("signal_index")
    if not isinstance(signal_index, str) or not signal_index.strip():
        try:
            cfg = load_config(VerbContext(defender_dir=defender_dir, run_dir=run_dir, env=env,
                                          settings_dir=settings_dir))
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
    # Counts, not booleans: with one call per backing index, some ancestor calls can answer
    # while others fail, and the rendering arms below distinguish the two.
    ancestor_issued = 0
    ancestor_answered = 0

    async def _issue(verb: str, params: dict, *, ancestor: bool) -> tuple[dict | None, int]:
        """`ancestor=False` marks the alert-shell fetch, which cannot produce an ancestor.

        Without the split, the shell fetch's success would mask an outage on every ancestor
        call and render it as "found nothing", a false absence. `ancestor` has no default so
        a new call site must choose."""
        nonlocal issued_any, answered_any, ancestor_issued, ancestor_answered
        issued_any = True
        if ancestor:
            ancestor_issued += 1
        _budget_gate(run_dir, limits)
        envelope, _text = await ledger.call(capture, deps, verb, params, env)
        _budget_account(run_dir, run_id, "query", limits)
        if envelope is not None:
            answered_any = True
            if ancestor:
                ancestor_answered += 1
        # Read after the call: the elision pointer names the payload of the fetch that
        # returned the document.
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
            # No group, or a group resolving to zero building blocks: fall back.
            docs, requested2, truncated = await _fetch_batched(ancestor_events, _issue)
            requested = max(requested, requested2)
    else:
        docs, requested2, truncated = await _fetch_batched(ancestor_events, _issue)
        requested = max(requested, requested2)

    if not issued_any:
        return (_unavailable("no usable ancestor identifier or alert id survived — no "
                              "fetch was issued"), STATUS_EMPTY)

    docs = _sort_chrono(docs)

    # A partial failure must not render as a resolved absence over an index that never
    # answered.
    ancestor_failed = ancestor_issued - ancestor_answered

    body_lines = []
    if docs:
        for doc, seq in docs:
            body_lines.append(_render_doc(doc, L0, seq))
    elif ancestor_issued and not ancestor_answered:
        # The shell fetch answered; only the ancestor calls failed.
        body_lines.append(_unavailable(
            "every backend call that could have resolved an ancestor failed"))
    elif not answered_any:
        # Only the shell fetch ran and it failed, so no absence was established.
        body_lines.append(_unavailable("every backend call this resolution attempted failed"))
    elif ancestor_failed:
        # The absence holds only over the indices actually reached.
        body_lines.append(_unavailable(
            f"{ancestor_failed} of {ancestor_issued} ancestor fetches failed; the rest "
            "reached the backend and found nothing"))
    else:
        # Every ancestor call answered empty, or there was none to make: a resolved absence.
        body_lines.append(_unavailable("the resolution reached the backend and found nothing"))

    if docs and ancestor_failed:
        # Distinct from the count shortfall below, which reads as "the backend lacked them".
        body_lines.append(
            f"{SHORTFALL} {ancestor_failed} of {ancestor_issued} ancestor fetches failed — "
            "the documents above are what the rest returned)"
        )

    if requested and (len(docs) < requested or truncated):
        body_lines.append(
            f"{SHORTFALL} resolved {len(docs)} of {requested} requested ancestor "
            "document(s))"
        )

    text = "\n\n".join(body_lines)

    # FAILED when no call that could have contributed answered (including a failed shell fetch
    # that was the only call); an alert with nothing to ask for stays EMPTY. A partial ancestor
    # failure stays EMPTY/TRUNCATED so the documents that did return are kept; the text above
    # already tells MAIN about the failures.
    if not ancestor_answered and (ancestor_issued or not answered_any):
        status = STATUS_FAILED
    elif not docs:
        status = STATUS_EMPTY
    elif requested and (len(docs) < requested or truncated):
        status = STATUS_TRUNCATED
    else:
        status = STATUS_RESOLVED

    return text, status


# item 3: the correlation lead's harness-authored contract

def _correlation_contract(
    alert: dict, ancestor_block: str, template_id: str,
) -> tuple[str, list[str]] | None:
    """Build the correlation lead's goal and summary asks. The goal carries item 1's resolved
    documents so the lead chooses the correlation axes from them, and names `template_id` as
    the template to bind. Returns None when the alert has no parseable timestamp."""
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
        "This is a correlation over PRIOR ALERTS, not raw telemetry. Do not narrow to this "
        "alert's own rule. The documents above may themselves name that rule, and it is still "
        "not an axis to bind: a different rule firing on the same entity is exactly the "
        "related behaviour this lead exists to surface, and narrowing to the signature that "
        "already fired is the one result guaranteed to teach nothing. Bind "
        f"`{template_id}` — read it first: it is named by your grant-filtered template "
        "index, and it carries the window params and the substitutable entity filter this "
        "contract needs. The template says where its count is read; each count below is that "
        "number, not the size of the returned sample."
    )
    # The goal is vendor-neutral: field names, index choice and where the count is read are the
    # template's to say, and the lead is told to read it first.
    #
    # Two counts, each answerable by one call of the granted verb. "Already benign-explained" is
    # omitted: workflow_status is always "open" here and ticket/change-mgmt are outside the
    # grant. "Across any rule" because a per-rule breakdown would exceed the request limit
    # without `esql`, which the grant withholds. Scoped/unscoped rather than on-host/fleet-wide,
    # which collapses when every alert reports the same shared host. The third line is there
    # because MAIN cannot weigh a count whose predicate it cannot see.
    what = [
        "the count of alerts in the window scoped to the entities you judged central — one "
        "call, across any rule (the count the template says to read, not the sample size)",
        "the count for those same entities UNSCOPED — the same window with the narrowing "
        "predicate dropped, across any rule (the same count, read the same way)",
        "which entities you correlated on, the field each came from, and why you judged them "
        "the discriminating ones for this alert",
    ]
    return goal, what


async def dispatch_correlation(  # noqa: C901, PLR0913 — item 3's own dispatch: the narrowed registry, the session/terminator wiring, the pre-claimed seam call — one composition frame
    *, run_dir: Path, defender_dir: Path, run_id: str,
    goal: str, what_to_summarize: list[str], verbs: Any, limits: dict,
    make_model: Any, logger: Any, box: Any, store: Any = None,
    budget_started_monotonic: float = 0.0, catalog: str | None,
    dispatch: CorrelationDispatch, settings_dir: Path,
) -> str | None:
    """The async half of item 3: dispatch the gather subagent for `l-00c` through
    `tools_gather._run_gather` with `pre_claimed=True` (`prepare_correlation_lead` already
    claimed the row).

    System and grant come from `dispatch`, the run-start check's result, not from `_spec`
    constants, so what was checked is what is dispatched. `settings_dir` is the run's tenant
    folder."""
    from ..agent_definition import bind
    from ..agent_role import GATHER_AGENT_ID_PREFIX
    from ..driver import build_gather_agent, gather_def_for
    from ..tools import GatherDeps
    from ..tools_gather import GatherRequest, _run_gather

    # Not named `system`: that would shadow `gather_factory`'s parameter, which keys the
    # prompt cache.
    dispatch_system = dispatch.system
    if dispatch_system is None:
        return None

    registry = _NarrowedRegistry(verbs, dispatch.grant)

    # Must match the agent id `_run_gather` derives, or the store gets an orphan session row.
    agent_id = f"{GATHER_AGENT_ID_PREFIX}{L3}"
    gather_session_id: str | None = None
    if store is not None:
        gather_session_id = store.new_session(agent_id=agent_id)

    def gather_factory(_agent_id: str, system: str, request_limit: int):
        from ..driver import _gather_extra_capabilities

        extra: list = []
        if store is not None and gather_session_id is not None:
            # Use the limit `_run_gather` enforces, not a re-read constant: the recorder
            # compares against it to withhold the doomed round.
            extra = _gather_extra_capabilities(
                store, gather_session_id, _agent_id, request_limit=request_limit,
            )
        return build_gather_agent(
            defender_dir, logger, _agent_id, make_model, registry, limits,
            extra_capabilities=extra, session_id=gather_session_id,
            verb_grant=dispatch.grant,
            # Same per-system cache key as `driver.py::_build_gather`. Known mismatch: the
            # grant-filtered template index makes this prompt prefix differ from MAIN's gather
            # leads on the same key; fixing it means keying on role in `driver.py` too.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def stamp_terminator(_agent_id: str, reason: str) -> None:
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            _logger.warning(f"correlation lead truncated_by write skipped: {e!r}")

    gbase = bind(gather_def_for(dispatch.grant), run_dir, defender_dir=defender_dir, box=box)
    assert isinstance(gbase, GatherDeps)
    # Carry the run's budget-clock origin; `bind`'s default would start a fresh clock and
    # overstate the remaining wall-clock budget.

    gdeps = replace(
        gbase, run_id=run_id, lead_id=L3, budget_started_monotonic=budget_started_monotonic,
        settings_dir=settings_dir,
    )

    request = GatherRequest(L3, dispatch_system, goal, tuple(what_to_summarize))
    try:
        return await _run_gather(
            gdeps, gather_factory, CORRELATION_REQUEST_LIMIT, request, dispatch.grant,
            stamp_terminator, catalog=catalog, pre_claimed=True,
        )
    except (BudgetKill, circuit_breaker.RunAborted):
        raise
    except Exception as e:  # noqa: BLE001 — item 3's own dispatch must never break the run
        _logger.warning(f"correlation lead dispatch failed ({e!r}); skipping its summary")
        return None
