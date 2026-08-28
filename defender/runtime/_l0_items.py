"""Harness-executed lead-0.

Before MAIN's first ORIENT turn, the runtime resolves the alert's ancestor documents (item 1)
and dispatches one tightly-bounded correlation gather lead (item 3), both writing into the
run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and
the review gate cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch those two items add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.

The two turn-zero items themselves: ancestor resolution, and correlation.

Split out of `lead_zero.py` at 1215 lines. `_resolve_item1` is the one function in the
tree that suppresses all three complexity limits at once, and its own comment says why —
keeping it here rather than in the facade is what makes that visible.
"""
from __future__ import annotations

import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from defender.hooks.budget_enforcer import (
    BudgetKill,
)
from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime import circuit_breaker
from defender.runtime.verbs import VerbContext
from ._l0_spec import ALERT_ID_FIELD, BUILDING_BLOCK_FIELD, CORRELATION_GRANT, CORRELATION_REQUEST_LIMIT, CORRELATION_SYSTEM, CORRELATION_TEMPLATE, GROUP_ID_FIELD, HARNESS_PROVENANCE, ITEM1_GOAL, ITEM1_SYSTEM, ITEM1_WHAT_TO_SUMMARIZE, L0, L3, SHORTFALL, STATUS_EMPTY, STATUS_FAILED, STATUS_RESOLVED, STATUS_TRUNCATED
from ._l0_capture import _CallLedger, _budget_account, _budget_gate, _build_deps, _last_row_seq, _sanitize
from ._l0_render import _render_doc, _sort_chrono, _unavailable
from ._l0_capture import _declare_l_finding


_DS_RE = re.compile(r"^\.ds-(?P<name>.+)-[^-]+-\d{4}\.\d{2}\.\d{2}-\d+$")


def _map_backing_index(index: str) -> str:
    """An open, bounded rewrite from a concrete `.ds-<name>-<namespace>-<date>-<generation>`
    backing index to the datastream pattern it belongs to, never a hardcoded substring table.
    A no-match passes the string through UNCHANGED so `confine_index`'s gate refuses it."""
    if not isinstance(index, str):
        return index
    m = _DS_RE.match(index)
    if not m:
        return index
    return f"{m.group('name')}-*"


async def _fetch_batched(ancestors: list[dict], issue) -> tuple[list[tuple[dict, int]], int, bool]:
    """Batch ancestor ids by MAPPED backing index — one call per distinct index, never one per
    ancestor. Returns `(docs, requested_count, truncated_any)` where each doc is paired with
    the queries-table `seq` of the call that returned it (the elision pointer's target).
    `issue` is the caller's budget-gated, success-tracking call wrapper: it returns
    `(envelope, seq)` and is told whether this call could produce an ancestor at all."""
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
    *, run_dir: Path, defender_dir: Path, run_id: str, alert: dict,
    capture: Any, env: dict, limits: dict,
) -> tuple[str, str]:
    from defender.scripts.adapters.elastic_adapter import load_config

    deps = _build_deps(run_dir, defender_dir, run_id, L0)
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L0, "goal": ITEM1_GOAL,
        "what_to_summarize": ITEM1_WHAT_TO_SUMMARIZE, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # Someone else already owns L0 (a planted collision): degrade rather than issue backend
        # calls or append a second, inconsistent `:L findings` row under an id this call does
        # not own. Mirrors `prepare_correlation_lead`'s L3 collision arm.
        #
        # `!= CLAIMED` and not `== ALREADY_CLAIMED`: a claim that could not be WRITTEN leaves
        # this frame owning exactly as little as a collision does, and the harness has no more
        # right than the model to run a lead with no leads row.
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
    # COUNTS, not booleans: one batched call per distinct backing index means "an ancestor call
    # answered" and "the ancestor calls answered" are different facts, and the rendering arms
    # below need both.
    ancestor_issued = 0
    ancestor_answered = 0

    async def _issue(verb: str, params: dict, *, ancestor: bool) -> tuple[dict | None, int]:
        """`ancestor=False` marks a call that CANNOT produce an ancestor document — item 1's
        opening by-`alert_id` fetch of the alert's own shell.

        The discriminator matters because the shell fetch answers on every alert with a
        resolvable `alert_id`: a single success flag set from every call is therefore always
        true, `STATUS_FAILED` becomes unreachable however the ancestor calls ended, and an
        outage on them renders as `_(unavailable: … found nothing)` — an absence of ancestors,
        which is triage evidence, asserted over a backend that never answered.

        `ancestor` has NO DEFAULT deliberately: a call site added later that forgets it must
        not silently read as an ancestor call.

        `answered_any` is tracked beside it because "no ancestor call was made" is not by
        itself a resolved absence: when the shell fetch is the ONLY call and it failed, the
        group-id branch was never reachable, so nothing was established."""
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
        # The seq is read AFTER the call, off the row it just wrote: a document's elision
        # pointer must name the payload of the fetch that returned it, not its own position.
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

    # One call per DISTINCT MAPPED BACKING INDEX means a resolution can have both an ancestor
    # call that answered and one that faulted. Gating the absence sentence below on "at least
    # one answered" makes an alert whose ancestors span two indices — the first matching
    # nothing, the second faulting — render "the resolution reached the backend and found
    # nothing": a resolved absence claimed over an index that never answered.
    ancestor_failed = ancestor_issued - ancestor_answered

    body_lines = []
    if docs:
        for doc, seq in docs:
            body_lines.append(_render_doc(doc, L0, seq))
    elif ancestor_issued and not ancestor_answered:
        # Not "every backend call this resolution attempted failed": the shell fetch answered,
        # and only the calls that could have produced an ancestor did not.
        body_lines.append(_unavailable(
            "every backend call that could have resolved an ancestor failed"))
    elif not answered_any:
        # No ancestor call was ISSUED and the only call this resolution made — the shell fetch
        # whose group id decides whether an ancestor branch exists at all — failed. Nothing
        # answered, so the group branch was never reachable and no absence was established;
        # without this arm the run renders `_(unavailable: … found nothing)`, a false claim
        # over a silent backend.
        body_lines.append(_unavailable("every backend call this resolution attempted failed"))
    elif ancestor_failed:
        # SOME answered and some did not, and nothing came back from the ones that did: the
        # absence holds only over the indices actually reached, never over the alert.
        body_lines.append(_unavailable(
            f"{ancestor_failed} of {ancestor_issued} ancestor fetches failed; the rest "
            "reached the backend and found nothing"))
    else:
        # Every ancestor call this resolution issued answered, and none matched — or the alert
        # declared no usable ancestor and its shell answered with no group id, so there was no
        # ancestor call to make. Both are a resolved absence, which is what this sentence says.
        body_lines.append(_unavailable("the resolution reached the backend and found nothing"))

    if docs and ancestor_failed:
        # The docs-present half of the same distinction. The count note below reads as "the
        # backend did not have them"; this one says the other thing that can be true at the
        # same time, and the two compose.
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

    # FAILED when no call that could have contributed answered. `ancestor_issued` guards the
    # ancestor half so an alert with nothing to ask for stays EMPTY: a resolution that issued
    # no ancestor call has no failed call to report. The `answered_any` half keeps a resolution
    # whose SHELL FETCH was its only call, and failed, out of EMPTY — it asked nothing further
    # because the answer that would have told it what to ask never came.
    #
    # A PARTIAL ancestor failure stays EMPTY/TRUNCATED rather than earning a fifth status: the
    # over-claim it could produce is in what MAIN is TOLD, which the arms above now say, while
    # the status has exactly two consumers — the dispatch gate, which refuses FAILED and EMPTY
    # alike, and `_user_prompt`, which forwards it. Moving a partial failure to FAILED would
    # discard the documents the calls that DID answer returned.
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

def _correlation_contract(alert: dict, ancestor_block: str) -> tuple[str, list[str]] | None:
    """The contract carries item 1's RESOLVED DOCUMENTS and the lead chooses the correlation
    axes off them.

    What gates the dispatch is item 1 resolving documents, which `prepare_correlation_lead`'s
    status check already decides — there is no entity-emptiness arm here. `GatherRequest`
    carries `goal` and `what_to_summarize` and nothing else, so handing over a harness-extracted
    entity triple instead would ask the lead to correlate on entities it had never seen."""
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
    # Two COUNT dimensions, each answerable by ONE `alerts` call, plus a third line that is not
    # a count. A fourth — "whether any correlated alert is already benign-explained" — is
    # deliberately absent: `kibana.alert.workflow_status` is `"open"` on every alert this
    # environment produces, and the systems that could carry a benign explanation (`ticket`,
    # `change-mgmt`) are outside this lead's grant, so it has exactly one possible answer.
    #
    # "across any rule", not "same-signature": the goal says do NOT narrow to this alert's own
    # rule, and a per-rule breakdown over the 8 installed rules is 8-16 `alerts` calls against a
    # request limit of 8 — the one verb that could group-by in a single call (`esql`) is exactly
    # what this lead's grant withholds for index confinement.
    #
    # Each dimension names its ENTITY SCOPE, and as SCOPED/UNSCOPED rather than
    # "on-host"/"fleet-wide". Read literally, "alerts fleet-wide" counts every alert the
    # environment emitted — a number about the SOC, not this alert — and the host-centric
    # spelling collapses on any source whose alerts all report the same shared host: the
    # on-host count degenerates to "every alert this source emitted" and the fleet-wide one has
    # nothing left to bind. Scoped/unscoped asks for the same two measurements without naming
    # which field carries them.
    #
    # The third line exists because the lead CHOOSES what the first two are counted over: a
    # number whose predicate MAIN cannot see is not a measurement MAIN can weigh, and the prose
    # summary is the only thing that reaches it.
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
    *, run_dir: Path, defender_dir: Path, run_id: str,
    goal: str, what_to_summarize: list[str], verbs: Any, limits: dict,
    make_model: Any, logger: Any, box: Any, store: Any = None,
    budget_started_monotonic: float = 0.0,
) -> str | None:
    """The ASYNC half of item 3: dispatch the real gather subagent for `l-00c`, reusing the
    shared terminator/bookkeeping seam (`tools_gather._run_gather`) with `pre_claimed=True` —
    `prepare_correlation_lead` already claimed the leads row synchronously, before MAIN's first
    turn."""
    from .agent_definition import bind
    from .agent_role import GATHER_AGENT_ID_PREFIX
    from .driver import GATHER_DEF, build_gather_agent
    from .tools import GatherDeps
    from .tools_gather import GatherRequest, _run_gather

    # A thin re-grant wrapper: same verb resolution, a narrower grant object — so `esql` (never
    # `confine_index`'d) is denied at the grant check rather than reaching a transport.
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
    # `stamp_terminator`. Spelled as a literal here, the session this frame opens and the one
    # those two callbacks key would drift apart the moment the prefix moved, with nothing to
    # catch it — the store would carry an orphan row.
    agent_id = f"{GATHER_AGENT_ID_PREFIX}{L3}"
    gather_session_id: str | None = None
    if store is not None:
        gather_session_id = store.new_session(agent_id=agent_id)

    def gather_factory(_agent_id: str, system: str, request_limit: int):
        from .driver import _gather_extra_capabilities

        extra: list = []
        if store is not None and gather_session_id is not None:
            # `request_limit` arrives from `_run_gather` — the value it is about to enforce —
            # rather than being read again from `CORRELATION_REQUEST_LIMIT` here: the recorder
            # withholds the doomed round by comparing against it, so it must not measure a
            # ceiling this dispatch did not receive.
            extra = _gather_extra_capabilities(
                store, gather_session_id, _agent_id, request_limit=request_limit,
            )
        return build_gather_agent(
            defender_dir, logger, _agent_id, make_model, registry, limits,
            extra_capabilities=extra, session_id=gather_session_id,
            # Same per-system cache-key convention as the model-dispatched path
            # (`driver.py::_build_gather`).
            #
            # KNOWN MISMATCH, not fixed here: this key is shared with MAIN's own gather leads
            # on the same system, and the prefix behind it is NOT the same text — the template
            # index is grant-filtered, so this role renders one template where role `gather`
            # renders fourteen. One lane, two prefixes. The fix is to key on role as well as
            # system; that changes `driver.py`'s convention too, so it is not made here.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def stamp_terminator(_agent_id: str, reason: str) -> None:
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] correlation lead truncated_by write skipped: {e!r}")

    gbase = bind(GATHER_DEF, run_dir, defender_dir=defender_dir, box=box)
    assert isinstance(gbase, GatherDeps)
    # Thread the RUN's own budget-clock origin through, the way `_run_gather`'s model-dispatched
    # path does. Otherwise `bind`'s `AgentDeps` default (`default_factory=time.monotonic`)
    # stamps a FRESH origin whenever this coroutine happens to start, and under
    # `DEFENDER_BUDGET_ENFORCE` the correlation lead's wall-clock enforcement measures elapsed
    # time from its own start rather than the run's true remaining budget.
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
