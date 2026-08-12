"""Scenario machinery for the #808 harness-executed lead-0 spec — NO test scripts.

This is the #808 half of what `_replay_harness.py` is to the runtime suite: the plumbing a
lead-0 scenario needs, so a test is a few lines of data and a docstring. It is NOT a test
module (the leading underscore keeps pytest from collecting it) and it holds no assertions.

Everything below the two replay models is production code. A scenario hands `run()` an alert
document and an `answer(verb, params)` callback; between the two, the REAL `orientation()`,
the REAL `QueryCapture` screens, the REAL `claim_lead`, the REAL circuit breaker, the REAL
budget hook, the REAL session store and the REAL two tables run.

WHAT IS FAKED, AND WHY IT IS THE ONLY THING FAKED
-------------------------------------------------
The elastic verbs. `elastic_adapter.query`/`alerts`/`esql` reach a cluster over
`docker --context soc-playground exec … curl`, which no hermetic run can start (c3 is
`unprobed` for exactly this reason: soc-playground.invalid does not resolve). The verb
registry is the run's declared injection seam (`run_investigation(verbs=…)`, #611), so the
scenario hands in a table of plain annotated functions whose SIGNATURES mirror the real
adapter's — the real `validate_params` screen checks lead-0's outbound params against them,
and the real capture capability writes the real rows.

The fakes inject faults and canned envelopes; they classify nothing. Every exit code, error
class, breaker outcome and payload status in a scenario's assertions is production's work.
Fault content is probe-derived, never authored: `answer` raises the adapter's own
`ConfinementFault`/`TransportFault`/`UpstreamFault` (P2, executed: `confine_index` fires on
the adapter side of both call paths; r3, executed: `resolve_sort` raises `UpstreamFault`),
and the canned envelope is built by the REAL `elastic_adapter.search_envelope`, so a scenario
cannot express a response shape the adapter cannot produce.

WHERE `kibana.alert.group.id` COMES FROM — AND WHY NOT FROM `alert.json`
------------------------------------------------------------------------
Item 1's FIRST backend call always fetches the alert's own SHELL DOCUMENT by `alert_id`
against the index the alert declares it came from (`signal_index`), reads `group.id` off THAT
document, and only then branches. `alert_doc()` therefore does NOT write
`kibana.alert.group.id` into the run-dir `alert.json`: brief R3 / claim `g17` (executed) shows
nothing under `defender/` produces that file — the projection lives in three `experiments/`
scripts and one evals synthesizer, and `project_alert.py` hardcodes a tree path and shells out
to a CLI that is not in this tree — so "the alert projection must start carrying `group.id`"
(F4 arm (a)) cannot be demanded of shipped code. §7 took arm (b) twice, and phase F caught the
first cut of this suite encoding arm (a) instead.

A scenario therefore supplies the group id through `run(shell=shell_doc(group_id="grp-0"))` —
the document the by-`alert_id` fetch RETURNS — and `alert_group_id.domain.distinguished[grp-0]`
is where the graph pins that value. Every other field of `alert_doc()` is copied from
`defender/fixtures/v2-sshd-success-after-failures/alert.json`'s real shape: brief R6 (the
design's own key list matches none of the five checked-in fixtures) is why the base document is
read off the tree rather than off the doc.

`elastic_backend` answers the shell fetch itself, so a scenario's `answer` callback serves only
the calls AFTER it — and `Res.shell_call` / `Res.ancestor_calls` split the record the same way,
because "which call was the shell fetch" is a question every item-1 assertion now asks.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.scripts.adapters.elastic_adapter import search_envelope  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
)

# ─── the names this spec mints on the production side ───────────────────────────────────
# `schema.md`, "Coin ids from the code's name": a private synonym does not cost a config
# entry, it costs the check. Spell these exactly in `defender/runtime/lead_zero.py`.
LEAD_ZERO_MODULE = "defender.runtime.lead_zero"
L0 = "l-000"          # item 1's reserved id (F5)
L3 = "l-00c"          # item 3's reserved id (F5)
CORRELATION_REQUEST_LIMIT = 8      # F6 — `d21`'s "strictly below 40" was vacuous at 39
HARNESS_PROVENANCE = "harness"     # K11's provenance field VALUE
PROVENANCE_KEY = "provenance"      # K11's provenance field NAME
LEAD_ZERO_HEADING = "## Alert ancestors"   # the ORIENT section `orientation()` appends

SALT = "aabbccddeeff0011"
# The three rendered notes, spelled in `orient.py`'s own shipped `_(unavailable: …)_` idiom
# so the block reads like every other degraded ORIENT section rather than inventing a second
# convention. `UNAVAILABLE` is the design's own word; the other two are this spec's, minted
# because K3 and K17 demand a note and name none.
UNAVAILABLE = "_(unavailable:"
SHORTFALL = "_(incomplete:"     # K3 — `returned < len(ancestor_events)` or `truncated`
ELIDED = "_(elided:"            # K17 — a per-document `message` over the rendering budget

# Read off the tree, not restated: `knowledge/environment/systems/elastic/config.env`.
EVENTS_INDEX = "logs-*"
ALERTS_INDEX = ".internal.alerts-security.alerts-default-*"

AUTH_BACKING = ".ds-logs-system.auth-default-2026.05.24-000002"
FALCO_BACKING = ".ds-logs-falco.alerts-default-2026.04.30-000003"


# ─── the alert ──────────────────────────────────────────────────────────────────────────

def ancestor(doc_id: str, index: str = AUTH_BACKING, **over: Any) -> dict:
    """One `ancestor_events[]` entry, in the exact shape g7 found across all five checked-in
    fixtures: every entry is `{id, type, index, depth}` with `type=event` and `depth=0`."""
    return {"id": doc_id, "type": "event", "index": index, "depth": 0, **over}


ALERT_ID = "94f777794d60c7c8f112d07b455ed79a41d4f0a0e932fccd94ce0d9914997606"
# THE FIELD the shell fetch retrieves on. `alert_id` is a key of the run-dir `alert.json`, not
# of an alert DOCUMENT, so the predicate has to name the document field it maps to. The only
# mapping in this tree is `experiments/effort-tradeoff/project_alert.py:62`
# (`"alert_id": s.get("kibana.alert.uuid")`) — and that file is the one brief R3 / g17
# (executed) refuted as a producer, so the mapping is recorded as claim `a6` WITH that caveat
# and the question of whether the alerts index answers on it is deferred beside c3. Pinned
# here because `d60` asserting only "the id appears somewhere in the predicate" cannot tell
# `kibana.alert.uuid:"…"` from `_id:"…"`, and an implementer who picks the other one ships
# green while the primary path silently never runs in production.
ALERT_ID_FIELD = "kibana.alert.uuid"


def alert_doc(
    *,
    ancestors: list[dict] | None = None,
    alert_id: str | None = ALERT_ID,
    signal_index: str | None = ALERTS_INDEX,
    timestamp: str = "2026-05-25T15:27:22.928Z",
    rule_id: str = "v2-sshd-success-after-failures",
    rule_query: str = 'sequence by host.name with maxspan=10m\n  [any where JOINME]',
    **over: Any,
) -> dict:
    """The run-dir `alert.json` a scenario drives. Defaults reproduce the sshd golden.

    It carries NO `kibana.alert.group.id`, and that is the fixture's whole point: no
    checked-in alert carries one (c5/r5, executed) and no in-repo producer writes this file
    (g17), so the group id has to come off the shell document item 1 fetches — `shell_doc`."""
    doc: dict[str, Any] = {
        "alert_timestamp": timestamp,
        "rule": {"id": rule_id, "name": "v2 sshd success after failures", "type": "eql",
                 "severity": "high", "language": "eql", "query": rule_query},
        "reason": "authentication event with process sshd, by dev.dana created high alert.",
        "host": {"name": "office-ws-1"},
        "user": {"name": "dev.dana"},
        "ancestor_events": [ancestor("anc-1"), ancestor("anc-2")]
        if ancestors is None else ancestors,
    }
    if alert_id is not None:
        doc["alert_id"] = alert_id
    if signal_index is not None:
        doc["signal_index"] = signal_index
    doc.update(over)
    return doc


def shell_doc(*, group_id: str | None = None, **over: Any) -> dict:
    """The alert's OWN shell document, as item 1's by-`alert_id` fetch returns it — the only
    surface `kibana.alert.group.id` can honestly arrive on (F4 arm (b), resolved twice).

    `_source` only, per P1c (executed): `_search` strips `_id`/`_index`/`_score`, so a shell
    document a scenario hands back can carry nothing the adapter would not have carried."""
    doc: dict[str, Any] = {
        "@timestamp": "2026-05-25T15:27:22.928Z",
        "kibana.alert.rule.name": "v2 sshd success after failures",
        "kibana.alert.uuid": ALERT_ID,
        **over,
    }
    if group_id is not None:
        doc["kibana.alert.group.id"] = group_id
    return doc


def hit(
    *, ts: str, message: str = "Accepted password for dev.dana", host: str = "office-ws-1",
    user: str = "dev.dana", ip: str = "172.18.0.15", **over: Any,
) -> dict:
    """One `_source` document, per P1c (executed): `_search` keeps ONLY `_source` per hit —
    `_id`/`_index`/`_score` are stripped and never reach a caller, so a hit a scenario hands
    back can carry nothing the adapter would not have carried."""
    return {"@timestamp": ts, "message": message, "host.name": host,
            "user.name": user, "source.ip": ip, **over}


def building_block(*, ts: str, group_index: int, **over: Any) -> dict:
    """A building-block alert document: shares the shell's `group.id` (c2) and carries the
    building-block stamp c2 also names as the only discriminator between the two."""
    return hit(ts=ts, **over) | {
        "kibana.alert.group.index": group_index,
        "kibana.alert.building_block_type": "default",
    }


# ─── the injected backend ───────────────────────────────────────────────────────────────

Answer = Callable[[str, dict], Any]


def envelope(docs: list[dict], *, total: int | None = None, truncated: bool | None = None,
             index: str = EVENTS_INDEX, sort: str = "desc") -> dict:
    """The response envelope, built by the REAL `elastic_adapter.search_envelope` so a
    scenario cannot mint a shape the adapter could not produce. `truncated` defaults the way
    `_search` computes it (`total_hits > len(docs)`)."""
    tot = len(docs) if total is None else total
    trunc = (tot > len(docs)) if truncated is None else truncated
    return search_envelope(index, list(docs), tot, trunc, sort)


def answer_hits(docs: list[dict], **kw: Any) -> Answer:
    """The commonest `answer`: every verb returns the same envelope."""
    def _answer(verb: str, params: dict) -> Any:  # noqa: ARG001
        return envelope(docs, **kw)
    return _answer


def answer_sequence(*results: Any) -> Answer:
    """Successive calls get successive results; an exception instance is RAISED rather than
    returned. Past the script the last result repeats, so a scenario about the FIRST two
    calls never fails on a third it did not intend to script."""
    seen: list[int] = [0]

    def _answer(verb: str, params: dict) -> Any:  # noqa: ARG001
        item = results[min(seen[0], len(results) - 1)]
        seen[0] += 1
        if isinstance(item, BaseException):
            raise item
        return item
    return _answer


def answer_by_index(table: dict[str | None, Any], default: Any = None) -> Answer:
    """Keyed on the `index=` param the call carried — the per-backing-index shape `d5`'s
    "one call per distinct mapped backing index" produces."""
    def _answer(verb: str, params: dict) -> Any:  # noqa: ARG001
        item = table.get(params.get("index"), default)
        if isinstance(item, BaseException):
            raise item
        assert item is not None, f"scenario scripted no answer for index={params.get('index')!r}"
        return item
    return _answer


def answer_raising(exc: BaseException) -> Answer:
    """A fault injector. `exc` must be one the ADAPTER itself raises — the fake maps nothing
    to an exit code, touches no breaker and writes no row; all three are production's."""
    def _answer(verb: str, params: dict) -> Any:  # noqa: ARG001
        raise exc
    return _answer


SHELL_DEFAULT: Any = object()   # sentinel: "a shell alert that resolves, carrying no group id"


def _shell_answer(shell: Any, index: str, answer: Answer) -> Answer:
    """Compose the SHELL fetch onto a scenario's ancestor answer.

    Keyed on the call's OWN predicate (`native_query` starting with `ALERT_ID_FIELD:`, the
    shell fetch's unique signature — d60/c-lookup), not on call order: when K13 correctly
    skips the shell fetch (no usable `alert_id`), item 1's first and only call is the
    batched ancestor fetch, and a call-order interceptor would misroute it into this
    scenario's shell answer instead of `answer`. `shell` is a document (or list) the fetch
    returns, `[]`/`None` for "unresolvable by alert_id", or an exception instance the fetch
    raises."""
    if shell is SHELL_DEFAULT:
        shell = shell_doc()

    def _answer(verb: str, params: dict) -> Any:
        native_query = params.get("native_query") or ""
        if not native_query.startswith(f"{ALERT_ID_FIELD}:"):
            return answer(verb, params)
        if isinstance(shell, BaseException):
            raise shell
        docs = [] if shell is None else (list(shell) if isinstance(shell, list) else [shell])
        return envelope(docs, index=index)
    return _answer


def elastic_backend(rec: VerbRecorder, answer: Answer, *, shell: Any = SHELL_DEFAULT,
                    signal_index: str = ALERTS_INDEX) -> FakeVerbs:
    """The injected registry, declaring all three elastic verbs with the REAL adapter's
    parameter signatures — so the real `validate_params` screen checks lead-0's outbound
    params against the real contract, and `esql` is REACHABLE unless something narrows the
    grant (F3/K7's whole question: `esql`'s FROM target is never `confine_index`'d — g6/r19,
    and P2 executed a DENIED esql running to completion on the direct-registry path).

    The SHELL fetch is answered here, so a scenario's `answer` serves calls 2..n."""
    answer = _shell_answer(shell, signal_index, answer)

    def _search_verb(name: str):
        def _fn(ctx: VerbContext, *, native_query: str, start: str | None = None,
                end: str | None = None, limit: int = 20, index: str | None = None,
                sort: str = "desc") -> dict:
            params = {"native_query": native_query, "start": start, "end": end,
                      "limit": limit, "index": index, "sort": sort}
            rec.record(name, ctx, params)
            return answer(name, params)
        return _fn

    def _esql(ctx: VerbContext, *, query: str) -> dict:
        rec.record("esql", ctx, {"query": query})
        return {"query": query, "columns": [], "row_count": 0, "values": []}

    return FakeVerbs({"elastic": {
        "query": _search_verb("query"), "alerts": _search_verb("alerts"), "esql": _esql,
    }})


# ─── the driven run ─────────────────────────────────────────────────────────────────────

@dataclass
class Res:
    """One driven replay: the run dir, the two replay models, the verb recorder, and lazy
    readers for every artifact lead-0 is supposed to have touched."""

    run_dir: Path
    main: ReplayFn
    gather: ReplayFn | None
    rec: VerbRecorder
    summary_dict: dict = field(default_factory=dict)
    stores: list = field(default_factory=list)
    alert_id: str | None = None

    # -- what MAIN was handed ------------------------------------------------------------
    @property
    def message_zero(self) -> str:
        """The flattened message history at MAIN's FIRST request — message 0, ORIENT text
        included. `d1`'s whole observable is that lead-0's work is already in it."""
        assert self.main.seen, "main was never asked for a turn — the run died before ORIENT"
        return self.main.seen[0]

    @property
    def second_request(self) -> str:
        """The flattened history at MAIN's SECOND request — where `d23` says item 3's summary
        must have arrived. Written against the REQUEST boundary, never "before PLAN": r17
        (executed) establishes ORIENT/PLAN are prompt phases with no runtime referent."""
        assert len(self.main.seen) >= 2, "main never made a second request"
        return self.main.seen[1]

    def section(self, salt: str = SALT) -> str:
        """Lead-0's ORIENT section BODY — the text inside its own untrusted frame.

        Sliced on the frame rather than on the next `##` deliberately: a forged `##` inside
        the frame reads as evidence text (K1), so a heading-to-heading slice would be reading
        the injection's own boundary.

        Each precondition is its own `assert` (never a bare `.index()`) so a caller that
        never got a lead-0 section at all fails here on an AssertionError naming what is
        missing, not on a generic `ValueError: substring not found` `spec-graph nullstub`
        would classify as riding machinery rather than discriminating."""
        assert LEAD_ZERO_HEADING in self.message_zero, \
            "message 0 carries no lead-0 section — the resolution did not happen before ORIENT"
        head = self.message_zero.index(LEAD_ZERO_HEADING)
        open_tag, close_tag = f"<run-{salt}-untrusted>", f"</run-{salt}-untrusted>"
        assert open_tag in self.message_zero[head:], \
            "lead-0's heading appears with no untrusted-frame open tag after it"
        start = self.message_zero.index(open_tag, head) + len(open_tag)
        assert close_tag in self.message_zero[start:], \
            "lead-0's untrusted frame opens but never closes"
        return self.message_zero[start:self.message_zero.index(close_tag, start)]

    # -- item 1's two-stage call record ---------------------------------------------------
    @property
    def shell_call(self):
        """Item 1's FIRST backend call — the by-`alert_id` fetch of the alert's own shell
        document, which is where `kibana.alert.group.id` is read (F4 arm (b))."""
        assert self.rec.calls, "item 1 issued no backend call at all — not even the shell fetch"
        return self.rec.calls[0]

    @property
    def ancestor_calls(self) -> list:
        """Every call AFTER the shell fetch: the branch item 1 took once it knew whether this
        alert is an EQL sequence. One per distinct mapped backing index, never one per
        ancestor — so the ordinary alert is exactly one of these, and item 1 is two calls.

        It NAMES call 0 rather than assuming it. A bare `rec.calls[1:]` is satisfied by an
        implementation whose first call is anything at all, and eleven tests read this
        property — so the shell fetch's identity was carried on behalf of all of them by the
        five tests that pin the verb sequence, and narrowing any of those five would have
        unmoored the rest silently. The check is here, once, where every reader gets it."""
        assert self.rec.calls, "item 1 issued no backend call at all"
        first = self.rec.calls[0]
        assert self.alert_id is None or self.alert_id in first.params.get("native_query", ""), (
            f"call 0 was not the by-alert_id shell fetch — it carried "
            f"{first.params.get('native_query')!r}, so every assertion below about 'the "
            "ancestor calls' is really about whatever this implementation did first"
        )
        return self.rec.calls[1:]

    # -- the run dir ---------------------------------------------------------------------
    @property
    def rows(self) -> list[dict]:
        return read_jsonl_rows(RunPaths(self.run_dir).executed_queries)

    def rows_for(self, lead: str) -> list[dict]:
        return [r for r in self.rows if r.get("lead_id") == lead]

    def sidecar(self, lead: str) -> dict:
        path = self.run_dir / "gather_raw" / f"{lead}.lead.json"
        assert path.is_file(), f"no leads-table row for {lead}: {self.gather_raw_names()}"
        return json.loads(path.read_text(encoding="utf-8"))

    def has_sidecar(self, lead: str) -> bool:
        return (self.run_dir / "gather_raw" / f"{lead}.lead.json").is_file()

    def gather_raw_names(self) -> list[str]:
        root = self.run_dir / "gather_raw"
        return sorted(p.name for p in root.iterdir()) if root.is_dir() else []

    def payloads(self, lead: str) -> list[str]:
        root = self.run_dir / "gather_raw" / lead
        return sorted(p.name for p in root.iterdir()) if root.is_dir() else []

    def lead_summary(self, lead: str) -> str:
        return (self.run_dir / "gather_summaries" / f"{lead}.md").read_text(encoding="utf-8")

    @property
    def budget(self) -> dict:
        path = self.run_dir / "budget.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    @property
    def breaker(self) -> dict:
        path = self.run_dir / "circuit_breaker.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    @property
    def denials(self) -> list[dict]:
        return read_jsonl_rows(self.run_dir / observe.POLICY_DENIALS)

    @property
    def investigation(self) -> str:
        path = self.run_dir / "investigation.md"
        return path.read_text(encoding="utf-8") if path.is_file() else ""


def materialize_alert(root: Path, doc: dict) -> Path:
    """The on-disk run dir a driven run starts from — `_replay_harness.materialize`'s shape,
    but writing a SYNTHESIZED alert rather than copying a golden."""
    run_dir = root / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")
    return run_dir


READ_ALERT = "read the alert"
CORRELATION_SUMMARY = "3 same-signature alerts on-host, 11 fleet-wide, none benign-explained."


def run(  # noqa: PLR0913 — a scenario builder: one parameter per thing a scenario varies
    root: Path,
    *,
    alert: dict | None = None,
    answer: Answer | None = None,
    shell: Any = SHELL_DEFAULT,
    verbs: Any = ...,
    main_turns: list[Turn] | None = None,
    gather_turns: list[Turn] | None = None,
    run_id: str = "lz808",
    salt: str = SALT,
    limits: dict | None = None,
    store_factory: Any = None,
    stores: list | None = None,
    before: Callable[[Path], None] | None = None,
) -> Res:
    """Drive a REAL `run_investigation` over a synthesized alert.

    `verbs` defaults to an `elastic_backend` over `answer`; pass `verbs=None` explicitly for
    the K12 scenario in which no registry is injected at all — 61 of 96 `drive()` sites omit
    `verbs=` (P9, executed), and that is the state lead-0 must not acquire a backend from.

    `shell` is what item 1's by-`alert_id` fetch RETURNS: a `shell_doc()` with no group id
    (the default, and the state of all five checked-in fixtures), a `shell_doc(group_id=…)`
    for the sequence path, `[]` for "unresolvable by alert_id", or an exception to raise.
    `answer` therefore serves only the calls AFTER the shell fetch.

    `before(run_dir)` runs on the materialized run dir just before the driver starts — the
    seam a scenario needs to plant a REAL fault in the tree the run is about to write into
    (a directory squatting an artifact's own name, a pre-claimed lead sidecar).

    MAIN's default script makes TWO requests (a read, then a text turn) because `d23`'s
    observable lives at the second one; the gather model answers item 3's dispatch with the
    kind of summary `d16`'s dimensions ask for."""
    doc = alert if alert is not None else alert_doc()
    run_dir = materialize_alert(root, doc)
    rec = VerbRecorder()
    registry = (
        elastic_backend(rec, answer if answer is not None else answer_hits([]), shell=shell,
                        signal_index=doc.get("signal_index", ALERTS_INDEX))
        if verbs is ... else verbs
    )
    main = ReplayFn(main_turns if main_turns is not None else [
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(gather_turns if gather_turns is not None
                      else [Turn(text=CORRELATION_SUMMARY)])
    if before is not None:
        before(run_dir)
    sink = stores if stores is not None else []
    kw: dict[str, Any] = {}
    if registry is not None:
        kw["verbs"] = registry
    if limits is not None:
        kw["limits"] = limits
    if store_factory is not None:
        kw["store_factory"] = store_factory
    out = drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather, **kw)
    return Res(run_dir, main, gather, rec, out or {}, sink, doc.get("alert_id"))


def defender_dir() -> Path:
    return DEFENDER
