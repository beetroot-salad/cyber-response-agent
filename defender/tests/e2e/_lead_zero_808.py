"""Scenario machinery for the #808 harness-executed lead-0 tests."""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.systems.verbs import VerbContext  # noqa: E402
from defender.integrations.elastic_adapter import search_envelope  # noqa: E402
from defender.tests.support.learning.curation._verb_authorization_632 import breaker_doc  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
)

# Production names, spelled exactly as `defender/investigation/lead_zero/` spells them.
L3 = "l-00c"          # item 3's reserved id
LEAD_ZERO_HEADING = "## Alert ancestors"   # the ORIENT section `orientation()` appends
#: The rendered note in `orient.py`'s `_(unavailable: …)_` idiom.
UNAVAILABLE = "_(unavailable:"

# As in the playground tenant's `settings/systems/elastic/config.env` (#1106).
EVENTS_INDEX = "logs-*"
ALERTS_INDEX = ".internal.alerts-security.alerts-default-*"

AUTH_BACKING = ".ds-logs-system.auth-default-2026.05.24-000002"


# the alert

def ancestor(doc_id: str, **over: Any) -> dict:
    """One `ancestor_events[]` entry, shaped like every checked-in fixture's:
    `{id, type=event, index, depth=0}`."""
    return {"id": doc_id, "type": "event", "index": AUTH_BACKING, "depth": 0, **over}


ALERT_ID = "94f777794d60c7c8f112d07b455ed79a41d4f0a0e932fccd94ce0d9914997606"
# The document field the shell fetch retrieves on (`alert_id` is a key of the run-dir
# `alert.json`, not of an alert document). Pinned exactly: "the id appears in the predicate"
# cannot tell `kibana.alert.uuid:"…"` from `_id:"…"`.
ALERT_ID_FIELD = "kibana.alert.uuid"


def alert_doc(*, ancestors: list[dict] | None = None, **over: Any) -> dict:
    """The run-dir `alert.json` a scenario drives; defaults reproduce the sshd golden. Like every
    real one, it carries no `kibana.alert.group.id`: that comes off the shell (`shell_doc`)."""
    doc: dict[str, Any] = {
        "alert_timestamp": "2026-05-25T15:27:22.928Z",
        "rule": {"id": "v2-sshd-success-after-failures", "name": "v2 sshd success after failures",
                 "type": "eql", "severity": "high", "language": "eql",
                 "query": "sequence by host.name with maxspan=10m\n  [any where JOINME]"},
        "reason": "authentication event with process sshd, by dev.dana created high alert.",
        "host": {"name": "office-ws-1"},
        "user": {"name": "dev.dana"},
        "ancestor_events": [ancestor("anc-1"), ancestor("anc-2")]
        if ancestors is None else ancestors,
        "alert_id": ALERT_ID,
        "signal_index": ALERTS_INDEX,
    }
    doc.update(over)
    return doc


def shell_doc(**over: Any) -> dict:
    """The alert's own shell document as item 1's by-`alert_id` fetch returns it (`_source`
    only): the only surface `kibana.alert.group.id` arrives on."""
    return {
        "@timestamp": "2026-05-25T15:27:22.928Z",
        "kibana.alert.rule.name": "v2 sshd success after failures",
        "kibana.alert.uuid": ALERT_ID,
        **over,
    }


def hit(
    *, ts: str, message: str = "Accepted password for dev.dana", host: str = "office-ws-1",
    user: str = "dev.dana", ip: str = "172.18.0.15", **over: Any,
) -> dict:
    """One `_source` document: `_search` strips `_id`/`_index`/`_score`, so a scripted hit
    carries nothing the adapter would not."""
    return {"@timestamp": ts, "message": message, "host.name": host,
            "user.name": user, "source.ip": ip, **over}


# the injected backend

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


SHELL_DEFAULT: Any = object()   # sentinel: "a shell alert that resolves, carrying no group id"


def _shell_answer(shell: Any, index: str, answer: Answer) -> Answer:
    """Compose the shell fetch onto a scenario's ancestor answer, keyed on the call's own
    predicate (`ALERT_ID_FIELD:`), not call order: with no usable `alert_id` the shell fetch is
    skipped and the first call is the ancestor fetch. `shell` is a document (or list), `[]`/`None`
    for "unresolvable by alert_id", or an exception to raise."""
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
    """The injected registry: all three elastic verbs with the real adapter's signatures, so the
    real `validate_params` screen applies and `esql` stays reachable unless the grant narrows it
    (its FROM target is never index-confined). The shell fetch is answered here; a scenario's
    `answer` serves calls 2..n."""
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


# the driven run

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

    # what MAIN was handed
    @property
    def message_zero(self) -> str:
        """The flattened history at MAIN's first request (message 0, ORIENT included), where
        lead-0's work must already be."""
        assert self.main.seen, "main was never asked for a turn — the run died before ORIENT"
        return self.main.seen[0]

    @property
    def second_request(self) -> str:
        """The flattened history at MAIN's second request, where item 3's summary must have
        arrived (a request boundary: ORIENT/PLAN are prompt phases, not runtime events)."""
        assert len(self.main.seen) >= 2, "main never made a second request"
        return self.main.seen[1]

    def section(self) -> str:
        """Lead-0's ORIENT section BODY — the text inside its own untrusted frame."""
        assert LEAD_ZERO_HEADING in self.message_zero, \
            "message 0 carries no lead-0 section — the resolution did not happen before ORIENT"
        head = self.message_zero.index(LEAD_ZERO_HEADING)
        after = self.message_zero[head:]
        opened = re.search(r"<run-([0-9a-f]+)-untrusted>", after)
        assert opened is not None, \
            "lead-0's heading appears with no untrusted-frame open tag after it"
        framed = re.search(
            rf"<run-{opened.group(1)}-untrusted>\n?(.*?)\n?</run-{opened.group(1)}-untrusted>",
            after, re.S,
        )
        assert framed is not None, "lead-0's untrusted frame opens but never closes"
        return framed.group(1)

    # item 1's two-stage call record
    @property
    def shell_call(self):
        """Item 1's first backend call: the by-`alert_id` fetch of the alert's own shell
        document, where `kibana.alert.group.id` is read."""
        assert self.rec.calls, "item 1 issued no backend call at all — not even the shell fetch"
        return self.rec.calls[0]

    @property
    def ancestor_calls(self) -> list:
        """Every call AFTER the shell fetch: the branch item 1 took once it knew whether this
        alert is an EQL sequence. One per distinct mapped backing index, never one per
        ancestor — so the ordinary alert is exactly one of these, and item 1 is two calls."""
        assert self.rec.calls, "item 1 issued no backend call at all"
        first = self.rec.calls[0]
        assert self.alert_id is None or self.alert_id in first.params.get("native_query", ""), (
            f"call 0 was not the by-alert_id shell fetch: it carried "
            f"{first.params.get('native_query')!r}"
        )
        return self.rec.calls[1:]

    # the run dir
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
    def state(self) -> Any:
        """The run's `RunState`, as `drive()` hands it back: where a driven run's budget and
        breaker are read."""
        return self.summary_dict["run_state"]

    @property
    def budget(self) -> dict:
        """The run's budget snapshot, off the run's state (no `budget.json` is written)."""
        return self.state.budget_snapshot()

    @property
    def breaker(self) -> dict:
        return breaker_doc(self.state)

    @property
    def denials(self) -> list[dict]:
        return read_jsonl_rows(RunPaths(self.run_dir).policy_denials)

    @property
    def investigation(self) -> str:
        path = self.run_dir / "investigation.md"
        return path.read_text(encoding="utf-8") if path.is_file() else ""


def materialize_alert(root: Path, doc: dict) -> Path:
    """The on-disk run dir a driven run starts from — `_replay_harness.materialize`'s shape,
    but planting a SYNTHESIZED alert (and the record the front door settles beside it) rather
    than copying a golden."""
    from defender.tests.support.storage import _alert_plant

    # A run folder's name is its canonical UUID run id (#1187).
    run_dir = root / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True)
    _alert_plant.plant_alert(run_dir, doc)
    return run_dir


#: The scripted gather return for item 3, in the correlation contract's own dimensions (a scoped
#: count, an unscoped count, across any rule). Keep its wording in step with the contract: a
#: stale spelling would let a delivery check pass on a dead term.
CORRELATION_SUMMARY = (
    "3 alerts scoped to user.name dev.dana, 11 unscoped, across any rule."
)


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
    limits: dict | None = None,
    store_factory: Any = None,
    stores: list | None = None,
    before: Callable[[Path], None] | None = None,
    defender_dir: Path | None = None,
    tenant: Any = None,
    agent: Path | None = None,
) -> Res:
    """Drive a real `run_investigation` over a synthesized alert; `agent` runs it as a tenant
    whose agent half (and so catalog) is that tree."""
    doc = alert if alert is not None else alert_doc()
    run_dir = materialize_alert(root, doc)
    rec = VerbRecorder()
    registry = (
        elastic_backend(rec, answer if answer is not None else answer_hits([]), shell=shell,
                        signal_index=doc.get("signal_index", ALERTS_INDEX))
        if verbs is ... else verbs
    )
    main = ReplayFn(main_turns if main_turns is not None else [
        Turn(tool_calls=[("read_file", {"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(gather_turns if gather_turns is not None
                      else [Turn(text=CORRELATION_SUMMARY)])
    gather.serves_correlation = True   # this scenario's gather script is `l-00c`'s (#1222)
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
    if defender_dir is not None:
        kw["defender_dir"] = defender_dir
    if tenant is not None:
        kw["tenant"] = tenant
    if agent is not None:
        kw["agent"] = agent
    out = drive(run_dir, run_id=run_id, main=main, gather=gather, **kw)
    return Res(run_dir, main, gather, rec, out or {}, sink, doc.get("alert_id"))
