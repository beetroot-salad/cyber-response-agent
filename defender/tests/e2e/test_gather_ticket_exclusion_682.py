"""#682 — gather may correlate tickets in any lifecycle state, but never its own case.

The ticket adapter remains an unrestricted read surface for gather: open and in-progress
records are useful for correlation and triage.  The gather query boundary owns the narrower
security property instead: the current run's ticket is excluded by identity before either the
model-facing result or the persisted ``gather_raw`` payload is built.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime.lead_zero import RESERVED_LEAD_IDS  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

SALT = "682aabbccddeeff0"
SELF = "20260723T120000Z-self-case-682"
OTHER = "SOC-682"
LEAD = "l-001"
DONE = Turn(text="Summary: ticket correlation complete.")


class _Run:

    def __init__(self, run_dir: Path, gather: ReplayFn):
        self.run_dir = run_dir
        self.gather = gather

    @property
    def rows(self) -> list[dict]:
        return read_jsonl_rows(self.run_dir / "executed_queries.jsonl")

    @property
    def own_rows(self) -> list[dict]:
        """`.rows` filtered to exclude #808's harness-authored leads (`l-000`/`l-00c`) — the
        rows produced by THIS test's own dispatched lead, not lead-0's unconditional
        pre-ORIENT resolution against `GOLDEN_AB3`'s alert."""
        return [r for r in self.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    @property
    def all_model_text(self) -> str:
        return "\n".join(self.gather.seen)

    def payload_text(self, seq: int = 0) -> str:
        return (self.run_dir / "gather_raw" / LEAD / f"{seq}.json").read_text(
            encoding="utf-8",
        )

    def payload(self, seq: int = 0):
        return json.loads(self.payload_text(seq))

    @property
    def breaker(self) -> dict:
        path = self.run_dir / "circuit_breaker.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _q(system: str, verb: str, params: dict) -> Turn:
    return Turn(tool_calls=[("query", {
        "system": system,
        "verb": verb,
        "params": params,
    })])


def _drive(
    tmp_path: Path,
    *,
    verbs: FakeVerbs,
    turns: list[Turn],
    system: str = "ticket",
    run_id: str = SELF,
) -> _Run:
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    assert run_dir.name != run_id, "the fixture must distinguish run_id from the directory name"
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD,
            "system": system,
            "goal": "correlate ticket context",
            "what_to_summarize": ["related cases and their lifecycle state"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    drive(
        run_dir,
        run_id=run_id,
        main=main,
        gather=gather,
        verbs=verbs,
    )
    return _Run(run_dir, gather)


def _ticket_registry(
    rec: VerbRecorder,
    *,
    get_payload: object | None = None,
    list_payload: object | None = None,
) -> FakeVerbs:
    get_result = get_payload if get_payload is not None else {
        "key": OTHER,
        "status": "open",
        "summary": "another active case",
    }
    list_result = list_payload if list_payload is not None else {"tickets": [], "total": 0}

    def get_ticket(
        ctx: VerbContext, *, key: str, require_closed: bool = False,
    ) -> object:
        rec.record("get-ticket", ctx, {"key": key, "require_closed": require_closed})
        return get_result

    def list_tickets(
        ctx: VerbContext,
        *,
        status: str | None = None,
        label: str | None = None,
        q: str | None = None,
        require_closed: bool = False,
    ) -> object:
        rec.record("list-tickets", ctx, {
            "status": status,
            "label": label,
            "q": q,
            "require_closed": require_closed,
        })
        return list_result

    return FakeVerbs({"ticket": {
        "get-ticket": get_ticket,
        "list-tickets": list_tickets,
    }})












def test_non_ticket_payload_with_run_id_is_untouched(tmp_path):
    """The policy is scoped to ticket verbs, not a generic scrub of matching strings."""
    rec = VerbRecorder()
    payload = {"key": SELF, "summary": "ordinary CMDB content"}

    def lookup(ctx: VerbContext, *, host: str) -> dict:
        rec.record("lookup", ctx, {"host": host})
        return payload

    run = _drive(
        tmp_path,
        verbs=FakeVerbs({"cmdb": {"lookup": lookup}}),
        system="cmdb",
        turns=[_q("cmdb", "lookup", {"host": "web-1"}), DONE],
    )

    assert rec.only().params == {"host": "web-1"}
    assert run.payload() == payload
