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
        salt=SALT,
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


def test_direct_self_get_rejected_before_store_and_capture(tmp_path):
    """The authoritative identity is deps.run_id; a direct self get never reaches the verb."""
    rec = VerbRecorder()
    run = _drive(
        tmp_path,
        verbs=_ticket_registry(rec, get_payload={
            "key": SELF,
            "status": "closed",
            "summary": "SELF-TICKET-SECRET",
        }),
        turns=[_q("ticket", "get-ticket", {"key": SELF}), DONE],
    )

    assert rec.calls == []
    assert len(run.rows) == 1
    assert run.rows[0]["exit_code"] == 64
    assert run.rows[0]["error_class"] == "agent-fixable"
    assert run.payload_text() == ""
    assert "SELF-TICKET-SECRET" not in run.all_model_text
    assert run.breaker.get("total_failures", 0) == 0


def test_list_drops_only_self_and_preserves_open_case_correlation(tmp_path):
    """Identity filtering happens per item before capture; lifecycle state is not a filter."""
    rec = VerbRecorder()
    listing = {
        "tickets": [
            {"key": SELF, "status": "open", "summary": "SELF-LIST-SECRET"},
            {
                "key": "SOC-OPEN",
                "status": "open",
                "summary": "active sibling",
                "description": f"correlates with {SELF}",
            },
            {"key": "SOC-WIP", "status": "in_progress", "summary": "triage in progress"},
            {"key": "SOC-CLOSED", "status": "closed", "summary": "historical sibling"},
            {"status": "open", "summary": "identity missing"},
            "not-a-ticket-object",
        ],
        "total": 6,
        "source": "ticket-store",
    }
    run = _drive(
        tmp_path,
        verbs=_ticket_registry(rec, list_payload=listing),
        turns=[_q("ticket", "list-tickets", {
            "q": "same-host",
            "require_closed": False,
        }), DONE],
    )

    assert rec.only().params["require_closed"] is False
    payload = run.payload()
    assert payload["total"] == 3
    assert payload["source"] == "ticket-store"
    assert [ticket["key"] for ticket in payload["tickets"]] == [
        "SOC-OPEN",
        "SOC-WIP",
        "SOC-CLOSED",
    ]
    assert {ticket["status"] for ticket in payload["tickets"]} == {
        "open",
        "in_progress",
        "closed",
    }
    assert SELF in payload["tickets"][0]["description"], (
        "record-identity exclusion must not erase useful cross-ticket references"
    )
    assert "SELF-LIST-SECRET" not in run.payload_text()
    assert "SELF-LIST-SECRET" not in run.all_model_text
    assert run.rows[0]["exit_code"] == 0


def test_other_open_ticket_get_remains_available_and_persisted(tmp_path):
    """An unrestricted gather get for a different open ticket retains its existing behavior."""
    rec = VerbRecorder()
    other = {
        "key": OTHER,
        "status": "open",
        "summary": "ACTIVE-CASE-CONTEXT",
        "description": f"may be related to {SELF}",
    }
    run = _drive(
        tmp_path,
        verbs=_ticket_registry(rec, get_payload=other),
        turns=[_q("ticket", "get-ticket", {
            "key": OTHER,
            "require_closed": False,
        }), DONE],
    )

    assert rec.only().params == {"key": OTHER, "require_closed": False}
    assert run.payload() == other
    assert "ACTIVE-CASE-CONTEXT" in run.all_model_text
    assert run.rows[0]["exit_code"] == 0


def test_get_response_that_resolves_to_self_is_withheld_before_capture(tmp_path):
    """The response identity is rechecked even when the requested key was not the self key."""
    rec = VerbRecorder()
    run = _drive(
        tmp_path,
        verbs=_ticket_registry(rec, get_payload={
            "key": SELF,
            "status": "open",
            "summary": "MISROUTED-SELF-SECRET",
        }),
        turns=[_q("ticket", "get-ticket", {"key": OTHER}), DONE],
    )

    assert rec.only().params["key"] == OTHER
    assert run.rows[0]["exit_code"] == 1
    assert run.payload_text() == ""
    assert "MISROUTED-SELF-SECRET" not in run.all_model_text
    assert run.breaker.get("total_failures", 0) == 0


@pytest.mark.parametrize(("verb", "params", "payload"), [
    ("get-ticket", {"key": OTHER}, ["not", "a", "ticket"]),
    ("list-tickets", {}, {"tickets": "not-a-list", "total": "unknown"}),
])
def test_malformed_ticket_payload_fails_without_persisting_vendor_content(
    tmp_path, verb, params, payload,
):
    """A top-level shape that cannot be identity-screened becomes an infrastructure fault."""
    rec = VerbRecorder()
    kwargs = {"get_payload": payload} if verb == "get-ticket" else {"list_payload": payload}
    run = _drive(
        tmp_path,
        verbs=_ticket_registry(rec, **kwargs),
        turns=[_q("ticket", verb, params), DONE],
    )

    assert len(rec.calls) == 1
    assert run.rows[0]["exit_code"] == 2
    assert run.rows[0]["error_class"] == "infra"
    assert run.payload_text() == ""
    assert run.breaker["systems"]["ticket"]["failures"] == 1


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
