"""#1221: gather is served a ticket reply exactly as the store answered it (capture and model
view), through a real driven run."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.learning.curation._verb_authorization_632 import (  # noqa: E402
    DONE,
    LEAD,
    ScopedFakeVerbs,
    q,
    run_gather,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402

#: The run's own id — and so the key of the case it is investigating (the lab's case key is
#: the run id).
OWN = "20261008t120000z-1221-own-case"
OPEN_KEY = "SOC-OPEN-1221"
#: Comment text distinctive enough that its presence in the model's view is unambiguous.
OWN_NOTE = "OWN-CASE-ENRICHMENT-1221: the customer's own note on the alerted host"
OPEN_NOTE = "UNRELEASED-COMMENT-1221: an analyst's note on a case nobody has closed"

#: A tenant whose gather grant holds `get-ticket` — the committed fixture's withholds it
#: (`test_gather_is_denied_ticket_get_ticket`), and this test is about the reply, not the grant.
GET_TICKET_TABLE = """dispositions:
  ticket:
    get-ticket: {roles: [gather]}
    health-check: {roles: [gather]}
    list-tickets: {roles: [gather]}
"""


def _ticket(key: str, note: str, *, status: str = "open") -> dict[str, Any]:
    return {"key": key, "summary": f"case {key}", "status": status, "labels": ["sig:5710"],
            "comments": [{"author": "analyst", "body": note, "created": "2026-10-08T11:00:00Z"}]}


def _capture(run_dir: Path, seq: int = 0) -> Any:
    return json.loads((run_dir / "gather_raw" / LEAD / f"{seq}.json").read_text(encoding="utf-8"))


def _list_registry(rec: VerbRecorder, answer: Any) -> ScopedFakeVerbs:
    """`list-tickets` answering `answer`, under the committed fixture tenant's real gather
    grant."""

    def list_tickets(ctx: VerbContext, *, status: str | None = None, label: str | None = None,
                     q: str | None = None) -> Any:
        rec.record("list-tickets", ctx, {"status": status, "label": label, "q": q})
        return copy.deepcopy(answer)

    return ScopedFakeVerbs({"ticket": {"list-tickets": list_tickets}},
                           T1106.fixture_grants().gather)


def test_1221_list_tickets_serves_the_own_case_and_an_open_cases_comments(tmp_path):
    """A `list-tickets` reply carrying the run's OWN case (its key is the run id) and an OPEN
    case — one no person has closed — each with a comment, reaches gather whole."""
    listing = {"total": 2, "source": "ticket-store",
               "tickets": [_ticket(OWN, OWN_NOTE), _ticket(OPEN_KEY, OPEN_NOTE)]}
    rec = VerbRecorder()
    run = run_gather(tmp_path / "envelope", verbs=_list_registry(rec, listing), system="ticket",
                     turns=[q("ticket", "list-tickets", {}), DONE], run_id=OWN)

    assert [c.verb for c in rec.calls] == ["list-tickets"], "the store was not asked"
    assert [r["exit_code"] for r in run.own_rows] == [0], "the listing was refused"
    assert _capture(run.run_dir) == listing, (
        "the captured reply is not what the store answered — a ticket-specific transform ran"
    )
    seen = run.gather_delta
    for needle, what in ((OWN, "the run's own case"), (OWN_NOTE, "the own case's comment"),
                         (OPEN_KEY, "the open case"), (OPEN_NOTE, "the open case's comment")):
        assert needle in seen, f"{what} never reached the gather model"

    bare = [_ticket(OWN, OWN_NOTE), _ticket(OPEN_KEY, OPEN_NOTE)]
    shaped = VerbRecorder()
    run = run_gather(tmp_path / "bare", verbs=_list_registry(shaped, bare), system="ticket",
                     turns=[q("ticket", "list-tickets", {}), DONE], run_id=OWN)
    assert len(shaped.calls) == 1
    assert [r["exit_code"] for r in run.own_rows] == [0], (
        "a bare-array ticket reply was refused — the query tool keeps a ticket-only shape rule"
    )
    assert _capture(run.run_dir) == bare
    assert OWN_NOTE in run.gather_delta, "the own case's comment never reached the model"
    assert OPEN_NOTE in run.gather_delta, "the open case's comment never reached the model"


@pytest.mark.parametrize(("key", "note"), [(OWN, OWN_NOTE), (OPEN_KEY, OPEN_NOTE)],
                         ids=["own-case", "another-open-case"])
def test_1221_get_ticket_on_the_runs_own_key_is_served(tmp_path, key, note):
    """A `get-ticket` on the run's OWN key — and, the sibling surface, on ANOTHER open case's
    key — reaches the store and its reply (an open case with a comment) reaches gather whole."""
    root = tmp_path / "tenants"
    S.plant(root, marker="t1221", table=GET_TICKET_TABLE)
    case = _ticket(key, note)
    rec = VerbRecorder()

    def get_ticket(ctx: VerbContext, *, key: str) -> Any:
        rec.record("get-ticket", ctx, {"key": key})
        return copy.deepcopy(case)

    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id=OWN)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "ticket",
                                     "goal": "read the case's own ticket",
                                     "what_to_summarize": ["what the ticket says"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([q("ticket", "get-ticket", {"key": key}), DONE])
    drive(run_dir, run_id=OWN, main=main, gather=gather,
          verbs=FakeVerbs({"ticket": {"get-ticket": get_ticket}}),
          tenant=S.tenant_folder_of(root))

    assert [(c.verb, c.params) for c in rec.calls] == [("get-ticket", {"key": key})], (
        f"a get-ticket on {key} never reached the store"
    )
    assert _capture(run_dir) == case, "the captured reply is not what the store answered"
    head = gather.seen[0]
    assert gather.seen[-1].startswith(head)
    seen = gather.seen[-1][len(head):]
    assert note in seen, f"{key}'s comment never reached the gather model"


