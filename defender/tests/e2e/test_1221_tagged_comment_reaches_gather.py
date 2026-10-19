"""#1221 e2e: a comment an earlier run posted (real ticket writer) reaches a later run's gather whole and tagged, beside the later run's own case; nothing is screened out."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import case_ticket  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.support.runtime.engine._spec767 import FakeStore, make_run, record, require  # noqa: E402
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

#: The later run — the one gathering — and so the key of its own case.
SELF = "20261008t120000z-1221-later-run"
#: The earlier run whose recorded investigation is on an open case.
PRIOR = "20261001t090000z-1221-prior-run"
LEAD = "l-001"
ENRICHMENT = "OWN-CASE-ENRICHMENT-1221: the host is a CI runner owned by build-infra"
PRIOR_NOTES = "PRIOR-RUN-NOTES-1221: the binary is the fleet's packaged metrics shipper"
DONE = Turn(text="Summary: ticket correlation complete.")


class _Reading(ReplayFn):
    """`ReplayFn` that also keeps the system prompt (`instructions`) each request carried —
    gather's prompt reaches the model there, not as a message part."""

    def __init__(self, turns: list[Turn]):
        super().__init__(turns)
        self.instructions: list[str] = []

    def __call__(self, messages, info):  # noqa: ANN001 — FunctionModel's own callable shape
        self.instructions.append(info.instructions or "")
        return super().__call__(messages, info)


def _q(system: str, verb: str, params: dict) -> Turn:
    return Turn(tool_calls=[("query", {"system": system, "verb": verb, "params": params})])


def _drive(tmp_path: Path, *, verbs: FakeVerbs, turns: list[Turn], system: str) -> tuple[
        Path, ReplayFn, _Reading]:
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id=SELF)
    assert run_dir.name == SELF, "the fixture must use the Run-derived identity"
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": "correlate ticket context",
            "what_to_summarize": ["related cases, their lifecycle state and their notes"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = _Reading(turns)
    drive(run_dir, run_id=SELF, main=main, gather=gather, verbs=verbs)
    return run_dir, main, gather


def _delta(model: ReplayFn) -> str:
    """What the drive added to the model's history past its first request — the channel a tool result comes back..."""
    head = model.seen[0]
    assert model.seen[-1].startswith(head), "the flattened history is not append-only"
    return model.seen[-1][len(head):]


def _capture(run_dir: Path) -> Any:
    return json.loads((run_dir / "gather_raw" / LEAD / "0.json").read_text(encoding="utf-8"))


def test_a_posted_agent_comment_on_an_open_case_reaches_gather_beside_the_own_case(tmp_path):
    """The writer's posted body, served back on an open case beside the gathering run's own case, reaches the..."""
    tag = require(case_ticket, "agent_comment_tag", "#1221 M1: the agent tag line")(PRIOR)

    prior_dir = make_run(tmp_path / "prior", name=PRIOR, body=PRIOR_NOTES)
    store = FakeStore()
    record(prior_dir, store)
    posted = store.only_comment()
    assert posted["body"].startswith(tag + "\n"), "the writer posted an untagged comment"

    listing = {"total": 2, "source": "ticket-store", "tickets": [
        {"key": SELF, "summary": "the case under investigation", "status": "open",
         "labels": ["sig:5710"],
         "comments": [{"author": "customer-soc", "body": ENRICHMENT,
                       "created": "2026-10-08T11:59:00Z"}]},
        {"key": PRIOR, "summary": "an earlier case on the same rule", "status": "open",
         "labels": ["sig:5710"],
         "comments": [{**posted, "created": "2026-10-01T09:30:00Z"}]},
    ]}
    rec = VerbRecorder()

    def list_tickets(ctx: VerbContext, *, status: str | None = None, label: str | None = None,
                     q: str | None = None) -> dict:
        rec.record("list-tickets", ctx, {"status": status, "label": label, "q": q})
        return copy.deepcopy(listing)

    run_dir, main, gather = _drive(
        tmp_path, verbs=FakeVerbs({"ticket": {"list-tickets": list_tickets}}),
        turns=[_q("ticket", "list-tickets", {"label": "sig:5710"}), DONE], system="ticket")

    assert rec.only().params["label"] == "sig:5710"
    assert _capture(run_dir) == listing, "the captured reply is not what the store answered"
    seen = _delta(gather)
    for needle, what in ((SELF, "the run's own case"), (ENRICHMENT, "its enrichment note"),
                         (PRIOR, "the prior run's case"), (PRIOR_NOTES, "the prior run's notes"),
                         (json.dumps(tag)[1:-1], "the agent tag line naming the prior run")):
        assert needle in seen, f"{what} never reached the gather model"
