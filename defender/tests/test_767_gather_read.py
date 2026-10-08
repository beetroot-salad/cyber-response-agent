"""#767 — what a gather lead's CAPTURE holds of a ticket reply (since #1221: the store's answer).

Three demands of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`, named by their
`discharged_by`. They need the whole pipe: what the capture persists is a statement about
everything between `handler(args)` and `_record`, and nothing short of driving the real query
tool can observe it. #1221 removed D4's release screen from that span, so the capture, the
archive surface and the model's turn now all hold the reply as the store answered it — an open
case's comments included — and a case re-opened between two reads changes neither read.

Sited in `tests/` rather than in `tests/e2e/` and carrying `pytestmark = pytest.mark.e2e`, the
way `tests/test_denial_gather_632.py` already does: the marker is what CI selects on, and the
spec-graph checkers scan the suite directory the graph names without descending into it.

Built on the machinery that already exists — `tests/_verb_authorization_632.run_gather` drives
a REAL run whose main agent dispatches one gather lead against an INJECTED verb registry, with
the query tool, the grant decision, the capture capability, the payload view and the two tables
all production. A new scenario is a verb table and two `Turn`s, not fresh plumbing.

THE MAPPING IS THE SHIPPED ONE HERE, deliberately: a driven run reads the committed playground
tenant's settings (#1106) for its mapping and its grants alike, so repointing it at a fixture
tenant would change the run rather than the mapping. The agent identity is therefore READ OFF
the shipped file (`shipped_comment_author`), which also makes these tests a statement about the
file an operator edits (O5). A closed case's status is the store's own `closed`
(`CLOSED_STATUS`): since #1221's amendment the mapping names no released status at all.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests._spec767 import CLOSED_STATUS, shipped_comment_author  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DONE,
    ScopedFakeVerbs,
    grant_of,
    q,
    run_gather,
)

pytestmark = pytest.mark.e2e

CLOSED_KEY = "SOC-CLOSED"
OPEN_KEY = "SOC-OPEN"
SERVED_TEXT = "LATEST-AGENT-NOTES-on-a-closed-case"
EARLIER_TEXT = "OLDER-AGENT-NOTES-on-the-same-closed-case"
ANALYST_TEXT = "an-analysts-own-note-on-the-closed-case"
WITHHELD_TEXT = "AGENT-NOTES-on-a-case-nobody-closed"
OPEN_ANALYST_TEXT = "an-analysts-note-on-the-open-case"
CORRELATION_SUMMARY = "brute force against the jump host"


def _comment(author: str, body: str) -> dict[str, Any]:
    return {"author": author, "body": body, "created": "2026-09-16T12:00:00Z"}


def _seed(author: str, *, closed: bool = True) -> dict[str, Any]:
    """The e2e seed (the `d6_e2e_seed` clause): one closed case carrying two agent comments
    and an analyst's, one open case carrying an agent's and an analyst's. `closed=False`
    re-opens the first case, which the no-retroactive-scrub demand drives across two calls in
    one run."""
    closed_ticket = {
        "key": CLOSED_KEY,
        "summary": CORRELATION_SUMMARY,
        "status": CLOSED_STATUS if closed else "in_progress",
        "labels": ["sig:5710"],
        "comments": [
            _comment(author, EARLIER_TEXT),
            _comment("analyst", ANALYST_TEXT),
            _comment(author, SERVED_TEXT),
        ],
    }
    open_ticket = {
        "key": OPEN_KEY,
        "summary": "a second case on the same host",
        "status": "open",
        "labels": ["sig:5710"],
        "comments": [_comment(author, WITHHELD_TEXT), _comment("analyst", OPEN_ANALYST_TEXT)],
    }
    return {"total": 2, "tickets": [closed_ticket, open_ticket]}


def _registry(payloads: list[dict[str, Any]]) -> ScopedFakeVerbs:
    """A ticket system whose `list-tickets` answers the next seeded store state per call.

    A fake of the STORE: it hands back an envelope and classifies nothing.
    The grant is gather's real one for this pair (`ticket.list-tickets`, c2)."""
    served: list[dict[str, Any]] = []

    def list_tickets(ctx: VerbContext, *, label: str = "", **rest: Any) -> Any:
        payload = payloads[min(len(served), len(payloads) - 1)]
        served.append(payload)
        return copy.deepcopy(payload)

    def health_check(ctx: VerbContext, **rest: Any) -> Any:
        return {"status": "ok"}

    table = {"ticket": {"list-tickets": list_tickets, "health-check": health_check}}
    return ScopedFakeVerbs(table, grant_of("gather", (("ticket", "list-tickets"),)))


def _rows_with_payloads(run) -> list[tuple[dict, Any]]:
    out = []
    for row in run.own_evidence:
        rel = row.get("payload_path")
        if not rel:
            continue
        path = run.run_dir / rel
        assert path.is_file(), f"the queries table names a payload file that is absent: {rel}"
        out.append((row, json.loads(path.read_text(encoding="utf-8"))))
    return out


def test_767_the_capture_carries_the_store_payload(tmp_path: Path):
    """d_capture_carries_the_screened_payload, after #1221 — COHERENCE, bound at the UNMOVED
    reader's own edge. The offline collectors join on `executed_queries.jsonl` and
    `gather_raw/`, and they inherit EXACTLY the reply the store gave: the capture equals the
    store's answer, so an open case's comments — an agent's and an analyst's — are as present
    in the capture as in the model's turn. (#1221 removed the release screen that ran between
    the handler and `_record` and once dropped them.)"""
    seed = _seed(shipped_comment_author())
    run = run_gather(
        tmp_path, verbs=_registry([seed]),
        system="ticket", turns=[q("ticket", "list-tickets"), DONE], run_id="s767-capture",
    )

    captured = _rows_with_payloads(run)
    assert [payload for _, payload in captured] == [seed], (
        "the capture is not the store's answer — something between the handler and `_record` "
        "transformed the ticket reply"
    )
    turn = "\n".join(run.gather.seen)
    for text in (SERVED_TEXT, EARLIER_TEXT, ANALYST_TEXT, WITHHELD_TEXT, OPEN_ANALYST_TEXT):
        assert text in turn, f"the model never saw {text}"


def test_767_an_archived_world_carries_the_capture_whole(tmp_path: Path):
    """d_archived_world_carries_only_screened_capture, after #1221. A branched world's staged
    tree carries only what the ORDINARY capture already wrote (F8/F9; the branch estate's
    stagers cover elastic and nothing else), and since #1221 that capture is the store's whole
    answer — so the surface a world archives holds every comment the store served, an open
    case's included, and nothing the capture did not write.

    Asserted over the whole surface a world archives — `executed_queries.jsonl` and every file
    under `gather_raw/` — because the archive copies the tree and not a row."""
    run = run_gather(
        tmp_path, verbs=_registry([_seed(shipped_comment_author())]),
        system="ticket", turns=[q("ticket", "list-tickets"), DONE], run_id="s767-archive",
    )

    surface: dict[str, str] = {}
    table = run.run_dir / "executed_queries.jsonl"
    if table.is_file():
        surface[table.name] = table.read_text(encoding="utf-8")
    for f in sorted((run.run_dir / "gather_raw").rglob("*")):
        if f.is_file():
            surface[str(f.relative_to(run.run_dir))] = f.read_text(encoding="utf-8", errors="replace")

    assert surface, "the run left no evidence surface for a world to archive"
    joined = "\n".join(surface.values())
    for text in (SERVED_TEXT, WITHHELD_TEXT, OPEN_ANALYST_TEXT):
        assert text in joined, f"{text} is missing from the surface a branched world archives"


def test_767_a_later_revocation_does_not_touch_an_existing_capture(tmp_path: Path):
    """d_capture_not_retroactively_scrubbed — NEGATIVE, settled premise 41. A re-open after
    the fact does not touch an already-persisted capture: nothing is a retroactive scrub.

    Driven as the pair the premise describes, inside ONE run: the same store is read twice,
    with the case RE-OPENED between the calls, so the first capture and the second are both
    on disk and can be compared. The first must still hold what it held. Since #1221 a ticket's
    lifecycle state decides nothing about what is served, so the second holds the re-opened
    case's comments too — each capture is exactly the store's answer at its call.

    Its positive control is `d_capture_carries_the_screened_payload` — a capture that DOES
    carry the agent text — so "the earlier capture is untouched" is not "no capture was ever
    written".

    KNOWN LIMIT, stated rather than implied: this demand is about the absence of a scrub, and
    no mechanism in this design could produce one. It is written to fail if a future retention
    or revocation feature reaches back into a written run dir."""
    author = shipped_comment_author()
    before, reopened = _seed(author), _seed(author, closed=False)
    run = run_gather(
        tmp_path,
        verbs=_registry([before, reopened]),
        system="ticket",
        turns=[
            q("ticket", "list-tickets", {"label": "first"}),
            q("ticket", "list-tickets", {"label": "second"}),
            DONE,
        ],
        run_id="s767-revocation",
    )

    captured = _rows_with_payloads(run)
    assert len(captured) == 2, (
        f"expected two captured ticket reads, saw {len(captured)} — the scenario cannot "
        "compare a capture written before a revocation with one written after"
    )
    first, second = (payload for _, payload in captured)

    assert first == before, "the first capture was altered after the case was re-opened"
    assert second == reopened, (
        "the second read is not the store's answer — the re-opened case's lifecycle state "
        "changed what was served"
    )
