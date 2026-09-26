"""#767 — what a gather lead's CAPTURE holds after D4's screen has run.

Three demands of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`, named by their
`discharged_by`. These are the ones that genuinely need the whole pipe: the screen runs
strictly between `handler(args)` and `_record` (F8/r5), so what the capture persists is a
statement about the ORDER of two production frames, and nothing short of driving the real
query tool can observe it.

Sited in `tests/` rather than in `tests/e2e/` and carrying `pytestmark = pytest.mark.e2e`, the
way `tests/test_denial_gather_632.py` already does: the marker is what CI selects on, and the
spec-graph checkers scan the suite directory the graph names without descending into it.

Built on the machinery that already exists — `tests/_verb_authorization_632.run_gather` drives
a REAL run whose main agent dispatches one gather lead against an INJECTED verb registry, with
the query tool, the grant decision, the capture capability, the payload view and the two tables
all production. A new scenario is a verb table and two `Turn`s, not fresh plumbing.

THE MAPPING IS THE SHIPPED ONE HERE, deliberately: a driven run reads the committed playground
tenant's settings (#1106) for its mapping and its grants alike, so repointing it at a fixture
tenant would change the run rather than the mapping. The released status and the agent identity are therefore READ OFF
the shipped file (`shipped_released_status_and_author`), which also makes these tests a
statement about the file an operator edits (O5).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests._spec767 import shipped_released_status_and_author  # noqa: E402
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


def _seed(released: str, author: str, *, closed: bool = True) -> dict[str, Any]:
    """The e2e seed (the `d6_e2e_seed` clause): one closed case carrying two agent comments
    and an analyst's, one open case carrying an agent's and an analyst's. `closed=False`
    re-opens the first case, which is what the retroactive-scrub demand drives across two
    calls in one run."""
    closed_ticket = {
        "key": CLOSED_KEY,
        "summary": CORRELATION_SUMMARY,
        "status": released if closed else "in_progress",
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

    A fake of the STORE, not of the screen: it hands back an envelope and classifies nothing.
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


def test_767_the_capture_carries_the_screened_payload(tmp_path: Path):
    """d_capture_carries_the_screened_payload — COHERENCE, settled premise 49, bound at the
    UNMOVED reader's own edge. The offline collectors join on `executed_queries.jsonl` and
    `gather_raw/`, and they inherit EXACTLY the screened payload: a comment D4 dropped is as
    absent from the capture as it is from the model's turn.

    The screen runs strictly after `handler(args)` and strictly before `_record` (F8/r5), so
    the capture persists the screened payload BY CONSTRUCTION — and that is precisely why it
    has to be observed rather than reasoned about: the whole property is the order of two
    production frames, and a screen moved one line later leaves the capture holding the
    unscreened record while every unit-level assertion about the screen stays green.

    Bound at this reader's own edge rather than at the boundary's altitude, per R7: a demand
    on `case_history_store` would read green with only the model's turn observed."""
    released, author = shipped_released_status_and_author()
    run = run_gather(
        tmp_path, verbs=_registry([_seed(released, author)]),
        system="ticket", turns=[q("ticket", "list-tickets"), DONE], run_id="s767-capture",
    )

    captured = _rows_with_payloads(run)
    assert captured, "the lead's ticket read left no evidence row at all"
    blob = json.dumps([payload for _, payload in captured])

    for text in (SERVED_TEXT, EARLIER_TEXT, ANALYST_TEXT):
        assert text in blob, (
            f"{text} is absent from the capture — a closed case is served WHOLE, and every "
            "absence asserted below could otherwise be green for any reason at all"
        )
    for text in (WITHHELD_TEXT, OPEN_ANALYST_TEXT):
        assert text not in blob, (
            f"the capture persisted {text} from an OPEN case — the screen runs after the "
            "handler and before `_record`, and this is what that ordering is FOR"
        )
    assert "a second case on the same host" in blob, (
        "the open case's non-comment fields were dropped from the capture (N5)"
    )

    turn = "\n".join(run.gather.seen)
    assert SERVED_TEXT in turn, "the model never saw the closed case's comment"
    assert WITHHELD_TEXT not in turn, "the model's turn carries the withheld comment"


def test_767_an_archived_world_carries_only_the_screened_capture(tmp_path: Path):
    """d_archived_world_carries_only_screened_capture — settled premise 44. A branched
    world's staged tree carries only what the ORDINARY capture already wrote, and that was
    written after the screen (F8/F9). There is no ticket-specific staging mechanism at all
    (g12: the branch estate's stagers cover elastic and nothing else), so "what a world
    carries" is exactly "what is on the run dir's evidence surface".

    Asserted over the whole surface a world archives — `executed_queries.jsonl` and every file
    under `gather_raw/` — rather than over the one payload the previous demand reads, because
    the archive copies the tree and not a row."""
    released, author = shipped_released_status_and_author()
    run = run_gather(
        tmp_path, verbs=_registry([_seed(released, author)]),
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
    assert SERVED_TEXT in joined, "nothing screened reached the surface — the assertion is vacuous"
    for withheld, why in (
        (WITHHELD_TEXT, "an open case's agent comment"),
        (OPEN_ANALYST_TEXT, "an open case's analyst comment"),
    ):
        offenders = sorted(k for k, v in surface.items() if withheld in v)
        assert not offenders, (
            f"{why} is on the tree a branched world archives, in {offenders} — a world's "
            "staged tree carries only what the capture wrote, so anything here reaches a "
            "later model with no screen between"
        )


def test_767_a_later_revocation_does_not_touch_an_existing_capture(tmp_path: Path):
    """d_capture_not_retroactively_scrubbed — NEGATIVE, settled premise 41. A revocation after
    the fact does not touch an already-persisted capture: O2 binds each read AT READ TIME, and
    nothing in D1-D8 is a retroactive scrub. Future reads correctly stop serving.

    Driven as the pair the premise describes, inside ONE run: the same store is read twice,
    with the case RE-OPENED between the calls, so the first capture and the second are both
    on disk and can be compared. The first must still hold what it lawfully held; the second
    must hold nothing.

    Its positive control is `d_capture_carries_the_screened_payload` — a capture that DOES
    carry screened agent text — so "the earlier capture is untouched" is not "no capture was
    ever written".

    KNOWN LIMIT, stated rather than implied: this demand is about the absence of a scrub, and
    no mechanism in this design could produce one. It is written to fail if a future retention
    or revocation feature reaches back into a written run dir."""
    released, author = shipped_released_status_and_author()
    run = run_gather(
        tmp_path,
        verbs=_registry([_seed(released, author), _seed(released, author, closed=False)]),
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

    assert SERVED_TEXT in json.dumps(first), (
        "the first read captured nothing the revocation could have removed"
    )
    assert SERVED_TEXT not in json.dumps(second), (
        "the second read served the comment after the case was re-opened — O2 binds each "
        "read at read time"
    )
    assert WITHHELD_TEXT not in json.dumps([first, second])
