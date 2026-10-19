"""#767 — what a gather lead's capture holds of a ticket reply: the store's answer, whole, through the real query tool."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.support.runtime.engine._spec767 import CLOSED_STATUS, shipped_comment_author  # noqa: E402
from defender.tests.support.learning.curation._verb_authorization_632 import (  # noqa: E402
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
    """The e2e seed (the `d6_e2e_seed` clause)."""
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
    """A ticket system whose `list-tickets` answers the next seeded store state per call."""
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
    reader's own edge."""
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
    """d_archived_world_carries_only_screened_capture, after #1221."""
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
    """d_capture_not_retroactively_scrubbed — NEGATIVE, settled premise 41."""
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
