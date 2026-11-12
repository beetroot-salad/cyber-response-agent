"""#1278 A4 O13 (master brief: the import refuses while a feedback record exists; the cutover never removes one).

#1414's tick kept seven record folders, a lessons channel, a retained-delivery record and commit rows on `feedback/`
branches under `<T>/learning`. Q1 is ruled as refusal: every such record makes `import_learning_state` raise `ImportRefused`
naming it, import nothing and change no file, and `cut_over_learning_state` leaves the record in place. The scenes are
`test_import_1278.py`'s (`world`, `refused_import`, `imported`).
"""
from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from defender.tests.learning.store_1278.test_import_1278 import (  # noqa: F401 — fixtures and helpers
    imported,
    refused_import,
    world,
)
from defender.tests.support.learning.core import _legacy1278 as legacy
from defender.tests.support.learning.core._store1278 import finding, store_mod

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

RUN = "11111111-1111-4111-8111-111111111111"
REQUEST = {"case_id": "case-1", "tenant_id": "t", "run_id": RUN, "outcome": "aborted", "lookups": []}
CASE = {**REQUEST, "issue": 7, "listed": True}
ITEM = {"comment_id": 101, "author": "ann", "created": "2026-11-10T10:00:00Z", "body": "x", "issue": 7,
        "issue_url": "https://forge.invalid/issues/7", "attempts": 1}
DECISION = {"comment_id": 101, "approved": [], "review_by": None, "instruction": "do x", "no_change": None,
            "unapprovable": None, "settled": False}
LESSONS_ROW = {"comment_id": "101", "issue": 7, "author": "ann", "case_id": "case-1", "instruction": "do x"}

#: The feedback records #1414 kept (a4.md 'The records, today and after'), as `(path under the learning root, content)`;
#: the id is what the refusal must name.
RECORDS = {
    "request": (f"feedback-issue-queue/case-1--{RUN}.json", REQUEST),
    "case record": (f"feedback-cases/{RUN}.json", CASE),
    "seen ids": ("feedback-seen/7.json", {"ids": [101, 102]}),
    "comment cursor": ("feedback-cursor/comments.json", {"since": "2026-11-10T10:00:00Z"}),
    "item": ("feedback-items/101.json", ITEM),
    "decision": ("feedback-decisions/101.json", DECISION),
    "lessons row": ("_pending/feedback_lessons.jsonl", LESSONS_ROW),
    "retained delivery": ("_pending_delivery/feedback-b1.json", {
        "branch": "feedback/aaaaaaaaaaaa", "batch_id": "b1", "label": "feedback_drain", "reason": "push refused",
        "at": legacy.STAMP}),
}


def _plant(root: Path, rel: str, body: dict) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(body, sort_keys=True)
    path.write_text(text + "\n" if rel.endswith(".jsonl") else text, encoding="utf-8")


@pytest.mark.parametrize("name", sorted(RECORDS))
async def test_o13_a_feedback_record_makes_the_import_refuse_naming_it_and_the_cutover_keeps_it(world, name):  # noqa: F811 — the imported fixture
    """Whichever feedback record the tenant holds, beside ordinary queued work, the import is refused naming that record, imports nothing and changes no file; the cutover then does not remove it. (O13, Q1 b)"""
    rel, body = RECORDS[name]
    legacy.queue(world.root, "finding", [finding("f1")])
    _plant(world.root, rel, body)

    await refused_import(world, Path(rel).name)

    with contextlib.suppress(Exception):
        store_mod().cut_over_learning_state(world.t.tenant, world.root)
    assert (world.root / rel).is_file(), "the cutover removed a feedback record the import did not take"


async def test_o13_a_commit_row_on_a_feedback_branch_makes_the_import_refuse_naming_the_branch(world):  # noqa: F811 — the imported fixture
    """The commit record holds a row for a `feedback/` branch: the import is refused naming it and nothing is imported. (O13, Q1 b)"""
    legacy.commit_record(world.root, [legacy.commit_row("a" * 40, "feedback/aaaaaaaaaaaa", "1" * 40, "0011223344556677",
                                                         lanes=("skills",), changes=[("agent/skills/tacit-knowledge/registry.yaml", "2" * 40, "3" * 40)])])

    await refused_import(world, "feedback/aaaaaaaaaaaa")


async def test_o13_control_a_tenant_with_no_feedback_record_imports_as_before(world):  # noqa: F811 — the imported fixture
    """Positive control: the same scene with no feedback record imports its queued finding. (O13)"""
    legacy.queue(world.root, "finding", [finding("f1")])

    done = await imported(world)

    assert {key: item.status for (_k, key), item in done.items.items()} == {"f1": "waiting"}
