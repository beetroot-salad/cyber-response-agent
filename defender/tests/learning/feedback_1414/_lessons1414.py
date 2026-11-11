"""#1414 D11 support (A4): the lessons author's feedback channel is the store's `feedback_instruction` work items.

Nothing here implements policy. `instruct` writes one instruction the way the feedback tick does (an issue row, a tick
lease, a comment taken in, one decision carrying the instruction text), through the store's own verbs; the curator
itself is the real feedback curator behind the scripted model (`_curators1278`), driven by `author_drain`.
Every store verb is resolved at call time, so collection never imports code that does not exist yet.

Interface requests this module uses (A4): `enqueue_feedback_issue`, `begin_feedback_tick`, `record_feedback_issue`,
`judge_comments`, `record_decision(held, comment_id, decision, *, instruction=)`, `end_feedback_tick`, `work`,
`claim` thresholds with the kind `feedback_instruction`.
"""
from __future__ import annotations

import re
from typing import Any

from defender.tests.support.learning.core._store1278 import call
from defender.tests.support.learning.core._store1278 import work as work_of

KIND = "feedback_instruction"
LESSON_NAME = "p4-feedback-lesson.md"
LESSON_PATH = f"agent/lessons/{LESSON_NAME}"
FRAME_RE = re.compile(r"<run-(?P<salt>[0-9a-f]+)-(?P<tag>[^>\n]+)>\n(?P<body>.*?)\n</run-(?P=salt)-(?P=tag)>",
                      re.DOTALL)
#: Every kind due at one waiting item, with the feedback kind (its threshold is 1 whatever the tenant sets, D11).
THRESHOLDS = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1, KIND: 1}


def instruct(dsn: str, tenant_id: str, comment_id: int = 101, *, issue: int = 7, author: str = "ann",
             case_id: str = "case-7", instruction: str = "check the VPN log first for this user",
             approve: bool = False) -> None:
    """The feedback tick's own sequence for one instruction: the run's issue recorded, the comment taken in, the decision
    recorded with its instruction. (The comment's run is `run-<issue>`.)"""
    run_id = f"run-{issue}"
    call(dsn, "enqueue_feedback_issue", tenant_id, run_id, case_id, outcome="inconclusive", lookups=[])
    held = call(dsn, "begin_feedback_tick", tenant_id, owner="seed")
    try:
        call(dsn, "record_feedback_issue", held, run_id, issue)
        call(dsn, "judge_comments", held, run_id, taken=[{
            "comment_id": comment_id, "author": author, "created": "2026-11-10T10:00:00Z", "body": instruction,
            "issue_url": f"https://forge.invalid/issues/{issue}"}], judged=[comment_id], listed=True)
        call(dsn, "record_decision", held, comment_id, {
            "approved": [], "review_by": None, "instruction": instruction, "no_change": None, "unapprovable": None},
            instruction={"comment_id": comment_id, "issue": issue, "author": author, "case_id": case_id,
                         "instruction": instruction})
    finally:
        call(dsn, "end_feedback_tick", held)


def instructions(dsn: str, tenant_id: str) -> dict[str, Any]:
    """The tenant's `feedback_instruction` items by comment id."""
    return {k: i for k, i in work_of(dsn, tenant_id).items() if i.kind == KIND}


def lesson(comment_id: int) -> str:
    """A lesson the feedback curator authored: cites its comment id under `source_finding_ids` like any lesson cites its source row."""
    from defender.tests.support.learning.core._store1278 import lesson_citing

    return lesson_citing(str(comment_id))


def frames(prompt: str) -> list[tuple[str, str, str]]:
    """`[(salt, tag, body)]` of every run-salted frame in `prompt`."""
    return [(m["salt"], m["tag"], m["body"]) for m in FRAME_RE.finditer(prompt)]
