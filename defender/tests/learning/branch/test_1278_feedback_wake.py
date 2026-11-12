"""#1278 A4 Wake: one `feedback_instruction` item (threshold 1) or a not-ended registry batch leaves the #1344 post-step's
record with work waiting. Store state built with the store's own verbs, as `test_1344_amend_post_step.py` does."""
from __future__ import annotations

import os

import pytest

from defender.tests.learning.branch.test_1344_amend_post_step import _record_at
from defender.tests.learning.branch.test_1344_post_step import (  # noqa: F401 — store_dsn is the module's autouse fixture
    _job_episode,
    hand_pending,
    post_step_in_container,
    store_dsn,
)
from defender.tests.learning.feedback_1414 import _lessons1414 as L
from defender.tests.support.learning.core._store1278 import DSN_ENV, call
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres


@pytest.mark.parametrize(("scenario", "waiting"), [("one_instruction_item", True), ("registry_batch_in_review", True),
                                                  ("registry_batch_ended", False)])
def test_wake_a_feedback_instruction_or_a_registry_batch_not_ended_leaves_work_waiting(tmp_path, monkeypatch, scenario, waiting):
    """One `feedback_instruction` item (threshold 1, below the judge's 5) and a not-ended registry batch both leave the post-step's record without `waiting: false`; an ended registry batch alone does. (Wake, A4)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    ep, _ = _job_episode(tmp_path, f"wake-{scenario}", findings=False)
    data_root, tenant_id = J.episode_location(ep)
    dsn = os.environ[DSN_ENV]
    if scenario == "one_instruction_item":
        L.instruct(dsn, tenant_id, 101)
    else:
        held = call(dsn, "begin_feedback_tick", tenant_id, owner="host-a")
        registry = call(dsn, "claim_registry", held)
        call(dsn, "in_review", registry, 7, {})
        if scenario == "registry_batch_ended":
            call(dsn, "end_review", tenant_id, registry.batch_id, expect_phase="in_review", outcome="merged",
                 published=[], held=[])
        call(dsn, "end_feedback_tick", held)

    hand_pending(data_root, tenant_id, None, [])
    post_step_in_container(None, tenant_id,
                   author_tick=lambda *_a, **_k: 0)

    assert _record_at(ep, tenant_id) == {"published": [], "refused": [], **({} if waiting else {"waiting": False})}
