"""#1278 A4 Wake, as #1487 Flow 3 moves it: one `feedback_instruction` item (threshold 1) or a not-ended registry batch
makes the post-step's waiting predicate (`defender.learning_store.tick.work_waiting`) true. Store state built with the store's
own verbs, as `test_1344_amend_post_step.py` does."""
from __future__ import annotations

import pytest

from defender.tests.learning.branch.test_1344_amend_post_step import TENANT, waiting_of
from defender.tests.learning.feedback_1414 import _lessons1414 as L
from defender.tests.support.learning.core._store1278 import call
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres


@pytest.mark.parametrize(("scenario", "waiting"), [("one_instruction_item", True), ("registry_batch_in_review", True),
                                                  ("registry_batch_ended", False)])
def test_wake_a_feedback_instruction_or_a_registry_batch_not_ended_keeps_the_tenant_waiting(
        migrated_database, scenario, waiting):  # noqa: F811 — the imported fixture
    """One `feedback_instruction` item (threshold 1, with the findings' threshold 5) and a not-ended registry batch both
    make the predicate true; an ended registry batch alone does not. (Wake, A4, O7)"""
    dsn = migrated_database
    register_tenant(dsn, TENANT)
    if scenario == "one_instruction_item":
        L.instruct(dsn, TENANT, 101)
    else:
        held = call(dsn, "begin_feedback_tick", TENANT, owner="host-a")
        registry = call(dsn, "claim_registry", held)
        call(dsn, "in_review", registry, 7, {})
        if scenario == "registry_batch_ended":
            call(dsn, "end_review", TENANT, registry.batch_id, expect_phase="in_review", outcome="merged",
                 published=[], held=[])
        call(dsn, "end_feedback_tick", held)

    assert waiting_of(dsn, TENANT, finding_at=5) is waiting
