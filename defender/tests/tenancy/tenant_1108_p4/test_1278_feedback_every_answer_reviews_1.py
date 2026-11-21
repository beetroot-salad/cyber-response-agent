"""#1278 feedback, H15 counting over the port, reviews read: slice 1 of 4 of the answers given on the reviews read. One slice of
`test_1278_feedback_every_answer.py`'s case, in a file of its own so the slices run on workers of their own (one file runs on
one worker, and the whole case ran ~8 minutes there); `check_h15_slice` is that module's, restricted to its slice.
"""
from __future__ import annotations

import pytest

from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_p4 import test_1278_feedback as _1278_feedback
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback_every_answer import check_h15_slice

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

#: The port's case alone (conftest `ONLY_TICK_IMPLS`); the adapter's are in `test_1278_feedback_every_answer.py`.
ONLY_TICK_IMPLS = ("port",)

world = _1278_feedback.world  # the fixture, from `test_1278_feedback`


@pytest.mark.parametrize("target", ["reviews"])
def test_h15_each_answer_the_forge_can_give_counts_or_not_as_the_rule_says_slice_1_of_4(world, caplog, target):
    """Slice 1 of 4 of every status 400..599, a lost connection, a timeout and good reads on the reviews read: the count the rule gives, and a person called exactly at the ceiling. (H15, D7)"""
    check_h15_slice(world, caplog, target, 0, 4)
