"""#1278 feedback, H15 counting over the port, pull read: the answers given on the pull read. The port's
case of `test_1278_feedback_every_answer.py` (the adapter runs every answer): each answer is a tick that starts a real
post-step helper, so the whole sequence over the port was ~8 minutes on one worker. The count rule is the tick's, the same
over both stores; these answers (every outcome class and the ceiling among them) hold the port to it, in a file of its
own so the two reads run on workers of their own. `check_h15` is that module's.
"""
from __future__ import annotations

import pytest

from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_p4 import test_1278_feedback as _1278_feedback
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback_every_answer import check_h15, port_answers

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

#: The port's case alone (conftest `ONLY_TICK_IMPLS`); the adapter's is in `test_1278_feedback_every_answer.py`.
ONLY_TICK_IMPLS = ("port",)

world = _1278_feedback.world  # the fixture, from `test_1278_feedback`


@pytest.mark.parametrize("target", ["pull"])
def test_h15_each_answer_the_forge_can_give_counts_or_not_as_the_rule_says_over_the_port(world, caplog, target):
    """A sample of every status 400..599, a lost connection, a timeout and good reads on the pull read: the count the rule gives, and a person called exactly at the ceiling. (H15, D7)"""
    check_h15(world, caplog, target, port_answers())
