"""#1476 review (second round), finding 10: the tick spells the store's lane names.

The tick keeps the lane names as plain strings so that loading it does not load the database models (the job image has
no database driver); the models are the one definition, and this pins the tick's spelling to them. The branch prefixes
have no second copy: the tick reads `BRANCH_PREFIX` from the models where it uses it."""
from __future__ import annotations

from defender.jobs import learning_models
from defender.learning.core import store_tick


def test_the_ticks_lane_names_are_the_stores():
    assert (store_tick.AUTHOR_LANE, store_tick.LEAD_LANE, store_tick.FEEDBACK_LANE) == learning_models.LANES


def test_every_lane_has_one_branch_prefix_and_the_revert_prefix_is_under_the_author_lanes():
    assert set(learning_models.BRANCH_PREFIX) == set(learning_models.LANES)
    assert learning_models.REVERT_PREFIX.startswith(learning_models.BRANCH_PREFIX[learning_models.AUTHOR_LANE])
