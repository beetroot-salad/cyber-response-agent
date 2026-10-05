"""#1135 claims-adversary findings, each pinned by a test that fails without its fix."""

from __future__ import annotations

from defender.learning.core.state import FINDINGS, LearningState
from defender.tests._drain719 import make_paths


def test_rotate_keeps_a_keyless_row_appended_after_the_batch_read(tmp_path):
    """A keyless row the batch handled leaves the queue; a different keyless row appended after
    the batch's read stays (it carries no id to have been "handled" by)."""
    paths = make_paths(tmp_path)
    state = LearningState.open(paths)
    state.append(FINDINGS, [{"x": 1}])
    state.append(FINDINGS, [{"x": 2}, {"finding_id": "k"}])

    state.rotate(FINDINGS, [], [{"x": 1}], None)

    rows, _bad = state.rows_report(FINDINGS)
    assert rows == [{"x": 2}, {"finding_id": "k"}]
