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


def test_rotate_keeps_an_empty_keyless_row_and_a_row_that_is_only_a_subset(tmp_path):
    """A handled keyless entry removes only the queued row it was made from (that row plus the
    batch's stamp): not an empty row, and not a different row whose fields happen to be a subset."""
    paths = make_paths(tmp_path)
    state = LearningState.open(paths)
    state.append(FINDINGS, [{"a": 1, "b": 2}])
    state.append(FINDINGS, [{}, {"a": 1}])

    state.rotate(FINDINGS, [], [{"a": 1, "b": 2, "consumed_category": "consumed_retired"}], None)

    rows, _bad = state.rows_report(FINDINGS)
    assert rows == [{}, {"a": 1}]


def test_read_window_reports_a_read_time_timeout_instead_of_a_busy_channel(tmp_path):
    """Only the lock's own deadline means "an appender holds it"; a TimeoutError out of the read
    inside the window is an ordinary I/O fault and must reach the caller."""
    import pytest

    paths = make_paths(tmp_path)
    state = LearningState.open(paths)

    class SlowRead(LearningState):
        def rows_report(self, channel):
            raise TimeoutError("read timed out")

    slow = SlowRead.__new__(SlowRead)
    slow.__dict__.update(state.__dict__)  # shares the real handle's descriptor
    with pytest.raises(TimeoutError, match="read timed out"):
        slow.read_window(FINDINGS, timeout=1)


def test_releasing_a_claim_or_a_delivery_survives_an_ordinary_unlink_failure(tmp_path, monkeypatch):
    """`done` and `delivered` are best-effort, as the unlinks they replaced were: an ordinary
    failure leaves the record for the next pass and does not abort the apply or the delivery."""
    import errno

    from defender.learning.core.state import PendingDelivery

    paths = make_paths(tmp_path)
    state = LearningState.open(paths)
    (tmp_path / "r").mkdir()
    state.enqueue_curation("case-1", {"case_id": "case-1", "run_dir": str((tmp_path / "r").resolve())})
    [claim] = list(state.claim("case_id"))

    def denied(self, name):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(type(state._held), "unlink", denied)  # lint-monkeypatch: ok — the core's unlink has no seam; an ordinary EACCES cannot be planted as root
    state.done(claim)
    state.delivered(PendingDelivery("a-b1", "a/b1", "b1"))
