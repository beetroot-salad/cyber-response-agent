"""#1487 Amendment r5.3: the learning store's settings are judged where they are owned, at the worker's start. The
post-step's helper inherits the worker's environment and binds the thresholds, the attempt ceiling and the lease
timings to the tick's store; a malformed one refuses the worker's start (exit 2, naming it) when it has learning slots,
so no post-step ever meets one."""
from __future__ import annotations

import pytest

from defender.tests.support.jobs._jobs1342 import FRONTEND_ORIGIN

BAD = [("LEARNING_AUTHOR_THRESHOLD", "high"), ("LEARNING_QUESTIONER_THRESHOLD", "x"),
       ("LEARNING_AUTHOR_MAX_ATTEMPTS", "abc"), ("DEFENDER_LEARNING_LEASE_SECONDS", "-1")]


@pytest.mark.parametrize(("variable", "raw"), BAD, ids=[v for v, _ in BAD])
def test_r53_a_malformed_learning_setting_refuses_the_start(monkeypatch, variable, raw):
    from defender.worker import WorkerStartRefused
    from defender.worker._start import check_learning_settings

    check_learning_settings()  # control: the defaults pass
    monkeypatch.setenv(variable, raw)
    with pytest.raises(WorkerStartRefused, match=variable):
        check_learning_settings()


def test_r53_the_deployed_worker_with_learning_slots_exits_2_before_any_work(monkeypatch, tmp_path, capsys):
    """The refusal comes before the job network is asked about, the lock is taken or the code copy is made."""
    from defender.worker.__main__ import main

    for name, value in {"DEFENDER_BUILD_COMMIT": "c" * 40, "DEFENDER_DATABASE_DSN": "postgresql://x/y",
                        "DEFENDER_DATA_ROOT": str(tmp_path), "DEFENDER_API_FRONTEND_ORIGIN": FRONTEND_ORIGIN,
                        "DEFENDER_WORKER_SLOTS": "2", "DEFENDER_WORKER_LEARNING_SLOTS": "1",
                        "LEARNING_AUTHOR_THRESHOLD": "high"}.items():
        monkeypatch.setenv(name, value)

    assert main() == 2
    assert "LEARNING_AUTHOR_THRESHOLD" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == [], "the refused start touched the data root"
