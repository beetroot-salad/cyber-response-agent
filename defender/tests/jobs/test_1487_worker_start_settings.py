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


#: Well-formed values no store could work with: each refused, naming what refuses it (the setting, or for a timing that
#: is wrong only against another, either one of the pair).
SENSELESS = [({"LEARNING_AUTHOR_MAX_ATTEMPTS": "0"}, "LEARNING_AUTHOR_MAX_ATTEMPTS"),
             ({"LEARNING_AUTHOR_MAX_ATTEMPTS": "-2"}, "LEARNING_AUTHOR_MAX_ATTEMPTS"),
             ({"DEFENDER_LEARNING_RENEW_SECONDS": "33"}, "DEFENDER_LEARNING_RENEW_SECONDS"),
             ({"DEFENDER_LEARNING_LEASE_SECONDS": "100", "DEFENDER_LEARNING_GRACE_SECONDS": "10",
               "DEFENDER_LEARNING_RENEW_SECONDS": "110.5"}, "DEFENDER_LEARNING_RENEW_SECONDS"),
             ({"DEFENDER_LEARNING_LEASE_SECONDS": "22", "DEFENDER_LEARNING_RENEW_SECONDS": "5"},
              "DEFENDER_LEARNING_LEASE_SECONDS")]


@pytest.mark.parametrize(("env", "named"), SENSELESS, ids=["attempts-0", "attempts-negative", "renew-at-lease-and-grace",
                                                          "renew-past-lease-and-grace", "lease-at-stop-window"])
def test_a_learning_setting_no_store_could_work_with_refuses_the_start(monkeypatch, env, named):
    """An attempt ceiling below 1, a renewal no sooner than the lease and its grace run out, and a lease no longer than
    the job container's stop window: each refuses the start, naming it. The control, the same knobs one step inside each
    bound, passes."""
    from defender.job_host import STOP_GRACE
    from defender.worker import WorkerStartRefused
    from defender.worker._start import check_learning_settings

    for variable, value in {"LEARNING_AUTHOR_MAX_ATTEMPTS": "1", "DEFENDER_LEARNING_LEASE_SECONDS": str(STOP_GRACE + 1),
                            "DEFENDER_LEARNING_GRACE_SECONDS": "10",
                            "DEFENDER_LEARNING_RENEW_SECONDS": str(STOP_GRACE + 10.5)}.items():
        monkeypatch.setenv(variable, value)
    check_learning_settings()  # control: just inside every bound
    for variable, value in env.items():
        monkeypatch.setenv(variable, value)
    with pytest.raises(WorkerStartRefused, match=named):
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
