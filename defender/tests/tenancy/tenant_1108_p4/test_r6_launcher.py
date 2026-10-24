"""#1108 P4 round 6 — the publish launcher's and child's report handling (each case was a
wrong-but-green production variant): the report is the child's LAST line, it is one line, the
summary of a failed child is bounded, the child runs from the repository root, a spawn fault of
any kind is a failed child, a stopped child exits non-zero, a reported stale reason is required,
and the child's own network bound sits well inside the launcher's budget."""
from __future__ import annotations

import inspect
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_delivery._support import Trickle
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, current_commit

WORKTREE = Path(__file__).resolve().parents[4]
OID = "0123456789abcdef0123456789abcdef01234567"


def _launch(tmp_path, code: str, *args: str) -> str:
    return B.launcher()("r6-tenant", data_root=tmp_path, budget=30.0,
                        command=[sys.executable, "-c", code, *args])


def test_r6_the_report_is_the_childs_last_line_not_the_first(tmp_path):
    line = _launch(tmp_path, f"print('a library warning on stdout'); print('fresh {OID}')")
    assert line == f"fresh {OID}"
    line = _launch(tmp_path, f"print('fresh {OID}'); print('stale:transient it moved on')")
    assert line == "stale:transient it moved on"


def test_r6_the_child_runs_from_the_repository_root(tmp_path):
    marker = tmp_path / "cwd"
    _launch(tmp_path, "import os, sys; open(sys.argv[1], 'w').write(os.getcwd()); "
            "print('stale:transient x')", str(marker))
    assert Path(marker.read_text()).resolve() == WORKTREE.resolve()


def test_r6_a_failed_childs_words_are_bounded_in_its_summary(tmp_path):
    line = _launch(tmp_path, "import sys; sys.stderr.write('x' * 5000); sys.exit(1)")
    assert line.startswith("stale:operator publish child failed")
    assert len(line) < 400, len(line)


@pytest.mark.parametrize("fault", [ValueError("embedded null"), OSError("no exec")])
def test_r6_a_spawn_fault_is_a_failed_child_not_a_crash(tmp_path, fault):
    from defender.runtime.publish_launch import launch_publish

    def spawn(*_a, **_k):
        raise fault

    line = launch_publish("r6-tenant", data_root=tmp_path, spawn=spawn)
    assert line.startswith("stale:operator publish child failed"), line


def test_r6_the_run_records_a_publish_seam_that_raises_anything_as_a_failed_child(
        tmp_path, data_root):
    def broken(*_a, **_k):
        raise RuntimeError("the publish seam blew up")

    with B.run_tenant(tmp_path, data_root) as t:
        out = B.launch(t, tmp_path, publish=broken)
        assert out.reached and out.rc == 0, out.text()
        source = B.knowledge_source(out)
        assert (source["kind"], source["stale_kind"]) == ("stale", "operator"), source
        assert "publish child failed" in source["reason"]


@pytest.mark.parametrize("line", ["stale:transient", "stale:operator ", "stale:transient   ",
                                  "misconfigured", "misconfigured "])
def test_r6_a_stale_or_misconfigured_report_without_a_reason_is_a_failed_child(line):
    from defender.runtime.run_knowledge import read_publish_report

    report = read_publish_report(line)
    assert (report.kind, report.stale_kind) == ("stale", "operator"), report
    assert "publish child failed" in report.reason


def test_r6_a_report_line_is_one_line_whatever_the_detail_says():
    from defender.learning.author.version_control import publish

    for kind in publish.REPORT_CLASSES:
        line = publish.report(kind, "first line\nsecond line\r\nthird")
        assert "\n" not in line and "\r" not in line, line


def test_r6_the_childs_network_bound_sits_well_inside_the_launchers_budget():
    from defender.learning.author.version_control import publish
    from defender.runtime import publish_launch

    budget = inspect.signature(publish_launch.launch_publish).parameters["budget"].default
    assert publish.CHILD_NETWORK_TIMEOUT * 2 <= budget, (publish.CHILD_NETWORK_TIMEOUT, budget)


def test_r6_a_lock_busy_is_a_transient_outage_not_an_operator_fault():
    from defender.learning.author.version_control import LockBusy, status

    assert status.classify(LockBusy("busy"))[0] == "transient"


def test_r6_a_child_stopped_while_fetching_exits_with_the_sigterm_status_and_reports_nothing(
        tmp_path, data_root, monkeypatch):
    import threading

    monkeypatch.setenv("PYTHONPATH", f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        t.merge(B.MERGE_FILES)
        stop = threading.Event()
        t.server.on_service = lambda service: (
            Trickle(stop, limit=120.0) if service == "git-upload-pack" else None)
        t.server.rearm()
        config = B.write_issuer_config(tmp_path / "operator")
        command, _spec, _marks = B.child_command(t, tmp_path, config, network_timeout=120.0,
                                                 locked_sleep=0)
        before = len(t.server.seen)
        proc = subprocess.Popen([*command, t.tenant_id, "--data-root", str(t.data_root)],  # noqa: S603
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        try:
            deadline = time.monotonic() + 60
            while len(t.server.seen) <= before and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            time.sleep(0.5)  # the fetch is in flight
            os.killpg(proc.pid, signal.SIGTERM)
            out, _err = proc.communicate(timeout=60)
        finally:
            stop.set()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        assert proc.returncode == 128 + signal.SIGTERM, (proc.returncode, out)
        assert out.strip() == "", out
        assert current_commit(t.tenant) == t.commit
