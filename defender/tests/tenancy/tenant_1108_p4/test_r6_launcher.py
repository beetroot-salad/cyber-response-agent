"""#1108 P4 r6, ported to #1618 flow 1: the fetch launcher's and the fetch child's report handling, each case a
wrong-but-green production variant.

The launcher is `investigation.publish_launch.launch_publish(tenant_id, *, data_root, dest, commit=None, budget, command,
spawn)` (FORCED, `knowledge_1618._support`); its child is the fetch child, whose one line is `ok <commit>` or `refused
<transient|lasting> <reason>` (D11). What the launcher says for a child with no valid line of its own (a crash, garbage,
nothing, a spawn fault) is `refused lasting fetch child failed: <summary>` (U11's failed child; today's `stale:operator`,
whose class D11 turns into `lasting`); what it says when its backstop stopped the child is `refused transient ...` (an
outage: the child ran out of time, D11's "timeout"). Retired here (K1: no lock, no `LockBusy`; K9: no `stale:*` report):
`test_r6_a_lock_busy_is_a_transient_outage_not_an_operator_fault`.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._support import Trickle

WORKTREE = Path(__file__).resolve().parents[4]
OID = "0123456789abcdef0123456789abcdef01234567"
#: The launcher's line for a child with no valid line of its own (U11), up to its summary.
FAILED_CHILD = "refused lasting fetch child failed"


def _dest(tmp_path: Path) -> Path:
    dest = tmp_path / "dest"
    dest.mkdir(exist_ok=True)
    return dest


def _launch(tmp_path: Path, code: str, *args: str, budget: float = 30.0) -> str:
    return A.launcher()("r6-tenant", data_root=tmp_path, dest=_dest(tmp_path), budget=budget,
                        command=[sys.executable, "-c", code, *args])


def test_r6_the_report_is_the_childs_last_line_not_the_first(tmp_path):
    line = _launch(tmp_path, f"print('a library warning on stdout'); print('ok {OID}')")
    assert line == f"ok {OID}"
    line = _launch(tmp_path, f"print('ok {OID}'); print('refused transient the forge moved on')")
    assert line == "refused transient the forge moved on"


def test_r6_the_child_runs_from_the_repository_root(tmp_path):
    marker = tmp_path / "cwd"
    _launch(tmp_path, "import os, sys; open(sys.argv[1], 'w').write(os.getcwd()); "
            "print('refused transient x')", str(marker))
    assert Path(marker.read_text()).resolve() == WORKTREE.resolve()


def test_r6_a_failed_childs_words_are_bounded_in_its_summary(tmp_path):
    line = _launch(tmp_path, "import sys; sys.stderr.write('x' * 5000); sys.exit(1)")
    assert line.startswith(FAILED_CHILD), line
    assert len(line) < 400, len(line)


def test_1618_a_child_that_printed_a_valid_line_but_exited_non_zero_is_a_failed_child_never_its_line(tmp_path):
    """The child exits 0 for every outcome it reports; a non-zero exit is a crash whatever it printed before, so the
    launcher answers the failed child's line naming the status, never the `ok` it printed. (Flow 1, U11)"""
    line = _launch(tmp_path, f"import sys; print('ok {OID}', flush=True); sys.exit(3)")
    assert line.startswith(FAILED_CHILD), line
    assert "status 3" in line, line


@pytest.mark.parametrize("printed", [
    f"fresh {OID}", f"stale:transient {OID} the forge moved on", "misconfigured no wiring",
    "refused the class is missing", "refused transient", f"ok {OID[:12]}", ""],
    ids=["retired-fresh", "retired-stale", "retired-misconfigured", "classless", "no-reason", "short-commit", "nothing"])
def test_1618_a_child_whose_line_is_not_the_fetch_vocabulary_is_a_failed_child_refused_lasting(tmp_path, printed):
    """A line outside `ok <commit>` / `refused <transient|lasting> <reason>` (today's retired words among them, K9) is a
    failed child: `refused lasting fetch child failed: ...`, never read as an outcome and never transient. (D11, U11)"""
    line = _launch(tmp_path, f"print({printed!r})")
    assert line.startswith(FAILED_CHILD), line


@pytest.mark.parametrize("fault", [ValueError("embedded null"), OSError("no exec")])
def test_r6_a_spawn_fault_is_a_failed_child_not_a_crash(tmp_path, fault):
    def spawn(*_a, **_k):
        raise fault

    line = A.launcher()("r6-tenant", data_root=tmp_path, dest=_dest(tmp_path), spawn=spawn)
    assert line.startswith(FAILED_CHILD), line


def test_r6_the_run_reads_a_fetch_seam_that_raises_anything_as_a_failed_child(tmp_path):
    """The run's fetch wait (`run_knowledge.fetch_report`) reads a seam that raises as the failed child: a lasting refusal
    naming it, never an outcome. (U11, D11)"""
    from defender import tenancy
    from defender.tenancy import run_knowledge

    def broken(*_a, **_k):
        raise RuntimeError("the fetch seam blew up")

    report = run_knowledge.fetch_report(broken, "r6-tenant", _dest(tmp_path), tenancy.data_root_from_path(tmp_path))
    assert report.kind == run_knowledge.REFUSED, report
    assert not report.transient, report
    assert "fetch child failed" in report.reason, report
    assert "the fetch seam blew up" in report.reason, report


def test_r6_a_report_line_is_one_line_whatever_the_detail_says():
    from defender.learning.author.version_control import fetch

    for kind, detail in ((fetch.OK, OID + "\nsecond line"), (fetch.REFUSED, "lasting first line\nsecond line\r\nthird")):
        line = fetch.report(kind, detail)
        assert "\n" not in line, line
        assert "\r" not in line, line


def test_r6_the_childs_network_bound_sits_well_inside_the_launchers_budget():
    import inspect

    from defender.investigation import publish_launch
    from defender.learning.author.version_control import fetch

    budget = inspect.signature(publish_launch.launch_publish).parameters["budget"].default
    assert budget >= fetch.CHILD_NETWORK_TIMEOUT * 2, (fetch.CHILD_NETWORK_TIMEOUT, budget)
    assert 0 < publish_launch.child_budget(budget) < budget, "the child's own deadline is not inside the launcher's"


_ENDS_WHEN_ASKED = "import time; time.sleep(60)"


def test_1618_a_child_the_backstop_stopped_is_refused_transient_naming_the_budget(tmp_path):
    """A child still running when the launcher's budget runs out is stopped by the backstop, which answers `refused
    transient` naming the budget: an outage (a timeout, D11), never lasting and never a failed child's line. (Flow 1)"""
    line = _launch(tmp_path, _ENDS_WHEN_ASKED, budget=1.0)
    assert line.startswith("refused transient "), line
    assert "budget" in line, line


# --- the real child, stopped or out of time while it fetches ------------------------------------------------------------

@pytest.fixture
def t(tmp_path, data_root):
    with K.scene(tmp_path, data_root) as scene:
        yield scene


def _fetching_child(t, tmp_path: Path, *extra: str) -> subprocess.Popen:
    """The real fetch child (over the scene's fakes) for an empty owned folder, in its own session, with `extra` argv."""
    dest = K.owned_dest(K.tenant_root(t) / "run-knowledge")
    return subprocess.Popen(  # noqa: S603 — the test's own child
        [*A.child_command(t, tmp_path), t.tenant_id, "--data-root", str(K.tenant_root(t).parent), "--dest", str(dest), *extra],
        cwd=A.IMPORT_ROOT, env={**os.environ, "PYTHONPATH": str(A.IMPORT_ROOT)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)


def _hold_upload_pack(t, stop: threading.Event, *, limit: float) -> None:
    """The scene's git listener answers the fetch's upload-pack slowly for ever (until `stop` or `limit`)."""
    t.server.on_service = lambda service: Trickle(stop, limit=limit) if service == "git-upload-pack" else None
    t.server.rearm()


def _wait_until_fetching(t, proc: subprocess.Popen, before: int) -> None:
    deadline = time.monotonic() + 60
    while not any(s == "git-upload-pack" for s, _sent, _ok in t.server.seen[before:]):
        assert proc.poll() is None, proc.communicate()
        assert time.monotonic() < deadline, "premise: the child never reached the forge"
        time.sleep(0.05)
    time.sleep(0.5)  # the fetch is in flight


def test_r6_a_child_stopped_while_fetching_exits_with_the_sigterm_status_and_reports_nothing(t, tmp_path):
    stop = threading.Event()
    _hold_upload_pack(t, stop, limit=120.0)
    before = len(t.server.seen)
    proc = _fetching_child(t, tmp_path)
    try:
        _wait_until_fetching(t, proc, before)
        os.killpg(proc.pid, signal.SIGTERM)
        out, _err = proc.communicate(timeout=60)
    finally:
        stop.set()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    assert proc.returncode == 128 + signal.SIGTERM, (proc.returncode, out)
    assert out.strip() == "", out
    assert K.repo_scratch(t) == [], "the stopped child left its private repository"


def test_1618_the_child_holds_its_own_deadline_and_reports_running_out_of_it(t, tmp_path):
    """Handed `--budget`, the child bounds its network phase itself: a fetch the forge never finishes is cut at that
    deadline and the child reports it, `refused transient <reason naming its budget>`, exit 0, well before the forge
    would have closed the request (the launcher's backstop is not involved: the child runs alone). (Flow 1, O-BUDGET)"""
    stop = threading.Event()
    _hold_upload_pack(t, stop, limit=40.0)
    before = len(t.server.seen)
    started = time.monotonic()
    proc = _fetching_child(t, tmp_path, "--budget", "3")
    try:
        out, err = proc.communicate(timeout=60)
    finally:
        stop.set()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    elapsed = time.monotonic() - started
    assert any(s == "git-upload-pack" for s, _sent, _ok in t.server.seen[before:]), "premise: the child reached the forge"
    lines = [line for line in out.splitlines() if line.strip()]
    assert proc.returncode == 0, (proc.returncode, out, err[-500:])
    assert lines, out
    assert lines[-1].startswith("refused transient "), out
    assert "budget" in lines[-1], lines[-1]
    assert elapsed < 30, f"the child ran {elapsed:.1f}s past its 3s budget: it holds no deadline of its own"
