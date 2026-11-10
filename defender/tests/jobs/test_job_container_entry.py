"""#1170 r4 (A4-A6, A10): the job entry exists only inside the job container (`run.job_main`, the command `run.py --job`):
it takes launch facts and passes from the job socket, opens no database, makes no run copy, runs no publish, takes no host
lock, and its box comes over the socket. The host half (admission, launch check, alert mapping, publish, run copy, grant,
run folder) is the helper's and the run half the container's, each shared with the operator command (`run.py <alert>`).
EOF on stdin ends the entry as SIGTERM does. Driven through the real helper (`job_host.main`) over a container stand-in
whose process is the entry (`_container_entry1170.enter`); the process cases run `run.serve_job` for real."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from defender.tests.support.jobs._container_entry1170 import (
    HOLD_CHILD,
    ThreadCalls,
    enter,
)
from defender.tests.support.jobs._job_helper import claims_of, helper_scene, until
from defender.tests.support.jobs._jobs1342 import DEFENDER, WORKTREE

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

PROXY = "http://proxy.invalid"


@pytest.fixture
def scene(tmp_path, monkeypatch, migrated_database):
    with helper_scene(tmp_path, monkeypatch, migrated_database, proxied=()) as s:
        yield s


def _investigation(kept: dict[str, Any] | None = None):
    """A lifecycle double: records what the entry hands it and settles the facts holder it is given."""
    from defender.investigation.challenge_gate import ReviewState

    def lifecycle(**kw: Any) -> dict[str, Any]:
        if kept is not None:
            kept.update(kw)
            kept["calls"] = kept.get("calls", 0) + 1
        facts = kw["job_facts"]
        facts.box, facts.report_committed, facts.scrub_verified = "started", True, True
        facts.review_state["state"] = ReviewState(closed=True)
        return {"output": "x", "requests": 0, "truncated_by": None, "closed_before_cut": False, "exit_reason": None}
    return lifecycle


def _clean(got: Any) -> None:
    assert got.helper.raised is None, got.helper.raised
    assert got.raised is None, got.raised


def test_a6_the_entry_takes_its_pass_from_the_socket_and_its_launch_facts_from_the_helper(
        tmp_path, monkeypatch, migrated_database):
    """The entry runs with the helper's launch facts and the pass the helper signed for this tenant and investigation, and the proxy address; the helper made the run folder and copy. (A6, O5, A4)"""
    from defender.kit.access import PROXY_URL_ENV
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        monkeypatch.setenv(PROXY_URL_ENV, PROXY)
        inv, kept, signer = str(uuid.uuid4()), {}, A.MarkedSigner()
        scene.plant(inv)
        pass_seen: list[str] = []

        def lifecycle(**kw: Any) -> dict[str, Any]:
            pass_seen.append(kw["access"].token())
            return _investigation(kept)(**kw)

        got = enter(scene, inv, signer=signer, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                    visualize=lambda *a, **k: None)

        _clean(got)
        assert kept["calls"] == 1, "the entry did not run the lifecycle exactly once"
        assert kept["access"].proxy_url == PROXY
        claims = claims_of(signer, pass_seen[0])
        assert (claims["tenant"], claims["investigation"]) == (scene.tenant, inv)
        assert sorted(claims["grant"]) == [("identity", "r")]
        assert got.out.splitlines()[0] == f"run_id={inv}"
        assert scene.end(inv).setup == "done", got.err[-1500:]
        assert got.helper.publishes == 1, "control: the helper ran the launch-time publish"


def test_a6_the_entry_opens_no_database_makes_no_copy_runs_no_publish_and_takes_no_lock(scene):
    """On the container's side: no tenant-records repository, no admission, no run copy, no publish child, no host lock; the helper's side made each once. (A6, O3, P-C)"""
    from defender.investigation import publish_launch
    from defender.systems import run_tenant
    from defender.tenancy import host_lock, postgres, run_knowledge

    inv = str(uuid.uuid4())
    scene.plant(inv)
    watched = {"repository": postgres.PostgresTenantRepository.__init__, "admission": run_tenant.host_tenant,
               "hold_shared": host_lock.hold_shared, "acquire": host_lock.acquire,
               "copy": run_knowledge.copy_for_run, "publish": publish_launch.launch_publish}
    with ThreadCalls(watched) as calls:
        got = enter(scene, inv, lifecycle=_investigation(), preflight=lambda *a, **k: 0,
                    visualize=lambda *a, **k: None)

    _clean(got)
    assert scene.end(inv).setup == "done", "control: the entry ran to its end record"
    assert got.docker.job_ran, "control: the entry ran in the job container"
    assert calls.helper("repository") >= 1, "control: the helper's side opens the database"
    assert calls.helper("admission") == 1, "control: the helper admitted once"
    assert calls.helper("copy") == 1, "control: the helper made the run copy once"
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1, "control: the helper holds the tenant lock"
    assert {k: calls.container(k) for k in watched} == dict.fromkeys(watched, 0)


@pytest.mark.parametrize("lane", ["job", "operator"])
def test_a6_the_host_half_and_the_run_half_each_run_once_in_a_job_and_in_the_operator_command(
        scene, tmp_path, lane):
    """One admission, one launch-time publish, one run copy and one lifecycle per run, for a job (helper then container) and for `run.py <alert>` unchanged. (A6, #1342 M3)"""
    from defender.systems import run_tenant
    from defender.tenancy import run_knowledge
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    ran = {"lifecycle": 0}
    count = {"admission": run_tenant.host_tenant, "copy": run_knowledge.copy_for_run}
    with ThreadCalls(count) as calls:
        if lane == "job":
            inv = str(uuid.uuid4())
            scene.plant(inv)
            got = enter(scene, inv, lifecycle=_investigation(ran), preflight=lambda *a, **k: 0,
                        visualize=lambda *a, **k: None)
            publishes = got.helper.publishes
            _clean(got)
        else:
            publishes = []
            out = B.launch(scene.t, tmp_path, publish=lambda *a, **k: publishes.append(1) or B.fresh(scene.t.commit),
                           lifecycle=lambda **kw: ran.__setitem__("lifecycle", ran["lifecycle"] + 1) or
                           {"output": "x", "requests": 0, "truncated_by": None})
            publishes = len(publishes)
            assert out.raised is None, out.text()
            assert out.rc == 0, out.text()
    assert (len(calls.by_thread["admission"]), len(calls.by_thread["copy"]), publishes, ran["lifecycle"]) == (1, 1, 1, 1), \
        (lane, calls.by_thread, publishes, ran)


def test_a10_the_job_leaves_its_page_in_its_run_folder_and_the_helper_copies_it_to_the_publish_folder_after_exit(
        scene, monkeypatch, tmp_path):
    """While the entry runs the shared publish folder is untouched; after the container exits the helper has copied the job's page there, under the tenant. (A10, A8)"""
    publish_dir = tmp_path / "published"
    publish_dir.mkdir()
    monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
    monkeypatch.setenv("DEFENDER_RUN_VISUALIZATIONS_DIR", str(publish_dir))
    inv, page = str(uuid.uuid4()), "<html>run page 1170</html>"
    scene.plant(inv)
    during: list[list[str]] = []

    def visualize(run: Any, **_kw: Any) -> None:
        run.observability.runtime_html.write(page)  # the job's half of `publish_page`: the record in its run folder
        during.append(sorted(str(p.relative_to(publish_dir)) for p in publish_dir.rglob("*") if p.is_file()))

    got = enter(scene, inv, lifecycle=_investigation(), preflight=lambda *a, **k: 0, visualize=visualize)

    _clean(got)
    assert during == [[]], f"the job wrote to the shared publish folder itself: {during}"
    landed = [p for p in publish_dir.rglob("*") if p.is_file()]
    assert [p.read_text(encoding="utf-8") for p in landed] == [page], "the helper did not copy the job's page"
    assert landed[0].relative_to(publish_dir).parts[0] == scene.tenant, "the page is not under its tenant"
    assert (scene.runs / inv).is_dir(), "control: the run folder (with the page record) is kept"


# --- A5 and the signal: real processes -----------------------------------------------------------------------------

def _hold_child(container: Any, scene: Any, inv: str, marks: Path, how: str, done: Any) -> int:
    env = {**{k: v for k, v in container.env.items() if v is not None},
           "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}", "PATH": os.environ["PATH"]}
    proc = subprocess.Popen([sys.executable, "-c", HOLD_CHILD, str(marks), "--job", inv, "--tenant", scene.tenant],  # noqa: S603
                            env=env, cwd=str(WORKTREE), stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        until(lambda: (marks / "in-lifecycle").exists() or proc.poll() is not None, "the entry's lifecycle", 120)
        done.extra["reached"] = (marks / "in-lifecycle").exists()
        if not done.extra["reached"]:
            done.extra["stderr"] = proc.stderr.read().decode(errors="replace")[-2000:]
            return 1
        if how == "control-no-signal":
            time.sleep(1.5)
            done.extra["alive_without_signal"] = proc.poll() is None
        elif how == "sigterm":
            proc.send_signal(signal.SIGTERM)
        else:
            proc.stdin.close()  # the helper's end of the pipe is gone: EOF
        if how == "control-no-signal":
            proc.send_signal(signal.SIGTERM)
        until(lambda: (marks / "stop-box-started").exists(), "the teardown", 30)
        proc.send_signal(signal.SIGTERM)  # a second signal during teardown
        time.sleep(0.5)
        (marks / "go-on").touch()
        return proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


@pytest.mark.parametrize("how", ["sigterm", "stdin-eof", "control-no-signal"])
def test_a5_eof_on_stdin_is_sigterm_to_the_entry_and_sigterm_is_one_keyboard_interrupt(scene, tmp_path, how):
    """Inside the container, EOF on stdin reaches the investigation as one `KeyboardInterrupt` exactly as SIGTERM does, the box teardown completes despite a later SIGTERM, the job-end record is written; with stdin open and no signal the entry stays up. (A5, #1342 O7)"""
    inv, marks = str(uuid.uuid4()), tmp_path / "marks"
    scene.plant(inv)

    got = enter(scene, inv, entry=lambda c, done: _hold_child(c, scene, inv, marks, how, done))

    assert got.helper.raised is None, got.helper.raised
    assert got.extra.get("reached"), got.extra.get("stderr")
    if how == "control-no-signal":
        assert got.extra["alive_without_signal"] is True, "the entry ended with its stdin still open"
    assert (marks / "interrupted").read_text(encoding="utf-8") == "KeyboardInterrupt"
    assert (marks / "stop-box-done").exists(), "a later SIGTERM interrupted the teardown"
    end = scene.end(inv)
    assert end is not None, "an interrupted entry still leaves its job-end record"
    assert end.setup == "done"


def test_a6_the_host_mode_job_entry_is_retired_run_py_job_without_a_container_does_nothing(scene):
    """`run.py --job <id> --tenant <T> --parent-pid <pid>` from a host shell with the database login and a valid launch pair: no run is made, no run folder, no holder recorded, a non-zero exit. (A6)"""
    from defender.tenancy import host_lock

    inv = str(uuid.uuid4())
    scene.plant(inv)
    env = {**os.environ, "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}

    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(DEFENDER / "run.py"), "--job", inv, "--tenant", scene.tenant,
         "--parent-pid", str(os.getpid())],
        env=env, cwd=str(WORKTREE), capture_output=True, text=True, timeout=180, check=False, stdin=subprocess.DEVNULL)

    assert proc.returncode != 0, proc.stdout[-1000:] + proc.stderr[-1000:]
    assert not (scene.runs / inv).exists(), "a host-mode job made its run folder"
    assert host_lock.holders(scene.root, scene.tenant) == [], "a host-mode job took the tenant lock"
    assert (scene.runs / f"{inv}.launch.json").exists(), "control: the launch pair was there to be run"
