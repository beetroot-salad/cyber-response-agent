"""#1170 r4 (A4-A6, A10): the job entry exists only inside the job container (`run.job_main`, the command `run.py --job`):
it takes launch facts and passes from the job socket, opens no database, makes no run copy, runs no publish, takes no host
lock, and its box comes over the socket. The host half (admission, launch check, alert mapping, publish, run copy, grant,
run folder) is the helper's and the run half the container's, each shared with the operator command (`run.py <alert>`).
EOF on stdin ends the entry as SIGTERM does. Driven through the real helper (`job_host.main`) over a container stand-in
whose process is the entry (`_container_entry1170.enter`); the process cases run `run.serve_job` for real."""
from __future__ import annotations

import functools
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
from defender.tests.support.jobs import _box_relay as R
from defender.tests.support.jobs._job_helper import OTHER_TENANT, claims_of, helper_scene, listing, until
from defender.tests.support.jobs._jobs1342 import DEFENDER, WORKTREE

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

PROXY = "http://proxy.invalid"


@pytest.fixture
def scene(tmp_path, monkeypatch, migrated_database):
    with helper_scene(tmp_path, monkeypatch, migrated_database, proxied=()) as s:
        yield s


@pytest.fixture
def granted_scene(tmp_path, monkeypatch, migrated_database):
    """The helper scene with `identity` proxied (the default grant), for a case whose control is a signed pass."""
    with helper_scene(tmp_path, monkeypatch, migrated_database) as s:
        yield s


def _investigation(kept: dict[str, Any] | None = None):
    """A lifecycle double: records what the entry hands it and settles the facts holder it is given."""
    from defender.investigation.challenge_gate import ReviewState

    def lifecycle(**kw: Any) -> dict[str, Any]:
        if kept is not None:
            kept.update(kw)
            kept["calls"] = kept.get("calls", 0) + 1
        facts = kw["job_facts"]
        facts.box, facts.scrub_verified = "started", True
        facts.review_state["state"] = ReviewState(closed=True)  # the report is committed (a property of the state)
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
        assert A.grant_of(claims) == [("identity", "r")]  # the decoded claims hold JSON lists, compared as pairs
        assert got.out.splitlines()[0] == f"run_id={inv}"
        assert scene.end(inv).setup == "done", got.err[-1500:]
        assert got.helper.publishes == 1, "control: the helper ran the launch-time publish"


def test_o6_the_entry_asks_for_its_pass_once_reuses_it_and_asks_again_only_within_the_reuse_margin(
        granted_scene, monkeypatch):
    """Inside the container the entry's read pass is asked of the helper when a call first needs one, reused on the next
    call and while more than the reuse margin is left (the clock moved to just outside the margin), and asked afresh once
    the clock is inside it: then the new pass is the one used. (O5, O6, H2: no pass outlives its lifetime)"""
    from defender import run as run_py
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    scene, inv, signer, got = granted_scene, str(uuid.uuid4()), A.MarkedSigner(), {}
    scene.plant(inv)
    real_time, offset = time.time, [0.0]
    # The stdlib wall clock is the boundary: the in-container pass holder reads it and has no clock seam, and the
    # helper's expiry, read off the same clock, moves with it.
    monkeypatch.setattr(time, "time", lambda: real_time() + offset[0])  # lint-monkeypatch: ok — stdlib clock boundary

    def lifecycle(**kw: Any) -> dict[str, Any]:
        access, seen = kw["access"], []

        def take(label: str) -> None:
            seen.append((label, access.token(), len(signer.payloads)))

        take("first")
        take("again")
        expiry = claims_of(signer, seen[0][1])["exp"]
        offset[0] = expiry - real_time() - run_py.TOKEN_REUSE_MARGIN_SEC - 5  # 5 s outside the margin
        take("outside-margin")
        offset[0] = expiry - real_time() - run_py.TOKEN_REUSE_MARGIN_SEC + 5  # 5 s inside it
        take("inside-margin")
        take("after-refresh")
        offset[0] = 0.0
        got["seen"] = seen
        return _investigation()(**kw)

    got_entry = enter(scene, inv, signer=signer, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                      visualize=lambda *a, **k: None)

    _clean(got_entry)
    (first, t1, n1), (_, t2, n2), (_, t3, n3), (_, t4, n4), (_, t5, n5) = got["seen"]
    assert t2 == t3 == t1, "the pass was asked again while more than the reuse margin was left"
    assert n2 == n3 == n1, "a pass was signed for a call the held pass covered"
    assert t4 != t1, "the held pass was used inside the reuse margin"
    assert n4 == n1 + 1, "inside the margin the entry asked the helper for exactly one new pass"
    assert (t5, n5) == (t4, n4), "the refreshed pass was not the one reused"
    assert claims_of(signer, t4)["investigation"] == inv


def test_a6_the_entry_opens_no_database_makes_no_copy_runs_no_publish_and_takes_no_lock(granted_scene):
    """On the container's side: no tenant-records repository, no admission, no run copy, no publish child, no host lock, no request signer or token mint; the helper's side made each once and signed the pass. (A6, O3, O4, P-B, P-C)"""
    from defender.credential_proxy import _launcher, _tokens
    from defender.investigation import publish_launch
    from defender.systems import run_tenant
    from defender.tenancy import host_lock, postgres, run_knowledge
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    scene = granted_scene  # the control below needs a signed pass: an empty grant signs none (O11)
    inv = str(uuid.uuid4())
    scene.plant(inv)
    watched = {"repository": postgres.PostgresTenantRepository.__init__, "admission": run_tenant.host_tenant,
               "hold_shared": host_lock.hold_shared, "acquire": host_lock.acquire,
               "copy": run_knowledge.copy_for_run, "publish": publish_launch.launch_publish,
               "request_signer": _launcher.request_signer, "signing_access": _launcher.signing_access,
               "mint": _tokens.mint_request_token}
    signer = A.MarkedSigner()
    with ThreadCalls(watched) as calls:
        got = enter(scene, inv, signer=signer, lifecycle=_investigation(), preflight=lambda *a, **k: 0,
                    visualize=lambda *a, **k: None)

    _clean(got)
    assert scene.end(inv).setup == "done", "control: the entry ran to its end record"
    assert got.docker.job_ran, "control: the entry ran in the job container"
    assert calls.helper("repository") >= 1, "control: the helper's side opens the database"
    assert calls.helper("admission") == 1, "control: the helper admitted once"
    assert calls.helper("copy") == 1, "control: the helper made the run copy once"
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1, "control: the helper holds the tenant lock"
    assert signer.payloads, "control: the helper signed the investigation's pass"
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
            kept: dict[str, Any] = {}
            got = enter(scene, inv, lifecycle=_investigation(kept), preflight=lambda *a, **k: 0,
                        visualize=lambda *a, **k: None)
            ran["lifecycle"] = kept.get("calls", 0)  # the double counts its calls under `calls`
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


@pytest.mark.parametrize("with_parent_pid", [True, False], ids=["todays-argv", "no-parent-pid"])
def test_a6_the_host_mode_job_entry_is_retired_run_py_job_without_a_container_does_nothing(scene, with_parent_pid):
    """`run.py --job <id> --tenant <T>` from a host shell (today's full argv, no job socket) with the database login and a valid launch pair does nothing: no run folder, no end record, no holder, a non-zero exit. (A6)"""
    from defender.tenancy import host_lock

    inv = str(uuid.uuid4())
    scene.plant(inv)
    env = {**os.environ, "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}
    argv = ["--job", inv, "--tenant", scene.tenant, *(["--parent-pid", str(os.getpid())] if with_parent_pid else [])]
    before = listing(scene.runs)

    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(DEFENDER / "run.py"), *argv],
        env=env, cwd=str(WORKTREE), capture_output=True, text=True, timeout=180, check=False, stdin=subprocess.DEVNULL)

    said = proc.stdout[-1000:] + proc.stderr[-1000:]
    assert proc.returncode != 0, said
    assert not (scene.runs / inv).exists(), "a host-mode job made its run folder:\n" + said
    assert listing(scene.runs) == before, "a host-mode job wrote a record:\n" + said
    assert host_lock.holders(scene.root, scene.tenant) == [], "a host-mode job took the tenant lock"
    assert (scene.runs / f"{inv}.launch.json").exists(), "control: the launch pair was there to be run"


# --- the box over the socket: the real lifecycle ---------------------------------------------------------------------

def _real_lifecycle(investigate: Any, **seams: Any):
    """The entry's own lifecycle, `run._run_investigation_lifecycle` for real, with only the model-driven investigation
    replaced by `investigate(box=, **kw)`; `seams` are the lifecycle's other keywords (its box start, say)."""
    from defender import run as run_py

    return functools.partial(run_py._run_investigation_lifecycle, investigate=investigate, **seams)


def _summary() -> dict[str, Any]:
    return {"output": "x", "requests": 0, "truncated_by": None, "closed_before_cut": False, "exit_reason": None}


def test_g3_the_real_lifecycle_starts_its_shell_box_and_runs_a_command_over_the_socket_with_no_docker_call_in_the_container(scene):
    """The container makes no docker call, no box start and no box exec of its own; the helper starts the box and runs the command, whose output reaches the job. (A4, O2, G3)"""
    from defender.box import _docker, _lifecycle, _output

    inv, ran = str(uuid.uuid4()), {}
    scene.plant(inv)
    docker = R.RelayDocker()
    docker.exec_with = R.printing(R.OK_FRAME)
    # No `put("running")`: the double's own model answers `running` once the start lands and nothing once the box is
    # removed; a status pinned to `running` would make the helper's proof of the box's stop impossible.

    def investigate(*, box: Any, **_kw: Any) -> dict[str, Any]:
        from defender.execution import bash_exec

        ran["result"] = box.run_parsed(bash_exec.parse("echo hello"), command="echo hello", cwd=Path("/runs/current"),
                                       timeout=5)
        ran["sandboxed"] = box.sandboxed
        return _summary()

    from defender.execution import bash_exec

    watched = {"docker_call": _docker._RealDocker.__call__, "docker_popen": _docker._RealDocker.popen,
               "exec": _output.capture_bounded, "box_start": _lifecycle._start_boxed}
    with ThreadCalls({**watched, "parse": bash_exec.parse}) as calls:
        got = enter(scene, inv, docker=docker, lifecycle=_real_lifecycle(investigate), preflight=lambda *a, **k: 0,
                    visualize=lambda *a, **k: None)

    _clean(got)
    assert ran["result"].out == b"hello\n", "the command's output did not reach the job"
    assert ran["sandboxed"] is True, "the job's box is not counted as confined"
    assert len(docker.creates()) >= 1, "control: the helper's side never created the box"
    assert any(c[1] == "exec" for c in docker.calls), "control: the helper's side never ran the command in the box"
    assert calls.container("parse") >= 1, "control: the watch sees the job's own calls on the container thread"
    assert {k: calls.container(k) for k in watched} == dict.fromkeys(watched, 0)
    assert scene.end(inv).box == "started"


@pytest.mark.parametrize("refused", [False, True], ids=["control-accepted", "refused"])
def test_o11_a_box_start_the_helper_refuses_is_a_start_fault_in_the_job_and_no_box_is_created(scene, refused):
    """The run folder is swapped for a link into another tenant before the box start: the helper's refusal reaches the lifecycle as `BoxStartFault`, the job-end record says `box: start_failed`, no box is created and the investigation never runs. Control: untouched, the same start succeeds. (O11, H10, #1342 M3)"""
    from defender import box as box_mod

    inv, ran = str(uuid.uuid4()), []
    scene.plant(inv)
    other = scene.root / OTHER_TENANT / "runs"
    canary = other / "canary-1170.txt"  # in the folder the link points at: a job's own write after the fault lands there too
    canary.write_text("untouched", encoding="utf-8")
    docker = R.RelayDocker()

    def start_box(*a: Any, **kw: Any) -> Any:
        if refused:
            folder = scene.runs / inv
            folder.rename(folder.with_name(folder.name + ".moved"))
            folder.symlink_to(other, target_is_directory=True)
        return box_mod.start_box(*a, **kw)

    def investigate(**_kw: Any) -> dict[str, Any]:
        ran.append(1)
        return _summary()

    got = enter(scene, inv, docker=docker, lifecycle=_real_lifecycle(investigate, start_box=start_box),
                preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None)

    assert got.helper.raised is None, got.helper.raised
    assert canary.read_text(encoding="utf-8") == "untouched", "the other tenant's folder changed"
    if not refused:
        assert got.raised is None, got.raised
        assert ran == [1], "control: the untouched folder did not run the investigation"
        assert len(docker.creates()) >= 1, "control: the untouched folder did not start a box"
        return
    assert isinstance(got.raised, box_mod.BoxStartFault), got.raised
    assert ran == [], "the investigation ran with no box"
    assert docker.creates() == [], "the helper created a box for a refused start"
    assert scene.end(inv).box == "start_failed"
