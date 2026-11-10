"""#1170 r4 (A3, A5, A6): the learning entries inside the job container: the learning job entry (`job_entry.main`), the
post-step and the family-less check (`post_step.main`), and the sibling (`run.main` with `--episode --world`). Inside the
container none takes a host lock, runs an admission, opens the tenant database, makes a run copy, publish or draft, or
builds a signer (the helper does, and answers over the job socket); EOF on stdin ends each as
SIGTERM does. The operator sibling, run from a host shell, is unchanged (positive control). Driven through the real helper
(`job_host.main`) over a container stand-in whose process is the entry; the process cases run each entry's real command
line. Slice D's counterpart for the investigation is `test_job_container_entry.py`."""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any

import pytest
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._container_entry1170 import ThreadCalls
from defender.tests.support.jobs._job_helper_learning import learning_end, listing, publish_status
from defender.tests.support.tenancy._host1214 import counting_calls
from defender.tests.support.jobs._learning_container1170 import (
    LEARNING_JOB_HOLD,
    POST_STEP_HOLD,
    SIBLING_HOLD,
    hold_how,
    plant_episode,
    process_gone,
    seen_in_container,
    start_hold,
)

# The shared fixtures (`_job_helper`'s docs): `process_state` is autouse, `scene` the default helper scene.
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

HOW = ["sigterm", "stdin-eof", "control-no-signal"]
POST_STEPS = pytest.mark.parametrize("family_less", [False, True], ids=["post-step", "family-less"])


def _watched() -> dict[str, Any]:
    """What a container-side entry must not call: the host lock, an admission, a database, a run copy, the launch-time
    publish, a signer (the helper's side calls each: the controls)."""
    from defender.credential_proxy import _launcher, _tokens
    from defender.database import async_engine
    from defender.investigation import publish_launch
    from defender.systems import run_tenant
    from defender.tenancy import host_lock, postgres, run_knowledge

    return {"repository": postgres.PostgresTenantRepository.__init__, "engine": async_engine,
            "admission": run_tenant.host_tenant, "hold_shared": host_lock.hold_shared, "acquire": host_lock.acquire,
            "copy": run_knowledge.copy_for_run, "publish": publish_launch.launch_publish,
            "request_signer": _launcher.request_signer, "signing_access": _launcher.signing_access,
            "mint": _tokens.mint_request_token}


def _container_side(calls: ThreadCalls, labels: Any) -> dict[str, int]:
    return {k: calls.container(k) for k in labels}


def _no_database_login(seen: Any, scene: Any) -> None:
    env = seen.kind.docker.box.env
    assert [k for k in env if "DSN" in k.upper() or "DATABASE" in k.upper()] == [], "the container holds a database setting"
    assert scene.dsn not in [v for v in env.values() if v], "the container holds the database login"


def _clean(seen: Any) -> None:
    assert seen.ran, "the job container never ran the entry"
    assert seen.raised is None, seen.raised
    assert seen.exit is None, seen.exit


# --- the learning job entry ----------------------------------------------------------------------------------------

def test_a6_the_learning_job_entry_takes_no_lock_runs_no_admission_and_opens_no_database(scene):
    """Run in the container with the job socket set, the entry reaches its source check and ends its job with a record, having taken no host lock, run no admission, opened no database, made no copy or publish and built no signer; the helper did. (A6, A3, P-C)"""
    from defender.learning.branch import cli, job_entry

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    plant_episode(scene, job_id, source)
    watched = {**_watched(), "source_opened": cli._open_launch_source}

    def entry(c, seen):
        return job_entry.main(["--job", job_id, "--tenant", scene.tenant, "--source", source], environ=c.env,
                              preflight=lambda *a, **k: 0)

    with ThreadCalls(watched) as calls:
        seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    _clean(seen)
    end = learning_end(scene, job_id)
    assert end is not None, "the entry left no learning end record"
    assert end.status != "stopped", "control: a hand-back means the entry waited on a lock it should not take"
    assert calls.container("source_opened") >= 1, "control: the entry never reached the launch steps past admission"
    assert {k: v for k, v in _container_side(calls, watched).items() if k != "source_opened"} == {
        k: 0 for k in _watched()}
    assert calls.helper("admission") == 1, "control: the helper admitted the tenant once"
    assert calls.helper("repository") >= 1, "control: the helper's side opens the database"
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1, "control: the helper holds the tenant lock"
    _no_database_login(seen, scene)


def test_a5_a6_the_learning_job_entry_is_container_only_it_does_nothing_from_a_host_shell(scene):
    """Run with no job socket in its environment (a host shell that has the database login), the entry exits non-zero having written no end record, taken no lock and started no family step. (A5, A6)"""
    from defender import job_host
    from defender.learning.branch import cli, job_entry
    from defender.tenancy import host_lock

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    plant_episode(scene, job_id, source)
    argv = ["--job", job_id, "--tenant", scene.tenant, "--source", source]

    with counting_calls(launch_job=cli.launch_job) as launches:
        assert job_host.SOCKET_ENV not in os.environ, "premise: a host shell has no job socket"
        with pytest.raises(SystemExit) as stop:
            job_entry.main(argv, preflight=lambda *a, **k: 0)

    assert stop.value.code not in (0, None), "the container-less entry ran as if it were a job"
    assert host_lock.holders(scene.root, scene.tenant) == [], "the container-less entry took the tenant lock"
    assert launches["launch_job"] == 0, "a family step started"
    assert learning_end(scene, job_id) is None, "an end record was written by an entry that must not run"


@pytest.mark.parametrize("how", HOW)
def test_a5_eof_on_stdin_is_sigterm_to_the_learning_job_entry_and_takes_its_sibling_with_it(scene, tmp_path, how):
    """The entry's real command line, in the container: EOF on stdin ends the job as SIGTERM does (its record `stopped`, its launcher's real sibling gone); with stdin open and no signal it stays up. (A5, #1344 O9)"""
    job_id, source, marks = str(uuid.uuid4()), str(uuid.uuid4()), tmp_path / "marks"
    plant_episode(scene, job_id, source)

    def entry(c, seen):
        proc = start_hold(c, LEARNING_JOB_HOLD, marks, "--job", job_id, "--tenant", scene.tenant, "--source", source)
        return hold_how(proc, marks, how, seen)

    seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    assert seen.raised is None, seen.raised
    assert seen.extra.get("reached"), seen.extra.get("stderr")
    if how == "control-no-signal":
        assert seen.extra["alive_without_signal"] is True, "the entry ended with its stdin still open"
    assert (marks / "unwound").exists()
    process_gone(int((marks / "child.pid").read_text(encoding="utf-8")), "the entry's sibling to be gone")
    end = learning_end(scene, job_id)
    assert end is not None, "no end record"
    assert end.status == "stopped", end


# --- the post-step and the family-less check -------------------------------------------------------------------------

@POST_STEPS
def test_a6_the_post_step_takes_no_lock_runs_no_admission_opens_no_database_and_makes_no_copy_or_draft(scene, family_less):
    """Run in the container with the job socket set, the post-step (and the family-less check) writes its record and runs the drain's gate, having taken no host lock, run no admission, opened no database; it made no run copy, draft or publish-status row. (A6, C23, P-C)"""
    from defender.learning.branch import post_step

    job_id = None if family_less else str(uuid.uuid4())
    key = scene.tenant if family_less else job_id
    ticks: list[int] = []
    tenant_folder = scene.root / scene.tenant
    before = (listing(tenant_folder / "run-knowledge"), listing(tenant_folder / "drafts"))

    def entry(c, seen):
        argv = [*(["--job", job_id] if job_id else []), "--tenant", scene.tenant]
        return post_step.main(argv, environ=c.env, author_tick=lambda *a, **k: ticks.append(1) or 0,
                              still_waiting=lambda *a, **k: True)

    with ThreadCalls(_watched()) as calls:
        seen = seen_in_container(scene, "post-step", entry, job_id=job_id, family_less=family_less)

    _clean(seen)
    assert ticks == [1], "control: the drain's gate did not run"
    assert (scene.runs / f"{key}.post-step.json").exists(), "control: the post-step left no record"
    assert _container_side(calls, _watched()) == {k: 0 for k in _watched()}
    assert calls.helper("admission") == 1, "control: the helper admitted the tenant once"
    assert calls.helper("repository") >= 1, "control: the helper's side opens the database"
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1, "control: the helper holds the tenant lock"
    assert (listing(tenant_folder / "run-knowledge"), listing(tenant_folder / "drafts")) == before
    assert publish_status(scene) is None, "the post-step's own code wrote the publish-status row"
    _no_database_login(seen, scene)


def test_a5_a6_the_post_step_is_container_only_it_does_nothing_from_a_host_shell(scene):
    """Run with no job socket in its environment, the post-step exits non-zero having written no record and run no gate. (A5, A6)"""
    from defender import job_host
    from defender.learning.branch import post_step

    job_id = str(uuid.uuid4())
    ticks: list[int] = []
    argv = ["--job", job_id, "--tenant", scene.tenant]

    assert job_host.SOCKET_ENV not in os.environ, "premise: a host shell has no job socket"
    with pytest.raises(SystemExit) as stop:
        post_step.main(argv, author_tick=lambda *a, **k: ticks.append(1) or 0)

    assert stop.value.code not in (0, None), "the container-less post-step ran as if it were a job"
    assert ticks == []
    assert not (scene.runs / f"{job_id}.post-step.json").exists()


@pytest.mark.parametrize("how", HOW)
def test_a5_eof_on_stdin_is_sigterm_to_the_post_step_one_keyboard_interrupt_reaches_the_gate(scene, tmp_path, how):
    """The post-step's real command line, in the container: EOF on stdin reaches the drain's gate as the one `KeyboardInterrupt` SIGTERM gives it, the process unwinds and the child the gate started is gone; with stdin open and no signal it stays up. (A5, #1344 O8)"""
    job_id, marks = str(uuid.uuid4()), tmp_path / "marks"

    def entry(c, seen):
        proc = start_hold(c, POST_STEP_HOLD, marks, "--job", job_id, "--tenant", scene.tenant)
        return hold_how(proc, marks, how, seen)

    seen = seen_in_container(scene, "post-step", entry, job_id=job_id)

    assert seen.raised is None, seen.raised
    assert seen.extra.get("reached"), seen.extra.get("stderr")
    if how == "control-no-signal":
        assert seen.extra["alive_without_signal"] is True, "the post-step ended with its stdin still open"
    assert (marks / "interrupted").read_text(encoding="utf-8") == "KeyboardInterrupt"
    assert (marks / "unwound").exists()
    process_gone(int((marks / "child.pid").read_text(encoding="utf-8")), "the gate's child to be gone")


# --- the sibling -----------------------------------------------------------------------------------------------------

def test_a6_a_sibling_in_the_container_takes_no_lock_runs_no_admission_and_signs_nothing_it_runs_at_the_helpers_copy(scene):
    """Run in the container with the job socket set, `run.py --episode --world` runs the lifecycle at its world's roster id, with the run copy the helper made (owned by the helper) and the one pass the helper signed, having taken no host lock, run no admission, opened no database and built no signer. (A6, #1449, C20)"""
    from defender import run as run_py
    from defender.tests.tenancy.tenant_1108_p4._drain_support import owner_record

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    ep, roster_id = plant_episode(scene, job_id, source)
    signer, got = J.make_signer(), {}

    def lifecycle(**kw):
        run = kw["run"]
        got["run_dir"], got["token"] = run.run_dir, kw["access"].token() if kw.get("access") else None
        copy = scene.root / scene.tenant / "run-knowledge" / run.run_dir.name
        got["copy_owner"] = owner_record(copy)["pid"] if copy.is_dir() else None
        (run.run_dir / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}

    def entry(c, seen):
        return run_py.main(["--tenant", scene.tenant, "--episode", job_id, "--world", "b"], environ=c.env,
                           lifecycle=lifecycle, visualize=lambda *a, **k: None, preflight=lambda *a, **k: 0)

    with ThreadCalls(_watched()) as calls:
        seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source, signer=signer)

    _clean(seen)
    assert got["run_dir"] == ep / "runs" / roster_id, "the sibling did not run at its world's roster id"
    assert got["copy_owner"] == os.getpid(), "the run copy was not made and owned by the helper"
    assert got["token"] is not None, "the lifecycle was handed no pass"
    claims = J.claims_of(signer, got["token"])
    assert (claims["tenant"], claims["investigation"]) == (scene.tenant, roster_id)
    assert len(signer.payloads) == 1, "more than the helper's one pass was signed"
    assert _container_side(calls, _watched()) == {k: 0 for k in _watched()}
    assert calls.helper("copy") == 1, "control: the helper made the sibling's run copy once"
    _no_database_login(seen, scene)


def test_a6_the_operator_sibling_from_a_host_shell_still_admits_holds_the_lock_and_copies_for_itself(tmp_path, monkeypatch):
    """Control: `run.py --episode --world` with no job socket runs as today: one admission, one run copy, the tenant's host lock held, one lifecycle. (A6: the operator path stays)"""
    from defender.tests.learning.branch.test_triplet_sibling import _episode, _no_preflight, _Recorder, _run, _sibling_argv
    from defender.tests.storage.ids_1187 import _spec1187 as S
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.shared._locations_1210 import location_path

    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    _base, src = location_path(T.runs_base)(tmp_path)
    ep = _episode(tmp_path, src)
    S.write_roster(ep, {T.world_id(ep, w): S.new_id() for w in T.WORLDS})
    rec = _Recorder([])

    with ThreadCalls({k: v for k, v in _watched().items() if k in ("admission", "copy", "hold_shared", "acquire")}) as calls:
        _run().main(_sibling_argv(ep / "family.yaml"), lifecycle=rec, visualize=lambda *a, **k: None,
                    preflight=_no_preflight)

    assert rec.kwargs, "the operator sibling never reached its lifecycle"
    assert (calls.helper("admission"), calls.helper("copy")) == (1, 1)
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1


@pytest.mark.parametrize("how", HOW)
def test_a5_eof_on_stdin_ends_the_sibling_as_sigterm_does(scene, tmp_path, how):
    """The sibling's real command line (`run.py --episode --world`), in the container: EOF on stdin ends the process as SIGTERM does; with stdin open and no signal it stays up. (A5, A2)"""
    job_id, source, marks = str(uuid.uuid4()), str(uuid.uuid4()), tmp_path / "marks"
    plant_episode(scene, job_id, source)

    def entry(c, seen):
        proc = start_hold(c, SIBLING_HOLD, marks, "--tenant", scene.tenant, "--episode", job_id, "--world", "b")
        return hold_how(proc, marks, how, seen)

    seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    assert seen.raised is None, seen.raised
    assert seen.extra.get("reached"), seen.extra.get("stderr")
    if how == "control-no-signal":
        assert seen.extra["alive_without_signal"] is True, "the sibling ended with its stdin still open"
    assert seen.rc != 0, "the sibling ended cleanly on a signal"
    process_gone(int((marks / "pid").read_text(encoding="utf-8")), "the sibling to be gone")
