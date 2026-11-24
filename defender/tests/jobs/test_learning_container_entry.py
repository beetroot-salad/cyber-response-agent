"""#1170 r4 (A3, A5, A6): the learning entries inside the job container: the learning job entry (`job_entry.main`), the
post-step and the family-less check (`post_step.main`), and the sibling (`run.main` with `--episode --world`). Inside the
container none takes a host lock, runs an admission, opens the tenant database, makes a run copy, fetches knowledge or drafts, or
builds a signer (the helper does, and answers over the job socket); EOF on stdin ends each as
SIGTERM does. The operator sibling, run from a host shell, is unchanged (positive control). Driven through the real helper
(`job_host.main`) over a container stand-in whose process is the entry; the process cases run each entry's real command
line. Slice D's counterpart for the investigation is `test_job_container_entry.py`."""
from __future__ import annotations

import json
import os
import sys
import uuid
from typing import Any

import pytest
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.evidence._facts1546 import VERB_ARMS
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs._container_entry1170 import ThreadCalls, in_container_environment
from defender.tests.support.jobs._job_helper_learning import learning_end, listing
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

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures the helper's store seams take
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

HOW = ["sigterm", "stdin-eof", "control-no-signal"]
POST_STEPS = pytest.mark.parametrize("family_less", [False, True], ids=["post-step", "family-less"])


def _watched() -> dict[str, Any]:
    """What a container-side entry must not call: the host lock, an admission, a database, a run copy, a knowledge
    fetch or the child launch behind it (#1618: `fetch_report` / `launch_publish`, which replaced the launch-time
    publish), a signer (the helper's side calls each: the controls)."""
    from defender.credential_proxy import _launcher, _tokens
    from defender.database import async_engine
    from defender.investigation import publish_launch
    from defender.systems import run_tenant
    from defender.tenancy import host_lock, postgres, run_knowledge

    return {"repository": postgres.PostgresTenantRepository.__init__, "engine": async_engine,
            "admission": run_tenant.host_tenant, "hold_shared": host_lock.hold_shared, "acquire": host_lock.acquire,
            "copy": run_knowledge.adopt_copy, "fetch": run_knowledge.fetch_report,
            "publish": publish_launch.launch_publish,
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


def _host_shell_premise() -> None:
    """Checked after the act, so a missing `job_host` is not what turns the arm red."""
    from defender import job_host

    assert job_host.SOCKET_ENV not in os.environ, "premise: a host shell has no job socket"


def _staged_end(scene: Any) -> dict[str, Any] | None:
    """The learning job's end as the helper staged it (#1546 A-O2, PR2: the `outcome` fact under the claim; no learning-end
    file), or None when none was staged."""
    return H.facts(scene.dsn, scene.claim).get("outcome")


def _claimed_with_its_source(request: Any, scene: Any, job_id: str, source: str, workdir: Any) -> Any:
    """#1546 (design Learning job: "Input set: the source's `bundle`"; the job pulls it into its root): the worker's claim of
    the learning job now; returned, what plants its source's accepted bundle (a real finished source run, packed), called on
    the container's side once the helper set its store up, so the job's pull is answered."""
    H.plant(scene, "learning", owner=job_id, source=source)
    return lambda: H.store_for(request, scene).plant_source_bundle(scene, source, workdir)


def _copy_owner(scene: Any, run_id: str, run_dir: Any, owner_record: Any) -> Any:
    """The pid in the owner record of the sibling's run copy, wherever the helper placed it for this claim (#1546: the run
    copy is the helper's, in the claim's inputs or root, not `<T>/run-knowledge/` of the tenant's folder), or None."""
    from pathlib import Path

    found = [p for base in (H.job_inputs(scene), H.job_root(scene))
             for p in (Path(base).rglob(run_id) if Path(base).is_dir() else ())
             if p.is_dir() and not p.is_symlink() and p != Path(run_dir)]
    for copy in found:
        record = owner_record(copy)
        if record:
            return record["pid"]
    return None


def _episode_in_the_job_root(scene: Any, c: Any, job_id: str, source: str) -> tuple[Any, str]:
    """#1546 (design "The job's folders": the episode and arm folders are in the job's root, the container's
    `DEFENDER_DATA_ROOT`): the learning job's episode as its pre-flight leaves it, planted in the container's root (not the
    host's tenant folder), and the roster's id for world `b`."""
    import dataclasses
    from pathlib import Path

    root = Path(str(c.env["DEFENDER_DATA_ROOT"]))
    (root / scene.tenant / "runs").mkdir(parents=True, exist_ok=True)
    (root / scene.tenant / "episodes").mkdir(parents=True, exist_ok=True)
    ep, roster_id = plant_episode(dataclasses.replace(scene, root=root, runs=root / scene.tenant / "runs"), job_id, source)
    # #1546 (census "Helper arm roster from job-written files -> `arms` and `arm/<id>` facts"): the launcher sends the roster
    # over the socket before the first arm runs; the helper answers a sibling only for a run it names.
    roster = json.loads((ep / "arms.json").read_text(encoding="utf-8"))
    c.request(VERB_ARMS, record={"roster": [{"run_id": run, "world_id": world} for world, run in sorted(roster.items())]})
    return ep, roster_id


# --- the learning job entry ----------------------------------------------------------------------------------------

def test_a6_the_learning_job_entry_takes_no_lock_runs_no_admission_and_opens_no_database(scene, request, tmp_path):
    """Run in the container with the job socket set, the entry reaches its source check and ends its job with a record, having taken no host lock, run no admission, opened no database, made no copy or publish and built no signer; the helper did. (A6, A3, P-C)"""
    from defender.learning.branch import cli, job_entry

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    source_bundle = _claimed_with_its_source(request, scene, job_id, source, tmp_path / "source")
    watched = {**_watched(), "source_opened": cli._open_launch_source}

    def entry(c, seen):
        source_bundle()
        with in_container_environment(c.env):
            return job_entry.main(["--job", job_id, "--tenant", scene.tenant, "--source", source], environ=c.env,
                                  preflight=lambda *a, **k: 0)

    with ThreadCalls(watched) as calls:
        seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    _clean(seen)
    end = _staged_end(scene)
    assert end is not None, "the entry staged no learning outcome"
    assert end.get("status") != "stopped", "control: a hand-back means the entry waited on a lock it should not take"
    assert calls.container("source_opened") >= 1, "control: the entry never reached the launch steps past admission"
    assert {k: v for k, v in _container_side(calls, watched).items() if k != "source_opened"} == {
        k: 0 for k in _watched()}
    assert calls.helper("admission") == 1, "control: the helper admitted the tenant once"
    assert calls.helper("repository") >= 1, "control: the helper's side opens the database"
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1, "control: the helper holds the tenant lock"
    _no_database_login(seen, scene)


@pytest.mark.parametrize("with_parent_pid", [True, False], ids=["todays-argv", "no-parent-pid"])
def test_a5_a6_the_learning_job_entry_is_container_only_it_does_nothing_from_a_host_shell(scene, with_parent_pid):
    """Run with no job socket in its environment (a host shell that has the database login), with today's full argv, the entry exits non-zero having written no end record or progress, taken no lock and started no family step. (A5, A6)"""
    from defender.learning.branch import cli, job_entry
    from defender.tenancy import host_lock

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    plant_episode(scene, job_id, source)
    argv = ["--job", job_id, "--tenant", scene.tenant, "--source", source,
            *(["--parent-pid", str(os.getppid())] if with_parent_pid else [])]
    before = listing(scene.runs)

    with counting_calls(launch_job=cli.launch_job, acquire=host_lock.acquire) as calls:
        try:
            code = job_entry.main(argv, preflight=lambda *a, **k: 0)
        except SystemExit as stop:
            code = stop.code

    assert calls["acquire"] == 0, "the container-less entry asked for the tenant lock"
    assert host_lock.holders(scene.root, scene.tenant) == [], "the container-less entry took the tenant lock"
    assert calls["launch_job"] == 0, "a family step started"
    assert learning_end(scene, job_id) is None, "an end record was written by an entry that must not run"
    assert listing(scene.runs) == before, "the container-less entry wrote a record"
    assert code not in (0, None), "the container-less entry ran as if it were a job"
    _host_shell_premise()


@pytest.mark.parametrize("how", HOW)
def test_a5_eof_on_stdin_is_sigterm_to_the_learning_job_entry_and_takes_its_sibling_with_it(scene, tmp_path, how, request):
    """The entry's real command line, in the container: EOF on stdin ends the job as SIGTERM does (its record `stopped`, its launcher's real sibling gone); with stdin open and no signal it stays up. (A5, #1344 O9)"""
    job_id, source, marks = str(uuid.uuid4()), str(uuid.uuid4()), tmp_path / "marks"
    source_bundle = _claimed_with_its_source(request, scene, job_id, source, tmp_path / "source")

    def entry(c, seen):
        source_bundle()
        proc = start_hold(c, LEARNING_JOB_HOLD, marks, "--job", job_id, "--tenant", scene.tenant, "--source", source)
        return hold_how(proc, marks, how, seen)

    seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    assert seen.raised is None, seen.raised
    assert seen.extra.get("reached"), seen.extra.get("stderr")
    if how == "control-no-signal":
        assert seen.extra["alive_without_signal"] is True, "the entry ended with its stdin still open"
    assert (marks / "unwound").exists()
    process_gone(int((marks / "child.pid").read_text(encoding="utf-8")), "the entry's sibling to be gone")
    end = _staged_end(scene)
    assert end is not None, "no outcome staged"
    assert end.get("status") == "stopped", end


# --- the post-step and the family-less check -------------------------------------------------------------------------

@POST_STEPS
def test_a6_the_post_step_takes_no_lock_runs_no_admission_opens_no_database_and_makes_no_copy_or_draft(scene, family_less):
    """Run in the container with the job socket set, the post-step (and the family-less check) runs the drain's gate and writes no record, having taken no host lock, run no admission, opened no database; it made no run copy or draft. (A6, C23, P-C, #1487 O7; #1618: no publish-status row exists to write)"""
    from defender.learning.branch import post_step

    job_id = None if family_less else str(uuid.uuid4())
    ticks: list[int] = []
    tenant_folder = scene.root / scene.tenant
    before = (listing(tenant_folder / "run-knowledge"), listing(tenant_folder / "drafts"))
    runs_before = listing(scene.runs)

    def entry(c, seen):
        argv = [*(["--job", job_id] if job_id else []), "--tenant", scene.tenant]
        return post_step.main(argv, environ=c.env, author_tick=lambda *a, **k: ticks.append(1) or 0)

    with ThreadCalls(_watched()) as calls:
        seen = seen_in_container(scene, "post-step", entry, job_id=job_id, family_less=family_less)

    _clean(seen)
    assert ticks == [1], "control: the drain's gate did not run"
    assert listing(scene.runs) == runs_before, "the post-step wrote a record or a list into the tenant's runs"
    assert _container_side(calls, _watched()) == {k: 0 for k in _watched()}
    assert calls.helper("admission") == 1, "control: the helper admitted the tenant once"
    assert calls.helper("repository") >= 1, "control: the helper's side opens the database"
    assert calls.helper("hold_shared") + calls.helper("acquire") >= 1, "control: the helper holds the tenant lock"
    assert (listing(tenant_folder / "run-knowledge"), listing(tenant_folder / "drafts")) == before
    _no_database_login(seen, scene)


@pytest.mark.parametrize("with_parent_pid", [True, False], ids=["todays-argv", "no-parent-pid"])
def test_a5_a6_the_post_step_is_container_only_it_does_nothing_from_a_host_shell(scene, with_parent_pid):
    """Run with no job socket in its environment, with today's full argv, the post-step exits non-zero having written no record and run no gate. (A5, A6)"""
    from defender.learning.branch import post_step

    job_id = str(uuid.uuid4())
    ticks: list[int] = []
    argv = ["--job", job_id, "--tenant", scene.tenant, *(["--parent-pid", str(os.getppid())] if with_parent_pid else [])]
    before = listing(scene.runs)

    try:
        code = post_step.main(argv, author_tick=lambda *a, **k: ticks.append(1) or 0)
    except SystemExit as stop:
        code = stop.code

    assert ticks == [], "the container-less post-step ran the gate"
    assert not (scene.runs / f"{job_id}.post-step.json").exists()
    assert listing(scene.runs) == before, "the container-less post-step wrote a record"
    assert code not in (0, None), "the container-less post-step ran as if it were a job"
    _host_shell_premise()


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
    signer, got = J.make_signer(), {}

    def lifecycle(**kw):
        run = kw["run"]
        got["run_dir"], got["token"] = run.run_dir, kw["access"].token() if kw.get("access") else None
        got["copy_owner"] = _copy_owner(scene, run.run_dir.name, run.run_dir, owner_record)
        (run.run_dir / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}

    def entry(c, seen):
        got["ep"], got["roster_id"] = _episode_in_the_job_root(scene, c, job_id, source)
        got["signed_before"] = len(signer.payloads)  # the learning job's own first pass, signed at claim (O5)
        with in_container_environment(c.env):
            return run_py.main(["--tenant", scene.tenant, "--episode", job_id, "--world", "b"], environ=c.env,
                               lifecycle=lifecycle, visualize=lambda *a, **k: None, preflight=lambda *a, **k: 0)

    with ThreadCalls(_watched()) as calls:
        seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source, signer=signer)

    _clean(seen)
    ep, roster_id = got["ep"], got["roster_id"]
    assert got["run_dir"] == ep / "runs" / roster_id, "the sibling did not run at its world's roster id"
    assert got["copy_owner"] == os.getpid(), "the run copy was not made and owned by the helper"
    assert got["token"] is not None, "the lifecycle was handed no pass"
    claims = J.claims_of(signer, got["token"])
    assert (claims["tenant"], claims["investigation"]) == (scene.tenant, roster_id)
    assert got["signed_before"] >= 1, "premise: the helper signed the learning job's first pass at claim"
    assert len(signer.payloads) == got["signed_before"] + 1, "the sibling's run had more than the helper's one pass signed"
    assert _container_side(calls, _watched()) == {k: 0 for k in _watched()}
    # #1618 flow 3 ("`copy.make` ..., the grant read and the judge's lesson bodies all ask the helper"): the helper adopts
    # two copies, the grant read's (`main`, at claim) and the sibling's (its pin), and the container none.
    assert calls.helper("copy") == 2, "control: the helper made the grant read's copy and the sibling's run copy, once each"
    _no_database_login(seen, scene)


def test_1546_r10_a_siblings_run_and_its_start_records_are_made_in_the_container_at_the_answered_run_id(scene):
    """D-2 (owner decision; design r10 (a) "The container materialises the run"): on `copy.make(world=)` the helper makes
    the sibling's run copy and only the episode's `runs/` folder; the sibling, in the container, makes its run
    (`run_common.materialize_run` at the roster's id: the folder with its alert and stamp) and writes its knowledge record
    (naming the launch facts' `knowledge_commit`) and its versions record. The helper writes none of them, so each is
    counted on the container's thread and never on the helper's. WRITE-TESTS CHOICE (r10 "Open for write-tests: the
    versions record's source"): the launch facts already carry `records` (#1366 O6), so the container writes the versions
    record from them and `copy.make(world=)`'s answer adds nothing; the oracle is the launch facts' own versions, read from
    the wire here, not through the writer. Control: the lifecycle ran at that run (the sibling started at all)."""
    from pathlib import Path

    from defender import run as run_py
    from defender import run_common
    from defender.records import RunPaths

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    got: dict[str, Any] = {}

    def lifecycle(**kw):
        run_dir = Path(kw["run"].run_dir)
        paths = RunPaths(run_dir)
        got["run_dir"] = run_dir
        got["made"] = {"alert": paths.alert.is_file(), "stamp": paths.provenance.is_file()}
        got["knowledge"] = json.loads(paths.knowledge_source().read_text(encoding="utf-8"))
        got["versions"] = json.loads(paths.record_versions.read_text(encoding="utf-8"))
        return {"output": "done", "requests": 1, "truncated_by": None}

    def entry(c, seen):
        got["ep"], got["roster_id"] = _episode_in_the_job_root(scene, c, job_id, source)
        got["launch"] = c.request("launch")
        with in_container_environment(c.env):
            return run_py.main(["--tenant", scene.tenant, "--episode", job_id, "--world", "b"], environ=c.env,
                               lifecycle=lifecycle, visualize=lambda *a, **k: None, preflight=lambda *a, **k: 0)

    watched = {"materialize": run_common.materialize_run, "knowledge_record": run_common.write_knowledge_record,
               "versions_record": run_common.write_versions_record}
    with ThreadCalls(watched) as calls:
        seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    _clean(seen)
    assert got.get("run_dir") == got["ep"] / "runs" / got["roster_id"], "control: the sibling did not run at its roster id"
    for label in watched:
        assert calls.helper(label) == 0, f"the helper ran `{label}` for the sibling (D-2: the container's)"
        assert calls.container(label) == 1, f"the sibling's container did not run `{label}` once: {calls.by_thread[label]}"
    assert got["made"] == {"alert": True, "stamp": True}, got["made"]
    launch = got["launch"]
    assert got["knowledge"].get("commit") == launch["knowledge_commit"], (got["knowledge"], launch["knowledge_commit"])
    handed = launch["records"]
    expected = {"systems": {sid: rec["version"] for sid, rec in sorted(handed["systems"].items())},
                "case": None if handed.get("case") is None else handed["case"]["version"]}
    assert got["versions"] == expected, f"the versions record is not the launch facts' records: {got['versions']}"


def test_o2_a_sibling_in_the_container_has_its_oracle_box_started_by_its_helper(scene, tmp_path, monkeypatch):
    """In the container, the box a sibling's oracle runs its python in is started by the job's helper over the job
    socket, for the sibling's own run id, as pre-flight's is: the sibling never starts a box itself (the job image has
    no docker, #1170 O2; #1543 R-B)."""
    from defender import run as run_py
    from defender.job_host import _learning as helper_learning
    from defender.learning.branch.estate import oracle as oracle_mod

    # The job image has no docker: a direct start from the container meets one that refuses (the helper's own
    # docker is its seam, never PATH).
    no_docker = tmp_path / "no-docker"
    no_docker.mkdir()
    (no_docker / "docker").write_text("#!/bin/sh\necho 'no docker in the job image' >&2\nexit 127\n", encoding="utf-8")
    (no_docker / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", f"{no_docker}{os.pathsep}{os.environ.get('PATH', '')}")

    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    got: dict[str, Any] = {}

    def lifecycle(**kw):
        try:
            got["box"] = kw["serving"].box()
        except Exception as failed:  # noqa: BLE001 — the start's failure is what the arm reports
            got["failed"] = failed
        return {"output": "done", "requests": 1, "truncated_by": None}

    def entry(c, seen):
        _ep, got["roster_id"] = _episode_in_the_job_root(scene, c, job_id, source)
        with in_container_environment(c.env):
            return run_py.main(["--tenant", scene.tenant, "--episode", job_id, "--world", "b"], environ=c.env,
                               lifecycle=lifecycle, visualize=lambda *a, **k: None, preflight=lambda *a, **k: 0)

    helper_start = helper_learning._oracle_box.__code__

    class _Calls(ThreadCalls):
        """`ThreadCalls`, also keeping the id each helper-side oracle box start was asked for."""

        def __init__(self, functions: dict[str, Any]) -> None:
            super().__init__(functions)
            self.idents: list[Any] = []

        def _hook(self, frame: Any, event: str, arg: object) -> None:
            super()._hook(frame, event, arg)
            if self._active and event == "call" and frame.f_code is helper_start:
                self.idents.append(frame.f_locals.get("_ident"))

    watched = {"direct": oracle_mod.start_process_box, "helper": helper_learning._oracle_box}
    with _Calls(watched) as calls:
        seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    _clean(seen)
    assert "failed" not in got, f"the sibling's oracle box did not start: {got.get('failed')!r}"
    assert calls.container("direct") == 0, "the sibling started its oracle box itself, from the container"
    assert calls.helper("helper") == 1, "the helper did not start the sibling's oracle box"
    assert calls.idents == [got["roster_id"]], f"the oracle box was not started for the sibling's own run: {calls.idents}"
    assert got["box"].sandboxed, "the sibling's oracle box is not a confined (relayed) box"
    oracle_starts = [c for c in seen.kind.docker.creates() if any("defender-oracle-" in a for a in c)]
    assert len(oracle_starts) == 1, f"expected one oracle box start through the helper's docker: {oracle_starts}"


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

    def entry(c, seen):
        _episode_in_the_job_root(scene, c, job_id, source)
        proc = start_hold(c, SIBLING_HOLD, marks, "--tenant", scene.tenant, "--episode", job_id, "--world", "b")
        return hold_how(proc, marks, how, seen)

    seen = seen_in_container(scene, "learning", entry, job_id=job_id, source=source)

    assert seen.raised is None, seen.raised
    assert seen.extra.get("reached"), seen.extra.get("stderr")
    if how == "control-no-signal":
        assert seen.extra["alive_without_signal"] is True, "the sibling ended with its stdin still open"
    assert seen.rc != 0, "the sibling ended cleanly on a signal"
    process_gone(int((marks / "pid").read_text(encoding="utf-8")), "the sibling to be gone")
