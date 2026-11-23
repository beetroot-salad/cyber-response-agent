"""#1471 slice B: the readiness helper (`job_host`, kind `readiness`) runs an investigation's tenant-level launch steps as
the same code, stopped before the run (P-1), and writes what it computed: a refusal, its knowledge record, its own
failures (R13-1.2). Each refusal case pairs a real investigation over the same tenant (green at the base: the premise) with
the readiness record (red until built). The container half is `test_1471_readiness_container.py`."""
from __future__ import annotations

import dataclasses
import json
import shutil
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import ContainerStandIn, helper_scene, listing, make_signer
from defender.tests.support.jobs._readiness1471 import (
    AFTER_PUBLISH,
    PUBLISH_CANARY,
    assert_refused_shape,
    ExplodingDocker,
    grants_text,
    investigate,
    listed_runs,
    norm,
    readiness,
    requests_other_than,
    readiness_scene,
    RestatingDirectory,
    SECOND_TENANT,
)

process_state = J.process_state

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: E402, F401 — fixtures the helper's store seams take
from defender.tests.support.shared._openbao1163 import openbao  # noqa: E402, F401 — fixture
from defender.tests.support.shared._postgres1339 import execute  # noqa: E402

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and uses prctl(PR_SET_PDEATHSIG), Linux only")]


# --- the faults: each a premise a real investigation of the tenant meets too ----------------------------------------

@dataclasses.dataclass(frozen=True)
class Fault:
    step: str
    needle: str
    files: dict[str, Any] = dataclasses.field(default_factory=dict)
    records: Callable[[Any], Any] | None = None
    prepare: Callable[[Any, Any, Path], None] | None = None
    sealed: bool = False


def _offboarding(state: str) -> Callable[[Any, Any], None]:
    def go(scene: Any, _mp: Any, _tmp: Path) -> None:
        from defender.tests.support.jobs._jobs1342 import restate_tenant

        restate_tenant(scene.dsn, scene.tenant, state=state, data_root=scene.root)
    return go


def _only_health_checks(d: dict[str, Any]) -> None:
    for system in list(d):
        del d[system]
    d["identity"] = {"health-check": {"roles": ["gather"]}}


def _only_elastic_queries(d: dict[str, Any]) -> None:
    for system in list(d):
        if system not in ("elastic", "tacit-knowledge"):
            del d[system]
    d["elastic"] = {"query": {"roles": ["gather"]}, "health-check": {"roles": ["gather"]}}
    d["tacit-knowledge"] = {"health-check": {"roles": ["gather"]}}


def _correlation_names_two_queries(d: dict[str, Any]) -> None:
    d["elastic"]["esql"] = {"roles": ["gather", "lead-zero-correlation"]}


def _withheld_without_reason(d: dict[str, Any]) -> None:
    d["cmdb"]["list-roles"] = {"roles": []}


def _disable_elastic(spec: Any) -> Any:
    from defender.tests.support.tenancy import _systems1366 as R

    return R.edited(spec, "elastic", enabled=False)


def _unmap(scene: Any, _mp: Any, _tmp: Path) -> None:
    scene.unmap()


def _no_adapters_tree(_scene: Any, mp: Any, tmp: Path) -> None:
    """The process's code tree is a folder with no `integrations/`: the adapters roster cannot be read."""
    tree = tmp / "no-adapters-tree"
    tree.mkdir()
    mp.setenv("DEFENDER_DIR", str(tree))


def _damaged_export(scene: Any, _mp: Any, _tmp: Path) -> None:
    """A link planted in the kept export the publish names, which a run's copy of it refuses whole."""
    stray = next(p for p in (scene.root / scene.tenant / "exports" / scene.t.commit / "agent").rglob("*") if p.is_file())
    stray.unlink()
    stray.symlink_to("/etc/passwd")


FAULTS: dict[str, Fault] = {
    "offboarding": Fault("tenant", "offboarding", prepare=_offboarding("offboarding")),
    "creating": Fault("tenant", "creating", prepare=_offboarding("creating")),
    "no_alert_mapping": Fault("alert_mapping", "alert mapping", prepare=_unmap),
    "gather_queries_nothing": Fault("run_tenant", "no query verb",
                                    files={"settings/verb-grants.yaml": grants_text(_only_health_checks)}),
    "withheld_without_reason": Fault("run_tenant", "gives no reason",
                                     files={"settings/verb-grants.yaml": grants_text(_withheld_without_reason)}),
    "correlation_two_query_pairs": Fault("run_tenant", "query verbs",
                                         files={"settings/verb-grants.yaml": grants_text(_correlation_names_two_queries)}),
    "every_query_grant_ignored": Fault("tenant_verdict", "were ignored", records=_disable_elastic,
                                       files={"settings/verb-grants.yaml": grants_text(_only_elastic_queries)}),
    "damaged_kept_export": Fault("knowledge_copy", "could not be copied", prepare=_damaged_export),
    "unreadable_adapters_tree": Fault("roster", "cannot be read", prepare=_no_adapters_tree),
    "sealed_signer": Fault("first_pass", "could not be signed", sealed=True),
}


def _signer(sealed: bool) -> Any:
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    return A.RaisingSigner(RuntimeError("openbao is sealed")) if sealed else make_signer()


def _scene(faults: list[Fault], tmp_path: Path, monkeypatch: Any, dsn: str, **kw: Any):
    """The helper scene with every fault in `faults` planted (their files and record edits merged, their preparations
    run once the scene exists)."""
    files: dict[str, Any] = {}
    for f in faults:
        files.update(f.files)
    editors = [f.records for f in faults if f.records is not None]

    def records(spec: Any) -> Any:
        for edit in editors:
            spec = edit(spec)
        return spec

    return readiness_scene(tmp_path, monkeypatch, dsn, files=files, records=records if editors else None, **kw)


def _premise_refused(scene: Any, faults: list[Fault], *, publish: Any = None) -> None:
    """A real investigation of the same tenant is refused in setup, its stderr naming the first fault's cause."""
    seams = {} if publish is None else {"publish": publish}
    inv = investigate(scene, signer=_signer(any(f.sealed for f in faults)), **seams)
    assert inv.refused, f"premise: the investigation was not refused: {inv.end!r}\n{inv.err[-800:]}"
    assert norm(faults[0].needle) in norm(inv.err), f"premise: the refusal does not name {faults[0].needle!r}:\n{inv.err[-800:]}"


# --- P-1: the first refusing step's sentence is the investigation's ---------------------------------------------------

@pytest.mark.parametrize("name", list(FAULTS))
def test_p1_each_tenant_level_step_refuses_a_readiness_with_the_sentence_an_investigation_of_that_tenant_is_refused_with(
        tmp_path, monkeypatch, migrated_database, name):
    """A tenant whose investigation is refused at a tenant-level step reads `refused` at that step, its sentence the
    cause, no container started, the knowledge record present exactly when the step is after `publish`. (P-1, R3, R13-1.2)"""
    fault = FAULTS[name]
    with _scene([fault], tmp_path, monkeypatch, migrated_database) as scene:
        if fault.prepare is not None:
            fault.prepare(scene, monkeypatch, tmp_path)
        _premise_refused(scene, [fault])
        ran = readiness(scene, signer=_signer(fault.sealed), container=lambda c: 0)

        sentence = assert_refused_shape(ran.result(), fault.step)
        assert norm(fault.needle) in norm(sentence), f"the sentence does not name its cause: {sentence!r}"
        assert ran.docker.boxes == [], "a container was started for a tenant the helper refused"
        assert ran.ran.raised is None
        assert ran.ran.rc == 0, f"the helper serves a refusal to its end: {ran.said()}"
        if fault.step in AFTER_PUBLISH:
            known = ran.knowledge
            assert isinstance(known, dict), f"a refusal after the publish carries its knowledge record: {ran.said()}"
            assert (known["status"], known["commit"]) == ("current", scene.t.commit), known  # staged served shape (#1546)
        else:
            assert ran.knowledge is None, f"no source was settled, so no knowledge record: {ran.knowledge!r}"
        assert listed_runs(scene) == [], "the runs listing refuses the readiness records the helper wrote"


@pytest.mark.parametrize(("first", "later"), [
    ("no_alert_mapping", "gather_queries_nothing"),
    ("gather_queries_nothing", "sealed_signer"),
    ("every_query_grant_ignored", "sealed_signer"),
], ids=["mapping-before-grants", "grants-before-signing", "verdict-before-signing"])
def test_p1_the_first_refusing_step_in_the_launch_order_is_the_result_and_nothing_after_it_is_judged(
        tmp_path, monkeypatch, migrated_database, first, later):
    """A tenant with two faults reads `refused` at the earlier step of P-1's order, the later fault unnamed; each fault
    alone (the controls) reads at its own step, and a real investigation stops at the same first one. (P-1, N5)"""
    a, b = FAULTS[first], FAULTS[later]
    with _scene([a, b], tmp_path, monkeypatch, migrated_database) as scene:
        for f in (a, b):
            if f.prepare is not None:
                f.prepare(scene, monkeypatch, tmp_path)
        _premise_refused(scene, [a, b])
        ran = readiness(scene, signer=_signer(True), container=lambda c: 0)

        sentence = assert_refused_shape(ran.result(), a.step)
        assert norm(a.needle) in norm(sentence)
        assert norm(b.needle) not in norm(sentence), f"the later fault was judged too: {sentence!r}"
        assert ran.docker.boxes == []


def test_p1_r13_1_the_records_step_premise_an_investigation_of_a_tenant_that_leaves_active_after_admission_is_refused(
        tmp_path, monkeypatch, migrated_database):
    """The premise of the `records` case: a real investigation handed the same restating directory is refused naming the
    tenant's state. (P-1, R13-1, owner decision: the step is tested)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        directory = RestatingDirectory(scene)
        inv = investigate(scene, directory=directory)
        assert directory.admitted_active, "the investigation never admitted the tenant through the directory it was handed"
        assert inv.refused, f"the investigation was not refused: {inv.end!r}\n{inv.err[-800:]}"
        assert "offboarding" in norm(inv.err), f"the refusal does not name the tenant's state:\n{inv.err[-800:]}"


def test_p1_r13_1_a_tenant_that_leaves_active_after_admission_reads_refused_at_the_records_step(
        tmp_path, monkeypatch, migrated_database):
    """An offboarding between admission and the records read is `refused` at `records`, no container, no knowledge record.
    (P-1, R13-1, owner decision: the step is tested)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        directory = RestatingDirectory(scene)
        ran = readiness(scene, container=lambda c: 0, directory=directory)

        assert directory.admitted_active, f"the helper never admitted the tenant through the directory it was handed: {ran.said()}"
        assert directory.records_asked == [scene.tenant], f"the records were not read through the handed directory: {ran.said()}"
        sentence = assert_refused_shape(ran.result(), "records")
        assert "offboarding" in norm(sentence), f"the sentence does not name the tenant's state: {sentence!r}"
        assert "not active" in norm(sentence), f"the sentence does not say the tenant is not active: {sentence!r}"
        assert ran.docker.boxes == [], "a container was started for a tenant that left active"
        assert ran.ran.raised is None
        assert ran.ran.rc == 0, f"the helper serves a refusal to its end: {ran.said()}"
        assert ran.knowledge is None, f"the records step is before the publish: {ran.knowledge!r}"


def test_p3_a_database_outage_at_admission_reads_refused_at_the_tenant_step_never_failed(
        tmp_path, monkeypatch, migrated_database):
    """The records' database cannot be reached: an outage reads as a refusal whose sentence says so, like an investigation's,
    and the helper writes no `failed` record. (P-3, D8)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", J.closed_port_dsn(migrated_database))
        inv = investigate(scene)
        assert inv.refused
        assert "could not be reached" in inv.err, f"premise: {inv.end!r}\n{inv.err[-600:]}"
        ran = readiness(scene, container=lambda c: 0)

        sentence = assert_refused_shape(ran.result(), "tenant")
        assert "reach" in norm(sentence), f"the sentence does not say the database could not be reached: {sentence!r}"
        assert ran.knowledge is None


# --- publish: R3 refused with the kind only, R5 a new tenant -----------------------------------------------------------

def _publish_says(kind: str) -> Callable[..., str]:
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    return {"misconfigured": lambda *a, **k: B.misconfigured(PUBLISH_CANARY),
            "stale:transient": lambda *a, **k: B.stale("transient", PUBLISH_CANARY),
            "stale:operator": lambda *a, **k: B.stale("operator", PUBLISH_CANARY)}[kind]


@pytest.mark.parametrize("kind", ["misconfigured", "stale:transient", "stale:operator"])
def test_p2_r5_a_refused_publish_is_refused_at_the_publish_step_naming_its_kind_and_never_the_reply_or_failed(
        tmp_path, monkeypatch, migrated_database, kind):
    """A misconfigured publish, or a stale one for a tenant with no published copy (a new tenant), reads `refused` at
    `publish` with the kind in its sentence and none of the reply text, and gives no knowledge record. (R3, R5, P-2)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        if kind != "misconfigured":
            (scene.root / scene.tenant / "exports" / "current").unlink()
        inv = investigate(scene, publish=_publish_says(kind))
        assert inv.refused, f"premise: the investigation was not refused: {inv.end!r}\n{inv.err[-600:]}"
        assert PUBLISH_CANARY in inv.err, "premise: the launch's own refusal carries the reply, which readiness must not"
        ran = readiness(scene, publish=_publish_says(kind), container=lambda c: 0)

        sentence = assert_refused_shape(ran.result(), "publish")
        words = norm(sentence)
        assert all(w in words for w in kind.split(":")), f"the sentence does not name its kind {kind!r}: {sentence!r}"
        staged = json.dumps(ran.staged(), default=str)  # everything the helper staged: the record, and nothing else carries the reply
        assert "FORGE-REPLY-CANARY" not in staged
        assert "/srv/forge" not in staged
        assert ran.knowledge is None, "the publish gave no source, so there is no knowledge record"
        assert ran.docker.boxes == []
        assert ran.ran.rc == 0


def test_r3_a_stale_publish_over_a_published_copy_is_no_refusal_and_its_knowledge_record_says_stale(
        tmp_path, monkeypatch, migrated_database):
    """Control for the refusals above: with a published copy a stale publish settles on it, and the helper starts its
    container with the knowledge record saying `stale` and its kind. (R3, R13-1.2)"""
    from defender.tenancy import run_knowledge

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        ran = readiness(scene, publish=_publish_says("stale:transient"), container=lambda c: 0)

        assert ran.docker.job_ran, f"a stale publish over a published copy refused the check: {ran.said()}"
        known = ran.knowledge
        assert isinstance(known, dict), ran.said()
        assert (known["status"], known["commit"], known["stale_kind"]) == (  # staged served shape (#1546)
            "stale", scene.t.commit, run_knowledge.TRANSIENT), known
        assert ran.record is None, "the helper writes no result record when it serves the job to its container"


# --- the publish trigger: the seam is told who asked, and the child's argv carries it ------------------------------------

def _recording_publish(seen: list[dict[str, Any]], commit: str) -> Callable[..., str]:
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    def publish(*_a: Any, **k: Any) -> str:
        seen.append(k)
        return B.fresh(commit)
    return publish


def test_p2_the_launch_time_publish_is_told_its_trigger_readiness_for_a_check_and_launch_time_publish_for_an_investigation(
        tmp_path, monkeypatch, migrated_database):
    """The publish seam is called with `trigger="readiness"` by the readiness helper and `"launch-time publish"` by an
    investigation's, so a readiness publish is recorded as one. (P-2, design §6 Publish trigger)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        inv_seen: list[dict[str, Any]] = []
        investigate(scene, publish=_recording_publish(inv_seen, scene.t.commit))
        assert len(inv_seen) == 1, f"premise: an investigation's launch publishes once: {inv_seen}"
        assert [k.get("trigger") for k in inv_seen] == ["launch-time publish"], inv_seen
        seen: list[dict[str, Any]] = []
        ran = readiness(scene, publish=_recording_publish(seen, scene.t.commit), container=lambda c: 0)

        assert ran.docker.job_ran, ran.said()
        assert [k.get("trigger") for k in seen] == ["readiness"], seen


@pytest.mark.parametrize("trigger", ["readiness", "launch-time publish"])
def test_p2_the_publish_child_is_handed_the_trigger_it_was_launched_with(tmp_path, trigger):
    """The launcher's child argv carries the trigger handed in, as its own token or a flag's value, and no other. (P-2)"""
    from defender.investigation.publish_launch import launch_publish

    argvs: list[list[str]] = []

    def spawn(argv: list[str], **_k: Any) -> Any:
        argvs.append(list(argv))
        raise OSError("no child in this test")

    launch_publish("trigger-tenant", data_root=tmp_path, trigger=trigger, spawn=spawn)

    assert len(argvs) == 1, argvs
    carried = {t.split("=", 1)[-1] for t in argvs[0]}
    other = ({"readiness", "launch-time publish"} - {trigger}).pop()
    assert trigger in carried, f"the child's argv does not carry the trigger {trigger!r}: {argvs[0]}"
    assert other not in carried, argvs[0]


# --- R13-1.2: the knowledge record --------------------------------------------------------------------------------------

def test_r13_1_2_the_helper_writes_the_knowledge_record_for_the_source_it_settled_before_its_container_starts(
        tmp_path, monkeypatch, migrated_database):
    """When the publish gave a source, its knowledge is staged under the check's claim (as the served shape `{status, commit,
    stale_kind}`, mapped once from the source's `{kind, commit, stale_kind, reason}`) by the time the container runs, and
    no record file is written. (R13-1.2; #1546 PR2, D5)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        seen: dict[str, Any] = {}

        def container(c: Any) -> int:
            seen["at_start"] = execute(scene.dsn, "SELECT body FROM jobs.staged_facts WHERE token = %s AND name = 'knowledge'",
                                       (scene.claim,))
            return 0

        rid = str(uuid.uuid4())
        seen["rid"] = rid
        ran = readiness(scene, rid=rid, container=container)

        assert seen.get("at_start"), f"no knowledge staged when the container started: {ran.said()}"
        known = ran.knowledge
        assert seen["at_start"] == [(known,)], "the knowledge staged at the container's start is not the one the check ends with"
        assert (known["status"], known["commit"]) == ("current", scene.t.commit), known
        assert set(known) == {"status", "commit", "stale_kind"}, known
        assert not (scene.runs / f"{seen['rid']}.knowledge-source.json").exists(), "a knowledge record file was written (A-O2)"


def test_r13_1_2_a_knowledge_record_that_cannot_be_written_is_a_crash_with_no_record_and_no_container(
        tmp_path, monkeypatch, migrated_database):
    """A `knowledge` fact already staged under the claim is kept as it was (a staged fact is create-once); the refused write
    propagates as a crash: the helper exits non-zero, stages no readiness result and starts no container. (R13-1.2,
    surface §5; #1546 PR7)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        control = readiness(scene, container=lambda c: 0)
        assert control.docker.job_ran, f"control: with no record in the way the container starts: {control.said()}"
        assert control.ran.rc == 0, control.said()
        rid = str(uuid.uuid4())
        ran = readiness(scene, rid=rid, container=lambda c: 0, staged={"knowledge": WEDGED_KNOWLEDGE})

        assert ran.knowledge == WEDGED_KNOWLEDGE, f"the helper replaced a staged knowledge fact: {ran.said()}"
        assert ran.docker.boxes == [], "a container was started over a knowledge record that could not be written"
        assert ran.record is None, f"a crash writes no readiness record: {ran.said()}"
        assert ran.ran.raised is not None or ran.ran.rc not in (0, None), f"a clean exit reads as no_record: {ran.said()}"


#: The faults refused at a step after the publish (the knowledge record is written before the refusal's own record).
AFTER_PUBLISH_FAULTS = [name for name, fault in FAULTS.items() if fault.step in AFTER_PUBLISH]


@pytest.mark.parametrize("name", AFTER_PUBLISH_FAULTS)
def test_r13_1_2_a_knowledge_record_that_cannot_be_written_at_a_refusal_after_the_publish_is_a_crash_with_no_record(
        tmp_path, monkeypatch, migrated_database, name):
    """At every refusing step after the publish, a knowledge record that cannot be written (one already there) is the
    helper's crash: no refusal record is written before it, no container, a non-zero exit (the worker's `worker_error`).
    The same fault with the way clear reads `refused` at its step (the P-1 case). (R13-1.2; repair 5)"""
    fault = FAULTS[name]
    with _scene([fault], tmp_path, monkeypatch, migrated_database) as scene:
        if fault.prepare is not None:
            fault.prepare(scene, monkeypatch, tmp_path)
        rid = str(uuid.uuid4())
        ran = readiness(scene, rid=rid, signer=_signer(fault.sealed), container=lambda c: 0,
                        staged={"knowledge": WEDGED_KNOWLEDGE})

        assert ran.knowledge == WEDGED_KNOWLEDGE, ran.said()
        assert ran.record is None, f"a record was written though the knowledge record could not be: {ran.said()}"
        assert ran.docker.boxes == []
        assert ran.ran.raised is not None or ran.ran.rc not in (0, None), f"a clean exit reads as no_record: {ran.said()}"


def _left_behind(scene: Any, rid: str) -> list[str]:
    """What under the tenant's folder, outside its runs folder (where the records are), is named for this check: its run
    copy, if it was not removed."""
    folder = scene.root / scene.tenant
    return sorted(str(p.relative_to(folder)) for p in folder.rglob(f"*{rid}*") if scene.runs not in p.parents)


#: A `knowledge` fact already staged under the claim: the helper's own staging of it is refused (create-once).
WEDGED_KNOWLEDGE = {"status": "current", "commit": "0" * 40, "stale_kind": None}


#: Every ending after the run copy was made: (faults, docker, container, rid planter).
COPY_MADE_ENDINGS: dict[str, tuple[list[str], Any, Any, Any]] = {
    **{f"refused-{name}": ([name], None, None, None) for name in AFTER_PUBLISH_FAULTS},
    "start-failed": ([], lambda: ContainerStandIn(run_fault=(125, "docker: refused\n")), None, None),
    "crash-writing-the-knowledge-record": ([], None, None, True),
    "crash-starting-the-container": ([], ExplodingDocker, None, None),
    "container-ended-with-no-record": ([], None, lambda c: 3, None),
    "ready": ([], None, "entry", None),
}


@pytest.mark.parametrize("ending", list(COPY_MADE_ENDINGS))
def test_r13_1_the_run_copy_is_gone_once_the_helper_has_ended_whatever_the_ending(
        tmp_path, monkeypatch, migrated_database, ending):
    """After every ending reached past the copy step (each later refusal, a start failure, a crash after the shared
    steps, a container ending of its own, `ready`), nothing named for the check is left under `<T>` but its records:
    the run copy is removed (the shared steps' cleanup; §8 run-less sidecars). Control: the copy existed while the
    container ran. (R13-1; repair 5)"""
    names, docker, container, plant = COPY_MADE_ENDINGS[ending]
    faults = [FAULTS[n] for n in names]
    with _scene(faults, tmp_path, monkeypatch, migrated_database) as scene:
        for f in faults:
            if f.prepare is not None:
                f.prepare(scene, monkeypatch, tmp_path)
        rid = str(uuid.uuid4())
        seen: dict[str, Any] = {}

        def watching(c: Any) -> int:
            facts = c.request("launch")
            seen["copy"] = Path(facts["run_copy"])
            seen["there"] = seen["copy"].is_dir()
            return 0 if container is None else (container(c) if callable(container) else 0)

        ran = readiness(scene, rid=rid, signer=_signer(any(f.sealed for f in faults)),
                        docker=None if docker is None else docker(),
                        container=None if container == "entry" else watching,
                        staged={"knowledge": WEDGED_KNOWLEDGE} if plant else None)

        assert _left_behind(scene, rid) == [], f"the check's run copy was left behind: {ran.said()}"
        if container == "entry":
            assert ran.result()["outcome"] == "ready", ran.said()
            assert ran.facts is not None
            assert not Path(ran.facts["run_copy"]).exists()
        if seen:
            assert seen["there"], "control: the run copy was there while the container ran"
            assert rid in str(seen["copy"]), f"premise: the copy is named for the check: {seen['copy']}"
            assert not seen["copy"].exists()


def test_r13_1_2_an_unexpected_crash_in_the_helpers_setup_ends_the_check_failed_worker_error_with_no_container(
        tmp_path, monkeypatch, migrated_database):
    """An exception the helper does not expect, raised by its docker seam when the container is started, is the helper's
    own `{failed, worker_error}`, no container, the helper served to its end (rc 0); a real investigation's setup ends
    crashed the same way. (R13-1.2)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        inv = investigate(scene, docker=ExplodingDocker())
        assert getattr(inv.end, "setup", None) == "crashed", f"premise: an unexpected crash is the job's setup crashed: {inv.end!r}"
        ran = readiness(scene, docker=ExplodingDocker(), container=lambda c: 0)

        assert ran.result() == {"outcome": "failed", "reason": "worker_error"}, ran.said()
        assert ran.docker.boxes == [], "a container was started after a crash"
        assert ran.ran.raised is None
        assert ran.ran.rc == 0, f"the record is the helper's own: {ran.said()}"


# --- R12-1 and C9: signing ---------------------------------------------------------------------------------------------

def test_r12_1_a_sealed_signer_refuses_a_check_with_a_grant_at_the_first_pass_and_one_with_none_not_at_all(
        tmp_path, monkeypatch, migrated_database):
    """A sealed signer with a non-empty read grant: `refused` at `first_pass`; with an empty grant it is never asked and
    the container starts. (R12-1, W-D8)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=("identity",)) as granted:
        sealed = A.RaisingSigner(RuntimeError("openbao is sealed"))
        inv = investigate(granted, signer=A.RaisingSigner(RuntimeError("openbao is sealed")))
        assert inv.refused
        assert "first pass" in inv.err, f"premise: {inv.end!r}\n{inv.err[-500:]}"
        ran = readiness(granted, signer=sealed, container=lambda c: 0)
        assert_refused_shape(ran.result(), "first_pass")
        assert sealed.asked >= 1
        assert ran.docker.boxes == []
    with readiness_scene(tmp_path / "empty", monkeypatch, migrated_database, proxied=(), tenant_id=SECOND_TENANT) as empty:
        sealed = A.RaisingSigner(RuntimeError("openbao is sealed"))
        ran = readiness(empty, signer=sealed, container=lambda c: 0)
        assert ran.docker.job_ran, f"a check with nothing to sign was refused by a sealed signer: {ran.said()}"
        assert sealed.asked == 0, "the signer was asked for a check whose grant is empty"
        assert ran.record is None


def test_p2_a_first_pass_refusal_carries_our_sentence_and_never_the_signers_own_error_text(
        tmp_path, monkeypatch, migrated_database):
    """The signer's error (OpenBao's reply) is not our words: the `first_pass` sentence the admin reads says the pass
    could not be signed and quotes none of it; the helper's log still names it. (P-2: never a reply from another
    system)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    reply = "vault-reply-7f3a: the barrier is sealed at 10.0.0.9"
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=("identity",)) as scene:
        ran = readiness(scene, signer=A.RaisingSigner(RuntimeError(reply)), container=lambda c: 0)
        sentence = assert_refused_shape(ran.result(), "first_pass")
        assert "could not be signed" in norm(sentence), sentence
        assert "vault-reply-7f3a" not in sentence, f"the signer's reply reached the admin: {sentence!r}"
        assert "10.0.0.9" not in sentence, f"the signer's reply reached the admin: {sentence!r}"
        assert "vault-reply-7f3a" in ran.err, f"the helper's log lost the cause: {ran.said()}"


def test_r12_1_the_first_read_pass_is_signed_once_under_the_readiness_id_and_thrown_away(
        tmp_path, monkeypatch, migrated_database):
    """A non-empty grant: exactly one signing call, naming the tenant, the readiness id and the grant; the container is
    handed no pass. (R12-1)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=("identity",)) as scene:
        signer, rid = make_signer(), str(uuid.uuid4())
        ran = readiness(scene, signer=signer, rid=rid, container=lambda c: 0)

        assert ran.docker.job_ran, ran.said()
        assert len(signer.payloads) == 1, f"the cost is one signing call per check: {len(signer.payloads)}"
        claims = A.claims_of_payload(signer.payloads[0])
        assert (claims["tenant"], claims["investigation"]) == (scene.tenant, rid)
        assert A.grant_of(claims) == [("identity", "r")]
        assert "pass" not in (ran.facts or {})
        assert "token" not in str(ran.facts), "the container was handed a pass"


@pytest.mark.parametrize("proxied", [("identity",), ()], ids=["grant", "no-grant"])
@pytest.mark.parametrize("missing", ["no proxy address", "no sign login"])
def test_r12_1_c9_signing_configuration_is_always_checked_and_its_sentence_never_says_a_system_is_reached_through_the_proxy(
        tmp_path, monkeypatch, migrated_database, missing, proxied):
    """No proxy address, or no sign login for the live generation, reads `refused` at `signing` whatever the grant; the
    sentence never says "a system is reached through the credential proxy", proxied system or none. (R12-1, W5, C9)"""
    from defender.kit.access import PROXY_URL_ENV
    from defender.tests.support.shared._postgres1339 import execute

    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=proxied) as scene:
        if missing == "no proxy address":
            monkeypatch.delenv(PROXY_URL_ENV, raising=False)
        else:
            execute(migrated_database, "DELETE FROM tenancy.generations WHERE tenant_id = %s", (scene.tenant,))
        inv = investigate(scene)
        assert inv.refused, f"premise: the investigation's signing set-up was not refused: {inv.end!r}"
        ran = readiness(scene, container=lambda c: 0)

        sentence = assert_refused_shape(ran.result(), "signing")
        assert "a system is reached through the credential proxy" not in sentence, sentence
        assert "sign" in norm(sentence) or PROXY_URL_ENV in sentence, sentence
        assert ran.docker.boxes == []


# --- C4: the socket; the launch facts -----------------------------------------------------------------------------------

def test_c4_a_readiness_container_is_started_for_readiness_is_answered_launch_alone_and_is_handed_the_records(
        tmp_path, monkeypatch, migrated_database):
    """The container's command is the readiness entry for this id; its facts are kind `readiness` for this tenant and id
    with the commit and records read; every request the helper registers beyond `launch` (read from its registry) is
    refused for the kind. (C4, R13-1.3, P-1)"""
    from defender import job_host
    from defender.tenancy.record_values import TenantRecords

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        rid, refusals = str(uuid.uuid4()), {}
        # #1546 A-O2/PR2: a readiness job's typed records travel on the verbs `knowledge` and `result` (the helper stages them),
        # so those two are the kind's besides `launch`; every other registered request stays refused for the kind.
        others = requests_other_than(("launch", "knowledge", "result"))
        assert {"box.start", "pass", "pass.write_back"} <= set(others), f"premise: the registry's requests: {others}"

        def container(c: Any) -> int:
            for name in others:
                try:
                    refusals[name] = ("answered", c.request(name))
                except job_host.Refused as refused:
                    refusals[name] = ("refused", refused.code)
            return 0

        ran = readiness(scene, rid=rid, container=container)

        assert ran.docker.job_ran
        assert ran.docker.job_error is None, ran.said()
        argv = ran.docker.box.argv
        assert "--readiness" in argv
        assert argv[argv.index("--readiness") + 1] == rid, argv
        assert "--job" not in argv[argv.index("--readiness") - 1:], "an investigation's entry was started"
        facts = ran.facts
        assert isinstance(facts, dict), ran.said()
        assert (facts["kind"], facts["tenant"], facts["job"], facts["tenant_state"]) == (
            "readiness", scene.tenant, rid, "active"), facts
        assert facts["export_commit"] == scene.t.commit
        assert Path(facts["run_copy"]) == scene.root / ".job-inputs" / scene.claim / "run-knowledge" / rid  # design: `<data root>/.job-inputs/<claim>/`
        assert set(TenantRecords.handed(facts).systems) == set(J.proxied_records(("identity", "ticket")).systems)
        assert refusals == {name: ("refused", "not-for-kind") for name in others}, refusals


# --- R13-1.2: the helper's own failures -----------------------------------------------------------------------------------

@pytest.mark.parametrize("stderr", [
    "Unable to find image 'defender-job:latest' locally\n",
    "docker: Error response from daemon: unknown or invalid runtime name: runsc\n",
])
def test_r13_1_2_a_container_that_cannot_start_ends_the_check_failed_start_failed_after_the_knowledge_record(
        tmp_path, monkeypatch, migrated_database, stderr):
    """`docker run` refuses (rc 125): the helper records `{outcome: failed, reason: start_failed}`, never a refusal, with
    the knowledge record already there. (R13-1.2, P-3)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        ran = readiness(scene, docker=ContainerStandIn(run_fault=(125, stderr)), container=lambda c: 0)

        assert ran.result() == {"outcome": "failed", "reason": "start_failed"}, ran.said()
        assert isinstance(ran.knowledge, dict)
        assert ran.knowledge["commit"] == scene.t.commit
        assert ran.ran.rc == 0, "the helper served the check to its end"


def _docker_did_not_run() -> list[int]:
    from defender.job_host._session import DOCKER_DID_NOT_RUN

    return sorted(DOCKER_DID_NOT_RUN)


@pytest.mark.parametrize("rc", _docker_did_not_run())
def test_r13_1_2_every_docker_exit_that_means_the_container_never_ran_is_start_failed(
        tmp_path, monkeypatch, migrated_database, rc):
    """Each `docker run` exit of the class that never ran the entry (refused, not invokable, not found), with no record:
    the helper's `{failed, start_failed}`. (R13-1.2; repair 5: the class, not 125 alone)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        ran = readiness(scene, docker=ContainerStandIn(run_fault=(rc, "docker: the container did not start\n")),
                        container=lambda c: 0)

        assert ran.result() == {"outcome": "failed", "reason": "start_failed"}, ran.said()
        assert ran.ran.rc == 0, "the helper served the check to its end"


def test_r13_5_a_helper_told_to_stop_before_its_container_starts_writes_no_record(tmp_path, monkeypatch, migrated_database):
    """SIGTERM while the host half runs (here, during the launch-time publish): no container, and no record of the
    helper's own, so the stopping worker's `worker_stopped` stands; control: unstopped, the container starts. (R13-5;
    repair 5)"""
    import os
    import signal

    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        control = readiness(scene, container=lambda c: 0)
        assert control.docker.job_ran, f"control: the container starts: {control.said()}"

        def stopped_while_publishing(*_a: Any, **_k: Any) -> str:
            os.kill(os.getpid(), signal.SIGTERM)
            return B.fresh(scene.t.commit)

        ran = readiness(scene, publish=stopped_while_publishing, container=lambda c: 0)

        assert ran.docker.boxes == [], f"a container was started after the stop: {ran.said()}"
        assert ran.record is None, f"a stopped helper wrote a record of its own: {ran.said()}"


def test_r13_1_2_a_job_socket_that_cannot_be_opened_ends_the_check_failed_start_failed(
        tmp_path, monkeypatch, migrated_database):
    """A data root so deep the job socket's path cannot fit: `failed`/`start_failed`, no container. (R13-1.2)"""
    with helper_scene(tmp_path, monkeypatch, migrated_database, proxied=("identity",), root_pad=60) as scene:
        ran = readiness(scene, container=lambda c: 0)

        assert ran.result() == {"outcome": "failed", "reason": "start_failed"}, ran.said()
        assert ran.docker.boxes == []


def test_r13_1_1_a_missing_runs_folder_is_damage_the_helper_does_not_make_and_it_exits_non_zero_with_no_record(
        tmp_path, monkeypatch, migrated_database):
    """`<T>/runs` removed after the worker's pre-open (a race): the helper makes nothing, starts no container, and does not
    report a refusal (`runs_folder` is no step), so the worker reads its exit. (R13-1.1, P-3)"""
    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        control = readiness(scene, container=lambda c: 0)
        assert control.docker.job_ran, f"control: with its runs folder the helper starts its container: {control.said()}"
        shutil.rmtree(scene.runs)  # it holds the control's records (its knowledge record, its result)
        ran = readiness(scene, container=lambda c: 0)

        assert not scene.runs.exists(), "the helper made the tenant's runs folder"
        assert ran.docker.boxes == []
        assert ran.ran.raised is not None or ran.ran.rc not in (0, None), f"a clean exit hides the damage: {ran.said()}"


# --- P-1: the same steps, none of the investigation's own ------------------------------------------------------------------

def test_p1_a_check_runs_each_tenant_level_launch_step_once_in_the_helper_and_none_that_belongs_to_an_investigation(
        tmp_path, monkeypatch, migrated_database):
    """Counted by the thread that made each call: the shared steps once in the helper; the launch check, the alert's
    materialisation and the versions record never; no run folder, launch record or job-end is made. (P-1)"""
    from defender import run_common
    from defender.records import job_lane
    from defender.tests.support.jobs._container_entry1170 import ThreadCalls

    steps = {"read_records": run_common.read_records, "read_alert_mapping": run_common.read_alert_mapping,
             "resolve_knowledge": run_common.resolve_knowledge, "copy_knowledge": run_common.copy_knowledge,
             "run_tenant_or_exit": run_common.run_tenant_or_exit, "run_roster": run_common.run_roster,
             "tenant_verdict": run_common.tenant_verdict,
             "materialize_run": run_common.materialize_run, "write_versions_record": run_common.write_versions_record,
             "check_launch": job_lane.JobLane.check_launch}
    with readiness_scene(tmp_path, monkeypatch, migrated_database, proxied=("identity",)) as scene:
        before = listing(scene.runs)
        with ThreadCalls(steps) as calls:
            ran = readiness(scene, container=lambda c: 0)
        assert ran.docker.job_ran, ran.said()

        once = {name: calls.helper(name) for name in steps}
        assert once == {"read_records": 1, "read_alert_mapping": 1, "resolve_knowledge": 1, "copy_knowledge": 1,
                        "run_tenant_or_exit": 1, "run_roster": 1, "tenant_verdict": 1, "materialize_run": 0,
                        "write_versions_record": 0, "check_launch": 0}, once
        assert listing(scene.runs) == sorted(before), "the helper left a file in the runs folder (its records are staged facts)"


MARKUP = '<img src=x onerror="alert(1)">&'


def test_p2_d7_a_tenant_value_with_markup_and_quotes_reaches_the_refusal_sentence_verbatim_in_one_well_formed_record(
        tmp_path, monkeypatch, migrated_database):
    """A grant table naming a system `<img ...>&` is refused at `run_tenant` by a sentence quoting that name verbatim (ours,
    unescaped: escaping is the page's), stored as one valid JSON record of the refused shape. (P-2, D7)"""

    def edit(d: dict[str, Any]) -> None:
        d[MARKUP] = {"query": {"roles": ["gather"]}}

    with readiness_scene(tmp_path, monkeypatch, migrated_database,
                         files={"settings/verb-grants.yaml": grants_text(edit)}) as scene:
        inv = investigate(scene)
        assert inv.refused, f"premise: the table was not refused: {inv.end!r}\n{inv.err[-500:]}"
        assert MARKUP in inv.err, f"premise: the investigation's refusal quotes the value: {inv.err[-500:]}"
        ran = readiness(scene, container=lambda c: 0)
        ran.result()
        record = ran.result()
        sentence = assert_refused_shape(record, "run_tenant")
        assert MARKUP in sentence, f"the tenant's value does not reach the sentence verbatim: {sentence!r}"
