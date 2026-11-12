"""#1170 (r4): the per-job host helper's learning kinds: a learning job (pre-flight and siblings), the post-step and the
family-less check. Requests are answered by job kind, ids are minted by the helper, and the post-step's database writes,
drain publish and forge tokens are the helper's. Driven as `test_job_helper.py` drives the investigation kind (its scene,
its stand-in container). What a container can reach from inside is `e2e/test_job_box_boundary_e2e.py`."""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

import pytest
from defender.tests.support.jobs._job_helper import (
    OTHER_TENANT,
    ContainerStandIn,
    ForgeCredentialRecorder,
    after_the_signal,
    claims_of,
    make_signer,
    parse_labels,
    parse_mounts,
)
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper_learning import (
    clear_publish_status,
    learning_end,
    listing,
    plant_decoy,
    plant_siblings,
    publish_status,
    run_kind,
)

# The shared fixtures (`_job_helper`'s docs): `process_state` is autouse, `scene` the default helper scene.
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and uses prctl(PR_SET_PDEATHSIG), Linux only")]




COMMIT = "0123456789abcdef0123456789abcdef01234567"
#: A post-step names the job it follows, or none: the tenant's family-less check.
POST_STEPS = pytest.mark.parametrize("family_less", [False, True], ids=["post-step", "family-less"])


def _job_state(scene, signer, forge, docker):
    """What a refused request must leave alone: passes signed, forge tokens asked, status row, copies, drafts, boxes."""
    tenant = scene.root / scene.tenant
    return (len(signer.payloads), len(forge.asked), publish_status(scene), listing(tenant / "run-knowledge"),
            listing(tenant / "drafts"), len(docker.creates()))


# --- requests answered by job kind ------------------------------------------------------------------------------------

#: What each kind may ask on the very channel the refused request goes down (the positive control).
_OWN_REQUEST = {"investigation": ("pass", {"id": "<job>"}), "learning": ("pass", {"id": "<job>"}),
                "post-step": ("forge.token", {"min_validity": 60})}
_RECORD = {"commit": COMMIT}
_REFUSAL = {"kind": "transient", "reason": "the forge is unreachable"}


@pytest.mark.parametrize(("kind", "request_name", "fields"), [
    ("investigation", "forge.token", {"min_validity": 60}),
    ("investigation", "record.published", _RECORD),
    ("investigation", "record.refusal", _REFUSAL),
    ("investigation", "batch.start", {"lanes": ["lessons"]}),
    ("learning", "forge.token", {"min_validity": 60}),
    ("learning", "record.published", _RECORD),
    ("learning", "record.refusal", _REFUSAL),
    ("learning", "batch.start", {"lanes": ["lessons"]}),
    ("post-step", "pass", {"id": "<job>"}),
])
def test_requests_are_refused_by_job_kind(scene, kind, request_name, fields):
    """A kind that runs adapter code gets no forge token, database write or drain publish; the post-step gets no pass;
    the refusal changes nothing, and the same socket answers the kind's own request. (Design: requests by job kind; O4)"""
    job_id = str(uuid.uuid4())
    got: dict = {}

    def job(c) -> int:
        def fill(f):
            return {k: (job_id if v == "<job>" else v) for k, v in f.items()}

        got["launch"] = c.request("launch")
        own, own_fields = _OWN_REQUEST[kind]
        got["own"] = c.request(own, **fill(own_fields))
        got["before"] = _job_state(scene, signer, forge, docker)
        got["refusal"] = c.refused(request_name, **fill(fields))
        got["after"] = _job_state(scene, signer, forge, docker)
        return 0

    signer, forge, docker = make_signer(), ForgeCredentialRecorder(), ContainerStandIn(job)
    run_kind(scene, kind, None, job_id=job_id, signer=signer, forge=forge, docker=docker)

    assert got["launch"], "control: launch was not answered"
    assert got["own"], f"control: a {kind} job was refused its own request"
    assert got["refusal"] is not None
    assert got["after"] == got["before"], "a refused request signed, minted, wrote, published or created something"


#: A full commit id the tenant's clone does not hold.
_ABSENT_COMMIT = "fedcba9876543210" * 2 + "fedcba98"


@pytest.mark.parametrize("kind", ["learning", "post-step", "investigation"])
def test_c32_export_materialise_writes_the_clones_commit_as_its_export_and_only_for_a_learning_job(scene, kind):
    """For a learning job, `export.materialise(commit=)` for a commit the tenant's clone holds (merged and fetched, never
    published) answers that commit and `<T>/exports/<commit>/`, which then holds exactly the commit's `agent/` and
    `settings/` blobs; a commit the clone lacks is refused `delivery` and no export is made. The post-step and the
    investigation are refused it and nothing is made. (Flow 2 behind the socket, C32; requests by job kind)"""
    from defender.tests.tenancy.tenant_1108_p4._support import agent_blobs, export_dir, files_under, git

    t = scene.t
    later = t.merge({"agent/lessons/merged-not-yet-published.md": "merged on origin, fetched, never published\n"})
    git(t.clone, "fetch", str(t.remote), "+refs/heads/main:refs/remotes/origin/main")
    got: dict = {}

    def job(c) -> int:
        if kind == "learning":
            got["answer"] = c.request("export.materialise", commit=later)
            got["absent"] = c.refused("export.materialise", commit=_ABSENT_COMMIT).code
        else:
            got["refused"] = c.refused("export.materialise", commit=later).code
        return 0

    run_kind(scene, kind, job, family_less=kind == "post-step")

    if kind != "learning":
        assert got["refused"] in ("not-for-kind", "unknown-request"), got["refused"]
        assert not export_dir(t.tenant, later).exists(), f"a {kind} job materialised an export"
        return
    assert got["answer"]["commit"] == later
    assert Path(got["answer"]["path"]) == export_dir(t.tenant, later)
    assert files_under(export_dir(t.tenant, later) / "agent") == agent_blobs(t.clone, later)
    assert files_under(export_dir(t.tenant, later) / "settings") == agent_blobs(t.clone, later, prefix="settings")
    assert got["absent"] == "delivery"
    assert not export_dir(t.tenant, _ABSENT_COMMIT).exists()


# --- the learning job: pre-flight --------------------------------------------------------------------------------------

def test_o5_o6_pre_flight_asks_for_a_fresh_pass_naming_the_learning_job_each_time_and_none_lasts_an_hour(scene):
    """Each `pass` is signed anew for the learning job's own id: tenant, its read grant, one pass lifetime; no single
    3600 s pass, no `rw`. (O5, O6, C12 replaced)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    job_id = str(uuid.uuid4())
    signer, got = make_signer(), {}

    def job(c) -> int:
        got["before"] = len(signer.payloads)
        got["asked_at"] = time.time()
        got["tokens"] = [c.request("pass", id=job_id)["token"] for _ in range(2)]
        return 0

    run_kind(scene, "learning", job, job_id=job_id, signer=signer)

    assert got["before"] >= 1, "no pass was signed at claim"
    first, second = (claims_of(signer, t) for t in got["tokens"])
    assert got["tokens"][0] != got["tokens"][1]
    for claims in (first, second):
        assert claims["tenant"] == scene.tenant
        assert claims["investigation"] == job_id
        assert A.grant_of(claims) == [("identity", "r")]
        assert 590 <= claims["exp"] - got["asked_at"] <= 601, claims["exp"] - got["asked_at"]
    assert second["exp"] >= first["exp"]
    assert all(m != "rw" for p in signer.payloads for _s, m in A.claims_of_payload(p)["grant"])


def test_a6_a_learning_job_is_passed_and_boxed_only_for_ids_the_helper_holds_for_it(scene):
    """The learning job's own id is answered for `pass`; the source run, a stranger's id, a host path and a `..` id are
    refused for `pass` and `box.start`, signing and creating nothing. (A6, O9)"""
    job_id, source = str(uuid.uuid4()), str(uuid.uuid4())
    foreign = [source, str(uuid.uuid4()), str(scene.root / OTHER_TENANT / "runs"), "../" + OTHER_TENANT]
    signer, got = make_signer(), {}

    def job(c) -> int:
        got["own"] = c.request("pass", id=job_id)
        got["state"] = (len(signer.payloads), len(docker.creates()))
        got["refusals"] = [c.refused(r, kind="shell", id=other) for r in ("pass", "box.start") for other in foreign]
        got["after"] = (len(signer.payloads), len(docker.creates()))
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, "learning", None, job_id=job_id, source=source, signer=signer, docker=docker)

    assert got["own"], "control: the job's own id was refused"
    assert len(got["refusals"]) == 2 * len(foreign)
    assert got["after"] == got["state"], "an id the helper does not hold signed a pass or created a box"


# --- the learning job: siblings -----------------------------------------------------------------------------------------

def test_a6_a_sibling_gets_its_worlds_roster_id_a_folder_in_the_episode_and_an_owned_copy_and_a_pass_and_box_for_that_id_only(
        scene):
    """`copy.make(world=)` for a world of the job's episode answers that world's canonical roster id, makes
    `<episode>/runs/<run>/` (not one under `<T>/runs/`) and an owned `<T>/run-knowledge/<run>/`; `pass` and `box.start` for
    it are answered (a read pass for the run, #1449); afterwards the copy is gone and the run's output stays. (A6, C20, C23,
    O5; `test_triplet_sibling::test_947_sibling_run_id...`)"""
    from defender.box import TENANT_LABEL
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.tenancy.tenant_1108_p4._drain_support import owner_record

    planted = plant_siblings(scene)
    job_id = planted.job_id
    labels = ("b", "c")
    signer, got = make_signer(), {}
    knowledge = scene.root / scene.tenant / "run-knowledge"

    def job(c) -> int:
        got["asked_at"] = time.time()
        got["copies"] = [c.request("copy.make", world=planted.worlds[w]) for w in labels]
        got["seen"] = [(planted.dir / "runs" / x["run"]).is_dir() for x in got["copies"]]
        got["owners"] = [owner_record(Path(x["path"]))["pid"] for x in got["copies"]]
        got["tokens"] = [c.request("pass", id=x["run"])["token"] for x in got["copies"]]
        got["boxes"] = [c.request("box.start", kind="shell", id=x["run"]) for x in got["copies"]]
        (planted.dir / "runs" / got["copies"][0]["run"] / "report.md").write_text("sibling output", encoding="utf-8")
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, "learning", None, job_id=planted.job_id, source=planted.source, signer=signer, docker=docker)

    assert [x["run"] for x in got["copies"]] == [planted.run_id(w) for w in labels], "not the worlds' roster ids"
    assert job_id not in [x["run"] for x in got["copies"]]
    for copy in got["copies"]:
        path = Path(copy["path"])
        assert path.parent == knowledge, path
        assert path.name == copy["run"]
        assert not (scene.runs / copy["run"]).exists(), "a sibling's folder was made under <T>/runs"
    assert got["seen"] == [True, True]
    assert got["owners"] == [os.getpid()] * 2, "a run copy's owner is not the helper"
    for copy, token in zip(got["copies"], got["tokens"], strict=True):
        claims = claims_of(signer, token)
        assert claims["investigation"] == copy["run"]
        assert claims["tenant"] == scene.tenant
        assert A.grant_of(claims) == [("identity", "r")]
        assert 590 <= claims["exp"] - got["asked_at"] <= 601
    assert len(got["boxes"]) == 2
    assert all(got["boxes"])
    sibling_creates = docker.creates()
    assert len(sibling_creates) == 2
    assert all(parse_labels(c)[TENANT_LABEL] == scene.tenant for c in sibling_creates)
    assert listing(knowledge) == [], "the helper left a sibling's run copy or a temporary behind"
    made = sorted(x["run"] for x in got["copies"])
    # Each sibling's folder, and beside it only the host-held knowledge-source record of that run (U12).
    assert [p.name for p in sorted((planted.dir / "runs").iterdir()) if p.is_dir()] == made
    # Beside each sibling's run: its knowledge-source record and (#1366 O6) its record of the versions the job read.
    assert [p.name for p in sorted((planted.dir / "runs").iterdir()) if not p.is_dir()] == \
        sorted(f"{run}{suffix}" for run in made for suffix in (".knowledge-source.json", ".record-versions.json"))
    assert (planted.dir / "runs" / got["copies"][0]["run"] / "report.md").read_text(encoding="utf-8") == "sibling output"


def test_a6_a_sibling_that_names_a_run_id_is_answered_its_worlds_roster_id_all_the_same(scene):
    """`copy.make(world=)` carrying an id of the job's choosing is refused or answers the world's roster id; the named
    folder is never made, in the episode or under `<T>/runs/`. (A6: the id is the roster's)"""
    from defender import job_host

    named = str(uuid.uuid4())
    planted = plant_siblings(scene)
    got: dict = {}

    def job(c) -> int:
        try:
            got["answer"] = c.request("copy.make", world=planted.worlds["b"], run=named, id=named)
        except job_host.Refused:
            got["answer"] = None
        got["control"] = c.request("copy.make", world=planted.worlds["c"])
        return 0

    run_kind(scene, "learning", job, job_id=planted.job_id, source=planted.source)

    assert got["control"]["run"] == planted.run_id("c"), "control: the world's roster id was not answered"
    if got["answer"] is not None:
        assert got["answer"]["run"] == planted.run_id("b")
    assert not (planted.dir / "runs" / named).exists()
    assert not (scene.runs / named).exists()
    assert not (scene.root / scene.tenant / "run-knowledge" / named).exists()


def _link_out_of_the_episode(planted, decoy, *, whole_folder):
    """After the control, a link that sends the roster entry's folder (or the episode's `runs/`) out of the episode, to
    `decoy` under `<T>/`."""
    runs = planted.dir / "runs"
    if whole_folder:
        runs.rename(planted.dir / "runs-real")
        runs.symlink_to(decoy, target_is_directory=True)
    else:
        (runs / planted.run_id("b")).symlink_to(decoy, target_is_directory=True)


@pytest.mark.parametrize("case", ["outside-world", "roster-id-not-canonical", "entry-folder-link", "runs-folder-link"])
def test_a6_h10_a_sibling_for_a_world_outside_the_episode_or_a_bad_or_linked_roster_entry_is_refused_and_nothing_is_made(
        scene, case):
    """`copy.make(world=)` for a world the job's episode does not hold, for a roster id that is not canonical, and for an
    entry whose folder would resolve outside the episode under `<T>/` (an entry link, the `runs/` link) is refused: no
    folder or copy is made, and the id is not answered for `pass` or `box.start`; on the same channel another world of the
    episode is answered (control). (A6, H10)"""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    planted = plant_siblings(scene)
    other = plant_decoy(scene, planted)
    tenant = scene.root / scene.tenant
    decoy = tenant / "decoy-folder"
    decoy.mkdir()
    world, good = planted.worlds["b"], planted.run_id("b")
    #: (world asked, id the roster holds for it or None: the roster is left alone)
    asks = {
        "outside-world": [(str(uuid.uuid4()), None), (other.worlds["b"], None)],
        "roster-id-not-canonical": [(world, bad) for bad in (
            "../" + OTHER_TENANT, good.upper(), good.replace("-", ""), "not-a-run-id",
            str(scene.root / OTHER_TENANT / "runs"), f"{good}/../{uuid.uuid4()}")],
    }.get(case, [(world, None)])
    got: dict = {"refusals": []}

    def folders():
        return listing(planted.dir / ("runs-real" if case == "runs-folder-link" else "runs"))

    def state():
        return (len(signer.payloads), len(docker.creates()), listing(tenant / "run-knowledge"), listing(decoy),
                listing(scene.runs), folders(), listing(other.dir / "runs"))

    def job(c) -> int:
        got["control"] = c.request("copy.make", world=planted.worlds["c"])
        if case.endswith("link"):
            _link_out_of_the_episode(planted, decoy, whole_folder=case == "runs-folder-link")
        got["before"] = state()
        for asked, roster_id in asks:
            if roster_id is not None:
                S.write_roster(planted.dir, {**planted.roster, world: roster_id})
            ident = roster_id or good
            got["refusals"].append(c.refused("copy.make", world=asked))
            got["refusals"] += [c.refused(r, kind="shell", id=ident) for r in ("pass", "box.start")]
        got["after"] = state()
        return 0

    signer, docker = make_signer(), ContainerStandIn(job)
    run_kind(scene, "learning", None, job_id=planted.job_id, source=planted.source, signer=signer, docker=docker)

    assert got["control"]["run"] == planted.run_id("c"), "control: a world of the episode was refused"
    assert len(got["refusals"]) == 3 * len(asks)
    assert got["after"] == got["before"], "a refused sibling signed, created, copied or made a folder"
    assert listing(decoy) == [], "the helper wrote through a link"
    assert not (scene.runs / good).exists()


def test_a6_a_decoy_episode_sharing_the_jobs_source_has_its_worlds_refused_and_the_jobs_own_answered(scene):
    """The episode is found from the claim (job id = episode id), not from `--source`: a second episode of the tenant made
    from the same source has every world refused for `copy.make`, `pass` and `box.start`, and gets no folder or copy;
    the job's own world on the same channel is answered. (A6, r4.1)"""
    planted = plant_siblings(scene)
    decoy = plant_decoy(scene, planted)
    tenant = scene.root / scene.tenant
    assert decoy.source == planted.source
    assert decoy.job_id != planted.job_id
    got: dict = {"refusals": []}

    def state():
        return (len(signer.payloads), len(docker.creates()), listing(tenant / "run-knowledge"),
                listing(decoy.dir / "runs"), listing(planted.dir / "runs"), listing(scene.runs))

    def job(c) -> int:
        got["before"] = state()
        for label in ("b", "c"):
            got["refusals"].append(c.refused("copy.make", world=decoy.worlds[label]))
            got["refusals"] += [c.refused(r, kind="shell", id=decoy.run_id(label)) for r in ("pass", "box.start")]
        got["after"] = state()
        got["control"] = c.request("copy.make", world=planted.worlds["b"])
        return 0

    signer, docker = make_signer(), ContainerStandIn(job)
    run_kind(scene, "learning", None, job_id=planted.job_id, source=planted.source, signer=signer, docker=docker)

    assert got["control"]["run"] == planted.run_id("b"), "control: the job's own world was refused"
    assert len(got["refusals"]) == 6
    assert got["after"] == got["before"], "a decoy episode's world was copied, passed or boxed"
    assert listing(decoy.dir / "runs") == []


def test_p_c_a_learning_jobs_siblings_add_no_holder_and_run_no_admission_inside_the_container(scene):
    """While the helper serves a sibling's `copy.make`, `pass` and `box.start`, the only process recorded under the
    tenant's host lock is the helper, and no lock is taken and no admission run beyond the helper's own, made before the
    container. (In-box entries; P-C: nothing in a container writes a host process record)"""
    from defender.systems import run_tenant
    from defender.tenancy import host_lock
    from defender.tests.support.tenancy._host1214 import (
        counting_calls,
        recorded,
        this_process,
    )

    planted = plant_siblings(scene)
    got: dict = {}

    def job(c) -> int:
        got["start"] = dict(calls.counts)
        run = c.request("copy.make", world=planted.worlds["b"])["run"]
        c.request("pass", id=run)
        c.request("box.start", kind="shell", id=run)
        got["holders"] = recorded(scene.root, scene.tenant)
        got["end"] = dict(calls.counts)
        return 0

    with counting_calls(host_tenant=run_tenant.host_tenant, acquire=host_lock.acquire,
                        hold_shared=host_lock.hold_shared) as calls:
        run_kind(scene, "learning", job, job_id=planted.job_id, source=planted.source)

    assert got["start"]["acquire"] + got["start"]["hold_shared"] >= 1, "premise: the helper took the lock before the container"
    assert got["end"] == got["start"], "a sibling's requests took a lock or ran an admission"
    assert got["holders"] == this_process(), got["holders"]


# --- the learning job: oracle boxes (C21) -------------------------------------------------------------------------------

def test_c21_an_oracle_boxs_bind_sources_are_in_a_folder_per_claim_under_the_data_root_and_not_host_tmp(scene, monkeypatch):
    """`box.start(kind="oracle")` binds only folders below the data root, never the job socket's folder or a
    `/tmp/defender-oracle-*` one; two claims bind disjoint folders; the helper removes them at the end. (C21, O9)"""
    from defender.box import CLAIM_ENV, TENANT_LABEL

    sources = []
    for claim in (scene.claim, uuid.uuid4().hex):
        monkeypatch.setenv(CLAIM_ENV, claim)
        job_id = str(uuid.uuid4())
        got: dict = {}

        def job(c, job_id=job_id, got=got) -> int:
            got["answer"] = c.request("box.start", kind="oracle", id=job_id)
            got["socket_dir"] = c.socket().parent
            return 0

        docker = ContainerStandIn(job)
        run_kind(scene, "learning", None, job_id=job_id, docker=docker)
        (create,) = docker.creates()
        assert got["answer"], "control: the oracle box was not started"
        assert parse_labels(create)[TENANT_LABEL] == scene.tenant
        mounts = [Path(m["source"]) for m in parse_mounts(create) if m["source"]]
        assert len(mounts) >= 2, "the oracle's runner and scratch folders are bound"
        for src in mounts:
            assert src.is_relative_to(scene.root), f"{src} is outside the data root"
            assert not src.is_relative_to(got["socket_dir"]), f"{src} would put the job socket in the box"
            assert not src.name.startswith("defender-oracle-") or src.parent != Path("/tmp")
            assert not src.exists(), f"the helper left {src} behind"
        sources.append(set(mounts))
    assert not (sources[0] & sources[1]), "two claims bound the same folder"


@pytest.mark.parametrize("box", ["sibling-shell", "oracle", "batch"])
def test_h10_every_folder_from_the_tenant_down_to_each_bind_source_of_a_learning_box_is_judged_and_an_unminted_id_is_refused(
        scene, box):
    """The learning kinds' twin of `test_job_helper::test_h10_every_folder_from_the_tenant_down...`, one box kind of the
    helper's registry per case (a sibling's `shell`, the learning job's `oracle`, the post-step's `batch`): each folder on the way from `<T>/` to each bind source under `<T>/`, swapped in turn for a link into a folder
    of the other tenant holding what lay below it, gets `box.start` refused as `confinement`, no further box and the other
    tenant's folder unchanged; an id the helper did not mint is refused as `unknown-id` for that box kind and creates
    nothing. Control: the untouched folders start the box. (H10, A6, O9, C21)"""
    from defender.tests.support.jobs._job_helper import swap_every_component

    planted = plant_siblings(scene) if box == "sibling-shell" else None
    kind = {"batch": "post-step"}.get(box, "learning")
    box_kind = {"sibling-shell": "shell"}.get(box, box)
    job_id = planted.job_id if planted is not None else str(uuid.uuid4())
    got: dict = {}

    def job(c) -> int:
        if box == "sibling-shell":
            ident = c.request("copy.make", world=planted.worlds["b"])["run"]
        elif box == "batch":
            ident = c.request("batch.start", lanes=["lessons"])["batch"]
        else:
            ident = job_id
        got["sources"], got["arms"] = swap_every_component(scene, c, docker, {"kind": box_kind, "id": ident})
        before = len(docker.creates())
        got["unminted"] = c.refused("box.start", kind=box_kind, id=str(uuid.uuid4())).code
        got["unminted_creates"] = (before, len(docker.creates()))
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, kind, None, job_id=None if kind == "post-step" else job_id, docker=docker,
             family_less=kind == "post-step", source=planted.source if planted is not None else None)

    if box != "oracle":  # the oracle's folders are the claim's, outside `<T>/` (C21): it has the unminted arm only
        assert got["sources"], f"control: the {box} box binds nothing under the tenant's folder"
        assert got["arms"], f"control: no folder on the way to the {box} box's sources was swapped"
    for arm in got["arms"]:
        assert arm.code == "confinement", f"{arm.component} swapped for a link: {arm.code}"
        assert arm.creates[1] == arm.creates[0], f"a box was created over the link at {arm.component}"
        assert arm.mirror[1] == arm.mirror[0], f"the other tenant's folder changed through {arm.component}"
    assert got["unminted"] == "unknown-id"
    assert got["unminted_creates"][1] == got["unminted_creates"][0], f"an unminted id started a {box} box"


# --- the learning job: the busy lock (A3, C24) -------------------------------------------------------------------------

def _hold_exclusive(scene):
    from defender.tenancy import host_lock

    fd = host_lock.acquire(scene.root, scene.tenant, exclusive=True, timeout=0)
    assert fd is not None, "premise: the lock was taken"
    return fd


def test_a3_a_learning_helper_waits_30_seconds_for_a_busy_lock_then_writes_stopped_and_starts_nothing(scene):
    """The tenant's lock held throughout: the helper waits about 30 s, writes the `stopped` end record the worker hands
    back, starts no container and signs nothing. (A3, C24)"""
    from defender.records.job_lane import LEARNING_STOPPED
    from defender.tenancy import host_lock

    job_id = str(uuid.uuid4())
    fd = _hold_exclusive(scene)
    signer, docker = make_signer(), ContainerStandIn(lambda c: 0)
    started = time.monotonic()
    try:
        run_kind(scene, "learning", None, job_id=job_id, signer=signer, docker=docker)
    finally:
        host_lock.release_lock(fd)
    waited = time.monotonic() - started

    assert 29 <= waited <= 45, waited
    end = learning_end(scene, job_id)
    assert end is not None
    assert end.status == LEARNING_STOPPED, end
    assert not docker.boxes, "a container was started without the lock"
    assert not docker.job_ran
    assert signer.payloads == []


def test_a3_a_learning_helper_that_gets_the_lock_within_the_wait_runs_the_job(scene):
    """Control for the 30 s case: a lock freed after 1.5 s is waited for and the job runs, with no end record from the
    helper. (A3)"""
    import threading

    from defender.tenancy import host_lock

    job_id = str(uuid.uuid4())
    fd = _hold_exclusive(scene)
    release = threading.Timer(1.5, host_lock.release_lock, args=(fd,))
    release.start()
    docker = ContainerStandIn(lambda c: 0)
    started = time.monotonic()
    try:
        run_kind(scene, "learning", None, job_id=job_id, docker=docker)
    finally:
        release.cancel()

    assert time.monotonic() - started >= 1.4, "premise: the helper did not wait for the lock"
    assert docker.job_ran
    assert learning_end(scene, job_id) is None


# --- the post-step and the family-less check -----------------------------------------------------------------------------

@POST_STEPS
def test_o4_forge_tokens_are_minted_afresh_for_the_post_steps_tenant_alone_and_valid_for_what_it_asks(scene, family_less):
    """Each `forge.token(min_validity)` is a new token of the helper's credential for this tenant, asked for at least that
    validity (up to 150 s); a request naming another tenant mints nothing for it. (O4, C25)"""
    forge = ForgeCredentialRecorder()
    asks = (60, 150, 60)
    got: dict = {}

    def job(c) -> int:
        got["before"] = len(forge.asked)
        got["tokens"] = [c.request("forge.token", min_validity=v)["token"] for v in asks]
        got["mid"] = len(forge.asked)
        try:
            got["other"] = c.request("forge.token", min_validity=60, tenant=OTHER_TENANT)
        except Exception as refused:  # noqa: BLE001 — a typed refusal or an answer, either is the helper's own
            got["other"] = refused
        return 0

    run_kind(scene, "post-step", job, forge=forge, family_less=family_less)

    assert len(set(got["tokens"])) == len(asks), "a token was handed out twice"
    taken = forge.asked[got["before"]:got["mid"]]
    assert len(taken) == len(asks), taken
    assert all(a >= v for a, v in zip(taken, asks, strict=True)), taken
    assert set(forge.built) == {scene.tenant}
    assert OTHER_TENANT not in str(got["other"])
    assert OTHER_TENANT not in "".join(forge.built)


@pytest.mark.parametrize("asked", [150.5, 151, 3600, 1e9])
def test_o4_a_forge_token_valid_for_more_than_150_seconds_is_refused_and_none_is_minted(scene, asked):
    """`forge.token(min_validity)` above 150 s is refused (fail closed) and asks the credential for nothing; 150 s on the
    same channel is answered (control). (O4, r4.1)"""
    forge = ForgeCredentialRecorder()
    got: dict = {}

    def job(c) -> int:
        got["control"] = c.request("forge.token", min_validity=150)
        got["before"] = list(forge.asked)
        got["refusal"] = c.refused("forge.token", min_validity=asked)
        got["after"] = list(forge.asked)
        return 0

    run_kind(scene, "post-step", job, forge=forge, family_less=True)

    assert got["control"]["token"], "control: 150 s was refused"
    assert got["after"] == got["before"], "the credential was asked for a token valid longer than 150 s"


@POST_STEPS
def test_o4_the_post_steps_publish_outcomes_are_written_by_the_helper_and_the_container_holds_no_database_login(
        scene, family_less):
    """`record.published` and `record.refusal` change the tenant's publish-status row, written by the helper; the
    post-step's container environment names no database. (O4, O3, C6)"""
    got: dict = {}

    def job(c) -> int:
        got["env"] = dict(c.env)
        clear_publish_status(scene)
        got["empty"] = publish_status(scene)
        c.request("record.published", commit=COMMIT)
        got["published"] = publish_status(scene)
        c.request("record.refusal", **_REFUSAL)
        got["refused"] = publish_status(scene)
        return 0

    run_kind(scene, "post-step", job, family_less=family_less)

    assert got["empty"] is None, "premise: the row was cleared"
    assert got["published"] is not None
    assert got["published"][:2] == (COMMIT, None), got["published"]
    row = got["refused"]
    assert row is not None
    assert row[2] == "transient", row
    assert "forge is unreachable" in row[1], row
    assert "DEFENDER_DATABASE_DSN" not in got["env"]
    assert scene.dsn not in "".join(str(v) for v in got["env"].values())


@pytest.mark.parametrize("kind", ["", "other", "TRANSIENT", "stale:operator", "transient\nforged"])
def test_o4_a_publish_refusal_of_a_kind_outside_the_vocabulary_is_refused_and_the_row_is_unchanged(scene, kind):
    """`record.refusal` takes `transient` or `operator`; anything else is refused and writes nothing (control: `operator`
    is written). (O4)"""
    got: dict = {}

    def job(c) -> int:
        clear_publish_status(scene)
        c.request("record.refusal", kind="operator", reason="a human is needed")
        got["control"] = publish_status(scene)
        got["refusal"] = c.refused("record.refusal", kind=kind, reason="nothing")
        got["after"] = publish_status(scene)
        return 0

    run_kind(scene, "post-step", job, family_less=True)

    assert got["control"] is not None
    assert got["control"][2] == "operator", got["control"]
    assert got["refusal"] is not None
    assert got["after"] == got["control"]


@POST_STEPS
def test_c23_batch_start_runs_the_drain_publish_and_makes_the_draft_owned_by_the_helper(scene, family_less):
    """After a human merge, `batch.start` answers a batch id and a draft `<T>/drafts/<id>/stage/agent/` built from the
    merged export, with the lanes asked for, owned by the helper, no temporary left. (C23, Flow: post-step)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
    from defender.tests.tenancy.tenant_1108_p4._drain_support import owner_record

    scene.t.merge(B.MERGE_FILES)
    drafts = scene.root / scene.tenant / "drafts"
    got: dict = {}

    def job(c) -> int:
        got["batch"] = c.request("batch.start", lanes=["lessons"])
        path = Path(got["batch"]["path"])
        got["lesson"] = (path / "stage" / "agent" / B.LESSON_REL).read_text(encoding="utf-8")
        got["lane"] = (path / "stage" / "agent" / "lessons").is_dir()
        got["owner"] = owner_record(path)["pid"]
        got["listing"] = listing(drafts)
        return 0

    run_kind(scene, "post-step", job, family_less=family_less)

    path = Path(got["batch"]["path"])
    assert path == drafts / got["batch"]["batch"]
    assert B.MERGED_MARK in got["lesson"], "the draft is not the merged export"
    assert B.SEEDED_MARK not in got["lesson"]
    assert got["lane"]
    assert got["owner"] == os.getpid(), "the draft's owner is not the helper"
    assert got["listing"] == [path.name], got["listing"]


def test_a6_the_drains_batch_box_is_started_only_for_a_draft_the_helper_made(scene):
    """`box.start(kind="batch", id=<batch>)` is answered and binds the draft; a stranger's id and a host path are
    refused and create nothing. (A6, O9)"""
    got: dict = {}

    def job(c) -> int:
        batch = c.request("batch.start", lanes=["lessons"])
        got["box"] = c.request("box.start", kind="batch", id=batch["batch"])
        got["state"] = len(docker.creates())
        got["refusals"] = [c.refused("box.start", kind="batch", id=other)
                           for other in (str(uuid.uuid4()), str(scene.root / OTHER_TENANT / "drafts"))]
        got["after"] = len(docker.creates())
        got["draft"] = batch["path"]
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, "post-step", None, docker=docker, family_less=True)

    assert got["box"], "control: the helper's own draft was refused"
    assert got["state"] == got["after"] == 1
    assert any(Path(m["source"]).is_relative_to(got["draft"]) for m in parse_mounts(docker.creates()[0]) if m["source"]), \
        "the batch box does not bind the draft"


# --- box kinds per job kind (r4.1) ---------------------------------------------------------------------------------------

@pytest.mark.parametrize(("kind", "refused_kinds", "own_kind"), [
    ("investigation", ("oracle", "batch"), "shell"),
    ("post-step", ("shell", "oracle"), "batch"),
    ("learning", ("batch",), "oracle"),
])
def test_r41_a_job_may_start_only_the_box_kinds_of_its_job_kind(scene, kind, refused_kinds, own_kind):
    """The job's own box kind is started; the kinds that belong to another job kind are refused for an id the helper holds,
    and create nothing: `shell` investigation and siblings, `oracle` learning job, `batch` post-step. (r4.1, O9)"""
    job_id = str(uuid.uuid4())
    got: dict = {}

    def job(c) -> int:
        ident = c.request("batch.start", lanes=["lessons"])["batch"] if kind == "post-step" else job_id
        got["control"] = c.request("box.start", kind=own_kind, id=ident)
        got["before"] = len(docker.creates())
        got["refusals"] = [c.refused("box.start", kind=other, id=ident) for other in refused_kinds]
        got["after"] = len(docker.creates())
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, kind, None, job_id=None if kind == "post-step" else job_id, docker=docker,
             family_less=kind == "post-step")

    assert got["control"], f"control: a {kind} job was refused its own box kind"
    assert got["before"] == 1
    assert len(got["refusals"]) == len(refused_kinds)
    assert got["after"] == got["before"], "a box of another job kind's kind was created"


# --- after the signal (A1) -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("kind", "request_name", "fields"), [
    ("learning", "pass", {"id": "<job>"}),
    ("learning", "box.start", {"kind": "oracle", "id": "<job>"}),  # the learning job's own box kind (r4.1)
    ("post-step", "batch.start", {"lanes": ["lessons"]}),
])
def test_a1_once_a_learning_kinds_helper_is_signalled_it_refuses_passes_boxes_copies_and_drafts(
        scene, kind, request_name, fields):
    """Answered before SIGTERM; after it the helper stops the container and refuses the same request, signing, creating,
    copying and drafting nothing more. (A1, O6, O8)"""
    got = after_the_signal(scene, kind, request_name, fields)

    assert got["control"], "control: the request was answered before the signal"
    assert got["refusal"] is not None
    assert got["after"] == got["before"], "a pass was signed, a box created or a copy or draft made after the signal"


def test_a1_once_a_learning_helper_is_signalled_it_refuses_a_siblings_copy_and_makes_nothing_more(scene):
    """A sibling's `copy.make(world=)` is answered before SIGTERM; after it the helper stops the container and refuses the
    same request, making no copy and no run folder. (A1, O8)"""
    import signal

    planted = plant_siblings(scene)
    tenant = scene.root / scene.tenant
    got: dict = {}

    def state():
        return (listing(tenant / "run-knowledge"), listing(planted.dir / "runs"), listing(scene.runs))

    def job(c) -> int:
        got["control"] = c.request("copy.make", world=planted.worlds["b"])
        got["before"] = state()
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        got["refusal"] = c.refused("copy.make", world=planted.worlds["c"])
        got["after"] = state()
        return 143

    run_kind(scene, "learning", job, job_id=planted.job_id, source=planted.source)

    assert got["control"]["run"] == planted.run_id("b"), "control: the request was answered before the signal"
    assert got["refusal"] is not None
    assert got["after"] == got["before"], "a copy or folder was made after the signal"


# --- a start that cannot be made confined (A3, O11) ---------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["learning", "post-step"])
def test_a3_o11_a_learning_kind_whose_container_cannot_start_runs_nowhere_else_and_claims_no_success(scene, kind):
    """docker refuses the start (image missing, rc 125): the job runs nowhere else; a learning job's end record is the
    learning entry's own failure word for it (`failed: entry_error`), and a post-step writes no record. (A3, O11, A7, r4.1)"""
    from defender.records.job_lane import ENTRY_ERROR, LEARNING_FAILED

    job_id = str(uuid.uuid4())
    docker = ContainerStandIn(lambda c: 0, run_fault=(125, "Unable to find image 'defender-job:latest' locally\n"))
    run_kind(scene, kind, None, job_id=job_id, docker=docker, family_less=kind == "post-step")

    assert len(docker.boxes) == 1, "premise: the container start was asked for"
    assert not docker.job_ran
    assert len(docker.creates()) == 0
    if kind == "learning":
        end = learning_end(scene, job_id)
        assert end is not None, "the helper wrote no end record for a learning job that could not start"
        assert (end.status, end.reason) == (LEARNING_FAILED, ENTRY_ERROR), end
        assert end.message, "a failed end names why"
    assert list(scene.runs.glob("*.post-step.json")) == [], "the helper wrote the post-step's record"


@pytest.mark.parametrize("cause", ["admission", "sign"])
def test_a3_a_learning_setup_the_helper_refuses_is_written_in_the_learning_entrys_refused_word(scene, cause):
    """The tenant offboarding, or the first pass failing to sign, refuses a learning job before its container: none is
    started and the end record is `failed: launch_refused`, not a `JobEnd` word. (A3, r4.1; control: the start-failure
    word above differs)"""
    from defender.records.job_lane import LAUNCH_REFUSED, LEARNING_FAILED
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.support.jobs._jobs1342 import restate_tenant

    job_id = str(uuid.uuid4())
    signer = make_signer()
    if cause == "admission":
        restate_tenant(scene.dsn, scene.tenant, state="offboarding", data_root=scene.root)
    else:
        signer = A.RaisingSigner(RuntimeError("openbao is sealed"))
    docker = ContainerStandIn(lambda c: 0)
    run_kind(scene, "learning", None, job_id=job_id, signer=signer, docker=docker)

    assert docker.boxes == [], "a container was started for a job that setup refused"
    end = learning_end(scene, job_id)
    assert end is not None, "no end record for a refused learning job"
    assert (end.status, end.reason) == (LEARNING_FAILED, LAUNCH_REFUSED), end
    assert end.message
    assert not list(scene.runs.glob(f"{job_id}.job-end.json")), "a JobEnd record was written for a learning job"



def test_a1_a_learning_helper_signalled_before_it_starts_the_container_starts_none_and_writes_stopped(scene):
    """SIGTERM lands before the container is started (during the first signing, or the launch-time publish): no `docker
    run`, and the end record is the learning entry's `stopped` word, which hands the row back. (A1, A3, r4.1 correction: a stop never permanently fails a learning job)"""
    import signal

    from defender.records.job_lane import LEARNING_STOPPED
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    job_id = str(uuid.uuid4())
    signer = J.SignalingSigner(make_signer())
    sent: list[bool] = []

    def publish(*_a, **_k) -> str:
        if not signer.sent and not sent:
            sent.append(True)
            os.kill(os.getpid(), signal.SIGTERM)
        return B.fresh(scene.t.commit)

    docker = ContainerStandIn(lambda c: 0)
    run_kind(scene, "learning", None, job_id=job_id, signer=signer, docker=docker, publish=publish)

    assert signer.sent or sent, "premise: the signal was sent"
    assert docker.boxes == [], "a container was started after the signal"
    assert docker.creates() == []
    end = learning_end(scene, job_id)
    assert end is not None, "no end record for a learning job signalled before its container"
    assert (end.status, end.reason) == (LEARNING_STOPPED, None), end
