"""#1471 A3/N-A1/R13-1: the per-job host helper's `adoption` kind. It re-reads the system record and its own catalog's base files at claim,
answers `launch` and `forge.token` only, hands the container the tenant, the system and the rendering, and writes its own failures as one
create-only record. Driven as `test_job_helper_learning.py` drives the learning kinds (its scene, its container stand-in)."""
from __future__ import annotations

import base64
import json
import shutil
import sys
import uuid
from pathlib import Path

import pytest
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import ContainerStandIn, ForgeCredentialRecorder, make_signer

process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

DEFENDER = Path(__file__).resolve().parents[2]
SYSTEM = "identity"  # the scene's proxied system; its adapter carries base files in the planted checkout below
NO_BASE = "cmdb"  # a tenant system whose adapter ships none there
PLANTED = {
    "skills/{system}/SKILL.md": b"---\nname: defender-{system}\ndescription: planted\n---\nkeep {host} and ${p}\n",
    "skills/{system}/execution.md": b"# Execution\r\n\xff raw\n",
    "skills/gather/queries/{system}/by-user.md": b"---\nid: {system}.by-user\nverb: x\n---\n",
}
#: What `PLANTED` renders to for `SYSTEM` (P-8: only `{system}` is filled), written out literally.
EXPECTED = {
    "agent/skills/identity/SKILL.md": b"---\nname: defender-identity\ndescription: planted\n---\nkeep {host} and ${p}\n",
    "agent/skills/identity/execution.md": b"# Execution\r\n\xff raw\n",
    "agent/skills/gather/queries/identity/by-user.md": b"---\nid: identity.by-user\nverb: x\n---\n",
}


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    """A code tree whose `identity` adapter declares `BASE_FILES` (a folder under `integrations/`) and whose other adapters declare none."""
    root = tmp_path / "checkout"
    shutil.copytree(DEFENDER / "integrations", root / "integrations", ignore=shutil.ignore_patterns("__pycache__"))
    adapter = root / "integrations" / "identity_adapter.py"
    adapter.write_text(adapter.read_text(encoding="utf-8") + '\nBASE_FILES = "base-files/identity"\n', encoding="utf-8")
    for rel, data in PLANTED.items():
        target = root / "integrations" / "base-files" / "identity" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    monkeypatch.setenv("DEFENDER_DIR", str(root))
    return root


def _argv(scene, job, system):
    return [*scene.argv("adoption", job), "--system", system]


def _run(scene, job_id, system, job=None, **seams):
    from defender.tests.support.jobs._job_helper import drive_helper

    docker = ContainerStandIn(job)
    forge = seams.pop("forge", None) or ForgeCredentialRecorder()
    ran = drive_helper(scene, _argv(scene, job_id, system), docker=docker, signer=make_signer(), forge=forge, **seams)
    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    return ran, docker, forge


def _record(scene, job_id):
    path = scene.runs / f"{job_id}.adoption.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


# --- the launch facts -----------------------------------------------------------------------------------------------------

def test_the_container_is_handed_the_tenant_the_system_and_the_rendering(scene, checkout):
    """`launch` answers kind adoption, this job and tenant, an active tenant, the system, and the exact rendering with its digest. (R13-1, A3, P-8)"""
    from defender.system_rules import base_files

    job_id, got = str(uuid.uuid4()), {}

    def job(c) -> int:
        got["facts"] = c.request("launch")
        return 0

    ran, _, _ = _run(scene, job_id, SYSTEM, job)
    assert "facts" in got, f"premise: the container never ran (the helper's rc {ran.rc!r}): the adoption kind is not served"
    facts = got["facts"]
    assert (facts["kind"], facts["job"], facts["tenant"], facts["tenant_state"], facts["system"]) == (
        "adoption", job_id, scene.tenant, "active", SYSTEM)
    rendering = {path: base64.b64decode(data) for path, data in facts["rendering"].items()}
    assert rendering == EXPECTED
    assert facts["digest"] == base_files.digest(rendering)
    assert _record(scene, job_id) is None, "the helper wrote a result record of its own for a job that was handed over"
    from defender.tests.support.shared._postgres1339 import execute

    [(repo, origin)] = execute(scene.dsn, "SELECT repo, origin FROM tenancy.forge_wiring WHERE tenant_id = %s", (scene.tenant,))
    assert origin, "premise: the scene records forge wiring for the tenant"
    assert (facts["forge_origin"], facts["forge_repo"]) == (origin, repo), "the launch facts carry the tenant's recorded wiring (surface s4)"


def test_the_container_is_started_on_the_adoption_entry_for_this_job_and_tenant(scene, checkout):
    """The job container's command is `-m defender.adoption --job <id> --tenant <T>`. (surface s4 table)"""
    job_id = str(uuid.uuid4())
    _, docker, _ = _run(scene, job_id, SYSTEM, lambda c: (c.request("launch"), 0)[1])
    assert docker.boxes, "premise: the container never started (the adoption kind is not served)"
    assert docker.box.argv[-6:] == ["-m", "defender.adoption", "--job", job_id, "--tenant", scene.tenant], docker.box.argv


# --- what the helper refuses to do (N-A1) -------------------------------------------------------------------------------------

ADOPTION_ANSWERS = {"launch", "forge.token"}


def test_an_adoption_helper_answers_launch_and_forge_token_and_nothing_else(scene, checkout):
    """The kind's row of C4, generated from the helper's own registry: `launch` and `forge.token` are the only requests answered to an adoption
    job, and every other registered request name is refused `not-for-kind`, signing, minting and starting nothing. (N-A1, R13-1)"""
    from defender.job_host._main import registry

    names = {name for name, _kind in registry().handlers}
    assert names >= ADOPTION_ANSWERS
    answered = {name for name, kind in registry().handlers if kind == "adoption"}
    assert answered == ADOPTION_ANSWERS, f"the adoption kind answers {sorted(answered)}"
    job_id, got = str(uuid.uuid4()), {"refusals": {}}
    signer, forge, docker = make_signer(), ForgeCredentialRecorder(), None

    def job(c) -> int:
        got["launch"] = c.request("launch")
        got["token"] = c.request("forge.token", min_validity=60)
        got["before"] = (len(signer.payloads), len(forge.asked), len(docker.creates()))
        for name in sorted(names - ADOPTION_ANSWERS):
            refusal = c.refused(name)
            got["refusals"][name] = refusal.code
        got["after"] = (len(signer.payloads), len(forge.asked), len(docker.creates()))
        return 0

    docker = ContainerStandIn(job)
    from defender.tests.support.jobs._job_helper import drive_helper

    ran = drive_helper(scene, _argv(scene, job_id, SYSTEM), docker=docker, signer=signer, forge=forge)
    assert ran.raised is None
    assert docker.job_error is None, (ran.raised, docker.job_error)
    assert "launch" in got, f"premise: the container never ran (the helper's rc {ran.rc!r}): the adoption kind is not served"
    assert got["token"].get("token"), "control: the kind's own requests were refused"
    assert forge.built == [scene.tenant]
    assert forge.asked, "the forge credential is the tenant's own, minted by the helper"
    assert got["refusals"] == {name: "not-for-kind" for name in names - ADOPTION_ANSWERS}
    assert got["after"] == got["before"], "a refused request signed, minted or started something"
    assert not signer.payloads, "an adoption was handed a pass"


# --- the helper's own failures (R13-1.2, A3) --------------------------------------------------------------------------------

def test_a_record_gone_at_claim_is_failed_system_gone_and_no_container_starts(scene, checkout):
    """A system the tenant has no record of at claim: one `{failed, system_gone}` record, no container. Positive control: the recorded system is handed over. (A3)"""
    job_id = str(uuid.uuid4())
    _, docker, _ = _run(scene, job_id, "ghost-system")
    assert _record(scene, job_id) == {"outcome": "failed", "reason": "system_gone"}
    assert docker.creates() == []
    assert not docker.boxes, "a container ran for a vanished system"
    control = str(uuid.uuid4())
    _, ran_docker, _ = _run(scene, control, SYSTEM, lambda c: (c.request("launch"), 0)[1])
    assert ran_docker.boxes
    assert _record(scene, control) is None


def test_a_system_whose_adapter_ships_no_base_files_is_failed_no_base_files(scene, checkout):
    """The worker's release ships none for this system's adapter: `{failed, no_base_files}`, no container. (A3)"""
    job_id = str(uuid.uuid4())
    _, docker, _ = _run(scene, job_id, NO_BASE)
    assert _record(scene, job_id) == {"outcome": "failed", "reason": "no_base_files"}
    assert not docker.boxes


def test_the_helper_never_reads_the_tenants_own_files_for_the_rendering(scene, checkout):
    """The rendering is the release's: a tenant `agent/skills/identity/SKILL.md` of other text does not change what is handed over. (P-9 digest of the render, never checked-out files)"""
    (scene.t.clone / "agent" / "skills" / "identity").mkdir(parents=True, exist_ok=True)
    (scene.t.clone / "agent" / "skills" / "identity" / "SKILL.md").write_bytes(b"the tenant's own text\n")
    got = {}
    ran, _, _ = _run(scene, str(uuid.uuid4()), SYSTEM, lambda c: (got.update(f=c.request("launch")), 0)[1])
    assert "f" in got, f"premise: the container never ran (the helper's rc {ran.rc!r}): the adoption kind is not served"
    assert base64.b64decode(got["f"]["rendering"]["agent/skills/identity/SKILL.md"]) == EXPECTED["agent/skills/identity/SKILL.md"]


def test_a_tenant_still_creating_is_failed_tenant_not_active_and_no_container_starts(scene, checkout):
    """The tenant admission at claim refuses a tenant that is not active: one `{failed, tenant_not_active}` record, no container; the active tenant's run is the control. (A3, R13-1.2)"""
    from defender.tests.support.jobs._jobs1342 import restate_tenant

    control = str(uuid.uuid4())
    _, ran_docker, _ = _run(scene, control, SYSTEM, lambda c: (c.request("launch"), 0)[1])
    assert ran_docker.boxes, "control: an active tenant's adoption is handed over"
    restate_tenant(scene.dsn, scene.tenant, state="creating", data_root=scene.root)
    job_id = str(uuid.uuid4())
    _, docker, _ = _run(scene, job_id, SYSTEM)
    assert _record(scene, job_id) == {"outcome": "failed", "reason": "tenant_not_active"}
    assert not docker.boxes
    assert docker.creates() == []


def test_the_helper_refuses_an_adoption_with_no_system_named(scene, checkout):
    """`--system` is required for the adoption kind: without it no container starts. (R13-1, A1)"""
    docker = ContainerStandIn(lambda c: 0)
    from defender.tests.support.jobs._job_helper import drive_helper

    ran = drive_helper(scene, scene.argv("adoption", str(uuid.uuid4())), docker=docker, signer=make_signer(), forge=ForgeCredentialRecorder())
    assert ran.rc not in (0, None) or ran.raised is not None
    assert not docker.boxes


def test_a_runs_folder_holding_the_helpers_failure_record_still_lists(scene, checkout):
    """The helper's own `.adoption.json` (a vanished system) is an accepted sidecar: the tenant's runs listing succeeds and names no run. (R13-1.7)"""
    from defender import tenancy
    from defender._paths import process_defender_dir

    job_id = str(uuid.uuid4())
    _run(scene, job_id, "ghost-system")
    assert _record(scene, job_id) == {"outcome": "failed", "reason": "system_gone"}, "premise: the helper wrote its record"
    accepted = tenancy.accept_tenant(tenancy.resolve_data_root(), scene.tenant, defender_dir=process_defender_dir(), clone_tree=False)
    assert [str(r) for r in accepted.runs_repository().list()] == []

    from defender.tests.support.shared._locations_1210 import location_path

    (location_path(accepted.tenant_root) / "runs" / f"{uuid.uuid4()}.unknown.json").write_text("{}", encoding="utf-8")
    with pytest.raises(Exception, match="unknown.json"):  # noqa: PT011 — the listing's own sentence names the file
        accepted.runs_repository().list()
