"""#1546 (design r8) readiness and adoption containers through the real helper: only the allowlisted binds (own root rw at its
own path, `.job-inputs/<claim>` ro, code tree ro, socket folder), none naming the tenant folder or another claim; the result
reaches the store as a staged `result` fact and no file under the tenant folder; adoption works in a root clone made without
hardlinks. Everything the helper places has link count 1. (A-O9, A-O2, D5, G12)

The claim row the helper stages under is planted by SQL because no worker claims here: the real worker's claim is covered by
`test_1546_host_request_rows.py`."""
from __future__ import annotations

import os
import shutil
import sys
import uuid
from pathlib import Path

import pytest

from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._evidence_flows1546 import INPUTS, REFERENCE, ROOTS, facts
from defender.tests.support.jobs._host_requests1471 import plant
from defender.tests.support.jobs._job_helper import ContainerStandIn, ForgeCredentialRecorder, make_signer
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]
process_state = J.process_state
scene = J.scene
DEFENDER = Path(__file__).resolve().parents[2]


def _claim(dsn: str, scene, kind: str, ref: str) -> None:
    execute(dsn, f"INSERT INTO jobs.claims (token, tenant_id, kind, {REFERENCE[kind]}, inputs) "  # noqa: S608
                 "VALUES (%s, %s, %s, %s, '[]'::jsonb)", (scene.claim, scene.tenant, kind, ref))


def _allowlisted(scene, mounts: list[dict], env: dict) -> None:
    root, inputs = scene.root / ROOTS / scene.claim, scene.root / INPUTS / scene.claim
    by_source = {m["source"]: m for m in mounts}
    assert by_source[str(root)]["target"] == str(root), mounts
    assert not by_source[str(root)]["readonly"], mounts
    assert by_source[str(inputs)]["readonly"], mounts
    tenant_folder = scene.runs.parent
    for m in mounts:
        assert not Path(m["source"]).is_relative_to(tenant_folder), f"a bind names the tenant folder: {m}"
        under_jobs = Path(m["source"]).is_relative_to(scene.root) and Path(m["source"]).relative_to(scene.root).parts[:1] and \
            Path(m["source"]).relative_to(scene.root).parts[0].startswith(".job-")
        assert not under_jobs or scene.claim in Path(m["source"]).parts, f"a bind names another claim: {m}"
    assert env.get("DEFENDER_DATA_ROOT") == str(root)


def test_a_readiness_container_gets_only_allowlisted_binds_and_stages_its_result(tmp_path, monkeypatch, migrated_database):
    """The real helper and container entry for a readiness check: allowlisted binds only; its result is the staged `result`
    fact and no `<rid>.readiness.json` exists under the tenant folder. (A-O9, A-O2, D5)"""
    from defender.tests.support.jobs._readiness1471 import readiness, readiness_scene

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        rid = plant(scene.dsn, scene.tenant, "readiness", stage="running")
        _claim(scene.dsn, scene, "readiness", rid)
        ran = readiness(scene, rid=rid)
        assert ran.docker.boxes, ran.said()
        box = ran.docker.boxes[0]
        _allowlisted(scene, box.mounts, box.env)
        staged = facts(scene.dsn, scene.claim)
        assert staged.get("result", {}).get("outcome") == "ready", staged
        assert list(scene.runs.parent.rglob(f"{rid}.readiness.json")) == []


PLANTED = {"skills/identity/SKILL.md": b"---\nname: defender-identity\ndescription: planted\n---\nbody\n"}


@pytest.fixture
def checkout(tmp_path, monkeypatch):
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


def test_an_adoption_container_gets_allowlisted_binds_and_no_repository_in_its_root(scene, checkout):
    """At the container's start: binds are allowlisted; its root holds no repository (no `.git` anywhere under it or the
    inputs: the helper makes no clone) and no file the helper placed has more than one link; the delivery opens against the
    forge origin the launch facts name, which is the tenant's recorded wiring. (A-O9; r10 (c), #1618 flow 7: the container
    opens a private repository in its tmpfs `/tmp` against the forge with `forge.token`; was
    `..._and_a_hardlink_free_clone_in_its_own_root`, r10 (f) bucket 2)"""
    from defender.tests.support.shared._postgres1339 import execute

    job_id = str(uuid.uuid4())
    seen: dict = {}

    def job(c) -> int:
        root, inputs = scene.root / ROOTS / scene.claim, scene.root / INPUTS / scene.claim
        seen["links"] = sorted(str(p) for base in (root, inputs) if base.exists() for p in base.rglob("*")
                               if p.is_file() and not p.is_symlink() and os.stat(p).st_nlink != 1)
        seen["gits"] = sorted(str(p) for base in (root, inputs) if base.exists() for p in base.rglob(".git"))
        seen["roots"] = [base.is_dir() for base in (root, inputs)]
        seen["facts"] = c.request("launch")
        return 0

    plant(scene.dsn, scene.tenant, "adoption", system="identity", stage="running", request_id=job_id)
    _claim(scene.dsn, scene, "adoption", job_id)
    docker = ContainerStandIn(job)
    ran = J.drive_helper(scene, [*scene.argv("adoption", job_id), "--system", "identity"], docker=docker,
                         signer=make_signer(), forge=ForgeCredentialRecorder())
    assert ran.raised is None, (ran.raised, docker.job_error)
    assert docker.job_error is None, (ran.raised, docker.job_error)
    assert docker.boxes, "premise: the container started"
    _allowlisted(scene, docker.boxes[0].mounts, docker.boxes[0].env)
    assert seen["roots"] == [True, True], "premise: the root and the inputs existed at the container's start"
    assert seen["links"] == [], f"the helper placed files with more than one link: {seen['links']}"
    assert seen["gits"] == [], f"adoption's root or inputs hold a repository: {seen['gits']}"
    [(origin,)] = execute(scene.dsn, "SELECT origin FROM tenancy.forge_wiring WHERE tenant_id = %s", (scene.tenant,))
    assert seen["facts"].get("forge_origin") == origin, f"the delivery does not open against the forge: {seen['facts']}"
