"""#1546 (design r8) readiness and adoption containers through the real helper: only the allowlisted binds (own root rw at its
own path, `.job-inputs/<claim>` ro, code tree ro, socket folder), none naming the tenant folder or another claim; the result
reaches the store as a staged `result` fact and no file under the tenant folder; adoption works in a root clone made without
hardlinks. Everything the helper places has link count 1. (A-O9, A-O2, D5, G12)

The claim row the helper stages under is planted by SQL because no worker claims here: the real worker's claim is covered by
`test_1546_host_request_rows.py`."""
from __future__ import annotations

import json
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


def test_an_adoption_container_gets_allowlisted_binds_and_a_hardlink_free_clone_in_its_own_root(scene, checkout):
    """At the container's start: binds are allowlisted; its root holds one git clone (not the tenant's knowledge clone) whose
    files all have link count 1 and whose origin is the forge's; every file the helper placed in root or inputs has link
    count 1. (A-O9, G11, G12: `--no-hardlinks`)"""
    job_id = str(uuid.uuid4())
    seen: dict = {}

    def job(c) -> int:
        root, inputs = scene.root / ROOTS / scene.claim, scene.root / INPUTS / scene.claim
        seen["links"] = sorted(str(p) for base in (root, inputs) if base.exists() for p in base.rglob("*")
                               if p.is_file() and not p.is_symlink() and os.stat(p).st_nlink != 1)
        seen["gits"] = sorted(p for p in root.rglob(".git") if p.is_dir()) if root.exists() else []
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
    assert seen["links"] == [], f"the helper placed files with more than one link: {seen['links']}"
    assert len(seen["gits"]) == 1, seen["gits"]
    assert str(seen["gits"][0]).startswith(str(scene.root / ROOTS / scene.claim))
    assert json.dumps(seen["facts"]), "premise: the launch facts were served"
