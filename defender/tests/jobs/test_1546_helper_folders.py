"""#1546 (design r8) the helper's folders and binds: a container's binds are exactly its kind's allowlist, the job's root,
inputs and spool exist during the job and are gone after (another live claim's are left alone), box binds are judged under
the root and inputs, every file the helper places has link count 1, adoption's clone is the helper's own, and
`export.materialise` refuses any commit but the pin. (A-O1, A-O9; adoption, export pin, arm settings check.)"""
from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from defender.tests.jobs import test_adoption_helper_1471 as ADOPT
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._helper_evidence1546 import (
    drive,
    job_inputs,
    job_root,
    job_spool,
    plant,
)
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture

evidence_store = H.evidence_store
checkout = ADOPT.checkout
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

NEEDS_STORE = ("investigation", "learning")
ALL_KINDS = ["investigation", "learning", "readiness", "adoption", "post-step", "drain"]


def _seams(request, kind):
    return request.getfixturevalue("evidence_store").seams if kind in NEEDS_STORE else {}


# --- A-O9: the binds are the kind's allowlist; A-O1: the folders ----------------------------------------------------------------

def _allowlist(scene, kind):
    """The writable and read-only bind sources the design allows `kind` (the code tree not counted)."""
    root, inputs, tenant = job_root(scene), job_inputs(scene), scene.root / scene.tenant
    rw, ro = {str(scene.root / ".job-sockets" / scene.claim)}, set()
    if kind != "post-step":
        rw.add(str(root))
        ro.add(str(inputs))
    if kind == "learning":
        rw.add(str(scene.root / H.SCRATCH / scene.claim / "shared"))
    if kind in ("post-step", "drain"):
        rw.add(str(tenant))
    return rw, ro


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_a_job_containers_binds_are_exactly_its_kinds_allowlist_and_its_folders_exist_only_while_it_runs(
        request, scene, checkout, kind):
    """Investigation, learning, readiness, adoption: own root rw, `.job-inputs/<claim>` ro, one ro code tree, the socket
    folder rw (learning: + `.job-scratch/<claim>/shared` rw), `DEFENDER_DATA_ROOT` the root; the post-step: tenant folder rw,
    code ro, socket; the drain: that set + root rw + inputs ro. No other bind; none under another claim; the four kinds' binds
    do not name the tenant folder. Root, inputs and spool exist during, are gone after, and a second live claim's three
    folders are left alone. (A-O9, A-O1, A-O2)"""
    planted = plant(scene, kind)
    other_claim = uuid.uuid4().hex
    others = H.other_claim_folders(scene, other_claim)
    seen: dict = {}

    def job(c) -> int:
        seen["during"] = {n: p.is_dir() for n, p in (("root", job_root(scene)), ("inputs", job_inputs(scene)),
                                                      ("spool", job_spool(scene)))}
        return 0

    ran = drive(scene, planted, job, **_seams(request, kind))
    box = ran.docker.box
    root, inputs = job_root(scene), job_inputs(scene)
    tenant = scene.root / scene.tenant
    by_source = {m["source"]: m for m in H.binds(box)}
    expected_rw, expected_ro = _allowlist(scene, kind)
    assert {s for s, m in by_source.items() if not m["readonly"]} == expected_rw, H.binds(box)
    ro = {s for s, m in by_source.items() if m["readonly"]}
    assert expected_ro <= ro, H.binds(box)
    assert len(ro - expected_ro) == 1, f"beyond the allowlist, exactly the one code tree is read-only: {ro - expected_ro}"
    if kind not in ("post-step", "drain"):
        assert box.env.get("DEFENDER_DATA_ROOT") == str(root)
        assert by_source[str(root)]["target"] == str(root)
    if kind not in ("post-step", "drain"):
        assert all(not Path(s).is_relative_to(tenant) for s in by_source), "a bind names the tenant folder"
    for folder in others.values():
        assert all(H.not_under(Path(s), folder) for s in by_source), f"a bind names another claim's {folder}"
    if kind != "post-step":
        assert seen["during"] == {"root": True, "inputs": True, "spool": True}
    for folder in (root, inputs, job_spool(scene)):
        assert not folder.exists(), f"{folder} outlived the job"
    for folder in others.values():
        assert (folder / "kept").read_text(encoding="utf-8") == other_claim, "another live claim's folder was touched"


# --- every file the helper places has link count 1 ----------------------------------------------------------------------------------

def _walk(folder: Path) -> list[tuple[Path, os.stat_result]]:
    return [(p, p.lstat()) for p in sorted(folder.rglob("*"))]


@pytest.mark.parametrize("kind", ["investigation", "learning", "readiness", "adoption"])
def test_every_file_the_helper_places_in_a_root_or_inputs_has_link_count_one_and_no_link(request, scene, checkout, kind):
    """At launch, every regular file under the job's root and inputs has `st_nlink == 1` and nothing is a symlink or special
    file; the folders are not empty (the control). (A-O9, review r7: shared inodes)"""
    planted = plant(scene, kind)
    seen: dict = {}

    def job(c) -> int:
        seen["entries"] = [(p, st) for folder in (job_root(scene), job_inputs(scene)) for p, st in _walk(folder)]
        return 0

    drive(scene, planted, job, **_seams(request, kind))
    assert seen["entries"], "control: nothing was placed in root or inputs"
    for p, st in seen["entries"]:
        assert not stat.S_ISLNK(st.st_mode), f"{p} is a link"
        if stat.S_ISREG(st.st_mode):
            assert st.st_nlink == 1, f"{p} has link count {st.st_nlink}"


def test_adoptions_clone_is_the_helpers_own_with_no_shared_objects_and_the_forge_as_origin(scene, checkout):
    """The root holds exactly one git clone made by the helper from the tenant's knowledge clone: its object files have link
    count 1 (`--no-hardlinks`; a plain local clone shares them), it names no alternates, its `origin` is the forge the tenant's
    clone names, and it holds the tenant's `main`. (A-O9, adoption, G11)"""
    planted = plant(scene, "adoption")
    seen: dict = {}

    def job(c) -> int:
        repos = sorted(p.parent for p in job_root(scene).rglob(".git") if p.is_dir())
        seen["repos"] = repos
        if len(repos) == 1:
            repo = repos[0]
            seen["objects"] = [p.lstat().st_nlink for p in (repo / ".git" / "objects").rglob("*") if p.is_file()]
            seen["alternates"] = (repo / ".git" / "objects" / "info" / "alternates").exists()
            seen["origin"] = _git(repo, "remote", "get-url", "origin")
            seen["main"] = _git(repo, "rev-parse", "refs/remotes/origin/main")
        return 0

    drive(scene, planted, job)
    assert len(seen["repos"]) == 1, seen["repos"]
    assert seen["objects"], "control: the clone has objects"
    assert set(seen["objects"]) == {1}, f"shared object files: {seen['objects']}"
    assert not seen["alternates"]
    assert seen["origin"] == _git(scene.t.clone, "remote", "get-url", "origin")
    assert seen["main"] == scene.t.commit


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)  # noqa: S603, S607
    return done.stdout.strip()


# --- helper bind judging covers the root and the inputs -----------------------------------------------------------------------------

def test_a_box_bind_under_the_root_or_the_inputs_replaced_by_a_link_is_refused_confinement(scene, evidence_store):
    """The run box's bind sources lie under `.job-roots/<claim>` and `.job-inputs/<claim>`: the control `box.start` is answered;
    after each of those folders and each bind source is in turn replaced by a link into another tenant's folder holding
    what lay below it, `box.start` is refused `confinement`, no further container is created and the other tenant's folder is
    unchanged. (A-O9, H10: today `judge_binds` skips binds outside the tenant folder)"""
    planted = plant(scene, "investigation")
    seen: dict = {"arms": []}

    def job(c) -> int:
        fields = {"kind": "shell", "id": planted.owner}
        first = c.request("box.start", **fields)
        sources = sorted(Path(m["source"]) for m in J.parse_mounts(docker.creates()[-1])
                         if m["source"] and (Path(m["source"]).is_relative_to(job_root(scene))
                                             or Path(m["source"]).is_relative_to(job_inputs(scene))))
        with contextlib.suppress(Exception):
            c.request("box.stop", handle=first["handle"])
        seen["sources"] = sources
        components = sorted({job_root(scene), job_inputs(scene), *sources}, key=lambda p: (len(p.parts), str(p)))
        for n, comp in enumerate(components):
            if not comp.is_dir() or comp.is_symlink():
                continue
            mirror = scene.root / J.OTHER_TENANT / "mirrors" / f"m{n}"
            for below in (s for s in sources if s.is_relative_to(comp)):
                (mirror / below.relative_to(comp)).mkdir(parents=True, exist_ok=True)
            before = len(docker.creates())
            moved = comp.with_name(comp.name + ".moved")
            comp.rename(moved)
            comp.symlink_to(mirror, target_is_directory=True)
            try:
                try:
                    code = c.refused("box.start", **fields).code
                except AssertionError:
                    code = "answered"
            finally:
                comp.unlink()
                moved.rename(comp)
            seen["arms"].append((comp, code, before, len(docker.creates())))
        return 0

    docker = J.ContainerStandIn(job)
    drive(scene, planted, None, docker=docker, **evidence_store.seams)
    assert any(s.is_relative_to(job_root(scene)) for s in seen["sources"]), seen["sources"]
    assert any(s.is_relative_to(job_inputs(scene)) for s in seen["sources"]), seen["sources"]
    assert seen["arms"], "control: nothing was swapped"
    for comp, code, before, after in seen["arms"]:
        assert code == "confinement", f"{comp} swapped for a link: {code}"
        assert after == before, f"a box was created over the link at {comp}"
    assert (scene.root / J.OTHER_TENANT / "canary").read_text(encoding="utf-8") == J.CANARY


# --- the pinned export ----------------------------------------------------------------------------------------------------------------

def test_export_materialise_answers_the_pin_and_refuses_every_other_commit_the_clone_holds(scene, evidence_store):
    """A learning job's `export.materialise(commit=<the launch facts' pin>)` is answered; a later commit the clone holds
    (merged and fetched), and one it lacks, are refused and no export is made for them. (design: `export.materialise` refuses
    any commit but the pin; the stamp branch is gone)"""
    from defender.tests.tenancy.tenant_1108_p4._support import git

    t = scene.t
    later = t.merge({"agent/lessons/merged-not-yet-published.md": "merged on origin, fetched, never published\n"})
    git(t.clone, "fetch", str(t.remote), "+refs/heads/main:refs/remotes/origin/main")
    planted = plant(scene, "learning")
    seen: dict = {}

    def job(c) -> int:
        seen["pin"] = c.request("export.materialise", commit=t.commit)
        seen["later"] = c.refused("export.materialise", commit=later)
        seen["absent"] = c.refused("export.materialise", commit="fedcba9876543210" * 2 + "fedcba98")
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert seen["pin"]["commit"] == t.commit
    assert seen["later"].code
    assert seen["absent"].code
    assert not (scene.root / scene.tenant / "exports" / later).exists()


def test_an_arms_run_copy_goes_through_the_same_settings_check_as_the_parents(scene, evidence_store):
    """With the pinned export's settings damaged (a link planted in them) after one arm's copy was made, the next arm's
    `copy.make` is refused and no copy or arm folder is made for it; the first arm's copy (control) was answered. (design:
    arm run copies get the settings check, today skipped)"""
    from defender.tests.support.jobs._learning_container1170 import plant_episode

    planted = plant(scene, "learning")
    ep, _ = plant_episode(scene, planted.owner, planted.source)
    from defender.tests.support.learning.branch import _triplet_947 as T

    worlds = {w: T.world_id(ep, w) for w in T.WORLDS}
    seen: dict = {}

    def job(c) -> int:
        export = c.request("export.materialise", commit=scene.t.commit)
        seen["first"] = c.request("copy.make", world=worlds["b"])
        stray = next(p for p in (Path(export["path"]) / "settings").rglob("*") if p.is_file())
        stray.unlink()
        stray.symlink_to("/etc/passwd")
        seen["second"] = c.refused("copy.make", world=worlds["c"])
        seen["folders"] = sorted(p.name for p in (ep / "runs").iterdir() if p.is_dir())
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert seen["first"]["run"]
    assert seen["second"].code
    assert seen["folders"] == [seen["first"]["run"]]
