"""#1546 (design r8) the helper's folders and binds: a container's binds are exactly its kind's allowlist, the job's root,
inputs and spool exist during the job and are gone after (another live claim's are left alone), box binds are judged under
the root and inputs, every file the helper places has link count 1, adoption's root holds no repository, and
`copy.make(commit=)` answers the claim's pin only. (A-O1, A-O9; adoption, the pin, arm settings check; design r10 (a), (b),
(f): knowledge comes from the forge, no clone and no `exports/`.)"""
from __future__ import annotations

import contextlib
import os
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

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
scene = H.fresh_scene

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


@pytest.mark.parametrize("kind", [k for k in ALL_KINDS if k != "post-step"])
def test_a_jobs_root_inputs_and_spool_are_each_mode_0700_and_owned_by_the_helper_while_the_job_runs(
        request, scene, checkout, kind):
    """Each of the three claim folders the helper makes for a job (`.job-roots/<claim>`, `.job-inputs/<claim>`,
    `.job-spool/<claim>`) is, seen from inside the running job, a directory of mode exactly 0700 owned by the helper's uid:
    no other host user can read the spooled bytes or swap them before their put, nor reach the root or the inputs. Every
    kind that has the folders. (amendment r10: "the spool is 0700 and bound into nothing"; A-O3, A-O9)"""
    planted = plant(scene, kind)
    seen: dict = {}

    def job(c) -> int:
        seen["folders"] = {name: os.lstat(path) for name, path in (
            ("root", job_root(scene)), ("inputs", job_inputs(scene)), ("spool", job_spool(scene)))}
        return 0

    drive(scene, planted, job, **_seams(request, kind))
    assert set(seen.get("folders", {})) == {"root", "inputs", "spool"}, "premise: the job ran with its three folders"
    held = {name: (stat.S_ISDIR(st.st_mode), oct(stat.S_IMODE(st.st_mode)), st.st_uid)
            for name, st in seen["folders"].items()}
    assert held == {name: (True, oct(0o700), os.getuid()) for name in held}, held


# --- every file the helper places has link count 1 ----------------------------------------------------------------------------------

def _walk(folder: Path) -> list[tuple[Path, os.stat_result]]:
    return [(p, p.lstat()) for p in sorted(folder.rglob("*"))]


@pytest.mark.parametrize("kind", ["investigation", "learning", "readiness", "adoption"])
def test_every_file_the_helper_places_in_a_root_or_inputs_has_link_count_one_and_no_link(request, scene, checkout, kind):
    """Every regular file under the job's root and inputs has `st_nlink == 1` and nothing is a symlink or special file, and
    no `exports/` exists: at launch, and for a learning job also after the helper fetched a sibling's run copy into the
    inputs (`copy.make(world=)`, the fetch stand-in's copy of the claim's pin). Adoption's root and inputs hold no file at all
    (the helper places none: no clone). The control: for every other kind something was placed. (A-O9, review r7: shared
    inodes; r10 (b) "Helper-placed files": every placed file is created fresh; no helper path links a host file into a bind)"""
    planted = plant(scene, kind)
    seen: dict = {}

    def entries() -> list[tuple[Path, os.stat_result]]:
        return [(p, st) for folder in (job_root(scene), job_inputs(scene)) for p, st in _walk(folder)]

    def job(c) -> int:
        seen["entries"] = entries()
        if kind == "learning":
            _ep, worlds, runs = H.stage_roster(scene, c, planted)
            seen["copy"] = c.request("copy.make", world=worlds["b"])
            seen["entries"] += entries()
        return 0

    drive(scene, planted, job, **_seams(request, kind))
    files = [p for p, st in seen["entries"] if stat.S_ISREG(st.st_mode)]
    if kind == "adoption":
        assert files == [], f"the helper placed files in adoption's root or inputs: {files}"
    else:
        assert files, "control: nothing was placed in root or inputs"
    if kind == "learning":
        copy = Path(seen["copy"]["path"])
        assert copy.is_relative_to(job_inputs(scene)), f"the sibling's copy is not in the inputs: {copy}"
        assert [p for p in files if p.is_relative_to(copy)], "control: the sibling's copy placed no file"
    assert not [p for p, _st in seen["entries"] if p.name == "exports"], "an exports folder exists"
    for p, st in seen["entries"]:
        assert not stat.S_ISLNK(st.st_mode), f"{p} is a link"
        assert stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode), f"{p} is a special file"
        if stat.S_ISREG(st.st_mode):
            assert st.st_nlink == 1, f"{p} has link count {st.st_nlink}"


# r10 (f) bucket 1 retired `test_adoptions_clone_is_the_helpers_own_with_no_shared_objects_and_the_forge_as_origin`: there is
# no adoption clone (#1618 flow 7: the container opens a private repository in its tmpfs against the forge with
# `forge.token`). What survives (adoption's root holds no repository; the delivery opens against the forge origin) is
# `test_1546_helper_mounts.py::test_an_adoption_container_gets_allowlisted_binds_and_no_repository_in_its_root` and the
# adoption row above.


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


# --- the pin: `copy.make(commit=)` answers the claim's pin only ---------------------------------------------------------------

def _shared(scene) -> Path:
    return scene.root / H.SCRATCH / scene.claim / "shared"


def test_copy_make_with_a_commit_answers_the_claims_pin_and_refuses_every_other_commit_with_no_fetch_and_no_folder(
        scene, evidence_store):
    """A learning job's `copy.make(commit=<the claim's knowledge_commit>)` is answered a copy of the pin; `copy.make()` is
    answered `main`'s tip; `copy.make(commit=)` of any other commit, a full commit the forge serves (`main`'s later tip
    among them) or one it does not, is refused `not-for-kind` naming that commit, before any fetch, and no folder is made.
    (r10 (a), owner decision H1: least privilege; the helper compares against the claim's pin only and never asks the forge
    what `main` is to judge a `commit=`)"""
    from defender.tests.tenancy.knowledge_1618 import _support as K

    t = scene.t
    pin = t.commit
    later = t.merge({"agent/lessons/merged-after-the-pin.md": "merged on main after the pinned commit\n"})
    assert later != pin, "premise: main moved past the pin"
    planted = plant(scene, "learning", pin=pin)
    fetch, asked = H.recording_fetch(scene)
    seen: dict = {"refused": {}}

    def listing() -> list[str]:
        return sorted(p.name for p in _shared(scene).iterdir()) if _shared(scene).is_dir() else []

    def job(c) -> int:
        seen["pin"] = c.request("copy.make", commit=pin)
        seen["main"] = c.request("copy.make")
        before_asks, before_dirs = len(asked), listing()
        for name, commit in (("later", later), ("absent", K.ABSENT_COMMIT)):
            seen["refused"][name] = c.refused("copy.make", commit=commit)
        seen["asks_after"], seen["dirs_after"] = asked[before_asks:], listing()
        seen["dirs_before"] = before_dirs
        return 0

    drive(scene, planted, job, fetch=fetch, **evidence_store.seams)
    assert seen["pin"]["commit"] == pin, seen["pin"]
    assert seen["main"]["commit"] == later, f"`copy.make()` did not answer main's tip: {seen['main']}"
    for name, commit in (("later", later), ("absent", K.ABSENT_COMMIT)):
        refusal = seen["refused"][name]
        assert refusal.code == "not-for-kind", f"{name}: {refusal.code}"
        assert commit in str(refusal), f"the refusal does not name the commit {commit}: {refusal}"
    assert seen["asks_after"] == [], f"a refused `copy.make(commit=)` fetched: {seen['asks_after']}"
    assert seen["dirs_after"] == seen["dirs_before"], "a refused `copy.make(commit=)` made a folder"
    assert (pin in [c for _d, c in asked]), "control: the pin's copy was fetched by id"


def _damaging_fetch(scene, nth: int, damage: list[Path]) -> Any:
    """The real fetch seam, which for the `nth` fetch into the claim's inputs `run-knowledge/` (the `nth` sibling's copy)
    also replaces the copy's `settings/verb-grants.yaml` (a `REQUIRED_SETTINGS` file, so the copy check reads it) by a link
    once the child has filled it, before the helper checks the copy: damage only that check can see. The damaged file is
    appended to `damage`."""
    fetch, _asked = H.recording_fetch(scene)
    count = {"n": 0}

    def damaging(tenant_id, dest, **kw) -> str:
        line = fetch(tenant_id, dest, **kw)
        if Path(dest).is_relative_to(J.run_copies(scene)):
            count["n"] += 1
            grants = Path(dest) / "settings" / "verb-grants.yaml"
            if count["n"] == nth and grants.is_file():
                grants.unlink()
                grants.symlink_to("/etc/passwd")
                damage.append(grants)
        return line

    damaging.calls = fetch.calls  # type: ignore[attr-defined]
    return damaging


def test_an_arms_run_copy_goes_through_the_same_settings_check_as_the_parents(scene, evidence_store):
    """The job stages its `arms` roster (the staged fact names each arm's run, no roster file exists); each sibling's copy is
    a fetch of the claim's pin into the inputs. The first sibling's `copy.make` is answered under the staged roster's run id
    (control: its copy in `.job-inputs/<claim>/run-knowledge/<run>/`, its `run_dir` the episode's `runs/<run>` the container
    will make); when the second sibling's fetched copy has its `settings/verb-grants.yaml` replaced by a link (after the
    fetch, before the helper's copy check), that sibling's `copy.make` is refused and it gets no copy and no run folder. (design r9:289-290 "arm run copies go through the same settings check as
    the parent's", discharged by `resolve_knowledge`'s copy check, r10 (a) "Who validates"; `arms` fact, PR2; D-2: the helper
    makes no `runs/<run>/`)"""
    planted = plant(scene, "learning")
    seen: dict = {}

    def job(c) -> int:
        ep, worlds, runs = H.stage_roster(scene, c, planted)
        seen["runs"], seen["ep"] = runs, ep
        seen["first"] = c.request("copy.make", world=worlds["b"])
        seen["second"] = c.refused("copy.make", world=worlds["c"])
        seen["copies"] = sorted(p.name for p in J.run_copies(scene).iterdir()) if J.run_copies(scene).is_dir() else []
        seen["folders"] = sorted(p.name for p in (ep / "runs").iterdir()) if (ep / "runs").is_dir() else []
        return 0

    damage: list[Path] = []
    drive(scene, planted, job, fetch=_damaging_fetch(scene, 2, damage), **evidence_store.seams)
    runs = seen["runs"]
    assert len(damage) == 1, f"premise: the second sibling's fetched copy was damaged once: {damage}"
    assert seen["first"]["run"] == runs["b"], "the arm's run is the staged roster's"
    assert Path(seen["first"]["path"]) == J.run_copies(scene) / runs["b"], seen["first"]
    assert Path(seen["first"]["run_dir"]) == seen["ep"] / "runs" / runs["b"], seen["first"]
    assert seen["second"].code, "a sibling whose copy carries a link in its settings was answered"
    assert runs["c"] not in seen["copies"], f"the refused sibling got a copy: {seen['copies']}"
    assert runs["c"] not in seen["folders"], f"the refused sibling got a run folder: {seen['folders']}"
