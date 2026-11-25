"""#1546 (design r10 (a), (b); amendment-r10 (f) 5, the learning helper's new scenes): the family's pin is the claim's launch
fact `knowledge_commit` and nothing the job writes moves it (an episode's `knowledge_pin.json` is the job's own reading aid,
owner decision D-2); a claim with no pin, or one that is no full commit id, is refused at setup with no fallback; the grant
read is the helper's, in the claim's spool, bound into nothing and gone before the container starts (D-1)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.tenancy.knowledge_1618 import _support as K

evidence_store = H.evidence_store
process_state = J.process_state
scene = H.fresh_scene

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

#: A lesson only main's later commit holds: a copy that has it was not made at the pin.
_LATER_ONLY = "agent/lessons/merged-after-the-pin.md"


def _shared(scene) -> Path:
    return scene.root / H.SCRATCH / scene.claim / "shared"


# --- the episode's pin moves nothing --------------------------------------------------------------------------------------

def test_an_altered_episode_pin_does_not_move_a_siblings_copy_commit(scene, evidence_store):
    """The job rewrites its episode's `knowledge_pin.json` to name main's later tip (a full commit the forge serves) before a
    sibling's `copy.make(world=)`: the sibling's copy is still fetched at the claim's `knowledge_commit` (the fetch into
    `.job-inputs/<claim>/run-knowledge/<run>/` asks the pin by id, and no fetch asks the later commit), and the copy holds the
    pin's `agent/`, not the later commit's. Premise: the episode's pin file names the later commit when the copy is asked.
    (r10 (a) "Siblings": the helper alone picks each sibling's commit and reads nothing from the episode, D-2)"""
    from defender.records._knowledge_pin import pin_text

    t = scene.t
    pin = t.commit
    later = t.merge({_LATER_ONLY: "merged on main after the pin\n"})
    assert later != pin, "premise: main moved past the pin"
    planted = H.plant(scene, "learning", pin=pin)
    fetch, asked = H.recording_fetch(scene)
    seen: dict = {}

    def job(c) -> int:
        ep, worlds, runs = H.stage_roster(scene, c, planted)
        (ep / "knowledge_pin.json").write_text(pin_text(later), encoding="utf-8")  # the job's own file, rewritten
        seen["pin_file"] = (ep / "knowledge_pin.json").read_text(encoding="utf-8")
        seen["mark"] = len(asked)
        seen["answer"] = c.request("copy.make", world=worlds["b"])
        seen["agent"] = K.tree_bytes(Path(seen["answer"]["agent"]))  # the answered copy's `agent` root (main's answer shape)
        seen["run"] = runs["b"]
        seen["copy_at"] = Path(seen["answer"]["path"])
        return 0

    H.drive(scene, planted, job, fetch=fetch, **evidence_store.seams)
    assert later in seen["pin_file"], "premise: the episode's pin did not name the later commit"
    # The fetch child builds into a folder of its own beside the copy and moves it into place, so a sibling's fetch is any
    # into the claim's `run-knowledge/` after the job's start (the only copy the scene asks there).
    sibling_asks = [commit for dest, commit in asked[seen["mark"]:] if Path(dest).is_relative_to(J.run_copies(scene))]
    assert sibling_asks == [pin], f"the sibling's copy was not fetched at the claim's pin: {asked[seen['mark']:]}"
    assert seen["copy_at"] == J.run_copies(scene) / seen["run"], f"the sibling's copy is not its own: {seen['copy_at']}"
    assert later not in [commit for _dest, commit in asked], "a fetch asked the commit the episode's pin names"
    assert seen["agent"] == K.half_at(t, pin, "agent"), "the sibling's copy is not the pin's agent/"
    assert _LATER_ONLY.removeprefix("agent/") not in seen["agent"], "the sibling's copy holds the later commit's lesson"


# --- no pin, or a malformed one: refused at setup -----------------------------------------------------------------------

def _pin_case(scene, how: str) -> object:
    good = scene.t.commit
    return {"control": good, "missing": H.NO_PIN, "short": good[:39], "upper": good.upper(), "non-hex": "g" * 40,
            "empty": "", "not-a-string": 40}[how]


@pytest.mark.parametrize("how", ["control", "missing", "short", "upper", "non-hex", "empty", "not-a-string"])
def test_a_learning_claim_with_no_pin_or_a_malformed_one_ends_launch_refused_before_any_container(scene, evidence_store,
                                                                                                    how):
    """A learning claim whose launch facts carry no `knowledge_commit`, or one that is not a full lowercase commit id, ends
    `failed: launch_refused` naming the pin; no container starts, and no copy is fetched into the claim's inputs or its
    `shared/` folder: the family is never served the settled (grant-read) commit or main's in its place. Control: the
    scene's served pin starts the container. (r10 (a) "No pin": no fallback to `main`, #1618 r5.1-b, nor to the settled or
    grant-read commit; the realisation's fallback goes)"""
    from defender.records.job_lane import LAUNCH_REFUSED, LEARNING_FAILED

    planted = H.plant(scene, "learning", pin=_pin_case(scene, how))
    fetch, asked = H.recording_fetch(scene)
    drove = H.drive(scene, planted, lambda c: 0, check=False, fetch=fetch, **evidence_store.seams)
    if how == "control":
        assert drove.raised is None, drove.raised
        assert drove.docker.job_ran, "control: the served pin did not start the container"
        return
    assert drove.raised is None, drove.raised
    assert drove.docker.boxes == [], f"a container started for a claim pinned {how}"
    assert not drove.docker.job_ran
    end = H.facts(scene.dsn, scene.claim).get("outcome")
    assert end is not None, "no end was staged for the refused setup"
    assert (end["status"], end["reason"]) == (LEARNING_FAILED, LAUNCH_REFUSED), end
    assert "pin" in (end.get("message") or "").lower(), f"the refusal does not say the knowledge cannot be pinned: {end}"
    placed = [(d, c) for d, c in asked if Path(d).is_relative_to(H.job_inputs(scene)) or Path(d).is_relative_to(_shared(scene))]
    assert placed == [], f"a copy was fetched for the job though its pin is {how}: {placed}"


# --- the grant read: the helper's, in the spool ---------------------------------------------------------------------------

def test_the_grant_read_is_in_the_claims_spool_in_no_folder_bound_into_the_job_and_gone_before_the_container_starts(
        scene, evidence_store):
    """The learning helper's grant read (the one fetch of `main`, no `commit=`, made at prepare before the container) lands
    under `.job-spool/<claim>/grant/`: not under the tenant folder `<T>/` (which the post-step and drain bind read-write,
    H4), in no folder any of the job container's binds holds and holding none, and it is gone when the container starts.
    Premise: the grant was read (the launch names the scene's `identity` read). (r10 (b) "The grant read (D-1)")"""
    planted = H.plant(scene, "learning")
    fetch, asked = H.recording_fetch(scene)
    seen: dict = {}

    def job(c) -> int:
        seen["prepare"] = list(asked)
        seen["mounts"] = [Path(m["source"]) for m in c.mounts if m.get("source")]
        seen["left"] = [Path(d).exists() for d, commit in asked if commit is None]
        seen["grant"] = c.request("launch").get("grant")
        return 0

    H.drive(scene, planted, job, fetch=fetch, **evidence_store.seams)
    assert seen["grant"] == [["identity", "r"]], f"premise: the grant was not read from main: {seen['grant']}"
    reads = [Path(d) for d, commit in seen["prepare"] if commit is None]
    assert len(reads) == 1, f"prepare made not exactly one fetch of main: {seen['prepare']}"
    (grant,) = reads
    assert grant.is_relative_to(H.job_spool(scene) / "grant"), f"the grant read is not in the claim's spool: {grant}"
    assert not grant.is_relative_to(scene.root / scene.tenant), f"the grant read lies under the tenant folder: {grant}"
    assert seen["mounts"], "premise: the container has binds"
    for source in seen["mounts"]:
        assert not grant.is_relative_to(source), f"the grant read is inside the job's bind {source}"
        assert not source.is_relative_to(grant), f"the job's bind {source} is inside the grant read"
    assert seen["left"] == [False], "the grant read was still there when the container started"
