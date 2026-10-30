# ruff: noqa: PT018
"""#1214 the lab's move, in memory over the fakes: the migration backfills the lab as a failed create at `names`; an
administrator records its forge wiring by hand and resumes it; the ordinary create job then makes it `active` on its
existing repo and clone with one fresh generation (O11, RC-9). There is no adoption code: the old row file, issuer
directory and unsalted OpenBao entries are removed by hand. The run on real Forgejo 17 is in `test_1214_live.py`.
"""
from __future__ import annotations

import subprocess

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.tenancy._active1214 import CREATED  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL, ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402

LAB = "5e1f0c7a-3b2d-4c68-9a41-7d8e6f0b2a13"
LAB_REPO = f"{ORG}/playground"
BACKFILL_FAILURE = "registered before #1214: record its forge wiring if it has a repository, then resume"
HAND_MADE = "hand-made-bot"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _forge(world: LifecycleWorld, method: str, path: str, **body):
    return world.forge.handle(httpx.Request(method, f"{FORGE_URL}/api/v1/{path}", json=body or None,
                                            headers={"Authorization": "token forge-admin-token"}))


def _git(*args: str, cwd) -> None:
    subprocess.run(["git", "-c", "user.name=lab", "-c", "user.email=lab@example.test", *args],  # noqa: S603, S607
                   cwd=cwd, check=True, capture_output=True)


class Lab:
    """The pre-#1214 lab: forge repo with a commit, a hand-made collaborator and a clone; the row is backfilled
    (step `names`, failure set) and the administrator has recorded its wiring."""

    def __init__(self, world: LifecycleWorld, *, clone_in: str = "knowledge") -> None:
        self.world = world
        self.folder = world.data_root / LAB
        self.clone = self.folder / clone_in
        assert _forge(world, "POST", f"orgs/{ORG}/repos", name="playground", private=True).status_code == 201
        assert _forge(world, "POST", "admin/users", username=HAND_MADE).status_code == 201
        assert _forge(world, "PUT", f"repos/{LAB_REPO}/collaborators/{HAND_MADE}", permission="write").status_code == 204
        self.clone.mkdir(parents=True)
        _git("init", "-q", "-b", "main", cwd=self.clone)
        (self.clone / "agent").mkdir()
        (self.clone / "agent" / ".tenant-id").write_text(f"{LAB}\n", encoding="utf-8")
        _git("add", "-A", cwd=self.clone)
        _git("commit", "-q", "-m", "lab", cwd=self.clone)
        _git("remote", "add", "origin", f"{FORGE_URL}/{LAB_REPO}.git", cwd=self.clone)
        _git("push", "-q", str(world.forge.bare(LAB_REPO)), "main", cwd=self.clone)
        (self.clone / "keep.txt").write_text("the lab's own clone\n", encoding="utf-8")
        world.call(world.tenants.add_tenant, LAB, created_at=CREATED, state="creating", pending_action="create",
                   step="names", step_actor="service", failure=BACKFILL_FAILURE, repo=LAB_REPO,
                   origin=f"{FORGE_URL}/{LAB_REPO}.git")
        self.forge_calls = len(world.forge.calls)
        self.git_calls = len(world.git.calls)

    def resume(self) -> None:
        assert self.world.ops.post(f"/admin/tenants/{LAB}/resume").status_code == 202


@pytest.fixture
def lab(world) -> Lab:
    return Lab(world)


def test_a_working_copy_at_the_tenant_folder_itself_is_not_its_clone(world):
    """The tenant's clone is `<T>/knowledge`, where every entry point accepts it; a working copy at `<T>` itself is
    not kept as the clone: prepare clones the recorded origin into `knowledge` (Flow 1.9)."""
    lab = Lab(world, clone_in=".")
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    assert [1 for args, _e in world.git.calls[lab.git_calls:] if "clone" in args], "the working copy at <T> was kept"
    assert (lab.folder / "knowledge" / ".git").exists()


def test_a_backfilled_row_does_nothing_until_resumed(world, lab):
    """The actors skip the backfilled row: its failure holds it until an administrator resumes it (O11, RC-3)."""
    assert world.drive() == 0
    item = world.item(LAB)
    assert (item["step"], item["step_actor"], item["failure"]) == ("names", "service", BACKFILL_FAILURE)
    assert len(world.forge.calls) == lab.forge_calls and len(world.openbao.calls) == 0


def test_the_job_keeps_the_recorded_wiring_skips_repo_and_template_and_keeps_the_clone(world, lab):
    """Resumed, the actors finish the job on the existing repo `tenants/playground`: wiring kept, no repo created, no
    template push, the clone kept and not re-cloned, an empty `learning/` made (RC-9, Flow 1.9)."""
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    wiring = world.call(world.tenants.forge_wiring, LAB)
    assert wiring.repo == LAB_REPO
    assert set(world.forge.repos) == {LAB_REPO}, "the job made another repo"
    new_calls = world.forge.calls[lab.forge_calls:]
    assert not [c for c in new_calls if (c.method, c.path) == ("POST", f"/api/v1/orgs/{ORG}/repos")]
    assert world.git.pushes() == [], "the template was committed over an existing repository"
    assert not [1 for args, _e in world.git.calls[lab.git_calls:] if "clone" in args]
    assert (lab.clone / "keep.txt").read_text(encoding="utf-8") == "the lab's own clone\n"
    assert (lab.folder / "learning").is_dir() and not list((lab.folder / "learning").iterdir())
    assert "main" in world.forge.repos[LAB_REPO]["protections"]
    [made] = [c for c in world.integration.created if c["user"] == world.live(LAB).bot_login]
    assert made["repos"] == [LAB_REPO], "the integration names the recorded repo, not one derived from the id (FR-2)"
    assert world.publish.calls == [(LAB, world.data_root)]


def test_the_job_leaves_one_fresh_generation_and_only_its_bot_on_the_repo(world, lab):
    """One live generation; the hand-made collaborator is removed, the new bot is the only collaborator with
    write (Flow 1.5)."""
    assert HAND_MADE in world.forge.collaborators(LAB_REPO), "control: the hand-made bot is there before"
    lab.resume()
    world.drive()
    gens = world.generations(LAB)
    [live] = [g for g in gens if g.status == "live"]
    assert len(gens) == 1
    assert world.forge.collaborators(LAB_REPO) == {live.bot_login: "write"}
