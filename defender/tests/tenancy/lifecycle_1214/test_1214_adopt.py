# ruff: noqa: PT018
"""#1214 O9 lab adoption (Flow 5) in memory over the fakes: a backfilled-style row for a lab that already has its repo,
a clone, a hand-made bot and old unsalted OpenBao entries becomes an `active` tenant with one fresh generation, and the
old facts are destroyed (O9, RC-1, RC-9, GAP-Re-3). The run on real Forgejo 17 is in `test_1214_live.py`.

GAP-Rc-1 (pinned here, not by r9): `await defender.lifecycle.adopt(T, *, tenants, openbao, config, clock, issuer_dir)`
does what is due on each call and is idempotent. While the row is at `adopt` it makes the clearing commit and leaves the
job to the actors; once the tenant is `active` it retires `tenant.json` (`tenancy.retire_row`), the old
`<issuer_dir>/client/<T>/` directory and the old OpenBao entries (`tenant-<T>` role and entity, `delivery-<T>` AppRole).
"""
from __future__ import annotations

import json
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
OLD_FAILURE = "registered before #1214: adopt it"
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
    """The pre-#1214 lab: forge repo with a commit, a hand-made collaborator, a clone, `tenant.json`, an issuer
    directory and the old OpenBao entries; the row is backfilled (step `adopt`, failure set)."""

    def __init__(self, world: LifecycleWorld) -> None:
        self.world = world
        self.folder = world.data_root / LAB
        self.issuer_dir = world.tmp_path / "playground-issuer"
        assert _forge(world, "POST", f"orgs/{ORG}/repos", name="playground", private=True).status_code == 201
        assert _forge(world, "POST", "admin/users", username=HAND_MADE).status_code == 201
        assert _forge(world, "PUT", f"repos/{LAB_REPO}/collaborators/{HAND_MADE}", permission="write").status_code == 204
        self.folder.mkdir(parents=True)
        _git("init", "-q", "-b", "main", cwd=self.folder)
        (self.folder / "agent").mkdir()
        (self.folder / "agent" / ".tenant-id").write_text(f"{LAB}\n", encoding="utf-8")
        _git("add", "-A", cwd=self.folder)
        _git("commit", "-q", "-m", "lab", cwd=self.folder)
        _git("remote", "add", "origin", f"{FORGE_URL}/{LAB_REPO}.git", cwd=self.folder)
        _git("push", "-q", str(world.forge.bare(LAB_REPO)), "main", cwd=self.folder)
        (self.folder / "keep.txt").write_text("the lab's own clone\n", encoding="utf-8")
        (self.folder / "tenant.json").write_text(json.dumps({"tenant_id": LAB, "created_at": "2026-09-01T00:00:00+00:00"}),
                                                 encoding="utf-8")
        client = self.issuer_dir / "client" / LAB
        client.mkdir(parents=True)
        (client / "issuer.json").write_text("{}", encoding="utf-8")
        bao = world.openbao
        bao.approles[f"delivery-{LAB}"] = {"old-accessor": "old-secret"}
        bao.oidc_roles[f"tenant-{LAB}"] = {"ttl": 600}
        bao.entities[f"tenant-{LAB}"] = {"id": f"entity-tenant-{LAB}", "metadata": {"tenant_id": LAB}}
        world.call(world.tenants.add_tenant, LAB, created_at=CREATED, state="creating", pending_action="create",
                   step="adopt", step_actor="service", failure=OLD_FAILURE, repo=LAB_REPO,
                   origin=f"{FORGE_URL}/{LAB_REPO}.git")
        self.forge_calls = len(world.forge.calls)
        self.git_calls = len(world.git.calls)

    def adopt(self) -> None:
        from defender.lifecycle import adopt

        w = self.world
        w.call(adopt, LAB, tenants=w.tenants, openbao=w.openbao.client(), config=w.config, clock=w.clock,
               issuer_dir=self.issuer_dir)


@pytest.fixture
def lab(world) -> Lab:
    return Lab(world)


def test_a_backfilled_row_cannot_be_resumed_and_does_nothing_until_adopted(world, lab):
    """The actors skip a row at `adopt` and resume is refused (409); the lab's facts are untouched (O9, RC-3)."""
    assert world.drive() == 0
    assert world.ops.post(f"/admin/tenants/{LAB}/resume").status_code == 409
    item = world.item(LAB)
    assert (item["step"], item["step_actor"], item["failure"]) == ("adopt", "service", OLD_FAILURE)
    assert len(world.forge.calls) == lab.forge_calls and len(world.openbao.calls) == 0


def test_adoption_clears_the_backfill_failure_and_starts_the_job_at_names(world, lab):
    """The clearing commit sets step `names` (service), clears the failure, and the tenant is still `creating` (O9, RC-1)."""
    lab.adopt()
    item = world.item(LAB)
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"], item["failure"]) == (
        "creating", "create", "names", "service", None)
    assert (lab.folder / "tenant.json").is_file(), "the row file is retired only once the job is active"


def test_the_job_keeps_the_recorded_wiring_skips_repo_and_template_and_keeps_the_clone(world, lab):
    """The actors finish the job on the existing repo `tenants/playground`: wiring kept, no repo created, no template
    push, the clone kept and not re-cloned, an empty `learning/` made (O9, RC-9, Flow 1.9)."""
    lab.adopt()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    wiring = world.call(world.tenants.forge_wiring, LAB)
    assert wiring.repo == LAB_REPO
    assert set(world.forge.repos) == {LAB_REPO}, "the job made another repo"
    new_calls = world.forge.calls[lab.forge_calls:]
    assert not [c for c in new_calls if (c.method, c.path) == ("POST", f"/api/v1/orgs/{ORG}/repos")]
    assert world.git.pushes() == [], "the template was committed over an existing repository"
    assert not [1 for args, _e in world.git.calls[lab.git_calls:] if "clone" in args]
    assert (lab.folder / "keep.txt").read_text(encoding="utf-8") == "the lab's own clone\n"
    assert (lab.folder / "learning").is_dir() and not list((lab.folder / "learning").iterdir())
    assert "main" in world.forge.repos[LAB_REPO]["protections"]
    [made] = [c for c in world.integration.created if c["user"] == world.live(LAB).bot_login]
    assert made["repos"] == [LAB_REPO], "the integration names the recorded repo, not one derived from the id (FR-2)"
    assert world.publish.calls == [(LAB, world.data_root)]


def test_the_job_leaves_one_fresh_generation_and_only_its_bot_on_the_repo(world, lab):
    """One live generation; the hand-made collaborator is removed, the new bot is the only collaborator with
    write (O9, Flow 1.5)."""
    assert HAND_MADE in world.forge.collaborators(LAB_REPO), "control: the hand-made bot is there before"
    lab.adopt()
    world.drive()
    gens = world.generations(LAB)
    [live] = [g for g in gens if g.status == "live"]
    assert len(gens) == 1
    assert world.forge.collaborators(LAB_REPO) == {live.bot_login: "write"}


def test_retiring_the_lab_deletes_the_row_file_the_issuer_directory_and_the_old_openbao_entries(world, lab):
    """Once active, adoption removes `tenant.json`, `client/<T>/` and the unsalted role, entity and AppRole with their
    secrets; the new generation's entries and the clone remain (O9, GAP-Re-3)."""
    lab.adopt()
    world.drive()
    live = world.live(LAB)
    assert (lab.folder / "tenant.json").is_file() and (lab.issuer_dir / "client" / LAB).is_dir(), "control: still there"
    lab.adopt()
    assert not (lab.folder / "tenant.json").exists()
    assert not (lab.issuer_dir / "client" / LAB).exists()
    bao = world.openbao
    assert f"delivery-{LAB}" not in bao.approles and f"tenant-{LAB}" not in bao.oidc_roles
    assert f"tenant-{LAB}" not in bao.entities
    assert live.approle in bao.approles and live.oidc_role in bao.oidc_roles and live.entity in bao.entities
    assert (lab.folder / "keep.txt").is_file()
    lab.adopt()  # idempotent: nothing left to retire, nothing fails, the new generation is untouched
    assert world.item(LAB)["state"] == "active"
    assert [(g.salt, g.status) for g in world.generations(LAB)] == [(live.salt, "live")]
    assert live.approle in bao.approles and (lab.folder / "keep.txt").is_file()


def test_the_old_secrets_no_longer_log_in(world, lab):
    """The old AppRole pair worked before adoption (control) and is refused after it (O9)."""
    bao = httpx.Client(transport=httpx.MockTransport(world.openbao.handle), base_url="https://openbao.test")
    body = {"role_id": f"role-id-delivery-{LAB}", "secret_id": "old-secret"}
    assert bao.post("/v1/auth/approle/login", json=body).status_code == 200
    lab.adopt()
    world.drive()
    lab.adopt()
    assert bao.post("/v1/auth/approle/login", json=body).status_code == 400
