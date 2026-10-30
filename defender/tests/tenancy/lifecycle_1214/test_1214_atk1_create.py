# ruff: noqa: F811, PT018
"""#1214 attack-1 on create, rotate and offboard in memory: every collaborator beyond the first page is removed (H-8),
credential lifetimes are the design's (H-18), nothing of the tenant's secrets directory is left (H-11) (O1, DC-2, DC-3)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._atk1 import page_collaborators, seconds  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import USERS  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402

CROWD = 120


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    page_collaborators(w.forge)
    w.service_actor = w.new_service(w.tenants, identity=w.service)
    yield w
    w.close()


def _crowd(world, repo: str) -> None:
    world.forge.repos[repo]["collaborators"].update({f"outsider-{i:03d}": "write" for i in range(CROWD)})


def test_create_removes_every_foreign_collaborator_not_just_the_first_page(world):
    """The repo has 120 foreign collaborators when the bot step runs: the forge pages its list (50 at most), and when the
    job is done the new bot is the only collaborator (O1, DC-3)."""
    tenant = world.create()
    repo = f"{ORG}/{tenant}"
    world.forge.during[("POST", USERS)] = lambda: _crowd(world, repo)
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert world.forge.collaborators(repo) == {world.live(tenant).bot_login: "write"}


def test_rotation_removes_every_foreign_collaborator_and_keeps_the_live_bot_until_retire(world):
    """Rotation with 120 foreign collaborators: after the `bot` step only the live and the new bot remain, and when the
    rotation ends the new bot alone (O1, DC-3)."""
    tenant = world.active_tenant()
    repo = f"{ORG}/{tenant}"
    old = world.live(tenant).bot_login
    _crowd(world, repo)
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    [new] = [g.bot_login for g in world.generations(tenant) if g.status == "pending"]
    assert world.forge.collaborators(repo) == {old: "write", new: "write"}
    world.drive()
    assert world.forge.collaborators(repo) == {new: "write"}


def test_the_credentials_have_the_lifetimes_the_design_gives(world):
    """The AppRole's secret id never expires and is not use-limited; the OIDC role (the JWT) lives at most 600 s (asset
    table, DC-5)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    [written] = [c for c in world.openbao.calls if c.method in ("POST", "PUT") and c.path == f"/v1/auth/approle/role/{gen.approle}"]
    assert seconds(written.body.get("secret_id_ttl", 0)) == 0
    assert int(written.body.get("secret_id_num_uses", 0)) == 0
    assert 0 < seconds(world.openbao.oidc_roles[gen.oidc_role]["ttl"]) <= 600


def test_offboarding_removes_the_tenants_secrets_directory_itself(world):
    """After offboarding neither `<data root>/<T>` nor `<secrets dir>/<T>` exists, not even empty (DC-2, O4)."""
    tenant = world.active_tenant()
    assert (world.config.secrets_dir / tenant).is_dir(), "control: the directory existed"
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.config.secrets_dir / tenant).exists()
    assert not (world.data_root / tenant).exists()


def test_create_removes_every_foreign_collaborator_when_the_forge_pages_by_fewer_than_asked(tmp_path, data_root):
    """A forge configured to answer at most 10 per page (Forgejo's `MAX_RESPONSE_ITEMS`) with 25 foreign collaborators:
    every page is shorter than the limit asked for, and still every one of them is removed (O1, DC-3)."""
    w = LifecycleWorld(tmp_path, data_root)
    try:
        page_collaborators(w.forge, max_limit=10)
        w.service_actor = w.new_service(w.tenants, identity=w.service)
        tenant = w.create()
        repo = f"{ORG}/{tenant}"
        w.forge.during[("POST", USERS)] = lambda: w.forge.repos[repo]["collaborators"].update(
            {f"outsider-{i:03d}": "write" for i in range(25)})
        w.drive()
        assert w.item(tenant)["state"] == "active"
        assert w.forge.collaborators(repo) == {w.live(tenant).bot_login: "write"}
    finally:
        w.close()
