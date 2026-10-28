"""#1214 offboard and rotate (O4, O5, O10) — in-memory twin."""
from __future__ import annotations

import datetime as _dt

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.api._identity1306 import NINA, AuditLog, user_id  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import (  # noqa: E402
    OFFBOARD,
    REPO_DELETE,
    REPO_WINDOW,
    ROTATE,
    LifecycleWorld,
)


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _destroyed_in_openbao(world, gen) -> dict[str, bool]:
    return {"oidc role": gen.oidc_role not in world.openbao.oidc_roles,
            "approle": gen.approle not in world.openbao.approles,
            "entity": gen.entity not in world.openbao.entities}


def test_offboard_ends_api_access_at_once_then_destroys_everything_but_the_archived_repo(world, caplog):
    """Offboarding: API access ends in the request's transaction; memberships end, invitations are
    revoked, every generation is destroyed, the repo archived, the host folder removed (O4, O10)."""
    tenant = world.active_tenant()
    member = world.member_of(tenant)
    assert world.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": NINA}).status_code == 202
    assert member.get(f"/tenants/{tenant}/members").status_code == 200  # control
    gen = world.live(tenant)
    audit = AuditLog(caplog)
    mark = audit.mark()

    asked = world.ops.post(f"/admin/tenants/{tenant}/offboard")
    assert asked.status_code == 202, asked.text
    # Before any worker runs.
    assert member.get(f"/tenants/{tenant}/members").status_code == 404
    assert world.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": "x@example.org"}).status_code == 404
    assert (world.item(tenant)["state"], world.item(tenant)["pending_action"]) == ("offboarding", "offboard")
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(OFFBOARD, user_id(world.ops), tenant)]

    world.drive()
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.failure) == ("offboarded", "delete_repo", None)
    assert record.repo_delete_after == record.offboarded_at + REPO_WINDOW
    statuses = {m.status for m in world.call(world.repo.memberships_of_tenant, tenant)}
    assert statuses == {"ended", "revoked"}
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    purge = world.forge.made("DELETE", f"/api/v1/admin/users/{gen.bot_login}")
    assert [c.query.get("purge") for c in purge] == [["true"]]
    assert gen.bot_login not in world.forge.integrations  # G8: purge took the integration
    assert _destroyed_in_openbao(world, gen) == {"oidc role": True, "approle": True, "entity": True}
    full = f"tenants/{tenant}"
    assert world.forge.repos[full]["archived"] is True
    assert not (world.data_root / tenant).exists()
    assert not gen.host_secret_file.exists()


def test_the_archived_repo_is_deleted_once_the_window_ends(world, caplog):
    """`delete_repo` waits for `repo_delete_after`, then deletes the repo and clears `repo_url` (O4, O10)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    audit = AuditLog(caplog)
    mark = audit.mark()
    world.clock.advance(REPO_WINDOW - _dt.timedelta(seconds=1))
    world.drive()
    assert f"tenants/{tenant}" in world.forge.repos  # control: not yet due
    world.clock.advance(_dt.timedelta(seconds=2))
    world.drive()
    assert f"tenants/{tenant}" not in world.forge.repos
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.repo_url) == ("offboarded", None, None)
    assert world.call(world.tenants.forge_wiring, tenant) is None
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(REPO_DELETE, tenant)]


def test_rotation_destroys_the_old_generation_and_leaves_one_live_generation(world, caplog):
    """Once rotated, the old bot, OIDC role, AppRole (with its secret ids) and entity are gone and
    the host holds only the new secret; the tenant stays active (O5, O10)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    audit = AuditLog(caplog)
    mark = audit.mark()
    asked = world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential")
    assert asked.status_code == 202, asked.text
    assert (world.item(tenant)["state"], world.item(tenant)["pending_action"]) == ("active", "rotate")
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(ROTATE, tenant)]
    world.drive()
    new = world.live(tenant)
    assert (world.item(tenant)["state"], world.item(tenant)["pending_action"]) == ("active", None)
    assert new.salt != old.salt and new.bot_login != old.bot_login
    assert [g.status for g in world.generations(tenant) if g.salt == old.salt] == ["destroyed"]
    assert old.bot_login not in world.forge.users and old.bot_login not in world.forge.integrations
    assert _destroyed_in_openbao(world, old) == {"oidc role": True, "approle": True, "entity": True}
    assert world.forge.collaborators(f"tenants/{tenant}") == {new.bot_login: "write"}
    assert not old.host_secret_file.exists()
    assert new.host_secret_file.is_file()


def test_rotation_is_refused_for_a_tenant_that_is_not_active(world):
    """Rotate is only for `active`; a creating tenant is refused and its row is unchanged (O5)."""
    tenant = world.ops.post("/admin/tenants", json={}).json()["tenant_id"]
    before = world.item(tenant)
    refused = world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential")
    assert refused.status_code == 409, refused.text
    assert world.item(tenant) == before
