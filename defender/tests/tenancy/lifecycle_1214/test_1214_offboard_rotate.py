# ruff: noqa: PT018
"""#1214 offboard, repo deletion and rotate (O4, O5, O10, DC-2/3, RC-4) — in-memory twin."""
from __future__ import annotations

import datetime as _dt
import shutil
import uuid

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.api._identity1306 import NINA, AuditLog, user_id  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import (  # noqa: E402
    as_bot,
    in_order,
    jwts,
    member_browser,
    sample,
)
from defender.tests.tenancy.lifecycle_1214._support import (  # noqa: E402
    OFFBOARD,
    REPO_DELETE,
    REPO_WINDOW,
    ROTATE,
    LifecycleWorld,
)

OFFBOARD_STEPS = [("offboard", "service"), ("teardown", "host"), ("finish", "service")]
ROTATE_STEPS = [
    ("names", "service"), ("provider", "service"), ("bot", "service"), ("integration", "service"),
    ("wrap", "service"), ("install", "host"), ("sweep", "service"), ("retire", "service"),
    ("remove_old_file", "host")]


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _gone_in_openbao(world, gen) -> dict[str, bool]:
    return {"oidc role": gen.oidc_role not in world.openbao.oidc_roles,
            "approle": gen.approle not in world.openbao.approles,
            "entity": gen.entity not in world.openbao.entities}


def _nothing_left(world, tenant: str) -> None:
    """No bot, integration, OpenBao entry, host folder or secret file of the tenant exists."""
    assert (world.forge.users, world.forge.integrations) == (set(), {})
    assert (world.openbao.oidc_roles, world.openbao.approles, world.openbao.entities) == ({}, {}, {})
    assert not (world.data_root / tenant).exists()
    assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()]


def _secret_files(world) -> list:
    return sorted(p for p in world.config.secrets_dir.rglob("*") if p.is_file())


# --- offboard -------------------------------------------------------------------------------------------

def test_offboard_ends_api_access_at_once_then_destroys_everything_but_the_archived_repo(world, caplog):
    """Offboarding: API access ends in the request's transaction; memberships end through `end_tenant`,
    invitations are revoked, every generation destroyed, repo archived, folder and secrets removed (O4, O10, DC-2)."""
    tenant = world.active_tenant()
    member = member_browser(world, tenant)
    assert member.post(f"/tenants/{tenant}/invitations", json={"email": NINA}).status_code == 202  # SK-2
    gen = world.live(tenant)
    audit = AuditLog(caplog)
    mark = audit.mark()

    asked = world.ops.post(f"/admin/tenants/{tenant}/offboard")
    assert asked.status_code == 202, asked.text
    # Before any worker runs.
    assert member.get(f"/tenants/{tenant}/members").status_code == 404
    assert world.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": "x@example.org"}).status_code == 404
    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"]) == (
        "offboarding", "offboard", "offboard", "service")
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(OFFBOARD, user_id(world.ops), tenant)]

    in_order(sample(world, tenant), OFFBOARD_STEPS, hosts=["teardown"])
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.failure) == ("offboarded", "delete_repo", None)
    assert record.repo_delete_after == record.offboarded_at + REPO_WINDOW
    assert {m.status for m in world.call(world.repo.memberships_of_tenant, tenant)} == {"ended", "revoked"}
    system = {e.action for e in audit.since(mark) if e.actor == "system"}
    assert {"member.remove", "invitation.revoke"} <= system
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    purges = [c for c in world.forge.made("DELETE", f"/api/v1/admin/users/{gen.bot_login}")]  # SK-3
    assert purges and all(c.query.get("purge") == ["true"] for c in purges)
    assert gen.bot_login not in world.forge.users and gen.bot_login not in world.forge.integrations
    assert _gone_in_openbao(world, gen) == {"oidc role": True, "approle": True, "entity": True}
    assert world.forge.repos[f"{ORG}/{tenant}"]["archived"] is True
    assert not (world.data_root / tenant).exists()
    assert not gen.host_secret_file.exists() and _secret_files(world) == []


def test_offboard_from_creating_destroys_what_the_unfinished_job_made(world):
    """Offboard asked while create waits at the host's install: both what exists and the folder are removed (O4, P1)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    [gen] = world.generations(tenant)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded"
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    assert gen.bot_login not in world.forge.users
    _nothing_left(world, tenant)
    assert world.forge.repos[f"{ORG}/{tenant}"]["archived"] is True


def test_offboard_replaces_a_pending_failed_create_and_clears_its_failure(world):
    """A failed create is replaced by the offboard: failure cleared, first offboard step set, job finishes (O4, DC-4)."""
    world.forge.fail_next[("POST", f"/api/v1/orgs/{ORG}/repos")] = 500
    tenant = world.create()
    world.drive()
    assert world.item(tenant)["failure"] is not None
    asked = world.ops.post(f"/admin/tenants/{tenant}/offboard")
    assert asked.status_code == 202, asked.text
    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"], item["failure"]) == (
        "offboarding", "offboard", "offboard", "service", None)
    world.drive()
    assert (world.record(tenant).state, world.record(tenant).failure) == ("offboarded", None)
    _nothing_left(world, tenant)


def test_offboard_during_rotation_destroys_both_generations(world):
    """Offboard while a rotation waits at install: the old and the new generation are both destroyed (O4, O5)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    assert len(world.generations(tenant)) == 2
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    assert old.bot_login not in world.forge.users
    _nothing_left(world, tenant)


GONE = {
    "bot": lambda w, t, g: (w.forge.users.discard(g.bot_login), w.forge.integrations.pop(g.bot_login, None)),
    "repo": lambda w, t, g: w.forge.repos.pop(f"{ORG}/{t}"),
    "oidc role": lambda w, t, g: w.openbao.oidc_roles.pop(g.oidc_role),
    "approle": lambda w, t, g: w.openbao.approles.pop(g.approle),
    "entity": lambda w, t, g: w.openbao.entities.pop(g.entity),
    "folder": lambda w, t, g: shutil.rmtree(w.data_root / t),
    "secret file": lambda w, t, g: g.host_secret_file.unlink(),
}


@pytest.mark.parametrize("gone", list(GONE))
def test_offboard_treats_a_thing_that_is_already_gone_as_done(world, gone):
    """Each destroy step finds its target already missing (forge 404, OpenBao 204, absent file) and carries on (RC-4, O4)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    GONE[gone](world, tenant, gen)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.failure) == ("offboarded", "delete_repo", None), gone
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}


def test_the_archived_repo_is_deleted_once_the_window_ends(world, caplog):
    """`delete_repo` waits for `repo_delete_after`, then deletes the repo, clears `repo_url` and forge wiring and
    audits `tenant.repo.delete` as `system` (O4, O10, DC-3)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    audit = AuditLog(caplog)
    mark = audit.mark()
    world.clock.advance(REPO_WINDOW - _dt.timedelta(seconds=1))
    world.drive()
    assert f"{ORG}/{tenant}" in world.forge.repos  # control: not yet due
    assert world.forge.made("DELETE", f"/api/v1/repos/{ORG}/{tenant}") == []
    assert audit.since(mark) == []
    world.clock.advance(_dt.timedelta(seconds=2))
    world.drive()
    assert f"{ORG}/{tenant}" not in world.forge.repos
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.repo_url, record.step) == ("offboarded", None, None, None)
    assert world.call(world.tenants.forge_wiring, tenant) is None
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(REPO_DELETE, "system", tenant)]


def test_a_failed_repo_deletion_is_not_audited_and_resume_finishes_it(world, caplog):
    """The event follows the commit: a failing deletion leaves `repo_url` and emits nothing; after resume the
    deletion happens and is audited once (O4, O10, DC-4)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    audit = AuditLog(caplog)
    mark = audit.mark()
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.forge.fail_next[("DELETE", f"/api/v1/repos/{ORG}/{tenant}")] = 500
    world.drive()
    record = world.record(tenant)
    assert record.failure and "500" in record.failure and record.repo_url is not None
    assert audit.actions(mark) == []
    world.ops = world.sign_in_admin()  # the 30-day jump expired the first session
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    mark = audit.mark()
    world.drive()
    assert world.record(tenant).repo_url is None
    assert audit.actions(mark) == [REPO_DELETE]


def test_a_repo_that_is_already_gone_when_its_window_ends_is_done(world):
    """`delete_repo` treats a missing repo as deleted (RC-4, O4)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    world.forge.repos.pop(f"{ORG}/{tenant}")
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.drive()
    record = world.record(tenant)
    assert (record.failure, record.repo_url, record.pending_action) == (None, None, None)


# --- rotate ---------------------------------------------------------------------------------------------

def _login(world, role_id: str, secret: str):
    return world.call(world.openbao.client(None).post, "/v1/auth/approle/login",
                      json={"role_id": role_id, "secret_id": secret})


def test_after_a_rotation_nothing_of_the_old_generation_is_accepted_and_the_new_one_works(world, caplog):
    """Once nothing is pending: the old JWT, OpenBao token and AppRole secret are refused, the old bot, role,
    AppRole and entity are gone, and the new generation's credential works end to end (O5, O10)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    repo = f"repos/{ORG}/{tenant}"
    old_jwt = jwts(world, old)[-1]
    old_secret = world.openbao.approles[old.approle][old.secret_accessor]
    [old_token] = [t for t, role in world.openbao.tokens.items() if role == old.approle][:1]
    assert as_bot(world, old_jwt, repo).status_code == 200  # control: the old credential worked
    assert _login(world, old.role_id, old_secret).status_code == 200  # control
    audit = AuditLog(caplog)
    mark = audit.mark()
    asked = world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential")
    assert asked.status_code == 202, asked.text
    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"]) == (
        "active", "rotate", "names", "service")
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(ROTATE, tenant)]
    world.drive()
    new = world.live(tenant)
    assert (world.item(tenant)["state"], world.item(tenant)["pending_action"]) == ("active", None)
    assert new.salt != old.salt and new.bot_login != old.bot_login
    assert [g.status for g in world.generations(tenant) if g.salt == old.salt] == ["destroyed"]

    assert as_bot(world, old_jwt, repo).status_code == 401
    minted = world.call(world.openbao.client(old_token).get, f"/v1/identity/oidc/token/{old.oidc_role}")
    assert minted.status_code == 403
    assert _login(world, old.role_id, old_secret).status_code == 400
    assert old.bot_login not in world.forge.users and old.bot_login not in world.forge.integrations
    assert _gone_in_openbao(world, old) == {"oidc role": True, "approle": True, "entity": True}

    login = _login(world, new.role_id, world.openbao.approles[new.approle][new.secret_accessor])
    assert login.status_code == 200
    token = login.json()["auth"]["client_token"]
    mint = world.call(world.openbao.client(token).get, f"/v1/identity/oidc/token/{new.oidc_role}")
    assert mint.status_code == 200
    assert as_bot(world, mint.json()["data"]["token"], repo).status_code == 200


def test_rotation_leaves_the_new_bot_the_only_collaborator_and_only_the_new_secret_file(world):
    """After rotation the repo's only collaborator is the new bot (any other removed), the AppRole holds only
    the new secret id, and the host keeps one file, the new one, named by its accessor (O5, DC-2)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    full = f"{ORG}/{tenant}"
    world.forge.repos[full]["collaborators"]["intruder"] = "write"
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    new = world.live(tenant)
    assert world.forge.collaborators(full) == {new.bot_login: "write"}
    assert world.openbao.secret_accessors(new.approle) == {new.secret_accessor}
    assert not old.host_secret_file.exists() and new.host_secret_file.is_file()
    assert _secret_files(world) == [new.host_secret_file] and new.secret_accessor in new.host_secret_file.name
    assert (world.data_root / tenant).is_dir()


def test_both_bots_have_write_and_the_old_jwt_works_once_install_is_done_and_rotate_shows_its_steps(world):
    """Where the job first stands at `sweep` (install done, nothing of the old generation touched) both bots have write
    and the old JWT works; rotate's steps and actors are DC-3's (O5, DC-3, r9 FR-8)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    full = f"{ORG}/{tenant}"
    old_jwt = jwts(world, old)[-1]
    seen: dict[str, object] = {}

    def at_sweep() -> None:
        seen["collaborators"] = world.forge.collaborators(full)
        seen["old jwt"] = as_bot(world, old_jwt, f"repos/{full}").status_code
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    in_order(sample(world, tenant, at={"sweep": at_sweep}), ROTATE_STEPS, hosts=["install", "remove_old_file"])
    new = world.live(tenant)
    assert seen, "control: the job stood at sweep"
    assert seen["collaborators"] == {old.bot_login: "write", new.bot_login: "write"}
    assert seen["old jwt"] == 200
    assert as_bot(world, old_jwt, f"repos/{full}").status_code == 401, "control: the old JWT dies with the old bot"


def test_rotation_is_refused_unless_the_tenant_is_active_with_nothing_pending(world):
    """Rotate: `creating` and a second rotate answer 409 with the row unchanged; an unknown tenant 404 (O5, RC-3)."""
    creating = world.ops.post("/admin/tenants", json={}).json()["tenant_id"]
    before = world.item(creating)
    refused = world.ops.post(f"/admin/tenants/{creating}/rotate-forge-credential")
    assert refused.status_code == 409, refused.text
    assert world.item(creating) == before
    world.drive()
    assert world.ops.post(f"/admin/tenants/{creating}/rotate-forge-credential").status_code == 202
    pending = world.item(creating)
    assert world.ops.post(f"/admin/tenants/{creating}/rotate-forge-credential").status_code == 409
    assert world.item(creating) == pending
    assert world.ops.post(f"/admin/tenants/{uuid.uuid4()}/rotate-forge-credential").status_code == 404


def test_offboard_is_refused_for_an_offboarded_tenant_and_resume_without_a_failure(world):
    """Offboard from `offboarded` and resume with no failure answer 409 and change nothing (O4, RC-3)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 409
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    before = world.item(tenant)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 409
    assert world.item(tenant) == before
