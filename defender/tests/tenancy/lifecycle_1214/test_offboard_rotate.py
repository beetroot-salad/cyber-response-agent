# ruff: noqa: PT018
"""#1214 offboard, repo deletion and rotate (O4, O5, O10, DC-2/3, RC-4) — in-memory twin.

#1214 r8, amended by #1592 (OD-5): `main`'s rule at tenant creation and at every rotation (A23): push off, merge whitelist
on naming exactly the organisation's `members` team, no user and no bot, read back as stored, install's can-merge check.
In memory over the fakes.
"""
from __future__ import annotations

import datetime as _dt
import os
import shutil
import uuid

import pytest

pytest.importorskip('fastapi')
pytest.importorskip('httpx')

from defender.tests.support.api._mount1161 import API  # noqa: E402
from defender.tests.support.api._identity1306 import NINA, AuditLog, user_id  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ADMIN_LOGIN, org_of, repo_of  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import (  # noqa: E402
    as_bot,
    body_of,
    in_order,
    jwts,
    member_browser,
    openbao_failing,
    sample,
)
from defender.tests.tenancy.lifecycle_1214._support import (  # noqa: E402
    OFFBOARD,
    REPO_DELETE,
    REPO_WINDOW,
    ROTATE,
    LifecycleWorld,
)
from defender.tests.support.tenancy._active1214 import CREATE_RETENTION


#: #1546 A-O5: the evidence pass is the host step between `teardown` and `finish` (its name `evidence` is a pinned pick).
OFFBOARD_STEPS = [("offboard", "service"), ("teardown", "host"), ("evidence", "host"), ("finish", "service")]


ROTATE_STEPS = [
    ("names", "service"), ("provider", "service"), ("bot", "service"), ("protect", "service"),
    ("integration", "service"), ("wrap", "service"), ("install", "host"), ("sweep", "service"), ("retire", "service"),
    ("remove_old_file", "host")]


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _gone_in_openbao(world, gen) -> dict[str, bool]:
    return {"oidc role": gen.oidc_role not in world.openbao.oidc_roles,
            "approle": gen.approle not in world.openbao.approles,
            "entity": gen.entity not in world.openbao.entities,
            "sign approle": gen.sign_approle not in world.openbao.approles,
            "sign entity": gen.sign_entity not in world.openbao.entities,
            "evidence approle": gen.evidence_approle not in world.openbao.approles,
            "evidence entity": gen.evidence_entity not in world.openbao.entities}


def _nothing_left(world, tenant: str) -> None:
    """No bot, integration, OpenBao entry, host folder or secret file of the tenant exists."""
    assert (world.forge.users, world.forge.integrations) == (set(), {})
    assert (world.openbao.oidc_roles, world.openbao.approles, world.openbao.entities) == ({}, {}, {})
    assert world.openbao.transit_keys == {}, "the tenant's signing or evidence key outlived it (A25, A-O5)"
    assert world.openbao.aliases == []
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
    assert member.post(f"{API}/tenants/{tenant}/invitations", json={"email": NINA}).status_code == 202  # SK-2
    gen = world.live(tenant)
    audit = AuditLog(caplog)
    mark = audit.mark()

    asked = world.ops.post(f"{API}/admin/tenants/{tenant}/offboard")
    assert asked.status_code == 202, asked.text
    # Before any worker runs.
    assert member.get(f"{API}/tenants/{tenant}/members").status_code == 404
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/invitations", json={"email": "x@example.org"}).status_code == 404
    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"]) == (
        "offboarding", "offboard", "offboard", "service")
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(OFFBOARD, user_id(world.ops), tenant)]

    in_order(sample(world, tenant), [*OFFBOARD_STEPS, ("delete_repo", "service")], hosts=["teardown", "evidence"])
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.failure) == ("offboarded", "delete_repo", None)
    assert record.repo_delete_after == record.offboarded_at + REPO_WINDOW
    assert {m.status for m in world.call(world.repo.memberships_of_tenant, tenant)} == {"ended", "revoked"}
    system = {e.action for e in audit.since(mark) if e.actor == "system"}
    assert {"member.remove", "invitation.revoke"} <= system
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    deletes = world.forge.made("DELETE", f"/api/v1/admin/users/{gen.bot_login}")  # SK-3 (#1433: never with purge)
    assert deletes and not any("purge" in c.query for c in deletes)
    assert gen.bot_login not in world.forge.users and gen.bot_login not in world.forge.integrations
    assert set(_gone_in_openbao(world, gen).values()) == {True}, _gone_in_openbao(world, gen)
    assert world.openbao.transit_keys == {}, "offboarding destroys the tenant's signing and evidence keys (A25, A-O5)"
    assert world.forge.repos[repo_of(tenant)]["archived"] is True
    assert not (world.data_root / tenant).exists()
    assert not gen.host_secret_file.exists() and not gen.sign_secret_file.exists() and _secret_files(world) == []
    assert not gen.evidence_secret_file.exists()


def test_offboarding_with_no_database_address_fails_the_teardown_and_removes_nothing_until_one_is_set(world, monkeypatch):
    """Without `DEFENDER_DATABASE_DSN` the teardown cannot purge the tenant's learning rows, so it fails naming the variable
    and removes nothing; with the address set, resume finishes. (O6, Offboarding)"""
    tenant = world.active_tenant()
    secret_file = world.live(tenant).host_secret_file
    dsn = os.environ["DEFENDER_DATABASE_DSN"]  # the folder's autouse fixture set one
    monkeypatch.delenv("DEFENDER_DATABASE_DSN")
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202

    world.drive()

    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("offboarding", "teardown", "host")
    assert item["failure"] and "DEFENDER_DATABASE_DSN" in item["failure"]
    assert (world.data_root / tenant).is_dir() and secret_file.is_file(), "files removed though the rows were not purged"
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.data_root / tenant).exists()


def test_offboard_from_creating_destroys_what_the_unfinished_job_made(world):
    """Offboard asked while create waits at the host's install: both what exists and the folder are removed (O4, P1)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    [gen] = world.generations(tenant)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded"
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    assert gen.bot_login not in world.forge.users
    _nothing_left(world, tenant)
    assert world.forge.repos[repo_of(tenant)]["archived"] is True


def test_offboard_replaces_a_pending_failed_create_and_clears_its_failure(world):
    """A failed create is replaced by the offboard: failure cleared, first offboard step set, job finishes (O4, DC-4)."""
    tenant = world.create()
    world.forge.fail_next[("POST", f"/api/v1/orgs/{org_of(tenant)}/repos")] = 500
    world.drive()
    assert world.item(tenant)["failure"] is not None
    asked = world.ops.post(f"{API}/admin/tenants/{tenant}/offboard")
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
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    assert len(world.generations(tenant)) == 2
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    assert old.bot_login not in world.forge.users
    _nothing_left(world, tenant)


GONE = {
    "bot": lambda w, t, g: (w.forge.users.discard(g.bot_login), w.forge.integrations.pop(g.bot_login, None)),
    "repo": lambda w, t, g: w.forge.repos.pop(repo_of(t)),
    "oidc role": lambda w, t, g: w.openbao.oidc_roles.pop(g.oidc_role),
    "approle": lambda w, t, g: w.openbao.approles.pop(g.approle),
    "entity": lambda w, t, g: w.openbao.entities.pop(g.entity),
    "folder": lambda w, t, g: shutil.rmtree(w.data_root / t),
    "secret file": lambda w, t, g: g.host_secret_file.unlink(),
    "sign approle": lambda w, t, g: w.openbao.approles.pop(g.sign_approle),
    "sign entity": lambda w, t, g: w.openbao.entities.pop(g.sign_entity),
    "sign secret file": lambda w, t, g: g.sign_secret_file.unlink(),
    "signing key": lambda w, t, g: w.openbao.transit_keys.pop(f"request-token-{t}"),
    "evidence approle": lambda w, t, g: w.openbao.approles.pop(g.evidence_approle),
    "evidence entity": lambda w, t, g: w.openbao.entities.pop(g.evidence_entity),
    "evidence secret file": lambda w, t, g: g.evidence_secret_file.unlink(),
    "evidence key": lambda w, t, g: w.openbao.transit_keys.pop(f"evidence-{t}"),
}


@pytest.mark.parametrize("gone", list(GONE))
def test_offboard_treats_a_thing_that_is_already_gone_as_done(world, gone):
    """Each destroy step finds its target already missing (forge 404, OpenBao 204, absent file or key) and carries on
    (RC-4, O4, A24', A25)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    GONE[gone](world, tenant, gen)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.failure) == ("offboarded", "delete_repo", None), gone
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}


def test_the_archived_repo_is_deleted_once_the_window_ends(world, caplog):
    """`delete_repo` waits for `repo_delete_after`, then deletes the repo and then organisation `t-<T>` (#1592 OD-5, S3-21), clears `repo_url` and forge wiring and
    audits `tenant.repo.delete` as `system` (O4, O10, DC-3)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    audit = AuditLog(caplog)
    mark = audit.mark()
    world.clock.advance(REPO_WINDOW - _dt.timedelta(seconds=1))
    world.drive()
    assert repo_of(tenant) in world.forge.repos  # control: not yet due
    assert world.forge.made("DELETE", f"/api/v1/repos/{repo_of(tenant)}") == []
    assert audit.since(mark) == []
    world.clock.advance(_dt.timedelta(seconds=2))
    world.drive()
    assert repo_of(tenant) not in world.forge.repos
    assert org_of(tenant) not in world.forge.orgs, "the organisation outlived its repository"
    deletes = [(c.method, c.path) for c in world.forge.calls if c.method == "DELETE" and c.path in (
        f"/api/v1/repos/{repo_of(tenant)}", f"/api/v1/orgs/{org_of(tenant)}")]
    assert deletes == [("DELETE", f"/api/v1/repos/{repo_of(tenant)}"), ("DELETE", f"/api/v1/orgs/{org_of(tenant)}")]
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.repo_url, record.step) == ("offboarded", None, None, None)
    assert world.call(world.tenants.forge_wiring, tenant) is None
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(REPO_DELETE, "system", tenant)]


def test_a_failed_repo_deletion_is_not_audited_and_resume_finishes_it(world, caplog):
    """The event follows the commit: a failing deletion leaves `repo_url` and emits nothing; after resume the
    deletion happens and is audited once (O4, O10, DC-4)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    audit = AuditLog(caplog)
    mark = audit.mark()
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.forge.fail_next[("DELETE", f"/api/v1/repos/{repo_of(tenant)}")] = 500
    world.drive()
    record = world.record(tenant)
    assert record.failure and "500" in record.failure and record.repo_url is not None
    assert audit.actions(mark) == []
    world.ops = world.sign_in_admin()  # the 30-day jump expired the first session
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
    mark = audit.mark()
    world.drive()
    assert world.record(tenant).repo_url is None
    assert audit.actions(mark) == [REPO_DELETE]


def test_a_repo_that_is_already_gone_when_its_window_ends_is_done(world):
    """`delete_repo` treats a missing repo as deleted (RC-4, O4)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    world.forge.repos.pop(repo_of(tenant))
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.drive()
    record = world.record(tenant)
    assert (record.failure, record.repo_url, record.pending_action) == (None, None, None)


# --- rotate ---------------------------------------------------------------------------------------------

def _login(world, role_id: str, secret: str):
    return world.call(world.openbao.client(None).post, "/v1/auth/approle/login",
                      json={"role_id": role_id, "secret_id": secret})


def _sign(world, token: str, tenant: str):
    return world.call(world.openbao.client(token).post, f"/v1/transit/sign/request-token-{tenant}", json={"input": "cHJvYmU="})


def test_after_a_rotation_nothing_of_the_old_generation_is_accepted_and_the_new_one_works(world, caplog):
    """Once nothing is pending: the old JWT, OpenBao token and all three AppRole secrets are refused, the old bot, role,
    AppRoles and entities are gone, and the new generation's credentials work end to end (O5, O10, A24', A25)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    repo = f"repos/{repo_of(tenant)}"
    old_jwt = jwts(world, old)[-1]
    old_secret = world.openbao.approles[old.approle][old.secret_accessor]
    [old_token] = [t for t, role in world.openbao.tokens.items() if role == old.approle][:1]
    assert as_bot(world, old_jwt, repo).status_code == 200  # control: the old credential worked
    assert _login(world, old.role_id, old_secret).status_code == 200  # control
    old_sign_secret = world.openbao.approles[old.sign_approle][old.sign_secret_accessor]
    old_sign = _login(world, old.sign_role_id, old_sign_secret)
    assert old_sign.status_code == 200 and _sign(world, old_sign.json()["auth"]["client_token"], tenant).status_code == 200  # control
    old_evidence_secret = world.openbao.approles[old.evidence_approle][old.evidence_secret_accessor]
    assert _login(world, old.evidence_role_id, old_evidence_secret).status_code == 200  # control
    audit = AuditLog(caplog)
    mark = audit.mark()
    asked = world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential")
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
    assert _login(world, old.sign_role_id, old_sign_secret).status_code == 400
    assert _sign(world, old_sign.json()["auth"]["client_token"], tenant).status_code == 403
    assert _login(world, old.evidence_role_id, old_evidence_secret).status_code == 400
    assert old.bot_login not in world.forge.users and old.bot_login not in world.forge.integrations
    assert set(_gone_in_openbao(world, old).values()) == {True}, _gone_in_openbao(world, old)

    login = _login(world, new.role_id, world.openbao.approles[new.approle][new.secret_accessor])
    assert login.status_code == 200
    token = login.json()["auth"]["client_token"]
    mint = world.call(world.openbao.client(token).get, f"/v1/identity/oidc/token/{new.oidc_role}")
    assert mint.status_code == 200
    assert as_bot(world, mint.json()["data"]["token"], repo).status_code == 200
    sign = _login(world, new.sign_role_id, world.openbao.approles[new.sign_approle][new.sign_secret_accessor])
    assert sign.status_code == 200
    assert _sign(world, sign.json()["auth"]["client_token"], tenant).status_code == 200
    evidence = _login(world, new.evidence_role_id, world.openbao.approles[new.evidence_approle][new.evidence_secret_accessor])
    assert evidence.status_code == 200, "the new generation's evidence login works"


def test_rotation_leaves_the_new_bot_the_only_collaborator_and_only_the_new_secret_file(world):
    """After rotation the repo's only collaborator is the new bot (any other removed), each AppRole holds only its
    new secret id, and the secrets folder holds exactly the new three files (O5, DC-2, A24')."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    full = repo_of(tenant)
    world.forge.repos[full]["collaborators"]["intruder"] = "write"
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    new = world.live(tenant)
    assert world.forge.collaborators(full) == {new.bot_login: "write"}
    assert world.openbao.secret_accessors(new.approle) == {new.secret_accessor}
    assert world.openbao.secret_accessors(new.sign_approle) == {new.sign_secret_accessor}
    assert world.openbao.secret_accessors(new.evidence_approle) == {new.evidence_secret_accessor}
    assert not old.host_secret_file.exists() and not old.sign_secret_file.exists() and not old.evidence_secret_file.exists()
    assert new.host_secret_file.is_file() and new.sign_secret_file.is_file() and new.evidence_secret_file.is_file()
    assert _secret_files(world) == sorted([new.host_secret_file, new.sign_secret_file, new.evidence_secret_file])
    assert new.secret_accessor in new.host_secret_file.name
    assert (world.data_root / tenant).is_dir()


def test_both_bots_have_write_and_the_old_jwt_works_once_install_is_done_and_rotate_shows_its_steps(world):
    """Where the job first stands at `sweep` (install done, nothing of the old generation touched) both bots have write
    and the old JWT works; rotate's steps and actors are DC-3's (O5, DC-3, r9 FR-8)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    full = repo_of(tenant)
    old_jwt = jwts(world, old)[-1]
    seen: dict[str, object] = {}

    def at_sweep() -> None:
        seen["collaborators"] = world.forge.collaborators(full)
        seen["old jwt"] = as_bot(world, old_jwt, f"repos/{full}").status_code
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    in_order(sample(world, tenant, at={"sweep": at_sweep}), ROTATE_STEPS, hosts=["install", "remove_old_file"])
    new = world.live(tenant)
    assert seen, "control: the job stood at sweep"
    assert seen["collaborators"] == {old.bot_login: "write", new.bot_login: "write"}
    assert seen["old jwt"] == 200
    assert as_bot(world, old_jwt, f"repos/{full}").status_code == 401, "control: the old JWT dies with the old bot"


def test_rotation_is_refused_unless_the_tenant_is_active_with_nothing_pending(world):
    """Rotate: `creating` and a second rotate answer 409 with the row unchanged; an unknown tenant 404 (O5, RC-3)."""
    creating = world.ops.post(API + "/admin/tenants", json=CREATE_RETENTION).json()["tenant_id"]
    before = world.item(creating)
    refused = world.ops.post(f"{API}/admin/tenants/{creating}/rotate-forge-credential")
    assert refused.status_code == 409, refused.text
    assert world.item(creating) == before
    world.drive()
    assert world.ops.post(f"{API}/admin/tenants/{creating}/rotate-forge-credential").status_code == 202
    pending = world.item(creating)
    assert world.ops.post(f"{API}/admin/tenants/{creating}/rotate-forge-credential").status_code == 409
    assert world.item(creating) == pending
    assert world.ops.post(f"{API}/admin/tenants/{uuid.uuid4()}/rotate-forge-credential").status_code == 404


def test_offboard_is_refused_for_an_offboarded_tenant_and_resume_without_a_failure(world):
    """Offboard from `offboarded` and resume with no failure answer 409 and change nothing (O4, RC-3)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 409
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    before = world.item(tenant)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 409
    assert world.item(tenant) == before


# --- the old bot's pull requests outlive it (#1433) -------------------------------------------------------

def test_rotation_cuts_the_old_bots_repo_access_then_deletes_it_without_purge(world):
    """K1, K4: retire removes the old bot from the repo, then deletes its account with no `purge` (purge erases the
    PRs, reviews and comments it wrote); the old JWT is refused (K2)."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    old_jwt = jwts(world, old)[-1]
    full = repo_of(tenant)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    seen = [(c.method, c.path, "purge" in c.query) for c in world.forge.calls if old.bot_login in c.path]
    removal = ("DELETE", f"/api/v1/repos/{full}/collaborators/{old.bot_login}", False)
    user_delete = ("DELETE", f"/api/v1/admin/users/{old.bot_login}", False)
    assert seen.count(user_delete) == 1 and not [c for c in seen if c[2]], seen
    assert removal in seen and seen.index(removal) < seen.index(user_delete), seen
    assert old.bot_login not in world.forge.users
    assert as_bot(world, old_jwt, f"repos/{full}").status_code == 401


def test_a_refused_delete_stops_rotation_with_the_forges_reason_after_revoking_everything(world):
    """K5, K4: an old bot that owns a repository (its fork) makes the forge refuse the delete; the job fails loudly with
    the forge's message, nothing retries with purge, and the refusal finds the bot already revoked: no access to the
    tenant repo, no OpenBao chain left to mint a token with."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    old_jwt = jwts(world, old)[-1]
    world.forge.add_user_repo(old.bot_login, tenant)
    full = repo_of(tenant)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    record = world.record(tenant)
    assert record.failure and "ownership of repositories" in record.failure, record.failure
    assert world.forge.made("DELETE", f"/api/v1/admin/users/{old.bot_login}"), "control: the delete was asked"
    assert not any("purge" in c.query for c in world.forge.calls if c.path.startswith("/api/v1/admin/users/"))
    assert old.bot_login in world.forge.users and f"{old.bot_login}/{tenant}" in world.forge.repos
    assert old.bot_login not in world.forge.collaborators(full)
    assert as_bot(world, old_jwt, f"repos/{full}").status_code != 200
    assert set(_gone_in_openbao(world, old).values()) == {True}, _gone_in_openbao(world, old)


def test_a_refused_delete_at_offboarding_still_destroys_the_signing_key_and_archives_the_repo(world):
    """K5, K4, A25: an offboarded tenant's bot that belongs to an organisation makes the forge refuse its delete; the
    job fails with the forge's reason only after every generation's OpenBao chain and the tenant's signing key are
    gone and the repo is archived."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    world.forge.make_team(org_of(tenant), "Reviewers", members=[gen.bot_login])
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    record = world.record(tenant)
    assert record.failure and "membership of organizations" in record.failure, record.failure
    assert gen.bot_login in world.forge.users, "control: the delete was refused"
    assert not any("purge" in c.query for c in world.forge.calls if c.path.startswith("/api/v1/admin/users/"))
    assert set(_gone_in_openbao(world, gen).values()) == {True}, _gone_in_openbao(world, gen)
    assert world.openbao.transit_keys == {}, "the signing key outlived a refused bot delete"
    assert world.forge.repos[repo_of(tenant)]["archived"] is True
    assert gen.bot_login not in world.forge.collaborators(repo_of(tenant))


def _rules(world, tenant: str) -> str:
    return f"/api/v1/repos/{repo_of(tenant)}/branch_protections"


def _rotate(world, tenant: str) -> None:
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202


def _bot_view(world, gen, tenant: str) -> dict:
    return as_bot(world, jwts(world, gen)[-1], f"repos/{repo_of(tenant)}/branches/main").json()


def _writes(world, tenant: str, since: int = 0) -> list:
    return [c for c in world.forge.calls[since:] if c.method in ("POST", "PATCH") and c.path.startswith(_rules(world, tenant))]


def test_creation_stores_the_rule_for_the_members_team_only_and_the_bot_cannot_merge(world):
    """Create sends push off and a merge whitelist of exactly team `members` with no user; the stored rule is that
    and the bot reads can-push and can-merge false (A23 amended by #1592 OD-5, S3-19)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    [sent] = _writes(world, tenant)
    assert (sent.method, sent.body["enable_push"], sent.body["enable_merge_whitelist"]) == ("POST", False, True)
    assert (sent.body["merge_whitelist_teams"], sent.body.get("merge_whitelist_usernames") or []) == (["members"], [])
    rule = world.forge.rule(repo_of(tenant))
    assert (rule["enable_push"], rule["enable_merge_whitelist"]) == (False, True)
    assert (rule["merge_whitelist_teams"], rule["merge_whitelist_usernames"]) == (["members"], [])
    view = _bot_view(world, gen, tenant)
    assert (view["protected"], view["user_can_push"], view["user_can_merge"]) == (True, False, False)


def test_a_rule_the_forge_refuses_fails_the_template_step_and_resumes_once_it_accepts(world):
    """The forge answers 422 to the rule: the step fails, no rule is stored and the job stops before wrapping anything;
    with the forge accepting again, resume finishes (A23, P-a)."""
    tenant = world.create()
    world.forge.fail_next[("POST", _rules(world, tenant))] = 422
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "template", "service")
    assert item["failure"] and "template" in item["failure"]
    assert world.forge.made("POST", _rules(world, tenant)), "control: the forge was sent the rule and refused it"
    assert world.forge.rule(repo_of(tenant)) is None
    assert world.openbao.wrapped == {}
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202  # control: the same channel, accepting
    world.drive()
    assert world.item(tenant)["state"] == "active"


# --- rotation ---------------------------------------------------------------------------------------------

def test_a_rotation_writes_nothing_to_a_rule_that_already_holds_the_invariant(world):
    """A healthy rule is read back and left alone by rotation's `protect` step: no POST, no PATCH (A23, r8.3)."""
    tenant = world.active_tenant()
    before = dict(world.forge.rule(repo_of(tenant)))
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["pending_action"] is None
    assert _writes(world, tenant, mark) == []
    assert any(c.method == "GET" and c.path.startswith(_rules(world, tenant)) for c in world.forge.calls[mark:]), \
        "control: rotation read the rule"
    assert world.forge.rule(repo_of(tenant)) == before


def test_a_rotation_heals_a_pre_r8_rule_and_the_new_bot_passes_install(world):
    """A tenant created before r8 (push on, no merge whitelist) is PATCHed by rotation to the invariant, the new bot
    can then neither push nor merge, and the rotation completes (A23, r8.3 upgrade)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    world.forge.put_rule(full, rule_name="main", branch_name="main", enable_push=True, enable_push_whitelist=False,
                         enable_merge_whitelist=False)
    assert _bot_view(world, world.live(tenant), tenant)["user_can_merge"] is True, "control: the old rule lets the bot merge"
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    [patch] = _writes(world, tenant, mark)
    assert (patch.method, patch.path) == ("PATCH", f"{_rules(world, tenant)}/main")
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["members"])
    new = world.live(tenant)
    view = _bot_view(world, new, tenant)
    assert (view["user_can_push"], view["user_can_merge"]) == (False, False)


def test_a_rotation_disables_push_on_a_rule_that_otherwise_holds_the_invariant(world):
    """A rule with push enabled but the merge whitelist on, exactly `members` named and no bot is PATCHed to push off by rotation's
    `protect`, and the rotation completes only with the stored rule holding (A23, r8.4 push disabled)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    world.forge.put_rule(full, rule_name="main", branch_name="main", enable_push=True, enable_push_whitelist=False,
                         enable_merge_whitelist=True, merge_whitelist_teams=["members"], merge_whitelist_usernames=[])
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    [patch] = _writes(world, tenant, mark)
    assert (patch.method, patch.body["enable_push"]) == ("PATCH", False)
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["members"])
    assert _bot_view(world, world.live(tenant), tenant)["user_can_push"] is False


def test_a_rotation_makes_a_rule_that_is_missing(world):
    """A rule deleted by hand is made again by rotation's `protect` step with the invariant (POST) (A23, r8.3)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    del world.forge.repos[full]["protections"]["main"]
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    assert [c.method for c in _writes(world, tenant, mark)] == ["POST"]
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["members"])


def test_a_rotation_whose_rule_the_forge_refuses_fails_at_protect_and_resumes_once_it_accepts(world):
    """A rule deleted by hand and a forge that refuses the new one at rotation (422): the rotation fails at `protect`
    with no new generation live; with the forge accepting again, resume completes (A23, r8.3)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    old = world.live(tenant)
    del world.forge.repos[full]["protections"]["main"]
    world.forge.fail_next[("POST", _rules(world, tenant))] = 422
    _rotate(world, tenant)
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "active" and item["pending_action"] is not None and item["step"] == "protect", item
    assert item["failure"] and "protect" in item["failure"]
    assert world.forge.made("POST", _rules(world, tenant)), "control: the forge was sent the rule and refused it"
    assert world.live(tenant).salt == old.salt
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202  # control: the same channel, accepting
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["pending_action"] is None
    assert world.forge.rule(full)["merge_whitelist_teams"] == ["members"]


def test_rotation_strips_everything_but_team_members_from_the_whitelist(world):
    """On the second rotation the whitelist names a destroyed generation's bot, the live one and the pending one, a human, a bot-like
    login of no generation, Owners and another team: it ends with team `members` only and the PATCH sent exactly that
    (A23 amended by #1592 OD-5, S3-19)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    world.forge.make_team(org_of(tenant), "Reviewers", members=["carol"])
    world.forge.users.update({"carol", "bot-ops"})
    _rotate(world, tenant)
    world.drive()
    [destroyed] = [g for g in world.generations(tenant) if g.status == "destroyed"]
    first = destroyed.bot_login
    seen: list[None] = []

    def hold_every_generation() -> None:
        if not seen:
            seen.append(None)
            # Added here, after rotation's `bot` step (which leaves only the new bot collaborating, Flow 1.5): a
            # bot-like login that is not a generation's, with access, so "strips the others" is really tested.
            world.forge.repos[full]["collaborators"]["bot-ops"] = "write"
            bots = [u for u in world.forge.users if u.startswith("bot-") and u != "bot-ops"]
            rule = world.forge.rule(full)
            world.forge.put_rule(full, **{**rule, "merge_whitelist_usernames": ["carol", "bot-ops", *bots],
                                          "merge_whitelist_teams": ["members", "Reviewers", "Owners"]})
            rule = world.forge.rule(full)
            rule["merge_whitelist_usernames"] = [*rule["merge_whitelist_usernames"], first]  # the purged bot's stale name
    base = _rules(world, tenant)
    world.forge.during[("GET", f"{base}/main")] = hold_every_generation
    world.forge.during[("GET", base)] = hold_every_generation
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert seen and world.item(tenant)["state"] == "active"
    rule = world.forge.rule(full)
    assert rule["merge_whitelist_usernames"] == []
    assert rule["merge_whitelist_teams"] == ["members"]
    [patch] = _writes(world, tenant, mark)
    assert patch.body["merge_whitelist_usernames"] == []
    assert patch.body["merge_whitelist_teams"] == ["members"]
    assert (patch.body["enable_merge_whitelist"], patch.body["enable_push"]) == (True, False)


def _team_patches(world, tenant: str) -> list:
    team_id = world.forge._team_id(org_of(tenant), "members")
    return [c for c in world.forge.calls if c.method == "PATCH" and c.path == f"/api/v1/teams/{team_id}"]


def test_creation_makes_the_organisation_and_the_members_team_in_the_shape_the_design_names(world):
    """Create makes private organisation `t-<T>`, then team `members`: write, units code/pulls/issues, not including
    all repositories, no org-repository creation, exactly T's repository, no `units_map` sent; Owners is the admin
    only (#1592 OD-5, P20, P33, S3-19)."""
    tenant = world.active_tenant()
    org = org_of(tenant)
    assert world.forge.org_visibility[org] == "private"
    posts = [c for c in world.forge.calls if c.method == "POST" and c.path == "/api/v1/orgs"]
    assert [c.body["username"] for c in posts] == [org]
    fields = world.forge.team(org, "members")
    assert fields["permission"] == "write"
    assert sorted(fields["units"]) == ["repo.code", "repo.issues", "repo.pulls"]
    assert (fields["includes_all_repositories"], fields["can_create_org_repo"]) == (False, False)
    assert world.forge.attached(org, "members") == {repo_of(tenant)}
    assert world.forge.team_members[org, "Owners"] == {ADMIN_LOGIN}
    sent = [c for c in world.forge.calls if c.method in ("POST", "PATCH") and "/teams" in c.path and "/repos/" not in c.path]
    assert sent, "control: the team was written"
    assert not [c for c in sent if "units_map" in (c.body or {})], "units_map can escalate to admin (P20)"
    for call in sent:
        if "includes_all_repositories" in (call.body or {}):
            assert call.body["includes_all_repositories"] is False
            assert call.body.get("permission") == "write", "without permission the forge ignores includes_all_repositories (P33)"
            assert call.body.get("can_create_org_repo") is False


def test_a_rotation_restores_the_organisation_to_the_shape_after_hand_edits(world):
    """After an operator turned the team to include all repositories, gave it admin and added a second repository
    and a second owner by hand, rotation's `protect` puts it back: includes-all off (sent with `permission: write`),
    write, exactly T's repository, Owners the admin only (A23 amended by #1592 OD-5, P33, S3-19)."""
    tenant = world.active_tenant()
    org, full = org_of(tenant), repo_of(tenant)
    world.forge.users.add("mallory")
    stray = f"{org}/extra"
    world.forge.add_user_repo(org, "extra")  # a bare repository of the organisation, made by hand
    world.forge.team_fields[org, "members"].update(permission="admin", includes_all_repositories=True, can_create_org_repo=True)
    world.forge.team_repos[org, "members"].add(stray)
    world.forge.team_members[org, "Owners"].add("mallory")
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    fields = world.forge.team(org, "members")
    assert (fields["permission"], fields["includes_all_repositories"], fields["can_create_org_repo"]) == ("write", False, False)
    assert world.forge.attached(org, "members") == {full}, "the extra repository stayed attached (P33)"
    assert world.forge.team_members[org, "Owners"] == {ADMIN_LOGIN}
    patches = [c for c in _team_patches(world, tenant) if c in world.forge.calls[mark:]]
    assert patches, "control: the team was written"
    assert all(c.body.get("permission") == "write" and "units_map" not in c.body for c in patches)
    assert any(c.body.get("includes_all_repositories") is False for c in patches)


def test_rotation_gives_an_existing_tenants_new_integration_write_issue(world):
    """A tenant whose live integration predates the grant (write:repository only: the issue API refuses its bot) has
    write:issue on the integration its next rotation creates (#1414 D13; moved here from the retired
    `test_1414_merge_eligibility`, whose creation twin `test_entry_guards` already pins through the recorded `--scope`)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    old = world.live(tenant)
    [rule] = [r for r in world.forge.integration_rules.values() if r["user"] == old.bot_login]
    rule["scopes"] = ["write:repository"]
    assert as_bot(world, jwts(world, old)[-1], f"repos/{full}/issues").status_code == 403, "control: no write:issue"
    _rotate(world, tenant)
    world.drive()
    new = world.live(tenant)
    assert new.salt != old.salt
    [made] = [c for c in world.integration.created if c["user"] == new.bot_login]
    assert sorted(part for value in made["scopes"] for part in value.split(",")) == ["write:issue", "write:repository"]
    assert as_bot(world, jwts(world, new)[-1], f"repos/{full}/issues").status_code == 200


@pytest.mark.parametrize("how", ["bot merge-whitelisted", "merge whitelist off"])
def test_rotation_install_fails_when_the_new_bot_can_merge_main_and_resumes_once_it_cannot(world, how):
    """Rotation's install makes the same check as creation's: a rule at install that lets the new bot merge fails install
    (restart at `wrap`) and commits no generation; restored, resume completes (A23, r8.3)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    saved = dict(world.forge.rule(full))
    old = world.live(tenant)
    _rotate(world, tenant)
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    [new] = [g for g in world.generations(tenant) if g.status == "pending"]
    broken = {
        "bot merge-whitelisted": {"enable_merge_whitelist": True, "merge_whitelist_usernames": [new.bot_login]},
        "merge whitelist off": {"enable_merge_whitelist": False},
    }[how]
    world.forge.repos[full]["protections"]["main"] = {**saved, **broken}
    world.drive()
    item = world.item(tenant)
    assert "install" in (item["failure"] or ""), item
    assert (item["step"], item["step_actor"]) == ("wrap", "service")
    assert world.live(tenant).salt == old.salt, "the new generation went live"
    world.forge.repos[full]["protections"]["main"] = saved  # control: the same channel, protected again
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.live(tenant).salt == new.salt


@pytest.mark.parametrize("held", [
    {"merge_whitelist_teams": ["members", "Owners"]},
    {"merge_whitelist_usernames": ["carol"]},
    {"merge_whitelist_teams": ["Owners"]},
], ids=["owners alongside members", "a user alongside members", "owners instead of members"])
def test_wrap_enforces_the_rule_again_and_heals_a_whitelist_that_holds_owners_or_a_user(world, held):
    """A whitelist that holds Owners or a user breaks the invariant: `wrap` reaches `_protect_main`, which PATCHes the
    whitelist to exactly team `members` and reads it back (A23 amended by #1592 OD-5, `_wrap`, S3-19, S3-20)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    world.forge.users.add("carol")
    # `protect`, `integration` and `wrap` run in one service pass, so a stop between passes cannot land before `wrap`.
    # Failing `integration` once (the role's client-id write; it calls no forge) gives the pass boundary: `protect` has
    # run, `wrap` has not, and the planted rule is the one `wrap`'s own `_protect_main` reads.
    flaky = openbao_failing(world, lambda r: r.method in ("POST", "PUT") and "/identity/oidc/role/" in r.url.path
                            and bool(body_of(r).get("client_id")))
    _rotate(world, tenant)
    world.drive()
    assert flaky.hit, "premise: the integration step never reached the role's client-id write"
    assert world.item(tenant)["step"] == "integration", world.item(tenant)
    world.forge.repos[full]["protections"]["main"] = {**world.forge.rule(full), "merge_whitelist_usernames": [], **held}
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
    mark = len(world.forge.calls)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    [patch] = _writes(world, tenant, mark)
    assert (patch.method, patch.body["merge_whitelist_teams"], patch.body["merge_whitelist_usernames"]) == ("PATCH", ["members"], [])
    rule = world.forge.rule(full)
    assert (rule["merge_whitelist_teams"], rule["merge_whitelist_usernames"]) == (["members"], [])


def test_a_whitelist_that_still_holds_a_user_on_read_back_fails_the_protect_step_and_resumes_once_it_does_not(world):
    """The forge keeps a user on the whitelist after the PATCH: the read-back refuses it, rotation fails at `protect`
    with no new generation live; with the forge keeping nothing, resume completes (A23, #1592 OD-5, S3-20)."""
    tenant = world.active_tenant()
    full = repo_of(tenant)
    old = world.live(tenant)
    world.forge.users.add("carol")
    world.forge.repos[full]["protections"]["main"] = {**world.forge.rule(full), "merge_whitelist_usernames": ["carol"]}
    base = _rules(world, tenant)

    def keep_the_user_on_read_back() -> None:
        # the first read finds the hand edit; the one after the PATCH is the read-back, and finds the user kept
        def kept() -> None:
            world.forge.rule(full)["merge_whitelist_usernames"] = ["carol"]
        world.forge.during[("GET", f"{base}/main")] = kept
    world.forge.during[("GET", f"{base}/main")] = keep_the_user_on_read_back
    _rotate(world, tenant)
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "active" and item["pending_action"] is not None and item["step"] == "protect", item
    assert item["failure"] and "protect" in item["failure"]
    assert world.live(tenant).salt == old.salt
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["pending_action"] is None
    assert world.forge.rule(full)["merge_whitelist_usernames"] == []
