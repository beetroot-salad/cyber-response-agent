"""#1214 create, progress, resume, many tenants, audit (O1, O2, O3, O6, O7, O10) — in-memory twin."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.api._identity1306 import NEW, AuditLog, user_id  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import (  # noqa: E402
    CREATE,
    RESUME,
    LifecycleWorld,
    is_uuid4,
    tenant_ids,
)

REPOS = "/api/v1/orgs/tenants/repos"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def test_create_answers_202_with_a_minted_id_and_a_creating_row(world):
    """POST /admin/tenants mints a UUID, records it `creating` with `create` pending, answers 202 (O1)."""
    made = world.ops.post("/admin/tenants", json={})
    assert made.status_code == 202, made.text
    tenant = made.json()["tenant_id"]
    assert is_uuid4(tenant)
    assert made.headers["location"] == f"/admin/tenants/{tenant}"
    assert (made.json()["state"], made.json()["pending_action"]) == ("creating", "create")
    assert world.forge.calls == [] and world.openbao.calls == []  # the API reaches neither


def test_the_job_leaves_an_active_tenant_with_repo_bot_credential_folder_and_no_membership(world):
    """After the job: `active`; private repo, `main` protected and read back; the bot is the only
    collaborator; the host holds the credential, the folder and one publish; no membership (O1, O6)."""
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert {k: item[k] for k in ("state", "pending_action", "step", "step_actor", "failure")} == {
        "state": "active", "pending_action": None, "step": None, "step_actor": None, "failure": None}
    full = f"tenants/{tenant}"
    gen = world.live(tenant)
    assert world.forge.repos[full]["private"] is True
    assert world.forge.collaborators(full) == {gen.bot_login: "write"}
    assert "main" in world.forge.repos[full]["protections"]
    protect = [i for i, c in enumerate(world.forge.calls) if c.path.endswith("/branch_protections")]
    read_back = [i for i, c in enumerate(world.forge.calls)
                 if c.method == "GET" and c.path.endswith("/branch_protections/main")]
    assert protect and read_back and read_back[-1] > protect[-1], "protection was not read back"
    assert world.forge.has_commits(full)
    # The template commit was pushed with a token minted for the bot's OIDC role.
    bot_jwts = [jwt for role, jwt in world.openbao.minted if role == gen.oidc_role]
    assert any(any(jwt in v for v in (*args, *env.values()) for jwt in bot_jwts)
               for args, env in world.git.pushes())
    assert world.forge.integrations[gen.bot_login] == [gen.audience]
    assert world.openbao.oidc_roles[gen.oidc_role]["client_id"] == gen.audience
    # Host: the secret file, the only live secret id of the AppRole, the folder and one publish.
    assert gen.host_secret_file is not None and gen.host_secret_file.is_file()
    assert world.openbao.secret_accessors(gen.approle) == {gen.secret_accessor}
    assert (world.data_root / tenant).is_dir()
    assert world.publish.calls == [(tenant, world.data_root)]
    assert world.call(world.repo.memberships_of_tenant, tenant) == []
    # O6: no tenant fact on disk.
    assert not list(world.data_root.rglob("tenant.json"))
    assert not list(world.data_root.rglob("publish-status.json"))


def test_progress_shows_the_failed_step_its_actor_and_the_failure(world):
    """A failing step is visible on GET: state, pending action, step, actor, failure (O2)."""
    world.forge.fail_next[("POST", REPOS)] = 500
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert {k: item[k] for k in ("state", "pending_action", "step", "step_actor")} == {
        "state": "creating", "pending_action": "create", "step": "repo", "step_actor": "service"}
    assert "500" in item["failure"]
    [listed] = [i for i in world.ops.get("/admin/tenants").json()["items"] if i["tenant_id"] == tenant]
    assert listed == item


def test_a_failed_step_is_not_retried_by_itself_and_resume_clears_it(world, caplog):
    """A failure stays until `resume`; resume clears it and the job finishes (O3, O10)."""
    audit = AuditLog(caplog)
    world.forge.fail_next[("POST", REPOS)] = 500
    tenant = world.create()
    world.drive()
    attempts = len(world.forge.made("POST", REPOS))
    assert world.drive() == 0
    assert len(world.forge.made("POST", REPOS)) == attempts == 1
    mark = audit.mark()
    resumed = world.ops.post(f"/admin/tenants/{tenant}/resume")
    assert resumed.status_code == 202, resumed.text
    assert world.item(tenant)["failure"] is None
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(RESUME, user_id(world.ops), tenant)]
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert len(world.forge.made("POST", REPOS)) == 2


def test_a_second_tenant_is_created_beside_the_first(world):
    """Another tenant existing never refuses a create; both end active, each with its own repo and bot (O7)."""
    first = world.active_tenant()
    second = world.active_tenant()
    assert first != second
    assert sorted(tenant_ids(world.ops.get("/admin/tenants"))) == sorted([first, second])
    bots = {t: world.live(t).bot_login for t in (first, second)}
    assert bots[first] != bots[second]
    for t in (first, second):
        assert world.forge.collaborators(f"tenants/{t}") == {bots[t]: "write"}
        assert (world.data_root / t).is_dir()


def test_create_is_audited_after_its_commit(world, caplog):
    """`tenant.create` is emitted once the row is committed, naming the administrator and the tenant (O10)."""
    audit = AuditLog(caplog)
    mark = audit.mark()
    tenant = world.create()
    assert [(e.action, e.actor, e.tenant_id) for e in audit.since(mark)] == [(CREATE, user_id(world.ops), tenant)]
    assert world.record(tenant).state == "creating"


def test_a_non_active_tenant_takes_no_invitation_and_an_active_one_does(world):
    """The identity seam: `tenant_exists` is present and `active` — a creating tenant is unknown to invite (O1, #1306)."""
    tenant = world.create()
    refused = world.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": NEW})
    assert refused.status_code == 404, refused.text
    world.drive()
    assert world.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": NEW}).status_code == 202
