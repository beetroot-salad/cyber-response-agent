# ruff: noqa: F811, PT018
"""#1214 create, progress, step lists, host boundary, many tenants, audit (O1, O2, O3, O6, O7, O10, DC-2/3/5/10/11/12)
— in-memory twin.

#1214 attack-1 H-1: a failure text never carries a secret the step handled, even when the external answer repeats it
or the secret straddles the text's length cut (DC-14).
"""
from __future__ import annotations

import subprocess
import re

import pytest
import httpx

pytest.importorskip('fastapi')
pytest.importorskip('httpx')

from defender.tests.support.api._identity1306 import NEW, AuditLog, user_id  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ORG, FakeForge  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import (  # noqa: E402
    REPOS,
    as_bot,
    in_order,
    jwts,
    protection_reads,
    sample,
    split_drive,
)
from defender.tests.tenancy.lifecycle_1214._support import (  # noqa: E402
    CREATE,
    RESUME,
    REPO_ROOT,
    LifecycleWorld,
    is_uuid4,
    tenant_ids,
)
from defender.tenancy import template_dir  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._atk1 import Echo, EchoGit  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ADMIN_TOKEN, FORGE_URL, OPENBAO_URL  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


CREATE_STEPS = [
    ("names", "service"), ("provider", "service"), ("repo", "service"), ("bot", "service"),
    ("integration", "service"), ("template", "service"), ("wrap", "service"), ("install", "host"),
    ("sweep", "service"), ("prepare", "host"), ("activate", "service")]


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def test_create_answers_202_with_a_minted_id_and_a_creating_row(world):
    """POST /admin/tenants mints a UUID, records it `creating` with `create` pending at `names`, answers 202 (O1, DC-3)."""
    made = world.ops.post("/admin/tenants", json={})
    assert made.status_code == 202, made.text
    tenant = made.json()["tenant_id"]
    assert is_uuid4(tenant)
    assert made.headers["location"] == f"/admin/tenants/{tenant}"
    body = made.json()
    assert (body["state"], body["pending_action"], body["step"], body["step_actor"]) == (
        "creating", "create", "names", "service")
    assert world.forge.calls == [] and world.openbao.calls == []  # the API reaches neither


def test_the_job_leaves_an_active_tenant_with_repo_bot_credential_folder_and_no_membership(world):
    """After the job: `active`; private repo from the template, `main` protected and read back, the bot the only
    collaborator with write, host credential, folder, one publish, no membership (O1, O6)."""
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert {k: item[k] for k in ("state", "pending_action", "step", "step_actor", "failure")} == {
        "state": "active", "pending_action": None, "step": None, "step_actor": None, "failure": None}
    full = f"{ORG}/{tenant}"
    gen = world.live(tenant)
    assert world.forge.repos[full]["private"] is True
    assert world.forge.collaborators(full) == {gen.bot_login: "write"}
    assert "main" in world.forge.repos[full]["protections"]
    protect = [i for i, c in enumerate(world.forge.calls) if c.method == "POST" and c.path.endswith("/branch_protections")]
    read_back = protection_reads(world, full)
    assert protect and read_back and read_back[-1] > protect[-1], "protection was not read back"
    assert world.forge.integrations[gen.bot_login] == [gen.audience]
    assert world.openbao.oidc_roles[gen.oidc_role]["client_id"] == gen.audience
    assert world.openbao.secret_accessors(gen.approle) == {gen.secret_accessor}
    assert world.openbao.secret_accessors(gen.sign_approle) == {gen.sign_secret_accessor}
    folder = world.data_root / tenant
    assert folder.is_dir() and not folder.is_symlink()
    assert not list(folder.rglob("learning")), "prepare made a learning entry; the tenant's learning state is in the store (O10, D10)"
    assert world.publish.calls == [(tenant, world.data_root)]
    assert world.call(world.repo.memberships_of_tenant, tenant) == []
    assert not list(world.data_root.rglob("tenant.json"))
    assert not list(world.data_root.rglob("publish-status.json"))


def test_the_repo_is_made_from_the_template_and_the_tenant_id_file(world):
    """`main` holds the template's files plus `agent/.tenant-id` carrying the tenant id (O1, Flow 1.7)."""
    tenant = world.active_tenant()
    bare = world.forge.bare(f"{ORG}/{tenant}")

    def git(*args: str) -> bytes:
        return subprocess.run(["git", *args], cwd=bare, capture_output=True, check=True).stdout  # noqa: S603, S607
    tracked = set(git("ls-tree", "-r", "--name-only", "main").decode().split())
    template = template_dir(REPO_ROOT)
    files = {p.relative_to(template).as_posix(): p for p in template.rglob("*") if p.is_file()}
    assert files, "control: the template directory has files"
    assert tracked == set(files) | {"agent/.tenant-id"}
    for rel, path in files.items():
        assert git("show", f"main:{rel}") == path.read_bytes(), f"{rel} differs from the template"
    assert git("show", "main:agent/.tenant-id") == f"{tenant}\n".encode()
    assert git("rev-list", "--count", "main").decode().strip() == "1"


def test_the_bot_is_created_able_to_sign_in_through_its_integration_and_cannot_push_main(world):
    """The bot has must_change_password=false and is not login-prohibited (G23, G15); its host credential reads the
    repo and `branches/main` reports protected, user_can_push=false (G22, DC-11) (O1)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    assert world.forge.must_change_password[gen.bot_login] is False
    assert gen.bot_login not in world.forge.prohibit_login
    own_calls = list(world.forge.integration_calls)
    [jwt, *_] = reversed(jwts(world, gen))
    repo = f"repos/{ORG}/{tenant}"
    assert as_bot(world, jwt, repo).status_code == 200
    branch = as_bot(world, jwt, f"{repo}/branches/main")
    assert (branch.status_code, branch.json()["protected"], branch.json()["user_can_push"]) == (200, True, False)
    assert own_calls and all(status == 200 for _bot, _m, _p, status in own_calls), \
        "the host's own integration calls were refused"


def test_the_install_check_reads_branch_main_after_protection_and_no_push_to_main_is_tried(world):
    """Install proves `main` refuses the bot with `GET branches/main` (user_can_push=false), never a dry-run or a
    real push; the only push is the template commit made before protection (DC-11, G22, O1)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    paths = [(c.method, c.path) for c in world.forge.calls]
    protect = max(i for i, c in enumerate(paths) if c[1].endswith("/branch_protections"))
    checks = [i for i, c in enumerate(world.forge.calls)
              if c.path == f"/api/v1/repos/{ORG}/{tenant}/branches/main" and c.headers.get("authorization", "").startswith("Bearer ")]
    assert checks and checks[-1] > protect, "no branches/main check after protection"
    assert any(b == gen.bot_login and p.endswith("/branches/main") and s == 200
               for b, _m, p, s in world.forge.integration_calls)
    assert not [1 for args, _env in world.git.calls if "--dry-run" in args]
    assert len(world.git.pushes()) == 1, "something other than the template commit was pushed"


def test_the_generation_is_live_at_the_sweep_while_the_tenant_is_still_creating_and_publish_comes_after(world):
    """DC-5: the sweep commit makes the new generation `live` with the tenant `creating`; prepare's first
    publish then runs and activate makes the tenant active (O1)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "prepare")
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "prepare", "host")
    assert world.live(tenant).bot_login  # one live generation already
    assert world.publish.calls == []
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert world.publish.calls == [(tenant, world.data_root)]


def test_the_job_shows_its_steps_with_their_actors_in_the_documented_order(world):
    """create's steps and actors as DC-3 lists them, every host step visible, nothing pending at the end (DC-3, O2)."""
    tenant = world.create()
    seen = sample(world, tenant)
    in_order(seen, CREATE_STEPS, hosts=["install", "prepare"])
    assert seen[-1] == (None, None)


def test_each_secret_has_its_own_file_named_by_its_accessor_outside_the_tenants_folder(world):
    """The host secret file is in the secrets directory (not under `<data root>/<T>/`), named by the accessor,
    holding that AppRole secret (DC-2, O1)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    path = gen.host_secret_file
    assert path.is_file() and gen.secret_accessor in path.name
    assert world.config.secrets_dir in path.parents and tenant in str(path.relative_to(world.config.secrets_dir))
    assert (world.data_root / tenant) not in path.parents
    assert world.openbao.approles[gen.approle][gen.secret_accessor] in path.read_text()


def test_the_jwt_is_never_in_git_argv_environment_or_a_file(world):
    """The bot's JWT reaches git only through the sealed transport: sealed for the template push, absent from every
    argv and environment and from every file the job wrote (DC-10, SK-4, O1)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    tokens = jwts(world, gen)
    assert tokens
    sealed = world.git.sealed_tokens()
    assert any("push" in s.args for s in world.git.sealed), "control: the template push went through the sealed transport"
    assert any(t in sealed for t in tokens)
    for token in tokens:
        assert not world.git.argv_env_contains(token)
    files = [p for root in (world.data_root, world.config.secrets_dir) for p in root.rglob("*") if p.is_file()]
    assert files
    for path in files:
        data = path.read_bytes()
        assert not any(t.encode() in data for t in tokens), f"a JWT is in {path}"


def test_the_host_never_holds_the_management_token_or_the_forge_admin_token(world):
    """The host actor's OpenBao calls carry no management token and only unwrap, approle login, token reads and the one
    sign proof with the tenant's own sign login; its forge calls are the bot's Bearer calls (DC-12, SK-5, P5, A24')."""
    tenant = world.create()
    calls = split_drive(world)
    assert world.item(tenant)["state"] == "active"
    service_tokens = {c.headers.get("x-vault-token") for c in calls["service"]["openbao"]}
    assert world.openbao.management_token in service_tokens, "control: the service uses the management login"
    host = calls["host"]["openbao"]
    assert host, "control: the host called OpenBao"
    assert world.openbao.management_token not in {c.headers.get("x-vault-token") for c in host}
    allowed = (("sys", "wrapping", "unwrap"), ("auth", "approle", "login"), ("identity", "oidc", "token"))
    gen = world.live(tenant)
    signs = [c for c in host if c.path.startswith("/v1/transit/")]
    assert [(c.method, c.path) for c in signs] == [("POST", f"/v1/transit/sign/request-token-{tenant}")], \
        "the host's one new power is a single sign with the tenant's own key"
    assert {world.openbao.tokens[c.headers["x-vault-token"]] for c in signs} == {gen.sign_approle}, \
        "the sign proof was not made as the tenant's sign login"
    for call in host:
        assert call in signs or tuple(call.path.removeprefix("/v1/").split("/")[:3]) in allowed, \
            f"host called {call.method} {call.path}"
    host_forge = calls["host"]["forge"]
    assert host_forge, "control: the host reached the forge (install's bot calls)"
    assert [c for c in host_forge if FakeForge.credential_of(c) == "bearer"], "control: the host made bot Bearer calls"
    assert world.forge.integration_calls and all(status == 200 for _bot, _m, _p, status in world.forge.integration_calls), \
        "control: those bot calls were answered 200"
    assert {FakeForge.credential_of(c) for c in host_forge} == {"bearer"}
    assert not [c for c in host_forge if "forge-admin-token" in str(c.headers)]
    assert [c for c in calls["service"]["forge"] if FakeForge.credential_of(c) == "token"], \
        "control: the service's own calls do carry the admin token"


def test_progress_shows_the_failed_step_its_actor_and_the_failure(world):
    """A failing step is visible on GET: state, pending action, step, actor, failure (O2)."""
    world.forge.fail_next[("POST", REPOS)] = 500
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert {k: item[k] for k in ("state", "pending_action", "step", "step_actor")} == {
        "state": "creating", "pending_action": "create", "step": "repo", "step_actor": "service"}
    assert "500" in item["failure"] and "repo" in item["failure"]
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


def test_a_failing_tenant_does_not_stop_the_others(world):
    """An exception inside one tenant's step becomes that tenant's failure; the loop goes on with the rest (O3, DC-14)."""
    world.forge.fail_next[("POST", REPOS)] = 500
    first, second = world.create(), world.create()
    world.drive()
    states = sorted((world.item(t)["state"], world.item(t)["failure"] is None) for t in (first, second))
    assert states == [("active", True), ("creating", False)]


def test_a_second_tenant_is_created_beside_the_first(world):
    """Another tenant existing never refuses a create; two created side by side both end active, each with its
    own repo, bot and folder (O7)."""
    first = world.active_tenant()
    second, third = world.create(), world.create()
    world.drive()
    tenants = [first, second, third]
    assert len(set(tenants)) == 3
    assert sorted(tenant_ids(world.ops.get("/admin/tenants"))) == sorted(tenants)
    bots = {t: world.live(t).bot_login for t in tenants}
    assert len(set(bots.values())) == 3
    for t in tenants:
        assert world.item(t)["state"] == "active"
        assert world.forge.collaborators(f"{ORG}/{t}") == {bots[t]: "write"}
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


def _post(path):
    return lambda r: r.method == "POST" and r.url.path == path


def _get_prefix(prefix):
    return lambda r: r.method == "GET" and r.url.path.startswith(prefix)


#: name -> (actor, client, step the failure names, which request is answered with the echo)
CASES = {
    "admin token": ("service", "forge", "repo", _post("/api/v1/orgs/tenants/repos")),
    "bot password": ("service", "forge", "bot", _post("/api/v1/admin/users")),
    "management login": ("service", "openbao", "provider",
                         lambda r: r.method == "POST" and re.fullmatch(r"/v1/auth/approle/role/[^/]+", r.url.path)),
    "secret id (service)": ("service", "openbao", "template", _post("/v1/auth/approle/login")),
    "client token (service)": ("service", "openbao", "template", _get_prefix("/v1/identity/oidc/token/")),
    "wrapped token": ("host", "openbao", "install", _post("/v1/sys/wrapping/unwrap")),
    "secret id (host)": ("host", "openbao", "install", _post("/v1/auth/approle/login")),
    "client token (host)": ("host", "openbao", "install", _get_prefix("/v1/identity/oidc/token/")),
    "jwt (host)": ("host", "forge", "install", _get_prefix("/api/v1/repos/")),
}


def _install(world, actor, client, step, when, straddle):
    echo = Echo((world.forge if client == "forge" else world.openbao).handle, when, straddle=step if straddle else None)
    if client == "forge":
        headers = {"Authorization": f"token {ADMIN_TOKEN}"} if actor == "service" else {}
        http = httpx.AsyncClient(transport=httpx.MockTransport(echo), base_url=FORGE_URL, headers=headers)
        key = "forge"
    else:
        headers = {"X-Vault-Token": world.openbao.management_token} if actor == "service" else {}
        http = httpx.AsyncClient(transport=httpx.MockTransport(echo), base_url=OPENBAO_URL, headers=headers)
        key = "openbao" if actor == "service" else "openbao_login"
    if actor == "service":
        world.service_actor = world.new_service(world.tenants, identity=world.service, **{key: http})
    else:
        world.host_actor = world.new_host(world.tenants, **{key: http})
    return echo


def _assert_clean(failure: str, secrets: list[str], step: str) -> None:
    assert step in failure, f"the failure does not name the step: {failure!r}"
    for secret in secrets:
        leaked = secret if len(secret) < 12 else secret[:8]
        assert leaked not in failure, f"the failure carries {leaked!r}: {failure!r}"


@pytest.mark.parametrize("straddle", [False, True], ids=["echoed", "straddling-the-cut"])
@pytest.mark.parametrize("name", list(CASES))
def test_a_failure_text_carries_no_credential_the_answer_repeats(world, name, straddle):
    """The external answer repeats the credential the step sent: the recorded failure still names the step and the
    status and holds none of it, whole or cut at the length limit (DC-14)."""
    actor, client, step, when = CASES[name]
    echo = _install(world, actor, client, step, when, straddle)
    tenant = world.create()
    world.drive()
    assert echo.hit, "control: the echoing answer was never reached"
    assert echo.secrets, "control: the request carried no credential to echo"
    failure = world.item(tenant)["failure"]
    assert failure is not None and "500" in failure
    _assert_clean(failure, echo.secrets, step)


def test_a_failure_text_carries_no_minted_token_a_git_server_repeats(world):
    """A refused template push whose message repeats the bot's JWT records a failure without it (DC-14)."""
    git = EchoGit(world.git)
    world.service_actor = world.new_service(world.tenants, identity=world.service, git=git)
    tenant = world.create()
    world.drive()
    assert git.tokens, "control: the push was never refused"
    failure = world.item(tenant)["failure"]
    assert failure is not None
    _assert_clean(failure, git.tokens, "template")
