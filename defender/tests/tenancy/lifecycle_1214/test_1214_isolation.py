# ruff: noqa: PT018
"""#1214 O8 tenant isolation and install's `main` check, in memory over the fakes (O8, O1, DC-11, F-6, F-7).
The live counterpart on real Forgejo and OpenBao is `test_1214_live.py`."""
from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import as_bot, jwts  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _login_and_mint(world: LifecycleWorld, gen, role: str | None = None) -> httpx.Response:
    """What the host does with a generation's AppRole pair: log in, then read `identity/oidc/token/<role>`."""
    bao = httpx.Client(transport=httpx.MockTransport(world.openbao.handle), base_url="http://openbao.test")
    secret = world.openbao.approles[gen.approle][gen.secret_accessor]
    logged = bao.post("/v1/auth/approle/login", json={"role_id": gen.role_id, "secret_id": secret})
    assert logged.status_code == 200, logged.text
    token = logged.json()["auth"]["client_token"]
    return bao.get(f"/v1/identity/oidc/token/{role or gen.oidc_role}", headers={"X-Vault-Token": token})


def _two(world: LifecycleWorld):
    a, b = world.active_tenant(), world.active_tenant()
    return a, world.live(a), b, world.live(b)


def test_a_credential_of_one_tenant_gets_404_on_the_others_repo_and_200_on_its_own(world):
    """A's bot JWT reads A's repo (200, control) and is told 404 for B's repo through A's integration (O8)."""
    a, gen_a, b, _gen_b = _two(world)
    jwt = jwts(world, gen_a)[-1]
    assert as_bot(world, jwt, f"repos/{ORG}/{a}").status_code == 200
    assert as_bot(world, jwt, f"repos/{ORG}/{b}").status_code == 404


def test_a_jwt_of_one_tenant_is_refused_by_the_others_integration_on_its_claim(world):
    """Mis-wire A's OIDC role to B's audience: B's integration refuses the JWT's `tenant_id` claim (401), while the
    same JWT shape for B itself is accepted (O8, F-6)."""
    a, gen_a, b, gen_b = _two(world)
    minted = _login_and_mint(world, gen_b)
    assert minted.status_code == 200
    own = as_bot(world, minted.json()["data"]["token"], f"repos/{ORG}/{b}")
    assert own.status_code == 200, "control: B's own mint is accepted by B's integration"
    world.openbao.oidc_roles[gen_a.oidc_role]["client_id"] = gen_b.audience
    crossed = _login_and_mint(world, gen_a)
    assert crossed.status_code == 200
    jwt = crossed.json()["data"]["token"]
    assert world.openbao.claims(jwt)["tenant_id"] == a
    assert as_bot(world, jwt, f"repos/{ORG}/{b}").status_code == 401
    assert as_bot(world, jwt, f"repos/{ORG}/{a}").status_code == 401


def test_an_entity_reads_only_its_own_oidc_role(world):
    """The templated policy: A's login mints A's role (control) and is refused B's (O8, F-6)."""
    _a, gen_a, _b, gen_b = _two(world)
    assert _login_and_mint(world, gen_a).status_code == 200
    assert _login_and_mint(world, gen_a, role=gen_b.oidc_role).status_code == 403


def test_the_entity_carries_the_role_and_tenant_the_templated_policy_and_the_claim_read(world):
    """The entity's metadata names its OIDC role and its tenant, and its alias is the AppRole's role id (G10, F-6)."""
    a, gen, _b, _gen_b = _two(world)
    metadata = world.openbao.entities[gen.entity]["metadata"]
    assert metadata["oidc_role"] == gen.oidc_role and metadata["tenant_id"] == a
    assert [x for x in world.openbao.aliases if x.get("name") == gen.role_id], "no alias named by the role id"


def test_each_integration_is_created_with_the_issuer_the_tenant_claim_the_repo_and_a_write_scope(world):
    """`--issuer <config.issuer_url> --claim-eq tenant_id=<T> --repo tenants/<T>` and a write scope (F-6, O8)."""
    a, gen_a, b, gen_b = _two(world)
    for tenant, gen in ((a, gen_a), (b, gen_b)):
        [made] = [c for c in world.integration.created if c["user"] == gen.bot_login]
        assert made["issuer"] == world.config.issuer_url
        assert made["claims_eq"] == {"tenant_id": tenant}
        assert made["repos"] == [f"{ORG}/{tenant}"]
        assert set(made["scopes"]) & {"write:repository", "all"}, made["scopes"]
        assert made["audience"] == gen.audience


# --- install's check that the bot cannot push main (DC-11, F-7) -------------------------------------

def _break_protection(world: LifecycleWorld, tenant: str, how: str) -> dict:
    full = f"{ORG}/{tenant}"
    bot = world.generations(tenant)[0].bot_login
    protections = world.forge.repos[full]["protections"]
    saved = dict(protections["main"])
    if how == "missing":
        del protections["main"]
    else:
        protections["main"] = {**saved, "enable_push": True, "push_whitelist_usernames": [bot]}
    return saved


@pytest.mark.parametrize("how", ["missing", "bot whitelisted"])
def test_install_fails_loudly_when_the_bot_could_push_main_and_resumes_once_it_cannot(world, how):
    """A protection that leaves the bot able to push `main` fails install (failure names it), commits no
    generation, tries no push; restored, resume finishes the job (DC-11, O1)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    saved = _break_protection(world, tenant, how)
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "creating" and "install" in item["failure"], item
    assert (item["step"], item["step_actor"]) == ("wrap", "service"), item  # DC-4: the check runs after the unwrap; the wrapper is spent
    assert not [g for g in world.generations(tenant) if g.status == "live"]
    assert world.publish.calls == []
    assert len(world.git.pushes()) == 1, "only the template commit may be pushed"
    assert not [1 for args, _e in world.git.calls if "--dry-run" in args]
    world.forge.repos[f"{ORG}/{tenant}"]["protections"]["main"] = saved  # control: the same channel, protected again
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert len(world.git.pushes()) == 1


def test_the_protection_read_back_is_the_rule_on_main_that_stops_the_bot(world):
    """The recorded protection rule is for `main`, does not whitelist the bot, and `branches/main` agrees (O1, DC-11)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    rule = world.forge.repos[f"{ORG}/{tenant}"]["protections"]["main"]
    assert (rule.get("rule_name") or rule.get("branch_name")) == "main"
    assert gen.bot_login not in (rule.get("push_whitelist_usernames") or [])
    reads = [c for c in world.forge.calls if c.method == "GET" and c.path.endswith(f"/repos/{ORG}/{tenant}/branch_protections/main")]
    assert reads and reads[-1].headers["authorization"].startswith("token "), "read back as the administrator"
