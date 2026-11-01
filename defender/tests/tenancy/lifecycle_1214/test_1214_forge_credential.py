"""#1214 forge credential provider: `forge_credential(T, purpose)` reads the live generation and its recorded secret
file on every mint, so a long run crosses a rotation (P4, O5, Flow 3).

Pinned (GAP-C-2): `from defender.learning.author.version_control import forge_credential`;
`forge_credential(tenant_id, purpose, *, directory, config, transport=None, clock=time.time) -> ForgeCredential`
(`directory`: a `TenantDirectory`; `config`: the `LifecycleConfig` carrying `issuer_url`/`openbao_url`; `transport`: a
sync httpx transport to OpenBao; `clock`: as `ForgejoIdentity`). The credential's `token()` is a bearer JWT.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import pytest

pytest.importorskip("fastapi")

from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402

LOGIN = "/v1/auth/approle/login"


def _b64(doc: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(doc).encode()).decode().rstrip("=")


class _Jwt:
    """The fake OpenBao seen through a sync transport, with each minted token given the shape of a signed JWT
    (the fake mints opaque strings); the fake's own `minted` record is rewritten so `claims()` still resolves it."""

    def __init__(self, world: LifecycleWorld, clock: Any) -> None:
        self.world, self.clock, self.tenant = world, clock, ""
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        answer = self.world.openbao.handle(request)
        if request.method != "GET" or "/identity/oidc/token/" not in request.url.path or answer.status_code != 200:
            return answer
        role = request.url.path.rsplit("/", 1)[1]
        opaque = json.loads(answer.content)["data"]["token"]
        now = int(self.clock())
        gen = next(g for g in self.world.generations(self.tenant) if g.oidc_role == role)
        shaped = ".".join((_b64({"alg": "none"}), _b64({
            "iss": self.world.config.issuer_url, "tenant_id": self.tenant, "aud": gen.audience,
            "iat": now, "exp": now + 600}), "sig"))
        minted = self.world.openbao.minted
        minted[minted.index((role, opaque))] = (role, shaped)
        return httpx.Response(200, json={"data": {"token": shaped}})


class _Scene:
    def __init__(self, world: LifecycleWorld) -> None:
        from defender.learning.author.version_control import forge_credential

        self.world, self.offset = world, 0.0
        self.shaped = _Jwt(world, self.now)
        self.make = lambda tenant, purpose="drain": forge_credential(
            tenant, purpose, directory=world.directory(), config=world.config,
            transport=self.shaped.transport, clock=self.now)

    def now(self) -> float:
        return time.time() + self.offset

    def later(self, seconds: float = 700.0) -> None:
        """Past the lifetime of any token already minted."""
        self.offset += seconds

    def logins(self) -> list[dict[str, Any]]:
        return [c.body for c in self.world.openbao.calls if c.path == LOGIN]

    def role_of(self, jwt: str) -> str:
        return self.world.openbao.claims(jwt)["role"]


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


@pytest.fixture
def scene(world):
    return _Scene(world)


def _active(scene: _Scene) -> tuple[str, Any]:
    tenant = scene.world.active_tenant()
    scene.shaped.tenant = tenant
    return tenant, scene.world.live(tenant)


@pytest.mark.parametrize("purpose", ["publish", "drain"])
def test_the_credential_mints_for_the_live_generation(scene, purpose):
    """The credential is for the tenant and its token is minted for the live generation's OIDC role (P4)."""
    tenant, gen = _active(scene)
    credential = scene.make(tenant, purpose)
    assert credential.tenant_id == tenant
    assert scene.role_of(credential.token()) == gen.oidc_role


def test_a_credential_made_before_a_rotation_mints_for_the_new_generation_after_it(scene):
    """Old credential object, new mint: after rotate, the token is minted for the new role and logged in with the new
    AppRole pair read from the new recorded file (P4, O5, Flow 3)."""
    world = scene.world
    tenant, before = _active(scene)
    credential = scene.make(tenant)
    first = credential.token()
    assert scene.role_of(first) == before.oidc_role
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    after = world.live(tenant)
    assert after.oidc_role != before.oidc_role
    assert not before.host_secret_file.exists(), "control: the old generation's file is gone"
    scene.later()
    second = credential.token()
    assert second != first
    assert scene.role_of(second) == after.oidc_role
    assert scene.logins()[-1]["role_id"] == after.role_id


def test_the_recorded_secret_file_is_read_on_every_mint(scene):
    """A file replaced by a wrong secret fails the next mint; restored, the mint works again (no cached secret)."""
    tenant, gen = _active(scene)
    credential = scene.make(tenant)
    credential.token()
    original = gen.host_secret_file.read_bytes()
    gen.host_secret_file.write_bytes(b"not-the-secret\n")
    scene.later()
    with pytest.raises(Exception, match=r"(?i)refus|login|token|secret") as refused:
        credential.token()
    assert "not-the-secret" not in str(refused.value)
    gen.host_secret_file.write_bytes(original)
    scene.later()
    assert scene.role_of(credential.token()) == gen.oidc_role  # control: the same channel works with the right file


def test_a_credential_outlives_nothing_after_offboarding(scene):
    """Once every generation is destroyed a further mint fails and no login is attempted with a stale secret (O4)."""
    world = scene.world
    tenant, _gen = _active(scene)
    credential = scene.make(tenant)
    credential.token()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    logins = len(scene.logins())
    scene.later()
    with pytest.raises(Exception, match=r"(?i)generation|credential|tenant|refus|secret"):
        credential.token()
    assert len(scene.logins()) == logins


def test_a_tenant_still_being_created_has_no_credential_to_mint(scene):
    """Before its generation is live there is nothing to read: the provider refuses rather than invent one (P3)."""
    tenant = scene.world.create()
    scene.shaped.tenant = tenant
    with pytest.raises(Exception, match=r"(?i)generation|credential|tenant|live|refus"):
        scene.make(tenant).token()


def test_a_tenant_stopped_at_prepare_mints_with_its_live_generation(scene):
    """DC-5: the generation is live at the sweep while the tenant is still `creating`, so prepare's first publish
    mints through the normal provider (P3 does not check the tenant's state)."""
    world = scene.world
    tenant = world.create()
    scene.shaped.tenant = tenant
    world.drive(stop=lambda: world.item(tenant)["step"] == "prepare")
    item = world.item(tenant)
    assert (item["state"], item["step"]) == ("creating", "prepare")
    live = world.live(tenant)
    credential = scene.make(tenant, "publish")
    assert credential.tenant_id == tenant
    assert scene.role_of(credential.token()) == live.oidc_role
    assert scene.logins()[-1]["role_id"] == live.role_id


def test_a_token_still_valid_is_handed_out_without_reading_the_tenant_records(scene):
    """Within the token's lifetime a second `token()` is the same token and reads neither the tenant records nor
    OpenBao (a drain asks once per forge call); past it, the next mint reads the live generation again (P4)."""
    tenant, _gen = _active(scene)
    credential = scene.make(tenant)
    reads: list[str] = []
    real = credential.directory.generations
    credential.directory.generations = lambda t: (reads.append(t), real(t))[1]
    first = credential.token()
    assert len(reads) == 1
    logins = len(scene.logins())
    assert credential.token() == first
    assert len(reads) == 1, "a valid token was handed out only after a database read"
    assert len(scene.logins()) == logins
    scene.later()
    assert credential.token() != first
    assert len(reads) == 2
