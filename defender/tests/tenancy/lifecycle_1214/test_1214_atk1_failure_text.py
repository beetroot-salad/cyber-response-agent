# ruff: noqa: F811, PT018
"""#1214 attack-1 H-1: a failure text never carries a secret the step handled, even when the external answer repeats it
or the secret straddles the text's length cut (DC-14)."""
from __future__ import annotations

import re

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._atk1 import Echo, EchoGit  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ADMIN_TOKEN, FORGE_URL, OPENBAO_URL  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


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
    assert failure.startswith(f"{step}:"), f"the failure does not name the step: {failure!r}"
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
