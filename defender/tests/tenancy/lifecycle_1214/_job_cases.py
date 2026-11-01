"""Helpers shared by slice B's in-memory lifecycle cases (create, offboard/rotate, crash/resume) — NO test functions.
Test-local: they only drive the world of `_support` and read the fakes of `_fakes`; they decide no policy."""
from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

import httpx

from defender.tests.support.api._identity1306 import NEW
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL, OPENBAO_URL
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld

REPOS = "/api/v1/orgs/tenants/repos"
USERS = "/api/v1/admin/users"


def member_browser(world: LifecycleWorld, tenant: str, email: str = NEW) -> Any:
    """`email` invited by `ops`, sent and signed in. #1306's first sign-in accepts the open invitation itself
    (SK-1: no separate accept), so the browser is an active member; checked on the members route."""
    invited = world.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": email})
    assert invited.status_code == 202, invited.text
    world.send_pending()
    browser = world.sign_in(email)
    assert browser.get(f"/tenants/{tenant}/members").status_code == 200
    return browser


def as_bot(world: LifecycleWorld, jwt: str, path: str) -> httpx.Response:
    """GET `path` (under /api/v1) on the fake forge with `jwt` as Bearer: what the host's credential does."""
    request = httpx.Request("GET", f"{FORGE_URL}/api/v1/{path}", headers={"Authorization": f"Bearer {jwt}"})
    return world.forge.handle(request)


def protection_reads(world: LifecycleWorld, full: str) -> list[int]:
    """Indexes of the forge calls that read `full`'s branch protection: `GET .../branch_protections/main` or the list
    read `GET .../branch_protections` (either shows the rule on `main`; DC-11, FR-9)."""
    base = f"/api/v1/repos/{full}/branch_protections"
    return [i for i, c in enumerate(world.forge.calls) if c.method == "GET" and c.path in (base, f"{base}/main")]


def jwts(world: LifecycleWorld, gen: Any) -> list[str]:
    """Every JWT OpenBao minted for the generation's OIDC role so far."""
    return [jwt for role, jwt in world.openbao.minted if role == gen.oidc_role]


def sample(world: LifecycleWorld, tenant: str, *, limit: int = 60,
           at: dict[str, Callable[[], None]] | None = None) -> list[tuple[str | None, str | None]]:
    """Drive the job, noting (step, actor) after every pass; consecutive repeats dropped. `at[step]` is called once,
    the first time a pass leaves the job at that step (its work not yet done)."""
    seen: list[tuple[str | None, str | None]] = []
    pending = dict(at or {})

    def note() -> bool:
        item = world.item(tenant)
        point = (item["step"], item["step_actor"])
        if point[0] in pending:
            pending.pop(point[0])()
        if not seen or seen[-1] != point:
            seen.append(point)
        return False
    world.drive(limit=limit, stop=note)
    return seen


def in_order(seen: list[tuple[str | None, str | None]], steps: list[tuple[str, str]], *, hosts: list[str]) -> None:
    """`seen` (nothing-pending dropped) lists steps of `steps` in order with their actors, and every host step
    of `hosts` appears: a pass may run several service steps, but never skips a handoff (DC-3)."""
    pending = [p for p in seen if p != (None, None)]
    names = [s for s, _ in steps]
    positions = [names.index(s) for s, _ in pending]
    assert positions == sorted(positions), f"steps out of order: {pending}"
    for step, actor in pending:
        assert (step, actor) in steps, f"{step} is not a {actor} step of this job"
    for host in hosts:
        assert any(s == host for s, _ in pending), f"host step {host} was never visible: {pending}"


class Flaky:
    """An `httpx` transport over a fake's `handle` that answers `status` to the first request `when` accepts
    (once, and only while `armed` is true), before the fake sees it; the call is kept in `hit`."""

    def __init__(self, handle: Callable[[httpx.Request], httpx.Response], when: Callable[[httpx.Request], bool],
                 status: int = 500) -> None:
        self.handle, self.when, self.status = handle, when, status
        self.hit: list[httpx.Request] = []
        self.armed = True

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.armed and not self.hit and self.when(request):
            self.hit.append(request)
            return httpx.Response(self.status, json={"message": "injected"})
        return self.handle(request)


def body_of(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content) if request.content else {}


def secret_id_listing(request: httpx.Request) -> bool:
    """A listing of an AppRole's secret ids, in either spelling OpenBao accepts: `LIST .../secret-id` or
    `GET .../secret-id?list=true` (F-10). A predicate for `openbao_failing`."""
    path = request.url.path
    return (path.startswith("/v1/auth/approle/role/") and path.endswith("/secret-id")
            and (request.method == "LIST" or request.url.params.get("list") == "true"))


def tenant_steps(world: LifecycleWorld) -> set[str | None]:
    """The step every tenant row is at now (read between passes, never from inside a call)."""
    return {t.step for t in world.call(world.tenants.tenants)}


def openbao_failing(world: LifecycleWorld, when: Callable[[httpx.Request], bool], status: int = 500, *,
                    during_step: str | None = None) -> Flaky:
    """Replace the world's service with one whose OpenBao management client fails the first request `when`
    accepts (same fakes and repository otherwise); the host is replaced likewise by `host_openbao_failing`.
    With `during_step="sweep"` the injection is armed only for a service pass that STARTS with a tenant at that
    step (steps of the other actor lie between, so an earlier listing, e.g. at `wrap`, never trips it); a pass
    that starts elsewhere runs unarmed. The world's `service_pass` is wrapped to do this (F-10)."""
    flaky = Flaky(world.openbao.handle, when, status)
    client = httpx.AsyncClient(transport=httpx.MockTransport(flaky), base_url=OPENBAO_URL,
                               headers={"X-Vault-Token": world.openbao.management_token})
    world.service_actor = world.new_service(world.tenants, identity=world.service, openbao=client)
    if during_step is not None:
        flaky.armed = False
        plain = type(world).service_pass.__get__(world)

        def gated() -> int:
            flaky.armed = during_step in tenant_steps(world)
            try:
                return plain()
            finally:
                flaky.armed = False
        world.service_pass = gated  # type: ignore[method-assign]
    return flaky


def sweep_failure(world: LifecycleWorld) -> Flaky:
    """`FAILURES["sweep"]`'s set-up: the first secret-id listing made while a tenant is at `sweep` answers 500."""
    return openbao_failing(world, secret_id_listing, during_step="sweep")


def host_openbao_failing(world: LifecycleWorld, when: Callable[[httpx.Request], bool], status: int = 500) -> Flaky:
    flaky = Flaky(world.openbao.handle, when, status)
    client = httpx.AsyncClient(transport=httpx.MockTransport(flaky), base_url=OPENBAO_URL)
    world.host_actor = world.new_host(world.tenants, openbao_login=client)
    return flaky


class FailingGit:
    """The git runner, except that a call `when(args)` accepts (once) returns exit status 1."""

    def __init__(self, inner: Any, when: Callable[[list[str]], bool]) -> None:
        self.inner, self.when, self.hit = inner, when, 0

    def __call__(self, args: Any, **kw: Any) -> subprocess.CompletedProcess[str]:
        if not self.hit and self.when([str(a) for a in args]):
            self.hit += 1
            return subprocess.CompletedProcess(args, 1, "", "fatal: injected failure")
        return self.inner(args, **kw)


def split_drive(world: LifecycleWorld, *, limit: int = 60) -> dict[str, dict[str, list[Any]]]:
    """Drive the job pass by pass, keeping each actor's OpenBao and forge calls apart."""
    out: dict[str, dict[str, list[Any]]] = {"service": {"openbao": [], "forge": []}, "host": {"openbao": [], "forge": []}}
    for _ in range(limit):
        ran = 0
        for kind, run_pass in (("service", world.service_pass), ("host", world.host_pass)):
            b0, f0 = len(world.openbao.calls), len(world.forge.calls)
            ran += run_pass()
            out[kind]["openbao"] += world.openbao.calls[b0:]
            out[kind]["forge"] += world.forge.calls[f0:]
        if not ran:
            return out
    raise AssertionError("the job did not settle")


def stray_secrets(world: LifecycleWorld) -> list[str]:
    """Every secret string the fakes hold (for 'failures never carry a secret')."""
    secrets = ["forge-admin-token", world.openbao.management_token]
    secrets += [s for ids in world.openbao.approles.values() for s in ids.values()]
    secrets += list(world.openbao.wrapped) + [j for _, j in world.openbao.minted]
    return secrets
