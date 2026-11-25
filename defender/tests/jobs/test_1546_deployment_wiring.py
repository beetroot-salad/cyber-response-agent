# ruff: noqa: PT018
"""#1546 Family C (triage 1; cross attack holes 2-5): what a deployment reads, with no seam in its place. Every other #1546
test hands the helper its store and key login (`evidence=`, `evidence_keys=`) and calls the retention sweep itself; here
the helper's store is the one `DEFENDER_EVIDENCE_*` names (`store_from_env`, region included, against a Garage whose
`s3_region` is not Garage's default), its key login is the one the tenant's live generation records
(`keys_from_generation`), that generation is made by the lifecycle's own create job, which writes the evidence AppRole on a
real OpenBao under the shipped `defender.evidence.TEMPLATED_POLICY` text, and the retention sweep is the lifecycle entry's
own (`python -m defender.lifecycle serve`: `_serve`, `_paced_sweep`, every five minutes).

Two fixed deployment facts no setting names stand between a test and a seamless helper run: the helper's OpenBao address is
`DEPLOYMENT_ISSUER.openbao_url` (`https://openbao:8200`), and the pacing reads `time.monotonic`. So the put and the pull
hand the helper the login `keys_from_generation` returned, its role and secret as the generation records them, rebuilt at
the test server's address (and the address checked to be the deployment's); the refused setups run with no seam at all;
and the pacing is observed through a profile hook that ages the pass the sweep remembers (it replaces nothing).

The lifecycle's create runs over the lifecycle tests' fakes except for the evidence chain: every OpenBao call about the
generation's evidence AppRole, its entity, the tenant's `evidence-<T>` key and the login on that role goes to the real
OpenBao (`_EvidenceToRealBao`); the delivery and sign chains, whose bot tokens the forge fake must recognise, stay on the
fake. Garage's second, regional instance is CI's `start_garage.sh ... DEFENDER_TEST_GARAGE_REGIONAL` (ci.yml)."""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import types
import uuid
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

pytest.importorskip("fastapi")

from defender.tests.support.evidence._evidence1546 import Garage, evidence_keys  # noqa: E402,F401 — fixture
from defender.tests.support.evidence._facts1546 import EVIDENCE_ENV_PREFIX  # noqa: E402
from defender.tests.support.jobs import _helper_evidence1546 as H  # noqa: E402
from defender.tests.support.jobs import _job_helper as J  # noqa: E402
from defender.tests.support.jobs._helper_evidence1546 import (  # noqa: E402
    drive,
    facts,
    inv_outcome,
    plant,
    pull_object,
    put_object,
    sha,
    uploads,
)
from defender.tests.support.shared._openbao1163 import TRANSIT_MOUNT, openbao  # noqa: E402,F401 — fixture
from defender.tests.support.shared._postgres1339 import empty_database, execute, migrated_database  # noqa: E402,F401 — fixtures
from defender.tests.tenancy.lifecycle_1214.test_lifecycle_process_entry import sessions_dsn  # noqa: E402,F401 — fixture

process_state = J.process_state

pytestmark = [pytest.mark.postgres, pytest.mark.openbao, pytest.mark.garage,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

#: CI's second Garage, whose `s3_region` is not `garage` (`tooling/testing/start_garage.sh <name> <port> <region> <prefix>`).
REGIONAL = "DEFENDER_TEST_GARAGE_REGIONAL"
#: defender/CLAUDE.md, the #1546 upgrade note: the lifecycle "sweeps expired evidence every five minutes".
SWEEP_EVERY = 300.0
BUNDLE = bytes(range(256)) * 4096  # 1 MiB


# --- the regional store ---------------------------------------------------------------------------------------------------

@pytest.fixture
def regional_garage() -> Iterator[Garage]:
    """CI's Garage in a region of its own; skipped where unset locally, failed where unset in CI. Its default-region twin is
    refused by it (the premise that makes the region matter)."""
    names = ("ENDPOINT", "ACCESS_KEY", "SECRET_KEY", "BUCKET", "REGION")
    values = [os.environ.get(f"{REGIONAL}_{name}") for name in names]
    if not all(values):
        if os.environ.get("CI"):
            pytest.fail(f"{REGIONAL}_* are not set in CI; the test job's second Garage step provides them")
        pytest.skip(f"{REGIONAL}_* are not set")
    endpoint, access, secret, bucket, region = (str(v) for v in values)
    assert region != "garage", f"premise: the regional store's region is not Garage's default ({region})"
    store = Garage(endpoint.rstrip("/"), access, secret, bucket, region)
    store.list("s0-probe/")
    with pytest.raises(Exception):  # noqa: B017, PT011 — any refusal: a request signed for `garage` is not this store's
        Garage(endpoint.rstrip("/"), access, secret, bucket, "garage").list("s0-probe/")
    try:
        yield store
    finally:
        for prefix in store.prefixes:
            store.delete_prefix(prefix)


def _deployment_store_env(monkeypatch, garage: Garage) -> None:
    """The helper's and the lifecycle's store settings, as a deployment sets them: `DEFENDER_EVIDENCE_*`, region included."""
    for name, value in (("ENDPOINT", garage.endpoint), ("BUCKET", garage.bucket), ("ACCESS_KEY", garage.access_key),
                        ("SECRET_KEY", garage.secret_key), ("REGION", garage.region)):
        monkeypatch.setenv(f"{EVIDENCE_ENV_PREFIX}{name}", value)


# --- the lifecycle's create, its evidence chain on the real OpenBao --------------------------------------------------------

class _EvidenceToRealBao:
    """An OpenBao transport for the lifecycle actors: a call about the evidence chain goes to the real server (its
    management token swapped for the test's root token, the approle mount's accessor for the real one), every other call
    to the lifecycle tests' fake. The chain is recognised by the lifecycle's names (`evidence-<T>-<salt>` AppRole,
    `tenant-<T>-<salt>-evidence` entity, `evidence-<T>` key) and by what the real server answered (role ids, entity ids,
    wrapping tokens)."""

    def __init__(self, fake: Any, bao: Any) -> None:
        self.fake, self.bao = fake, bao
        self.role_ids: set[str] = set()
        self.entity_ids: set[str] = set()
        self.wraps: set[str] = set()
        self.real_calls: list[tuple[str, str, int]] = []
        self._accessor: str | None = None

    def _real(self, parts: list[str], body: dict[str, Any], token: str | None) -> bool:
        if parts[:3] == ["auth", "approle", "role"] and len(parts) > 3:
            return parts[3].startswith("evidence-")
        if parts[:3] == ["identity", "entity", "name"] and len(parts) > 3:
            return parts[3].endswith("-evidence")
        if parts[:2] == ["identity", "entity-alias"]:
            return body.get("canonical_id") in self.entity_ids
        if parts[:1] == [TRANSIT_MOUNT] and len(parts) >= 3:
            key = parts[3] if parts[1] == "datakey" and len(parts) > 3 else parts[2]
            return key.startswith("evidence-")
        if parts[:3] == ["auth", "approle", "login"]:
            return body.get("role_id") in self.role_ids
        if parts[:2] == ["sys", "wrapping"]:
            return token in self.wraps
        return False

    def accessor(self) -> str:
        if self._accessor is None:
            mounts = self.bao.ok("GET", "sys/auth")["data"]
            if "approle/" not in mounts:  # the deployment's one AppRole mount (`approle`), shared like `transit/`
                reply = self.bao.call("POST", "sys/auth/approle", json={"type": "approle"})
                assert reply.status_code < 300 or "already in use" in reply.text, reply.text
                mounts = self.bao.ok("GET", "sys/auth")["data"]
            self._accessor = mounts["approle/"]["accessor"]
        return self._accessor

    def handle(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.removeprefix("/v1/").split("/")
        body = json.loads(request.content) if request.content else {}
        token = request.headers.get("x-vault-token")
        if not self._real(parts, body if isinstance(body, dict) else {}, token):
            return self.fake.handle(request)
        headers = {k: v for k, v in request.headers.items() if k.lower() in ("x-vault-wrap-ttl", "content-type")}
        if token is not None:  # the management login is the test's root token there; a client or wrapping token is as sent
            headers["X-Vault-Token"] = self.bao.root_token if token == self.fake.management_token else token
        if parts[:2] == ["identity", "entity-alias"]:
            body = {**body, "mount_accessor": self.accessor()}
        if parts[:3] == ["auth", "approle", "role"]:
            self.accessor()  # the mount exists before its first role
        reply = httpx.request(request.method, f"{self.bao.addr}{request.url.path}", params=request.url.params,
                              headers=headers, content=json.dumps(body).encode() if body else None, timeout=10)
        self.real_calls.append((request.method, request.url.path, reply.status_code))
        answer = reply.json() if reply.content else {}
        data = (answer or {}).get("data") or {}
        if parts[-1] == "role-id" and data.get("role_id"):
            self.role_ids.add(data["role_id"])
        if parts[:3] == ["identity", "entity", "name"] and data.get("id"):
            self.entity_ids.add(data["id"])
        if ((answer or {}).get("wrap_info") or {}).get("token"):
            self.wraps.add(answer["wrap_info"]["token"])
        return httpx.Response(reply.status_code, content=reply.content,
                              headers={"content-type": reply.headers.get("content-type", "application/json")})


@pytest.fixture
def installed(tmp_path, data_root, openbao, evidence_keys, monkeypatch, regional_garage):  # noqa: F811
    """A tenant made active by the lifecycle's own create and install, its generation's evidence AppRole on the real OpenBao
    under the shipped `TEMPLATED_POLICY` (the policy's name the config's, its text the shipped one). Yields
    `(tenant, live generation)`; the real role, entity and key are removed at the end."""
    from defender.evidence import TEMPLATED_POLICY
    from defender.tests.tenancy.lifecycle_1214._fakes import OPENBAO_URL
    from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config

    _deployment_store_env(monkeypatch, regional_garage)
    policy = openbao.apply_policy("defender-tenant-evidence", TEMPLATED_POLICY)
    world = LifecycleWorld(tmp_path, data_root)
    tenant = gen = None
    try:
        route = _EvidenceToRealBao(world.openbao, openbao)
        world.config = lifecycle_config(tmp_path, data_root, evidence_policy=policy)
        world.service_actor = world.new_service(world.tenants, identity=world.service, openbao=httpx.AsyncClient(
            transport=httpx.MockTransport(route.handle), base_url=OPENBAO_URL,
            headers={"X-Vault-Token": world.openbao.management_token}))
        world.host_actor = world.new_host(world.tenants, openbao_login=httpx.AsyncClient(
            transport=httpx.MockTransport(route.handle), base_url=OPENBAO_URL))
        tenant = world.active_tenant()
        gen = world.live(tenant)
        assert gen.evidence_role_id in route.role_ids, "premise: the evidence AppRole is the real server's"
        assert any(path.endswith(f"/datakey/plaintext/evidence-{tenant}") and status == 200
                   for _m, path, status in route.real_calls), "premise: install proved the evidence login on the real server"
        yield tenant, gen
    finally:
        if gen is not None:
            openbao.call("DELETE", f"auth/approle/role/{gen.evidence_approle}")
            openbao.call("DELETE", f"identity/entity/name/{gen.evidence_entity}")
        if tenant is not None:
            key = f"{TRANSIT_MOUNT}/keys/evidence-{tenant}"
            openbao.call("POST", f"{key}/config", json={"deletion_allowed": True})
            openbao.call("DELETE", key)
        world.close()


@pytest.fixture
def scene(tmp_path, monkeypatch, migrated_database, installed) -> Iterator[J.HelperScene]:  # noqa: F811
    """The helper's world for the installed tenant: its records in the helper's database, its live generation carrying the
    evidence chain exactly as the lifecycle recorded it (the sign chain is the helper scene's own)."""
    tenant, gen = installed
    with J.helper_scene(tmp_path, monkeypatch, migrated_database, tenant_id=tenant) as s:
        _record_evidence_chain(s.dsn, tenant, {c: getattr(gen, c) for c in _EVIDENCE_COLUMNS})
        yield s


_EVIDENCE_COLUMNS = ("evidence_approle", "evidence_entity", "evidence_role_id", "evidence_secret_file",
                     "evidence_wrapped_secret", "evidence_secret_accessor")


def _record_evidence_chain(dsn: str, tenant: str, values: dict[str, Any]) -> None:
    names = ", ".join(f"{c} = %s" for c in values)
    execute(dsn, f"UPDATE tenancy.generations SET {names} WHERE tenant_id = %s AND status = 'live'",  # noqa: S608 — fixed names
            (*(None if v is None else str(v) for v in values.values()), tenant))


def _deployment_login(tenant: str) -> Any:
    """What `keys_from_generation` builds from the stored records for `tenant` (the helper's own call, over the database
    `DEFENDER_DATABASE_DSN` names), checked to be at the deployment's OpenBao on the lifecycle's mount, then rebuilt with the
    same role and secret at the test server (no setting names the address: module doc)."""
    from defender.configuration.issuer import DEPLOYMENT_ISSUER
    from defender.job_host import _evidence

    login = _evidence.keys_from_generation(types.SimpleNamespace(directory=None, tenant_id=tenant))
    assert login is not None, "the helper read no evidence login from the generation the lifecycle installed"
    assert (login._addr, login._mount) == (DEPLOYMENT_ISSUER.openbao_url.rstrip("/"), "approle"), login
    return login


def _at(login: Any, addr: str) -> Any:
    from defender import evidence

    return evidence.EvidenceKeys(addr=addr, role_id=login._role_id, secret_id=login._secret_id, mount=login._mount)


# --- the helper: put, pull, another tenant's key ----------------------------------------------------------------------------

def test_the_helper_stores_in_the_named_region_under_the_generations_evidence_login_and_another_tenants_key_is_refused(
        scene, installed, openbao, evidence_keys, regional_garage):  # noqa: F811
    """No `evidence=` seam: the helper's store is `DEFENDER_EVIDENCE_*`'s, in a region not Garage's default. Its key login is
    the one the lifecycle installed (the role and secret the live generation records). An investigation's outcome and bundle
    are stored there, readable with the data key its upload row wraps; and that login, held to the shipped templated policy,
    takes no data key of another tenant's `evidence-<T>`. (cross holes 2, 4, 5; A-O5)"""
    from defender.evidence import EvidenceKeyError

    tenant, gen = installed
    login = _deployment_login(tenant)
    assert login._role_id == gen.evidence_role_id, "the helper's login is not the generation's evidence role"
    regional_garage.tenant_prefix(tenant)
    planted = plant(scene, "investigation")
    got: dict[str, Any] = {}

    def job(c) -> int:
        c.request("outcome", record=inv_outcome())
        got["bundle"] = put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, evidence_keys=_at(login, openbao.addr))
    assert got["bundle"] == {"size": len(BUNDLE), "sha256": sha(BUNDLE)}
    row = uploads(scene.dsn, scene.claim).get("bundle") or {}
    assert row.get("status") == "uploaded", f"the bundle was not stored in the deployment's store: {row}"
    key = H.object_key(tenant, "investigation", planted.owner, scene.claim, "bundle")
    stored = regional_garage.get(key, sse_key=evidence_keys.unwrap(tenant, row["wrapped_key"]))
    assert (stored.status_code, sha(stored.content)) == (200, sha(BUNDLE))
    other = str(uuid.uuid4())
    evidence_keys.make(other)
    with pytest.raises(EvidenceKeyError):
        _at(login, openbao.addr).datakey(other)
    assert _at(login, openbao.addr).datakey(tenant).wrapped, "control: the login takes its own tenant's data key"


def test_the_helper_pulls_an_accepted_input_from_the_named_region_under_the_generations_evidence_login(
        scene, installed, openbao, evidence_keys, regional_garage):  # noqa: F811
    """No `evidence=` seam: a learning job's pull of its source's accepted bundle reads it from `DEFENDER_EVIDENCE_*`'s
    regional store, unwrapping its data key with the installed evidence login. (cross holes 2, 4; A-O6)"""
    tenant, _gen = installed
    login = _deployment_login(tenant)
    store = H.Store(regional_garage, evidence_keys, openbao, tenant, {})
    planted = plant(scene, "learning")
    data = b"the source bundle, in the regional store"
    store.plant_accepted(scene, tenant, planted.source, "bundle", data)
    execute(scene.dsn, "UPDATE jobs.claims SET inputs = %s::jsonb WHERE token = %s",
            (json.dumps([{"owner": planted.source, "object": "bundle"}]), scene.claim))
    got: dict[str, Any] = {}

    def job(c) -> int:
        got["pulled"] = pull_object(c, planted.source, "bundle")
        return 0

    drive(scene, planted, job, evidence_keys=_at(login, openbao.addr))
    assert got["pulled"] == data


# --- the refused setups: no seam at all -------------------------------------------------------------------------------------

@pytest.mark.parametrize("recorded", ["sign-chain-only", "empty-secret-file"])
def test_a_generation_with_no_usable_evidence_login_is_a_refused_setup_not_a_crash(
        scene, installed, tmp_path, recorded):
    """No seam at all: a live generation that records only the sign chain (its evidence columns empty), or an evidence
    secret file that holds nothing, is `setup: refused` before any container, never a crash and never a job run under some
    other login. (cross holes 2, 2b; design: an unconfigured evidence-key login is refused at setup)"""
    tenant, _gen = installed
    if recorded == "sign-chain-only":
        _record_evidence_chain(scene.dsn, tenant, dict.fromkeys(_EVIDENCE_COLUMNS))
    else:
        empty = tmp_path / "secrets" / f"{tenant}-evidence-empty"
        empty.write_text("", encoding="utf-8")
        empty.chmod(0o600)
        _record_evidence_chain(scene.dsn, tenant, {"evidence_secret_file": empty.absolute()})
    planted = plant(scene, "investigation")
    ran = drive(scene, planted, lambda c: 0, check=False)
    assert ran.raised is None, ran.raised
    assert not ran.docker.job_ran, "a job ran with no usable evidence login"
    outcome = facts(scene.dsn, scene.claim).get("outcome") or {}
    assert outcome.get("setup") == "refused", outcome


# --- the lifecycle's own sweep wiring and pacing ----------------------------------------------------------------------------

def _lifecycle_entry_env(monkeypatch, tmp_path, data_root, dsn: str, sessions: str, garage: Garage) -> None:
    """Every setting `_serve` reads, from the environment, as `test_lifecycle_process_entry` sets them, with the store's
    the regional one (region included)."""
    from defender.lifecycle import config as settings
    from defender.tests.support.tenancy._active1214 import DSN_ENV
    from defender.tests.support.tenancy._host1214 import LIFECYCLE_MARK
    from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config, people_settings

    monkeypatch.setenv(LIFECYCLE_MARK, "")
    monkeypatch.delenv(LIFECYCLE_MARK)  # the mark `main` leaves is removed at teardown (test_lifecycle_process_entry)
    expected = lifecycle_config(tmp_path, data_root)
    for name, value in (("forge-token", expected.forge_admin_token), ("bao-login", expected.openbao_login)):
        (tmp_path / name).write_text(value + "\n", encoding="utf-8")
    for name in [k for k in os.environ if k.startswith(("DEFENDER_LIFECYCLE_", "LIFECYCLE_", EVIDENCE_ENV_PREFIX))]:
        monkeypatch.delenv(name)
    _deployment_store_env(monkeypatch, garage)
    for name, value in ((DSN_ENV, dsn), (settings.FORGE_URL_ENV, expected.forge_url),
                        (settings.FORGE_TOKEN_FILE_ENV, str(tmp_path / "forge-token")),
                        (settings.OPENBAO_LOGIN_FILE_ENV, str(tmp_path / "bao-login")),
                        (settings.INTEGRATION_ENV, expected.integration_command),
                        (settings.SECRETS_DIR_ENV, str(expected.secrets_dir)), (settings.DATA_ROOT_ENV, str(data_root)),
                        (settings.POLL_ENV, "0.02"), *people_settings(settings, sessions)):
        monkeypatch.setenv(name, value)


class _PacingWatch:
    """A profile hook over `_serve`: a round begins at the service's `work` pass (`serve` runs the actors, then the sweep);
    it records the rounds the entry's paced sweep is called in and the rounds a pass (`sweep_evidence`) runs in, ages the
    pass the sweep remembers by `aging[n]` seconds as round `n`'s sweep is called, and stops the process with SIGTERM
    (`_serve`'s own handler) as round `stop_at` begins. It replaces nothing."""

    def __init__(self, entry_file: str, service: type, pass_code: Any, aging: dict[int, float], stop_at: int) -> None:
        self.entry_file, self.service, self.pass_code = entry_file, service, pass_code
        self.aging, self.stop_at = aging, stop_at
        self.rounds = 0
        self.swept: list[int] = []
        self.passes: list[int] = []
        self.stopped = False
        self._seen: list[Any] = []  # every coroutine frame entered once, kept so no id is reused

    def _first_entry(self, frame: Any) -> bool:
        if any(f is frame for f in self._seen):
            return False  # a coroutine resumed after an await
        self._seen.append(frame)
        return True

    def __call__(self, frame: Any, event: str, _arg: Any) -> None:
        if event != "call":
            return
        code = frame.f_code
        if code is self.service.work.__code__ and isinstance(frame.f_locals.get("self"), self.service) \
                and self._first_entry(frame):  # the host's own `work` runs the same pass: not a round
            self.rounds += 1
            if self.rounds == self.stop_at and not self.stopped:
                self.stopped = True
                os.kill(os.getpid(), signal.SIGTERM)
        elif code.co_name == "sweep" and code.co_filename == self.entry_file and self._first_entry(frame):
            self.swept.append(self.rounds)
            last = frame.f_locals.get("last")
            if self.rounds in self.aging and last:
                last[0] -= self.aging[self.rounds]
        elif code is self.pass_code and self._first_entry(frame):
            self.passes.append(self.rounds)


def test_the_lifecycle_entry_sweeps_evidence_at_once_and_again_only_after_five_minutes(
        empty_database, tmp_path, data_root, monkeypatch, sessions_dsn, regional_garage):  # noqa: F811
    """`python -m defender.lifecycle serve` as built (`_serve`, every setting from the environment, the store's region
    included): its first round sweeps; a round 299 s after that pass does not; one 301 s after it does; the next does not.
    Time is aged in the pass the paced sweep remembers, by a profile hook (it replaces nothing; the clock is
    `time.monotonic`). (cross holes 3, 3b; A-O7, defender/CLAUDE.md: every five minutes)"""
    from defender.lifecycle import ManagementService
    from defender.lifecycle import __main__ as entry
    from defender.lifecycle import _evidence as retention
    from defender.migrations import upgrade

    upgrade(empty_database)
    _lifecycle_entry_env(monkeypatch, tmp_path, data_root, empty_database, sessions_dsn, regional_garage)
    # By round 2 the remembered pass is 299 s old; by round 3, 301 s.
    watch = _PacingWatch(entry.__file__, ManagementService, retention.sweep_evidence.__code__,
                         {2: SWEEP_EVERY - 1.0, 3: 2.0}, stop_at=6)
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    sys.setprofile(watch)
    try:
        code = asyncio.run(asyncio.wait_for(entry._serve(), 60))
    finally:
        sys.setprofile(None)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    assert code == 0 and watch.stopped, (code, watch.rounds, watch.swept, watch.passes)
    assert watch.swept[:5] == [1, 2, 3, 4, 5], f"the entry's serve did not call its sweep each round: {watch.swept}"
    assert watch.passes == [1, 3], f"sweep passes ran in rounds {watch.passes}; expected the first, then the one 301 s on"
