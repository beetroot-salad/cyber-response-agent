"""#1546 (design r8, slice SB): machinery for the per-job helper's evidence half: planted owner and claim rows, the helper
driven for every kind, the job-side verbs, the stored-object readers, and a recording S3 relay.

Interface picks (names only; design r8 fixes the content, not the spelling). Each is pinned by the tests that use it and
listed in the slice's return:
- Job socket verbs (job -> helper): `outcome(record=)`, `page(record=)`, `arms(record=)`, `arm(run_id=, record=)`,
  `progress(record=)`, `result(record=)`; `evidence.put(object=, part=, last=, data=[, sha256=])`; `evidence.pull(owner=,
  object=, part=)` answered `{data, last}`. A malformed record may be answered or refused: only what is staged is pinned.
- Staged fact bodies: `page` `{"page": rendered|render_failed|none}`; `arm/<id>` `{"scrub": ..., "page": ...}`; `arms`
  `{"roster": [{"run_id", "world_id"}]}`; a learning outcome's `findings` `{"state": "screened", "rows": {channel: rows}}`
  or `{"state": "refused", "reason": text}`; `refused/<name>` `{"reason": text}`.
- Seams of `job_host.main`: `evidence=` (`evidence.BlobStore(endpoint=, bucket=, access_key=, secret_key=, region=)`),
  `evidence_keys=` (`evidence.EvidenceKeys(addr=, role_id=, secret_id=, mount=)`), `upload_budget=` (seconds an object's PUT is
  retried; design: 120).
- Refusal codes of a pull: `out_of_claim`, `unavailable`, `store_fault`.
- Tables as the sketch spelled them: `jobs.claims`, `jobs.staged_facts`, `jobs.uploads` (see `_support` of the sketch).
- Fact and record shapes: `support/evidence/_facts1546.py` owns them (the picks are listed at its top); re-exported here as sent forms."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import random
import re
import socket
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.evidence._facts1546 import closing_found  # noqa: E402
from defender.tests.support.jobs._job_helper import (
    ContainerStandIn,
    ForgeCredentialRecorder,
    HelperScene,
    drive_helper,
    make_signer,
)
from defender.tests.support.shared._postgres1339 import execute

ROOTS, INPUTS, SPOOL, SCRATCH = ".job-roots", ".job-inputs", ".job-spool", ".job-scratch"
KINDS = ("investigation", "learning", "readiness", "adoption", "post-step", "drain")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_key(tenant: str, owner_kind: str, owner: str, claim: str, obj: str) -> str:
    """The design's key layout, spelled out (the oracle's own): `t/<tenant>/<owner kind>/<owner id>/<claim>/<object>`."""
    return f"t/{tenant}/{owner_kind}/{owner}/{claim}/{obj}"


def job_root(scene: HelperScene, claim: str | None = None) -> Path:
    return scene.root / ROOTS / (claim or scene.claim)


def job_inputs(scene: HelperScene, claim: str | None = None) -> Path:
    return scene.root / INPUTS / (claim or scene.claim)


def job_spool(scene: HelperScene, claim: str | None = None) -> Path:
    return scene.root / SPOOL / (claim or scene.claim)


# --- record shapes: one owner, `support/evidence/_facts1546.py` (sent builders: what the job puts on the socket) ----------

from defender.tests.support.evidence._facts1546 import (  # noqa: E402, F401 — re-exported: one owner of the fact bodies
    ADOPTION_RESULT,
    EPISODE_PAGE,
    KNOWLEDGE,
    READINESS_RESULT,
    RUN_PAGE,
    VALID,
    arm_page,
    inv_progress,
    learning_progress,
    sent_inv_outcome,
    sent_learning_outcome,
)

closing = closing_found
inv_outcome = sent_inv_outcome
learning_outcome = sent_learning_outcome
INV_PROGRESS = inv_progress()
LEARNING_PROGRESS = learning_progress()


# --- the new rows, by SQL -------------------------------------------------------------------------------------------------

def facts(dsn: str, token: str) -> dict[str, Any]:
    return dict(execute(dsn, "SELECT name, body FROM jobs.staged_facts WHERE token = %s", (token,)))


UPLOAD = ("token", "object", "size", "sha256", "wrapped_key", "status", "scrub", "accepted_at")


def uploads(dsn: str, token: str) -> dict[str, dict[str, Any]]:
    rows = execute(dsn, f"SELECT {', '.join(UPLOAD)} FROM jobs.uploads WHERE token = %s", (token,))  # noqa: S608
    return {r[1]: dict(zip(UPLOAD, r, strict=True)) for r in rows}


def accepted(dsn: str, token: str) -> list[str]:
    return sorted(o for o, r in uploads(dsn, token).items() if r["accepted_at"] is not None)


# --- planted owners and claims: what the worker's claim transaction leaves ------------------------------------------------

@dataclass
class Planted:
    """A running owner row of the scene's tenant claimed under `scene.claim` and its claim row. `owner` is the id the helper is
    started for; `source` (a learning job) the complete, clean investigation its input set names; `kind` the claim's kind."""

    kind: str
    owner: str
    claim: str
    source: str | None = None
    owner_table: str = ""
    owner_kind: str = ""   # the key layout's owner kind word (`investigation` / `learning`)


def _make_investigation(scene: HelperScene, tenant: str | None = None) -> tuple[str, str]:
    from defender.tests.support.jobs._jobs1342 import an_alert, job_store, register_tenant

    tenant = tenant or scene.tenant
    if tenant != scene.tenant:
        register_tenant(scene.dsn, tenant)

    async def make() -> tuple[str, str]:
        async with job_store(scene.dsn) as store:
            alert = await an_alert(store, tenant, ticket=f"T-{uuid.uuid4().hex[:6]}")
            inv, _ = await store.create_investigation(tenant, alert.alert_id, f"k-{uuid.uuid4().hex[:6]}", actor="u-1")
            return str(inv.investigation_id), str(alert.alert_id)  # plain text: the ids go into YAML/JSON documents

    return asyncio.run(make())


def another_investigation(scene: HelperScene, tenant: str | None = None, *, tainted: bool = False) -> str:
    """An ended investigation (of `tenant`): `complete` and clean, or (`tainted`) failed, `partial`, `tainted`."""
    other, _ = _make_investigation(scene, tenant)
    if tainted:
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'failed', failure_reason = 'no_report', "
                           "finished_at = now(), evidence_state = 'partial', scrub = 'tainted' WHERE id = %s", (other,))
    else:
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', "
                           "finished_at = now(), evidence_state = 'complete', scrub = 'clean' WHERE id = %s", (other,))
    return other


def plant(scene: HelperScene, kind: str, *, inputs: list[dict[str, str]] | None = None, system: str = "identity",
          claim: str | None = None) -> Planted:
    """The owner row (running, with a lease) and the claim row for `kind`, as the worker's claim transaction leaves them.
    FORCED CHOICES: the claim's `launch` for an investigation is the launch record `HelperScene.plant` writes today
    (design: "launch facts (admission facts; knowledge pin...; alert reference)"), for a learning job `{"knowledge_commit":
    <pin>}`; a post-step's hold row is `jobs.learning_checks` with `holder` = the claim token."""
    claim = claim or scene.claim
    t, dsn = scene.tenant, scene.dsn
    if kind == "investigation":
        inv, alert = _make_investigation(scene)
        launch = {"investigation_id": inv, "tenant_id": t, "alert_id": alert, "digest": _alert_digest(),
                  "label": _alert_title(), "box_token": uuid.uuid4().hex}
        execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), "
                     "lease_expires_at = now() + interval '1 hour' WHERE id = %s", (inv,))
        execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, investigation_id, launch, inputs) "
                     "VALUES (%s, %s, 'investigation', %s, %s::jsonb, '[]'::jsonb)", (claim, t, inv, json.dumps(launch)))
        return Planted(kind, inv, claim, None, "investigations", "investigation")
    if kind == "learning":
        source, alert = _make_investigation(scene)
        execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', finished_at = now(), "
                     "evidence_state = 'complete', scrub = 'clean' WHERE id = %s", (source,))
        job = str(uuid.uuid4())
        execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                     "trigger, status, created_at, started_at, lease_expires_at, sibling_cost_usd, publish_state) "
                     "VALUES (%s, %s, %s, %s, 'k-learn', 1, 'auto', 'running', now(), now(), "
                     "now() + interval '1 hour', 0, 'none')", (job, t, alert, source))
        execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, learning_job_id, launch, inputs) "
                     "VALUES (%s, %s, 'learning', %s, %s::jsonb, %s::jsonb)",
                (claim, t, job, json.dumps({"knowledge_commit": scene.t.commit}),
                 json.dumps(inputs if inputs is not None else [{"owner": source, "object": "bundle"}])))
        return Planted(kind, job, claim, source, "learning_jobs", "learning")
    if kind in ("readiness", "adoption", "drain"):
        from defender.tests.support.jobs._host_requests1471 import plant as plant_request

        rid = plant_request(dsn, t, kind if kind != "drain" else "readiness", system=system if kind == "adoption" else None,
                            stage="running")
        if kind == "drain":  # a drain is a host request of its own kind (D7); only its kind word differs from a readiness row
            execute(dsn, "UPDATE jobs.host_requests SET kind = 'drain', dedupe_key = %s WHERE id = %s", (t, rid))
        execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, host_request_id, launch, inputs) "
                     "VALUES (%s, %s, %s, %s, '{}'::jsonb, %s::jsonb)",
                (claim, t, kind, rid, json.dumps(inputs or [])))
        return Planted(kind, rid, claim)
    assert kind == "post-step", kind
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle, checking_until, holder, "
                 "armed_while_held) VALUES (%s, now(), false, now() + interval '1 hour', %s, false) ON CONFLICT (tenant_id) DO UPDATE SET "
                 "checking_until = EXCLUDED.checking_until, holder = EXCLUDED.holder", (t, claim))
    execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, hold_tenant_id, launch, inputs) "
                 "VALUES (%s, %s, 'post-step', %s, '{}'::jsonb, '[]'::jsonb)", (claim, t, t))
    return Planted(kind, t, claim)


def _alert_digest() -> str:
    from defender.tests.support.jobs._job_helper import PLANTED_DIGEST

    return PLANTED_DIGEST


def _alert_title() -> str:
    from defender.tests.support.jobs._jobs1342 import TITLE

    return TITLE


# --- driving the helper ----------------------------------------------------------------------------------------------------

def argv_for(scene: HelperScene, planted: Planted, *, system: str = "identity") -> list[str]:
    if planted.kind == "investigation":
        return scene.argv("investigation", planted.owner)
    if planted.kind == "learning":
        return scene.argv("learning", planted.owner, source=planted.source)
    if planted.kind == "adoption":
        return [*scene.argv("adoption", planted.owner), "--system", system]
    if planted.kind == "post-step":
        return scene.argv("post-step", None)
    return scene.argv(planted.kind, planted.owner)


@dataclass
class Drove:
    planted: Planted
    docker: ContainerStandIn
    rc: int | None
    raised: BaseException | None = None


def drive(scene: HelperScene, planted: Planted, job: Callable[[Any], int] | None, *, docker: ContainerStandIn | None = None,
          signer: Any = None, check: bool = True, **seams: Any) -> Drove:
    """One helper run for a planted claim over a container stand-in running `job`; the helper raised nothing, the job no
    error, and the job container ran (a vacuous run is no evidence). `check=False`: the caller reads the outcome."""
    docker = docker or ContainerStandIn(job)
    if planted.kind in ("post-step", "adoption", "drain"):
        forge = scene.forge_seams(seams.pop("forge", None))
        seams = {**forge, **seams}
    else:
        seams.setdefault("forge", ForgeCredentialRecorder())
    ran = drive_helper(scene, argv_for(scene, planted), docker=docker, signer=signer or make_signer(), **seams)
    if check:
        assert ran.raised is None, ran.raised
        assert docker.job_error is None, docker.job_error
        assert docker.job_ran, "the helper never started the job container: nothing below was observed"
    return Drove(planted, docker, ran.rc, ran.raised)


# --- the store and the keys (real Garage and OpenBao) --------------------------------------------------------------------

def evidence_module() -> Any:
    from defender import evidence  # SEAM (missing): the evidence package

    return evidence


def evidence_login(openbao: Any, tenant: str) -> dict[str, str]:
    """An AppRole for `tenant` holding the policy the lifecycle writes for it (seam: `evidence.approle_policy`)."""
    evidence = evidence_module()
    policy = openbao.apply_policy(f"evidence-{tenant[:8]}", evidence.approle_policy(tenant))
    mount = f"approle-{openbao.tag}"
    if mount not in openbao.auth_mounts:
        openbao.ok("POST", f"sys/auth/{mount}", json={"type": "approle"})
        openbao.auth_mounts.append(mount)
    role = f"evidence-{uuid.uuid4().hex[:8]}"
    openbao.ok("POST", f"auth/{mount}/role/{role}", json={"token_policies": [policy], "token_no_default_policy": True})
    role_id = openbao.ok("GET", f"auth/{mount}/role/{role}/role-id")["data"]["role_id"]
    secret = openbao.ok("POST", f"auth/{mount}/role/{role}/secret-id")["data"]["secret_id"]
    return {"role_id": role_id, "secret_id": secret, "mount": mount}


@dataclass
class Store:
    """The real evidence store for a scene's tenant: Garage (`garage`), the tenant's `evidence-<T>` key (`keys`) and the
    seams `job_host.main` takes. `garage_endpoint` is what the seam's blob store talks to (a relay's, when one is put in front)."""

    garage: Any
    keys: Any
    openbao: Any
    tenant: str
    seams: dict[str, Any]

    def blob_store(self, endpoint: str | None = None) -> Any:
        evidence = evidence_module()
        g = self.garage
        return evidence.BlobStore(endpoint=endpoint or g.endpoint, bucket=g.bucket, access_key=g.access_key,
                                  secret_key=g.secret_key, region=g.region)

    def plant_accepted(  # noqa: PLR0913 — one keyword per planted column
            self, scene: HelperScene, tenant: str, owner: str, obj: str, data: bytes, *,
                       owner_kind: str = "investigation", state: str = "complete", scrub: str = "clean",
                       key_tenant: str | None = None) -> str:
        """An accepted object of `owner` (its bytes in the bucket under a real data key of `evidence-<tenant>`, its claim and
        promoted upload rows, the owner's state and scrub); returns the claim token it lives under."""
        made = self.keys.datakey(key_tenant or tenant)
        claim = uuid.uuid4().hex
        self.garage.put(object_key(tenant, owner_kind, owner, claim, obj), data, sse_key=made.plaintext)
        self.garage.tenant_prefix(tenant)
        execute(scene.dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, investigation_id, inputs) VALUES "
                           "(%s, %s, 'investigation', %s, '[]'::jsonb)", (claim, tenant, owner))
        execute(scene.dsn, "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, created_at, "
                           "accepted_at) VALUES (%s, %s, %s, %s, %s, 'uploaded', now(), now())",
                (claim, obj, len(data), sha(data), made.wrapped))
        execute(scene.dsn, "UPDATE jobs.investigations SET evidence_state = %s, scrub = %s "
                           "WHERE id = %s", (state, scrub, owner))
        return claim

    def read(self, tenant: str, owner_kind: str, owner: str, claim: str, obj: str, wrapped: str) -> bytes:
        """The stored object read back with the data key its upload row's wrapped key unwraps to (this oracle's own read)."""
        key = self.keys.unwrap(tenant, wrapped)
        response = self.garage.get(object_key(tenant, owner_kind, owner, claim, obj), sse_key=key)
        assert response.status_code == 200, (response.status_code, response.text[:200])
        return response.content


# --- the job's side of the socket ----------------------------------------------------------------------------------------

def put_object(c: Any, obj: str, data: bytes, *, part_size: int = 1 << 20, **extra: Any) -> dict[str, Any]:
    """The job's push of one object in capped parts, in order, the last marked (throwaway framing until #1512)."""
    answer: dict[str, Any] = {}
    parts = [data[i:i + part_size] for i in range(0, len(data), part_size)] or [b""]
    for n, part in enumerate(parts):
        answer = c.request("evidence.put", object=obj, part=n, last=n == len(parts) - 1, data=part, **extra)
    return answer


def pull_object(c: Any, owner: str, obj: str) -> bytes:
    got, n = b"", 0
    while True:
        answer = c.request("evidence.pull", owner=owner, object=obj, part=n)
        got += answer["data"]
        if answer["last"]:
            return got
        n += 1


def send(c: Any, verb: str, **fields: Any) -> Any:
    """`verb` asked of the helper; its answer, or its refusal (either is a legal reaction to a bad record: only what the
    helper stages is pinned)."""
    from defender import job_host

    try:
        return c.request(verb, **fields)
    except job_host.Refused as refused:
        return refused


def spool_bytes(scene: HelperScene) -> bytes:
    """Everything in the claim's spool, concatenated (the objects' bytes wherever the helper laid them)."""
    folder = job_spool(scene)
    if not folder.is_dir():
        return b""
    return b"".join(p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file() and not p.is_symlink())


# --- malformed inputs, by construction -----------------------------------------------------------------------------------

def non_records(seed: int, n: int = 12) -> list[Any]:
    """Values that are no record of any kind: JSON scalars, arrays, objects of no known key, text and raw bytes."""
    rng = random.Random(seed)
    out: list[Any] = [None, True, False, 0, -1, 3.5, "", "outcome", [], [1, 2], {}, {"x": 1}, [{"a": []}], b"", b"{}"]
    out += [rng.randbytes(rng.randrange(1, 64)) for _ in range(n)]
    out += ["".join(chr(rng.randrange(0x20, 0x2FF)) for _ in range(rng.randrange(1, 40))) for _ in range(n // 2)]
    out += [json.dumps({"k": rng.random()}).encode() for _ in range(3)]
    return out


def deep(depth: int) -> Any:
    value: Any = 1
    for _ in range(depth):
        value = [value]
    return value


def mutants(valid: dict[str, Any], seed: int, n: int = 12) -> list[Any]:
    """Records near `valid` that no kind accepts, by construction: a key removed, an unknown key added, a field replaced by
    an object or an array (no field of any record takes one but `closing`/`findings`, which then get one of the wrong
    shape), nested too deep, or every field kept but one with a value of text longer than any field."""
    rng = random.Random(seed)
    out: list[Any] = []
    for key in valid:
        out.append({k: v for k, v in valid.items() if k != key})
        out.append({**valid, key: [rng.random()]})
        out.append({**valid, key: {"x": rng.random()}})
    out.append({**valid, "unknown_key_1546": 1})
    out.append({**valid, "inserted": {"deeper": deep(300)}})
    out.append(deep(400))
    rng.shuffle(out)
    return out[:n] if n else out


# --- a recording relay in front of the S3 endpoint ----------------------------------------------------------------------

_REQUEST_LINE = re.compile(rb"(?:^|\r\n)(PUT|POST|GET|HEAD|DELETE) (/\S*) HTTP/1\.1\r\n")


class S3Relay:
    """A TCP relay the test owns, loopback to the S3 endpoint, recording every HTTP request line (method, target) it carries.
    `before(method, target)` runs when a request line is seen (before the request is forwarded whole: it sees the rows at
    the moment of the PUT). `down()` closes every connection and refuses new ones until `up()`: a real outage the test
    chooses the moment of."""

    def __init__(self, endpoint: str, before: Callable[[str, str], None] | None = None) -> None:
        from urllib.parse import urlsplit

        parts = urlsplit(endpoint)
        self._target = (parts.hostname or "127.0.0.1", parts.port or 80)
        self.requests: list[tuple[str, str]] = []
        self._before = before
        self._lock = threading.Lock()
        self._open: list[socket.socket] = []
        self._down = threading.Event()
        self._stop = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.2)
        self.endpoint = f"http://127.0.0.1:{self._listener.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                continue
            if self._down.is_set():
                client.close()
                continue
            try:
                server = socket.create_connection(self._target)
            except OSError:
                client.close()
                continue
            with self._lock:
                self._open += [client, server]
            threading.Thread(target=self._pipe, args=(client, server, True), daemon=True).start()
            threading.Thread(target=self._pipe, args=(server, client, False), daemon=True).start()

    def _pipe(self, src: socket.socket, dst: socket.socket, upstream: bool) -> None:
        try:
            while data := src.recv(65536):
                if upstream:
                    for m in _REQUEST_LINE.finditer(data):
                        seen = (m.group(1).decode(), m.group(2).decode())
                        with self._lock:
                            self.requests.append(seen)
                        if self._before is not None:
                            self._before(*seen)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for end in (src, dst):
                with contextlib.suppress(OSError):
                    end.shutdown(socket.SHUT_RDWR)

    def puts(self, containing: str = "") -> list[str]:
        with self._lock:
            return [t for m, t in self.requests if m == "PUT" and containing in t]

    def down(self) -> None:
        self._down.set()
        with self._lock:
            for end in self._open:
                with contextlib.suppress(OSError):
                    end.close()
            self._open.clear()

    def up(self) -> None:
        self._down.clear()

    def close(self) -> None:
        self._stop.set()
        self.down()
        with contextlib.suppress(OSError):
            self._listener.close()


@contextlib.contextmanager
def s3_relay(endpoint: str, before: Callable[[str, str], None] | None = None) -> Iterator[S3Relay]:
    relay = S3Relay(endpoint, before)
    try:
        yield relay
    finally:
        relay.close()


# --- binds ----------------------------------------------------------------------------------------------------------------

def binds(box: Any) -> list[dict[str, Any]]:
    """The container's bind mounts (a tmpfs names no source)."""
    return [m for m in box.mounts if m["source"]]


def not_under(path: Path, folder: Path) -> bool:
    return not path.is_relative_to(folder) and not folder.is_relative_to(path)


def other_claim_folders(scene: HelperScene, claim: str, *, alive: bool = True) -> dict[str, Path]:
    """A second claim's root, inputs and spool folders, planted as another live helper's (an owner record naming this
    process, which is alive), each holding a file; returns them by name."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import owner_record  # noqa: F401 — imported for the signature

    made = {name: scene.root / name / claim for name in (ROOTS, INPUTS, SPOOL)}
    for folder in made.values():
        folder.mkdir(parents=True)
        (folder / "kept").write_text(claim, encoding="utf-8")
    return made


def env_flag(name: str) -> bool:
    return bool(os.environ.get(name))


@pytest.fixture
def fresh_scene(tmp_path, monkeypatch, migrated_database) -> Iterator[HelperScene]:
    """The default helper scene on a tenant of its own: the Garage bucket is shared by every file of a run, and these tests
    list a tenant's whole prefix (R13, F4)."""
    from defender.tests.support.jobs._job_helper import helper_scene

    with helper_scene(tmp_path, monkeypatch, migrated_database, tenant_id=str(uuid.uuid4())) as s:
        yield s


@pytest.fixture
def evidence_store(request: pytest.FixtureRequest, scene: HelperScene) -> Iterator[Store]:
    """The missing seam first (red here without it), then Garage and OpenBao (skipped without them), the tenant's `evidence-<T>`
    key and login, and the seams `job_host.main` takes."""
    from defender.tests.tenancy.tenant_1108_p4._support import FIXTURE_TENANT_ID

    assert scene.tenant != FIXTURE_TENANT_ID, "a scene on the shared fixture tenant lists other tests' objects: use `fresh_scene`"
    evidence_module()
    openbao = request.getfixturevalue("openbao")
    garage = request.getfixturevalue("garage")
    keys = request.getfixturevalue("evidence_keys")
    keys.make(scene.tenant)
    garage.tenant_prefix(scene.tenant)
    login = evidence_login(openbao, scene.tenant)
    store = Store(garage, keys, openbao, scene.tenant, {})
    store.seams = {"evidence": store.blob_store(),
                   "evidence_keys": evidence_module().EvidenceKeys(addr=openbao.addr, **login)}
    return store
