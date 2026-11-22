"""#1546 sketch (r6), the helper's half through the real helper (`job_host.main`, driven by `run_kind` over a container
stand-in whose job talks to the real job socket): the outcome and the pushes (flow "Investigation end" steps 1-3;
A-O1, A-O3, A-O5, A-O8), the allowlisted binds (A-O9), and the pull gate (A-O6, PR6) for a learning job, an
investigation and a drain job. The blob store is the test Garage, the tenant key a real transit key on the test
OpenBao. Every case touches the missing `defender.evidence` seam before any service skip (fixture taken late via
`request.getfixturevalue`), so on a machine with neither service it is red at the seam, not skipped.

The helper's claim is `scene.claim` (`box.CLAIM_ENV`, as the worker hands it); the claim row and its owner row are
planted by SQL as the worker's claim transaction would leave them.
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import uuid
from pathlib import Path

import pytest

from defender.tests.evidence_1546._support import (
    RUN_PAGE,
    RawS3,
    accepted,
    arm_page,
    blob_store,
    evidence_module,
    facts,
    inv_outcome,
    job_inputs,
    job_root,
    job_spool,
    object_key,
    pack,
    sha,
    uploads,
)
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import OTHER_TENANT
from defender.tests.support.jobs._job_helper_learning import run_kind
from defender.tests.support.shared._postgres1339 import execute

process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.openbao,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

PAGE = b"<html>the renderer's page</html>"
TAMPERED = b"<html>written in the job's root</html>"


# --- the store and the keys ------------------------------------------------------------------------------------------

def _make_key(openbao, tenant: str) -> str:
    name = f"transit/keys/evidence-{tenant}"
    openbao.ok("POST", name, json={"type": "aes256-gcm96"})
    return name


def _drop_key(openbao, name: str) -> None:
    openbao.call("POST", f"{name}/config", json={"deletion_allowed": True})
    openbao.call("DELETE", name)


def evidence_login(openbao, tenant: str) -> dict[str, str]:
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


@pytest.fixture
def store_env(request, scene):
    """The missing seam first (red here without it), then Garage and OpenBao (skipped without them), the tenant's
    `evidence-<T>` key, and the helper seams `evidence=` / `evidence_keys=`.
    FORCED CHOICE: where the helper gets the per-tenant evidence AppRole's secret (beside the sign login on the
    tenant's generation record, `host_secret_file`/`sign_secret_file`?) and its name; r6 says only "created by the
    lifecycle at prepare, beside the sign AppRole"."""
    evidence = evidence_module()
    openbao = request.getfixturevalue("openbao")
    blob = blob_store()
    key = _make_key(openbao, scene.tenant)
    login = evidence_login(openbao, scene.tenant)
    yield {"openbao": openbao, "seams": {"evidence": blob, "evidence_keys": evidence.EvidenceKeys(addr=openbao.addr,
                                                                                                 **login)}}
    _drop_key(openbao, key)


def _unwrap(openbao, tenant: str, wrapped: str) -> bytes:
    body = openbao.ok("POST", f"transit/decrypt/evidence-{tenant}", json={"ciphertext": wrapped})
    return base64.b64decode(body["data"]["plaintext"])


def _put(c, obj: str, data: bytes, *, part_size: int = 1 << 20, **extra) -> dict:
    """The job's push of one object in capped parts (throwaway framing until #1512).
    FORCED CHOICE: part numbering, part size, how the last part is marked (r6: "complete, in order and matching its
    digest" but not who sends the digest: computed by the helper on receipt, so the job sends none here)."""
    answer: dict = {}
    parts = [data[i:i + part_size] for i in range(0, len(data), part_size)] or [b""]
    for n, part in enumerate(parts):
        answer = c.request("evidence.put", object=obj, part=n, last=n == len(parts) - 1, data=part, **extra)
    return answer


def _pull(c, owner: str, obj: str) -> bytes:
    got, n = b"", 0
    while True:
        answer = c.request("evidence.pull", owner=owner, object=obj, part=n)
        got += answer["data"]
        if answer["last"]:
            return got
        n += 1


# --- planted rows: the worker's claim -------------------------------------------------------------------------------

def _plant_running(scene, kind: str, *, inputs: list | None = None) -> str:
    """A running owner row of the scene's tenant claimed under `scene.claim`, and its claim row; returns its id.
    `kind`: `investigation` or `learning` (whose source is a complete investigation, returned as `.source`)."""
    from defender.tests.support.jobs._jobs1342 import an_alert, job_store

    async def make() -> tuple[str, str]:
        async with job_store(scene.dsn) as store:
            alert = await an_alert(store, scene.tenant, ticket=f"T-{uuid.uuid4().hex[:6]}")
            inv, _ = await store.create_investigation(scene.tenant, alert.alert_id, f"k-{uuid.uuid4().hex[:6]}",
                                                      actor="u-1")
            return inv.investigation_id, alert.alert_id

    inv, alert = asyncio.run(make())
    launch = {"investigation_id": inv, "tenant_id": scene.tenant, "alert_id": alert}
    if kind == "investigation":
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), "
                           "lease_expires_at = now() + interval '1 hour', claim_token = %s WHERE id = %s",
                (scene.claim, inv))
        execute(scene.dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, investigation_id, launch, inputs) "
                           "VALUES (%s, %s, 'investigation', %s, %s::jsonb, '[]'::jsonb)",
                (scene.claim, scene.tenant, inv, json.dumps(launch)))
        return inv
    execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', "
                       "finished_at = now(), evidence_state = 'complete', scrub = 'clean' WHERE id = %s", (inv,))
    job = str(uuid.uuid4())
    execute(scene.dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, "
                       "attempt, trigger, status, created_at, started_at, lease_expires_at, sibling_cost_usd, "
                       "publish_state, claim_token) VALUES (%s, %s, %s, %s, 'k-learn', 1, 'auto', 'running', now(), "
                       "now(), now() + interval '1 hour', 0, 'none', %s)",
            (job, scene.tenant, alert, inv, scene.claim))
    execute(scene.dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, learning_job_id, launch, inputs) "
                       "VALUES (%s, %s, 'learning', %s, '{}'::jsonb, %s::jsonb)",
            (scene.claim, scene.tenant, job,
             json.dumps(inputs if inputs is not None else [{"owner": inv, "object": "bundle"}])))
    _plant_running.source = inv  # type: ignore[attr-defined]
    return job


def _plant_accepted(openbao, dsn: str, tenant: str, owner_id: str, obj: str, data: bytes, *,  # noqa: PLR0913 — one keyword per planted column
                    kind: str = "investigation", evidence_state: str = "complete", scrub: str = "clean") -> None:
    """An accepted object of `owner_id`: its bytes in the bucket under a real data key of `evidence-<tenant>`, its claim
    and upload rows (promoted), and the owner's evidence state and scrub."""
    made = openbao.ok("POST", f"transit/datakey/plaintext/evidence-{tenant}", json={"bits": 256})["data"]
    claim = uuid.uuid4().hex
    RawS3().put(object_key(tenant, kind, owner_id, claim, obj), data, base64.b64decode(made["plaintext"]))
    execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, investigation_id) VALUES (%s, %s, "
                 "'investigation', %s) ON CONFLICT DO NOTHING", (claim, tenant, owner_id))
    execute(dsn, "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, created_at, accepted_at) "
                 "VALUES (%s, %s, %s, %s, %s, 'uploaded', now(), now())",
            (claim, obj, len(data), sha(data), made["ciphertext"]))
    execute(dsn, "UPDATE jobs.investigations SET evidence_state = %s, scrub = %s, claim_token = %s WHERE id = %s",
            (evidence_state, scrub, claim, owner_id))


def _another_investigation(scene, tenant: str | None = None, *, tainted: bool = False) -> str:
    from defender.tests.support.jobs._jobs1342 import an_alert, job_store, register_tenant

    tenant = tenant or scene.tenant
    if tenant != scene.tenant:
        register_tenant(scene.dsn, tenant)

    async def make() -> str:
        async with job_store(scene.dsn) as store:
            alert = await an_alert(store, tenant, ticket=f"T-{uuid.uuid4().hex[:6]}")
            inv, _ = await store.create_investigation(tenant, alert.alert_id, f"k-{uuid.uuid4().hex[:6]}", actor="u-1")
            return inv.investigation_id

    other = asyncio.run(make())
    if tainted:
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'failed', failure_reason = 'no_report', "
                           "finished_at = now(), evidence_state = 'partial', scrub = 'tainted' WHERE id = %s", (other,))
    else:
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', "
                           "finished_at = now(), evidence_state = 'complete', scrub = 'clean' WHERE id = %s", (other,))
    return other


# --- investigation: outcome, pushes, root gone -------------------------------------------------------------------------

def test_an_investigations_outcome_and_pushes_are_staged_under_its_claim_and_nothing_of_it_remains(
        scene, store_env, run_visualizations_dir):
    """The job sends its outcome, then its page and a 3 MiB bundle in parts; its root's `runtime.html` holds other
    bytes. Each put is acknowledged with size and digest. After the helper exits: the bucket holds exactly
    `t/<T>/investigation/<inv>/<claim>/{bundle,page/runtime.html}`, unreadable without a key; the upload rows are
    `uploaded` with those sizes and digests and a wrapped key that unwraps under `evidence-<T>` to the data key reading
    the bytes back; the page stored is the one sent, never the root's (A-O8); nothing is promoted (PR3); the staged
    facts are `started` and the outcome as sent; the claim's root, inputs and spool are gone (A-O1); nothing is
    mirrored to the publish folder."""
    inv = _plant_running(scene, "investigation")
    openbao = store_env["openbao"]
    bundle = bytes(range(256)) * (3 * 4096)
    got: dict = {}

    def job(c) -> int:
        root = J.host_path(c.mounts, str(job_root(scene.root, scene.claim)))
        (root / "runs" / inv).mkdir(parents=True, exist_ok=True)
        (root / "runs" / inv / "runtime.html").write_bytes(TAMPERED)
        c.request("outcome", record=inv_outcome())
        got["page"] = _put(c, RUN_PAGE, PAGE)
        got["bundle"] = _put(c, "bundle", bundle)
        return 0

    run_kind(scene, "investigation", job, job_id=inv, **store_env["seams"])
    claim = scene.claim

    assert got["page"] == {"size": len(PAGE), "sha256": sha(PAGE)}
    assert got["bundle"] == {"size": len(bundle), "sha256": sha(bundle)}
    raw = RawS3()
    assert raw.keys(f"t/{scene.tenant}/investigation/{inv}/") == sorted(
        object_key(scene.tenant, "investigation", inv, claim, o) for o in ("bundle", RUN_PAGE))
    assert raw.get(object_key(scene.tenant, "investigation", inv, claim, RUN_PAGE)) == 400, "read without its key"
    rows = uploads(scene.dsn, claim)
    assert {o: (r["status"], r["size"], r["sha256"]) for o, r in rows.items()} == {
        "bundle": ("uploaded", len(bundle), sha(bundle)), RUN_PAGE: ("uploaded", len(PAGE), sha(PAGE))}
    for obj, data in (("bundle", bundle), (RUN_PAGE, PAGE)):
        assert rows[obj]["wrapped_key"].startswith("vault:v1:")
        key = _unwrap(openbao, scene.tenant, rows[obj]["wrapped_key"])
        assert raw.get(object_key(scene.tenant, "investigation", inv, claim, obj), key) == data
    assert accepted(scene.dsn, claim) == [], "the helper promoted; only the end transaction may (PR3)"
    staged = facts(scene.dsn, claim)
    assert staged["outcome"] == inv_outcome()
    assert "started" in staged
    for folder in (job_root(scene.root, claim), job_inputs(scene.root, claim), job_spool(scene.root, claim)):
        assert not folder.exists(), f"{folder} outlived the job"
    assert list(run_visualizations_dir.rglob("*.html")) == [], "the helper mirrored a page"


def test_a_put_before_the_outcome_is_refused_and_an_investigation_has_no_inputs(scene, store_env):
    """Flow step 1: a `put` before the outcome is refused (an investigation has no `page/runs/*` exception); an
    investigation's claim names no inputs, so any pull is refused, though the tenant has accepted evidence. (A-O6)
    FORCED CHOICE: the refusal codes. r6 says a pull outside the gate gets "one refusal code" but names none, and
    nothing for the out-of-order put."""
    inv = _plant_running(scene, "investigation")
    other = _another_investigation(scene)
    _plant_accepted(store_env["openbao"], scene.dsn, scene.tenant, other, "bundle", b"some run's bundle")
    got: dict = {}

    def job(c) -> int:
        got["early"] = c.refused("evidence.put", object="bundle", part=0, last=True, data=b"x")
        got["pull"] = c.refused("evidence.pull", owner=other, object="bundle", part=0)
        return 0

    run_kind(scene, "investigation", job, job_id=inv, **store_env["seams"])
    assert got["early"].code and got["pull"].code
    assert uploads(scene.dsn, scene.claim) == {}


# --- mounts: an allowlist -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["investigation", "learning"])
def test_a_job_container_mounts_only_its_allowlist(scene, store_env, kind):
    """A-O9: the job container's binds are exactly its own root (rw, at its own path, and `DEFENDER_DATA_ROOT`), its
    `.job-inputs/<claim>/` (ro), the code tree (ro), its socket folder (rw), and for a learning job
    `.job-scratch/<claim>/shared/` (rw). No bind names the tenant folder, and none lies under another claim.
    FORCED CHOICE: the code tree's bind is today `<code dir>` read-only; r6 lists it but the readiness container reads
    "the one code tree" too; unchanged here."""
    job_id = _plant_running(scene, kind)
    seen: dict = {}

    def job(c) -> int:
        seen["mounts"], seen["env"] = list(c.mounts), dict(c.env)
        return 0

    run_kind(scene, kind, job, job_id=job_id, source=getattr(_plant_running, "source", None) if kind == "learning"
             else None, **store_env["seams"])
    claim, root = scene.claim, scene.root
    allowed = {str(job_root(root, claim)): False, str(job_inputs(root, claim)): True,
               str(root / ".job-sockets" / claim): False}
    if kind == "learning":
        allowed[str(root / ".job-scratch" / claim / "shared")] = False
    mounts = seen["mounts"]
    by_source = {m["source"]: m for m in mounts}
    for source, readonly in allowed.items():
        assert source in by_source, f"{source} is not bound: {mounts}"
        assert by_source[source]["readonly"] is readonly, by_source[source]
    assert by_source[str(job_root(root, claim))]["target"] == str(job_root(root, claim))
    assert seen["env"].get("DEFENDER_DATA_ROOT") == str(job_root(root, claim))
    others = [m for m in mounts if m["source"] not in allowed]
    assert len(others) == 1 and others[0]["readonly"], f"beyond the allowlist and the code tree: {others}"
    tenant = scene.runs.parent
    for m in mounts:
        assert not Path(m["source"]).is_relative_to(tenant), f"a bind names the tenant folder: {m}"


# --- the pull gate ------------------------------------------------------------------------------------------------------

def test_a_learning_job_pulls_only_clean_inputs_of_its_claim_with_one_refusal_code(scene, store_env):
    """The claim's input set names S's bundle and T's bundle (T tainted; planted to reach the gate's clean check).
    S, an investigation O of the same tenant, a foreign tenant's F and T each have an accepted bundle. The job's pull
    of `(S, bundle)` gets S's bytes; `(S, page)` (outside the set), `(O, bundle)` (outside the claim), `(F, bundle)`
    (another tenant) and `(T, bundle)` (not `clean`) are each refused with the one same code. (A-O6, PR6, "Done when")
    FORCED CHOICE: the input set's form (`[{owner, object}]` here) and whether a learning job's set is only the
    source's `bundle` or every accepted object of it."""
    openbao = store_env["openbao"]
    other_key = _make_key(openbao, OTHER_TENANT)
    try:
        decoy, tainted = _another_investigation(scene), _another_investigation(scene, tainted=True)
        foreign = _another_investigation(scene, OTHER_TENANT)
        job_id = _plant_running(scene, "learning", inputs=None)
        source = _plant_running.source  # type: ignore[attr-defined]
        execute(scene.dsn, "UPDATE jobs.claims SET inputs = %s::jsonb WHERE token = %s",
                (json.dumps([{"owner": source, "object": "bundle"},
                                           {"owner": tainted, "object": "bundle"}]), scene.claim))
        _plant_accepted(openbao, scene.dsn, scene.tenant, source, "bundle", pack({"runs/x/a.txt": b"the source"}))
        _plant_accepted(openbao, scene.dsn, scene.tenant, decoy, "bundle", b"another owner's bundle")
        _plant_accepted(openbao, scene.dsn, OTHER_TENANT, foreign, "bundle", b"another tenant's bundle")
        _plant_accepted(openbao, scene.dsn, scene.tenant, tainted, "bundle", b"tainted", evidence_state="partial",
                        scrub="tainted")
        got: dict = {}

        def job(c) -> int:
            got["own"] = _pull(c, source, "bundle")
            got["refused"] = [c.refused("evidence.pull", owner=o, object=obj, part=0) for o, obj in
                              ((source, RUN_PAGE), (decoy, "bundle"), (foreign, "bundle"), (tainted, "bundle"))]
            return 0

        run_kind(scene, "learning", job, job_id=job_id, source=decoy, **store_env["seams"])
    finally:
        _drop_key(openbao, other_key)

    assert got["own"] == pack({"runs/x/a.txt": b"the source"})
    codes = {r.code for r in got["refused"]}
    assert len(codes) == 1 and next(iter(codes)), got["refused"]


def test_a_drain_job_pulls_only_runs_named_by_a_batch_it_was_issued(scene, store_env):
    """Lead-author drain job: a pull is allowed when its run is named by a batch the helper issued this session through
    the port. A curation request naming run R is due; the job claims a lead-lane batch (`store.claim`), then pulls
    `(R, bundle)` (allowed) and `(Q, bundle)` (refused), Q accepted and clean but named by no batch.
    FORCED CHOICES: (1) how a batch "names" a run (an item's `source_run`? the curation request's payload?);
    (2) how the drain is queued (r6: "an operator command as a claim under the tenant's learning-check hold"), since a
    claim row exists only once launched, what holds a queued drain before a worker launches it, and the helper kind's
    argv word (`drain` here); (3) whether the drain's pull also requires `clean` when R's evidence is tainted (PR6 says
    yes; r6's drain paragraph only says an expired R ends as `RunAbsent`)."""
    from defender.tests.support.learning.core import _store1278 as LS

    openbao = store_env["openbao"]
    named, unnamed = _another_investigation(scene), _another_investigation(scene)
    for owner_id in (named, unnamed):
        _plant_accepted(openbao, scene.dsn, scene.tenant, owner_id, "bundle", f"bundle of {owner_id}".encode())

    async def due() -> None:
        async with LS.learning_store(scene.dsn) as store:
            await LS.publish(store, scene.tenant, "c1", kind="curation_request", run=named)

    asyncio.run(due())
    execute(scene.dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, hold_tenant_id) VALUES (%s, %s, 'drain', %s)",
            (scene.claim, scene.tenant, scene.tenant))
    got: dict = {}

    def job(c) -> int:
        got["batch"] = c.request("store.claim")
        got["named"] = _pull(c, named, "bundle")
        got["unnamed"] = c.refused("evidence.pull", owner=unnamed, object="bundle", part=0)
        return 0

    from defender.tests.support.jobs._job_helper import drive_helper

    docker = J.ContainerStandIn(job)
    ran = drive_helper(scene, scene.argv("drain", None), docker=docker, signer=J.make_signer(),
                       **{**scene.forge_seams(), **store_env["seams"]})
    assert ran.raised is None and docker.job_error is None, (ran.raised, docker.job_error)
    assert got["batch"] is not None
    assert got["named"] == f"bundle of {named}".encode()
    assert got["unnamed"].code


def test_an_arm_page_put_before_the_outcome_is_accepted_only_for_a_roster_arm(scene, store_env):
    """Flow "Learning job": the job stages `arms` before the first arm runs; an arm's page `page/runs/<id>/runtime.html`
    may be put before the outcome, with its `scrub`, only for a run id on the roster; another id is refused. The upload
    row carries the arm's verdict. (D3, A-O10)"""
    job_id = _plant_running(scene, "learning")
    arm, stranger, world_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    got: dict = {}

    def job(c) -> int:
        c.request("arms", roster=[{"run_id": arm, "world_id": world_id}])
        got["arm"] = _put(c, arm_page(arm), PAGE, scrub="tainted")
        got["stranger"] = c.refused("evidence.put", object=arm_page(stranger), part=0, last=True, data=PAGE,
                                    scrub="clean")
        return 0

    run_kind(scene, "learning", job, job_id=job_id, source=_plant_running.source,  # type: ignore[attr-defined]
             **store_env["seams"])
    rows = uploads(scene.dsn, scene.claim)
    assert (rows[arm_page(arm)]["status"], rows[arm_page(arm)]["scrub"]) == ("uploaded", "tainted")
    assert arm_page(stranger) not in rows
    assert got["stranger"].code
    assert facts(scene.dsn, scene.claim)["arms"] == {"roster": [{"run_id": arm, "world_id": world_id}]}
