"""#1546 (design r8) the helper's evidence half against the real Garage and OpenBao: streamed parts, one PUT per object under a
fresh data key wrapped by the tenant's key, the upload rows, retries, the pull gate (`out_of_claim` / `unavailable` /
store faults), the digest check on every read, pages as the renderer's bytes, and the forged receipt. The folders, binds and
JobTenant halves are in `test_1546_helper_folders.py`."""
from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from defender.job_host import Refused
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._helper_evidence1546 import (
    EPISODE_PAGE,
    RUN_PAGE,
    accepted,
    another_investigation,
    drive,
    facts,
    inv_outcome,
    job_inputs,
    job_root,
    job_spool,
    learning_outcome,
    object_key,
    plant,
    pull_object,
    put_object,
    s3_relay,
    send,
    sha,
    spool_bytes,
    uploads,
)
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute

evidence_store = H.evidence_store
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.openbao, pytest.mark.garage,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

PAGE = b"<html>the renderer's page</html>"
TAMPERED = b"<html>written in the job's root</html>"
BUNDLE = bytes(range(256)) * (3 * 4096)  # 3 MiB: three parts of 1 MiB


def _key(scene, planted, obj, claim=None):
    return object_key(scene.tenant, planted.owner_kind, planted.owner, claim or planted.claim, obj)


# --- the investigation's pushes: layout, keys, rows, the page's bytes, A-O1 -------------------------------------------------

def test_an_investigations_pushes_are_stored_under_its_claim_wrapped_by_the_tenants_key_and_nothing_of_it_remains(
        scene, evidence_store):
    """Outcome, page (the bytes the job sent, not the root's file) and a 3 MiB bundle in parts: each put answered with size
    and digest; the bucket holds exactly `t/<T>/investigation/<inv>/<claim>/{bundle,page/runtime.html}` unreadable without
    a key; rows `uploaded` with size, digest and a wrapped key of `evidence-<T>`; a different data key per object; another
    tenant's key cannot unwrap; nothing promoted; root, inputs and spool existed during and are gone after. (A-O1, A-O3, A-O5, A-O8, PR3)"""
    planted = plant(scene, "investigation")
    got: dict = {}

    def job(c) -> int:
        root = J.host_path(c.mounts, str(job_root(scene) / scene.tenant))
        (root / "runs" / planted.owner).mkdir(parents=True, exist_ok=True)
        (root / "runs" / planted.owner / "runtime.html").write_bytes(TAMPERED)
        got["during"] = [p.is_dir() for p in (job_root(scene), job_inputs(scene), job_spool(scene))]
        c.request("outcome", record=inv_outcome())
        c.request("page", record={"page": "rendered"})
        got["page"] = put_object(c, RUN_PAGE, PAGE)
        got["bundle"] = put_object(c, "bundle", BUNDLE)
        got["spool"] = spool_bytes(scene)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert got["during"] == [True, True, True]
    assert PAGE in got["spool"], "control: the spool held the object while the job ran"
    assert got["page"] == {"size": len(PAGE), "sha256": sha(PAGE)}
    assert got["bundle"] == {"size": len(BUNDLE), "sha256": sha(BUNDLE)}
    bucket = evidence_store.garage
    assert bucket.list(f"t/{scene.tenant}/") == sorted(_key(scene, planted, o) for o in ("bundle", RUN_PAGE))
    assert bucket.get(_key(scene, planted, RUN_PAGE)).status_code == 400, "readable without its key"
    rows = uploads(scene.dsn, scene.claim)
    assert {o: (r["status"], r["size"], r["sha256"]) for o, r in rows.items()} == {
        "bundle": ("uploaded", len(BUNDLE), sha(BUNDLE)), RUN_PAGE: ("uploaded", len(PAGE), sha(PAGE))}
    for obj, data in (("bundle", BUNDLE), (RUN_PAGE, PAGE)):
        assert evidence_store.read(scene.tenant, "investigation", planted.owner, scene.claim, obj,
                                   rows[obj]["wrapped_key"]) == data
    keys = {evidence_store.keys.unwrap(scene.tenant, r["wrapped_key"]) for r in rows.values()}
    assert len(keys) == 2, "one data key served two objects"
    other = str(uuid.uuid4())
    evidence_store.keys.make(other)
    for r in rows.values():
        try:
            leaked = evidence_store.keys.unwrap(other, r["wrapped_key"])
        except Exception:  # noqa: BLE001 — the other tenant's key refusing is the point
            leaked = None
        assert leaked is None, "another tenant's key unwrapped this tenant's data key"
    assert accepted(scene.dsn, scene.claim) == [], "the helper promoted; only the applier may (PR3)"
    for folder in (job_root(scene), job_inputs(scene), job_spool(scene)):
        assert not folder.exists(), f"{folder} outlived the job"


def test_an_arm_pages_stored_bytes_are_the_ones_the_job_pushed_not_the_arm_folders(scene, evidence_store):
    """A learning job's arm page and episode page are the pushed bytes even when the arm's folder in the root holds another
    `runtime.html`; the arm page's upload row copies its arm fact's `scrub`. (A-O8, A-O10)"""
    planted = plant(scene, "learning")
    arm, world = str(uuid.uuid4()), str(uuid.uuid4())

    def job(c) -> int:
        root = J.host_path(c.mounts, str(job_root(scene) / scene.tenant))
        folder = root / "episodes" / planted.owner / "runs" / arm
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "runtime.html").write_bytes(TAMPERED)
        c.request("arms", record={"roster": [{"run_id": arm, "world_id": world}]})
        c.request("arm", run_id=arm, record={"scrub": "tainted", "page": "rendered"})
        put_object(c, H.arm_page(arm), PAGE)
        c.request("outcome", record=learning_outcome())
        put_object(c, EPISODE_PAGE, b"episode page")
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    rows = uploads(scene.dsn, scene.claim)
    assert rows[H.arm_page(arm)]["scrub"] == "tainted"
    assert evidence_store.read(scene.tenant, "learning", planted.owner, scene.claim, H.arm_page(arm),
                               rows[H.arm_page(arm)]["wrapped_key"]) == PAGE


# --- streamed parts: complete, in order, matching its digest ----------------------------------------------------------------

def _part(c, obj, n, last, data, **extra):
    return send(c, "evidence.put", object=obj, part=n, last=last, data=data, **extra)


@pytest.mark.parametrize("fault", ["gap", "repeat", "no-last-part", "digest-mismatch", "out-of-order"])
def test_an_object_streamed_with_a_gap_a_repeat_no_end_or_a_wrong_digest_is_refused_and_its_spool_removed(
        scene, evidence_store, fault):
    """A part sequence that skips a part, repeats one, arrives out of order, never marks its last part, or ends with a digest
    that is not the bytes' refuses that object: no `uploaded` row, none of its bytes left in the spool, nothing in the bucket;
    an object streamed correctly beside it (control) is uploaded. (PR2, flow step 2)"""
    planted = plant(scene, "investigation")
    marker = (b"MARKER-1546-" + fault.encode()) * 40
    chunks = [marker[:100], marker[100:200], marker[200:]]
    got: dict = {}

    def job(c) -> int:
        send(c, "outcome", record=inv_outcome())
        if fault == "gap":
            _part(c, "bundle", 0, False, chunks[0])
            _part(c, "bundle", 2, True, chunks[2])
        elif fault == "repeat":
            _part(c, "bundle", 0, False, chunks[0])
            _part(c, "bundle", 0, False, chunks[0])
            _part(c, "bundle", 1, True, chunks[1])
        elif fault == "out-of-order":
            _part(c, "bundle", 1, False, chunks[1])
            _part(c, "bundle", 0, True, chunks[0])
        elif fault == "no-last-part":
            _part(c, "bundle", 0, False, chunks[0])
            _part(c, "bundle", 1, False, chunks[1])
        else:
            for n, chunk in enumerate(chunks):
                _part(c, "bundle", n, n == 2, chunk, **({"sha256": sha(b"other")} if n == 2 else {}))
        got["spool"] = spool_bytes(scene)
        send(c, "page", record={"page": "rendered"})
        put_object(c, RUN_PAGE, PAGE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    rows = uploads(scene.dsn, scene.claim)
    assert rows.get("bundle", {}).get("status") != "uploaded"
    assert rows[RUN_PAGE]["status"] == "uploaded", "control: a correct object beside it was uploaded"
    assert marker[:60] not in got["spool"], "the refused object's bytes stayed in the spool"
    assert evidence_store.garage.list(f"t/{scene.tenant}/") == [_key(scene, planted, RUN_PAGE)]


def test_a_correct_digest_on_the_last_part_is_accepted(scene, evidence_store):
    """The positive control of the digest check: the same stream with the bytes' own digest is uploaded. (PR2)"""
    planted = plant(scene, "investigation")

    def job(c) -> int:
        send(c, "outcome", record=inv_outcome())
        put_object(c, "bundle", BUNDLE, sha256=sha(BUNDLE))
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert uploads(scene.dsn, scene.claim)["bundle"]["status"] == "uploaded"


# --- one PUT per object, rows pending before it, retries ---------------------------------------------------------------------

def test_each_object_is_put_once_with_its_row_pending_first_and_never_by_multipart(scene, evidence_store):
    """Through a recording relay in front of Garage: each stored object is one `PUT` of its key (no multipart `POST`, no
    `uploadId`), and when the PUT arrives the object's row already exists, `pending`; after, `uploaded`. (A-O3, flow step 3)"""
    planted = plant(scene, "investigation")
    pending_at_put: dict[str, str | None] = {}

    def before(method: str, target: str) -> None:
        if method == "PUT":
            obj = target.split(f"/{scene.claim}/", 1)[-1].split("?")[0]
            pending_at_put[obj] = (uploads(scene.dsn, scene.claim).get(obj) or {}).get("status")

    with s3_relay(evidence_store.garage.endpoint, before) as relay:
        seams = {**evidence_store.seams, "evidence": evidence_store.blob_store(relay.endpoint)}

        def job(c) -> int:
            send(c, "outcome", record=inv_outcome())
            send(c, "page", record={"page": "rendered"})
            put_object(c, RUN_PAGE, PAGE)
            put_object(c, "bundle", BUNDLE)
            return 0

        drive(scene, planted, job, **seams)
        puts = relay.puts(f"/{scene.claim}/")
        posts = [t for m, t in relay.requests if m == "POST" and scene.claim in t]
    assert sorted(t.split("?")[0].split(f"/{scene.claim}/")[1] for t in puts) == ["bundle", RUN_PAGE], puts
    assert posts == [], "a multipart upload was started"
    assert all("uploadId" not in t and "partNumber" not in t for t in puts)
    assert pending_at_put == {"bundle": "pending", RUN_PAGE: "pending"}
    assert {o: r["status"] for o, r in uploads(scene.dsn, scene.claim).items()} == {"bundle": "uploaded",
                                                                                      RUN_PAGE: "uploaded"}


def test_a_store_outage_shorter_than_the_budget_is_retried_and_the_object_still_uploaded(scene, evidence_store):
    """The store drops the first PUT's connection and returns three seconds later: the helper retries within its budget and
    the row ends `uploaded` with the bytes readable; the PUT was seen at least twice. (flow step 3)"""
    planted = plant(scene, "investigation")
    fired = threading.Event()
    box: dict = {}

    def before(method: str, _target: str) -> None:
        if method == "PUT" and not fired.is_set():
            fired.set()
            box["relay"].down()
            threading.Timer(3.0, box["relay"].up).start()

    with s3_relay(evidence_store.garage.endpoint, before) as relay:
        box["relay"] = relay
        seams = {**evidence_store.seams, "evidence": evidence_store.blob_store(relay.endpoint)}

        def job(c) -> int:
            send(c, "outcome", record=inv_outcome())
            put_object(c, "bundle", BUNDLE)
            return 0

        drive(scene, planted, job, **seams)
        puts = relay.puts("/bundle")
    row = uploads(scene.dsn, scene.claim)["bundle"]
    assert row["status"] == "uploaded"
    assert len(puts) >= 2, puts
    assert evidence_store.read(scene.tenant, "investigation", planted.owner, scene.claim, "bundle",
                               row["wrapped_key"]) == BUNDLE


def test_a_store_that_stays_down_past_the_budget_refuses_the_object_and_the_helper_ends(scene, evidence_store):
    """With the store down for good and a 4 s budget (the `upload_budget=` seam; the design's value is 120 s), the object's row
    ends `refused` (never `pending` or `uploaded`) and the helper exits within seconds of the budget. (flow step 3)"""
    planted = plant(scene, "investigation")
    with s3_relay(evidence_store.garage.endpoint) as relay:
        relay.down()
        seams = {**evidence_store.seams, "evidence": evidence_store.blob_store(relay.endpoint), "upload_budget": 4.0}

        def job(c) -> int:
            send(c, "outcome", record=inv_outcome())
            put_object(c, "bundle", BUNDLE)
            return 0

        started = time.monotonic()
        drive(scene, planted, job, **seams)
        took = time.monotonic() - started
    assert uploads(scene.dsn, scene.claim)["bundle"]["status"] == "refused"
    assert took < 60, took


# --- setup: an unconfigured store or key login is refused, terminally ---------------------------------------------------------

@pytest.mark.parametrize("missing", ["store", "key-login", "both"])
def test_an_unconfigured_store_or_evidence_login_refuses_the_job_at_setup_and_starts_no_container(scene, evidence_store,
                                                                                                   missing):
    """With no blob store, no evidence-key login, or neither (no seam, and the scene's settings name none), the helper stages
    an outcome with `setup = refused`, starts no container and stores nothing. The positive control is every other test of
    this file (the same run with both configured). (design: flow, last line)"""
    seams = {k: v for k, v in evidence_store.seams.items()
             if not (missing in ("both", "store") and k == "evidence")
             and not (missing in ("both", "key-login") and k == "evidence_keys")}
    planted = plant(scene, "investigation")
    ran = drive(scene, planted, lambda c: 0, check=False, **seams)
    assert ran.raised is None
    assert not ran.docker.creates(), "a container was started with the store unconfigured"
    assert not ran.docker.job_ran
    assert facts(scene.dsn, scene.claim)["outcome"]["setup"] == "refused"
    assert evidence_store.garage.list(f"t/{scene.tenant}/") == []


# --- the pull gate ------------------------------------------------------------------------------------------------------------

def _learning_with_inputs(scene, store, *, extra_inputs=()):
    planted = plant(scene, "learning")
    source = planted.source
    data = b"the source bundle"
    store.plant_accepted(scene, scene.tenant, source, "bundle", data)
    inputs = [{"owner": source, "object": "bundle"}, *extra_inputs]
    execute(scene.dsn, "UPDATE jobs.claims SET inputs = %s::jsonb WHERE token = %s", (json.dumps(inputs),
                                                                                       scene.claim))
    return planted, data


def test_a_learning_job_pulls_its_input_and_everything_else_is_out_of_claim_with_one_code(scene, evidence_store):
    """The set names the source's bundle: it is pulled whole. Another object of the source, another owner of the tenant, a
    foreign tenant's object and an owner that does not exist are each refused `out_of_claim`, the same code for each (no
    existence oracle). (A-O6, "Done when": cross-tenant, out-of-claim)"""
    store = evidence_store
    planted, data = _learning_with_inputs(scene, store)
    decoy = another_investigation(scene)
    store.plant_accepted(scene, scene.tenant, decoy, "bundle", b"another owner's bundle")
    foreign_tenant = J.OTHER_TENANT
    store.keys.make(foreign_tenant)
    foreign = another_investigation(scene, foreign_tenant)
    store.plant_accepted(scene, foreign_tenant, foreign, "bundle", b"another tenant's bundle")
    got: dict = {}

    def job(c) -> int:
        got["own"] = pull_object(c, planted.source, "bundle")
        asks = [(planted.source, RUN_PAGE), (decoy, "bundle"), (foreign, "bundle"), (str(uuid.uuid4()), "bundle")]
        got["refused"] = [c.refused("evidence.pull", owner=o, object=obj, part=0).code for o, obj in asks]
        return 0

    drive(scene, planted, job, **store.seams)
    assert got["own"] == data
    assert got["refused"] == ["out_of_claim"] * 4


@pytest.mark.parametrize("why", ["tainted", "expired", "offboarded"])
def test_a_pull_of_a_set_member_that_is_unusable_is_unavailable_never_its_bytes(scene, evidence_store, why):
    """A set member whose owner is tainted, whose evidence expired, or whose objects and rows an offboarding removed is
    refused `unavailable` (not `out_of_claim`): PR6, A-O6. (The exact offboarded signal is a design gap: rows gone, claim kept.)"""
    store = evidence_store
    planted, _ = _learning_with_inputs(scene, store)
    source = planted.source
    if why == "tainted":
        execute(scene.dsn, "UPDATE jobs.investigations SET stage = 'failed', failure_reason = 'no_report', "
                           "evidence_state = 'partial', scrub = 'tainted' WHERE id = %s", (source,))
    else:
        execute(scene.dsn, "DELETE FROM jobs.uploads WHERE token IN (SELECT claim_token FROM jobs.investigations "
                           "WHERE id = %s)", (source,))
        execute(scene.dsn, "UPDATE jobs.investigations SET evidence_state = %s WHERE id = %s",
                ("expired" if why == "expired" else "none", source))
    got: dict = {}
    drive(scene, planted, lambda c: got.update(code=c.refused("evidence.pull", owner=source, object="bundle", part=0).code)
          or 0, **store.seams)
    assert got["code"] == "unavailable"


def test_an_accepted_object_that_is_missing_or_does_not_match_its_digest_is_a_store_fault_never_wrong_bytes(scene,
                                                                                                           evidence_store):
    """Every read checks the recorded digest: a pull of an object whose stored bytes were replaced (under the same data key)
    is refused `store_fault`, and so is one whose object was deleted; neither answers bytes, and neither is `out_of_claim` or
    `unavailable`. The untouched pull is the control. (A-O3, A-O6)"""
    store = evidence_store
    planted, data = _learning_with_inputs(scene, store)
    other = another_investigation(scene)
    store.plant_accepted(scene, scene.tenant, other, "bundle", b"the untouched bundle")
    gone = another_investigation(scene)
    gone_claim = store.plant_accepted(scene, scene.tenant, gone, "bundle", b"a bundle later deleted")
    [(tampered_claim,)] = execute(scene.dsn, "SELECT claim_token FROM jobs.investigations WHERE id = %s",
                                  (planted.source,))
    wrapped = uploads(scene.dsn, tampered_claim)["bundle"]["wrapped_key"]
    store.garage.put(object_key(scene.tenant, "investigation", planted.source, tampered_claim, "bundle"),
                     b"X" * len(data), sse_key=store.keys.unwrap(scene.tenant, wrapped))
    store.garage.delete(object_key(scene.tenant, "investigation", gone, gone_claim, "bundle"))
    execute(scene.dsn, "UPDATE jobs.claims SET inputs = %s::jsonb WHERE token = %s", (
        json.dumps([{"owner": o, "object": "bundle"} for o in (planted.source, other, gone)]), scene.claim))
    got: dict = {}

    def job(c) -> int:
        got["control"] = pull_object(c, other, "bundle")
        got["tampered"] = c.refused("evidence.pull", owner=planted.source, object="bundle", part=0)
        got["missing"] = c.refused("evidence.pull", owner=gone, object="bundle", part=0)
        return 0

    drive(scene, planted, job, **store.seams)
    assert got["control"] == b"the untouched bundle"
    assert got["tampered"].code == "store_fault"
    assert got["missing"].code == "store_fault"


@pytest.mark.parametrize("kind", ["investigation", "post-step"])
def test_a_job_with_an_empty_input_set_has_every_pull_refused(scene, evidence_store, kind):
    """An investigation and a post-step claim name no inputs: a pull of a clean, accepted object of the same tenant is
    refused (`out_of_claim` for the investigation). (A-O6)"""
    store = evidence_store
    other = another_investigation(scene)
    store.plant_accepted(scene, scene.tenant, other, "bundle", b"some run's bundle")
    planted = plant(scene, kind)
    got: dict = {}
    seams = store.seams if kind == "investigation" else {}
    drive(scene, planted, lambda c: got.update(refusal=c.refused("evidence.pull", owner=other, object="bundle", part=0)) or 0,
          **seams)
    assert got["refusal"].code
    if kind == "investigation":
        assert got["refusal"].code == "out_of_claim"
    assert uploads(scene.dsn, scene.claim) == {}


# --- the forged receipt ------------------------------------------------------------------------------------------------------------

def test_a_job_that_claims_an_upload_it_did_not_make_or_another_claims_object_changes_nothing(scene, evidence_store):
    """A job forges what it can: files in its root that look like outcomes and receipts, an outcome naming uploads, a `page`
    fact `rendered` it never pushed, `put`s addressed to another claim's object (by key path, `..`, an unknown name), and a
    pull of another claim's object. Afterwards: the only upload row is its own legitimate bundle, the other claim's stored
    bytes and rows are unchanged, no forged outcome is staged, and no object lies outside this claim's prefix. ("Done when": forged receipt)"""
    store = evidence_store
    other = another_investigation(scene)
    other_claim = store.plant_accepted(scene, scene.tenant, other, "bundle", b"another claim's accepted bundle")
    other_key = object_key(scene.tenant, "investigation", other, other_claim, "bundle")
    before_rows = uploads(scene.dsn, other_claim)
    planted = plant(scene, "investigation")
    forged = [f"t/{scene.tenant}/investigation/{other}/{other_claim}/bundle", f"../{other_claim}/bundle",
              "bundle/../../x", "receipt", "page/../bundle", ""]
    got: dict = {}

    def job(c) -> int:
        root = J.host_path(c.mounts, str(job_root(scene) / scene.tenant))
        (root / "runs").mkdir(parents=True, exist_ok=True)
        for name in (f"{planted.owner}.job-end.json", f"{planted.owner}.receipt.json", "receipt"):
            (root / "runs" / name).write_text('{"uploaded": ["bundle"], "outcome": "forged"}', encoding="utf-8")
        send(c, "outcome", record={**inv_outcome(), "uploads": [{"object": "bundle", "status": "uploaded"}]})
        send(c, "page", record={"page": "rendered"})
        got["forged"] = [send(c, "evidence.put", object=name, part=0, last=True, data=b"forged") for name in forged]
        got["pull"] = c.refused("evidence.pull", owner=other, object="bundle", part=0).code
        put_object(c, "bundle", b"my own bundle")
        return 0

    drive(scene, planted, job, **store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert "outcome" not in staged, "a forged outcome was staged"
    assert "refused/outcome" in staged
    assert all(isinstance(r, Refused) for r in got["forged"])
    assert got["pull"] == "out_of_claim"
    rows = uploads(scene.dsn, scene.claim)
    assert set(rows) == {"bundle"}, f"an upload row exists that the helper did not make from a legitimate put: {sorted(rows)}"
    assert rows["bundle"]["sha256"] == sha(b"my own bundle")
    assert uploads(scene.dsn, other_claim) == before_rows
    assert store.garage.get(other_key, sse_key=store.keys.unwrap(scene.tenant, before_rows["bundle"]["wrapped_key"])
                            ).content == b"another claim's accepted bundle"
    mine = {k for k in store.garage.list(f"t/{scene.tenant}/") if scene.claim in k}
    assert mine == {_key(scene, planted, "bundle")}
    assert Path(job_root(scene)).exists() is False
