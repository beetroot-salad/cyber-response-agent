"""#1546 (design-r9 Data model, Claim: "launch facts (admission facts; knowledge pin...; alert reference)", "the
investigation's box token stays a separate launch fact"; census "Worker writes alert and launch record beside the run ->
claim row; the helper writes the job's copies"): an investigation's claim row carries, from the claim's own transaction, what
the worker's launch record and alert file carried before: the alert reference, whose stored bytes are what the job is handed
byte for byte (O6, M5), the digest of those bytes, the label (#1345 O2: the alert's stored title, else its vendor ticket id;
#1420: the title stored with the alert, not one from a later mapping) and a box token minted per claim (r5 C1: 32 lowercase
hex, never a function of the id, not the claim token). Each row's facts are its own alert's, never another job's.

Guards the retired file-write subjects of `test_worker.py` (launch files beside the run, create-only, symlinks, D-af, the
tenant lock during the write)."""
from __future__ import annotations

import hashlib
import uuid

import pytest

from defender.tests.support.evidence._facts1546 import LAUNCH_ALERT, LAUNCH_BOX_TOKEN, LAUNCH_DIGEST, LAUNCH_LABEL
from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    AWKWARD_ALERT_BYTES,
    FEFF_RICH_ALERT_BYTES,
    PADDED_ALERT_BYTES,
    T1,
    TITLE,
    an_alert,
    is_box_token,
    job_store,
    launch_facts,
    plant_queued_investigation,
    register_tenant,
    seed_alert_mapping,
)
from defender.tests.support.jobs._worker1342 import _helper_child, _committed, _worker
from defender.tests.support.jobs import _worker1342 as _shared
from defender.tests.support.tenancy._mapping1345 import mapping_value

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


async def _queue(store, dsn: str, ticket: str, raw: bytes, key: str, *, mapping: dict | None = None):
    """A queued investigation of T1 over a new alert (`raw`, `ticket`), its title derived under `mapping` when given (the
    tenant's mapping is replaced first): `(investigation id, alert)`."""
    if mapping is not None:
        seed_alert_mapping(dsn, T1, mapping)
    alert = await an_alert(store, T1, ticket=ticket, raw=raw)
    inv, _ = await store.create_investigation(T1, alert.alert_id, key, actor="u-1")
    return str(inv.investigation_id), alert


async def _expect_facts(store, dsn: str, inv: str, alert, raw: bytes, label: str, token: str | None) -> str:
    """The row's claim carries its own alert's reference, digest and label and a box token; the referenced alert row holds
    `raw` byte for byte. Returns the box token."""
    launch = launch_facts(dsn, inv)
    assert isinstance(launch, dict), f"no launch facts on {inv}'s claim: {launch!r}"
    assert launch.get(LAUNCH_ALERT) == str(alert.alert_id), launch
    assert launch.get(LAUNCH_DIGEST) == _digest(raw), "the digest is not of this row's stored alert bytes"
    assert launch.get(LAUNCH_LABEL) == label, launch
    box = launch.get(LAUNCH_BOX_TOKEN)
    assert is_box_token(box), launch
    assert token is None or box != token, "the box token is the claim token, not a launch fact of its own"
    handed = await store.get_alert(T1, alert.alert_id)
    assert handed is not None, "the alert the claim names is not in the store"
    assert handed.raw == raw, "the alert the claim names does not hold the stored bytes as given"
    return box


async def test_each_claim_row_carries_its_own_alerts_digest_label_reference_and_a_box_token_of_its_own(migrated_database):
    """Three rows over alerts that differ in every launch fact (bytes a text read or a strip would change; a mapped
    title, a title the mapping finds no value for, one unmapped; all saved before a later mapping change), claimed
    through the store: each claim row
    carries its own alert's reference, digest and label, a box token of the decided form, one per claim and not the claim's
    token; the referenced alert rows hold the bytes as given. (Claim, #1345 O2, #1420, O6, r5 C1)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        titled, titled_alert = await _queue(store, dsn, "T-1", ALERT_BYTES, "k1")
        padded, padded_alert = await _queue(store, dsn, "T-2", PADDED_ALERT_BYTES, "k2")
        untitled, untitled_alert = await _queue(store, dsn, "T-3", AWKWARD_ALERT_BYTES, "k3", mapping={})
        titles = [(await store.get_alert(T1, a.alert_id)).title for a in (titled_alert, padded_alert, untitled_alert)]
        assert titles == [TITLE, None, None], f"premise: one titled alert, two untitled: {titles}"
        # #1420: a mapping saved after the rows are queued changes no label (it would title an alert "é").
        await store.put_alert_mapping(T1, mapping_value({"title": "a"}), actor="u-1")
        claims = {}
        for _ in range(3):
            claim = await store.claim()
            assert claim is not None, "premise: three rows are queued"
            claims[str(claim.record.investigation_id)] = claim.token
        assert await store.claim() is None, "premise: nothing else was queued"
        assert set(claims) == {titled, padded, untitled}
        for inv in claims:
            assert await store.get_claim(claims[inv]) is not None, "premise: the helper's read finds the claim"
        boxes = [await _expect_facts(store, dsn, titled, titled_alert, ALERT_BYTES, TITLE, claims[titled]),
                 await _expect_facts(store, dsn, padded, padded_alert, PADDED_ALERT_BYTES, "T-2", claims[padded]),
                 await _expect_facts(store, dsn, untitled, untitled_alert, AWKWARD_ALERT_BYTES, "T-3", claims[untitled])]
    assert len(set(boxes)) == 3, f"a box token is shared between claims: {boxes}"


async def test_the_same_alert_claimed_twice_gets_the_same_alert_facts_and_two_box_tokens(migrated_database):
    """Two attempts over one alert (the first ended before the second): both claims carry that alert's reference, digest and label; each claim mints
    its own box token, never one derived from the alert or the row. (Claim, r5 C1)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1, ticket="T-9", raw=FEFF_RICH_ALERT_BYTES)
        assert (await store.get_alert(T1, alert.alert_id)).title is None, "premise: the mapping finds no title"
        tokens = []
        for n in range(2):
            inv = str(uuid.uuid4())
            plant_queued_investigation(dsn, tenant=T1, alert_id=alert.alert_id, investigation_id=inv, key=f"k{n}")
            claim = await store.claim()
            assert claim is not None, "premise: the planted row is claimed"
            assert str(claim.record.investigation_id) == inv, "premise: the claim took the planted row"
            tokens.append(await _expect_facts(store, dsn, inv, alert, FEFF_RICH_ALERT_BYTES, "T-9", claim.token))
            await store.cancel_investigation(T1, inv, actor="u-1")  # one live attempt per alert: end it before the next
    assert tokens[0] != tokens[1], "two claims of one alert share a box token"
    derived = {uuid.UUID(str(alert.alert_id)).hex, hashlib.sha256(FEFF_RICH_ALERT_BYTES).hexdigest()[:32]}
    assert not set(tokens) & derived, "the box token is derived from the alert"


async def test_a_workers_run_leaves_each_row_its_launch_facts_on_its_claim_and_none_beside_the_run(world):
    """Through the worker's own claim: two rows run to completion, each claim row carries its own alert's facts and its
    own box token, and nothing is written beside the run for either (the launch record and alert file are gone).
    (Claim; census row "Worker writes alert and launch record beside the run")"""
    dsn = world["dsn"]
    child = _helper_child(world, files=_committed())
    async with job_store(dsn) as store:
        first, first_alert = await _queue(store, dsn, "T-1", ALERT_BYTES, "k1")
        second, second_alert = await _queue(store, dsn, "T-2", AWKWARD_ALERT_BYTES, "k2", mapping={})
        await _worker(world, store, child).drain()
        boxes = [await _expect_facts(store, dsn, first, first_alert, ALERT_BYTES, TITLE, None),
                 await _expect_facts(store, dsn, second, second_alert, AWKWARD_ALERT_BYTES, "T-2", None)]
    assert child.seen(first) is not None, "premise: the first row's child ran"
    assert child.seen(second) is not None, "premise: the second row's child ran"
    assert boxes[0] != boxes[1], "two claims share a box token"
    for inv in (first, second):  # the child's own decoy records lie there too; only the worker's two files are named
        assert not (world["runs"] / f"{inv}.launch.json").exists(), "the worker wrote a launch record beside the run"
        assert not (world["runs"] / f"{inv}.alert.json").exists(), "the worker wrote an alert file beside the run"
