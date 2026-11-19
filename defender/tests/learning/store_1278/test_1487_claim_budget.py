"""#1487 Amendment r5.4: a claim takes the due items oldest first up to the store's `claim_bytes` of payload (PostgreSQL's
JSON text of each), and always at least one; the rest wait for the next claim. The default budget keeps the largest
claim under the job socket's message cap, since a post-step's claim crosses it whole. Real PostgreSQL for the claim; the
socket's own encoding for the cap."""
from __future__ import annotations

import json

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, finding
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

TENANT = fixture_uuid("tenant:1487-claim-budget")
ONE = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1}


def _publish(store, key: str, size: int) -> None:
    store.publish_findings(TENANT, "run-1", [dict(finding(key), finding="x" * size)], kind="finding")


def _sizes(dsn: str) -> dict[str, int]:
    return dict(execute(dsn, "SELECT item_key, octet_length(payload::text) FROM learning.work_items WHERE tenant_id = %s",
                        (TENANT,)))


def _claimed(store) -> tuple[list[str], list[str]]:
    held = store.claim(TENANT, AUTHOR_LANE, owner="o", thresholds=ONE)
    waiting = sorted(i.key for i in store.work(TENANT) if i.status == "waiting")
    return [key for _kind, key, _payload in held.items], waiting


@pytest.mark.postgres
def test_r54_a_claim_takes_the_oldest_items_within_its_budget_and_leaves_the_rest_waiting(migrated_database):
    """Three findings, published oldest first; a budget that holds the first two exactly: the claim takes those two,
    the newest waits. The control, one byte more than all three, takes them all. (Amendment r5.4)"""
    from defender.learning_store import blocking

    dsn = migrated_database
    register_tenant(dsn, TENANT)
    with blocking(dsn) as setup:
        for key, size in (("f1", 3000), ("f2", 2000), ("f3", 1000)):
            _publish(setup, key, size)
    sizes = _sizes(dsn)

    with blocking(dsn, claim_bytes=sizes["f1"] + sizes["f2"]) as store:
        assert _claimed(store) == (["f1", "f2"], ["f3"])

    execute(dsn, "DELETE FROM learning.work_items WHERE tenant_id = %s", (TENANT,))
    execute(dsn, "DELETE FROM learning.batches WHERE tenant_id = %s", (TENANT,))
    with blocking(dsn) as setup:
        for key, size in (("f1", 3000), ("f2", 2000), ("f3", 1000)):
            _publish(setup, key, size)
    with blocking(dsn, claim_bytes=sum(_sizes(dsn).values()) + 1) as store:
        assert _claimed(store) == (["f1", "f2", "f3"], [])


@pytest.mark.postgres
def test_r54_a_claim_takes_its_oldest_item_whatever_its_size(migrated_database):
    """A budget smaller than any item still claims the oldest one, so no item waits for good. (Amendment r5.4)"""
    from defender.learning_store import blocking

    dsn = migrated_database
    register_tenant(dsn, TENANT)
    with blocking(dsn) as setup:
        _publish(setup, "f1", 2000)
        _publish(setup, "f2", 10)
    with blocking(dsn, claim_bytes=1) as store:
        assert _claimed(store) == (["f1"], ["f2"])


def test_r54_a_claim_at_the_default_budget_crosses_the_job_socket_whatever_its_text():
    """The worst text for the socket's ASCII JSON, a four-byte character escaped as twelve bytes, filling the default
    budget in 1 MiB rows (the worker's row bound): the claim as the port encodes it is under the socket's cap. A
    control character is no worse: PostgreSQL's JSON text already counts it as its six-byte escape. (Amendment r5.4)"""
    from defender.job_socket import MAX_MESSAGE, _encode_value
    from defender.learning_store._store import DEFAULT_CLAIM_BYTES, Held
    from defender.learning_store.tick_port import HELD
    from defender.records.formats import BatchId, TenantId

    row = 1024 * 1024
    payload = {"finding_id": "j/w/0/0", "finding": "\U0001F600" * ((row - 64) // 4)}
    stored = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))  # PostgreSQL's text is no shorter
    count = DEFAULT_CLAIM_BYTES // stored
    held = Held(tenant_id=TenantId(TENANT), batch_id=BatchId.mint(), lane=AUTHOR_LANE, kind="author", branch="b",
                token=1, owner="o", items=tuple(("finding", f"j/w/0/{n}", payload) for n in range(count)))

    wire = json.dumps(_encode_value({"ok": True, "value": HELD.encode(held)}), separators=(",", ":")).encode("utf-8")

    assert count * stored > DEFAULT_CLAIM_BYTES - stored, "premise: the claim fills the budget"
    assert len(wire) <= MAX_MESSAGE, (len(wire), MAX_MESSAGE)
