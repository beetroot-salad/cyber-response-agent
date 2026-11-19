"""#1487 Amendment r5.4: a claim takes the due items oldest first while their size on the job socket stays within the
store's `claim_bytes`, and always at least one; the rest wait for the next claim. The size is what a post-step's claim
answer carries over the socket, so the default keeps the largest claim under the socket's message cap. Real PostgreSQL
for the claim; the port's and the socket's own encoding for the size."""
from __future__ import annotations

import json
import random
import time

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, finding
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

TENANT = fixture_uuid("tenant:1487-claim-budget")
ONE = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1}


def _publish(store, key: str, text: str) -> None:
    store.publish_findings(TENANT, "run-1", [dict(finding(key), finding=text)], kind="finding")


def _reset(dsn: str) -> None:
    execute(dsn, "DELETE FROM learning.work_items WHERE tenant_id = %s", (TENANT,))
    execute(dsn, "DELETE FROM learning.batches WHERE tenant_id = %s", (TENANT,))


def _claimed(store) -> tuple[list[str], list[str]]:
    held = store.claim(TENANT, AUTHOR_LANE, owner="o", thresholds=ONE)
    waiting = sorted(i.key for i in store.work(TENANT) if i.status == "waiting")
    return [key for _kind, key, _payload in held.items], waiting


def _wire(held) -> bytes:
    """The claim answer as the helper writes it to the job socket."""
    from defender.job_socket import _encode_value
    from defender.learning_store.tick_port import HELD

    return json.dumps(_encode_value({"ok": True, "value": HELD.encode(held)}), separators=(",", ":")).encode("utf-8")


def _sizes(dsn: str) -> dict[str, int]:
    """Each waiting item's size as the claim counts it, from the store's declared bound."""
    from defender.learning_store._store import CLAIM_KEY_RATIO, CLAIM_PAYLOAD_RATIO, CLAIM_ROW_FRAMING

    times, per = CLAIM_PAYLOAD_RATIO
    rows = execute(dsn, "SELECT item_key, octet_length(payload::text), octet_length(item_key), octet_length(kind) "
                        "FROM learning.work_items WHERE tenant_id = %s", (TENANT,))
    return {key: -(-p * times // per) + k * CLAIM_KEY_RATIO + n + CLAIM_ROW_FRAMING for key, p, k, n in rows}


@pytest.mark.postgres
def test_r54_a_claim_takes_the_oldest_items_within_its_budget_and_leaves_the_rest_waiting(migrated_database):
    """Three findings published in an order that is neither their keys' nor their sizes': `c` (smallest), then `a`
    (largest), then `b`. A budget that holds the first two published exactly takes `c` and `a`; `b` waits. The control,
    one byte more than all three, takes them all. (Amendment r5.4)"""
    from defender.learning_store import blocking

    dsn = migrated_database
    register_tenant(dsn, TENANT)
    published = (("c", 1000), ("a", 3000), ("b", 2000))
    with blocking(dsn) as setup:
        for key, size in published:
            _publish(setup, key, "x" * size)
            time.sleep(0.01)  # one enqueue time each: oldest first is publish order
    sizes = _sizes(dsn)

    with blocking(dsn, claim_bytes=sizes["c"] + sizes["a"]) as store:
        assert _claimed(store) == (["c", "a"], ["b"])

    _reset(dsn)
    with blocking(dsn) as setup:
        for key, size in published:
            _publish(setup, key, "x" * size)
    with blocking(dsn, claim_bytes=sum(_sizes(dsn).values()) + 1) as store:
        assert _claimed(store) == (["c", "a", "b"], [])


@pytest.mark.postgres
def test_r54_a_claim_takes_its_oldest_item_whatever_its_size(migrated_database):
    """A budget smaller than any item still claims the oldest one, so no item waits for good. (Amendment r5.4)"""
    from defender.learning_store import blocking

    dsn = migrated_database
    register_tenant(dsn, TENANT)
    with blocking(dsn) as setup:
        _publish(setup, "f2", "x" * 2000)
        time.sleep(0.01)
        _publish(setup, "f1", "x" * 10)
    with blocking(dsn, claim_bytes=1) as store:
        assert _claimed(store) == (["f2"], ["f1"])


#: Every kind of character the socket's ASCII JSON writes longer than its UTF-8 bytes, and plain ASCII.
_ALPHABET = ["a", "é", "中", "\U0001F600", '"', "\\", "\x01", "\n", " "]


def _text(rng: random.Random, max_bytes: int) -> str:
    out, size = [], 0
    while True:
        c = rng.choice(_ALPHABET) if rng.random() < 0.9 else rng.choice(_ALPHABET) * rng.randint(1, 64)
        if size + len(c.encode("utf-8")) > max_bytes:
            return "".join(out)
        out.append(c)
        size += len(c.encode("utf-8"))


@pytest.mark.postgres
@pytest.mark.parametrize("seed", range(6))
def test_r54_a_claim_within_its_budget_crosses_the_socket_within_it_whatever_its_text(migrated_database, seed):
    """Findings of generated text (every character the socket's ASCII JSON lengthens, in the finding and in a key up to
    the id bound), from a few bytes to tens of KiB each, more than the budget holds: the claim's answer as the port and
    the socket encode it is within the budget plus the envelope's room, and the default budget plus that room is within
    the socket's cap. (Amendment r5.4)"""
    from defender.job_socket import MAX_MESSAGE
    from defender.learning_store import blocking
    from defender.learning_store._store import DEFAULT_CLAIM_BYTES

    envelope = MAX_MESSAGE - DEFAULT_CLAIM_BYTES
    budget = 256 * 1024
    rng = random.Random(seed)
    dsn = migrated_database
    register_tenant(dsn, TENANT)
    _reset(dsn)
    with blocking(dsn) as setup:
        total = n = 0
        while total < 2 * budget:
            key = f"j/{n}/" + _text(rng, rng.choice([8, 200, 1000]))
            text = _text(rng, rng.choice([16, 2048, 40 * 1024]))
            _publish(setup, key, text)
            total += len(key.encode("utf-8")) * 6 + len(text.encode("utf-8")) * 4
            n += 1
    with blocking(dsn, claim_bytes=budget) as store:
        held = store.claim(TENANT, AUTHOR_LANE, owner="o", thresholds=ONE)
    waiting = execute(dsn, "SELECT count(*) FROM learning.work_items WHERE tenant_id = %s AND status = 'waiting'",
                      (TENANT,))[0][0]

    assert waiting, "premise: the budget left items waiting"
    assert len(_wire(held)) <= budget + envelope, (len(_wire(held)), budget)
    assert envelope >= 64 * 1024, "the default leaves the answer's envelope room"
