"""#1278 sketch, Migration: the one-time import of a tenant's file learning state into the store."""
from __future__ import annotations

import json

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import finding, learning_store, store_mod
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-blue")


def _jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


async def test_migration_a_finding_in_both_queue_and_ledger_imports_as_the_ledger_says(migrated_database, tmp_path):
    """Queue and consumed ledger both hold f1: the ledger wins (published); f2, queued only, waits. (Migration import rules)"""
    register_tenant(migrated_database, BLUE)
    root = tmp_path / "learning"  # the tenant's state root as base lays it out (`_pending/` channel files)
    f1, f2 = finding("f1"), finding("f2")
    _jsonl(root / "_pending" / "findings.jsonl", [f1, f2])
    _jsonl(root / "_pending" / "consumed.jsonl", [
        dict(f1, consumed_category="consumed_committed", consumed_at="2026-11-01T00:00:00Z",
             consumed_commit="0" * 40)])

    async with learning_store(migrated_database) as store:
        await store_mod().import_learning_state(store, BLUE, root)
        items = {i.key: i for i in await store.work(BLUE)}

    assert {k: (i.kind, i.status) for k, i in items.items()} == {
        "f1": ("finding", "published"), "f2": ("finding", "waiting")}
