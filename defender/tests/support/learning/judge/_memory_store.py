"""An in-memory stand-in for the learning store's synchronous face, for tests of the judge's findings sink (#1278).

Only the verbs the operator-lane sink calls (`work`, `publish_finding_channels`, by way of `publish_findings` per
kind) and the store's one rule they depend on: a finding id is unique for good per (tenant, kind): a repeat is a duplicate, not a second row, and other content at a held id a
collision (#1565), refusing the whole call. Everything else about the store (leases, batches,
phases) is the store's own tests'; a test that needs it uses the real store (`tests/support/learning/core/_store1278.py`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

#: The store kind each findings channel is queued under (`enqueue._STORE_KINDS`).
KINDS = {"findings": "finding", "questioner_findings": "questioner_finding"}


@dataclass(frozen=True)
class Item:
    kind: str
    key: str
    payload: dict[str, Any]


@dataclass
class MemoryStore:
    items: dict[str, list[Item]] = field(default_factory=dict)

    def work(self, tenant: str, *, statuses: Any = None, kind: str | None = None) -> list[Item]:
        return [i for i in self.items.get(str(tenant), [])
                if (statuses is None or getattr(i, "status", "waiting") in statuses) and (kind is None or i.kind == kind)]

    def item_keys(self, tenant: str, kind: str) -> list[str]:
        return [i.key for i in self.items.get(str(tenant), []) if i.kind == kind]

    def publish_findings(self, tenant: str, run_id: str, rows: Any, *, kind: str) -> tuple[int, int]:
        """One kind's rows: `publish_finding_channels` with one channel."""
        return self.publish_finding_channels(tenant, run_id, {kind: rows})[kind]

    def publish_finding_channels(self, tenant: str, run_id: str, channels: Any) -> dict[str, tuple[int, int]]:  # noqa: ARG002 — the real verb's shape
        """Every kind's rows in one call, as the real verb: all stored, or (a clash, or a fault a subclass plants in
        `_publish_kind`) none. Content is compared as sorted JSON text, close to (not exactly) jsonb's equality."""
        before = {t: list(held) for t, held in self.items.items()}
        try:
            return {kind: self._publish_kind(str(tenant), kind, list(rows)) for kind, rows in channels.items()}
        except BaseException:
            self.items.clear()
            self.items.update(before)
            raise

    def _publish_kind(self, tenant: str, kind: str, rows: list[Any]) -> tuple[int, int]:
        held = self.items.setdefault(tenant, [])
        added = 0
        for row in rows:
            key = str(row["finding_id"])
            same = [i for i in held if i.kind == kind and i.key == key]
            if same and json.dumps(same[0].payload, sort_keys=True) != json.dumps(dict(row), sort_keys=True):
                from defender.learning_store import ItemCollision

                raise ItemCollision(f"a {kind} with id {key!r} came with other content: a collision, not a retry")
            if same:
                continue
            held.append(Item(kind, key, dict(row)))
            added += 1
        return added, len(rows) - added

    def rows(self, channel: Any, tenant: str | None = None) -> list[dict[str, Any]]:
        """The payloads queued as `channel`'s kind (every tenant's when none is named)."""
        kind = KINDS[channel.name]
        tenants = [str(tenant)] if tenant is not None else list(self.items)
        return [i.payload for t in tenants for i in self.items.get(t, []) if i.kind == kind]
