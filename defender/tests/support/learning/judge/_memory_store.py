"""An in-memory stand-in for the learning store's synchronous face, for tests of the judge's findings sink (#1278).

Only the two verbs the operator-lane sink calls (`work`, `publish_findings`) and the store's one rule they depend on: a finding id is
unique for good per (tenant, kind) and a repeat is a duplicate, not a second row. Everything else about the store (leases, batches,
phases) is the store's own tests'; a test that needs it uses the real store (`tests/support/learning/core/_store1278.py`).
"""
from __future__ import annotations

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

    def work(self, tenant: str) -> list[Item]:
        return list(self.items.get(str(tenant), []))

    def publish_findings(self, tenant: str, run_id: str, rows: Any, *, kind: str) -> tuple[int, int]:  # noqa: ARG002 — the real verb's shape
        held = self.items.setdefault(str(tenant), [])
        added = 0
        for row in rows:
            key = str(row["finding_id"])
            if any(i.kind == kind and i.key == key for i in held):
                continue
            held.append(Item(kind, key, dict(row)))
            added += 1
        return added, len(rows) - added

    def rows(self, channel: Any, tenant: str | None = None) -> list[dict[str, Any]]:
        """The payloads queued as `channel`'s kind (every tenant's when none is named)."""
        kind = KINDS[channel.name]
        tenants = [str(tenant)] if tenant is not None else list(self.items)
        return [i.payload for t in tenants for i in self.items.get(t, []) if i.kind == kind]
