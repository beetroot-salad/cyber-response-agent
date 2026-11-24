"""#1618: a delivery opened for a tenant whose clone, `exports/` and lock have been deleted (design "Upgrade"), so a case that
uses it shows what delivery does with no local knowledge, not what a fixture clone supplies. Test machinery only."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path

from ._support import delivery


def retire_clone(tenant: Any) -> None:
    """Delete `<T>/knowledge`, `<T>/exports/` and `<T>/knowledge.lock`."""
    root = Path(location_path(tenant.tenant_root))
    for name in ("knowledge", "exports"):
        shutil.rmtree(root / name, ignore_errors=True)
    (root / "knowledge.lock").unlink(missing_ok=True)
    assert not (root / "knowledge").exists()


def delivery_without_clone(repo: Any, http: Any, **options: Any) -> Any:
    """`delivery(repo, http)` for a tenant with no `<T>/knowledge`, `exports/` or lock (`retire_clone` makes sure: the seeded
    `repo` already has none, #1618). FORCED: r5 keeps `TenantDelivery.open(tenant, defender_dir=, client=, identity=, origin=)`;
    the tenant has no knowledge path."""
    retire_clone(repo[0])
    return delivery(repo, http, **options)
