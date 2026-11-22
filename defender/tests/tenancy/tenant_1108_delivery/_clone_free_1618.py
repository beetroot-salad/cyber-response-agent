"""#1618: a delivery opened for a tenant whose clone, `exports/` and lock have been deleted (design "Upgrade"), so a case that
uses it shows what delivery does with no local knowledge, not what a fixture clone supplies. Test machinery only."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path

from ._support import DEFENDER, configured_origin, fixture_identity, target


def retire_clone(tenant: Any) -> None:
    """Delete `<T>/knowledge`, `<T>/exports/` and `<T>/knowledge.lock`."""
    root = Path(location_path(tenant.tenant_root))
    for name in ("knowledge", "exports"):
        shutil.rmtree(root / name, ignore_errors=True)
    (root / "knowledge.lock").unlink(missing_ok=True)
    assert not (root / "knowledge").exists()


def delivery_without_clone(repo: Any, http: Any, **options: Any) -> Any:
    """`delivery(repo, http)` after `retire_clone`: the origin is read from the clone first, then the clone goes.
    FORCED: r5 keeps `TenantDelivery.open(tenant, defender_dir=, client=, identity=, origin=)`; the tenant has no knowledge path."""
    origin = configured_origin(repo[0].knowledge)
    if http.remote is None:
        http.remote = repo[1]
    if http.address is None and origin is not None:
        http.serve(origin)
    options.setdefault("identity", fixture_identity(str(repo[0].id)))
    retire_clone(repo[0])
    return target().TenantDelivery.open(repo[0], defender_dir=DEFENDER, client=http.client, origin=origin, **options)
