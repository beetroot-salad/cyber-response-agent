"""#1618 K7 helpers: watch the host-side private repositories an operation opens, observed from the outside.

The watch rides the git server fake's existing `on_service` hook (it runs on the server's thread while the operation's
client waits, in whichever process the operation runs), so no production function is replaced. Nothing here implements
the policy under test: the properties asserted are the design's (Model, "Private repository").
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K


def scratch_root(t: Any) -> Path:
    """`<data root>/.repo-scratch/`."""
    return Path(location_path(t.data_root)) / ".repo-scratch"


class Watch:
    """Snapshots `<data root>/.repo-scratch/` (entries, modes, owners, liveness) and the git repositories under `<T>` each
    time the scene's git server serves a service for the first time after `arm()`."""

    def __init__(self, t: Any) -> None:
        self.t = t
        self.snapshots: list[dict[str, Any]] = []

    def arm(self) -> None:
        from defender.tenancy._owner import owner_alive

        server = self.t.server
        server._fired.clear()  # the fake fires `on_service` once per service name: re-arm after any setup traffic (FORCED: request a `GitHTTP.rearm()`)

        def snap(_service: str) -> None:
            root = scratch_root(self.t)
            names = sorted(p.name for p in root.iterdir()) if root.is_dir() else []
            self.snapshots.append({
                "names": names,
                "modes": {n: stat.S_IMODE((root / n).lstat().st_mode) for n in names},
                "uids": {n: (root / n).lstat().st_uid for n in names},
                "alive": {n: owner_alive(root / n) for n in names},
                "under_tenant": A.repos_under(K.tenant_root(self.t)),
            })

        server.on_service = snap

    def disarm(self) -> None:
        self.t.server.on_service = None

    def during(self) -> list[dict[str, Any]]:
        """The snapshots that saw at least one repository entry."""
        return [s for s in self.snapshots if s["names"]]


def assert_private_while_open(watch: Watch) -> None:
    """K7 during: some snapshot saw an entry under `.repo-scratch/`, named with the tenant id and an owner (existing
    `_owner` grammar), 0700, ours, owned by a live process; no snapshot saw a git repository under `<T>`."""
    t = watch.t
    assert watch.snapshots, "the operation never reached the git server: nothing was observed"
    seen = watch.during()
    assert seen, "no private repository was under <data root>/.repo-scratch/ while the operation fetched"
    for snap in watch.snapshots:
        assert snap["under_tenant"] == [], f"a git repository under <T> while the operation ran: {snap['under_tenant']}"
    for snap in seen:
        for name in snap["names"]:
            assert t.tenant_id in name, f"{name}: not named with the tenant id"
            assert A.NAMED_OWNER.search(name), f"{name}: not an owned_temporary name"
            assert snap["modes"][name] == 0o700, (name, oct(snap["modes"][name]))
            assert snap["uids"][name] == os.getuid(), name
            assert snap["alive"][name], f"{name}: its owner is not a live process"


def assert_nothing_left(t: Any) -> None:
    assert K.repo_scratch(t) == [], "the operation left its private repository behind"
    assert A.repos_under(K.tenant_root(t)) == []


def plant_dead_owner_entry(t: Any) -> Path:
    """A `.repo-scratch/` entry of this tenant whose owner (by name) is a dead process."""
    planted = A.plant(scratch_root(t) / A.named(t.tenant_id, *A.dead_mark()), by_name=True)
    assert planted.is_dir(), "control: the dead owner's entry is there before the trigger"
    return planted
