"""#1108 P4 (OD14, O11, U7): the in-process stand-in for `run.main`'s launch-time publish.

Only the CLI binds the real publish child (`publish_launch.launch_publish`, a separate process); an
in-process caller of `run.main` passes `publish=`. This stand-in does what the child does, at
the moment `run.main` calls it and with exactly the identifiers it is handed (the tenant id and
the data root, nothing else — U7/O8): it publishes the tenant's knowledge folder AS IT IS NOW,
for real, through the one shared helper (`tenant_1108_p4._support.publish_once`: the clone
committed, pushed to a served remote, P3's `TenantDelivery.publish()` exporting it and pointing
`current` at it), and answers with OD2's one report line — `fresh <commit>`, or
`stale:operator <reason>` when P3 or acceptance refuses the folder (a scenario that plants a
broken tenant on purpose), or `stale:transient <reason>` when the tenant lock is still busy
after P3's bounded retry (O-STALE). It decides nothing else: which export the run reads, and every
refusal, stay `run.main`'s.

Publishing at call time (not at the test's setup) keeps "an edit made to the tenant's folder
before the launch is what the run reads" true, and a run.main that hands the wrong tenant id or
data root publishes nothing the run can read.
"""
from __future__ import annotations

from pathlib import Path
from collections.abc import Callable, MutableMapping
from typing import Any

import pytest

#: The keyword `run.main` takes its launch-time publish under (OD14).
PUBLISH_SEAM = "publish"


def forge_scratch(data_root: Path) -> Path:
    """Where a data root's served remotes live: beside it (`<root>-p4-forge`), never under it,
    shared with `_replay_harness._default_tenant` so a re-publish fast-forwards one remote."""
    root = Path(data_root)
    return root.with_name(f"{root.name}-p4-forge")


def in_process_publish(scratch: Path | None = None,
                       calls: list[tuple[str, Path]] | None = None) -> Callable[..., str]:
    """A `publish=` for `run.main` (module doc). `calls`, when given, records each
    `(tenant_id, data_root)` it was handed."""

    def publish(tenant_id: str, *, data_root: Any, **_kw: Any) -> str:
        from defender.learning.author.version_control import DeliveryRefused, LockBusy
        from defender.tenancy._tenant import TenantRefused
        from defender.tests.tenancy.tenant_1108_p4._support import publish_once

        root = Path(str(data_root))
        if calls is not None:
            calls.append((str(tenant_id), root))
        served = scratch if scratch is not None else forge_scratch(root)
        # A test re-plants a tenant's folder in place, keeping its `.git` (`_spec1107.plant`),
        # so every publish of one tenant is a fast-forward on the same remote. A folder with no
        # `.git` beside a remote an earlier publish left is a planter that replaced the
        # repository: a test-setup fault, never papered over by starting the remote anew. It is
        # `pytest.fail` (a BaseException): `run.main` reads an `Exception` out of `publish=` as a
        # failed child (U11) and would run on, stale, on the last snapshot.
        remote = served / "tenants" / f"{tenant_id}.git"
        if remote.exists() and not (root / str(tenant_id) / "knowledge" / ".git").exists():
            pytest.fail(
                f"tenant {tenant_id}'s knowledge folder lost its .git after a publish to "
                f"{remote}: re-plant the folder in place (keep .git), or give each arm its own "
                "data root")
        try:
            done = publish_once(served, root=root, tenant_id=str(tenant_id))
        except LockBusy as busy:
            # O-STALE: a tenant lock still busy after the bounded retry is transient.
            reason = " ".join(str(busy).split()) or type(busy).__name__
            return f"stale:transient {reason}"
        except (DeliveryRefused, TenantRefused) as refused:
            reason = " ".join(str(refused).split()) or type(refused).__name__
            return f"stale:operator {reason}"
        return f"fresh {done.commit}"

    return publish


def with_publish(seams: MutableMapping[str, Any], scratch: Path | None = None) -> MutableMapping[str, Any]:
    """`seams` with the in-process publish added, unless the caller already passes its own."""
    seams.setdefault(PUBLISH_SEAM, in_process_publish(scratch))
    return seams


class RunWithPublish:
    """`run.py`'s module, as an in-process caller drives it: `.main(argv, **seams)` is the real
    `run.main` handed the in-process publish (unless the caller passes its own `publish=`);
    every other attribute is the module's own."""

    def __init__(self, module: Any) -> None:
        self._module = module

    def __getattr__(self, name: str) -> Any:
        return getattr(self._module, name)

    def main(self, argv: Any = None, **seams: Any) -> Any:
        return self._module.main(argv, **with_publish(seams))
