"""The in-process stand-in for `run.main`'s launch-time publish (#1108 P4).

Only the CLI binds the real publish child (`publish_launch.launch_publish`); an in-process caller
of `run.main` passes `publish=`. Handed only the tenant id and data root, this stand-in publishes
the tenant's folder as it is now through `tenant_1108_p4._support.publish_once` and answers with
the child's one report line: `fresh <commit>`, `stale:operator <reason>` when P3 or acceptance
refuses the folder, or `stale:transient <reason>` when the tenant lock stays busy after P3's
bounded retry. Every other decision stays `run.main`'s.

Publishing at call time, not test setup, keeps "an edit made before the launch is what the run
reads" true, and a `run.main` that hands the wrong tenant id or data root publishes nothing the
run can read.
"""
from __future__ import annotations

from pathlib import Path
from collections.abc import Callable, MutableMapping
from typing import Any

import pytest

#: The keyword `run.main` takes its launch-time publish under.
PUBLISH_SEAM = "publish"


def forge_scratch(data_root: Path) -> Path:
    """Where a data root's served remotes live: beside it (`<root>-p4-forge`), never under it,
    shared with `_replay_harness._default_tenant` so a re-publish fast-forwards one remote."""
    root = Path(data_root)
    return root.with_name(f"{root.name}-p4-forge")


def in_process_publish() -> Callable[..., str]:
    """A `publish=` for `run.main` (module doc)."""

    def publish(tenant_id: str, *, data_root: Any, **_kw: Any) -> str:
        from defender.learning.author.version_control import DeliveryRefused, LockBusy
        from defender.records._tenant_id import TenantRefused
        from defender.tests.tenancy.tenant_1108_p4._support import publish_once

        root = Path(str(data_root))
        served = forge_scratch(root)
        # Tests re-plant a folder in place, keeping its `.git`, so each publish fast-forwards one
        # remote; a folder with no `.git` beside an earlier remote means the planter replaced the
        # repo, a setup fault. `pytest.fail` (a BaseException), because `run.main` reads an
        # `Exception` from `publish=` as a failed child and would run on, stale.
        remote = served / "tenants" / f"{tenant_id}.git"
        if remote.exists() and not (root / str(tenant_id) / "knowledge" / ".git").exists():
            pytest.fail(
                f"tenant {tenant_id}'s knowledge folder lost its .git after a publish to "
                f"{remote}: re-plant the folder in place (keep .git), or give each arm its own "
                "data root")
        try:
            done = publish_once(served, root=root, tenant_id=str(tenant_id))
        except LockBusy as busy:
            reason = " ".join(str(busy).split()) or type(busy).__name__
            return f"stale:transient {reason}"
        except (DeliveryRefused, TenantRefused) as refused:
            reason = " ".join(str(refused).split()) or type(refused).__name__
            return f"stale:operator {reason}"
        return f"fresh {done.commit}"

    return publish


def with_publish(seams: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """`seams` with the in-process publish added, unless the caller already passes its own."""
    seams.setdefault(PUBLISH_SEAM, in_process_publish())
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
