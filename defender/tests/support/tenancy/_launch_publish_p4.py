"""The in-process stand-in for `run.main`'s launch-time knowledge fetch (#1618 flow 1; was #1108 P4's publish).

Only the CLI binds the real fetch child (`publish_launch.default_fetch`); an in-process caller of `run.main` passes
`fetch=`. This module's `in_process_fetch` (`_fetch_standin_1618`) commits what the test placed for the tenant to its
served forge remote at CALL time and fills the run's empty folder through the product's own `fetch_copy`, answering the
child's one report line (`ok <commit>` | `refused <transient|lasting> <reason>`). Every other decision stays
`run.main`'s.

Seeding at call time, not test setup, keeps "an edit made before the launch is what the run reads" true, and a
`run.main` that hands the wrong tenant id or data root fetches nothing the run can read.
"""
from __future__ import annotations

from pathlib import Path
from collections.abc import MutableMapping
from typing import Any

from defender.tests.support.tenancy._fetch_standin_1618 import forge_scratch, in_process_fetch
from defender.tests.support.tenancy._twin1496 import seed_tenant

#: The keyword `run.main` takes its knowledge fetch under (#1618: `publish=` is gone).
FETCH_SEAM = "fetch"

__all__ = ["FETCH_SEAM", "RunWithFetch", "directory_for_argv", "directory_for_root", "empty_directory",
           "forge_scratch", "in_process_fetch", "with_fetch"]


def empty_directory() -> Any:
    """A `TenantDirectory` that knows no tenant: the unknown-tenant side of a refusal (pass it as `directory=`)."""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin = InMemoryTenantRepository()
    return TenantDirectory(lambda: twin)


def directory_for_argv(argv: Any, root: Path | str | None = None, **keywords: Any) -> Any:
    """The `TenantDirectory` a run's `--tenant T` is admitted from (#1214 Flow 4): `T` ACTIVE with its forge wiring
    whatever the folder state, so a missing or broken folder is refused by `accept_tenant`'s own folder check, never
    by this helper. With no `--tenant` nothing is active; a test whose subject is an unknown tenant passes
    `empty_directory()` itself. `root` defaults to this test's data root (none in this process: a nonexistent one, so
    the data-root fault refuses); `keywords` are `active_directory`'s (`state=`, `wiring=`, ...)."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, tenant_directory

    words = [str(a) for a in argv or ()]
    if root is None:
        try:
            root = current_data_root()
        except AssertionError:  # no data root in this process: the tenant is active, the data-root fault refuses
            root = Path("/nonexistent-data-root")
    tenant = words[words.index("--tenant") + 1] if "--tenant" in words[:-1] else None
    if tenant is None:
        return empty_directory()
    return tenant_directory(Path(root), tenant, **keywords)


def directory_for_root(root: Path | str | None = None, *, also: Any = ()) -> Any:
    """The `TenantDirectory` a drain over several tenants is served from (#1214 Flow 4: it re-checks the state per
    claim): every tenant placed under `root` (default: this test's data root; `<root>/<T>/knowledge` is a
    directory) active with its forge wiring, and so is every id in `also` (active whatever its folder: acceptance
    refuses it); any other tenant is unknown to it."""
    import inspect

    from defender.tenancy import InMemoryTenantRepository, TenantDirectory
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
    from defender.tests.support.tenancy import _active1214

    root = Path(root) if root is not None else current_data_root()
    twin: Any = InMemoryTenantRepository()
    placed = sorted(p.name for p in root.iterdir() if (p / "knowledge").is_dir()) if root.is_dir() else []
    for tenant in dict.fromkeys([*placed, *map(str, also)]):
        added = seed_tenant(twin, tenant, created_at=_active1214.CREATED, state="active", repo=f"tenants/{tenant}",
                                origin=_active1214._origin_of(root, tenant, None))
        if inspect.isawaitable(added):
            _active1214.run_sync(_active1214._await(added))
        _active1214.seed_twin(twin, tenant, _active1214.PLANTED_ALERT_MAPPING)  # #1345: today's mapping
        _active1214.seed_twin_records(twin, root, tenant)  # #1366 R8
    return TenantDirectory(lambda: twin)


def with_fetch(seams: MutableMapping[str, Any], argv: Any = None) -> MutableMapping[str, Any]:
    """`seams` with the in-process fetch added, unless the caller already passes its own; given the run's `argv`,
    also `directory=` (`directory_for_argv`) unless the caller passes one."""
    seams.setdefault(FETCH_SEAM, in_process_fetch())
    if argv is not None:
        seams.setdefault("directory", directory_for_argv(argv))
    return seams


class RunWithFetch:
    """`run.py`'s module, as an in-process caller drives it: `.main(argv, **seams)` is the real
    `run.main` handed the in-process fetch (unless the caller passes its own `fetch=`);
    every other attribute is the module's own."""

    def __init__(self, module: Any) -> None:
        self._module = module

    def __getattr__(self, name: str) -> Any:
        return getattr(self._module, name)

    def main(self, argv: Any = None, **seams: Any) -> Any:
        return self._module.main(argv, **with_fetch(seams, argv))
