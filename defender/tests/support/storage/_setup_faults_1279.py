"""Faults planted in run setup through the repository's `io=` injection (#1279 R2).

Run setup reaches the run dir through `tenant.runs_repository()`, whose `io=` is the guarded
`defender._io` seam. A test that must obstruct a write *after* the real run-dir creation (an
id is minted by setup now, so nothing can be planted at a chosen id beforehand) passes a tenant
whose repository was built with a pass-through io that plants the obstruction once the real
`guarded_mkdir` has returned. Nothing is patched: the fault is a real directory on the real
filesystem, and the real writers refuse it.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender import _io
from defender.run_repository import RUN_LAYOUT


class PlantAfterRunDirIo:
    """A pass-through over the real `defender._io` that calls `plant(run_dir)` once, right after
    the first real `guarded_mkdir` that made (part of) a run dir."""

    def __init__(self, plant: Callable[[Path], None]) -> None:
        self._plant = plant
        self.planted_in: Path | None = None

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        real = getattr(_io, name)
        if name != "guarded_mkdir":
            return real

        def guarded_mkdir(path: Path, *args: Any, **kwargs: Any) -> Any:
            result = real(path, *args, **kwargs)
            if self.planted_in is None:
                path = Path(path)
                self.planted_in = path.parent if path.name == RUN_LAYOUT.gather_raw.name else path
                self._plant(self.planted_in)
            return result

        return guarded_mkdir


class TenantWithRunsIo:
    """An accepted tenant whose `runs_repository()` is built over `io`. Everything else is the
    real tenant's (it answers `isinstance(…, Tenant)`)."""

    def __init__(self, tenant: Any, io: Any) -> None:
        self._tenant = tenant
        self._io = io

    @property
    def __class__(self) -> type:  # type: ignore[override]
        return type(self._tenant)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tenant, name)

    def runs_repository(self) -> Any:
        from defender.run_repository import RunsRepository

        return RunsRepository(self._tenant, io=self._io)


def tenant_with_runs_io(tenant: Any, io: Any) -> Any:
    return TenantWithRunsIo(tenant, io)


def materialize_through(io: Any) -> Callable[..., Any]:
    """`run.main`'s `materialize` seam: the real `_materialize_run`, over a tenant whose runs
    repository uses `io`."""
    from defender import run as run_py

    def materialize(alert: Path, *args: Any, tenant: Any, **kwargs: Any) -> Any:
        return run_py._materialize_run(alert, *args, tenant=tenant_with_runs_io(tenant, io), **kwargs)

    return materialize
