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


class PlantBeforeRunDirIo(PlantAfterRunDirIo):
    """A pass-through over the real `defender._io` that calls `plant(run_dir)` right BEFORE the
    first real run-dir `guarded_mkdir` (not `gather_raw`): between any check of the id and the
    make, so only an exclusive make refuses what it finds."""

    def __getattr__(self, name: str) -> Any:
        if name != "guarded_mkdir":
            return super().__getattr__(name)
        real = getattr(_io, name)

        def guarded_mkdir(path: Path, *args: Any, **kwargs: Any) -> Any:
            path = Path(path)
            if self.planted_in is None and path.name != RUN_LAYOUT.gather_raw.name:
                self.planted_in = path
                self._plant(path)
            return real(path, *args, **kwargs)

        return guarded_mkdir


#: What can sit at a sidecar's (or a run dir's) name besides a plain file; `plant_entry` makes each.
OBSTRUCTIONS = ("regular-file", "directory", "dangling-link", "link-to-file",
                "link-to-dir")


def plant_entry(kind: str, at: Path, elsewhere: Path) -> None:
    """Put an entry of `kind` at `at`; `link-to-file` points at a real file under `elsewhere`."""
    if kind == "regular-file":
        at.write_text("{}\n", encoding="utf-8")
    elif kind == "directory":
        at.mkdir()
    elif kind == "dangling-link":
        at.symlink_to(elsewhere / "nowhere")
    elif kind == "link-to-file":
        elsewhere.mkdir(exist_ok=True)
        (elsewhere / "target.json").write_text("{}\n", encoding="utf-8")
        at.symlink_to(elsewhere / "target.json")
    elif kind == "link-to-dir":
        (elsewhere / "target-dir").mkdir(parents=True, exist_ok=True)
        at.symlink_to(elsewhere / "target-dir", target_is_directory=True)
    else:
        raise ValueError(kind)


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
