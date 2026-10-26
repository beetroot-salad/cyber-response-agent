"""#1165 flow fixtures: real Run/core I/O, with observation and fault injection only."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import asyncio
import errno
from pathlib import Path
from typing import Any

from pydantic_ai.models import override_allow_model_requests
from pydantic_ai.models.function import FunctionModel

from defender import _io
from defender.records import Run
from defender import box
from defender.runtime import driver
from defender.runtime.providers import BuiltModel
from defender.runtime.run_state import RunState
from defender.tests.support.runtime.permissions import _review_bundle
from defender.tests.support.tenancy import _tenants1106
from defender.tests.e2e import _replay_harness as replay


class RecordIO:
    """Delegate to the actual backend; record accesses and optionally fail one operation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path, str, Any]] = []
        self.fail: tuple[str, str] | None = None
        self.before_write: Any = None
        self.fail_reads = False

    def __getattr__(self, name: str) -> Any:
        real = getattr(_io, name)
        if not callable(real):
            return real

        def observe(*args: Any, **kwargs: Any) -> Any:
            if self.fail_reads and (name in ("bind", "hold") or (name.startswith("rooted_") and "read" in name)):
                raise OSError(errno.EIO, "#1165 injected record read fault")
            if name.startswith("rooted_") and len(args) >= 2:
                root, relative = Path(args[0]), str(args[1])
                self.calls.append((name, root, relative, kwargs.get("mode")))
                if name == "rooted_write" and self.before_write is not None:
                    self.before_write(root, relative, args[2], kwargs)
                if self.fail == (name, relative):
                    raise OSError(errno.EIO, "#1165 injected record backend fault")
            result = real(*args, **kwargs)
            if name in ("bind", "hold"):
                return ReadObservation(result, Path(args[0]), self)
            return result

        return observe

    def names(self, operation: str) -> list[str]:
        return [name for op, _root, name, _mode in self.calls if op == operation]


class ReadObservation:
    """Observe bound/core reader calls without changing the real backend's answers."""

    def __init__(self, real: Any, root: Path, observer: RecordIO, prefix: str = "") -> None:
        self.real, self.root, self.observer, self.prefix = real, root, observer, prefix

    def __enter__(self):
        self.real.__enter__()
        return self

    def __exit__(self, *exc):
        return self.real.__exit__(*exc)

    def __getattr__(self, name):
        real = getattr(self.real, name)
        if name == "view":
            return lambda *args, **kwargs: ReadObservation(
                real(*args, **kwargs), self.root, self.observer, self.prefix)
        if name == "under":
            def under(component):
                return ReadObservation(real(component), self.root, self.observer,
                                       str(Path(self.prefix) / str(component)))
            return under
        if name in ("read", "read_bytes", "read_jsonl"):
            def read(relative, **kwargs):
                if self.observer.fail_reads:
                    raise OSError(errno.EIO, "#1165 injected bound record read fault")
                combined = str(Path(self.prefix) / str(relative))
                self.observer.calls.append(("rooted_" + name, self.root, combined, None))
                return real(relative, **kwargs)
            return read
        return real


def run_handle(directory: Path, io: RecordIO | None = None) -> Run:
    directory.mkdir(parents=True, exist_ok=True)
    return Run.under(fixture_runs_base(directory.parent), directory.name, io=io if io is not None else _io)


def drive_run(  # noqa: PLR0913 — the real driver's injection inputs
    run: Run, main: Any, *, gather: Any = None, verbs: Any = None,
              state: RunState | None = None, resume: Any = None,
              source_run: Run | None = None, limits: Any = None, toolset: Any = None) -> dict:
    """Use the existing replay models at the new driver boundary, with real runtime wiring.

    The shared harness currently passes the retired run_dir/run_id pair. This fixture only
    adapts that boundary and uses its established tenant, review and model inputs.
    """
    tree = replay.DEFENDER
    main_model = BuiltModel(FunctionModel(replay._awaiting(main)), None)
    gather_fn = replay._with_default_correlation(gather, main) if resume is None and verbs is not None else gather
    gather_model = BuiltModel(FunctionModel(replay._awaiting(gather_fn)), None) if gather_fn is not None else None

    def make_model(name: str, effort: str) -> BuiltModel:
        if gather_model is not None and name == driver.gather_model():
            return gather_model
        return main_model

    default, export = replay._default_tenant()
    tenant = _tenants1106.run_tenant(
        default, defender_dir=tree, agent_root=export / "agent", settings_root=export / "settings",
        dispatches_lead_zero=resume is None and verbs is not None)
    kwargs: dict[str, Any] = {}
    if state is not None:
        kwargs["run_state"] = state
    if verbs is not None:
        kwargs["verbs"] = verbs
    if limits is not None:
        kwargs["limits"] = limits
    if toolset is not None:
        kwargs["toolset"] = toolset
    if resume is not None:
        kwargs.update(resume=resume, source_run=source_run)
    execution_box = replay.production_unboxed_box(run.run_dir, tree, tenant)
    try:
        with override_allow_model_requests(False):
            return asyncio.run(driver.run_investigation(
                run=run, alert_path=run.facts.alert.path, defender_dir=tree,
                make_model=make_model, tenant=tenant,
                box=execution_box,
                review_stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("holds")),
                orient_shim=replay.no_orient_shims, **kwargs))

    finally:
        box.stop_box(execution_box)
