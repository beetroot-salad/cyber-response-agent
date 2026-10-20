"""Oracle attempt state, sandbox ownership, and billing."""
from __future__ import annotations

import asyncio
import contextlib






import threading

import time


from collections.abc import Callable

from dataclasses import dataclass, field


from typing import Any












from defender.box._oracle import (
    stop_oracle_box,
)


from defender.learning.branch.estate.checks import RealData
from defender.learning.branch.estate._oracle_store import LimiterWaits as LimiterWaits, QueryDoor as QueryDoor, _AttemptFailed as _AttemptFailed




def _stop_box(box: Any) -> None:
    if not getattr(box, "sandboxed", False):
        return
    # Teardown is best effort; the sibling is already ending.
    with contextlib.suppress(Exception):
        stop_oracle_box(box)




@dataclass
class _Attempt:
    """One attempt's staged state, committed only with a verified answer."""

    forged: dict[str, dict] = field(default_factory=dict)
    facts: dict[tuple[str, str], Any] = field(default_factory=dict)




class _AttemptBox:
    """The python box of one attempt: started on the attempt's first `python` call, stopped
    (its container and scratch removed) after the attempt's Python worker settles. Cancellation
    stops execution without removing resources under that worker. An attempt that runs no
    Python starts no box; a startup completing after cancellation is discarded by its worker."""

    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._lock = threading.Lock()
        self._box: Any = None
        self._ended = False

    def get(self) -> Any:
        with self._lock:
            if self._ended:
                raise _AttemptFailed("the attempt has already ended")
            if self._box is not None:
                return self._box
        box = self._factory()  # outside the lock: a slow start never holds up `stop`
        with self._lock:
            keep = not self._ended and self._box is None
            if keep:
                self._box = box
        if not keep:
            _stop_box(box)
            return self.get()
        return box

    def lost(self, box: Any) -> None:
        """`box` died under a frame or cannot serve: the next `python` call starts a fresh one."""
        with self._lock:
            if self._ended:
                return  # the attempt finalizer removes it after the worker settles
            if self._box is box:
                self._box = None
        _stop_box(box)

    def cancel(self) -> None:
        """Stop useful execution; retain the box and scratch until the worker settles."""
        from defender.box._lifecycle import BoxRuns

        with self._lock:
            self._ended = True
            box = self._box
        if box is not None:
            BoxRuns(box).stop()

    def stop(self) -> None:
        with self._lock:
            self._ended = True
            box, self._box = self._box, None
        if box is not None:
            _stop_box(box)




@dataclass
class _Run:
    """One model run's state, which its tools and its request guard read: the run's clock (the
    turn deadline, its own rate-limiter waits excluded) and, for an oracle attempt, the call it
    serves, what the attempt staged, its python box, and the verdict a tool ended it with."""

    door: QueryDoor
    deadline: float
    call: tuple[str, str, dict] = ("", "", {})
    base: Any = None
    real: Callable[[], RealData] = lambda: RealData(answers=[])
    attempt: _Attempt = field(default_factory=_Attempt)
    ended: str | None = None
    reasked: bool = False
    #: Side-query answers already read this attempt, so a re-checked draft re-reads nothing.
    reruns: dict[str, Any] = field(default_factory=dict)
    began: float = field(default_factory=time.monotonic)
    #: This attempt's limiter waits; the verifier's run shares its attempt's.
    waits: LimiterWaits = field(default_factory=LimiterWaits)
    #: The oracle attempt's python box (`None` for the verifier, which runs no python).
    box: _AttemptBox | None = None
    #: Asked of a submission before its checks (`Oracle.serve`'s `gate`).
    gate: Callable[[Any], str | None] | None = None
    #: Python workers are owned by the attempt even when its tool coroutine is cancelled.
    _box_workers: list[asyncio.Task[Any]] = field(default_factory=list, repr=False)

    def remaining(self) -> float:
        return self.deadline - (time.monotonic() - self.began - self.waits.excluded())

    async def blocking(self, work: Callable[[], Any]) -> Any:
        """External reads and host checks may finish after their attempt stops waiting."""
        import anyio.to_thread

        return await anyio.to_thread.run_sync(work, abandon_on_cancel=True)

    async def box_work(self, work: Callable[[], Any]) -> Any:
        """Deliver a Python outcome, or leave its worker for the attempt to settle."""
        worker = asyncio.create_task(asyncio.to_thread(work))
        self._box_workers.append(worker)
        try:
            result = await asyncio.shield(worker)
        except asyncio.CancelledError:
            # The framework cancels tool tasks directly; the attempt still owns this worker.
            raise
        except BaseException:
            self._box_workers.remove(worker)
            raise
        self._box_workers.remove(worker)
        return result

    @property
    def has_box_work(self) -> bool:
        return bool(self._box_workers)

    async def settle_box_work(self) -> None:
        """Drain every retained worker and propagate its failure before an attempt can retry."""
        results = await asyncio.gather(*self._box_workers, return_exceptions=True)
        self._box_workers.clear()
        failures = [result for result in results if isinstance(result, BaseException)]
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("Oracle Python workers failed", failures)




def _model_and_settings(given: Any) -> tuple[Any, Any]:
    """A pydantic-ai `Model`, or a `BuiltModel` carrying one with its settings."""
    if hasattr(given, "request"):
        return given, None
    return given.model, getattr(given, "settings", None)




class OraclePricingError(RuntimeError):
    """A role's model has no pricing row: its spend would read as zero and the oracle's budget
    could not bound it, so it is refused before any request goes out."""




def price_row(actor: str, given: Any) -> str:
    """`actor`'s pricing row, from the model's name alone: a `Model`, a `BuiltModel` carrying
    one, or a model built lazily from its knob (whose name needs no provider key)."""
    from defender.configuration._pricing import UnknownModel, model_key

    name = getattr(given, "model_name", None)
    if name is None:
        name = getattr(_model_and_settings(given)[0], "model_name", "")
    name = str(name or "")
    try:
        return model_key(name)
    except UnknownModel:
        raise OraclePricingError(
            f"the {actor}'s model {name!r} has no row in defender/configuration/_pricing.py: its spend would "
            "be charged as zero and the oracle's budget could not bound it") from None
