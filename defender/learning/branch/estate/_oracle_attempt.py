"""Oracle attempt state, sandbox ownership, and billing."""
from __future__ import annotations

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
    (its container and scratch removed) when the attempt ends, whatever the ending. Stopping it
    also ends a frame the attempt's deadline abandoned. An attempt that runs no python starts
    no box; a box started after the attempt ended (by its abandoned thread) is stopped at once."""

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
            if self._box is box:
                self._box = None
        _stop_box(box)

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

    def remaining(self) -> float:
        return self.deadline - (time.monotonic() - self.began - self.waits.excluded())

    async def blocking(self, work: Callable[[], Any]) -> Any:
        """`work` (a tenant read, a box run, the host checks) on a worker thread the attempt's
        deadline can stop waiting on; the abandoned thread finishes on its own (a python frame
        ends sooner: the attempt's box is stopped under it)."""
        import anyio.to_thread

        return await anyio.to_thread.run_sync(work, abandon_on_cancel=True)




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
