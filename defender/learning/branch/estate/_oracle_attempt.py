"""Oracle attempt state, sandbox ownership, and billing."""
from __future__ import annotations

import asyncio
import contextlib






import threading

import time


from collections.abc import Callable

from dataclasses import dataclass, field


from typing import Any












from defender.box import stop_oracle_box


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
    #: The re-ask this attempt made and the host read (`checks.ReAsked`, the `re_ask` tool), or
    #: `None`: its answer is the attempt's base from then on, and the registry keeps it as a base
    #: answer of the world when the attempt commits (#1385 A3).
    re_asked: Any = None
    #: The code whose output this attempt submitted (#1543 O4), or `None` for a literal hand-in.
    code: str | None = None
    #: The saved file holding this attempt's re-asked answer, once it made one (#1543 O1).
    against_file: str | None = None




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
        #: Why the box could not start, once it could not: it is not tried again.
        self._refused: Exception | None = None
        #: The saved reads already written into the current box's scratch, by file name (#1543 O1).
        self.placed: set[str] = set()

    def get(self) -> Any:
        with self._lock:
            if self._ended:
                raise _AttemptFailed("the attempt has already ended")
            if self._box is not None:
                return self._box
            if self._refused is not None:
                raise _AttemptFailed("its box could not start earlier in this run") from self._refused
        try:
            box = self._factory()  # outside the lock: a slow start never holds up `stop`
        except Exception as exc:
            # A box that could not start is not started again for this run: every later call
            # gets the same refusal at once, rather than another container start each.
            with self._lock:
                self._refused = exc
            raise
        with self._lock:
            keep = not self._ended and self._box is None
            if keep:
                self._box = box
                self.placed = set()
        if not keep:
            _stop_box(box)
            return self.get()
        return box

    def refuse(self, box: Any, why: Exception) -> None:
        """`box` started but can never serve (it is not sandboxed): it goes, and no other box is
        started for this run, as when one could not start."""
        with self._lock:
            self._refused = why
        self.lost(box)

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
        from defender.box import BoxRuns

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




class _AttemptBoxes:
    """Every python box of one oracle attempt: the oracle's own, and a fresh one for each of its
    verifications (each judges in a cold context). They are made here, and stopped through one
    path whatever ends the attempt (its deadline, the sibling closing under it, or its end): a
    box made once the attempt was cancelled is born ended and never starts a container."""

    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._lock = threading.Lock()
        self._made: list[_AttemptBox] = []
        self._cancelled = False

    def new(self) -> _AttemptBox:
        return self.adopt(_AttemptBox(self._factory))

    def adopt(self, box: _AttemptBox) -> _AttemptBox:
        """Own `box` from now on: it is stopped with the attempt's, or born ended if the attempt
        was already cancelled."""
        with self._lock:
            self._made.append(box)
            if self._cancelled:
                box.cancel()  # nothing started yet: it only marks the box ended
        return box

    def _each(self, act: Callable[[_AttemptBox], None]) -> list[BaseException]:
        with self._lock:
            made = list(self._made)
        failures: list[BaseException] = []
        for box in made:
            try:
                act(box)
            except BaseException as exc:  # noqa: BLE001 — one box's failure never spares another
                failures.append(exc)
        return failures

    def cancel(self) -> list[BaseException]:
        """Stop execution in every box, keeping each for its workers to settle, and end the
        attempt's boxes: any made from now on is born ended. Returns what each stop raised."""
        with self._lock:
            self._cancelled = True
        return self._each(lambda box: box.cancel())

    def stop(self) -> list[BaseException]:
        """Remove every box (its container and scratch): only once its Python workers settled.
        The attempt's boxes end here: any made from now on is born ended."""
        with self._lock:
            self._cancelled = True
        return self._each(lambda box: box.stop())


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
    #: The serving's record of lookups that failed on our side (#1363 O7, A4), as each one's
    #: system and detail: every attempt of one serving, and its verifier runs, share one list, so a
    #: thread an earlier serving abandoned can only add to that serving's.
    ours: list[tuple[str, str]] = field(default_factory=list)
    #: The serving's saved reads (#1543 O1), each `{name, kind, question, answer}`: the call's base,
    #: the world's frozen rows, and the oracle's own reads and re-asks, shared by its attempts.
    saved: list[dict] = field(default_factory=list)
    #: Whether the call's base is a live read, as opposed to the source's recording: a re-ask is
    #: allowed only on a live base (#1385).
    live: bool = False
    #: Whether the call is a recorded pre-branch call, served unchanged: never re-asked.
    fixed: bool = False
    #: This run's python box: the oracle attempt's own, or on a verifier's run that verification's,
    #: which is never the oracle's (it judges in a cold context).
    box: _AttemptBox | None = None
    #: Every box of the oracle attempt (`_AttemptBoxes`), this run's among them; the verifier's run
    #: shares its attempt's. `None` only on a run that runs no python.
    boxes: _AttemptBoxes | None = None
    #: Whether this is a verifier's run: its saved files are what it judges (`_place`).
    verifying: bool = False
    #: Asked of a submission before its checks (`Oracle.serve`'s `gate`).
    gate: Callable[[Any], str | None] | None = None
    #: The agents entered on the oracle attempt's event loop, closed with the attempt outside its deadline
    #: (`Oracle._attempt`); `None` on a verifier's run.
    entered: contextlib.AsyncExitStack | None = None
    #: Python workers are owned by the attempt even when its tool coroutine is cancelled.
    _box_workers: list[asyncio.Task[Any]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        # A run's box is always owned by an attempt's boxes, so no stop path can miss it.
        if self.box is not None and self.boxes is None:
            self.boxes = _AttemptBoxes(self.box._factory)
            self.boxes.adopt(self.box)

    @property
    def against(self) -> Any:
        """The answer this attempt's claim is made against: its re-ask's answer once it has
        made one, else the call's base."""
        re_asked = self.attempt.re_asked
        return self.base if re_asked is None else re_asked.answer

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
    from defender.configuration import UnknownModel, model_key

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
