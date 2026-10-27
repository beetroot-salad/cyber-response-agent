"""The slice of a run's live state the systems modules touch: the circuit breaker and the systems
down for the run. The run's whole state (`investigation.run_state.RunState`) also holds the budget, the
clock and the branch counters, and it sits above `systems`; this names only what `systems` reads
and writes, so `systems` never imports it and `RunState` satisfies it by shape."""
from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, Protocol

from defender.kit.verbs import RunClock

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.systems.system_status import ReasonScope, StartCause


class SystemsState(RunClock, Protocol):
    """What the breaker and the system-status code need from a run's state, and the run clock an
    adapter stamps a capture with: `VerbContext.run_state` carries both."""

    reason_scope: ReasonScope | None

    @property
    def lock(self) -> AbstractContextManager[Any]:
        """Serialises every read-modify-write on the fields below."""
        ...

    @property
    def breaker(self) -> dict:
        """`{"systems": {name: {"failures": n, "tripped_at"?: iso}}, "total_failures": n}`."""
        ...

    @property
    def system_down(self) -> dict[str, StartCause]:
        """Each system down for the run for a cause the breaker does not count."""
        ...

    def now_iso(self) -> str:
        """The run clock's reading as ISO-8601 text."""
        ...

    def breaker_snapshot(self) -> dict:
        """A deep copy of the breaker."""
        ...

    def breaker_failures(self, system: str) -> int:
        """The failures charged to `system`'s breaker; 0 before any."""
        ...

    def system_down_cause(self, system: str) -> StartCause | None:
        """Why `system` is down for this run for a cause the breaker does not count."""
        ...
