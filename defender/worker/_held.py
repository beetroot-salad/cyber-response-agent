"""What a worker keeps for each row it holds, and how it tells a database outage from a bug (#1343)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout


def is_outage(fault: BaseException) -> bool:
    """Whether a failed store write is the environment's fault (B5, r5 item 13): the database
    could not be reached, or answered with a transient condition. Waiting can cure these. Anything
    else (integrity, data, programming, anything unplanned) is ours or the value's, and waiting
    never cures it."""
    if isinstance(fault, DBAPIError) and fault.connection_invalidated:
        return True
    return isinstance(fault, OperationalError | InterfaceError | PoolTimeout | OSError | ConnectionError)


@dataclass
class Held:
    """One row this worker holds, from its claim until its last write has landed (B-P2).

    `fenced`: a renewal that succeeded omitted the row, so it was cancelled, taken over or
    deleted. `signalled`: a deliberate stop signalled this row's child while it was alive.
    `cost_so_far`: the last figure the cost task read for the row; the renewal copies it."""

    record: Any
    proc: asyncio.subprocess.Process | None = None
    fenced: bool = False
    signalled: bool = False
    cost_so_far: float | None = None
    enders: list[asyncio.Task[None]] = field(default_factory=list)


@dataclass(frozen=True)
class Ending:
    """The terminal write for one row."""

    stage: str
    disposition: str | None = None
    failure_reason: str | None = None
    failure_message: str | None = None


@dataclass(frozen=True)
class End:
    """What a row's holder writes last: the decided ending (`ending`), or the row handed back
    (`ending` None) when a deliberate stop ended its child. Either way carries the final cost
    (None when unknown) and knowledge."""

    ending: Ending | None
    cost: float | None
    knowledge: dict | None
