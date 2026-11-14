"""#1470 test machinery: the record store's typed refusals and the shape of what its writes and `credential_slot` return.
NO test functions. FORCED CHOICES, each in this one place for the code stage to correct: the design lists the refusal
types (stale, judged, no such tenant, tenant not active, no current record) and `RecordRefused` as their base without
naming the subclasses; the names below are the spike's. `created` and `generation_raised` are the design's names for what
a write returns; the slot's parts are read as attributes `generation` and `auth`, and a stale or moved refusal's shown
version as `current_version` (the design's name for it on the wire)."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

#: The typed refusals, as `defender.system_records` names them.
REFUSAL_NAMES = ("Stale", "Judged", "NoSuchTenant", "TenantNotActive", "NoCurrentRecord")

SEED = "test member"

#: O10's list, the one literal the O10 and O11 tests share: the operator subcommands removed in #1470.
REMOVED_COMMANDS = frozenset({"set-alert-mapping", "set-system", "delete-system", "set-case", "delete-case", "systems",
                              "set-credentials", "catalog", "import"})


def refusals() -> Mapping[str, type[Exception]]:
    import defender.system_records as store

    return {name: getattr(store, name) for name in REFUSAL_NAMES}


def accept_all(after: Any, before: Any) -> list[str]:
    return []


def refuse_with(*faults: str) -> Callable[[Any, Any], list[str]]:
    """A judge that finds exactly `faults` (the store's contract is to refuse with them, whoever finds them)."""
    return lambda after, before: list(faults)


def run(dsn: str, work: Callable[[Any], Awaitable[Any]], *, judge: Callable[[Any, Any], list[str]] = accept_all) -> Any:
    """`work(store)` on a store over `dsn` with `judge`, closed afterwards; the answer."""
    async def go() -> Any:
        from defender.system_records import RecordStore
        from defender.tests.support.jobs._jobs1342 import fixed_clock

        store = RecordStore(dsn, clock=fixed_clock, judge=judge)
        try:
            return await work(store)
        finally:
            await store.close()

    return asyncio.run(go())


def refused(dsn: str, work: Callable[[Any], Awaitable[Any]], *, judge: Callable[[Any, Any], list[str]] = accept_all) -> Exception:
    """The `RecordRefused` `work(store)` raises (a test fails if it raised nothing, or something else)."""
    from defender.system_records import RecordRefused

    async def attempt(store: Any) -> Exception | None:
        try:
            await work(store)
        except RecordRefused as refusal:
            return refusal
        return None

    found = run(dsn, attempt, judge=judge)
    assert found is not None, "the store refused nothing"
    return found


def kind_of(refusal: Exception) -> str | None:
    """Which typed refusal `refusal` is: the one name it is an instance of, None when it is of none of them."""
    named = [name for name, cls in refusals().items() if isinstance(refusal, cls)]
    assert len(named) <= 1, f"{type(refusal).__name__} is an instance of {named}: the types must be separate"
    return named[0] if named else None


def slot_parts(slot: Any) -> tuple[int, Any]:
    """`(generation, parsed auth)` of what `credential_slot` returned."""
    return slot.generation, slot.auth
