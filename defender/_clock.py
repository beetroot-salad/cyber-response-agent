from __future__ import annotations

import datetime as _dt


def now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


#: The trailing-`Z`, whole-second spelling — NOT `now_iso`'s, and the two are not
#: interchangeable. `now_iso` ends `+00:00` and `tests/test_env.py` pins that shape; the
#: host-state adapter's payload contract is `Z` (`skills/host-state/SKILL.md`) and its readers
#: are told to cross-reference `captured_at` against event timestamps. One home for the format
#: because the turn-N branch stamps the same moment from more than one place — a state
#: adapter's capture time and an event query's open upper bound — and two copies of a
#: strftime string drift without anything going red.
Z_SECONDS = "%Y-%m-%dT%H:%M:%SZ"


def z_seconds(moment: _dt.datetime) -> str:
    """`moment` as `YYYY-MM-DDTHH:MM:SSZ`.

    A NAIVE input is read as UTC, matching `parse_iso_utc`'s documented rule so the two ends of
    a round trip agree. `astimezone` would read it as LOCAL and shift the moment by the host's
    offset — silently, and differently on a developer's machine than in CI, which is the one
    failure a timestamp helper must not have.

    Whole seconds because the format drops sub-second precision anyway: formatting a
    microsecond-bearing moment yields a string that no longer round-trips to it, so two
    spellings of one instant compare unequal and a cross-check against a stored T0 fails for a
    difference no reader can see.
    """
    at = moment if moment.tzinfo is not None else moment.replace(tzinfo=_dt.UTC)
    return at.astimezone(_dt.UTC).strftime(Z_SECONDS)


def parse_iso_utc(raw: object) -> _dt.datetime | None:
    """One ISO-8601 timestamp → an aware UTC datetime, or ``None`` if it is not one.

    Accepts the trailing ``Z`` that `now_iso`'s readers meet on the wire.

    A naive value is READ AS UTC rather than rejected: the stores mint ``datetime.now(utc)``,
    but a hand-written seed file may omit the offset, and treating that as unparseable would
    drop legitimate precedent over a formatting detail. A naive value in some other zone is
    misread, but the error is bounded by that zone's offset, which cannot approach the gap
    between seeded precedent and a live case. Returning aware-always also makes a mixed batch
    SORTABLE — comparing a naive datetime with an aware one raises `TypeError`.

    Named `_utc` to leave `parse_iso` to `evals/oracle_golden/controls.parse_iso`, which is
    deliberately NOT this function: it parses the two `@timestamp` literal shapes ES|QL
    accepts, requires an offset, and RAISES on anything else.
    """
    if not isinstance(raw, str):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)
