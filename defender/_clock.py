from __future__ import annotations

import datetime as _dt


def now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


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
