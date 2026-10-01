from __future__ import annotations

import datetime as _dt


def now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


#: The trailing-`Z`, whole-second spelling. Not interchangeable with `now_iso` (which ends
#: `+00:00`): the host-state adapter's payload contract is `Z`. One home because the turn-N
#: branch stamps the same moment from several places and must produce identical strings.
Z_SECONDS = "%Y-%m-%dT%H:%M:%SZ"


def as_utc(moment: _dt.datetime) -> _dt.datetime:
    """`moment` as an aware UTC datetime, reading a naive value as UTC.

    The single normalisation: the turn-N branch derives a moment in one module, formats it in
    another, and cross-checks them for exact equality (`runtime.branch._refuse_bad_as_of`).
    `astimezone` on a naive value would read it as local time and shift it by the host offset.
    """
    at = moment if moment.tzinfo is not None else moment.replace(tzinfo=_dt.UTC)
    return at.astimezone(_dt.UTC)


def z_seconds(moment: _dt.datetime) -> str:
    """`moment` as `YYYY-MM-DDTHH:MM:SSZ`; a naive input is read as UTC.

    Sub-second precision is dropped, so the result does not round-trip a microsecond-bearing
    moment — compare formatted strings, not the original datetimes.
    """
    return as_utc(moment).strftime(Z_SECONDS)


def parse_iso_utc(raw: object) -> _dt.datetime | None:
    """One ISO-8601 timestamp (trailing ``Z`` accepted) → an aware UTC datetime, or ``None``.

    A naive value is read as UTC rather than rejected, since hand-written seed files may omit
    the offset. Always returning aware values keeps a mixed batch sortable: a bare
    ``fromisoformat`` yields naive or aware depending on the input, and comparing the two
    raises `TypeError`.

    Distinct from `evals/oracle_golden/controls.parse_iso`, which requires an offset and raises.
    """
    if not isinstance(raw, str):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)
