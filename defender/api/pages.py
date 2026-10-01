"""Cursor pagination for every list endpoint.

A list answers `Page[T]`: at most `limit` items and a `next_cursor`, `null` on the last page. A
client pages by sending the same query again with `cursor=<next_cursor>`. The cursor is opaque:
base64url JSON naming the list it came from, the tenant that asked, a digest of the filters it was
issued for, and the position of the last item served. The filters go in as a digest, not their
values, so a cursor's size never depends on the query: whatever filter a list accepts, the cursor
it issues fits the cursor parameter it is sent back in. What a cursor carries back in is checked
with the same types as every other input — its position's id is a `RecordId` and its moment an
`Instant` (`models.py`) — so an edited cursor cannot hand a port what a path or query could not. A cursor that does not decode, or that names
another list, another tenant or other filters, is a 422 — never a silently different page. It is
not signed: it cannot widen what a caller reads, since the tenant comes from the login and the
store filters by it whatever the cursor says.

Each list has one total order, which the store answers in (its ports say which): newest first
by `(timestamp, id)` for alerts, investigations and learning jobs, and by id for lessons and
systems. The id breaks ties, so a page boundary between two rows with one timestamp neither
repeats nor skips either. The route asks its port for one row more than `limit`; that row, if
it comes back, is how the page knows another follows. The route also checks that the rows
advance past `after`, in order: a store whose page does not (an off-by-one at the boundary)
would otherwise hand the client the same cursor forever, so it is a 500 (`StoreBrokePromise`).
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Generic, Literal, TypeVar

from fastapi import HTTPException
from pydantic import BaseModel, ValidationError

from .models import Instant, RecordId
from .ports import StoreBrokePromise, TimePosition

T = TypeVar("T")
P = TypeVar("P")


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None


class _CursorBody(BaseModel, extra="forbid"):
    v: Literal[1]
    of: str
    tenant: str
    filters: str
    at: Instant | None
    id: RecordId


class Order(Generic[T, P]):
    """How one list is ordered: the position of an item, whether one position comes before
    another, and a position's cursor fields."""

    def __init__(self, position: Callable[[T], P], precedes: Callable[[P, P], bool],
                 dump: Callable[[P], tuple[_dt.datetime | None, str]],
                 load: Callable[[_CursorBody], P | None]) -> None:
        self.position = position
        self.precedes = precedes
        self.dump = dump
        self.load = load


def newest_first(at: Callable[[T], _dt.datetime], ident: Callable[[T], str]) -> Order[T, TimePosition]:
    return Order(
        position=lambda item: (at(item), ident(item)),
        precedes=lambda a, b: a > b,
        dump=lambda pos: (pos[0], pos[1]),
        load=lambda body: None if body.at is None else (body.at, body.id),
    )


def ordered_by_id(ident: Callable[[T], str]) -> Order[T, str]:
    return Order(
        position=ident,
        precedes=lambda a, b: a < b,
        dump=lambda pos: (None, pos),
        load=lambda body: body.id if body.at is None else None,
    )


def _refused(reason: str) -> HTTPException:
    return HTTPException(422, f"invalid cursor: {reason}")


def _filters_digest(filters: Mapping[str, str | None]) -> str:
    canonical = json.dumps(dict(filters), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _encode_cursor(body: _CursorBody) -> str:
    return base64.urlsafe_b64encode(body.model_dump_json().encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> _CursorBody:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        return _CursorBody.model_validate_json(raw)
    except (binascii.Error, ValueError, ValidationError) as e:
        raise _refused("not a cursor this API issued") from e


def _advances(order: Order[T, P], after: P | None, rows: Sequence[T], asked: int) -> None:
    """The rows are what the port promised: at most `asked`, each strictly after the one before
    it (the first, strictly after `after`)."""
    if len(rows) > asked:
        raise StoreBrokePromise(f"asked for {asked} rows, answered {len(rows)}")
    previous = after
    for row in rows:
        position = order.position(row)
        if previous is not None and not order.precedes(previous, position):
            raise StoreBrokePromise(f"row at {position!r} does not follow {previous!r} in the list's order")
        previous = position


def paginate(
    fetch: Callable[[P | None, int], Sequence[T]],
    order: Order[T, P],
    *,
    list_name: str,
    tenant_id: str,
    filters: Mapping[str, str | None],
    cursor: str | None,
    limit: int,
) -> Page[T]:
    """One page of `fetch(after, n)`, which answers up to `n` items strictly after `after` in
    the list's order. The cursor is checked before the store is asked anything."""
    after: P | None = None
    filters_digest = _filters_digest(filters)
    if cursor is not None:
        body = _decode_cursor(cursor)
        if body.of != list_name:
            raise _refused(f"issued for {body.of}, not {list_name}")
        if body.tenant != tenant_id:
            raise _refused("issued to another tenant")
        if body.filters != filters_digest:
            raise _refused("the filters changed; send the query the cursor came from")
        after = order.load(body)
        if after is None:
            raise _refused("not a position in this list")
    rows = list(fetch(after, limit + 1))
    _advances(order, after, rows, limit + 1)
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        at, ident = order.dump(order.position(items[-1]))
        next_cursor = _encode_cursor(_CursorBody(
            v=1, of=list_name, tenant=tenant_id, filters=filters_digest, at=at, id=ident,
        ))
    return Page(items=items, next_cursor=next_cursor)
