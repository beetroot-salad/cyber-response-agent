"""Cursor pagination for every list endpoint.

A list answers `Page[T]`: at most `limit` items and a `next_cursor`, `null` on the last page. A
client pages by sending the same query again with `cursor=<next_cursor>`. The cursor is opaque:
base64url JSON naming the list it came from, the tenant that asked, the filters it was issued
for, and the position of the last item served. A cursor that does not decode, or that names
another list, another tenant or other filters, is a 422 — never a silently different page. It is
not signed: it cannot widen what a caller reads, since the tenant comes from the login and the
store filters by it whatever the cursor says.

Each list has one total order, which the store answers in (its ports say which): newest first
by `(timestamp, id)` for alerts, investigations and learning jobs, and by id for lessons and
systems. The id breaks ties, so a page boundary between two rows with one timestamp neither
repeats nor skips either. The route asks its port for one row more than `limit`; that row, if
it comes back, is how the page knows another follows.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
from collections.abc import Callable, Mapping, Sequence
from typing import Generic, Literal, TypeVar

from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel, ValidationError

from .ports import TimePosition

T = TypeVar("T")
P = TypeVar("P")


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None


class _CursorBody(BaseModel, extra="forbid"):
    v: Literal[1]
    of: str
    tenant: str
    filters: dict[str, str | None]
    at: AwareDatetime | None
    id: str


class Order(Generic[T, P]):
    """How one list is ordered: the position of an item, and a position's cursor fields."""

    def __init__(self, position: Callable[[T], P], dump: Callable[[P], tuple[_dt.datetime | None, str]],
                 load: Callable[[_CursorBody], P | None]) -> None:
        self.position = position
        self.dump = dump
        self.load = load


def newest_first(at: Callable[[T], _dt.datetime], ident: Callable[[T], str]) -> Order[T, TimePosition]:
    return Order(
        position=lambda item: (at(item), ident(item)),
        dump=lambda pos: (pos[0], pos[1]),
        load=lambda body: None if body.at is None else (body.at, body.id),
    )


def ordered_by_id(ident: Callable[[T], str]) -> Order[T, str]:
    return Order(
        position=ident,
        dump=lambda pos: (None, pos),
        load=lambda body: body.id if body.at is None else None,
    )


def _refused(reason: str) -> HTTPException:
    return HTTPException(422, f"invalid cursor: {reason}")


def _encode_cursor(body: _CursorBody) -> str:
    return base64.urlsafe_b64encode(body.model_dump_json().encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> _CursorBody:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        return _CursorBody.model_validate_json(raw)
    except (binascii.Error, ValueError, ValidationError) as e:
        raise _refused("not a cursor this API issued") from e


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
    if cursor is not None:
        body = _decode_cursor(cursor)
        if body.of != list_name:
            raise _refused(f"issued for {body.of}, not {list_name}")
        if body.tenant != tenant_id:
            raise _refused("issued to another tenant")
        if body.filters != dict(filters):
            raise _refused("the filters changed; send the query the cursor came from")
        after = order.load(body)
        if after is None:
            raise _refused("not a position in this list")
    rows = list(fetch(after, limit + 1))
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        at, ident = order.dump(order.position(items[-1]))
        next_cursor = _encode_cursor(_CursorBody(
            v=1, of=list_name, tenant=tenant_id, filters=dict(filters), at=at, id=ident,
        ))
    return Page(items=items, next_cursor=next_cursor)
