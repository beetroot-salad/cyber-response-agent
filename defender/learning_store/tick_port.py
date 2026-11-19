"""The tick's store over the job socket (#1487 Flow 2): the port a post-step's tick calls in its job container
(`TickPort`), the relay its per-job helper answers it with (`TickRelay`), and the wire between them (`REQUESTS`).

The port has no semantics of its own (P2): every call is one request, and the helper answers it through a
`tick.StoreAdapter` it bound itself (the claim's tenant, the author lane, its own owner and thresholds), so the port
returns what the adapter returns and raises what it raises of the exceptions the tick handles (`CROSSING`, matched by
exact type, so a fault in the helper's own code never passes as one); any other is the outage `StoreUnavailable`. The
helper adds exactly three things:

- it binds the trusted values: no request has a field for a tenant, lane, owner, threshold, `by` or setting;
- it refuses a batch reference it did not issue this session with `ForeignBatch` (`TickRelay`'s registry): an id from
  `claim` or `take_over` (this session's lease) is accepted by every verb; an own-lane batch listed in review, lapsed
  or with a person's abandon request by every verb but a holder's; another reconcile lane's batch listed in review or
  with an abandon request by the reconcile verbs alone (`end_review`, `note_check`, `note_refusal`, `settle_abandon`);
- after the stop signal `claim` and `take_over` answer the store's `Stop`; every other verb answers as before.

The wire: a request is `store.<verb>` with declared fields (a holder's verb sends its batch id and token, never the
`Held`); the answer is `{"value": ...}` in a declared shape per type, decoded to exactly the adapter's types (record ids
as their id classes, datetimes aware, tuples as tuples). Finding payloads cross as JSON text, never as structures the
socket's own decoder reads. A store exception the tick handles (`CROSSING`) crosses by name with its arguments; anything
else the helper meets is `StoreUnavailable`. A lost transport or a wait that runs out latches the port dead: every later
call raises `StoreUnavailable` at once. The port answers its settings from the helper at its start, and refuses to start
(`ValueError`) when the lease is not longer than the container's stop window, so a batch the stop's unwind could not
reach always lapses to recovery."""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import logging
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from defender._clock import parse_iso_utc
from defender.job_socket import Refused
from defender.records.formats import BatchId, TenantId, WorkItemId
from defender.records.learning_causes import BATCH_CAUSES, ITEM_CAUSES, Why

from ._store import CommitRecord, Held, LaneBusy, LaneWork, LeaseLost, NotLapsed, Outcome, Stop, TenantInactive
from .tick import ForeignBatch, ListedBatch, ListedItem, StoreAdapter, StoreUnavailable

__all__ = ["CROSSING", "REQUESTS", "SETTINGS", "TickPort", "TickRelay"]

_logger = logging.getLogger(__name__)

#: The store exceptions the tick has handlers for, by name: each crosses as the adapter raised it (Flow 2).
CROSSING: dict[str, type[Exception]] = {
    "Stop": Stop, "LeaseLost": LeaseLost, "NotLapsed": NotLapsed, "LaneBusy": LaneBusy, "TenantInactive": TenantInactive,
    "LookupError": LookupError, "ValueError": ValueError}
#: The refusal codes the relay answers a store outcome with: an exception that crosses, a foreign reference, an outage.
RAISED, FOREIGN, UNAVAILABLE = "store-raised", "store-foreign", "store-unavailable"
SETTINGS = "store.settings"


class _Unreadable(Exception):  # noqa: N818 — named for the answer
    """An answer that is not the wire's declared shape."""


def _expect(ok: bool, what: str) -> None:
    if not ok:
        raise _Unreadable(what)


# --- the declared shapes: (encode, decode) per value kind ------------------------------------------------------------

Codec = tuple[Callable[[Any], Any], Callable[[Any], Any]]


def _exact(kind: type, name: str) -> Codec:
    def decode(v: Any) -> Any:
        _expect(type(v) is kind, name)
        return v
    return (lambda v: kind(v)), decode


def _optional(codec: Codec) -> Codec:
    encode, decode = codec
    return (lambda v: None if v is None else encode(v)), (lambda v: None if v is None else decode(v))


def _id(family: Any) -> Codec:
    def decode(v: Any) -> Any:
        _expect(type(v) is str, family.__name__)
        try:
            return family(v)
        except Exception as bad:  # noqa: BLE001 — a malformed id is an unreadable answer
            raise _Unreadable(f"{family.__name__}: {bad}") from None
    return (lambda v: str(v)), decode


def _float_decode(v: Any) -> float:
    _expect(type(v) in (int, float), "a number")
    return float(v)


def _time_decode(v: Any) -> _dt.datetime:
    _expect(type(v) is str, "a time")
    parsed = parse_iso_utc(v)
    if parsed is None:
        raise _Unreadable("a time")
    return parsed


def _json_decode(v: Any) -> dict[str, Any]:
    _expect(type(v) is str, "a payload")
    try:
        loaded = json.loads(v)
    except ValueError:
        raise _Unreadable("a payload") from None
    _expect(isinstance(loaded, dict), "a payload object")
    return loaded


def _rows(width: int, *cells: Codec) -> Codec:
    """A tuple of fixed-width tuples, each cell its own codec."""
    def encode(rows: Any) -> Any:
        return [[c[0](x) for c, x in zip(cells, row, strict=True)] for row in rows]

    def decode(v: Any) -> Any:
        _expect(type(v) is list, "rows")
        out = []
        for row in v:
            _expect(type(row) is list and len(row) == width, "a row")
            out.append(tuple(c[1](x) for c, x in zip(cells, row, strict=True)))
        return tuple(out)
    return encode, decode


TEXT = _exact(str, "text")
INT = _exact(int, "an integer")
BOOL = _exact(bool, "a flag")
TIME: Codec = (lambda v: v.isoformat()), _time_decode
PAYLOAD: Codec = (lambda v: json.dumps(v)), _json_decode
OPT_TEXT, OPT_INT, OPT_TIME = _optional(TEXT), _optional(INT), _optional(TIME)
BATCH, OPT_BATCH = _id(BatchId), _optional(_id(BatchId))
ITEMS = _rows(3, TEXT, TEXT, PAYLOAD)
CHANGES = _rows(3, TEXT, OPT_TEXT, OPT_TEXT)
REVERTS = _optional(_rows(2, TEXT, TEXT))


@dataclasses.dataclass(frozen=True)
class _Record:
    """A dataclass's declared wire shape: every field and its codec, sent as an object of exactly those keys."""

    kind: type
    fields: Mapping[str, Codec]

    def encode(self, value: Any) -> dict[str, Any]:
        return {name: codec[0](getattr(value, name)) for name, codec in self.fields.items()}

    def decode(self, v: Any) -> Any:
        _expect(type(v) is dict and set(v) == set(self.fields), self.kind.__name__)
        return self.kind(**{name: codec[1](v[name]) for name, codec in self.fields.items()})

    @property
    def codec(self) -> Codec:
        return self.encode, self.decode


HELD = _Record(Held, {
    "tenant_id": _id(TenantId), "batch_id": BATCH, "lane": TEXT, "kind": TEXT, "branch": TEXT, "token": INT,
    "owner": TEXT, "items": ITEMS, "replaces": OPT_BATCH, "feedback_pr": OPT_INT})
LISTED = _Record(ListedBatch, {
    "id": BATCH, "tenant_id": _id(TenantId), "kind": TEXT, "lane": TEXT, "branch": TEXT, "base": OPT_TEXT,
    "start": OPT_TEXT, "phase": TEXT, "outcome": OPT_TEXT, "lease_expiry": OPT_TIME, "cancel_requested": BOOL,
    "pr_number": OPT_INT, "replaces": OPT_BATCH, "generation": INT, "refusals": INT, "last_checked": OPT_TIME,
    "reason": OPT_TEXT, "created_at": TIME, "ended_at": OPT_TIME, "lapsed": BOOL, "cause": OPT_TEXT,
    "parked_at": OPT_TIME, "abandon_requested_at": OPT_TIME, "abandon_requested_by": OPT_TEXT})
LISTED_ITEM = _Record(ListedItem, {
    "id": _id(WorkItemId), "kind": TEXT, "key": TEXT, "status": TEXT, "reason": OPT_TEXT, "fault": OPT_TEXT,
    "batch_id": OPT_BATCH, "pr_number": OPT_INT, "attempts": INT, "deferrals": INT, "offers_declined": INT,
    "coalesce_key": OPT_TEXT, "mistake_key": OPT_TEXT, "source_run": OPT_TEXT,
    "enqueued_at": TIME, "updated_at": TIME, "cause": OPT_TEXT})
LANE_WORK = _Record(LaneWork, {
    "busy": BOOL, "claimable": BOOL, "replaces": OPT_BATCH, "replaces_pr": OPT_INT, "replaces_generation": INT})
COMMIT = _Record(CommitRecord, {
    "commit": TEXT, "branch": TEXT, "base": TEXT, "start": TEXT, "batch_id": OPT_BATCH, "changes": CHANGES,
    "reverts": REVERTS})


def _list_of(record: _Record) -> Codec:
    def decode(v: Any) -> list[Any]:
        _expect(type(v) is list, f"a list of {record.kind.__name__}")
        return [record.decode(x) for x in v]
    return (lambda vs: [record.encode(x) for x in vs]), decode


def _none_decode(v: Any) -> None:
    _expect(v is None, "nothing")


NONE: Codec = (lambda _v: None), _none_decode


def _settings_decode(v: Any) -> dict[str, Any]:
    _expect(type(v) is dict and set(v) == {"renew_every", "generation_ceiling", "lease", "stop_window"}, "settings")
    return {"renew_every": _float_decode(v["renew_every"]), "generation_ceiling": INT[1](v["generation_ceiling"]),
            "lease": _float_decode(v["lease"]), "stop_window": _float_decode(v["stop_window"])}

REFUSALS = _rows(2, INT, TEXT)
#: Each verb's answer, by request name.
ANSWERS: dict[str, Codec] = {
    "store.batches": _list_of(LISTED), "store.lane_work": LANE_WORK.codec, "store.work": _list_of(LISTED_ITEM),
    "store.commit_record": _list_of(COMMIT), "store.claim": _optional(HELD.codec), "store.take_over": HELD.codec,
    "store.note_refusal": ((lambda v: REFUSALS[0]([v])[0]), (lambda v: REFUSALS[1]([v])[0])),
    "store.end_review": BOOL, "store.settle_abandon": BOOL, SETTINGS: ((lambda v: dict(v)), _settings_decode)}
_HOLDER = ("batch", "token")
#: Every request the port sends and the fields it takes (all required; a value may be null where the verb's is).
REQUESTS: dict[str, tuple[str, ...]] = {
    SETTINGS: (), "store.batches": (), "store.lane_work": (), "store.work": ("statuses", "kind"),
    "store.commit_record": (), "store.claim": (), "store.take_over": ("batch",), "store.renew": _HOLDER,
    "store.record_commit": (*_HOLDER, "commit", "base", "start", "changes"),
    "store.in_review": (*_HOLDER, "pr", "outcomes"), "store.end_no_commits": (*_HOLDER, "outcomes"),
    "store.abandon_clean": _HOLDER, "store.abandon_crashed": _HOLDER, "store.expire_own": _HOLDER,
    "store.abandon": ("batch",), "store.note_check": ("batch", "reset"), "store.note_refusal": ("batch", "why"),
    "store.needs_person": ("batch", "why"),
    "store.end_review": ("batch", "expect_phase", "outcome", "published", "held", "detail", "items_why"),
    "store.settle_abandon": ("batch", "pr", "pr_state", "published", "held")}


# --- the port: the tick's store in the job container -----------------------------------------------------------------


def _held_fields(held: Any) -> dict[str, Any]:
    return {"batch": str(held.batch_id), "token": held.token}


def _outcomes(outcomes: Mapping[tuple[str, str], Outcome]) -> list[list[Any]]:
    return [[kind, key, o.name, o.reason, o.cause] for (kind, key), o in outcomes.items()]


def _wire_pairs(pairs: Sequence[tuple[str, str]]) -> list[list[str]]:
    return [[str(a), str(b)] for a, b in pairs]


def _why_row(why: Any) -> list[Any] | None:
    return None if why is None else [why.cause, why.detail]


class TickPort:
    """`tick.TickStore` over the job socket's client `ask` (`JobContainer.tick_store()`): no lifecycle of its own (each
    call is one request). Its settings are the helper's, asked once here; a lease not longer than the stop window is a
    `ValueError` naming both."""

    def __init__(self, ask: Callable[..., Any]) -> None:
        self._ask = ask
        self._dead: str | None = None
        settings = self._request(SETTINGS, {}, _settings_decode)
        lease, window = settings["lease"], settings["stop_window"]
        if not lease > window:
            raise ValueError(f"the learning store's lease ({lease:g} s) is not longer than the job container's stop "
                             f"window ({window:g} s): a batch its stop could not reach would never lapse to recovery")
        self._renew_every = settings["renew_every"]
        self._ceiling = settings["generation_ceiling"]

    @property
    def renew_every(self) -> float:
        return self._renew_every

    @property
    def generation_ceiling(self) -> int:
        return self._ceiling

    # -- one request ----------------------------------------------------------------------------------------------

    def _request(self, name: str, fields: dict[str, Any], decode: Callable[[Any], Any]) -> Any:
        if self._dead is not None:
            raise StoreUnavailable(f"the helper is not reachable ({self._dead}): {name} was not sent")
        try:
            answer = self._ask(name, **fields)
        except Refused as refused:
            raise _crossing_of(name, refused) from None
        except OSError as lost:  # the socket is gone, or the wait ran out: nothing more is sent
            self._dead = f"{type(lost).__name__}: {lost}"
            raise StoreUnavailable(f"{name} got no answer from the helper ({self._dead})") from None
        except Exception as unreadable:  # noqa: BLE001 — an answer the socket could not read is an outage
            raise StoreUnavailable(f"{name}: the helper's answer could not be read ({type(unreadable).__name__})"
                                   ) from None
        try:
            _expect(type(answer) is dict and set(answer) == {"value"}, "an answer")
            return decode(answer["value"])
        except (_Unreadable, TypeError, KeyError) as bad:
            raise StoreUnavailable(f"{name}: the helper's answer is not the wire's ({bad})") from None

    def _verb(self, name: str, **fields: Any) -> Any:
        return self._request(name, fields, ANSWERS.get(name, NONE)[1])

    # -- the census ---------------------------------------------------------------------------------------------------

    def batches(self) -> list[ListedBatch]:
        return self._verb("store.batches")

    def lane_work(self) -> LaneWork:
        return self._verb("store.lane_work")

    def work(self, *, statuses: Sequence[str] | None = None, kind: str | None = None) -> list[ListedItem]:
        return self._verb("store.work", statuses=None if statuses is None else list(statuses), kind=kind)

    def commit_record(self) -> list[CommitRecord]:
        return self._verb("store.commit_record")

    def claim(self) -> Held | None:
        return self._verb("store.claim")

    def take_over(self, batch_id: str) -> Held:
        return self._verb("store.take_over", batch=str(batch_id))

    def renew(self, held: Held) -> None:
        self._verb("store.renew", **_held_fields(held))

    def record_commit(self, held: Held, commit: str, base: str, start: str,
                      changes: Sequence[tuple[str, str | None, str | None]]) -> None:
        self._verb("store.record_commit", **_held_fields(held), commit=commit, base=base, start=start,
                   changes=[list(c) for c in changes])

    def in_review(self, held: Held, pr_number: int, outcomes: Mapping[tuple[str, str], Outcome]) -> None:
        self._verb("store.in_review", **_held_fields(held), pr=pr_number, outcomes=_outcomes(outcomes))

    def end_no_commits(self, held: Held, outcomes: Mapping[tuple[str, str], Outcome]) -> None:
        self._verb("store.end_no_commits", **_held_fields(held), outcomes=_outcomes(outcomes))

    def abandon_clean(self, held: Held) -> None:
        self._verb("store.abandon_clean", **_held_fields(held))

    def abandon_crashed(self, held: Held) -> None:
        self._verb("store.abandon_crashed", **_held_fields(held))

    def expire_own(self, held: Held) -> None:
        self._verb("store.expire_own", **_held_fields(held))

    def abandon(self, batch_id: str) -> None:
        self._verb("store.abandon", batch=str(batch_id))

    def note_check(self, batch_id: str, *, reset_refusals: bool = True) -> None:
        self._verb("store.note_check", batch=str(batch_id), reset=reset_refusals)

    def note_refusal(self, batch_id: str, why: Why[Any]) -> tuple[int, str]:
        return self._verb("store.note_refusal", batch=str(batch_id), why=_why_row(why))

    def needs_person(self, batch_id: str, why: Why[Any]) -> None:
        self._verb("store.needs_person", batch=str(batch_id), why=_why_row(why))

    def end_review(self, batch_id: str, *, expect_phase: str, outcome: str, published: Sequence[tuple[str, str]],
                   held: Sequence[tuple[str, str]], detail: str | None = None,
                   items_why: Why[Any] | None = None) -> bool:
        return self._verb("store.end_review", batch=str(batch_id), expect_phase=expect_phase, outcome=outcome,
                          published=_wire_pairs(published), held=_wire_pairs(held), detail=detail, items_why=_why_row(items_why))

    def settle_abandon(self, batch_id: str, *, pr_number: int | None, pr_state: str | None,
                       published: Sequence[tuple[str, str]] = (), held: Sequence[tuple[str, str]] = ()) -> bool:
        return self._verb("store.settle_abandon", batch=str(batch_id), pr=pr_number, pr_state=pr_state,
                          published=_wire_pairs(published), held=_wire_pairs(held))


def _crossing_of(name: str, refused: Refused) -> Exception:
    """The exception a refusal stands for: a crossing store exception as it was raised, a foreign reference, else the
    outage exception (the helper's own refusal of a request it was sent is no answer the tick can use)."""
    if refused.code == FOREIGN:
        return ForeignBatch(str(refused))
    if refused.code == RAISED:
        crossed = _raised_of(str(refused))
        if crossed is not None:
            return crossed
    return StoreUnavailable(f"the helper did not answer {name} ({refused.code}): {refused}")


def _raised_of(reason: str) -> Exception | None:
    """The store exception a `store-raised` refusal names (`{"type": name, "args": [...]}`), or None if it is not one."""
    try:
        raised = json.loads(reason)
    except ValueError:
        return None
    if not isinstance(raised, dict):
        return None
    name, args = raised.get("type"), raised.get("args")
    kind = CROSSING.get(name) if isinstance(name, str) else None
    if kind is None or not isinstance(args, list):
        return None
    exception: Exception = kind(*args)
    return exception


# --- the relay: the helper's side ------------------------------------------------------------------------------------


def _bad(what: str) -> Refused:
    return Refused(f"a store request's {what}", "bad-fields")


def _need(ok: bool, what: str) -> None:
    if not ok:
        raise _bad(what)


def _field_text(v: Any, what: str) -> str:
    _need(type(v) is str, f"{what} is text")
    return v


def _opt_text(v: Any, what: str) -> str | None:
    return None if v is None else _field_text(v, what)


def _wire_int(v: Any, what: str) -> int:
    _need(type(v) is int, f"{what} is an integer")
    return v


def _pair_list(v: Any, what: str) -> list[tuple[str, str]]:
    _need(type(v) is list, f"{what} is a list")
    out = []
    for p in v:
        _need(type(p) is list and len(p) == 2, f"{what} holds pairs")
        out.append((_field_text(p[0], what), _field_text(p[1], what)))
    return out


def _changes(v: Any) -> list[tuple[str, str | None, str | None]]:
    _need(type(v) is list, "changes are a list")
    out = []
    for c in v:
        _need(type(c) is list and len(c) == 3, "a change is (path, base blob, left blob)")
        out.append((_field_text(c[0], "a path"), _opt_text(c[1], "a blob"), _opt_text(c[2], "a blob")))
    return out


def _outcome_map(v: Any) -> dict[tuple[str, str], Outcome]:
    _need(type(v) is list, "outcomes are a list")
    out: dict[tuple[str, str], Outcome] = {}
    for o in v:
        _need(type(o) is list and len(o) == 5, "an outcome is (kind, key, name, detail, cause)")
        kind, key, name = _field_text(o[0], "a kind"), _field_text(o[1], "a key"), _field_text(o[2], "an outcome")
        cause = _opt_text(o[4], "a cause")
        _need(cause is None or cause in ITEM_CAUSES, "an item cause is one of the store's")
        try:
            out[(kind, key)] = Outcome(name, _opt_text(o[3], "a detail"), cause)  # type: ignore[arg-type]
        except ValueError as bad:
            raise _bad(f"outcome: {bad}") from None
    return out


def _why_of(v: Any, causes: tuple[str, ...], build: Callable[[Any, str], Why[Any]]) -> Why[Any]:
    """A `(cause, detail)` row as the table's `Why` (`build`: `Why.batch` or `Why.item`), its cause one of `causes`."""
    _need(type(v) is list and len(v) == 2, "why is (cause, detail)")
    _need(v[0] in causes, "cause is one of the store's")
    return build(_field_text(v[0], "a cause"), _field_text(v[1], "a detail"))


@dataclasses.dataclass
class _Issued:
    """The batch references this session gave out (Flow 2): leases by id (the `Held` the store answered), and listed ids
    by the reach their listing gave them."""

    leased: dict[str, Held] = dataclasses.field(default_factory=dict)
    own: set[str] = dataclasses.field(default_factory=set)
    other: set[str] = dataclasses.field(default_factory=set)


class TickRelay:
    """The helper's answers to the port's requests, for one session: `adapter()` builds the bound adapter at the first
    request (the helper's own database login and settings); `signalled()` tells whether the stop signal came;
    `stop_window` is the container's stop grace; `reconcile_lanes` the lanes the author tick reconciles. Thread-safe:
    the helper answers each connection on a thread of its own."""

    def __init__(self, adapter: Callable[[], StoreAdapter], *, signalled: Callable[[], bool], stop_window: float,
                 reconcile_lanes: Sequence[str]) -> None:
        self._make = adapter
        self._adapter: StoreAdapter | None = None
        self._signalled = signalled
        self._window = float(stop_window)
        self._reconciled = frozenset(reconcile_lanes)
        self._lock = threading.Lock()
        self._issued = _Issued()

    def adapter(self) -> StoreAdapter:
        with self._lock:
            if self._adapter is None:
                self._adapter = self._make()
            return self._adapter

    def answer(self, name: str, fields: Mapping[str, Any]) -> dict[str, Any]:
        """`{"value": ...}`, the adapter's answer in its declared shape; or `Refused`: `bad-fields`, a crossing store
        exception (`store-raised`), a foreign reference (`store-foreign`), anything else an outage."""
        verb = _VERBS[name]
        try:
            value = verb(self, fields)
        except Refused:
            raise
        except ForeignBatch as foreign:
            raise Refused(str(foreign), FOREIGN) from None
        except Exception as raised:  # noqa: BLE001 — every other fault is the one outage exception at the port
            raise _crossed(name, raised) from None
        return {"value": ANSWERS.get(name, NONE)[0](value)}

    # -- the registry --------------------------------------------------------------------------------------------

    def leased(self, fields: Mapping[str, Any]) -> Held:
        """The `Held` a holder's verb acts with: this session's lease of the batch, with the token the tick presents."""
        batch, token = _field_text(fields["batch"], "batch"), _wire_int(fields["token"], "token")
        with self._lock:
            held = self._issued.leased.get(batch)
        if held is None:
            raise ForeignBatch(f"batch {batch} is not leased by this session")
        return dataclasses.replace(held, token=token)

    def issued(self, fields: Mapping[str, Any], *, other_lanes: bool) -> str:
        """The batch id a by-id verb acts on, if this session issued it with that reach."""
        batch = _field_text(fields["batch"], "batch")
        with self._lock:
            ok = (batch in self._issued.leased or batch in self._issued.own
                  or (other_lanes and batch in self._issued.other))
        if not ok:
            raise ForeignBatch(f"batch {batch} was not issued to this session for this request")
        return batch

    def listed(self, views: list[ListedBatch]) -> list[ListedBatch]:
        own_lane = self.adapter().lane
        with self._lock:
            for b in views:
                reviewed = b.phase == "in_review" or b.abandon_pending
                if b.lane == own_lane and (reviewed or b.lapsed):
                    self._issued.own.add(str(b.id))
                elif b.lane in self._reconciled and reviewed:
                    self._issued.other.add(str(b.id))
        return views

    def lease(self, held: Held | None) -> Held | None:
        if held is not None:
            with self._lock:
                self._issued.leased[str(held.batch_id)] = held
        return held

    def no_lease_after_stop(self) -> None:
        if self._signalled():
            raise Stop("the helper was told to stop: no new lease is taken")

    def settings(self) -> dict[str, Any]:
        a = self.adapter()
        return {"renew_every": a.renew_every, "generation_ceiling": a.generation_ceiling, "lease": a.lease,
                "stop_window": self._window}


def _crossed(name: str, raised: Exception) -> Refused:
    kind = type(raised).__name__
    if CROSSING.get(kind) is type(raised):
        args = [a if a is None or type(a) in (bool, int, float) else str(a) for a in raised.args]
        return Refused(json.dumps({"type": kind, "args": args}), RAISED)
    if not isinstance(raised, StoreUnavailable):
        _logger.warning("the tick's store request %s failed in the helper", name, exc_info=raised)
    return Refused(f"{name}: the learning store could not answer ({kind})", UNAVAILABLE)


def _relay_claim(r: TickRelay, _f: Mapping[str, Any]) -> Any:
    r.no_lease_after_stop()
    return r.lease(r.adapter().claim())


def _take_over(r: TickRelay, f: Mapping[str, Any]) -> Any:
    r.no_lease_after_stop()
    return r.lease(r.adapter().take_over(r.issued(f, other_lanes=False)))


def _work(r: TickRelay, f: Mapping[str, Any]) -> Any:
    statuses = f["statuses"]
    if statuses is not None:
        _need(type(statuses) is list, "statuses are a list")
        statuses = [_field_text(s, "a status") for s in statuses]
    return r.adapter().work(statuses=statuses, kind=_opt_text(f["kind"], "kind"))


def _record_commit(r: TickRelay, f: Mapping[str, Any]) -> Any:
    held = r.leased(f)
    return r.adapter().record_commit(held, _field_text(f["commit"], "commit"), _field_text(f["base"], "base"),
                                     _field_text(f["start"], "start"), _changes(f["changes"]))


def _end_review(r: TickRelay, f: Mapping[str, Any]) -> Any:
    batch = r.issued(f, other_lanes=True)
    items_why = None if f["items_why"] is None else _why_of(f["items_why"], ITEM_CAUSES, Why.item)
    return r.adapter().end_review(
        batch, expect_phase=_field_text(f["expect_phase"], "expect_phase"), outcome=_field_text(f["outcome"], "outcome"),
        published=_pair_list(f["published"], "published"), held=_pair_list(f["held"], "held"),
        detail=_opt_text(f["detail"], "detail"), items_why=items_why)


def _settle_abandon(r: TickRelay, f: Mapping[str, Any]) -> Any:
    batch = r.issued(f, other_lanes=True)
    pr = None if f["pr"] is None else _wire_int(f["pr"], "pr")
    return r.adapter().settle_abandon(batch, pr_number=pr, pr_state=_opt_text(f["pr_state"], "pr_state"),
                                      published=_pair_list(f["published"], "published"),
                                      held=_pair_list(f["held"], "held"))


def _commit_record(r: TickRelay, _f: Mapping[str, Any]) -> Any:
    return r.adapter().commit_record()


def _note_check(r: TickRelay, f: Mapping[str, Any]) -> Any:
    _need(type(f["reset"]) is bool, "reset is a flag")
    return r.adapter().note_check(r.issued(f, other_lanes=True), reset_refusals=f["reset"])


_VERBS: dict[str, Callable[[TickRelay, Mapping[str, Any]], Any]] = {
    SETTINGS: lambda r, _f: r.settings(),
    "store.batches": lambda r, _f: r.listed(r.adapter().batches()),
    "store.lane_work": lambda r, _f: r.adapter().lane_work(),
    "store.work": _work,
    "store.commit_record": _commit_record,
    "store.claim": _relay_claim,
    "store.take_over": _take_over,
    "store.renew": lambda r, f: r.adapter().renew(r.leased(f)),
    "store.record_commit": _record_commit,
    "store.in_review": lambda r, f: r.adapter().in_review(r.leased(f), _wire_int(f["pr"], "pr"), _outcome_map(f["outcomes"])),
    "store.end_no_commits": lambda r, f: r.adapter().end_no_commits(r.leased(f), _outcome_map(f["outcomes"])),
    "store.abandon_clean": lambda r, f: r.adapter().abandon_clean(r.leased(f)),
    "store.abandon_crashed": lambda r, f: r.adapter().abandon_crashed(r.leased(f)),
    "store.expire_own": lambda r, f: r.adapter().expire_own(r.leased(f)),
    "store.abandon": lambda r, f: r.adapter().abandon(r.issued(f, other_lanes=False)),
    "store.note_check": _note_check,
    "store.note_refusal": lambda r, f: r.adapter().note_refusal(r.issued(f, other_lanes=True),
                                                                _why_of(f["why"], BATCH_CAUSES, Why.batch)),
    "store.needs_person": lambda r, f: r.adapter().needs_person(r.issued(f, other_lanes=False),
                                                                _why_of(f["why"], BATCH_CAUSES, Why.batch)),
    "store.end_review": _end_review,
    "store.settle_abandon": _settle_abandon,
}
