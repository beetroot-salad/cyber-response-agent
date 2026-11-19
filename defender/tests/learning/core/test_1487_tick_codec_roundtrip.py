"""#1487 Flow 2: the tick port's wire. Every value the helper answers crosses in a declared shape per type and is decoded
to exactly the adapter's types (record ids as their id classes, datetimes aware, tuples as tuples). A round-trip
property over every codec `learning_store.tick_port` declares: generated values of each codec's type, encoded,
carried through the job socket's own JSON encoding (`job_socket._encode_value`, `json`, `job_socket._decode`) and
decoded, come back equal and of the same types, element by element. hypothesis is not in the venv, so the values are
drawn from a seeded `random.Random` (the seed is in each failure). The generators are driven by the declared types
(each record's dataclass fields, each answer's value type), never by the codecs under test."""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import random
import types
import typing
import uuid
from collections.abc import Callable
from typing import Any

import pytest

SEED = 1487
DRAWS = 200

Gen = Callable[[random.Random], Any]


def _port() -> Any:
    from defender.learning_store import tick_port

    return tick_port


# --- values of a declared type ---------------------------------------------------------------------------------------

_TEXTS = ("", "a", "lessons/abc", "line\nbreak", 'quote " and \\ backslash', "ünïcödé ✓", "{\"not\": \"json\"}",
          "$bytes", "\u0000nul", " ")


def _text(rng: random.Random) -> str:
    if rng.random() < 0.4:
        return rng.choice(_TEXTS)
    return "".join(rng.choice("abcXYZ019 -_/:.é✓\"\\\n") for _ in range(rng.randint(0, 24)))


def _int(rng: random.Random) -> int:
    return rng.choice((0, 1, -1, rng.randint(-10**6, 10**6), rng.randint(0, 2**62), -(2**53) - 1))


def _float(rng: random.Random) -> float:
    return rng.choice((0.0, 0.5, 600.0, rng.uniform(0, 10**6), float(rng.randint(1, 10**4))))


#: 1970 to 2100, any second.
_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)
_SPAN = int((_dt.datetime(2100, 1, 1, tzinfo=_dt.UTC) - _EPOCH).total_seconds())


def _time(rng: random.Random) -> _dt.datetime:
    """An aware datetime: a varied instant, microseconds zero or not, an offset from -14h to +14h in minutes (UTC too)."""
    micro = rng.choice((0, rng.randint(1, 999_999)))
    instant = _EPOCH + _dt.timedelta(seconds=rng.randint(0, _SPAN), microseconds=micro)
    offset = rng.choice((0, rng.randint(-14 * 60, 14 * 60)))
    zone = _dt.UTC if offset == 0 and rng.random() < 0.5 else _dt.timezone(_dt.timedelta(minutes=offset))
    return instant.astimezone(zone)


def _json_value(rng: random.Random, depth: int = 0) -> Any:
    pick = rng.randint(0, 7 if depth < 3 else 4)
    if pick == 0:
        return None
    if pick == 1:
        return rng.random() < 0.5
    if pick == 2:
        return _int(rng)
    if pick == 3:
        return _text(rng)
    if pick == 4:
        return rng.uniform(-1e6, 1e6)
    if pick == 5:
        return [_json_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return _payload(rng, depth + 1)


def _payload(rng: random.Random, depth: int = 0) -> dict[str, Any]:
    """A finding's payload: a JSON object, sometimes keyed like the socket's own bytes marker."""
    out = {_text(rng): _json_value(rng, depth) for _ in range(rng.randint(0, 4))}
    if rng.random() < 0.2:
        out["$bytes"] = "aGk="
    return out


def _uuid_text(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _of_type(tp: Any) -> Gen:  # noqa: C901, PLR0911 — one arm per kind of declared type
    """A generator of values of the declared type `tp`."""
    from defender.records._record_ids import UuidId

    origin, args = typing.get_origin(tp), typing.get_args(tp)
    if origin in (typing.Union, types.UnionType):
        inner = [a for a in args if a is not type(None)]
        assert len(inner) == 1, tp
        gen = _of_type(inner[0])
        return lambda rng: None if rng.random() < 0.3 else gen(rng)
    if origin is typing.Literal:
        return lambda rng: rng.choice(args)
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            cell = _of_type(args[0])
            return lambda rng: tuple(cell(rng) for _ in range(rng.randint(0, 3)))
        cells = [_of_type(a) for a in args]
        return lambda rng: tuple(c(rng) for c in cells)
    if origin is list:
        cell = _of_type(args[0])
        return lambda rng: [cell(rng) for _ in range(rng.randint(0, 3))]
    if origin is dict:
        assert args == (str, Any), tp
        return _payload
    if dataclasses.is_dataclass(tp):
        return _record_of(tp)
    if isinstance(tp, type) and issubclass(tp, UuidId):
        return lambda rng: tp(_uuid_text(rng))
    simple = {str: _text, int: _int, bool: lambda rng: rng.random() < 0.5, float: _float, _dt.datetime: _time}
    assert tp in simple, f"no generator for the declared type {tp!r}"
    return simple[tp]


def _record_of(cls: type) -> Gen:
    hints = typing.get_type_hints(cls)
    fields = {f.name: _of_type(hints[f.name]) for f in dataclasses.fields(cls)}
    return lambda rng: cls(**{name: gen(rng) for name, gen in fields.items()})


def _settings(rng: random.Random) -> dict[str, Any]:
    return {"renew_every": _float(rng), "generation_ceiling": _int(rng), "lease": _float(rng),
            "stop_window": _float(rng)}


# --- every declared codec and the type of its values ------------------------------------------------------------------


def _types() -> dict[str, Any]:
    """Each module-level codec's value type, by its name in `tick_port`, as the port's docstrings declare them."""
    from defender.learning_store import CommitRecord, Held, LaneWork
    from defender.learning_store.tick import ListedBatch, ListedItem
    from defender.records.formats import BatchId

    return {
        "TEXT": str, "INT": int, "BOOL": bool, "TIME": _dt.datetime, "PAYLOAD": dict[str, Any],
        "OPT_TEXT": str | None, "OPT_INT": int | None, "OPT_TIME": _dt.datetime | None,
        "BATCH": BatchId, "OPT_BATCH": BatchId | None,
        "ITEMS": tuple[tuple[str, str, dict[str, Any]], ...], "CHANGES": tuple[tuple[str, str | None, str | None], ...],
        "REVERTS": tuple[tuple[str, str], ...] | None, "REFUSALS": tuple[tuple[int, str], ...],
        "NONE": type(None),
        "HELD": Held, "LISTED": ListedBatch, "LISTED_ITEM": ListedItem, "LANE_WORK": LaneWork, "COMMIT": CommitRecord,
    }


def _answer_types() -> dict[str, Any]:
    """Each verb's answer type (`TickStore`'s signatures), by request name."""
    from defender.learning_store import CommitRecord, Held, LaneWork
    from defender.learning_store.tick import ListedBatch, ListedItem

    return {
        "store.batches": list[ListedBatch], "store.lane_work": LaneWork, "store.work": list[ListedItem],
        "store.commit_record": list[CommitRecord], "store.claim": Held | None, "store.take_over": Held,
        "store.note_refusal": tuple[int, str], "store.end_review": bool, "store.settle_abandon": bool,
        "store.settings": "settings",
    }


def _is_codec(value: Any) -> bool:
    return (isinstance(value, tuple) and len(value) == 2 and all(callable(x) for x in value))


def _declared() -> dict[str, tuple[Any, Any]]:
    """Every codec the module declares (`(encode, decode)` pairs and records), and every answer's: `(codec, type)`."""
    port = _port()
    out: dict[str, tuple[Any, Any]] = {}
    for name in dir(port):
        value = getattr(port, name)
        if isinstance(value, port._Record):
            out[name] = (value.codec, _types().get(name))
        elif _is_codec(value) and name.isupper():
            out[name] = (value, _types().get(name))
    for name, codec in port.ANSWERS.items():
        out[f"answer:{name}"] = (codec, _answer_types().get(name))
    return out


def _gen(tp: Any) -> Gen:
    if tp == "settings":
        return _settings
    if tp is type(None):
        return lambda _rng: None
    return _of_type(tp)


def _wire(encoded: Any) -> Any:
    """What the other side of the job socket reads: the socket's own value encoding, as JSON text, decoded back."""
    from defender.job_socket import _decode, _encode_value

    return _decode(json.loads(json.dumps(_encode_value({"value": encoded}), separators=(",", ":"))))["value"]


def _same(a: Any, b: Any, where: str = "value") -> None:
    """`a == b` and of the same types throughout (an id class, not a bare `str`; a tuple, not a list; aware times)."""
    assert type(a) is type(b), f"{where}: {type(a).__name__} came back as {type(b).__name__}"
    if dataclasses.is_dataclass(a):
        for f in dataclasses.fields(a):
            _same(getattr(a, f.name), getattr(b, f.name), f"{where}.{f.name}")
    elif isinstance(a, (list, tuple)):
        assert len(a) == len(b), f"{where}: {len(a)} items came back as {len(b)}"
        for n, (x, y) in enumerate(zip(a, b, strict=True)):
            _same(x, y, f"{where}[{n}]")
    elif isinstance(a, dict):
        assert list(a) == list(b), f"{where}: keys {list(a)} came back as {list(b)}"
        for k in a:
            _same(a[k], b[k], f"{where}[{k!r}]")
    elif isinstance(a, _dt.datetime):
        assert b.tzinfo is not None, f"{where}: an aware time came back naive"
        assert a == b, f"{where}: {a.isoformat()} came back as {b.isoformat()}"
    else:
        assert a == b, f"{where}: {a!r} came back as {b!r}"


def test_g9_every_declared_codec_has_a_value_type():
    """Premise of the property: every codec the module declares, and every answer's, is in the property below, so a
    codec added later without a value type fails here rather than going unchecked."""
    missing = sorted(name for name, (_codec, tp) in _declared().items() if tp is None)
    assert not missing, f"codecs with no declared value type in this test: {missing}"
    assert {"TIME", "HELD", "LISTED", "LISTED_ITEM", "LANE_WORK", "COMMIT", "PAYLOAD", "BATCH"} <= set(_declared())


@pytest.mark.parametrize("name", sorted(_declared()))
def test_g9_decode_of_encode_is_the_value_over_the_wire(name):
    """Seeded values of the codec's type, through the job socket's JSON: `decode(encode(v)) == v`, same types."""
    (encode, decode), tp = _declared()[name]
    assert tp is not None, f"premise: {name} has a value type"
    gen = _gen(tp)
    rng = random.Random(f"{SEED}:{name}")
    for draw in range(DRAWS):
        value = gen(rng)
        back = decode(_wire(encode(value)))
        _same(value, back, f"{name} draw {draw} (seed {SEED}:{name})")
