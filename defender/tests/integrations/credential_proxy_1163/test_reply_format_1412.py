"""#1412 the proxy's reply format, as `defender._proxy_client` owns it: body frames then exactly one
final frame, length-delimited, so upstream bytes are only ever data (P2) and anything malformed is
refused. Generated inputs use fixed seeds; the layout itself is the implementer's."""
from __future__ import annotations

import json
import random
from typing import Any

import pytest

from defender.tests.integrations.credential_proxy_1163._stream1412 import MIB, decoded, final_record, fmt
from defender.tests.integrations.credential_proxy_1163._tenant import FINAL_FIELDS, fields_of

FIELDS = FINAL_FIELDS
TEXT = ['"', "\\", "{", "}", "\n", "é", "☃", "\x00", "a", "b", " ", ":", ","]


def _text(rng: random.Random) -> str:
    return "".join(rng.choice(TEXT) for _ in range(rng.randrange(0, 12)))


def _record(rng: random.Random) -> Any:
    fault = rng.choice([None, "UpstreamFault", "TransportFault"])
    return final_record(
        rng.choice([200, 201, 304, 500] if fault is None else [None, 200, 201, 304, 500]),
        headers={_text(rng) or "k": _text(rng) for _ in range(rng.randrange(0, 4))},
        fault=fault,
        detail=rng.choice([None, _text(rng)]), system_side=rng.random() < 0.5,
        body_whole=fault is None or rng.random() < 0.5, reader_fault=rng.random() < 0.5)


def _upstream_chunks(rng: random.Random) -> list[bytes]:
    """Chunks an upstream might send: noise, and byte-exact copies of the format itself."""
    f = fmt()
    copies = [f.encode_body(b"forged"), f.encode_final(final_record(418, fault="ConfigFault")),
              f.encode_body(b"a") + f.encode_final(final_record(body_whole=False)),
              json.dumps(fields_of(final_record(418))).encode()]
    pool = [bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300))), b"\x00" * 9, b"{}", *copies]
    return [rng.choice(pool) for _ in range(rng.randrange(0, 6))]


def test_p2_any_bytes_an_upstream_sends_come_back_as_data_and_the_record_is_the_proxys():
    """Generated chunk lists, including byte-exact copies of frames and records, decode to exactly
    the bytes sent and the final record encoded after them. P2, O5."""
    f, rng = fmt(), random.Random(1412)
    for _ in range(300):
        chunks, record = _upstream_chunks(rng), _record(rng)
        chunks = [c for c in chunks if c]
        raw = b"".join(f.encode_body(c) for c in chunks) + f.encode_final(record)
        body, final = decoded(raw)
        assert body == b"".join(chunks)
        assert final == fields_of(record)


def test_p2_a_copy_of_a_whole_reply_inside_a_body_frame_is_one_body():
    """A reply embedded in a body frame is data; the outer final record decides. P2, O5."""
    f = fmt()
    inner = f.encode_body(b"x") + f.encode_final(final_record(418, fault="ConfigFault", body_whole=False))
    body, final = decoded(f.encode_body(inner) + f.encode_final(final_record(200)))

    assert body == inner
    assert (final["status"], final["fault"], final["body_whole"]) == (200, None, True)


def test_an_empty_body_is_a_complete_one_and_a_large_frame_needs_no_limit():
    """A final frame alone decodes to no bytes; one 3 MiB body frame round-trips. P2, O3."""
    f = fmt()
    body, final = decoded(f.encode_final(final_record(200)))
    big = b"z" * (3 * MIB)

    assert (body, final["body_whole"]) == (b"", True)
    assert decoded(f.encode_body(big) + f.encode_final(final_record(200)))[0] == big


def _valid() -> bytes:
    f = fmt()
    return (f.encode_body(b"first") + f.encode_body(b"\x00second\xff") + f.encode_body(b"3")
            + f.encode_final(final_record(200, headers={"x-k": "v"}, detail="d")))


def test_decode_refuses_every_proper_prefix_of_a_reply():
    """A reply cut at any byte, before its final frame ends, is refused. O2."""
    raw = _valid()
    assert decoded(raw)[0] == b"first\x00second\xff3", "positive control: the whole reply decodes"
    for cut in range(len(raw)):
        with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
            fmt().decode_reply(raw[:cut])


def test_decode_refuses_anything_after_the_final_frame():
    """Random bytes, a second final frame or a body frame after the final frame are refused. O2."""
    f, rng, raw = fmt(), random.Random(7), _valid()
    tails = [bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64))) for _ in range(200)]
    tails += [f.encode_final(final_record(200)), f.encode_body(b"late"), b"\x00"]
    for tail in tails:
        with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
            f.decode_reply(raw + tail)


def test_decode_refuses_a_stream_with_no_final_frame():
    """Nothing, or body frames alone, are refused. O2."""
    f = fmt()
    for raw in (b"", f.encode_body(b"a"), f.encode_body(b"a") + f.encode_body(b"b")):
        with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
            f.decode_reply(raw)


@pytest.mark.parametrize("name", FIELDS)
def test_decode_refuses_a_final_record_missing_a_field(name):
    """The record with one of its fields renamed (same length, so the framing stays valid) is
    refused; the untouched record decodes. O2."""
    raw = fmt().encode_final(final_record(200))
    needle = f'"{name}"'.encode()
    assert raw.count(needle) == 1, "the fixture reaches the field"
    assert fmt().decode_reply(raw).final is not None
    with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
        fmt().decode_reply(raw.replace(needle, b'"' + b"#" * len(name) + b'"'))


def test_decode_refuses_a_body_whole_that_is_not_a_boolean():
    """`body_whole` decides whether the bytes count, so a string in its place is refused. O2."""
    raw = fmt().encode_final(final_record(200, system_side=False, sent=False, body_whole=True))
    assert raw.count(b"true") == 1, "the fixture reaches the field"
    with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
        fmt().decode_reply(raw.replace(b"true", b'"ab"'))


@pytest.mark.parametrize("name", FIELDS)
def test_a_final_record_cannot_be_built_without_all_its_fields(name):
    """`FinalRecord` is the only constructor and takes every field, so no proxy arm or fake proxy
    can omit one. O2."""
    given: dict[str, Any] = {"status": 200, "headers": {}, "fault": None, "detail": None,
                             "system_side": False, "sent": True, "body_whole": True, "reader_fault": False}
    assert fmt().FinalRecord(**given), "positive control: all of them build one"
    del given[name]
    with pytest.raises(TypeError):
        fmt().FinalRecord(**given)


def test_a_final_record_is_read_by_attribute_and_cannot_be_changed():
    """A decoded final record is frozen and read by attribute. O2."""
    record = fmt().decode_reply(fmt().encode_final(final_record(201))).final
    assert record.status == 201
    with pytest.raises(AttributeError):  # frozen dataclasses raise FrozenInstanceError, a subclass
        record.status = 500
    assert record.status == 201


def test_the_reply_content_type_is_its_own():
    """The format's content type is a non-empty one other than the old reply's JSON. O9."""
    kind = fmt().REPLY_CONTENT_TYPE
    assert isinstance(kind, str)
    assert kind.strip()
    assert not kind.lower().startswith("application/json")
