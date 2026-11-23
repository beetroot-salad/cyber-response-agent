"""#1592 test oracle: gob's integer encoding, written from the `encoding/gob` package documentation and nothing
else, and Forgejo session rows built from P31's real bytes (`probe1592g/stage-hex.txt`, Forgejo 17.0.0).

The oracle shares no code with the product's session reader. It is anchored on the documentation's worked examples and
on P31's sample (`KNOWN_UINTS`), which `test_1592_sessions.py` asserts.
"""
from __future__ import annotations

#: `encoding/gob`: "0 is transmitted as (00), 7 is transmitted as (07) and 256 is transmitted as (FE 01 00)".
#: P31: the signed-in row of Forgejo user 2 holds the gob int 2, the unsigned value 4.
KNOWN_UINTS = {0: b"\x00", 7: b"\x07", 256: b"\xfe\x01\x00", 4: b"\x04"}

#: The design's `UID_ENTRY` as P31 shows it (gob string `uid`, interface type name `int64`, type id 4), spelled here
#: independently of the product's constant.
UID_ENTRY = b"\x03uid\x05int64\x04"

#: The largest Forgejo user id (Go `int64`).
MAX_UID = 2**63 - 1


def gob_uint(value: int) -> bytes:
    """An unsigned integer: below 128 one byte; otherwise its minimal big-endian bytes after their count, negated."""
    if value < 0:
        raise ValueError("an unsigned integer")
    if value < 128:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([256 - len(body)]) + body


def gob_int(value: int) -> bytes:
    """A signed integer: the unsigned value `i << 1`, or `(^i << 1) | 1` for a negative `i`."""
    return gob_uint(value << 1 if value >= 0 else ((~value) << 1) | 1)


def uid_value(uid: int) -> bytes:
    """What follows `UID_ENTRY` in a row of user `uid`: the value's byte count L, the field delta 0, then the int."""
    encoded = gob_int(uid)
    return bytes([1 + len(encoded)]) + b"\x00" + encoded


#: P31 "after-callback-signed-in" (and "page-load", byte-identical): `{uid: int64(2), _gothic_session}`.
SIGNED_IN_P31 = bytes.fromhex(
    "0d7f040102ff8000011001100000ff87ff80000206737472696e670c05000375696405696e7436340402000406737472696e670c11000f5f"
    "676f746869635f73657373696f6e112a73657373696f6e732e53657373696f6eff810301010753657373696f6e01ff8200010401024944"
    "010c00010656616c75657301ff800001074f7074696f6e7301ff8400010549734e6577010200000069ff83030101074f7074696f6e7301"
    "ff84000107010450617468010c000106446f6d61696e010c0001064d617841676501040001065365637572650102000108487474704f6e"
    "6c79010200010b506172746974696f6e6564010200010853616d655369746501040000001cff82190110626331363630396636323463"
    "3633386401000103010000")

#: P31 "oauth-start": uid-less, `_gothic_session` and the OAuth state (what an anonymous sign-in start leaves).
ANONYMOUS_P31 = bytes.fromhex(
    "0d7f040102ff80000110011000006fff80000306737472696e670c11000f5f676f746869635f73657373696f6e112a73657373696f6e73"
    "2e53657373696f6eff810301010753657373696f6e01ff8200010401024944010c00010656616c75657301ff800001074f7074696f6e73"
    "01ff8400010549734e6577010200000069ff83030101074f7074696f6e7301ff84000107010450617468010c000106446f6d61696e010c"
    "0001064d617841676501040001065365637572650102000108487474704f6e6c79010200010b506172746974696f6e6564010200010853"
    "616d65536974650104000000fe01dfff82fe0166011062633136363039663632346336333864010106737472696e670c0a00086b657963"
    "6c6f616b06737472696e670cfe013100fe012d1f8b08000000000000ff4c8e518be2301485ff4b204f5a9aa6b6da42590abb85857d12f7"
    "651890f4f6c6c6c6de90a43032cc7f1f541c84c37d38e772bef3c9da258efff7ff58cdc6185d9da6ce538f5951c95332419ded8aaa483d"
    "2a7b098fe8762301d9941cce664880e61921a66a89e32fb006e7783443a3c99ff04cef8b10b2f438188f108f8b37cd0dc4f396cb8ecbee"
    "05a7cf3c6fb3bca80a2ebb25a0e7b2a35babe4b29bf00a96d4c46507cada5ec1f4ac0e8ee680c77875d8000df8f00390c3e6b171851765"
    "ecca79d2c63ef3a8223665a97765914152f5559e6c36629b28cc74a2256cb322affa52946ccd5a000ce14013ceac666ccdf6a83d86f1c5"
    "f9f3e18cc7d0465633214496dc7510a2beeb8dadd9dfdf3fff5fdf000000ffff010000ffff2bf9f3787a01000001000006737472696e67"
    "0c1500136f617574685f7369676e696e5f73696c656e7404626f6f6c0202000006737472696e670c0e000c436f64655665726966696572"
    "06737472696e670c2d002b3564634f63685f313874726931417055357862755034554b33445365584c4a4d5635704e2d44563072522d")

#: Where P31's signed-in row puts things: its first message (the map type) is 14 bytes; the map message's length
#: prefix follows (`ff 87`, 135); `02 00 04` (user 2) follows the one `UID_ENTRY`.
_MAP_LENGTH_AT = 14
_P31_TAIL = b"\x02\x00\x04"


def _spliced(tail: bytes) -> bytes:
    """P31's signed-in row with the bytes after `UID_ENTRY` (`02 00 04`) replaced by `tail`, the map message's length
    prefix rewritten to match (a Forgejo row's framing stays well formed)."""
    data = SIGNED_IN_P31
    at = data.index(UID_ENTRY) + len(UID_ENTRY)
    assert data[at:at + 3] == _P31_TAIL, "P31's sample changed"
    assert data[_MAP_LENGTH_AT:_MAP_LENGTH_AT + 2] == gob_uint(135), "P31's sample changed"
    length = 135 - len(_P31_TAIL) + len(tail)
    head = data[:_MAP_LENGTH_AT] + gob_uint(length) + data[_MAP_LENGTH_AT + 2:at]
    return head + tail + data[at + 3:]


def signed_in_data(uid: int) -> bytes:
    """A signed-in session row of Forgejo user `uid` (1..`MAX_UID`): P31's row with the uid re-encoded by the oracle."""
    if not 0 < uid <= MAX_UID:
        raise ValueError("a Forgejo user id is a positive int64")
    return _spliced(uid_value(uid))


def uid_tail_row(tail: bytes) -> bytes:
    """A row holding `UID_ENTRY` once, followed by arbitrary `tail` bytes in place of a well-formed value (for the
    reader's refusals: wrong L, a nonzero delta, an odd or zero value, a truncated int)."""
    return _spliced(tail)
