"""#1592 OD-11 / r15.1: the session reader `defender.lifecycle.session_uid` against the independent gob oracle
(S2-17..19, S2-21). No hypothesis in this repo: generation is a seeded `random.Random` over every bit length."""
from __future__ import annotations

import random

import pytest

from defender.tests.tenancy.people_1592._gob1592 import (
    KNOWN_UINTS,
    MAX_UID,
    SIGNED_IN_P31,
    UID_ENTRY,
    gob_int,
    gob_uint,
    signed_in_data,
    uid_tail_row,
    uid_value,
)
from defender.tests.tenancy.people_1592._sessions1592 import junk, uid_edges, uids


def _reader():
    from defender.lifecycle import UnreadableSession, session_uid

    return session_uid, UnreadableSession


def test_the_oracle_matches_the_documentation_and_p31():
    """S2-18: the oracle's anchors, so a broken oracle cannot bless a broken reader."""
    assert all(gob_uint(n) == raw for n, raw in KNOWN_UINTS.items())
    assert signed_in_data(2) == SIGNED_IN_P31
    assert gob_int(2) == b"\x04"
    assert signed_in_data(MAX_UID).count(UID_ENTRY) == 1


def test_the_product_constant_is_the_gob_anchor():
    """S2-21: the product's `UID_ENTRY` equals the test-side copy (OD-11)."""
    from defender.lifecycle import UID_ENTRY as product

    assert product == UID_ENTRY


@pytest.mark.parametrize("seed", range(4))
def test_a_generated_uid_reads_back_whatever_its_byte_length(seed: int):
    """S2-17: uids across the positive int64 range, each encoded by the oracle, read back (not one byte, not an offset)."""
    session_uid, _ = _reader()
    for uid in [*uid_edges(), *uids(seed)]:
        assert session_uid(signed_in_data(uid)) == uid, uid


@pytest.mark.parametrize("seed", range(3))
def test_the_entry_may_sit_anywhere_in_the_row(seed: int):
    """S2-17: a reader that looks at a fixed offset fails when other bytes come before the entry."""
    session_uid, _ = _reader()
    rng = random.Random(seed)
    for uid in uids(seed, 60):
        row = junk(rng) + UID_ENTRY + uid_value(uid) + junk(rng)
        assert session_uid(row) == uid


def _refused(row: bytes) -> None:
    session_uid, unreadable = _reader()
    with pytest.raises(unreadable) as why:
        session_uid(row)
    assert row.hex() not in str(why.value)
    assert repr(row) not in str(why.value)


@pytest.mark.parametrize("seed", range(3))
def test_a_wrong_length_byte_is_unreadable(seed: int):
    """S2-19: L must be one more than the int's own bytes."""
    rng = random.Random(seed)
    for uid in uids(seed, 25):
        encoded = gob_int(uid)
        wrong = rng.choice([n for n in range(256) if n != 1 + len(encoded)])
        _refused(uid_tail_row(bytes([wrong]) + b"\x00" + encoded))


@pytest.mark.parametrize("seed", range(3))
def test_a_nonzero_field_delta_is_unreadable(seed: int):
    """S2-19."""
    rng = random.Random(seed)
    for uid in uids(seed, 25):
        encoded = gob_int(uid)
        _refused(uid_tail_row(bytes([1 + len(encoded), rng.randint(1, 255)]) + encoded))


@pytest.mark.parametrize("seed", range(3))
def test_an_odd_or_zero_value_is_unreadable(seed: int):
    """S2-19: a gob int is the unsigned value shifted left, so an odd value is a negative and zero is no user."""
    for uid in uids(seed, 25):
        odd = gob_int(-uid)  # (^i << 1) | 1: odd
        assert odd != gob_int(uid)
        _refused(uid_tail_row(bytes([1 + len(odd)]) + b"\x00" + odd))
    _refused(uid_tail_row(b"\x02\x00\x00"))


def test_the_entry_twice_is_unreadable():
    """S2-19: exactly once, even when both are well formed or the second is junk."""
    _refused(signed_in_data(5) + UID_ENTRY + uid_value(6))
    _refused(signed_in_data(5) + UID_ENTRY)
    _refused(UID_ENTRY + uid_value(5) + UID_ENTRY + uid_value(5))


def test_a_row_cut_short_is_unreadable():
    """S2-19: the row ends inside the entry's value."""
    for uid in (1, 200, 2**20, MAX_UID):
        row = UID_ENTRY + uid_value(uid)
        for cut in range(len(row) - len(uid_value(uid)), len(row)):
            _refused(row[:cut])


@pytest.mark.parametrize("seed", range(3))
def test_arbitrary_bytes_without_the_entry_are_unreadable(seed: int):
    """S2-19: a row with no anchored entry is never a uid."""
    rng = random.Random(seed)
    for _ in range(100):
        _refused(junk(rng, 200))
