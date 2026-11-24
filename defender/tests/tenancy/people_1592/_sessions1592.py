"""#1592 S2 machinery (slice-owned, NO test functions): the Forgejo sessions database built from the SHIPPED table SQL,
the generator of uids and session rows.

The shipped file is `.devcontainer/postgres/forgejo-sessions-table.sql` (r15.1). It does not exist yet, so every case
that builds the database fails by naming it: expected red, never a skip. The first file, `forgejo-sessions.sql`
(roles, database, CONNECT grants), needs `psql`'s `\\connect` and is owed to the live job (S4-11).
The package's `sessions` fixture (`_world1592`) builds the same shipped database.
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from defender.tests.tenancy.people_1592._gob1592 import (
    ANONYMOUS_P31,
    MAX_UID,
    UID_ENTRY,
    signed_in_data,
    uid_tail_row,
)
from defender.tests.tenancy.people_1592._spec1592 import Sessions, session_key

SHIPPED_TABLE = Path(__file__).resolve().parents[4] / ".devcontainer" / "postgres" / "forgejo-sessions-table.sql"
#: The three NOLOGIN roles the first shipped file creates; the table file grants to them.
SESSION_ROLES = ("fs_owner", "fs_forgejo", "fs_lifecycle")
MINUTE = dt.timedelta(minutes=1)


def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


# --- the sessions database from the shipped SQL --------------------------------------------------------

def _roles_sql() -> str:
    return "".join(f"""DO $$ BEGIN CREATE ROLE {role} NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation
                       THEN NULL; END $$;\n""" for role in SESSION_ROLES)


@contextlib.contextmanager
def shipped_sessions_database() -> Iterator[Sessions]:
    """A fresh database holding the shipped table, trigger, grants and index (run as the server's superuser)."""
    from defender.tests.support.shared._postgres1339 import database, execute

    if not SHIPPED_TABLE.is_file():
        pytest.fail(f"the shipped sessions table SQL is missing: {SHIPPED_TABLE} (r15.1)", pytrace=False)
    text = SHIPPED_TABLE.read_text(encoding="utf-8")
    with database(migrated=False) as dsn:
        execute(dsn, _roles_sql())
        execute(dsn, text)
        yield Sessions(dsn)


@pytest.fixture
def sessions() -> Iterator[Sessions]:
    """The shipped sessions database; `people` resolves to this fixture."""
    with shipped_sessions_database() as s:
        yield s


@contextlib.contextmanager
def as_role(dsn: str, role: str) -> Iterator[Any]:
    """A connection on which `SET ROLE <role>` is in force: what that role may do."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"SET ROLE {role}")  # type: ignore[arg-type]
        yield conn


# --- generated uids and rows -----------------------------------------------------------------------------

def uid_edges() -> list[int]:
    """Both ends of every bit length of a positive int64, so each gob byte-length class and its boundaries appear."""
    edges = {1, 2, 3, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, MAX_UID, MAX_UID - 1}
    for bits in range(1, 64):
        edges |= {2 ** (bits - 1), 2**bits - 1}
    return sorted(e for e in edges if 0 < e <= MAX_UID)


def uids(seed: int, count: int = 150) -> list[int]:
    """`count` uids over the whole positive int64 range: the bit length is drawn first, so small and large uids are
    equally likely (a uniform draw would almost never be short)."""
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        bits = rng.randint(1, 63)
        out.append(rng.randint(2 ** (bits - 1), 2**bits - 1))
    return out


def junk(rng: random.Random, limit: int = 40) -> bytes:
    """Arbitrary bytes that do not hold the `uid` entry."""
    while True:
        data = bytes(rng.randrange(256) for _ in range(rng.randint(0, limit)))
        if UID_ENTRY not in data and UID_ENTRY[:4] not in data:
            return data


@dataclasses.dataclass(frozen=True)
class Row:
    """A planted session row and what a test knows it to be (independent of any reader)."""

    key: str
    data: bytes
    signed_in_at: dt.datetime | None
    kind: str


def generated_rows(seed: int, count: int = 36) -> list[Row]:
    """Rows of every shape the prefilter and the cap see, with stamps well clear of the one-hour cap."""
    rng = random.Random(seed)
    stamps = [None, None, now() - 300 * MINUTE, now() - 90 * MINUTE, now() - 62 * MINUTE, now() - 58 * MINUTE,
              now() - 10 * MINUTE, now() - MINUTE, now() + 5 * MINUTE]
    rows = []
    for i in range(count):
        kind = rng.choice(["signed_in", "anonymous", "odd", "zero", "junk", "junk_with_entry", "twice"])
        if kind == "signed_in":
            data = signed_in_data(rng.choice(uid_edges()))
        elif kind == "anonymous":
            data = ANONYMOUS_P31
        elif kind == "odd":
            data = uid_tail_row(b"\x02\x00\x03")
        elif kind == "zero":
            data = uid_tail_row(b"\x02\x00\x00")
        elif kind == "junk":
            data = junk(rng)
        elif kind == "junk_with_entry":
            data = junk(rng) + UID_ENTRY + junk(rng)
        else:
            data = signed_in_data(5) + UID_ENTRY + b"\x02\x00\x0a"
        rows.append(Row(session_key(f"g{i:04d}"), data, rng.choice(stamps), kind))
    return rows


def holds_entry(data: bytes) -> bool:
    """Whether a row holds the `uid` entry bytes: the prefilter's whole test."""
    return UID_ENTRY in data
