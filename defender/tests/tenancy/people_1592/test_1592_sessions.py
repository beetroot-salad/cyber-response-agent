"""#1592 r15.1 "Session rows", "The cap job", the sessions port and the shipped table: which rows the worker (stamped
only) and the cap job (unstamped `UID_ENTRY` rows, unread) delete (S2-15, 16, 20, 36, 37, 38, 39). Postgres-marked.
"""
from __future__ import annotations

import datetime as dt
import logging
import re

import pytest

from defender.tests.tenancy.people_1592._gob1592 import ANONYMOUS_P31, UID_ENTRY, signed_in_data, uid_tail_row
from defender.tests.tenancy.people_1592._sessions1592 import (  # noqa: F401 — `sessions` overrides the package fixture
    MINUTE,
    SESSION_ROLES,
    as_role,
    generated_rows,
    holds_entry,
    now,
    sessions,
)
from defender.tests.tenancy.people_1592._spec1592 import (
    UNREACHABLE_DSN,
    login_of,
    session_key,
    sessions_port,
    sessions_twin,
)
from defender.tests.tenancy.people_1592._world1592 import T, U2, People
from defender.tests.tenancy.people_1592._worker1592 import CountingSessions, errors, records, settled, use

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


async def _two(people: People, *, other_tenant: bool):
    await people.tenant(T)
    if other_tenant:
        await people.tenant(U2)
    person = await people.person("erin@x.org", *((T, U2) if other_tenant else (T,)), session=False)
    other = await people.person("gina@x.org", T, session=False)
    await settled(people)
    # The case worker's first poll runs the cap job (r15.2: at the first poll that holds the lock), which deletes
    # unstamped `UID_ENTRY` rows; take that poll now, with nothing planted, so the cases below see the worker's own
    # session step. The fake clock never moves, so no later poll is due for another.
    await people.step()
    return person, other


def _plant(people: People, user, other, pivot: dt.datetime) -> None:
    uid, other_uid = (people.forge.uid(login_of(str(u.id))) for u in (user, other))
    for key, data, at in (
        ("before", signed_in_data(uid), pivot - 10 * MINUTE), ("after", signed_in_data(uid), pivot + MINUTE),
        ("unstamped", signed_in_data(uid), None), ("gina", signed_in_data(other_uid), pivot - 10 * MINUTE),
        ("gina-un", signed_in_data(other_uid), None), ("anon", ANONYMOUS_P31, None),
    ):
        people.sessions.plant(key, data, signed_in_at=at)


def _k(*names: str) -> set[str]:
    return {session_key(n).strip() for n in names}


async def test_a_suspended_person_loses_every_stamped_row_but_not_an_unstamped_one(people: People):
    """S2-15: wanted nowhere: all of their stamped rows go; the unstamped one is the cap job's (r15.1); others stay."""
    erin, gina = await _two(people, other_tenant=False)
    _plant(people, erin, gina, now())
    await people.end(erin, T)

    await people.step()

    assert people.sessions.keys() == _k("unstamped", "gina", "gina-un", "anon")


async def test_after_a_sign_out_only_rows_stamped_before_it_go(people: People):
    """S2-15: wanted and signed out: rows stamped before `signed_out_at` go; the later and the unstamped stay."""
    erin, gina = await _two(people, other_tenant=True)
    await people.sign_out(erin)
    pivot = (await people.identity.user(erin.id)).signed_out_at
    _plant(people, erin, gina, pivot)
    await people.step()

    assert people.sessions.keys() >= _k("after", "unstamped", "gina", "gina-un", "anon")
    assert not people.sessions.keys() & _k("before")


async def test_with_no_sign_out_a_person_kept_elsewhere_keeps_every_row(people: People):
    """S2-15 / OD-4a: leaving one tenant, never signed out, still wanted: no row is touched."""
    erin, gina = await _two(people, other_tenant=True)
    _plant(people, erin, gina, now())
    await people.end(erin, T)

    await people.step()

    assert people.sessions.keys() == _k("before", "after", "unstamped", "gina", "gina-un", "anon")


@pytest.mark.parametrize("uid", [63, 64, 255, 256, 1000, 2**31 - 1, 2**32 + 5, 2**63 - 1])
async def test_a_person_with_a_large_forgejo_id_loses_their_row_when_suspended(people: People, uid: int):
    """S2-16: a uid past one byte is read whole, so the suspended person's row is found and deleted."""
    await people.tenant(T)
    erin = await people.person("erin@x.org", T, session=False)
    people.forge.accounts[login_of(str(erin.id))]["id"] = uid
    await settled(people)
    people.sessions.plant("erin", signed_in_data(uid), signed_in_at=now() - 5 * MINUTE)
    people.sessions.plant("near", signed_in_data(uid ^ 1 or 2), signed_in_at=now() - 5 * MINUTE)
    await people.end(erin, T)

    await people.step()

    assert people.sessions.keys() == _k("near")


_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?")


def _logged_instants(message: str) -> list[dt.datetime]:
    """Every timestamp a log line holds, as an instant (a stamp with no zone is read as UTC)."""
    found = []
    for text in _TIMESTAMP.findall(message):
        at = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        found.append(at if at.tzinfo else at.replace(tzinfo=dt.timezone.utc))
    return found


async def test_an_unreadable_stamped_row_is_deleted_and_logged_without_its_key(people: People, caplog):
    """S2-20 / OD-11: a stamped row the prefilter selects but the reader refuses goes in a run with a session step; one
    log line per row names the user and the row's `signed_in_at`, never its key or data."""
    caplog.set_level(logging.INFO)
    erin, gina = await _two(people, other_tenant=False)
    weird_at = now() - 17 * MINUTE  # distinct from every other row's time, so a line naming it names this row
    people.sessions.plant("weird", uid_tail_row(b"\x02\x00\x03"), signed_in_at=weird_at)
    people.sessions.plant("weird-un", uid_tail_row(b"\x02\x00\x03"), signed_in_at=None)
    _plant(people, erin, gina, now())
    await people.end(erin, T)

    await people.step()

    assert people.sessions.keys() == _k("weird-un", "unstamped", "gina", "gina-un", "anon")
    messages = [r.getMessage() for r in records(caplog)]
    row_lines = [m for m in messages if str(erin.id) in m and any(abs(at - weird_at) < dt.timedelta(seconds=1) for at in _logged_instants(m))]
    assert len(row_lines) == 1, f"one line per deleted row naming the user and its signed_in_at, got {row_lines}"
    for message in messages:
        assert session_key("weird") not in message
        assert uid_tail_row(b"\x02\x00\x03").hex() not in message


# --- the cap job ------------------------------------------------------------------------------------------

async def test_the_cap_job_deletes_old_and_unstamped_entry_rows_without_decoding(people: People, caplog):
    """S2-36: stamped past the cap, and unstamped rows holding `UID_ENTRY` (readable or not) go; the rest stay."""
    caplog.set_level(logging.INFO)
    await people.tenant(T)
    await settled(people)
    odd = uid_tail_row(b"\x02\x00\x03")
    rows = {
        "old": (signed_in_data(7), now() - 61 * MINUTE), "fresh": (signed_in_data(7), now() - MINUTE),
        "revived": (signed_in_data(7), None), "revived-odd": (odd, None), "anon": (ANONYMOUS_P31, None),
        "odd-fresh": (odd, now() - MINUTE), "anon-old": (ANONYMOUS_P31, now() - 90 * MINUTE),
    }
    for key, (data, at) in rows.items():
        people.sessions.plant(key, data, signed_in_at=at)
    worker = use(people)

    await worker.cap()

    assert people.sessions.keys() == _k("fresh", "anon", "odd-fresh")
    assert not [r for r in records(caplog) if r.levelno >= logging.WARNING]


async def test_the_cap_runs_only_once_its_period_has_passed_and_a_failure_is_logged(people: People, caplog):
    """S2-37 (r15.2, "The cap job"): at the first poll that holds the lock, then at the first poll `forge_cap_every` after
    the last run began, not on every poll; an unreachable sessions database is logged and the poll goes on."""
    await people.tenant(T)
    await settled(people)
    counting = CountingSessions(sessions_port(people.sessions.dsn))
    use(people, sessions=counting)
    await people.step()
    assert counting.calls.get("cap", 0) == 1, "the cap job did not run at the first poll that held the lock"
    people.clock.advance(dt.timedelta(seconds=30))
    await people.step()
    assert counting.calls.get("cap", 0) == 1
    people.clock.advance(MINUTE)
    await people.step()
    assert counting.calls.get("cap", 0) == 2
    await people.step()
    assert counting.calls.get("cap", 0) == 2

    before = len(errors(caplog))
    broken = use(people, sessions=sessions_port(UNREACHABLE_DSN))
    people.clock.advance(5 * MINUTE)
    await people.step()
    assert broken is people.worker
    # the new worker's first take of the lock is one error (OD-12); the cap failure is another
    assert len(errors(caplog)) - before >= 2, "the cap failure was not logged"


# --- the port and its twin --------------------------------------------------------------------------------

def _twin_keys(twin) -> set[str]:
    return {k.strip() for k in twin.keys()}  # noqa: SIM118 — a method of the twin, not a dict


def _tuple(row) -> tuple:
    return (row.key.strip(), bytes(row.data), row.signed_in_at)


@pytest.mark.parametrize("seed", range(5))
async def test_the_postgres_port_and_its_twin_agree_on_selects_deletes_and_the_cap(people: People, seed: int):
    """S2-38: the same generated rows give the same prefilter select, delete and cap result on both."""
    rows = generated_rows(seed)
    twin = sessions_twin()
    for row in rows:
        people.sessions.plant(row.key, row.data, signed_in_at=row.signed_in_at)
        twin.insert(row.key, row.data, signed_in_at=row.signed_in_at)
    port = sessions_port(people.sessions.dsn)
    expected = {r.key.strip() for r in rows if r.signed_in_at is not None and holds_entry(r.data)}

    got_pg = {_tuple(r) for r in await port.signed_in_rows()}
    got_twin = {_tuple(r) for r in await twin.signed_in_rows()}
    assert got_pg == got_twin
    assert {k for k, _d, _a in got_pg} == expected

    victims = [r.key for r in rows[::3]]
    await port.delete(victims)
    await twin.delete(victims)
    assert people.sessions.keys() == _twin_keys(twin)

    removed_pg = await port.cap(3600.0)
    removed_twin = await twin.cap(3600.0)
    assert removed_pg == removed_twin
    assert people.sessions.keys() == _twin_keys(twin)
    cap_gone = {r.key.strip() for r in rows if r.key not in victims
                and ((r.signed_in_at is not None and r.signed_in_at < now() - dt.timedelta(hours=1))
                     or (r.signed_in_at is None and holds_entry(r.data)))}
    assert removed_pg == len(cap_gone)


# --- the shipped table -------------------------------------------------------------------------------------

def test_the_shipped_table_stamps_a_rekey_only_and_grants_each_role_its_part(sessions):  # noqa: F811
    """S2-39: the shipped `forgejo-sessions-table.sql` (the first file's CONNECT grants are the live job's, S4-11)."""
    from defender.tests.support.shared._postgres1339 import execute

    dsn = sessions.dsn
    cols = execute(dsn, "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                        "WHERE table_name = 'session' ORDER BY column_name")
    assert cols == [("data", "bytea", "YES"), ("expiry", "integer", "NO"), ("key", "character", "NO"),
                    ("signed_in_at", "timestamp with time zone", "YES")]
    assert execute(dsn, "SELECT indexdef FROM pg_indexes WHERE tablename = 'session' AND indexdef LIKE '%signed_in_at%'")
    execute(dsn, "DO $$ BEGIN CREATE ROLE nobody1592 NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation "
                 "THEN NULL; END $$")
    privileges = {role: {p: execute(dsn, f"SELECT has_table_privilege('{role}', 'session', '{p}')")[0][0]
                         for p in ("SELECT", "INSERT", "UPDATE", "DELETE")} for role in (*SESSION_ROLES, "nobody1592")}
    assert privileges["fs_forgejo"] == dict.fromkeys(("SELECT", "INSERT", "UPDATE", "DELETE"), True)
    assert privileges["fs_lifecycle"] == {"SELECT": True, "INSERT": False, "UPDATE": False, "DELETE": True}
    assert not any(privileges["nobody1592"].values())

    with as_role(dsn, "fs_forgejo") as forgejo:
        forgejo.execute("INSERT INTO session (key, data, expiry) VALUES ('aaaaaaaaaaaaaaaa', 'x', 1)")
        assert forgejo.execute("SELECT signed_in_at FROM session").fetchall() == [(None,)]
        forgejo.execute("UPDATE session SET data = 'y'")
        assert forgejo.execute("SELECT signed_in_at FROM session").fetchall() == [(None,)]
        forgejo.execute("UPDATE session SET key = 'bbbbbbbbbbbbbbbb'")
        stamped = forgejo.execute("SELECT signed_in_at FROM session").fetchall()[0][0]
    assert stamped is not None
    assert UID_ENTRY  # the prefilter's anchor is shared with the reader tests
