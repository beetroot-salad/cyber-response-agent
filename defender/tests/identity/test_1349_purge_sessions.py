"""#1349 B2: the deployment-scheduled command that removes expired sessions.

`python -m defender.cli.purge_sessions` on the database named by DEFENDER_DATABASE_DSN. It
needs only the database, and refuses one whose schema is not at the migrations head. PostgreSQL
cases are marked `postgres`; each runs on a database of its own.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender.tests.support.shared._postgres1339 import VERSION_TABLE, database, execute

ROOT = Path(__file__).resolve().parents[3]  # the checkout under test, put first on the child's path
HOUR = dt.timedelta(hours=1)


def purge(dsn: str | None, python_flags: list[str] = []) -> subprocess.CompletedProcess[str]:  # noqa: B006 — never mutated
    """The command as a deployment's scheduler runs it: only the DSN in the environment."""
    child = {k: v for k, v in os.environ.items() if k != "DEFENDER_DATABASE_DSN"}
    child["PYTHONPATH"] = os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")])
    if dsn is not None:
        child["DEFENDER_DATABASE_DSN"] = dsn
    return subprocess.run([sys.executable, *python_flags, "-m", "defender.cli.purge_sessions"], env=child, cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


@pytest.fixture
def migrated() -> Iterator[str]:
    with database(migrated=True) as dsn:
        yield dsn


def _seed(dsn: str, sessions: dict[str, dt.datetime]) -> None:
    now = dt.datetime.now(dt.UTC)
    execute(dsn, "INSERT INTO identity.users (id, email, display_name, status, is_platform_admin, "
                 "set_password_requested_seq, set_password_sent_seq, set_password_attempts, created_at, updated_at, activated_at) "
                 "VALUES ('u1', 'ann@x.org', '', 'active', false, 0, 0, 0, %s, %s, %s)", (now, now, now))
    for value, expires in sessions.items():
        execute(dsn, "INSERT INTO identity.sessions (token_hash, user_id, used_otp, created_at, last_seen_at, expires_at) "
                     "VALUES (%s, 'u1', false, %s, %s, %s)",
                (hashlib.sha256(value.encode()).hexdigest(), now - 8 * 24 * HOUR, now - 8 * 24 * HOUR, expires))


def _left(dsn: str) -> set[str]:
    return {h for (h,) in execute(dsn, "SELECT token_hash FROM identity.sessions")}


@pytest.mark.postgres
def test_the_command_removes_expired_sessions_keeps_live_ones_and_says_how_many(migrated):
    now = dt.datetime.now(dt.UTC)
    _seed(migrated, {"old": now - HOUR, "older": now - 24 * HOUR, "live": now + HOUR})
    done = purge(migrated)
    assert done.returncode == 0, done.stderr
    assert _left(migrated) == {hashlib.sha256(b"live").hexdigest()}
    assert "2" in done.stdout.split()
    again = purge(migrated)
    assert again.returncode == 0, again.stderr
    assert "0" in again.stdout.split()


@pytest.mark.postgres
def test_the_command_refuses_a_database_not_at_the_migrations_head_and_deletes_nothing(migrated):
    """Fail closed: the tables are there, but the recorded revision is not this code's head."""
    _seed(migrated, {"old": dt.datetime.now(dt.UTC) - HOUR})
    execute(migrated, f"UPDATE {VERSION_TABLE} SET version_num = 'f00dfeedbeef'")
    done = purge(migrated)
    assert done.returncode != 0
    assert "f00dfeedbeef" in done.stderr, done.stderr
    assert done.returncode == 1, done.stderr  # a refusal, not a crash
    assert "Traceback" not in done.stderr, done.stderr
    assert _left(migrated) == {hashlib.sha256(b"old").hexdigest()}


@pytest.mark.parametrize("optimize", [[], ["-OO"]])
def test_the_command_without_a_database_refuses_loudly(optimize):
    """Also under -OO, which strips the docstrings a help text might be built from."""
    done = purge(None, optimize)
    assert done.returncode == 2, done.stderr
    assert "DEFENDER_DATABASE_DSN" in done.stderr
