"""#1339 PostgreSQL test databases: one migrated template per xdist worker, one database per test.

Every PostgreSQL test gets a database of its own, cloned from its worker's template, which the
migrations bring to head once per worker. Migrations run only in synchronous fixtures, never on a
running event loop. A template is named by worker and process id and built fresh, never reused from an earlier run.
"""
from __future__ import annotations

import atexit
import functools
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

DSN_ENV = "DEFENDER_TEST_POSTGRES_DSN"
#: Alembic's version table, which the design keeps in `public`.
VERSION_TABLE = "public.alembic_version"


def server_dsn() -> str:
    """The test server's address; skipped where none is set, but never in CI."""
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        if os.environ.get("CI"):
            pytest.fail(f"{DSN_ENV} is not set in CI; the test job's PostgreSQL service provides it")
        pytest.skip(f"{DSN_ENV} is not set")
    pytest.importorskip("psycopg")
    pytest.importorskip("sqlalchemy")
    return dsn


def dsn_for(dsn: str, database: str) -> str:
    """`dsn` with its database name replaced; the scheme (`postgresql://`) is kept as given."""
    from sqlalchemy.engine import make_url

    return make_url(dsn).set(database=database).render_as_string(hide_password=False)


def execute(dsn: str, statement: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """One autocommit statement on its own connection; the rows it returned, if any."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        cur = conn.execute(statement, params or None)  # type: ignore[arg-type]
        return cur.fetchall() if cur.description else []


def _create(server: str, name: str, *, template: str) -> str:
    execute(server, f'CREATE DATABASE "{name}" TEMPLATE "{template}"')
    return dsn_for(server, name)


def _drop(server: str, name: str) -> None:
    execute(server, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@functools.cache
def _template(server: str) -> str:
    """This worker's template database at head, built once per process."""
    from defender.migrations import upgrade

    name = f"defender_tmpl_{os.environ.get('PYTEST_XDIST_WORKER', 'main')}_{os.getpid()}"
    _drop(server, name)
    upgrade(_create(server, name, template="template0"))
    atexit.register(_drop, server, name)
    return name


@contextmanager
def database(*, migrated: bool) -> Iterator[str]:
    """A database of this test's own: at head (cloned from the template) or empty; dropped after."""
    server = server_dsn()
    template = _template(server) if migrated else "template0"
    name = f"t_{uuid.uuid4().hex}"
    try:
        yield _create(server, name, template=template)
    finally:
        _drop(server, name)


@pytest.fixture
def migrated_database() -> Iterator[str]:
    """The DSN of a fresh database at head."""
    with database(migrated=True) as dsn:
        yield dsn


@pytest.fixture
def empty_database() -> Iterator[str]:
    """The DSN of a fresh database nothing has touched."""
    with database(migrated=False) as dsn:
        yield dsn
