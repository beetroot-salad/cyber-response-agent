"""The shared database layer (#1339): the declarative base every feature's models extend, and the
one place that turns a DSN into an engine, for the async application and for Alembic alike.

Imports no feature. Each feature defines its models in its own package, with its own schema on the
table; the one migration history that creates them is `defender.migrations`."""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass

#: Every constraint and index name derives from its table and columns, so a migration and a model
#: that declare the same thing give it the same name. A CHECK carries its own short name.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(MappedAsDataclass, DeclarativeBase):
    """Models are dataclasses with every field settable at construction and Python-side values only:
    no server defaults, so the repositories agree on every value they return."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def url(dsn: str) -> URL:
    """`dsn` (libpq form, `postgresql://...`) for the psycopg driver, sessions in UTC."""
    return make_url(dsn).set(drivername="postgresql+psycopg")


#: Applied to every connection, by the application and by Alembic.
CONNECT_ARGS = {"options": "-c timezone=UTC"}


def async_engine(dsn: str, *, max_connections: int = 10) -> AsyncEngine:
    """A pooled engine. Use it in one event loop, and `dispose()` it there."""
    return create_async_engine(
        url(dsn), connect_args=CONNECT_ARGS, pool_size=max_connections, max_overflow=0)


def sessions(engine: AsyncEngine) -> async_sessionmaker:
    """Sessions whose objects stay readable after the transaction ends."""
    return async_sessionmaker(engine, expire_on_commit=False)
