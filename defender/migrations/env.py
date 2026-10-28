"""Alembic's environment: migrate the database `defender.migrations.upgrade` was given."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from defender.database import CONNECT_ARGS, url
from defender.migrations import VERSION_TABLE_SCHEMA
from defender.migrations.models import target_metadata


def _ours(object_, _name, _type, _reflected, _compare_to):
    """Autogenerate looks only at feature schemas, never at `public` (Alembic's own table)."""
    return getattr(object_, "schema", None) != "public"


engine = create_engine(url(context.config.attributes["dsn"]), connect_args=CONNECT_ARGS,
                       poolclass=pool.NullPool)
try:
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, include_schemas=True,
            include_object=_ours, version_table_schema=VERSION_TABLE_SCHEMA)
        with context.begin_transaction():
            context.run_migrations()
finally:
    engine.dispose()
