"""Alembic's environment: migrate the database `defender.migrations.upgrade` was given."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from defender.database import CONNECT_ARGS, url
from defender.migrations import VERSION_TABLE_SCHEMA, include_object
from defender.migrations.models import target_metadata

engine = create_engine(url(context.config.attributes["dsn"]), connect_args=CONNECT_ARGS,
                       poolclass=pool.NullPool)
try:
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, include_schemas=True,
            include_object=include_object, version_table_schema=VERSION_TABLE_SCHEMA)
        with context.begin_transaction():
            context.run_migrations()
finally:
    engine.dispose()
