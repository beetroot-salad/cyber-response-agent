"""The one migration history for every feature's tables (#1339), and the checks around it.

Synchronous (Alembic is). Reading the history or checking a database's version loads no feature's
models; those are collected in `defender.migrations.models`, which only the Alembic environment and
the models-match-migrations test import."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, pool

from defender.database import CONNECT_ARGS, url

HERE = Path(__file__).resolve().parent
#: Alembic's own table stays in `public`, which exists before the first upgrade.
VERSION_TABLE_SCHEMA = "public"


class RevisionMismatch(Exception):
    """The database is not at the revision this code expects: `database` is its recorded revision
    (`None` when unmigrated), `head` the code's."""

    def __init__(self, database: str | None, head: str) -> None:
        self.database = database
        self.head = head
        recorded = "no recorded revision (unmigrated)" if database is None else f"revision {database}"
        super().__init__(f"the database is at {recorded}, but this code expects revision {head}; "
                         "stop every process, run `python -m defender.migrations upgrade`, then start them")


def _config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(HERE))
    return config


def _scripts() -> ScriptDirectory:
    return ScriptDirectory.from_config(_config())


def heads() -> tuple[str, ...]:
    """Every head of the history; the single-head check asserts there is one."""
    return tuple(_scripts().get_heads())


def head() -> str:
    """The revision this code expects every database to be at."""
    [only] = heads()
    return only


def upgrade(dsn: str) -> None:
    """Bring the database to head; at head it changes nothing. Leaves no connection open."""
    config = _config()
    config.attributes["dsn"] = dsn
    command.upgrade(config, "head")


def check_version(dsn: str) -> None:
    """Pass only when the database's recorded revision is exactly head, else raise
    `RevisionMismatch` naming both. Reads only."""
    engine = create_engine(url(dsn), connect_args=CONNECT_ARGS, poolclass=pool.NullPool)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn, opts={"version_table_schema": VERSION_TABLE_SCHEMA})
            recorded = context.get_current_heads()
    finally:
        engine.dispose()
    if recorded != (head(),):
        raise RevisionMismatch(recorded[0] if len(recorded) == 1 else (", ".join(recorded) or None), head())
