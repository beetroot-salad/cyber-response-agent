"""The job store's newest-first lists (#1083): one index each on alerts, investigations and learning jobs, keyed
tenant, time descending, id descending, so a tenant's page is read in index order with no sort. The tables are analyzed
after, so the planner has their statistics from the first read (on a table it has none for it prices a wide row's
bitmap scan below the index and sorts).

Revision ID: 0016_list_indexes
Revises: 0015_system_records

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0016_list_indexes"
down_revision = "0015_system_records"

SCHEMA = "jobs"
LISTS = (("alerts", "fired_at"), ("investigations", "created_at"), ("learning_jobs", "created_at"))


def upgrade() -> None:
    for table, time in LISTS:
        op.create_index(f"{table}_newest_first", table, ["tenant_id", sa.text(f"{time} DESC"), sa.text("id DESC")],
                        schema=SCHEMA)
    for table, _ in LISTS:
        op.execute(f"ANALYZE {SCHEMA}.{table}")
