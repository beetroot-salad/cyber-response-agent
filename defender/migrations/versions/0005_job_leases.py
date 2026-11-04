"""Leases and final accounting on investigations (#1343 piece B).

Revision ID: 0005_job_leases
Revises: 0004_jobs

A running row's lease says who keeps it alive; the accounting mark says its holder is done with
the host. Rows from before this revision: a running row gets an already-lapsed lease (no piece-A
worker survives the migration, so it is retried at once); an ended row's accounting is final, so
its mark is its finish time. The revision holds no copy of the lease length.
"""
import sqlalchemy as sa
from alembic import op

revision = "0005_job_leases"
down_revision = "0004_jobs"

TABLE, SCHEMA = "investigations", "jobs"


def upgrade() -> None:
    for name in ("lease_expires_at", "accounting_written_at"):
        op.add_column(TABLE, sa.Column(name, sa.DateTime(timezone=True), nullable=True), schema=SCHEMA)
    op.execute(f"UPDATE {SCHEMA}.{TABLE} SET lease_expires_at = now() - interval '1 second' WHERE stage = 'running'")
    op.execute(f"UPDATE {SCHEMA}.{TABLE} SET accounting_written_at = finished_at "
               "WHERE stage IN ('completed', 'unparseable', 'failed', 'aborted')")
    op.create_check_constraint(op.f("ck_investigations_running_has_a_lease"), TABLE, "stage <> 'running' OR lease_expires_at IS NOT NULL",
                               schema=SCHEMA)
