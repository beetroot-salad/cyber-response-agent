"""A learning job's row keeps no findings count (#1589): `jobs.learning_jobs.findings_count` is dropped.

Revision ID: 0024_drop_findings_count
Revises: 0023_findings_at_job_end

The column held two meanings (the entry's own count on rows from before #1487, the rows the end write stored after it)
and nothing decided on it. A job's stored findings carry its id (`source_run`); a completed job's message still names
how many findings its pass left. There is no downgrade.
"""
from alembic import op

revision = "0024_drop_findings_count"
down_revision = "0023_findings_at_job_end"

SCHEMA = "jobs"


def upgrade() -> None:
    op.drop_column("learning_jobs", "findings_count", schema=SCHEMA)
