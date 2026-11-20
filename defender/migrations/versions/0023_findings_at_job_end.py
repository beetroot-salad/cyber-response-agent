"""A completed learning job's findings are stored by its own end write (#1487): `pending` retires.

Revision ID: 0023_findings_at_job_end
Revises: 0022_learning_causes

`jobs.learning_jobs.publish_state` becomes `none | done | refused`. Every row still `pending` (findings a post-step
never published; since #1170 no post-step in a deployment could) becomes `refused`: their findings stay in their
episodes and are not recovered. How many, per tenant, is logged here, one line per tenant that had any.

`jobs.learning_checks` gains `armed_while_held`: a job that ends `completed` while a post-step holds the tenant's check
clock sets it, and that hold's end then makes the tenant due at once. Existing rows read unmarked; the column keeps no
server default afterwards (the store sets it on every insert).

Stop the API and the workers before migrating (an older worker writes `pending`). There is no downgrade.
"""
import logging

import sqlalchemy as sa
from alembic import op

revision = "0023_findings_at_job_end"
down_revision = "0022_learning_causes"

SCHEMA = "jobs"
#: The upgrade's own log: what it changed for good is worth a line in an operator's output.
_logger = logging.getLogger("defender.migrations")


def upgrade() -> None:
    moved = op.get_bind().execute(sa.text(
        "WITH moved AS (UPDATE jobs.learning_jobs SET publish_state = 'refused' WHERE publish_state = 'pending' "
        "RETURNING tenant_id) SELECT tenant_id, count(*) FROM moved GROUP BY tenant_id ORDER BY tenant_id")).all()
    for tenant, count in moved:
        _logger.warning("tenant %s: %d learning job(s) whose findings were never published now read refused; "
                        "their findings are not recovered", tenant, count)
    op.drop_constraint(op.f("ck_learning_jobs_publish_state"), "learning_jobs", schema=SCHEMA, type_="check")
    op.create_check_constraint(op.f("ck_learning_jobs_publish_state"), "learning_jobs",
                               "publish_state IN ('none', 'done', 'refused')", schema=SCHEMA)
    op.add_column("learning_checks", sa.Column("armed_while_held", sa.Boolean(), nullable=False,
                                               server_default=sa.false()), schema=SCHEMA)
    op.alter_column("learning_checks", "armed_while_held", server_default=None, schema=SCHEMA)
