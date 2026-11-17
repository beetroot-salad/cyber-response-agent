"""A job's ticket write-back (#1471 r8, r9): `jobs.investigations` gains `update_ticket` (the request's flag), and the
case record loses its comment template (W7). No outcome word is stored (r9 R9-1): the job's receipt stays in its run's
records, and the proxy's audit is the record of a write.

Revision ID: 0021_ticket_write
Revises: 0020_signin_attempts

Existing investigations read unflagged. `update_ticket` has no server default afterwards: the store sets it on every
insert. The case versions keep every row; only the template column goes. Stop the API, the workers and the credential
proxy before migrating (an older process writes the dropped column), and rebuild the job image with the upgrade.

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0021_ticket_write"
down_revision = "0020_signin_attempts"


def upgrade() -> None:
    op.add_column("investigations", sa.Column("update_ticket", sa.Boolean(), nullable=False, server_default=sa.false()),
                  schema="jobs")
    op.alter_column("investigations", "update_ticket", server_default=None, schema="jobs")
    op.drop_column("case_versions", "comment_body", schema="tenancy")
