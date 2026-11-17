"""A job's ticket write-back (#1471 r8): `jobs.investigations` gains `update_ticket` (the request's flag) and `ticket_write`
(the outcome word, null until the investigation ends), and the case record loses its comment template (W7).

Revision ID: 0021_ticket_write
Revises: 0019_drop_records_mark

Existing investigations read unflagged with no word. `update_ticket` has no server default afterwards: the store sets it
on every insert. The case versions keep every row; only the template column goes. Stop the API, the workers and the
credential proxy before migrating (an older process writes the dropped column), and rebuild the job image with the upgrade.

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0021_ticket_write"
down_revision = "0020_signin_attempts"

WORDS = ("commented", "escalated", "error", "unknown", "no_receipt", "not_read")


def upgrade() -> None:
    op.add_column("investigations", sa.Column("update_ticket", sa.Boolean(), nullable=False, server_default=sa.false()),
                  schema="jobs")
    op.alter_column("investigations", "update_ticket", server_default=None, schema="jobs")
    op.add_column("investigations", sa.Column("ticket_write", sa.Text(), nullable=True), schema="jobs")
    words = ", ".join(repr(w) for w in WORDS)
    op.create_check_constraint(op.f("ck_investigations_ticket_write"), "investigations",
                               f"ticket_write IN ({words})", schema="jobs")
    op.drop_column("case_versions", "comment_body", schema="tenancy")
