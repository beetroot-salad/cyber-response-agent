"""Whether an investigation's cost is only a lower limit (#1377 S2).

Revision ID: 0010_cost_lower_limit
Revises: 0009_programs

A cost is exact unless the host knows spend may be missing from it (a failed spend write, a run
killed before it reported, a row ended without its holder's final figure). Rows from before this
revision keep their cost and store `false`. The mark is worked out when a record is read, so a row that
started, ended with a cost and never had its holder's final figure written reads "at least" all the same; every
other old row reads exact. A lower limit
only ever stands beside a number, so the row refuses `true` beside a null cost.
"""
import sqlalchemy as sa
from alembic import op

revision = "0010_cost_lower_limit"
down_revision = "0009_programs"

TABLE, SCHEMA = "investigations", "jobs"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("cost_is_lower_limit", sa.Boolean(), nullable=False,
                                   server_default=sa.false()), schema=SCHEMA)
    # The default only fills the rows that exist: no column of the jobs schema keeps a server default.
    op.alter_column(TABLE, "cost_is_lower_limit", server_default=None, schema=SCHEMA)
    op.create_check_constraint(op.f("ck_investigations_lower_limit_has_a_cost"), TABLE,
                               "NOT cost_is_lower_limit OR cost_usd IS NOT NULL", schema=SCHEMA)
