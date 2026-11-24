"""Drop `tenancy.publish_status` (#1618 D7): the launch-time publish outcome is no longer recorded; a fetch is refused or
served at the moment it is asked for, and nothing reads the table.

Revision ID: 0028_drop_publish_status
Revises: 0027_people_requests

Drops one table and changes no other. A row in it does not stop the upgrade, and the tenant it named keeps its row.
There is no downgrade.
"""
from alembic import op

revision = "0028_drop_publish_status"
down_revision = "0027_people_requests"


def upgrade() -> None:
    op.drop_table("publish_status", schema="tenancy")
