"""The tenant's alert mapping lives in the database (#1345): a table beside the tenant records, one nullable text
column per entry, no rows (a tenant has no mapping until one is saved). An alert's title and description become
nullable (the store derives them from the tenant's mapping) and every existing value is nulled: no product code has
inserted alerts yet, so only development rows exist (a departure from 0004/0005's refuse-first precedent, justified
by that).

Revision ID: 0007_alert_mapping
Revises: 0006_job_leases
"""
import sqlalchemy as sa
from alembic import op

revision = "0007_alert_mapping"
down_revision = "0006_job_leases"

#: The entries, as this revision knew them (a migration keeps its own copy: it must mean what it meant when written).
_ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")


def upgrade() -> None:
    op.create_table(
        "alert_mappings",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        *(sa.Column(entry, sa.Text(), nullable=True) for entry in _ENTRIES),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_alert_mappings")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_alert_mappings_tenant_id_tenants")),
        schema="tenancy")
    op.alter_column("alerts", "title", existing_type=sa.Text(), nullable=True, schema="jobs")
    op.alter_column("alerts", "description", existing_type=sa.Text(), nullable=True, schema="jobs")
    op.execute("UPDATE jobs.alerts SET title = NULL, description = NULL")
