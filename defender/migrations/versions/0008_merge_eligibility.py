"""Who may merge into a tenant's `main` lives in the database (#1414 D13): a table beside the tenant records, at most one
row per tenant, absent until the management service's first successful read of the merge whitelist. A tenant that exists
already has no row, which readers take as "not read yet".

Revision ID: 0008_merge_eligibility
Revises: 0007_alert_mapping
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_merge_eligibility"
down_revision = "0007_alert_mapping"


def upgrade() -> None:
    op.create_table(
        "merge_eligibility",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("logins", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_merge_eligibility")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_merge_eligibility_tenant_id_tenants")),
        schema="tenancy")
