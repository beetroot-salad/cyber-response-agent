"""Per-tenant evidence retention (#1546 A-O7): `tenancy.evidence_retention`, one row per tenant with both values, the days
an accepted object of an investigation and of a learning job is kept, each 30 to 730. There is no default (#1082): the
tenant's create request carries both values, and the API changes them (`config.write`, audited).

Revision ID: 0028_evidence_retention
Revises: 0027_run_evidence

Creates a table and changes no other. There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0028_evidence_retention"
down_revision = "0027_run_evidence"

SCHEMA = "tenancy"
#: The bounds, frozen here as they stand at this revision.
_LEAST, _MOST = 30, 730


def upgrade() -> None:
    op.create_table(
        "evidence_retention",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("investigation_days", sa.Integer(), nullable=False),
        sa.Column("learning_days", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_evidence_retention")),
        sa.ForeignKeyConstraint(["tenant_id"], [f"{SCHEMA}.tenants.id"], name=op.f("fk_evidence_retention_tenant_id_tenants")),
        sa.CheckConstraint(f"investigation_days BETWEEN {_LEAST} AND {_MOST}",
                           name=op.f("ck_evidence_retention_investigation_days")),
        sa.CheckConstraint(f"learning_days BETWEEN {_LEAST} AND {_MOST}", name=op.f("ck_evidence_retention_learning_days")),
        schema=SCHEMA)
