"""A tenant's systems and case record live in the database (#1366): append-only version tables beside the tenant records,
a per-tenant mark that its systems come from records, and the proxy's read-only role (R14).

Revision ID: 0013_system_records
Revises: 0012_programs_table

The role is cluster-wide and may already exist (another database on the same server created it), so it is created only
when absent. It cannot log in: a deployment attaches a login that is a member of it. There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013_system_records"
down_revision = "0012_programs_table"

ROLE = "defender_proxy_reader"


def upgrade() -> None:
    tenant = sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False)
    op.create_table(
        "system_versions",
        tenant,
        sa.Column("system_id", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("settings", postgresql.JSONB(), nullable=False),
        sa.Column("access", sa.Text(), nullable=False),
        sa.Column("credential_generation", sa.Integer(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("author", sa.Text(), nullable=False),
        sa.Column("written_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "system_id", "version", name=op.f("pk_system_versions")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_system_versions_tenant_id_tenants")),
        schema="tenancy")
    op.create_table(
        "case_versions",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("system_id", sa.Text(), nullable=False),
        sa.Column("comment_body", sa.Text(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("author", sa.Text(), nullable=False),
        sa.Column("written_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "version", name=op.f("pk_case_versions")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_case_versions_tenant_id_tenants")),
        schema="tenancy")
    op.create_table(
        "records_mark",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_records_mark")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_records_mark_tenant_id_tenants")),
        schema="tenancy")
    # Tenants that exist now come from folders until the operator imports them: no mark for them.
    op.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{ROLE}') "
               f"THEN CREATE ROLE {ROLE} NOLOGIN; END IF; END $$")
    op.execute(f"GRANT USAGE ON SCHEMA tenancy TO {ROLE}")
    op.execute(f"GRANT SELECT ON tenancy.system_versions TO {ROLE}")
    # The mark: whether a token's tenant is one whose systems come from records at all (R8), read, never inferred from
    # whether it has a version row (a tenant created since #1366 has the mark and may have none).
    op.execute(f"GRANT SELECT ON tenancy.records_mark TO {ROLE}")
