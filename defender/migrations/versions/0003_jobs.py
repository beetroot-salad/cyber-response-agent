"""The job store's tables (#1342): alerts, and the investigations of them.

Revision ID: 0003_jobs
Revises: 0002_tenancy
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_jobs"
down_revision = "0002_tenancy"

SCHEMA = "jobs"


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA {SCHEMA}")
    op.create_table(
        "alerts",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("vendor_ticket_id", sa.Text(), nullable=False),
        _time("fired_at", nullable=False),
        _time("changed_at", nullable=False),
        _time("received_at", nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("raw", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_alerts_tenant_id_tenants")),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_alerts_tenant_id_id")),
        sa.UniqueConstraint("tenant_id", "vendor", "vendor_ticket_id",
                            name=op.f("uq_alerts_tenant_id_vendor_vendor_ticket_id")),
        schema=SCHEMA)
    op.create_table(
        "investigations",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("request_key", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("stage", sa.Text(), nullable=False),
        _time("created_at", nullable=False),
        _time("started_at"),
        _time("finished_at"),
        sa.Column("disposition", sa.Text(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("knowledge", postgresql.JSONB(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("failure_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_investigations")),
        sa.ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"],
                                name=op.f("fk_investigations_tenant_id_alert_id_alerts")),
        sa.UniqueConstraint("tenant_id", "alert_id", "request_key", "attempt",
                            name=op.f("uq_investigations_tenant_id_alert_id_request_key_attempt")),
        sa.CheckConstraint("stage IN ('queued', 'running', 'completed', 'unparseable', 'failed', 'aborted')",
                           name=op.f("ck_investigations_stage")),
        schema=SCHEMA)
    op.create_index("investigations_one_live_per_alert", "investigations", ["tenant_id", "alert_id"], unique=True,
                    schema=SCHEMA, postgresql_where=sa.text("stage IN ('queued', 'running')"))
