"""Learning jobs (#1344): one row per attempt of a learning job, beside the investigations.

Revision ID: 0008_learning_jobs
Revises: 0007_alert_mapping

No backfill: an investigation that ended `completed` before this revision queues no job (O1). Every
value is set by the store in Python (no server defaults). The foreign keys carry no ON DELETE
action: the investigation delete removes its jobs itself, under their row locks (O10).
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_learning_jobs"
down_revision = "0007_alert_mapping"

SCHEMA = "jobs"


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "learning_jobs",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("alert_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("investigation_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("request_key", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        _time("created_at", nullable=False),
        sa.Column("stage", sa.Text(), nullable=True),
        sa.Column("fork_message_id", sa.Text(), nullable=True),
        sa.Column("sibling_cost_usd", sa.Float(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("publish_state", sa.Text(), nullable=False),
        _time("started_at"),
        _time("finished_at"),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        _time("lease_expires_at"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_learning_jobs")),
        sa.ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"],
                                name=op.f("fk_learning_jobs_tenant_id_alert_id_alerts")),
        sa.ForeignKeyConstraint(["investigation_id"], [f"{SCHEMA}.investigations.id"],
                                name=op.f("fk_learning_jobs_investigation_id_investigations")),
        sa.UniqueConstraint("tenant_id", "investigation_id", "request_key", "attempt",
                            name=op.f("uq_learning_jobs_tenant_id_investigation_id_request_key_attempt")),
        sa.CheckConstraint("status IN ('queued', 'running', 'completed', 'failed', 'skipped')",
                           name=op.f("ck_learning_jobs_status")),
        sa.CheckConstraint("trigger IN ('auto', 'explicit')", name=op.f("ck_learning_jobs_trigger")),
        sa.CheckConstraint("publish_state IN ('none', 'pending', 'done', 'refused')",
                           name=op.f("ck_learning_jobs_publish_state")),
        sa.CheckConstraint("status <> 'running' OR lease_expires_at IS NOT NULL",
                           name=op.f("ck_learning_jobs_running_has_a_lease")),
        schema=SCHEMA)
