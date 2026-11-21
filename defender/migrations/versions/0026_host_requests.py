"""Host requests (#1471): `jobs.host_requests`, the one table of the short requests a tenant admin makes of the host, a
readiness check of the tenant or an adoption of a system's base files. A request runs once and is never retried: it ends
`completed` with its kind's JSON result, or `failed` with a fixed reason and the worker's own words.

At most one row of a kind and dedupe key is queued (a partial unique index); a running or ended row dedupes nothing. The
claim reads the oldest queued row of any kind, the take-over the running rows by lease, the offboard a tenant's live
rows: one index each. Every value is set by the store in Python (no server defaults). The tenant key carries no ON
DELETE action, as every jobs table (M10). The stages and kinds are frozen here as they stand at this revision.

Revision ID: 0026_host_requests
Revises: 0025_alert_outcome

Creates a table and changes no other. There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0026_host_requests"
down_revision = "0025_alert_outcome"

SCHEMA = "jobs"

_STAGES = "'queued', 'running', 'completed', 'failed'"
_KINDS = "'readiness', 'adoption'"


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "host_requests",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("dedupe_key", sa.Text(), nullable=False),
        sa.Column("system_id", sa.Text(), nullable=True),
        sa.Column("requester", sa.Text(), nullable=False),
        _time("created_at", nullable=False),
        _time("started_at"),
        _time("finished_at"),
        sa.Column("stage", sa.Text(), nullable=False),
        _time("lease_expires_at"),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("failure_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_host_requests")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_host_requests_tenant_id_tenants")),
        sa.CheckConstraint(f"stage IN ({_STAGES})", name=op.f("ck_host_requests_stage")),
        sa.CheckConstraint(f"kind IN ({_KINDS})", name=op.f("ck_host_requests_kind")),
        sa.CheckConstraint("stage <> 'running' OR lease_expires_at IS NOT NULL",
                           name=op.f("ck_host_requests_running_has_a_lease")),
        schema=SCHEMA)
    op.create_index("host_requests_one_queued_per_key", "host_requests", ["kind", "dedupe_key"], unique=True,
                    schema=SCHEMA, postgresql_where=sa.text("stage = 'queued'"))
    op.create_index("host_requests_queued_by_age", "host_requests", ["created_at", "id"], schema=SCHEMA,
                    postgresql_where=sa.text("stage = 'queued'"))
    op.create_index("host_requests_running_by_lease", "host_requests", ["lease_expires_at", "id"], schema=SCHEMA,
                    postgresql_where=sa.text("stage = 'running'"))
    op.create_index("host_requests_live_by_tenant", "host_requests", ["tenant_id"], schema=SCHEMA,
                    postgresql_where=sa.text("stage IN ('queued', 'running')"))
