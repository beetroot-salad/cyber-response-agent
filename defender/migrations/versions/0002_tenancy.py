"""Tenancy (#1214): `tenants` moves from `identity` to a `tenancy` schema and gains its job columns;
the forge wiring, credential generations and publish status tables are added.

The move keeps the rows, the memberships' foreign key (its name is schema-free) and the primary
key. Every tenant registered before this revision becomes a failed create: `creating`, `create`
pending at step `names` (service), with a failure saying what to do. An administrator records the
tenant's forge wiring by hand, if it has a repository already, and resumes it. Columns are added nullable, filled, then made NOT NULL, leaving no default.

Revision ID: 0002_tenancy
Revises: 0001_baseline
"""
import sqlalchemy as sa
from alembic import op

revision = "0002_tenancy"
down_revision = "0001_baseline"

SCHEMA = "tenancy"
#: Spelled here, not imported: a revision says what it wrote when it ran.
BACKFILL_FAILURE = "registered before #1214: record its forge wiring if it has a repository, then resume"
#: A state only with the pending actions it allows. NULL-safe: a CHECK lets a NULL result through,
#: so `pending_action = 'create'` alone would admit `creating` with nothing pending.
STATE_ALLOWS_PENDING_ACTION = (
    "(state = 'creating' AND (pending_action IS NOT DISTINCT FROM 'create'))"
    " OR (state = 'active' AND (pending_action IS NULL OR pending_action IS NOT DISTINCT FROM 'rotate'))"
    " OR (state = 'offboarding' AND (pending_action IS NOT DISTINCT FROM 'offboard'))"
    " OR (state = 'offboarded' AND (pending_action IS NULL OR pending_action IS NOT DISTINCT FROM 'delete_repo'))")


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _tenant_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(["tenant_id"], [f"{SCHEMA}.tenants.id"], name=op.f(f"fk_{table}_tenant_id_tenants"))


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA {SCHEMA}")
    op.execute(f"ALTER TABLE identity.tenants SET SCHEMA {SCHEMA}")
    for name in ("state", "pending_action", "step", "step_actor", "failure", "repo_url"):
        op.add_column("tenants", sa.Column(name, sa.Text(), nullable=True), schema=SCHEMA)
    for name in ("offboarded_at", "repo_delete_after"):
        op.add_column("tenants", _time(name), schema=SCHEMA)
    op.execute(sa.text(
        f"UPDATE {SCHEMA}.tenants SET state = 'creating', pending_action = 'create', step = 'names',"
        " step_actor = 'service', failure = :failure").bindparams(failure=BACKFILL_FAILURE))
    op.alter_column("tenants", "state", nullable=False, schema=SCHEMA)
    op.create_check_constraint(
        op.f("ck_tenants_state"), "tenants", "state IN ('creating', 'active', 'offboarding', 'offboarded')",
        schema=SCHEMA)
    op.create_check_constraint(
        op.f("ck_tenants_pending_action"), "tenants",
        "pending_action IN ('create', 'rotate', 'offboard', 'delete_repo')", schema=SCHEMA)
    op.create_check_constraint(
        op.f("ck_tenants_step_actor"), "tenants", "step_actor IN ('service', 'host')", schema=SCHEMA)
    op.create_check_constraint(
        op.f("ck_tenants_state_allows_pending_action"), "tenants", STATE_ALLOWS_PENDING_ACTION, schema=SCHEMA)

    op.create_table(
        "forge_wiring",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("repo", sa.Text(), nullable=False),
        sa.Column("origin", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_forge_wiring")),
        _tenant_fk("forge_wiring"),
        schema=SCHEMA)
    op.create_table(
        "generations",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("salt", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("bot_login", sa.Text(), nullable=False),
        sa.Column("oidc_role", sa.Text(), nullable=False),
        sa.Column("approle", sa.Text(), nullable=False),
        sa.Column("entity", sa.Text(), nullable=False),
        sa.Column("integration_args", sa.ARRAY(sa.Text()), nullable=True),
        sa.Column("role_id", sa.Text(), nullable=True),
        sa.Column("audience", sa.Text(), nullable=True),
        sa.Column("host_secret_file", sa.Text(), nullable=True),
        sa.Column("wrapped_secret", sa.Text(), nullable=True),
        sa.Column("secret_accessor", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("tenant_id", "salt", name=op.f("pk_generations")),
        _tenant_fk("generations"),
        sa.CheckConstraint("status IN ('pending', 'live', 'retiring', 'destroyed')",
                           name=op.f("ck_generations_status")),
        schema=SCHEMA)
    op.create_index("generations_one_live", "generations", ["tenant_id"], unique=True, schema=SCHEMA,
                    postgresql_where=sa.text("status = 'live'"))
    op.create_table(
        "publish_status",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("recorded_by", sa.Text(), nullable=False),
        sa.Column("published", sa.Text(), nullable=True),
        sa.Column("refused", sa.Text(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_publish_status")),
        _tenant_fk("publish_status"),
        schema=SCHEMA)
