"""The baseline: identity's tables (users, memberships, sessions and, until #1214, tenants).

Revision ID: 0001_baseline
Revises: none
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_baseline"
down_revision = None

SCHEMA = "identity"


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA {SCHEMA}")
    op.create_table(
        "tenants",
        sa.Column("id", sa.Text(), nullable=False),
        _time("created_at", nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        schema=SCHEMA)
    op.create_table(
        "users",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("signin_account_id", sa.Text(), nullable=True),
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False),
        sa.Column("set_password_requested_seq", sa.Integer(), nullable=False),
        sa.Column("set_password_sent_seq", sa.Integer(), nullable=False),
        _time("set_password_requested_at"),
        _time("set_password_sent_at"),
        sa.Column("set_password_attempts", sa.Integer(), nullable=False),
        _time("set_password_next_try_at"),
        _time("created_at", nullable=False),
        _time("updated_at", nullable=False),
        _time("activated_at"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("signin_account_id", name=op.f("uq_users_signin_account_id")),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_users_email_lowercase")),
        sa.CheckConstraint("status IN ('invited', 'active')", name=op.f("ck_users_status")),
        sa.CheckConstraint("status <> 'active' OR activated_at IS NOT NULL",
                           name=op.f("ck_users_active_is_activated")),
        schema=SCHEMA)
    op.create_table(
        "memberships",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("invited_by", sa.Text(), nullable=False),
        _time("created_at", nullable=False),
        sa.Column("notify_requested_seq", sa.Integer(), nullable=False),
        sa.Column("notify_sent_seq", sa.Integer(), nullable=False),
        _time("notify_requested_at"),
        _time("notified_at"),
        sa.Column("notify_attempts", sa.Integer(), nullable=False),
        _time("notify_next_try_at"),
        _time("expires_at"),
        _time("accepted_at"),
        _time("ended_at"),
        sa.Column("ended_by", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"],
                                name=op.f("fk_memberships_user_id_users")),
        sa.ForeignKeyConstraint(["tenant_id"], [f"{SCHEMA}.tenants.id"],
                                name=op.f("fk_memberships_tenant_id_tenants")),
        sa.CheckConstraint("status IN ('invited', 'active', 'ended', 'revoked')",
                           name=op.f("ck_memberships_status")),
        sa.CheckConstraint("status <> 'active' OR accepted_at IS NOT NULL",
                           name=op.f("ck_memberships_active_is_accepted")),
        sa.CheckConstraint("status <> 'ended' OR (ended_at IS NOT NULL AND ended_by IS NOT NULL)",
                           name=op.f("ck_memberships_ended_is_ended")),
        schema=SCHEMA)
    op.create_index("memberships_one_live_row", "memberships", ["user_id", "tenant_id"], unique=True,
                    schema=SCHEMA, postgresql_where=sa.text("status IN ('invited', 'active')"))
    op.create_index("memberships_by_tenant", "memberships", ["tenant_id"], schema=SCHEMA)
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("used_otp", sa.Boolean(), nullable=False),
        _time("created_at", nullable=False),
        _time("last_seen_at", nullable=False),
        _time("expires_at", nullable=False),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_sessions")),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"], name=op.f("fk_sessions_user_id_users")),
        schema=SCHEMA)
    op.create_index("sessions_by_user", "sessions", ["user_id"], schema=SCHEMA)
