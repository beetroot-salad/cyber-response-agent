"""Program identities (#1307): a user has a `kind` (`person` | `program`) and, for a program, its creator; a
program has no email, so `users.email` may be absent (exactly for programs). A membership has a `role`
(`admin` | `automation`): every existing row is a person's, so `admin`. A new table holds the programs' credentials.

Revision ID: 0008_programs
Revises: 0007_alert_mapping
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_programs"
down_revision = "0007_alert_mapping"

_TIME = sa.DateTime(timezone=True)


def _uuid() -> sa.Uuid:
    return sa.Uuid(as_uuid=False)


def upgrade() -> None:
    op.add_column("users", sa.Column("kind", sa.Text(), nullable=False, server_default="person"), schema="identity")
    op.alter_column("users", "kind", server_default=None, schema="identity")
    op.add_column("users", sa.Column("created_by", _uuid(), nullable=True), schema="identity")
    op.create_foreign_key(
        "fk_users_created_by_users", "users", "users", ["created_by"], ["id"],
        source_schema="identity", referent_schema="identity")
    op.alter_column("users", "email", existing_type=sa.Text(), nullable=True, schema="identity")
    op.create_check_constraint("kind", "users", "kind IN ('person', 'program')", schema="identity")
    op.create_check_constraint(
        "email_iff_person", "users", "(kind = 'program') = (email IS NULL)", schema="identity")
    op.create_check_constraint(
        "program_is_plain", "users",
        "kind = 'person' OR (signin_account_id IS NULL AND NOT is_platform_admin AND status = 'active')",
        schema="identity")
    op.create_check_constraint(
        "creator_is_for_programs", "users", "kind = 'program' OR created_by IS NULL", schema="identity")
    # The target of `program_credentials`' composite foreign key: a credential's program is a program by schema, not by recheck.
    op.create_unique_constraint(op.f("uq_users_id_kind"), "users", ["id", "kind"], schema="identity")

    op.add_column("memberships", sa.Column("role", sa.Text(), nullable=False, server_default="admin"), schema="identity")
    op.alter_column("memberships", "role", server_default=None, schema="identity")
    op.create_check_constraint(
        "role", "memberships", "role IN ('admin', 'automation')", schema="identity")

    op.create_table(
        "program_credentials",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("program_id", _uuid(), nullable=False),
        # Always 'program'; with the composite foreign key below it ties `program_id` to a user of kind program.
        sa.Column("program_kind", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_by", _uuid(), nullable=False),
        sa.Column("created_at", _TIME, nullable=False),
        sa.Column("expires_at", _TIME, nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=True),
        sa.Column("service_account_id", sa.Text(), nullable=True),
        sa.Column("pending_deadline", _TIME, nullable=True),
        sa.Column("last_used_at", _TIME, nullable=True),
        sa.Column("revoked_at", _TIME, nullable=True),
        sa.Column("revoked_by", _uuid(), nullable=True),
        sa.Column("warn_threshold_days", sa.Integer(), nullable=True),
        sa.Column("warn_next_at", _TIME, nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_program_credentials")),
        sa.ForeignKeyConstraint(
            ["program_id", "program_kind"], ["identity.users.id", "identity.users.kind"],
            name=op.f("fk_program_credentials_program_id_program_kind_users")),
        sa.CheckConstraint("program_kind = 'program'", name=op.f("ck_program_credentials_program_kind")),
        sa.ForeignKeyConstraint(["created_by"], ["identity.users.id"], name=op.f("fk_program_credentials_created_by_users")),
        sa.ForeignKeyConstraint(["revoked_by"], ["identity.users.id"], name=op.f("fk_program_credentials_revoked_by_users")),
        sa.CheckConstraint("kind IN ('key', 'oauth_client')", name=op.f("ck_program_credentials_kind")),
        sa.CheckConstraint("state IN ('pending', 'live', 'revoked')", name=op.f("ck_program_credentials_state")),
        sa.CheckConstraint("(kind = 'key') = (key_hash IS NOT NULL)", name=op.f("ck_program_credentials_key_iff_hash")),
        sa.CheckConstraint("state <> 'pending' OR kind = 'oauth_client'",
                           name=op.f("ck_program_credentials_only_oauth_is_pending")),
        sa.CheckConstraint("state <> 'revoked' OR revoked_at IS NOT NULL",
                           name=op.f("ck_program_credentials_revoked_is_revoked")),
        sa.CheckConstraint("warn_threshold_days IN (14, 3)", name=op.f("ck_program_credentials_warn_threshold")),
        sa.CheckConstraint("(warn_threshold_days IS NULL) = (warn_next_at IS NULL)",
                           name=op.f("ck_program_credentials_warn_both_or_neither")),
        schema="identity")
    op.create_index("program_credentials_by_program", "program_credentials", ["program_id"], schema="identity")
    op.create_index("program_credentials_one_unrevoked_key", "program_credentials", ["key_hash"], unique=True,
                    schema="identity", postgresql_where=sa.text("state <> 'revoked'"))
    op.create_index("program_credentials_warning_due", "program_credentials", ["warn_next_at"], schema="identity",
                    postgresql_where=sa.text("warn_next_at IS NOT NULL"))

    op.create_table(
        "warning_deliveries",
        sa.Column("credential_id", _uuid(), nullable=False),
        sa.Column("threshold_days", sa.Integer(), nullable=False),
        sa.Column("person_id", _uuid(), nullable=False),
        sa.Column("sent_at", _TIME, nullable=False),
        sa.PrimaryKeyConstraint(
            "credential_id", "threshold_days", "person_id", name=op.f("pk_warning_deliveries")),
        sa.ForeignKeyConstraint(["credential_id"], ["identity.program_credentials.id"],
                                name=op.f("fk_warning_deliveries_credential_id_program_credentials")),
        sa.ForeignKeyConstraint(["person_id"], ["identity.users.id"],
                                name=op.f("fk_warning_deliveries_person_id_users")),
        sa.CheckConstraint("threshold_days IN (14, 3)", name=op.f("ck_warning_deliveries_threshold")),
        schema="identity")
