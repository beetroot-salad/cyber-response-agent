"""Programs get their own table (#1454): a program is a row of `identity.programs` (its tenant, creator, name and removal),
no longer a `users` row of kind `program` with an `automation` membership. Users are people only (a required email, no
`kind`, no creator), a membership's role is `admin` alone, and a credential's `program_id` is a plain foreign key to
`programs`. A program is removed exactly when it has a removal time: there is no separate status. No production path ever
wrote a program (census C3), so nothing moves: the upgrade refuses, changing nothing, while any row exists that the new
schema cannot hold (a program user, or a membership whose role is not `admin`).

Revision ID: 0012_programs_table
Revises: 0011_merge_eligibility
"""
import sqlalchemy as sa
from alembic import op

revision = "0012_programs_table"
down_revision = "0011_merge_eligibility"

_TIME = sa.DateTime(timezone=True)


def _uuid() -> sa.Uuid:
    return sa.Uuid(as_uuid=False)


def upgrade() -> None:
    bind = op.get_bind()
    programs: int = bind.execute(sa.text("SELECT count(*) FROM identity.users WHERE kind = 'program'")).scalar_one()
    # The old schema let any user, a person included, hold `automation`; the new role CHECK refuses it.
    roles: int = bind.execute(sa.text("SELECT count(*) FROM identity.memberships WHERE role <> 'admin'")).scalar_one()
    if programs or roles:
        raise RuntimeError(
            f"{programs} program row(s) in identity.users and {roles} membership(s) whose role is not 'admin': programs "
            "now have their own table, a membership's role is 'admin' alone, and no data move is written for either "
            "(#1454); remove them, or move them by hand, before upgrading")

    op.create_table(
        "programs",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("tenant_id", _uuid(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("created_by", _uuid(), nullable=False),
        sa.Column("created_at", _TIME, nullable=False),
        sa.Column("removed_at", _TIME, nullable=True),
        sa.Column("removed_by", _uuid(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_programs")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_programs_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["created_by"], ["identity.users.id"], name=op.f("fk_programs_created_by_users")),
        sa.ForeignKeyConstraint(["removed_by"], ["identity.users.id"], name=op.f("fk_programs_removed_by_users")),
        schema="identity")
    op.create_index("programs_by_tenant", "programs", ["tenant_id"], schema="identity")

    # A credential's program is a `programs` row: the table is the rule, so the composite key and its kind column go.
    op.drop_constraint(op.f("fk_program_credentials_program_id_program_kind_users"), "program_credentials",
                       type_="foreignkey", schema="identity")
    op.drop_constraint(op.f("ck_program_credentials_program_kind"), "program_credentials", type_="check", schema="identity")
    op.drop_column("program_credentials", "program_kind", schema="identity")
    op.create_foreign_key(op.f("fk_program_credentials_program_id_programs"), "program_credentials", "programs",
                          ["program_id"], ["id"], source_schema="identity", referent_schema="identity")

    # Memberships are people's: `admin` alone (the column stays for a planned tenant analyst role, R1).
    op.drop_constraint(op.f("ck_memberships_role"), "memberships", type_="check", schema="identity")
    op.create_check_constraint(op.f("ck_memberships_role"), "memberships", "role IN ('admin')", schema="identity")

    # Users are people: a required email, no kind, no creator.
    for name in ("ck_users_email_iff_person", "ck_users_program_is_plain", "ck_users_creator_is_for_programs",
                 "ck_users_kind"):
        op.drop_constraint(op.f(name), "users", type_="check", schema="identity")
    op.drop_constraint(op.f("uq_users_id_kind"), "users", type_="unique", schema="identity")
    op.drop_column("users", "created_by", schema="identity")
    op.drop_column("users", "kind", schema="identity")
    op.alter_column("users", "email", existing_type=sa.Text(), nullable=False, schema="identity")
