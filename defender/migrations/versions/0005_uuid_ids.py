"""Record ids are PostgreSQL `uuid` (#1382): tenant, user, membership, alert and investigation ids,
and every column that refers to one. A row whose id is not UUID text makes the cast fail, and the
upgrade stops there with nothing changed. A membership's `invited_by`/`ended_by` hold a user id or,
for the system, NULL (they held the text `'system'`) and now refer to `identity.users`.

Revision ID: 0005_uuid_ids
Revises: 0004_jobs
"""
from alembic import op

revision = "0005_uuid_ids"
down_revision = "0004_jobs"

#: Every foreign key over an id column: (table, name, columns, referred table, referred columns).
#: Dropped before the columns change type, and made again after.
_FOREIGN_KEYS = (
    ("identity.memberships", "fk_memberships_user_id_users", "user_id", "identity.users", "id"),
    ("identity.memberships", "fk_memberships_tenant_id_tenants", "tenant_id", "tenancy.tenants", "id"),
    ("identity.sessions", "fk_sessions_user_id_users", "user_id", "identity.users", "id"),
    ("tenancy.forge_wiring", "fk_forge_wiring_tenant_id_tenants", "tenant_id", "tenancy.tenants", "id"),
    ("tenancy.generations", "fk_generations_tenant_id_tenants", "tenant_id", "tenancy.tenants", "id"),
    ("tenancy.publish_status", "fk_publish_status_tenant_id_tenants", "tenant_id", "tenancy.tenants", "id"),
    ("jobs.alerts", "fk_alerts_tenant_id_tenants", "tenant_id", "tenancy.tenants", "id"),
    ("jobs.investigations", "fk_investigations_tenant_id_alert_id_alerts", "tenant_id, alert_id",
     "jobs.alerts", "tenant_id, id"),
)

#: Every id column, by table.
_ID_COLUMNS = (
    ("tenancy.tenants", ("id",)),
    ("identity.users", ("id",)),
    ("identity.memberships", ("id", "user_id", "tenant_id", "invited_by", "ended_by")),
    ("identity.sessions", ("user_id",)),
    ("tenancy.forge_wiring", ("tenant_id",)),
    ("tenancy.generations", ("tenant_id",)),
    ("tenancy.publish_status", ("tenant_id",)),
    ("jobs.alerts", ("id", "tenant_id")),
    ("jobs.investigations", ("id", "tenant_id", "alert_id")),
)


def upgrade() -> None:
    for table, name, *_ in _FOREIGN_KEYS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT {name}")
    op.execute("ALTER TABLE identity.memberships DROP CONSTRAINT ck_memberships_ended_is_ended")
    op.execute("ALTER TABLE identity.memberships ALTER COLUMN invited_by DROP NOT NULL")
    op.execute("UPDATE identity.memberships SET invited_by = NULL WHERE invited_by = 'system'")
    op.execute("UPDATE identity.memberships SET ended_by = NULL WHERE ended_by = 'system'")
    for table, names in _ID_COLUMNS:
        changes = ", ".join(f"ALTER COLUMN {c} TYPE uuid USING {c}::uuid" for c in names)
        op.execute(f"ALTER TABLE {table} {changes}")
    for table, name, columns, referred, referred_columns in _FOREIGN_KEYS:
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} FOREIGN KEY ({columns})"
                   f" REFERENCES {referred} ({referred_columns})")
    for column in ("invited_by", "ended_by"):
        op.execute(f"ALTER TABLE identity.memberships ADD CONSTRAINT fk_memberships_{column}_users"
                   f" FOREIGN KEY ({column}) REFERENCES identity.users (id)")
    op.execute("ALTER TABLE identity.memberships ADD CONSTRAINT ck_memberships_ended_is_ended"
               " CHECK (status <> 'ended' OR ended_at IS NOT NULL)")
