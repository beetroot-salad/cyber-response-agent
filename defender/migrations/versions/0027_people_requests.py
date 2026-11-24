"""Tenant people use Forgejo's web interface (#1592): a tenant's wiring is only its own `t-<T>/knowledge` (a CHECK), a
person's sign-out is recorded (`identity.users.signed_out_at`), and every change to who has access records a people
request (`tenancy.forge_people_requests`) from database triggers in the changing transaction (OD-10). The merge
eligibility record goes (OD-6): feedback reads product membership instead.

Revision ID: 0027_people_requests
Revises: 0026_host_requests

The triggers, one per table, each inserting one request with a fresh `gen_random_uuid()` id and the transaction's
`now()` (no column has a server default):
- `identity.memberships`, after an insert or an update that changes `status`: (U, T) of the row;
- `tenancy.tenants`, after an insert or an update that changes `state`: (none, T);
- `identity.users`, after an update that changes `signed_out_at`: (U, none).
This departs on purpose from 0025's "No trigger": the jobs tables still have none.

On the 0019 precedent the upgrade first refuses, changing nothing, while any tenant has a pending action (create,
rotate, offboard, delete_repo; a failed one included) or a wiring other than its own `t-<T>/knowledge`, naming each
tenant: move the repositories by hand and let every action finish first (`defender/CLAUDE.md`, "Upgrade from before
#1592"). Stop the lifecycle and the feedback drains before migrating (the dropped table is theirs).

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0027_people_requests"
down_revision = "0026_host_requests"

#: The wiring CHECK, frozen here as it stands at this revision (`tenancy.models.WIRING_IS_KNOWLEDGE_REPO`).
_KNOWLEDGE_REPO = "repo = 't-' || tenant_id::text || '/knowledge'"

#: Each recording trigger: the table, the column whose change records, whether an insert records, the request's ids.
_TRIGGERS = (
    ("identity", "memberships", "status", True, "NEW.user_id", "NEW.tenant_id"),
    ("tenancy", "tenants", "state", True, "NULL", "NEW.id"),
    ("identity", "users", "signed_out_at", False, "NEW.id", "NULL"),
)


def _refusals(bind: sa.engine.Connection) -> list[str]:
    """One line per tenant the upgrade cannot take yet, empty when it can."""
    pending = bind.execute(sa.text(
        "SELECT id::text, pending_action FROM tenancy.tenants WHERE pending_action IS NOT NULL ORDER BY id")).all()
    wired = bind.execute(sa.text(
        f"SELECT tenant_id::text, repo FROM tenancy.forge_wiring WHERE NOT ({_KNOWLEDGE_REPO}) ORDER BY tenant_id")).all()
    return ([f"{tenant} has {action} pending" for tenant, action in pending]
            + [f"{tenant} is wired to {repo!r}, not t-{tenant}/knowledge" for tenant, repo in wired])


def _record_on_change(schema: str, table: str, column: str, on_insert: bool, user: str, tenant: str) -> None:
    function = f"{schema}.{table}_people_request"
    changed = f"NEW.{column} IS DISTINCT FROM OLD.{column}"
    condition = f"TG_OP = 'INSERT' OR {changed}" if on_insert else changed
    op.execute(f"""CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF {condition} THEN
        INSERT INTO tenancy.forge_people_requests (id, user_id, tenant_id, requested_at)
        VALUES (gen_random_uuid(), {user}, {tenant}, now());
    END IF;
    RETURN NULL;
END
$$""")
    events = f"INSERT OR UPDATE OF {column}" if on_insert else f"UPDATE OF {column}"
    op.execute(f"CREATE TRIGGER {table}_people_request AFTER {events} ON {schema}.{table} "
               f"FOR EACH ROW EXECUTE FUNCTION {function}()")


def upgrade() -> None:
    refused = _refusals(op.get_bind())
    if refused:
        raise RuntimeError(
            f"{len(refused)} tenant(s) are not ready for #1592's upgrade: {'; '.join(refused)}. Nothing was changed. "
            "Let every pending action finish and move each repository to t-<T>/knowledge first "
            "(defender/CLAUDE.md, \"Upgrade from before #1592\")")

    op.create_check_constraint(op.f("ck_forge_wiring_repo_is_knowledge"), "forge_wiring", _KNOWLEDGE_REPO,
                               schema="tenancy")
    op.add_column("users", sa.Column("signed_out_at", sa.DateTime(timezone=True), nullable=True), schema="identity")
    op.create_table(
        "forge_people_requests",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_forge_people_requests")),
        sa.CheckConstraint("user_id IS NOT NULL OR tenant_id IS NOT NULL",
                           name=op.f("ck_forge_people_requests_names_someone")),
        schema="tenancy")
    for trigger in _TRIGGERS:
        _record_on_change(*trigger)
    op.drop_table("merge_eligibility", schema="tenancy")
