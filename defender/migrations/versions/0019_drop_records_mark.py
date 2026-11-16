"""No "not imported" state (#1470 O8, D-F): the per-tenant records mark goes, and the proxy's read-only role reads whether
a token's tenant is known from the tenant row instead (its `id` and `state` columns, nothing else of the row).

Revision ID: 0019_drop_records_mark
Revises: 0018_learning_set_aside_indexes

A tenant's records are known exactly while it is `active`. Every tenant created since #1366 has its mark; one without it
(from before #1366, never moved onto records) would read as a tenant with no systems once the mark is gone, so the
upgrade stops, changing nothing, while any tenant that is not offboarded lacks it: recreate such a development database.
Stop the API, the credential proxy and the workers before migrating (they read the dropped table), and rebuild the job
image with the upgrade (`defender/CLAUDE.md`, "Upgrade from before #1366").

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_drop_records_mark"
down_revision = "0018_learning_set_aside_indexes"

ROLE = "defender_proxy_reader"


def upgrade() -> None:
    bind = op.get_bind()
    found = bind.execute(sa.text(
        "SELECT t.id FROM tenancy.tenants t WHERE t.state <> 'offboarded' "
        "AND NOT EXISTS (SELECT 1 FROM tenancy.records_mark m WHERE m.tenant_id = t.id) ORDER BY t.id"))
    unmarked = [str(row[0]) for row in found]
    if unmarked:
        raise RuntimeError(
            f"{len(unmarked)} tenant(s) not offboarded have no records mark (from before #1366, their systems never "
            f"moved onto records): {', '.join(unmarked)}. Without the mark each would read as a tenant with no systems "
            "(#1470); nothing was changed. Recreate such a development database before upgrading")

    op.drop_table("records_mark", schema="tenancy")
    # The proxy tells an unknown tenant from an unknown system by the tenant row (#1470 O8): exactly its id and state.
    op.execute(f"GRANT SELECT (id, state) ON tenancy.tenants TO {ROLE}")
