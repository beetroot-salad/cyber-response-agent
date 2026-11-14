"""The #1278 learning-state cutover is retired (#1485): every deployment has cut over, so `learning_cutover` leaves the
pending actions an `active` tenant may carry.

Stops, changing nothing, while any tenant row still carries it: finish or resume that tenant's job with the revision
that has the cutover (`0015_system_records`), then run this again. The two CHECK constraints on `tenancy.tenants` that
name the actions are replaced by the texts `0002_tenancy` wrote; no row changes.

Revision ID: 0017_retire_learning_cutover
Revises: 0015_system_records
"""
import sqlalchemy as sa
from alembic import op

revision = "0017_retire_learning_cutover"
down_revision = "0016_list_indexes"

SCHEMA = "tenancy"
ACTIONS = "'create', 'rotate', 'offboard', 'delete_repo'"
#: Spelled here, not imported: a revision says what it wrote when it ran.
STATE_ALLOWS_PENDING_ACTION = (
    "(state = 'creating' AND (pending_action IS NOT DISTINCT FROM 'create'))"
    " OR (state = 'active' AND (pending_action IS NULL OR pending_action IS NOT DISTINCT FROM 'rotate'))"
    " OR (state = 'offboarding' AND (pending_action IS NOT DISTINCT FROM 'offboard'))"
    " OR (state = 'offboarded' AND (pending_action IS NULL OR pending_action IS NOT DISTINCT FROM 'delete_repo'))")


def upgrade() -> None:
    pending: int = op.get_bind().execute(
        sa.text(f"SELECT count(*) FROM {SCHEMA}.tenants WHERE pending_action = 'learning_cutover'")).scalar_one()
    if pending:
        raise RuntimeError(
            f"{pending} tenant(s) still carry a pending learning_cutover: finish it (or resume it) with the previous "
            "revision before upgrading; nothing was changed")
    for name in ("state_allows_pending_action", "pending_action"):
        op.drop_constraint(op.f(f"ck_tenants_{name}"), "tenants", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_tenants_pending_action"), "tenants", f"pending_action IN ({ACTIONS})", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_tenants_state_allows_pending_action"), "tenants", STATE_ALLOWS_PENDING_ACTION,
                               schema=SCHEMA)
