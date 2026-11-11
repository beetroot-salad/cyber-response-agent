"""The learning-state cutover is a lifecycle job (#1278 Migration): `learning_cutover` joins the pending actions an
`active` tenant may carry, beside `rotate`.

The two CHECK constraints on `tenancy.tenants` that name the actions are replaced; no row changes.

Revision ID: 0013_learning_cutover_action
Revises: 0012_learning_store
"""
from alembic import op

revision = "0013_learning_cutover_action"
down_revision = "0012_learning_store"

SCHEMA = "tenancy"
ACTIONS = "'create', 'rotate', 'offboard', 'delete_repo', 'learning_cutover'"
#: Spelled here, not imported: a revision says what it wrote when it ran.
STATE_ALLOWS_PENDING_ACTION = (
    "(state = 'creating' AND (pending_action IS NOT DISTINCT FROM 'create'))"
    " OR (state = 'active' AND (pending_action IS NULL OR pending_action IS NOT DISTINCT FROM 'learning_cutover'"
    " OR pending_action IS NOT DISTINCT FROM 'rotate'))"
    " OR (state = 'offboarding' AND (pending_action IS NOT DISTINCT FROM 'offboard'))"
    " OR (state = 'offboarded' AND (pending_action IS NULL OR pending_action IS NOT DISTINCT FROM 'delete_repo'))")


def upgrade() -> None:
    for name in ("state_allows_pending_action", "pending_action"):
        op.drop_constraint(op.f(f"ck_tenants_{name}"), "tenants", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_tenants_pending_action"), "tenants", f"pending_action IN ({ACTIONS})", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_tenants_state_allows_pending_action"), "tenants", STATE_ALLOWS_PENDING_ACTION,
                               schema=SCHEMA)
