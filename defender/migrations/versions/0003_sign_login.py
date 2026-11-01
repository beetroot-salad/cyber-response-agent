"""Sign login (#1163 A24'): each credential generation records a second, sign-only AppRole chain
beside its delivery one: the AppRole and entity names, the role id, the host's sign secret file,
its single-use wrapping token and the installed secret's accessor.

The columns are nullable and left NULL on the rows already there: a generation recorded before
this revision has no sign login. The lifecycle's provider records the names of a pending one
before it makes anything (r8.5); a live one gets its sign login from the tenant's next rotation.

Revision ID: 0003_sign_login
Revises: 0002_tenancy
"""
import sqlalchemy as sa
from alembic import op

revision = "0003_sign_login"
down_revision = "0002_tenancy"

SCHEMA = "tenancy"
COLUMNS = ("sign_approle", "sign_entity", "sign_role_id", "sign_secret_file", "sign_wrapped_secret",
           "sign_secret_accessor")


def upgrade() -> None:
    for name in COLUMNS:
        op.add_column("generations", sa.Column(name, sa.Text(), nullable=True), schema=SCHEMA)
