"""Evidence login (#1546 A-O5, r9): each credential generation records a third AppRole chain beside the delivery and
sign ones, the evidence login that takes a datakey of, and decrypts with, the tenant's `evidence-<T>` key: the AppRole and
entity names, the role id, the host's secret file, its single-use wrapping token and the installed secret's accessor.

The columns are nullable and left NULL on the rows already there. There is no backfill: no tenant survives the upgrade
without being created again (`0030_retention_required` refuses while one lacks its retention), and the lifecycle makes
the chain for every new generation.

Revision ID: 0031_evidence_login
Revises: 0030_retention_required

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0031_evidence_login"
down_revision = "0030_retention_required"

SCHEMA = "tenancy"
COLUMNS = ("evidence_approle", "evidence_entity", "evidence_role_id", "evidence_secret_file", "evidence_wrapped_secret",
           "evidence_secret_accessor")


def upgrade() -> None:
    for name in COLUMNS:
        op.add_column("generations", sa.Column(name, sa.Text(), nullable=True), schema=SCHEMA)
