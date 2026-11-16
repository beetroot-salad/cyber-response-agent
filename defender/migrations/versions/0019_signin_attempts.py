"""Sign-in attempts in flight (#1161 D6): the browser keeps only a random token under the attempt's cookie, and the
nonce, PKCE verifier and return path stay here until the callback reads them once.

Revision ID: 0019_signin_attempts
Revises: 0018_learning_set_aside_indexes
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_signin_attempts"
down_revision = "0018_learning_set_aside_indexes"

SCHEMA = "identity"


def upgrade() -> None:
    op.create_table(
        "signin_attempts",
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("verifier", sa.Text(), nullable=False),
        sa.Column("return_path", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("state", name=op.f("pk_signin_attempts")),
        schema=SCHEMA)
    op.create_index("signin_attempts_by_expiry", "signin_attempts", ["expires_at"], schema=SCHEMA)

