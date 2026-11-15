"""The API's reads of held, dead and parked learning work (#1485): `work_items.id` and two partial indexes.

`work_items.id` is filled for existing rows in SQL and left with no default: the store mints it at insert.

Revision ID: 0018_learning_set_aside_indexes
Revises: 0017_retire_learning_cutover
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0018_learning_set_aside_indexes"
down_revision = "0017_retire_learning_cutover"

SCHEMA = "learning"


def upgrade() -> None:
    op.add_column("work_items", sa.Column("id", postgresql.UUID(as_uuid=False), nullable=True), schema=SCHEMA)
    op.execute(f"UPDATE {SCHEMA}.work_items SET id = gen_random_uuid() WHERE id IS NULL")
    op.alter_column("work_items", "id", nullable=False, schema=SCHEMA)
    op.create_unique_constraint(None, "work_items", ["id"], schema=SCHEMA)
    op.create_index("work_items_set_aside", "work_items",
                    ["tenant_id", sa.text("updated_at DESC"), sa.text("id DESC")],
                    schema=SCHEMA, postgresql_where=sa.text("status IN ('held', 'dead')"))
    op.create_index("batches_needs_person", "batches", ["tenant_id", sa.text("created_at DESC"), sa.text("id DESC")],
                    schema=SCHEMA, postgresql_where=sa.text("phase = 'needs_person'"))
