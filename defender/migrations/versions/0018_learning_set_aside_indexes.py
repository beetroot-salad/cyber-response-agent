"""The API's reads of held, dead and parked learning work (#1485): `work_items.id` and two partial indexes.

`work_items.id` is filled for existing rows in SQL and keeps `gen_random_uuid()` as its default, the one server default
in the schema: the store still mints the id at insert, and the default only fills it for a process of older code that
inserts none, so it can keep running across the upgrade.

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
    op.alter_column("work_items", "id", nullable=False, server_default=sa.text("gen_random_uuid()"), schema=SCHEMA)
    op.create_unique_constraint(None, "work_items", ["id"], schema=SCHEMA)
    op.create_index("work_items_set_aside", "work_items",
                    ["tenant_id", sa.text("updated_at DESC"), sa.text("id DESC")],
                    schema=SCHEMA, postgresql_where=sa.text("status IN ('held', 'dead')"))
    op.create_index("batches_needs_person", "batches", ["tenant_id", sa.text("created_at DESC"), sa.text("id DESC")],
                    schema=SCHEMA, postgresql_where=sa.text("phase = 'needs_person'"))
