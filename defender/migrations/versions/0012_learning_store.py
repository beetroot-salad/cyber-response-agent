"""The learning store (#1278): work items, batches and the commit-maker's record; #1414's feedback records (A4:
issues, comments, the feedback tick's lease and cursor).

Revision ID: 0012_learning_store
Revises: 0011_merge_eligibility

No backfill here: a tenant's file state is imported once, at its cutover (`import_learning_state`). Every
value is set by the store in Python (no server defaults). The rules the data holds on its own (one item per
key, one waiting request per case, one open authoring batch and one working batch per lane, one run per feedback
issue) are constraints and partial unique indexes.
"""
import sqlalchemy as sa
from alembic import op

revision = "0012_learning_store"
down_revision = "0011_merge_eligibility"

SCHEMA = "learning"
KINDS = "'finding', 'questioner_finding', 'pitfall', 'curation_request', 'feedback_instruction'"
STATUSES = "'waiting', 'in_batch', 'held', 'published', 'skipped', 'dead'"


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.execute(sa.schema.CreateSchema(SCHEMA))
    tenant = ["tenancy.tenants.id"]
    op.create_table(
        "batches",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("lane", sa.Text(), nullable=False),
        sa.Column("branch", sa.Text(), nullable=False),
        sa.Column("base", sa.Text(), nullable=True),
        sa.Column("start", sa.Text(), nullable=True),
        sa.Column("phase", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        _time("lease_expiry"),
        sa.Column("fencing_token", sa.Integer(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("replaces", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("refusals", sa.Integer(), nullable=False),
        _time("last_checked"),
        sa.Column("reason", sa.Text(), nullable=True),
        _time("created_at", nullable=False),
        _time("ended_at"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_batches")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_batches_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["replaces"], [f"{SCHEMA}.batches.id"], name=op.f("fk_batches_replaces_batches")),
        sa.CheckConstraint("kind IN ('author', 'revert', 'registry')", name=op.f("ck_batches_kind")),
        sa.CheckConstraint("lane IN ('author', 'lead_author', 'feedback')",  # lint-run-records: ok — the lane's database value
                           name=op.f("ck_batches_lane")),
        sa.CheckConstraint("phase IN ('working', 'in_review', 'needs_person', 'ended')", name=op.f("ck_batches_phase")),
        sa.CheckConstraint("outcome IS NULL OR outcome IN ('merged', 'closed', 'abandoned')",
                           name=op.f("ck_batches_outcome")),
        sa.CheckConstraint("(phase = 'ended') = (outcome IS NOT NULL)", name=op.f("ck_batches_ended_has_an_outcome")),
        sa.CheckConstraint("phase <> 'working' OR (lease_owner IS NOT NULL AND lease_expiry IS NOT NULL)",
                           name=op.f("ck_batches_working_has_a_lease")),
        sa.CheckConstraint("phase <> 'in_review' OR pr_number IS NOT NULL", name=op.f("ck_batches_in_review_has_a_pr")),
        schema=SCHEMA)
    op.create_index("batches_one_open_author_per_lane", "batches", ["tenant_id", "lane"], unique=True, schema=SCHEMA,
                    postgresql_where=sa.text("kind IN ('author', 'registry') AND phase <> 'ended'"))
    op.create_index("batches_one_working_per_lane", "batches", ["tenant_id", "lane"], unique=True, schema=SCHEMA,
                    postgresql_where=sa.text("phase = 'working'"))
    op.create_table(
        "work_items",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("item_key", sa.Text(), nullable=False),
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("source_run", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("fault", sa.Text(), nullable=True),
        sa.Column("batch_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("deferrals", sa.Integer(), nullable=False),
        sa.Column("offers_declined", sa.Integer(), nullable=False),
        sa.Column("coalesce_key", sa.Text(), nullable=True),
        sa.Column("mistake_key", sa.Text(), nullable=True),
        _time("enqueued_at", nullable=False),
        _time("updated_at", nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "kind", "item_key", name=op.f("pk_work_items")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_work_items_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["batch_id"], [f"{SCHEMA}.batches.id"], name=op.f("fk_work_items_batch_id_batches")),
        sa.CheckConstraint(f"kind IN ({KINDS})", name=op.f("ck_work_items_kind")),
        sa.CheckConstraint(f"status IN ({STATUSES})", name=op.f("ck_work_items_status")),
        schema=SCHEMA)
    op.create_index("work_items_one_waiting_request_per_case", "work_items", ["tenant_id", "kind", "coalesce_key"],
                    unique=True, schema=SCHEMA,
                    postgresql_where=sa.text("status = 'waiting' AND coalesce_key IS NOT NULL"))
    op.create_index("work_items_by_status", "work_items", ["tenant_id", "status"], schema=SCHEMA)
    op.create_index("work_items_by_batch", "work_items", ["batch_id"], schema=SCHEMA)
    op.create_table(
        "commits",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("batch_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("commit", sa.Text(), nullable=False),
        sa.Column("branch", sa.Text(), nullable=False),
        sa.Column("base", sa.Text(), nullable=False),
        sa.Column("start", sa.Text(), nullable=False),
        sa.Column("reverts", sa.dialects.postgresql.JSONB(), nullable=True),
        _time("created_at", nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_commits")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_commits_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["batch_id"], [f"{SCHEMA}.batches.id"], name=op.f("fk_commits_batch_id_batches")),
        schema=SCHEMA)
    op.create_index("commits_by_tenant", "commits", ["tenant_id", "created_at"], schema=SCHEMA)
    op.create_table(
        "commit_changes",
        sa.Column("commit_row", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("blob_base", sa.Text(), nullable=True),
        sa.Column("blob_left", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("commit_row", "ordinal", name=op.f("pk_commit_changes")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_commit_changes_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["commit_row"], [f"{SCHEMA}.commits.id"],
                                name=op.f("fk_commit_changes_commit_row_commits")),
        schema=SCHEMA)
    _feedback_tables(tenant)


def _feedback_tables(tenant: list[str]) -> None:
    """#1414's feedback records (A4): one row per run whose issue is owed or recorded, one per comment taken in, and
    the tenant's feedback tick (its comment cursor and lease)."""
    op.create_table(
        "feedback_issues",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("case_id", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("lookups", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("issue_number", sa.Integer(), nullable=True),
        sa.Column("listed", sa.Boolean(), nullable=False),
        sa.Column("judged_comment_ids", sa.dialects.postgresql.JSONB(), nullable=False),
        _time("requested_at", nullable=False),
        _time("recorded_at"),
        sa.PrimaryKeyConstraint("tenant_id", "run_id", name=op.f("pk_feedback_issues")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_feedback_issues_tenant_id_tenants")),
        schema=SCHEMA)
    op.create_index("feedback_issues_one_run_per_issue", "feedback_issues", ["tenant_id", "issue_number"], unique=True,
                    schema=SCHEMA, postgresql_where=sa.text("issue_number IS NOT NULL"))
    op.create_table(
        "feedback_comments",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("comment_id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("author", sa.Text(), nullable=False),
        sa.Column("created", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("issue_url", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("decision", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("settled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "comment_id", name=op.f("pk_feedback_comments")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_feedback_comments_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["tenant_id", "run_id"], [f"{SCHEMA}.feedback_issues.tenant_id",
                                                          f"{SCHEMA}.feedback_issues.run_id"],
                                name=op.f("fk_feedback_comments_tenant_id_run_id_feedback_issues")),
        schema=SCHEMA)
    op.create_table(
        "feedback_tick",
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        _time("comments_since"),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        _time("lease_expiry"),
        sa.Column("fencing_token", sa.Integer(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_feedback_tick")),
        sa.ForeignKeyConstraint(["tenant_id"], tenant, name=op.f("fk_feedback_tick_tenant_id_tenants")),
        schema=SCHEMA)
