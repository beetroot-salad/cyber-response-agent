"""Run evidence leaves the host (#1546): the claims every launched child runs under, the facts its helper stages and the
uploads it makes, and each owner row's evidence state.

- `jobs.claims`: one row per launched child (investigation, learning job, post-step, readiness, adoption, drain), its
  token minted by the store in the claim's own transaction. It names its lease reference, exactly the one its kind takes
  (a check): the owner row, the host-request row, or the tenant's learning-check hold for a post-step. `inputs` (the
  `(owner, object)` pairs it may pull) is never null. Only the claim -> reference foreign keys exist: a row is claimed at
  most once, so an owner -> claim column would be redundant.
- `jobs.staged_facts` (`(token, name)`) and `jobs.uploads` (`(token, object)`), each keyed under its claim.
- `evidence_state` on investigations and learning jobs, `scrub` on investigations: null exactly while the row is queued
  or running, one of the vocabulary's once it ended (A-O4, A-O10). Rows already ended are backfilled `none`/`not_run`.
- `learning_jobs.sibling_cost_is_lower_limit` (D15): false for every existing row (their costs read exact).
- host requests may be of kind `drain` (D7), at most one queued or running per tenant.

No foreign key carries an ON DELETE action: deleting an investigation removes its claims, facts and uploads itself.

Revision ID: 0027_run_evidence
Revises: 0026_host_requests

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0027_run_evidence"
down_revision = "0026_host_requests"

SCHEMA = "jobs"

# Frozen here as they stand at this revision.
_LIVE = "'queued', 'running'"
_EVIDENCE = "'complete', 'partial', 'none', 'lost', 'expired'"
_SCRUB = "'clean', 'tainted', 'not_run'"
_UPLOAD = "'pending', 'uploaded', 'refused'"
_COMPUTED = "status = 'refused' OR (size IS NOT NULL AND sha256 IS NOT NULL AND wrapped_key IS NOT NULL)"
_CLAIM_KINDS = "'investigation', 'learning', 'readiness', 'adoption', 'drain', 'post-step'"
_HOST_KINDS = "'readiness', 'adoption', 'drain'"
_REFERENCES = ("investigation_id", "learning_job_id", "host_request_id", "hold_tenant_id")


def _only(column: str) -> str:
    return " AND ".join(f"{c} IS {'NOT ' if c == column else ''}NULL" for c in _REFERENCES)


#: Each kind names exactly its own reference.
_KIND_REFERENCE = (f"(kind IN ('investigation') AND {_only('investigation_id')}) "
                   f"OR (kind IN ('learning') AND {_only('learning_job_id')}) "
                   f"OR (kind IN ('readiness', 'adoption', 'drain') AND {_only('host_request_id')}) "
                   f"OR (kind IN ('post-step') AND {_only('hold_tenant_id')})")


def _time(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    _owner_columns()
    _claims()
    op.drop_constraint(op.f("ck_host_requests_kind"), "host_requests", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_host_requests_kind"), "host_requests", f"kind IN ({_HOST_KINDS})", schema=SCHEMA)
    op.create_index("host_requests_one_live_drain_per_tenant", "host_requests", ["tenant_id"], unique=True,
                    schema=SCHEMA, postgresql_where=sa.text(f"kind = 'drain' AND stage IN ({_LIVE})"))


def _owner_columns() -> None:
    op.add_column("investigations", sa.Column("evidence_state", sa.Text(), nullable=True), schema=SCHEMA)
    op.add_column("investigations", sa.Column("scrub", sa.Text(), nullable=True), schema=SCHEMA)
    op.execute(f"UPDATE {SCHEMA}.investigations SET evidence_state = 'none', scrub = 'not_run' "
               f"WHERE stage NOT IN ({_LIVE})")
    op.create_check_constraint(op.f("ck_investigations_evidence_state"), "investigations",
                               f"evidence_state IN ({_EVIDENCE})", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_investigations_scrub"), "investigations", f"scrub IN ({_SCRUB})", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_investigations_ended_has_evidence"), "investigations",
                               f"(stage IN ({_LIVE})) = (evidence_state IS NULL) "
                               f"AND (stage IN ({_LIVE})) = (scrub IS NULL)", schema=SCHEMA)

    op.add_column("learning_jobs", sa.Column("evidence_state", sa.Text(), nullable=True), schema=SCHEMA)
    op.add_column("learning_jobs", sa.Column("sibling_cost_is_lower_limit", sa.Boolean(), nullable=False,
                                             server_default=sa.false()), schema=SCHEMA)
    # The default only fills the rows that exist: no column of the jobs schema keeps a server default (#1339 P4).
    op.alter_column("learning_jobs", "sibling_cost_is_lower_limit", server_default=None, schema=SCHEMA)
    op.execute(f"UPDATE {SCHEMA}.learning_jobs SET evidence_state = 'none' WHERE status NOT IN ({_LIVE})")
    op.create_check_constraint(op.f("ck_learning_jobs_evidence_state"), "learning_jobs",
                               f"evidence_state IN ({_EVIDENCE})", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_learning_jobs_ended_has_evidence"), "learning_jobs",
                               f"(status IN ({_LIVE})) = (evidence_state IS NULL)", schema=SCHEMA)


def _claims() -> None:
    op.create_table(
        "claims",
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("learning_job_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("host_request_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("hold_tenant_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("launch", postgresql.JSONB(), nullable=True),
        sa.Column("inputs", postgresql.JSONB(), nullable=False),
        _time("created_at"),
        sa.PrimaryKeyConstraint("token", name=op.f("pk_claims")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenancy.tenants.id"], name=op.f("fk_claims_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["investigation_id"], [f"{SCHEMA}.investigations.id"],
                                name=op.f("fk_claims_investigation_id_investigations")),
        sa.ForeignKeyConstraint(["learning_job_id"], [f"{SCHEMA}.learning_jobs.id"],
                                name=op.f("fk_claims_learning_job_id_learning_jobs")),
        sa.ForeignKeyConstraint(["host_request_id"], [f"{SCHEMA}.host_requests.id"],
                                name=op.f("fk_claims_host_request_id_host_requests")),
        sa.ForeignKeyConstraint(["hold_tenant_id"], [f"{SCHEMA}.learning_checks.tenant_id"],
                                name=op.f("fk_claims_hold_tenant_id_learning_checks")),
        sa.CheckConstraint(f"kind IN ({_CLAIM_KINDS})", name=op.f("ck_claims_kind")),
        sa.CheckConstraint(_KIND_REFERENCE, name=op.f("ck_claims_kind_names_its_reference")),
        schema=SCHEMA)
    # A row is claimed at most once; a post-step hold is one row reused by many claims, told apart by `holder`.
    for column in ("investigation_id", "learning_job_id", "host_request_id"):
        op.create_index(f"claims_one_per_{column}", "claims", [column], unique=True, schema=SCHEMA,
                        postgresql_where=sa.text(f"{column} IS NOT NULL"))
    op.create_index("claims_by_tenant", "claims", ["tenant_id"], schema=SCHEMA)

    op.create_table(
        "staged_facts",
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("body", postgresql.JSONB(), nullable=False),
        _time("staged_at", nullable=False),
        sa.PrimaryKeyConstraint("token", "name", name=op.f("pk_staged_facts")),
        sa.ForeignKeyConstraint(["token"], [f"{SCHEMA}.claims.token"], name=op.f("fk_staged_facts_token_claims")),
        schema=SCHEMA)

    op.create_table(
        "uploads",
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("object", sa.Text(), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.Text(), nullable=True),
        sa.Column("wrapped_key", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("scrub", sa.Text(), nullable=True),
        _time("accepted_at"),
        _time("created_at", nullable=False),
        sa.PrimaryKeyConstraint("token", "object", name=op.f("pk_uploads")),
        sa.ForeignKeyConstraint(["token"], [f"{SCHEMA}.claims.token"], name=op.f("fk_uploads_token_claims")),
        sa.CheckConstraint(f"status IN ({_UPLOAD})", name=op.f("ck_uploads_status")),
        sa.CheckConstraint(f"scrub IN ({_SCRUB})", name=op.f("ck_uploads_scrub")),
        sa.CheckConstraint("size >= 0", name=op.f("ck_uploads_size")),
        # A refused row may be made before anything was computed (no data key); every other row carries all three.
        sa.CheckConstraint(_COMPUTED, name=op.f("ck_uploads_computed_unless_refused")),
        sa.CheckConstraint("accepted_at IS NULL OR status = 'uploaded'", name=op.f("ck_uploads_only_uploaded_is_accepted")),
        schema=SCHEMA)
    op.create_index("uploads_unaccepted_by_age", "uploads", ["created_at"], schema=SCHEMA,
                    postgresql_where=sa.text("accepted_at IS NULL"))
    op.create_index("uploads_accepted_by_age", "uploads", ["accepted_at"], schema=SCHEMA,
                    postgresql_where=sa.text("accepted_at IS NOT NULL"))
