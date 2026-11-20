"""Each alert's outcome, stored on the alert (#1581): `jobs.alerts` gains `outcome` (the disposition of the alert's newest
`completed` investigation by `(created_at, id)`) and that investigation's id and `created_at` as its source, all three
null or all set, with an index over `(tenant_id, outcome, fired_at DESC, id DESC)` so the alert list's outcome filter is
an index range. `jobs.investigations` gains two checks: a `completed` row has a disposition, and a disposition is one of
the five codes. The investigations still own the facts; the job store keeps the copy (`defender/jobs/store.py`, finish and
the investigation delete). No trigger.

The codes are frozen here as they stand at this revision, so a later change to the vocabulary cannot change what this
upgrade does.

The upgrade refuses, changing nothing, while any row exists the new checks cannot hold: a `completed` row with no
disposition, or a row of any stage whose disposition is not one of the five codes (`unsanctioned-benign` was a code for
three hours on 2026-11-17). No production investigation has run, so no data move is written for them.

Stop the API and the workers first (`defender/CLAUDE.md`, "Upgrade from before #1581"): a worker of the old code would
complete investigations without keeping the copy.

Revision ID: 0024_alert_outcome
Revises: 0023_findings_at_job_end

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0024_alert_outcome"
down_revision = "0023_findings_at_job_end"

SCHEMA = "jobs"

DISPOSITIONS = ("benign", "false-positive", "inconclusive", "malicious", "unresolved")
_CODES = ", ".join(repr(v) for v in DISPOSITIONS)


def upgrade() -> None:
    bind = op.get_bind()
    missing: int = bind.execute(sa.text(
        f"SELECT count(*) FROM {SCHEMA}.investigations WHERE stage = 'completed' AND disposition IS NULL")).scalar_one()
    unknown: int = bind.execute(sa.text(
        f"SELECT count(*) FROM {SCHEMA}.investigations WHERE disposition NOT IN ({_CODES})")).scalar_one()  # noqa: S608
    if missing or unknown:
        raise RuntimeError(
            f"{missing} completed investigation(s) in jobs.investigations with no disposition and {unknown} investigation(s) "
            f"whose disposition is not one of the five codes ({_CODES}): a completed investigation now always has a "
            "disposition, one of the five, and no data move is written for either (#1581); remove or correct them by hand "
            "before upgrading")

    op.create_check_constraint(op.f("ck_investigations_completed_has_a_disposition"), "investigations",
                               "stage <> 'completed' OR disposition IS NOT NULL", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_investigations_disposition"), "investigations",
                               f"disposition IN ({_CODES})", schema=SCHEMA)

    op.add_column("alerts", sa.Column("outcome", sa.Text(), nullable=True), schema=SCHEMA)
    op.add_column("alerts", sa.Column("outcome_investigation_id", sa.Uuid(as_uuid=False), nullable=True), schema=SCHEMA)
    op.add_column("alerts", sa.Column("outcome_created_at", sa.DateTime(timezone=True), nullable=True), schema=SCHEMA)
    op.execute(f"""
        UPDATE {SCHEMA}.alerts AS a
        SET outcome = n.disposition, outcome_investigation_id = n.id, outcome_created_at = n.created_at
        FROM (SELECT DISTINCT ON (alert_id) alert_id, id, disposition, created_at
              FROM {SCHEMA}.investigations WHERE stage = 'completed'
              ORDER BY alert_id, created_at DESC, id DESC) AS n
        WHERE a.id = n.alert_id""")  # noqa: S608
    op.create_check_constraint(
        op.f("ck_alerts_outcome_copy_whole"), "alerts",
        "(outcome IS NULL) = (outcome_investigation_id IS NULL) AND (outcome IS NULL) = (outcome_created_at IS NULL)",
        schema=SCHEMA)
    op.create_check_constraint(op.f("ck_alerts_outcome"), "alerts", f"outcome IN ({_CODES})", schema=SCHEMA)

    op.create_index("alerts_outcome_newest_first", "alerts",
                    ["tenant_id", "outcome", sa.text("fired_at DESC"), sa.text("id DESC")], schema=SCHEMA)
    op.execute(f"ANALYZE {SCHEMA}.alerts")
