"""A cause for every set-aside item and parked or abandoned batch, and the columns a person's release and abandon need (#1537).

`work_items.cause` and `batches.cause` come from a closed list per table (picked by code; `reason` stays as the detail text).
A row has a cause exactly when its state calls for one (an item held, dead or skipped; a batch parked or ended abandoned).
`batches.parked_at` says when a batch entered `needs_person`; `abandon_requested_at` and `abandon_requested_by` record a
person's request to abandon a parked batch, which the loop carries out.

The backfill reads the texts today's code writes, frozen here so a later change to a text cannot change what an old row
means. Any text it does not know (anything a model wrote) is `unrecorded`. Batches already parked keep `parked_at` NULL.

Revision ID: 0021_learning_causes
Revises: 0020_signin_attempts
"""
import sqlalchemy as sa
from alembic import op

revision = "0021_learning_causes"
down_revision = "0020_signin_attempts"

SCHEMA = "learning"

ITEM_CAUSES = (
    "attempt_ceiling", "replacement_ceiling", "replacement_committed_nothing", "closed_without_feedback", "cut_from_merge",
    "curator_held", "malformed_row", "abandoned_by_person", "declined_ceiling", "deferral_ceiling", "artifact_missing",
    "superseded", "declined_at_gate", "consumed_no_systems", "unteachable_system", "curator_skipped", "unrecorded")
BATCH_CAUSES = (
    "forge_credential_refused", "forge_refused", "delivery_unavailable", "foreign_commits_remote", "foreign_commits_local",
    "foreign_pr", "holder_lost", "holder_crashed", "stopped", "no_commits", "abandoned_by_person", "unrecorded")


def _in_list(column: str, allowed: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in allowed)})"


#: A parked batch's reason, by the text each park path wrote (`needs_person`, and `note_refusal`'s "the forge refused N times: ...").
_PARKED_CAUSE = r"""
    CASE
      WHEN reason ~ '^the forge refused [0-9]+ times: ' THEN
        CASE
          WHEN reason ~ '(secret file .* (could not be read|does not hold one secret id)|has no usable forge wiring)'
            OR reason ~ 'records no .* login \(no role id\)|records no absolute .* secret file'
            THEN 'delivery_unavailable'
          WHEN reason ~ '(Client|Server) error ''(401|403) '
            OR reason ~ 'Vault identity token request failed|Vault returned no identity token'
            OR reason ~ 'Vault returned an invalid identity token|invalid identity claims|identity claims must be an object'
            OR reason ~ 'invalid lifetime claims|Vault identity does not match|Vault identity is expired'
            OR reason ~ 'Vault identity role must be|Vault identity needs a tenant|Vault issuer must be an HTTPS'
            OR reason ~ 'short-lived token budget|has no live credential generation|records no audience'
            OR reason ~ 'issuer URL must be an HTTPS|issuer CA certificate .* is unusable'
            OR (reason ~ 'the issuer AppRole login failed' AND reason !~ '\(HTTP [0-9]+\)')
            OR reason ~ 'the issuer AppRole login failed.*\(HTTP (401|403)\)'
            THEN 'forge_credential_refused'
          ELSE 'forge_refused'
        END
      WHEN reason ~ '^the branch .* on the forge holds commits the commit-maker did not make' THEN 'foreign_commits_remote'
      WHEN reason ~ '^the local branch .* holds commits outside batch ' THEN 'foreign_commits_local'
      WHEN reason ~ '^an open PR on .* that no batch made holds the lane' THEN 'foreign_pr'
      ELSE 'unrecorded'
    END"""

_ABANDONED_CAUSE = """
    CASE reason
      WHEN 'no commits' THEN 'no_commits'
      WHEN 'stopped' THEN 'stopped'
      WHEN 'its holder crashed' THEN 'holder_crashed'
      WHEN 'its holder was lost' THEN 'holder_lost'
      WHEN 'abandoned by a person' THEN 'abandoned_by_person'
      ELSE 'unrecorded'
    END"""

_ITEM_CAUSE = r"""
    CASE
      WHEN reason ~ '^reached the attempt ceiling \(' THEN 'attempt_ceiling'
      WHEN reason = 'abandoned by a person' THEN 'abandoned_by_person'
      WHEN reason = 'the replacement committed nothing' THEN 'replacement_committed_nothing'
      WHEN reason ~ '^feedback reached the replacement ceiling' THEN 'replacement_ceiling'
      WHEN reason ~ '^PR #[0-9]+ of batch .* was closed with no feedback' THEN 'closed_without_feedback'
      WHEN reason ~ '^cited at the branch tip, not in PR #' THEN 'cut_from_merge'
      WHEN reason ~ '^declined by the curator [0-9]+ times$' THEN 'declined_ceiling'
      WHEN reason ~ '^deferred [0-9]+ times$' THEN 'deferral_ceiling'
      WHEN reason = 'superseded by a later run' OR reason ~ '^superseded by run ' THEN 'superseded'
      WHEN reason = 'artifact-missing' THEN 'artifact_missing'
      WHEN reason ~ '^row carries no value under ' THEN 'malformed_row'
      WHEN reason ~ '^consumed_no_systems' THEN 'consumed_no_systems'
      WHEN reason = 'declined at the gate' THEN 'declined_at_gate'
      WHEN reason IN ('no-system', 'malformed-system') OR reason ~ '^undeclared-system:' THEN 'unteachable_system'
      ELSE 'unrecorded'
    END"""


def upgrade() -> None:
    op.add_column("work_items", sa.Column("cause", sa.Text(), nullable=True), schema=SCHEMA)
    op.add_column("batches", sa.Column("cause", sa.Text(), nullable=True), schema=SCHEMA)
    op.add_column("batches", sa.Column("parked_at", sa.DateTime(timezone=True), nullable=True), schema=SCHEMA)
    op.add_column("batches", sa.Column("abandon_requested_at", sa.DateTime(timezone=True), nullable=True), schema=SCHEMA)
    op.add_column("batches", sa.Column("abandon_requested_by", sa.Text(), nullable=True), schema=SCHEMA)

    op.execute(f"UPDATE {SCHEMA}.batches SET cause = {_PARKED_CAUSE} WHERE phase = 'needs_person'")
    op.execute(f"UPDATE {SCHEMA}.batches SET cause = {_ABANDONED_CAUSE} WHERE phase = 'ended' AND outcome = 'abandoned'")
    op.execute(f"UPDATE {SCHEMA}.work_items SET cause = {_ITEM_CAUSE} WHERE status IN ('held', 'dead', 'skipped')")

    op.create_check_constraint(
        op.f("ck_work_items_cause_follows_status"), "work_items",
        "(status IN ('held', 'dead', 'skipped')) = (cause IS NOT NULL)", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_work_items_cause"), "work_items", "cause IS NULL OR " + _in_list("cause", ITEM_CAUSES),
                               schema=SCHEMA)
    op.create_check_constraint(
        op.f("ck_batches_cause_follows_state"), "batches",
        "(phase = 'needs_person' OR outcome IS NOT DISTINCT FROM 'abandoned') = (cause IS NOT NULL)", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_batches_cause"), "batches", "cause IS NULL OR " + _in_list("cause", BATCH_CAUSES),
                               schema=SCHEMA)
    op.create_check_constraint(op.f("ck_batches_parked_at_only_when_parked"), "batches",
                               "parked_at IS NULL OR phase = 'needs_person'", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_batches_request_is_whole"), "batches",
                               "(abandon_requested_at IS NULL) = (abandon_requested_by IS NULL)", schema=SCHEMA)
    op.create_check_constraint(op.f("ck_batches_request_only_when_parked"), "batches",
                               "abandon_requested_at IS NULL OR phase IN ('needs_person', 'ended')", schema=SCHEMA)
