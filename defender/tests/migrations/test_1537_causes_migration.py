"""#1537 (design r3): the one migration after `0020_signin_attempts` adds the cause, parked and request columns and backfills
every row already stored. The revision is found as the one built directly on `0020_signin_attempts`; rows are planted by SQL at
the revision before it (the head store cannot write them), with the texts today's code writes, frozen here."""
from __future__ import annotations

import datetime as _dt
import uuid

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

TENANT = "b1537000-0000-4000-8000-000000000001"
CREATED = _dt.datetime(2026, 11, 1, 8, 0, tzinfo=_dt.UTC)
CREDENTIAL = "forge_credential_refused"
PARK = "the forge refused 3 times: "
STATUS_403 = "Forgejo GET failed: Client error '403 Forbidden' for url 'https://forge.invalid/api/v1/repos/o/r/pulls/7'"
STATUS_401 = "Forgejo GET failed: Client error '401 Unauthorized' for url 'https://forge.invalid/api/v1/repos/o/r/pulls/7'"
#: A 422 whose URL (not its status line) holds "403".
STATUS_422 = "Forgejo GET failed: Client error '422 Unprocessable Entity' for url 'https://forge.invalid/api/v1/repos/403/r/pulls/7'"
DELIVERY = f"the tenant {TENANT}'s delivery refused: the issuer AppRole login failed"

#: (reason as stored today, parked-batch cause it backfills to)
PARKED = {
    "403 in the status line": (PARK + STATUS_403, CREDENTIAL),
    "401 in the status line": (PARK + STATUS_401, CREDENTIAL),
    "422 with 403 in its url": (PARK + STATUS_422, "forge_refused"),
    "statusless credential failure at delivery open": (PARK + DELIVERY, CREDENTIAL),
    "foreign tip on the forge": ("the branch lessons/ab12 on the forge holds commits the commit-maker did not make for batch "
                                 "b1 (tip abc123)", "foreign_commits_remote"),
    "foreign local commits": ("the local branch lessons/ab12 holds commits outside batch b1's record", "foreign_commits_local"),
    "foreign pr": ("an open PR on lessons/ that no batch made holds the lane: #5 (lessons/other)", "foreign_pr"),
    "model text": ("the batch looked odd to the curator", "unrecorded"),
    "no reason": (None, "unrecorded"),
}
ENDED_ABANDONED = {
    "no commits": ("no commits", "no_commits"), "stopped": ("stopped", "stopped"),
    "crashed": ("its holder crashed", "holder_crashed"), "lost": ("its holder was lost", "holder_lost"),
    "person": ("abandoned by a person", "abandoned_by_person"), "text": ("something a person typed", "unrecorded"),
    "none": (None, "unrecorded"),
}
#: (status, reason as stored today, cause) of items
ITEMS = {
    "held attempts": ("held", "reached the attempt ceiling (5)", "attempt_ceiling"),
    "held person": ("held", "abandoned by a person", "abandoned_by_person"),
    "held replacement nothing": ("held", "the replacement committed nothing", "replacement_committed_nothing"),
    "held replacement ceiling": ("held", "feedback reached the replacement ceiling (3 replacement PRs)", "replacement_ceiling"),
    "held closed": ("held", "PR #3 of batch b1 was closed with no feedback: held for a person", "closed_without_feedback"),
    "held cut": ("held", "cited at the branch tip, not in PR #3's merge", "cut_from_merge"),
    "dead declined": ("dead", "declined by the curator 5 times", "declined_ceiling"),
    "dead deferred": ("dead", "deferred 5 times", "deferral_ceiling"),
    "skipped superseded": ("skipped", "superseded by a later run", "superseded"),
    "skipped superseded by run": ("skipped", "superseded by run r-2", "superseded"),
    "held model text": ("held", "this finding is not about the alert", "unrecorded"),
    "held no reason": ("held", None, "unrecorded"),
    "waiting stale reason": ("waiting", "reached the attempt ceiling (5)", None),
    "published stale reason": ("published", "held for a person", None),
}


def _after_signin() -> str:
    """The one revision built directly on `0020_signin_attempts`."""
    base = revisions.by_suffix("_signin_attempts")
    [child] = [r.revision for r in revisions.scripts().walk_revisions() if r.down_revision == base]
    return child


def _tenant(dsn: str) -> None:
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor, failure) "
                 "VALUES (%s, %s, 'active', NULL, NULL, NULL, NULL)", (TENANT, CREATED))


def _batch(dsn: str, *, kind: str, lane: str, phase: str, outcome: str | None = None, reason: str | None = None,
           pr: int | None = None) -> str:
    batch = str(uuid.uuid4())
    execute(dsn, """INSERT INTO learning.batches (id, tenant_id, kind, lane, branch, phase, outcome, fencing_token,
        cancel_requested, pr_number, generation, refusals, reason, created_at, ended_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 2, false, %s, 0, 3, %s, %s, %s)""",
            (batch, TENANT, kind, lane, f"lessons/{batch[:8]}", phase, outcome, pr, reason, CREATED,
             CREATED if phase == "ended" else None))
    return batch


def _item(dsn: str, key: str, status: str, reason: str | None) -> None:
    execute(dsn, """INSERT INTO learning.work_items (tenant_id, kind, id, item_key, payload, status, reason, attempts,
        deferrals, offers_declined, enqueued_at, updated_at) VALUES (%s, 'finding', %s, %s, '{}', %s, %s, 1, 0, 0, %s, %s)""",
            (TENANT, str(uuid.uuid4()), key, status, reason, CREATED, CREATED))


@pytest.fixture
def planted(empty_database):
    """The database at the revision before the migration, holding a row for each text above."""
    dsn = empty_database
    _upgrade_to(dsn, revisions.down_of(_after_signin()))
    _tenant(dsn)
    rows: dict[str, tuple[str, str | None]] = {}
    for name, (reason, want) in PARKED.items():
        rows[f"parked: {name}"] = (_batch(dsn, kind="revert", lane="author", phase="needs_person", reason=reason), want)
    for name, (reason, want) in ENDED_ABANDONED.items():
        rows[f"abandoned: {name}"] = (_batch(dsn, kind="revert", lane="author", phase="ended", outcome="abandoned", reason=reason), want)
    rows["merged with a reason"] = (_batch(dsn, kind="revert", lane="author", phase="ended", outcome="merged",
                                           reason="cited at the branch tip, not in PR #3's merge", pr=3), None)
    rows["closed with a reason"] = (_batch(dsn, kind="revert", lane="author", phase="ended", outcome="closed",
                                           reason="revert PR #4 closed unmerged", pr=4), None)
    rows["in review"] = (_batch(dsn, kind="revert", lane="author", phase="in_review", pr=5), None)
    for name, (status, reason, _cause) in ITEMS.items():
        _item(dsn, name, status, reason)
    return dsn, rows


def test_the_migration_is_the_one_revision_after_0020_and_the_head_is_not_behind_it():
    """Exactly one revision sits on `0020_signin_attempts`, and it is an ancestor of the head. (Data)"""
    child = _after_signin()
    heads = revisions.scripts().get_heads()
    assert len(heads) == 1
    assert child in revisions.ancestors(heads[0])


def test_the_backfill_gives_every_batch_the_cause_its_frozen_text_names_and_unmatched_text_is_unrecorded(planted):
    """Each stored batch reason maps to its cause (a 403 or 401 inside the park's status line, or a statusless credential failure at delivery open, `forge_credential_refused`; a 403 elsewhere in the text is not), unmatched or missing text `unrecorded`; merged, closed and in-review batches get none. (Data backfill, PR1)"""
    dsn, rows = planted
    _upgrade_to(dsn, _after_signin())
    got = {name: execute(dsn, "SELECT cause FROM learning.batches WHERE id = %s", (batch,))[0][0] for name, (batch, _w) in rows.items()}
    assert got == {name: want for name, (_b, want) in rows.items()}


def test_the_backfill_gives_every_held_dead_and_skipped_item_its_cause_and_the_rest_none(planted):
    """Each stored item reason maps to its cause; unmatched or missing reasons are `unrecorded`; a waiting or published item has none. (Data backfill, PR1)"""
    dsn, _rows = planted
    _upgrade_to(dsn, _after_signin())
    got = dict(execute(dsn, "SELECT item_key, cause FROM learning.work_items WHERE tenant_id = %s", (TENANT,)))
    assert got == {name: cause for name, (_s, _r, cause) in ITEMS.items()}


def test_the_backfill_leaves_parked_at_and_the_request_empty_and_keeps_every_reason_as_the_detail(planted):
    """Already-parked batches get `parked_at` NULL (the screen falls back to `created_at`); no batch has a request; reasons are untouched. (Data backfill, O5)"""
    dsn, _rows = planted
    before = execute(dsn, "SELECT id, reason FROM learning.batches ORDER BY id")
    items_before = execute(dsn, "SELECT item_key, status FROM learning.work_items ORDER BY item_key")
    _upgrade_to(dsn, _after_signin())
    assert execute(dsn, "SELECT count(*) FROM learning.batches WHERE parked_at IS NOT NULL OR abandon_requested_at IS NOT NULL "
                        "OR abandon_requested_by IS NOT NULL") == [(0,)]
    assert execute(dsn, "SELECT id, reason FROM learning.batches ORDER BY id") == before
    assert execute(dsn, "SELECT item_key, status FROM learning.work_items ORDER BY item_key") == items_before


def test_the_upgraded_database_carries_the_new_columns_as_nullable_text_and_timestamps(migrated_database):
    """`cause` on both tables, `parked_at`, `abandon_requested_at` (timestamptz) and `abandon_requested_by` (text) exist and are nullable. (Data)"""
    got = {(t, c): (ty, n) for t, c, ty, n in execute(migrated_database, """SELECT table_name, column_name, data_type, is_nullable
        FROM information_schema.columns WHERE table_schema = 'learning' AND (table_name, column_name) IN
        (('work_items', 'cause'), ('batches', 'cause'), ('batches', 'parked_at'), ('batches', 'abandon_requested_at'),
         ('batches', 'abandon_requested_by'))""")}
    assert got == {("work_items", "cause"): ("text", "YES"), ("batches", "cause"): ("text", "YES"),
                   ("batches", "parked_at"): ("timestamp with time zone", "YES"),
                   ("batches", "abandon_requested_at"): ("timestamp with time zone", "YES"),
                   ("batches", "abandon_requested_by"): ("text", "YES")}
