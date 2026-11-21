"""Reverts over the learning store (#1278): the scenes the revert tests set up and read.

A lesson the commit-maker wrote is a batch in the store (claimed, its commits recorded through the batch's
recorder before its branch moves, its PR opened) that a person merged on the forge. `revert_lesson` reads
that record from the store; a revert's own life (working, in review, merged, closed) is the store's batch row
that the tick would stamp, so the scenes stamp it with the same verbs (`end_review`).
"""
from __future__ import annotations

import contextlib

import pytest

from defender.tests.support.learning.core._store1278 import ONE, finding
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture the store needs

from ._support import LANES, ForgeHTTP, delivery, merge_on_remote

OWNER = "revert-test"


@contextlib.contextmanager
def _opened_store(tenant, dsn):
    from defender.learning_store._blocking import blocking
    from defender.tests.support.jobs._jobs1342 import register_tenant

    register_tenant(dsn, str(tenant.id))
    with blocking(dsn) as opened:
        yield opened


@pytest.fixture
def store(repo, migrated_database):  # noqa: F811 — the imported fixture
    """The learning store (sync facade) on a migrated database where `repo`'s tenant is active."""
    with _opened_store(repo[0], migrated_database) as opened:
        yield opened


@pytest.fixture
def http_store(http_repo, migrated_database):  # noqa: F811 — the imported fixture
    """`store` for a test over the smart-HTTP remote (`http_repo`)."""
    with _opened_store(http_repo[0], migrated_database) as opened:
        yield opened


def _recorder(store, held):
    def record(made):
        store.record_commit(held, made.commit, made.batch.base, made.batch.start, list(made.changes))
    return record


def claimed_batch(repo, store, d, name):
    """An author batch as the tick starts one: a finding published, the batch claimed in the store, and the delivery's
    batch started on the claim's branch with each commit recorded before its branch moves. `(batch, held)`."""
    tenant = str(repo[0].id)
    store.publish_findings(tenant, f"run-{name}", [finding(name)], kind="finding")
    held = store.claim(tenant, "author", owner=OWNER, thresholds=ONE)
    assert held is not None, "premise: the finding is due"
    return d.start_batch(str(held.batch_id), lanes=LANES, branch=held.branch, recorder=_recorder(store, held)), held


def reviewed(store, held, result):
    """The batch's PR is open: the store has it in review, as the tick leaves it."""
    store.in_review(held, int(result.url.rstrip("/").rsplit("/", 1)[-1]), {})


def wrote(repo, tmp_path, store, name, commits, *, style="merge", merge=True):
    """A lesson the commit-maker wrote, as the author tick writes one: a claimed author batch whose `commits`
    (a list of `{path: bytes or None}`, `None` deleting the file) are made by the batch's commit-maker, each
    recorded, then delivered as a PR and (`merge`) merged by a person in `style`, the batch then ended merged.
    Unmerged, the batch stays in review. Returns the batch id."""
    d = delivery(repo, ForgeHTTP())
    batch, held = claimed_batch(repo, store, d, name)
    for files in commits:
        for path, content in files.items():
            file = batch.draft_root / path
            if content is None:
                file.unlink()
            else:
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(content)
        batch.commit(batch.change_set(), f"learning {name}")
        batch.reset()
    result = d.finish(batch)
    assert result.status == "opened", result
    reviewed(store, held, result)
    if merge:
        merge_on_remote(repo, tmp_path, batch.branch, style)
        store.end_review(str(repo[0].id), str(held.batch_id), expect_phase="in_review", outcome="merged",
                         published=[], held=[])
    return str(held.batch_id)
