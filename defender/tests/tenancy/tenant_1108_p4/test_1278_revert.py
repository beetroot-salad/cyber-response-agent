"""#1278 Reverts: a revert is a batch of kind revert in the learning store, its commits in the tenant's record.

Driven through the revert CLI's own `main` over `p4_tenant`, the lesson written by a real author tick
(the commit-maker's record in the database) and merged on the forge by a person. The CLI's
exit codes and PR output are in `test_revert_cli.py`; the store-level rules in `test_store_1278.py`.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from defender.tests.support.learning.core._store1278 import (
    LessonWriter,
    authored_and_merged,
    batches,
    call,
    finding,
    lapse_lease,
    lesson_citing,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._support import close_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    BoxSpy,
    author_drain,
    critical_text,
    remote_branches,
)

pytestmark = pytest.mark.postgres

LESSON = LESSON_NAME.removesuffix(".md")
LESSON_PATH = f"agent/lessons/{LESSON_NAME}"


def _revert(t, name: str) -> int:
    cli = importlib.import_module("defender.cli.learning.revert_lesson")
    return cli.main(["--tenant", t.tenant_id, name], client=t.forge.client,
                    identity=t.vault.identity(), directory=t.directory)


def test_reverts_a_revert_opens_beside_an_open_author_batch_and_its_commit_is_in_the_record(world, caplog):  # noqa: F811 — the imported fixture
    """The author batch still in review does not block the revert; the revert's commit is a record row of its own batch naming what it undoes, and no file record is written. (Reverts, D5, O10)"""
    t = world.t
    authored, _branch = authored_and_merged(world)
    [author_row] = call(world.dsn, "commit_record", t.tenant_id)
    assert [b.phase for b in batches(world.dsn, t.tenant_id)] == ["in_review"], "premise: an author PR is open"

    rc = _revert(t, LESSON)

    assert rc == 0, critical_text(caplog)
    [revert] = [b for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"]
    rows = call(world.dsn, "commit_record", t.tenant_id)
    assert [str(r.batch_id) for r in rows] == [str(authored), str(revert.id)]
    undo = rows[1]
    assert (undo.branch, undo.base) == (revert.branch, revert.base)
    assert undo.start
    assert LESSON_PATH in str(undo.reverts)
    assert str(authored) in str(undo.reverts)
    assert not author_row.reverts
    assert [c[0] for c in undo.changes] == [LESSON_PATH]
    assert not (Path(location_path(t.tenant.learning)) / "commit-maker.jsonl").exists()


def test_reverts_a_revert_that_is_running_makes_a_second_revert_wait(world):  # noqa: F811 — the imported fixture
    """A revert batch working under a live lease holds the lane: another revert exits 3, claiming nothing and asking nothing of the forge. (Reverts, O3)"""
    t = world.t
    authored_and_merged(world)
    running = call(world.dsn, "claim_revert", t.tenant_id, owner="first-cli")
    t.forge.requests.clear()

    assert _revert(t, LESSON) == 3

    assert t.forge.requests == []
    assert [b.id for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"] == [running.batch_id]


def test_reverts_the_clis_open_revert_pr_stops_the_next_tick_authoring(world, caplog):  # noqa: F811 — the imported fixture
    """After a real revert opened its PR, a tick with a waiting finding authors nothing and claims nothing. (Reverts, O3)"""
    t = world.t
    authored_and_merged(world)
    assert _revert(t, LESSON) == 0
    call(world.dsn, "publish_findings", t.tenant_id, "run-2", [finding("f2")], kind="finding")
    before = remote_branches(t.remote, prefix="")
    writer = LessonWriter({LESSON_NAME: lesson_citing("f2")})

    author_drain(t, world.paths, trigger=writer, box=BoxSpy())

    assert writer.served == [], critical_text(caplog)
    assert remote_branches(t.remote, prefix="") == before
    assert {i.key: i.status for i in call(world.dsn, "work", t.tenant_id)}["f2"] == "waiting"


def test_reverts_a_revert_that_crashed_after_its_push_is_taken_over_and_gets_one_pr(world, caplog):  # noqa: F811 — the imported fixture
    """The CLI's PR open fails after the push and its lease lapses: the next tick takes the revert batch over and opens its one PR. (G-C6, Crash recovery)"""
    t = world.t
    authored_and_merged(world)
    t.forge.fail_create = True
    assert _revert(t, LESSON) != 0
    t.forge.fail_create = False
    [revert] = [b for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"]
    assert revert.phase == "working", "premise: the revert is stranded after its push"
    assert revert.branch in remote_branches(t.remote, prefix="")

    lapse_lease(world.dsn, revert.id)
    for _ in range(2):
        author_drain(t, world.paths, trigger=LessonWriter({}), box=BoxSpy())

    [after] = [b for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"]
    opened = [r for r in t.forge.prs if r["state"] == "open" and r["head"]["ref"] == revert.branch]
    assert (after.phase, len(opened)) == ("in_review", 1), critical_text(caplog)
    assert after.pr_number == opened[0]["number"]


def test_reverts_a_revert_pr_closed_unmerged_ends_its_batch_and_refuses_the_next_revert_of_that_lesson(world, caplog):  # noqa: F811 — the imported fixture
    """A closed revert PR is a rejection kept in the store: its batch ends, a second CLI revert of the same lesson exits 2 and makes no branch or PR, and no batch is left not ended. (Reverts, D7)"""
    t = world.t
    authored_and_merged(world)
    assert _revert(t, LESSON) == 0
    [revert] = [b for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"]
    close_on_remote(t.p3, revert.branch)
    author_drain(t, world.paths, trigger=LessonWriter({}), box=BoxSpy())  # the tick reconciles the closed PR
    assert {b.id: b.phase for b in batches(world.dsn, t.tenant_id)}[revert.id] == "ended", critical_text(caplog)
    branches, creates = remote_branches(t.remote, prefix=""), list(t.forge.creates)

    assert _revert(t, LESSON) == 2

    assert list(t.forge.creates) == creates, "a closed revert was made again"
    assert remote_branches(t.remote, prefix="") == branches
    assert [b.kind for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"] == ["revert"], "a second revert batch was minted"
    assert {b.phase for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"} == {"ended"}
