"""#1278 Migration and cutover: the one-time import of a tenant's file learning state into the store.

Every case plants today's file layout (`_legacy1278`, bytes as base writes them) and open PRs on the
p4 tenant's origin and forge fake, then imports. The import's seam beyond `interface.md` (requests in
the report): `import_learning_state(store, tid, state_root, *, delivery)`, `delivery` the tenant's
`TenantDelivery` (forge listing and branch reads), and `cut_over_learning_state(tenant, state_root)`.
"""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core import _legacy1278 as legacy
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    files_under,
    finding,
    learning_store,
    lesson_citing,
    store_mod,
)
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

LESSONS = "agent/lessons"
QUESTIONER = "agent/lessons-questioner"


@pytest.fixture
def world(tmp_path, data_root, migrated_database):
    """The p4 tenant (real clone, origin and forge fake) registered active in a migrated database, with
    an existing, empty `<T>/learning`."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        register_tenant(migrated_database, t.tenant_id)
        root = Path(location_path(t.tenant.tenant_root)) / "learning"
        root.mkdir(parents=True, exist_ok=True)
        yield SimpleNamespace(t=t, tid=t.tenant_id, dsn=migrated_database, root=root)


async def refused_import(w, *named):
    """The import is refused (`ImportRefused`, interface request) naming each of `named`, and the store holds nothing of the
    tenant afterwards: one transaction (G-I10)."""
    files = files_under(w.root)
    async with learning_store(w.dsn) as store:
        with pytest.raises(store_mod().ImportRefused) as refusal:
            await store_mod().import_learning_state(store, w.tid, w.root, delivery=w.t.open_delivery())
        for name in named:
            assert name in str(refusal.value), f"the refusal does not name {name}: {refusal.value}"
        assert (await store.work(w.tid), await store.batches(w.tid), await store.commit_record(w.tid)) == ([], [], [])
    assert files_under(w.root) == files, "a refused import changed the tenant's learning files"


async def imported(w):
    """Run the import; the store's views afterwards: items by (kind, key), batches, commit record."""
    async with learning_store(w.dsn) as store:
        await store_mod().import_learning_state(store, w.tid, w.root, delivery=w.t.open_delivery())
        items = {(i.kind, i.key): i for i in await store.work(w.tid)}
        return SimpleNamespace(items=items, batches=list(await store.batches(w.tid)),
                               commits=list(await store.commit_record(w.tid)))


def statuses(done, kind):
    return {key: item.status for (k, key), item in done.items.items() if k == kind}


# --- items: ledger, queue, dead-letter ---------------------------------------------------------------------------


async def test_migration_a_finding_in_both_queue_and_ledger_imports_as_the_ledger_says(world):
    """Queue and consumed ledger both hold f1: the ledger wins (published); f2, queued only, waits. (Migration)"""
    legacy.queue(world.root, "finding", [finding("f1"), finding("f2")])
    legacy.consumed(world.root, "finding", [finding("f1")], "consumed_committed")

    done = await imported(world)

    assert statuses(done, "finding") == {"f1": "published", "f2": "waiting"}


async def test_migration_ledger_rows_import_as_published_or_skipped_by_their_recorded_category(world):
    """Committed and idempotent -> published, skip -> skipped with its reason, on the channels that write them. (Migration, A2 D1)"""
    legacy.consumed(world.root, "finding", [finding("c1")], "consumed_committed")
    legacy.consumed(world.root, "finding", [finding("i1")], "consumed_idempotent")
    legacy.consumed(world.root, "finding", [finding("s1")], "consumed_skip", skip_reason="not generalisable")
    legacy.consumed(world.root, "questioner_finding", [legacy.world_finding("qi1")], "consumed_idempotent")
    legacy.consumed(world.root, "pitfall", [legacy.pitfall("pc1")], "consumed_committed")

    done = await imported(world)

    assert statuses(done, "finding") == {"c1": "published", "i1": "published", "s1": "skipped"}
    assert statuses(done, "questioner_finding") == {"qi1": "published"}
    assert statuses(done, "pitfall") == {"pc1": "published"}
    assert "not generalisable" in (done.items[("finding", "s1")].reason or "")


async def test_migration_a_questioner_row_drained_for_naming_no_systems_is_skipped_with_that_reason(world):
    """`consumed_no_systems` is a skip variant: skipped, its reason kept; a queued row beside it waits. (Migration, A2 D1, G-I1)"""
    legacy.queue(world.root, "questioner_finding", [legacy.world_finding("w2")])
    legacy.consumed(world.root, "questioner_finding", [legacy.world_finding("w1")], "consumed_no_systems")

    done = await imported(world)

    assert statuses(done, "questioner_finding") == {"w1": "skipped", "w2": "waiting"}
    assert "system" in (done.items[("questioner_finding", "w1")].reason or "").lower()


async def test_migration_an_unknown_ledger_category_refuses_the_import_naming_it_and_writes_nothing(world):
    """A category the import does not know is refused, not tolerated; nothing is imported and no file changes. (G-I1, G-I10)"""
    legacy.queue(world.root, "finding", [finding("f1")])
    legacy.consumed(world.root, "finding", [finding("c1")], "consumed_committed")
    legacy.consumed(world.root, "finding", [finding("x1")], "consumed_from_the_future")
    before = files_under(world.root)

    await refused_import(world, "consumed_from_the_future")

    assert files_under(world.root) == before, "a refused import leaves the files as they were"


async def test_migration_a_ledger_only_retirement_imports_dead_by_its_category_alone(world):
    """`consumed_retired` and `consumed_unattributable` with no dead-letter twin are dead; no twin is needed. (G-I2)"""
    legacy.consumed(world.root, "finding", [finding("r1")], "consumed_retired")
    legacy.consumed(world.root, "pitfall", [legacy.pitfall("r2")], "consumed_unattributable")

    done = await imported(world)

    assert (statuses(done, "finding"), statuses(done, "pitfall")) == ({"r1": "dead"}, {"r2": "dead"})
    assert (bool(done.items[("finding", "r1")].reason), bool(done.items[("pitfall", "r2")].reason)) == (True, True)


async def test_migration_a_queued_row_with_a_dead_letter_record_and_no_ledger_row_imports_dead(world):
    """The dead-letter record outranks the queue row: dead with its reason, not waiting. (G-I3, Migration)"""
    row = finding("d1")
    legacy.queue(world.root, "finding", [row, finding("f2")])
    legacy.deadletter(world.root, "finding", [row], "ceiling reached for d1")

    done = await imported(world)

    assert statuses(done, "finding") == {"d1": "dead", "f2": "waiting"}
    assert "ceiling reached for d1" in (done.items[("finding", "d1")].reason or "")


async def test_migration_the_same_keyless_row_in_ledger_and_dead_letter_is_one_dead_item(world):
    """A keyless row's digest covers the row as queued: the ledger copy (fields added) and the nested dead-letter copy agree. (G-I4)"""
    keyless = {k: v for k, v in finding("x").items() if k != "finding_id"}
    other = dict(keyless, finding="another narrative")
    legacy.consumed(world.root, "finding", [keyless], "consumed_retired")
    legacy.deadletter(world.root, "finding", [keyless], "ceiling reached")
    legacy.deadletter(world.root, "finding", [other], "ceiling reached")

    done = await imported(world)

    assert [i.status for i in done.items.values()] == ["dead", "dead"], "one item per original row, not per file"


async def test_migration_the_counters_in_the_file_rows_carry_over(world):
    """A queued row's attempts and deferrals, and a pitfall's offers_declined, come in as the item's counters. (G-I5, schema)"""
    legacy.queue(world.root, "finding", [{**finding("f1"), "attempts": 2, "deferrals": 1}, finding("f2")])
    legacy.queue(world.root, "pitfall", [{**legacy.pitfall("p1"), "offers_declined": 2}])

    done = await imported(world)

    f1, f2 = done.items[("finding", "f1")], done.items[("finding", "f2")]
    assert (f1.attempts, f1.deferrals, f2.attempts, f2.deferrals) == (2, 1, 0, 0)
    assert done.items[("pitfall", "p1")].offers_declined == 2  # interface request: the item view's `.offers_declined`


async def test_migration_a_row_in_both_ledger_and_dead_letter_imports_as_dead(world):
    """Every retirement writes ledger and dead-letter: the dead-letter wins, with its reason, on all three channels. (Migration)"""
    rows = {"finding": finding("r1"), "questioner_finding": legacy.world_finding("r2"), "pitfall": legacy.pitfall("r3")}
    for kind, row in rows.items():
        legacy.consumed(world.root, kind, [row], "consumed_retired")
        legacy.deadletter(world.root, kind, [row], f"ceiling reached for {row[legacy.CHANNELS[kind]['key']]}")
    # the pitfalls curator's unattributable drop writes both too (`_graveyard_dropped_rows`), with no attempts count
    legacy.consumed(world.root, "pitfall", [legacy.pitfall("r4")], "consumed_unattributable")
    legacy.deadletter(world.root, "pitfall", [legacy.pitfall("r4")], "undeclared system", attempts=0)

    done = await imported(world)

    assert {k: i.status for k, i in done.items.items()} == {
        ("finding", "r1"): "dead", ("questioner_finding", "r2"): "dead", ("pitfall", "r3"): "dead",
        ("pitfall", "r4"): "dead"}
    assert "ceiling reached for r1" in (done.items[("finding", "r1")].reason or "")
    assert "undeclared system" in (done.items[("pitfall", "r4")].reason or "")


async def test_migration_queue_rows_import_as_waiting_whatever_the_file_holds_beside_them(world):
    """Queued rows wait, a held row too, a repeated pitfall id once, one id on two channels twice; stuck files add nothing. (Migration)"""
    legacy.queue(world.root, "finding", [finding("f1"), {**finding("f2"), "held_reason": "retired_direction('lead')"}])
    legacy.queue(world.root, "questioner_finding", [legacy.world_finding("f1")])
    legacy.queue(world.root, "pitfall", [legacy.pitfall("p1"), legacy.pitfall("p1"), legacy.pitfall("p2")])
    legacy.stuck(world.root, "finding", ["f1", "ghost"])
    legacy.stuck(world.root, "pitfall", ["p9"])

    done = await imported(world)

    assert statuses(done, "finding") == {"f1": "waiting", "f2": "waiting"}
    assert statuses(done, "questioner_finding") == {"f1": "waiting"}
    assert statuses(done, "pitfall") == {"p1": "waiting", "p2": "waiting"}
    assert done.batches == []


async def test_migration_a_row_with_no_key_imports_dead_keyed_by_its_digest(world):
    """A keyless queue row is dead with a reason; equal rows share a key, different rows do not. (Migration)"""
    keyless = {k: v for k, v in finding("x").items() if k != "finding_id"}
    other = dict(keyless, finding="another narrative")
    legacy.queue(world.root, "finding", [keyless, dict(keyless), other, finding("f1")])

    done = await imported(world)

    dead = {key: i for (kind, key), i in done.items.items() if kind == "finding" and i.status == "dead"}
    assert len(dead) == 2
    assert all(isinstance(key, str) and key and key != "f1" for key in dead)
    assert all(i.reason for i in dead.values())
    assert done.items[("finding", "f1")].status == "waiting"


# --- requests --------------------------------------------------------------------------------------------------


async def test_migration_requests_in_flight_wait_and_a_fresher_one_for_the_case_supersedes_them(world):
    """In-flight c1 waits alone; for c2 the fresher queued request waits and the in-flight one is skipped, superseded. (Migration, coalesce)"""
    legacy.request(world.root, "c1", "run-1", world.tid, where="inflight")
    legacy.request(world.root, "c2", "run-old", world.tid, where="inflight")
    legacy.request(world.root, "c2", "run-new", world.tid)
    legacy.request(world.root, "c3", "run-3", world.tid)

    done = await imported(world)

    assert statuses(done, "curation_request") == {
        "run-1": "waiting", "run-old": "skipped", "run-new": "waiting", "run-3": "waiting"}
    assert "superseded" in (done.items[("curation_request", "run-old")].reason or "")


async def test_migration_a_failed_request_imports_dead_with_its_reason(world):
    """A quarantined request (`author-queue/failed/`) is dead; its reason is kept. (Migration)"""
    legacy.request(world.root, "c9", "run-9", world.tid, where="failed", failed="unreadable: not a mapping")

    done = await imported(world)

    assert statuses(done, "curation_request") == {"run-9": "dead"}
    assert "not a mapping" in (done.items[("curation_request", "run-9")].reason or "")


# --- open PRs -----------------------------------------------------------------------------------------------------


async def test_migration_an_open_author_pr_imports_as_an_in_review_batch_whose_members_the_branch_cites(world):
    """f1 and q1, cited by the branch's own commits, are in_batch of the PR's batch; f2 and f9 (cited on main) wait. (Migration)"""
    t, branch = world.t, "lessons/0a1b2c3d4e5f"
    legacy.queue(world.root, "finding", [finding("f1"), finding("f2"), finding("f9")])
    legacy.queue(world.root, "questioner_finding", [legacy.world_finding("q1")])
    main = legacy.land_on_main(t, {f"{LESSONS}/old.md": lesson_citing("f9")})
    tip = legacy.open_pr(t, 7, branch, {f"{LESSONS}/new.md": lesson_citing("f1"),
                                        f"{QUESTIONER}/q.md": lesson_citing("q1")})
    legacy.closed_pr(t, 8, "lessons/closed00000000", merged=True)
    legacy.commit_record(world.root, [legacy.commit_row(tip, branch, main, "s" * 16)])

    done = await imported(world)

    [batch] = done.batches
    assert (batch.kind, batch.lane, batch.phase, batch.outcome) == ("author", AUTHOR_LANE, "in_review", None)
    assert (batch.branch, batch.pr_number) == (branch, 7)
    members = {key: item for (_kind, key), item in done.items.items() if item.batch_id == batch.id}
    assert set(members) == {"f1", "q1"}
    assert {i.status for i in members.values()} == {"in_batch"}
    assert statuses(done, "finding")["f2"] == "waiting"
    assert statuses(done, "finding")["f9"] == "waiting"


async def test_migration_open_revert_prs_import_as_item_less_revert_batches_beside_an_author_batch(world):
    """Two `revert-` PRs and an author PR coexist: two revert batches in_review with no members, one author batch. (Migration)"""
    t = world.t
    legacy.queue(world.root, "finding", [finding("f1")])
    legacy.open_pr(t, 7, "lessons/aaaaaaaaaaaa", {f"{LESSONS}/new.md": lesson_citing("f1")})
    legacy.open_pr(t, 11, "lessons/revert-alpha-1a2b3c4d", {f"{LESSONS}/alpha.md": "reverted\n"})
    legacy.open_pr(t, 12, "lessons/revert-beta-5e6f7a8b", {f"{LESSONS}/beta.md": "reverted\n"})

    done = await imported(world)

    assert sorted((b.kind, b.pr_number, b.phase) for b in done.batches) == [
        ("author", 7, "in_review"), ("revert", 11, "in_review"), ("revert", 12, "in_review")]
    assert {b.lane for b in done.batches} == {AUTHOR_LANE}
    [author] = [b for b in done.batches if b.kind == "author"]
    assert {item.batch_id for item in done.items.values()} == {author.id}


async def test_migration_an_open_lead_lane_pr_imports_as_a_member_less_batch_that_starts_no_replacement(world):
    """The lead PR's items were consumed before landing; its batch has none, and ending it closed adds no batch. (Migration)"""
    t, branch = world.t, "lead-author/bbbbbbbbbbbb"
    legacy.consumed(world.root, "pitfall", [legacy.pitfall("p1")], "consumed_committed")
    legacy.open_pr(t, 9, branch, {"agent/pitfalls/notes.md": "taught\n"})

    done = await imported(world)

    [batch] = done.batches
    assert (batch.kind, batch.phase, batch.pr_number, batch.branch) == ("author", "in_review", 9, branch)
    assert batch.lane == LEAD_LANE
    assert [i for i in done.items.values() if i.batch_id == batch.id] == []
    assert statuses(done, "pitfall") == {"p1": "published"}
    async with learning_store(world.dsn) as store:
        await store.end_review(world.tid, batch.id, expect_phase="in_review", outcome="closed", published=[], held=[])
        after = list(await store.batches(world.tid))
        assert [(b.id, b.phase, b.outcome) for b in after] == [(batch.id, "ended", "closed")]
        assert {(i.kind, i.key, i.status) for i in await store.work(world.tid)} == {("pitfall", "p1", "published")}
    assert "no replacement" in (after[0].reason or "").lower(), "a lead PR's feedback is visibly not acted on"  # interface request: batch view `.reason`


async def test_migration_two_open_author_prs_on_one_lane_refuse_the_import_naming_both(world):
    """The store allows one not-ended author batch per lane; two open lesson PRs are refused, nothing imported. (G-I7, G-I10)"""
    t = world.t
    legacy.queue(world.root, "finding", [finding("f1"), finding("f2")])
    legacy.open_pr(t, 7, "lessons/aaaaaaaaaaaa", {f"{LESSONS}/one.md": lesson_citing("f1")})
    legacy.open_pr(t, 8, "lessons/bbbbbbbbbbbb", {f"{LESSONS}/two.md": lesson_citing("f2")})

    await refused_import(world, "7", "8")


# --- deliveries ---------------------------------------------------------------------------------------------------


async def test_migration_a_retained_delivery_imports_as_a_needs_person_batch_and_a_failed_one_is_logged_and_dropped(world, caplog):
    """A record still present at quiesce, per lane, becomes a needs_person batch on its branch; a failed record yields none. (Migration)"""
    t = world.t
    author_branch, lead_branch = "lessons/cccccccccccc", "lead-author/dddddddddddd"
    legacy.local_branch(t, author_branch, {f"{LESSONS}/kept.md": lesson_citing("f1")})
    legacy.local_branch(t, lead_branch, {"agent/pitfalls/kept.md": "taught\n"})
    legacy.pending_delivery(world.root, "cccccccccccc", author_branch)
    legacy.pending_delivery(world.root, "dddddddddddd", lead_branch, label="lead_author_drain")
    failed = legacy.pending_delivery(world.root, "eeeeeeeeeeee", "lessons/eeeeeeeeeeee",
                                     failed="unreadable pending-delivery record")

    with caplog.at_level(logging.INFO):
        done = await imported(world)

    by_branch = {b.branch: b for b in done.batches}
    assert set(by_branch) == {author_branch, lead_branch}
    assert {(b.phase, b.pr_number) for b in done.batches} == {("needs_person", None)}
    assert by_branch[author_branch].lane == AUTHOR_LANE
    assert by_branch[lead_branch].lane == LEAD_LANE
    assert failed in caplog.text, "a failed delivery record is logged before it is dropped"


async def test_migration_a_retained_delivery_batch_holds_the_items_its_branch_cites(world):
    """The retained delivery's batch is needs_person with the items its branch's commits cite in_batch, as an open PR's; the rest wait. (G-I8)"""
    t, branch = world.t, "lessons/cccccccccccc"
    legacy.queue(world.root, "finding", [finding("f1"), finding("f2")])
    legacy.local_branch(t, branch, {f"{LESSONS}/kept.md": lesson_citing("f1")})
    legacy.pending_delivery(world.root, "cccccccccccc", branch)

    done = await imported(world)

    [batch] = done.batches
    assert (batch.phase, batch.branch) == ("needs_person", branch)
    assert {key: (i.status, i.batch_id) for (_k, key), i in done.items.items()} == {
        "f1": ("in_batch", batch.id), "f2": ("waiting", None)}


# --- the commit record --------------------------------------------------------------------------------------------


async def test_migration_the_whole_commit_record_imports_with_its_own_branch_base_and_start_and_no_batch(world):
    """Every row of all lanes, a revert's target included, comes back as written; the batch link is null for imported history. (Migration, A2 D5)"""
    from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL

    lead_lanes = LEAD_AUTHOR_DRAIN_LABEL.lanes  # the real lead lane's lanes, not a literal
    a, b, c = "a" * 40, "b" * 40, "c" * 40
    own = {"branch": "lessons/ffffffffffff", "base": "1" * 40, "start": "0011223344556677"}
    rows = [
        legacy.commit_row(a, own["branch"], own["base"], own["start"], changes=[(f"{LESSONS}/x.md", None, "2" * 40)]),
        legacy.commit_row(b, "lessons/revert-x-00ff00ff", "3" * 40, "8899aabbccddeeff",
                          lanes=("lessons", "lessons-questioner"), changes=[(f"{LESSONS}/x.md", "2" * 40, None)],
                          reverts=(own, f"{LESSONS}/x.md")),
        legacy.commit_row(c, "lead-author/gggggggggggg", "4" * 40, "1122334455667788", lanes=lead_lanes,
                          changes=[("agent/pitfalls/n.md", "5" * 40, "6" * 40)]),
    ]
    legacy.commit_record(world.root, rows)

    done = await imported(world)

    by_commit = {r.commit: r for r in done.commits}
    assert set(by_commit) == {a, b, c}
    for row, planted in zip((by_commit[a], by_commit[b], by_commit[c]), rows, strict=True):
        assert (row.branch, row.base, row.start) == tuple(planted["batch"][k] for k in ("branch", "base", "start"))
        assert row.batch_id is None
        assert list(row.lanes) == planted["lanes"]
        assert [tuple(ch) for ch in row.changes] == [(ch["path"], ch["before"], ch["after"]) for ch in planted["changes"]]
    assert by_commit[a].reverts is None
    assert by_commit[c].reverts is None
    assert by_commit[b].reverts is not None


# --- after the import ---------------------------------------------------------------------------------------------


async def test_migration_a_finding_the_ledger_made_published_is_not_published_again_by_a_republish(world):
    """The imported ledger replaces the consumed-ledger dedup: republishing f1 leaves it published, f2 is new. (Migration, r8 work_items)"""
    legacy.consumed(world.root, "finding", [finding("f1")], "consumed_committed")

    await imported(world)
    async with learning_store(world.dsn) as store:
        await store.publish_findings(world.tid, "run-again", [finding("f1"), finding("f2")], kind="finding")
        items = {i.key: i.status for i in await store.work(world.tid) if i.kind == "finding"}

    assert items == {"f1": "published", "f2": "waiting"}


# --- cutover ------------------------------------------------------------------------------------------------------


def test_cutover_removes_the_whole_learning_folder_discards_traces_and_moves_worktrees(world):
    """No file stays under `<T>/learning`; traces exist nowhere; the worktree moves out of it, the rest of the tenant stays. (A1 cutover, A2 D10)"""
    trace, worktree = b"a pre-cutover curator trace\n", b"a batch worktree draft\n"
    legacy.queue(world.root, "finding", [finding("f1")])
    legacy.commit_record(world.root, [legacy.commit_row("a" * 40, "lessons/hhhhhhhhhhhh", "1" * 40, "0011223344556677")])
    legacy.leftovers(world.root, trace=trace, worktree=worktree)
    tenant_root = Path(location_path(world.t.tenant.tenant_root))
    elsewhere = {p: b for p, b in files_under(tenant_root).items()
                 if not p.startswith("learning/") and ".git/" not in p}

    store_mod().cut_over_learning_state(world.t.tenant, world.root)

    assert files_under(world.root) == {}
    after = {p: b for p, b in files_under(tenant_root).items() if ".git/" not in p}
    assert {p: after[p] for p in elsewhere} == elsewhere, "the rest of the tenant's folder is untouched"
    moved = {p: b for p, b in after.items() if p not in elsewhere}
    assert list(moved.values()) == [worktree], "only the worktree's file survives, and outside learning/"
    assert not any(p.startswith("learning/") for p in moved)
    assert trace not in files_under(Path(world.t.data_root)).values(), "pre-cutover traces are discarded"
