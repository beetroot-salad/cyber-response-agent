"""The e2e spine replay over the learning store: graded rows reach the curator, the corpus gains one lesson, a merge settles them.

#1135 pinned the spine over the file queues and the handle. #1278 moved the queue into the store (design r8 Flows), so the same
four hops are observed there: the judge's graded rows are queued, the batch's curator is handed exactly them, the tenant repo
gains one `lessons/` branch with one commit naming them (the product checkout untouched), and after the PR's merge a second
tick publishes them and authors nothing again.

Retired from this file:
- `test_1135_the_drains_append_lock_wait_ends_at_the_configured_deadline`: the findings append lock, its wait deadline and the
  skipped tick are gone (design r8 Locks: "three append locks: transactions and the unique key"; the read window with them).
  Two ticks over one lane now meet the working-batch rule, observed by `test_1278_tick.py::test_locks_a_tick_finding_a_live_batch_of_another_holder_authors_nothing_and_exits_quietly`.
"""
from __future__ import annotations

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.judge._memory_store import MemoryStore
from defender.tests.support.learning.core._store1278 import (  # noqa: F401 — fixtures
    LessonWriter, call, lesson_citing, migrated_database, world)
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSONS_PREFIX, BoxSpy, author_drain, remote_branches, touched)
from defender.tests.tenancy.tenant_1108_p4._support import git
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on

pytestmark = [pytest.mark.postgres, pytest.mark.e2e]


class _Recording(LessonWriter):
    """`LessonWriter` that also records the items each claim hands its curator, by module."""

    def __init__(self, lessons: dict[str, str]) -> None:
        super().__init__(lessons)
        self.items: list[tuple[str, list[str]]] = []

    def __call__(self, paths, state, kind, threshold_env, module_name, pending_label, *, batch, items=None, **kw) -> None:
        self.items.append((module_name, [key for _kind, key, _payload in items or ()]))
        if module_name == "author":
            super().__call__(batch=batch)


def test_1135_the_e2e_spine_replay_reaches_the_corpus_unchanged(world, monkeypatch):  # noqa: F811 — the imported fixture
    w = world
    tmp_path = w.scratch
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    sink = MemoryStore()
    J.grade_at(ep, judge=J.FakeJudge(  # the family-scope call files family findings only
        default=J.as_reply_text(J.reply_doc()), family_default=J.as_reply_text(J.family_reply())), draws=1, store=sink)
    record = J.judge_record(ep)

    # hop 1: the judge's record says how many rows it enqueued, and the sink carries them; they are queued in the store
    rows = [i.payload for t in sink.items.values() for i in t if i.kind == "finding"]
    queued = [r["finding_id"] for r in rows]
    assert record.get("enqueued_rows") == len(queued) == 2, f"the graded episode did not enqueue its rows: {queued}"
    assert {r["direction"] for r in rows} == {"family"}, "the spine's producer is the family judge"
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", rows, kind="finding")
    assert sorted(i.key for i in call(w.dsn, "work", w.t.tenant_id) if i.kind == "finding") == sorted(queued)

    # hop 2: the batch's curator is handed exactly those rows
    main = w.t.origin_main()
    product_head = D.git(w.paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    writer = _Recording({"family-lesson.md": lesson_citing(*queued)})
    assert author_drain(w.t, w.paths, trigger=writer, box=BoxSpy()) == 0, "author_drain did not complete its batch"
    handed = [keys for module, keys in writer.items if module == "author"]
    assert len(handed) == 1, f"the curator was handed {handed}, not the graded rows {queued}"
    assert sorted(handed[0]) == sorted(queued), f"the curator was handed {handed}, not the graded rows {queued}"

    # hop 3: the tenant repo gains one lessons/ branch whose one commit adds one document naming both ids; the product
    # checkout is untouched; the rows stay in their batch until the PR is merged
    (branch, tip), = remote_branches(w.t.remote, LESSONS_PREFIX).items()
    landed = touched(w.t.remote, main, tip)
    assert landed == ["agent/lessons/family-lesson.md"], f"the batch landed {landed}, not one lesson"
    body = git(w.t.remote, "show", f"{tip}:{landed[0]}")
    assert all(fid in body for fid in queued), f"the committed lesson does not attribute {queued}"
    assert D.git(w.paths.repo_root, "rev-parse", "HEAD").stdout.strip() == product_head, "the drain committed to the product checkout"
    assert {i.status for i in call(w.dsn, "work", w.t.tenant_id)} == {"in_batch"}, "the committed rows left their batch before the merge"

    # hop 4: once merged, a second tick reads the corpus back, publishes the rows and authors nothing again
    merge_on_remote(w.t.p3, w.scratch, branch)
    branches = remote_branches(w.t.remote, LESSONS_PREFIX)
    second = _Recording({"must-not-run-twice.md": "x"})
    assert author_drain(w.t, w.paths, trigger=second, box=BoxSpy()) == 0, "the second tick failed"
    assert [keys for module, keys in second.items if module == "author"] == [], "the second tick authored the same findings again"
    assert {i.key: i.status for i in call(w.dsn, "work", w.t.tenant_id)} == {fid: "published" for fid in queued}
    assert remote_branches(w.t.remote, LESSONS_PREFIX) == branches, "the second tick opened a second batch"
