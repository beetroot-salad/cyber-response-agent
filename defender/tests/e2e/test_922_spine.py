"""#922 — the surviving training spine, and a drain that no longer derives its curators or
mounts from the retired direction table."""
from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from defender.learning.author.lessons import run as lessons_run
from defender.learning.core import drains
from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.e2e import _box665 as B
from defender.tests.support.learning.core import _store1278 as ST
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    AUTHOR_DRAFT_LANES,
    LESSONS_PREFIX,
    draft_lane_trees,
    drain_paths,
    product_repo,
    remote_branches,
    touched,
    under,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, git, published_tenant

pytestmark = [pytest.mark.e2e, pytest.mark.postgres]


RETIRED_CORPORA = ("lessons-actor", "lessons-environment")
# retired: the retired observation queue files (`actor_observations.jsonl`, ...) and `stuff_retired_queues`: the queues
# are rows of the learning store now (design O10 retires the state tree), so a retired channel has no file to stuff and
# the drain can only be woken by a kind the store holds; `test_o10_*` in the census pins that no product code reads them.


@pytest.fixture(autouse=True)
def _isolated_roots(tmp_path, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """Every shared root this spine touches, pointed inside `tmp_path`; the learning store is the test database."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(ST.DSN_ENV, migrated_database)
    for name, value in ((ST.LEASE_ENV, "600"), (ST.GRACE_ENV, "300"), (ST.RENEW_ENV, "600")):
        monkeypatch.setenv(name, value)
    # Stated rather than inherited: the drive below queues two family rows, and the shipped
    # default of 5 would make every assertion below vacuous on a drain that never woke.
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")


class TriggerRecorder:
    """The `trigger_author=` seam: records the inbound payload of every curator trigger, and
    runs the REAL findings curator for the findings one."""

    def __init__(self, agent) -> None:
        self.calls: list[dict] = []
        #: The modules whose REAL `run_batch` returned. The drain records a curator's fault and
        #: goes on (rc 0), so a curator knocked out of the tick looks like one that held every
        #: row; a demand about what the curator did checks this first.
        self.completed: list[str] = []
        self._agent = agent

    def __call__(self, paths, state, kind, threshold_env, module_name, pending_label,  # noqa: PLR0913 — the curator seam's own signature
                 *, batch, box=None, items=(), outcomes=None, feedback=None, make_model=None) -> None:
        # The curator runs over the tick's batch draft lanes (`batch=`, as
        # `_drain_support.CuratorTrigger` does), never over checkout trees built from `paths`.
        assert batch is not None, "the drain handed the findings trigger no batch"
        self.calls.append({
            "kind": kind, "items": [key for _kind, key, _payload in items], "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
            "batch": batch,
        })
        if module_name != "author":
            return
        with draft_lane_trees(batch, AUTHOR_DRAFT_LANES) as trees:
            cfg = dataclasses.replace(
                lessons_run.build_author_config(
                    paths, trees=trees, box=box, batch=batch, feedback=feedback, make_model=make_model),
                invoke_agent=self._agent,
            )
            assert Path(cfg.corpus_dir).is_relative_to(Path(batch.draft_root)), (
                f"the curator's corpus {cfg.corpus_dir} is not in the batch's draft")
            lessons_run.run_batch(paths=paths, cfg=cfg, items=items, outcomes=outcomes, box=box)
        self.completed.append(module_name)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def _finding_items(t, *statuses: str) -> list:
    """The finding rows the tenant's store holds (in the given statuses; all without), in key order."""
    return sorted((i for i in ST.call(os.environ[ST.DSN_ENV], "work", t.tenant_id)
                   if i.kind == "finding" and (not statuses or i.status in statuses)), key=lambda i: i.key)


def graded_episode(tmp_path: Path, t):
    """One accepted episode graded by the REAL family judge, its rows in the REAL learning store."""
    from defender.learning.store import blocking

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / J.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    with blocking(os.environ[ST.DSN_ENV]) as store:
        J.grade_at(
            ep, judge=J.FakeJudge(
                default=J.as_reply_text(J.reply_doc()),
                family_default=J.as_reply_text(J.family_reply())),
            draws=1, store=store)
    return ep, J.judge_record(ep)


@pytest.fixture
def tenant(tmp_path, data_root, migrated_database):  # noqa: F811 — the imported fixture
    """The fixture tenant published for real, its forge bound and its row registered in the store: the drain's
    batches are branches of the tenant repo."""
    from defender.tests.support.jobs._jobs1342 import register_tenant

    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        register_tenant(migrated_database, t.tenant_id)
        yield t


def tenant_paths(t, tmp_path):
    """The tenant's learning paths over a scratch product checkout."""
    return drain_paths(t, product_repo(tmp_path))


def drive_tenant_author_drain(t, paths, trigger, *, rec=None):
    """The real `author_drain` over the tenant path, with the forge fake's client, an identity
    over its issuer fake, and the box seams."""
    rec = rec or B.BoxLifecycleRecorder()
    rc = drains.author_drain(
        paths, trigger_author=trigger, client=t.forge.client, identity=t.vault.identity(), directory=t.directory,
        start_box=rec.start_box, stop_box=rec.stop_box)
    return rc, rec


def draft_root(request) -> Path:
    """The batch draft's root: the box's one `staged` mount."""
    (staged,) = [Path(m.source) for m in request.mounts if m.kind == "staged"]
    return staged


def writable_sources(request) -> set[Path]:
    return {Path(m.source) for m in request.mounts if m.writable}


def test_922_graded_episode_reaches_the_corpus_through_the_family_partition(tenant, tmp_path):
    """GUARD: the family rows reach the findings curator, which commits one attributing lesson on
    a `lessons/` branch; the rows stay in the batch until a later tick reads the merge back and
    publishes them, authoring nothing new."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    _ep, record = graded_episode(tmp_path, t)

    assert all(row["measured"] for row in record["worlds"]), "a graded world was not measured"
    queued = [i.key for i in _finding_items(t)]
    assert record["enqueued_rows"] == len(queued) == 2, (
        f"the graded episode did not put its rows in the store: {queued}")
    assert {i.payload["direction"] for i in _finding_items(t)} == {"family"}, (
        "a non-family row: the drive is not exercising the family partition")

    main = t.origin_main()
    agent = D.recording(D.committing("family-lesson"))
    first = TriggerRecorder(agent)
    rc, _rec = drive_tenant_author_drain(t, paths, first)

    assert rc == 0, "author_drain did not complete its batch"
    assert first.completed == ["author"], "the findings curator was taken out of the tick"
    assert len(agent.calls) == 1, (
        f"the findings curator ran {len(agent.calls)} times, not once")
    authored = sorted(r["finding_id"] for r in agent.calls[0]["rows"])
    assert authored == sorted(queued), (
        f"the curator was handed {authored}, not the graded episode's rows {queued} — the "
        "family partition did not admit them for authoring")

    (branch, tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    landed = touched(t.remote, main, tip)
    assert len(landed) == 1, f"the batch landed {landed}, not one lesson"
    assert landed[0].startswith("agent/lessons/family-lesson-"), landed
    body = git(t.remote, "show", f"{tip}:{landed[0]}")
    for fid in queued:
        assert fid in body, f"the committed lesson does not attribute {fid}"
    assert {i.key: i.status for i in _finding_items(t)} == {k: "in_batch" for k in queued}, (
        "the committed rows are not held in the batch whose PR is open — they would be authored again or lost "
        "before the PR merged")

    merge_on_remote(t.p3, t.scratch, branch)
    branches = remote_branches(t.remote, LESSONS_PREFIX)
    second = D.recording(D.committing("must-not-run-twice"))
    again = TriggerRecorder(second)
    assert drive_tenant_author_drain(t, paths, again)[0] == 0
    assert second.calls == [], (
        "the second tick authored the same findings again — the merged batch's rows were not retired")
    assert {i.key: i.status for i in _finding_items(t)} == {k: "published" for k in queued}, (
        "the rows did not become published once their PR merged")
    assert remote_branches(t.remote, LESSONS_PREFIX) == branches, (
        "the second tick opened a second batch for findings already in the corpus")


def test_922_a_caught_family_is_not_authored(tenant, tmp_path):
    """GUARD: a retired-word family row is held, never authored: no curator call that writes, no batch
    branch or PR on the tenant forge, nothing published."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    row = dict(D.finding_row("ep-caught/b/0/0", run_id="ep-caught", direction="family"),
               type="decision-discipline", judge_outcome="caught", subject_anchor="l-001",
               subject_topic="holding-system coverage",
               source_run_dir="episodes/ep-caught/worlds/b")
    ST.call(os.environ[ST.DSN_ENV], "publish_findings", t.tenant_id, "ep-caught", [row], kind="finding")

    agent = D.recording(D.committing("must-not-run"))
    trigger = TriggerRecorder(agent)
    rc, _rec = drive_tenant_author_drain(t, paths, trigger)

    assert rc == 0
    assert trigger.completed == ["author"], (
        "the findings curator was taken out of the tick, so 'never authored' proves nothing")
    assert agent.calls == [], (
        "a retired-word family row reached the curator — the partition authored a row the "
        "retired design would have read")
    assert remote_branches(t.remote, LESSONS_PREFIX) == {}, (
        "a retired-word family row produced a batch on the tenant repo")
    assert t.forge.creates == []
    [item] = _finding_items(t)
    assert item.key == "ep-caught/b/0/0"
    assert item.status not in ("published", "in_batch"), (
        f"the retired-word row was consumed or batched, not held: {item.status}")


def test_922_the_drain_box_gets_exactly_the_lessons_corpus_writable(tenant, tmp_path):
    """The drain box's writable mounts are exactly the draft's two lesson corpora, its read-only
    ones the product code (`code`) and the draft root (`staged`); never the tenant clone or a
    retired corpus. The findings queue alone wakes the drain and only the findings curator is triggered (the store
    hands a curator only its kind's items; there is no retired queue to wake it, O10)."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    graded_episode(tmp_path, t)

    rec = B.BoxLifecycleRecorder()
    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rc, rec = drive_tenant_author_drain(t, paths, trigger, rec=rec)

    assert rc == 0
    assert trigger.completed == ["author"], "the findings curator was taken out of the tick"
    assert trigger.modules == ["author"], (
        f"author_drain triggered {trigger.modules}: a curator with no items of its kind was woken")
    call = trigger.calls[0]
    assert call["kind"] == "finding"
    assert call["threshold_env"] == "LEARNING_AUTHOR_THRESHOLD"
    assert call["pending_label"] == "pending"
    assert len(call["items"]) == 2, call["items"]
    request = rec.only_request()
    draft = draft_root(request)
    assert writable_sources(request) == {draft / "agent" / "lessons",
                                         draft / "agent" / "lessons-questioner"}, (
        f"the drain box's writable mounts are {sorted(map(str, writable_sources(request)))}")
    assert sorted(m.kind for m in request.mounts if not m.writable) == ["code", "staged"], (
        request.mounts)
    assert not [m for m in request.mounts
                if under(m.source, t.clone) or under(t.clone, m.source)], request.mounts
    for retired in RETIRED_CORPORA:
        assert B.mount_for(request, retired) is None, (
            f"{retired} is still bound into the drain box")
