"""#1108 P4 slice S-D — U10 (human decision D2, `.spec-flow/record.md` "Human decisions
(2026-10-23)"): a claim the commit-maker refuses, at drain level.

U10: the refused claim's draft is reset, the refusal counts ONE attempt on that claim's row, the
row stays queued and is retried on later ticks until #952's attempt ceiling quarantines it; the
other claims of the same batch proceed (commit and deliver).

What a claim is here: the lessons lane serves two curators into one batch (`author`, then
`questioner_curator`), each one claim (one ChangeSet, one commit-maker commit); the lead lane
serves each queued run as one claim. The refusal is the commit-maker's: a ChangeSet over the
draft carries only plain regular files under `agent/` (P3), so a symlink or a FIFO the claim's
model left in the draft refuses that claim.

How each half is observed:
  - "draft reset": the NEXT claim of the same batch (the sibling) looks at the draft when its
    model runs. Positive control: with no plant, the sibling sees the first claim's committed
    edit there (the observation reads the right folder).
  - attempts / queued / quarantine: the lane's own queue state. Lessons lane: the pending row's
    `attempts`, its graveyard entry (`LEARNING_AUTHOR_MAX_ATTEMPTS`). Lead lane: the queued
    record `author-queue/<case>.json`'s `attempts`, never left in `inflight/`, quarantined in
    `failed/` (`LEAD_AUTHOR_MAX_RETRIES`).
  - "proceeds": the sibling's edit is the batch branch's only change and has its PR.

Between ticks a human merges the sibling's PR (`merge_on_remote`), so the lane's writer lease
(OD8: our open PR on the lane's prefix holds the lane) does not hold the retry tick.

ASSUMED SEAMS: those of `_drain_support` (OD16: the trigger and steps receive the tick's
`batch=`; `draft_root_of(batch)` is where the lanes' files live). The lessons lane's
`hold_committed` keeps the committed sibling's row pending until its lesson reaches `main`
(#922/#952), so its re-serving is not asserted; only that it is never committed twice.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.curation._drain719 import graveyard, pending_by_id
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LEAD_DRAFT_LANES,
    LEAD_PREFIX,
    LESSON_NAME,
    LESSONS_PREFIX,
    BoxSpy,
    CuratorTrigger,
    LeadStep,
    author_drain,
    critical_text,
    draft_entries,
    draft_root_of,
    drain_paths,
    executed_lead,
    lead_author_drain,
    product_repo,
    queue,
    queued_run,
    remote_branches,
    touched,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, git

SIBLING_NAME = "p4-sibling.md"
PLANTED_NAME = "p4-planted.md"
LESSON_REL = f"agent/lessons/{LESSON_NAME}"
SIBLING_REL = f"agent/lessons-questioner/{SIBLING_NAME}"
TEMPLATE = "gather/queries/cmdb/host-owner.md"
TEMPLATE_REL = f"agent/skills/{TEMPLATE}"
REFUSED_EDIT = "\nRefused claim: check the badge reader.\n"
SIBLING_EDIT = "\nSibling claim: also check the asset tag.\n"


def _plant(kind: str, where: Path, outside: Path) -> None:
    where.parent.mkdir(parents=True, exist_ok=True)
    if kind == "link":
        where.symlink_to(outside)
    else:
        os.mkfifo(where)


def _outside(tmp_path: Path) -> Path:
    target = tmp_path / "outside-the-draft.md"
    target.write_text("a file outside every draft\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------------------------
# Lessons lane: the author claim refused, the questioner claim proceeds
# ---------------------------------------------------------------------------------------------


class _LessonsScene:
    """One tenant, one lessons-lane queue: `f-bad` for the author curator (whose model writes a
    plain lesson and, when `plant`, a symlink beside it) and `w1` for the questioner curator
    (the sibling, whose model writes a plain lesson and records what it sees of the author's
    claim in the draft)."""

    def __init__(self, t: Any, tmp_path: Path, *, plant: bool) -> None:
        from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS

        self.t, self.tmp_path = t, tmp_path
        self.findings, self.questioner = FINDINGS, QUESTIONER_FINDINGS
        self.paths = drain_paths(t, product_repo(tmp_path))
        queue(self.paths, [S.finding_row("f-bad", run_id="f-bad")])
        queue(self.paths, [S.world_row("w1", systems=["cmdb"])], channel=QUESTIONER_FINDINGS)
        outside = _outside(tmp_path)
        self.sibling_saw: list[dict] = []

        def plant_link(_rows: Any, _batch_id: str, cfg: Any) -> None:
            if plant:
                _plant("link", Path(cfg.corpus_dir) / PLANTED_NAME, outside)

        def look(_rows: Any, _batch_id: str, cfg: Any) -> None:
            lessons = Path(cfg.corpus_dir).parent / "lessons"
            self.sibling_saw.append({
                "lesson": (lessons / LESSON_NAME).is_file(),
                "planted": os.path.lexists(lessons / PLANTED_NAME),
            })

        self.author = S.FakeCurator(writes={LESSON_NAME: S.lesson("f-bad")}, also=plant_link)
        self.sibling = S.FakeCurator(writes={SIBLING_NAME: S.lesson("w1")}, also=look)
        self.trigger = CuratorTrigger(author=self.author, questioner_curator=self.sibling)

    def tick(self, caplog: Any) -> int:
        with caplog.at_level(logging.INFO):
            return author_drain(self.t, self.paths, trigger=self.trigger, box=BoxSpy())

    def bad_row(self) -> dict | None:
        return pending_by_id(self.paths, self.findings).get("f-bad")

    def served_bad(self) -> int:
        return sum(1 for c in self.author.calls
                   if "f-bad" in [r.get("finding_id") for r in c["rows"]])


@pytest.fixture
def lessons_lane(monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "2")


def test_u10_control_an_unrefused_lessons_batch_commits_both_claims(
        p4_tenant, tmp_path, lessons_lane, caplog):
    """Positive control for the cases below, on the same scene with no plant: both claims commit
    into the one batch branch (one PR), the sibling sees the author's committed lesson in the
    draft when its model runs, and the author's row carries no attempt."""
    t = p4_tenant
    bind_forge(t)
    s = _LessonsScene(t, tmp_path, plant=False)
    main = t.origin_main()

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert s.sibling_saw == [{"lesson": True, "planted": False}]
    (branch, tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    assert sorted(touched(t.remote, main, tip)) == sorted([LESSON_REL, SIBLING_REL])
    assert [c["head"] for c in t.forge.creates] == [branch]
    row = s.bad_row()
    assert row is not None, "the committed row is held until its lesson reaches main (#952)"
    assert int(row.get("attempts") or 0) == 0, row
    assert draft_entries(t) == []


def test_u10_a_refused_lessons_claim_is_reset_counted_and_left_queued_while_its_sibling_delivers(
        p4_tenant, tmp_path, lessons_lane, caplog):
    """U10, lessons lane: the author curator's model leaves a symlink beside its lesson, so the
    commit-maker refuses the author claim. Its draft changes are reset before the sibling runs
    (the sibling sees neither the lesson nor the link), nothing of it reaches the branch, the
    refusal counts one attempt on `f-bad`, which stays queued and out of the graveyard; the
    questioner claim of the same batch commits and is delivered (branch + PR). The tick itself
    completes (rc 0): a refused claim is the claim's outcome, not the tick's."""
    t = p4_tenant
    bind_forge(t)
    s = _LessonsScene(t, tmp_path, plant=True)
    main = t.origin_main()

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert s.served_bad() == 1
    assert s.sibling_saw == [{"lesson": False, "planted": False}], "the refused claim was not reset"
    (branch, tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    assert touched(t.remote, main, tip) == [SIBLING_REL]
    assert git(t.remote, "show", f"{tip}:{SIBLING_REL}") + "\n" == S.lesson("w1")
    assert [c["head"] for c in t.forge.creates] == [branch]
    row = s.bad_row()
    assert row is not None, "the refused claim's row left the queue"
    assert row.get("attempts") == 1, row
    assert [g for g in graveyard(s.paths, s.findings) if g.get("finding_id") == "f-bad"] == []
    assert draft_entries(t) == []


def test_u10_a_refused_lessons_row_is_retried_next_tick_and_quarantined_at_the_ceiling(
        p4_tenant, tmp_path, lessons_lane, caplog):
    """U10 + #952, lessons lane, ceiling 2 (`LEARNING_AUTHOR_MAX_ATTEMPTS`): after the sibling's
    PR is merged, the next tick serves `f-bad` again (attempt 2), is refused again and, at the
    ceiling, retires it to the graveyard (out of the queue); a third tick never serves it. The
    sibling's lesson is committed once only: no later branch touches it."""
    t = p4_tenant
    bind_forge(t)
    s = _LessonsScene(t, tmp_path, plant=True)

    assert s.tick(caplog) == 0, critical_text(caplog)
    (branch, _tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    assert s.bad_row()["attempts"] == 1
    merge_on_remote(t.p3, t.scratch, branch)
    merged = t.origin_main()
    known = set(remote_branches(t.remote, LESSONS_PREFIX))

    assert s.tick(caplog) == 0, critical_text(caplog)
    assert s.served_bad() == 2, "the refused row was not retried"
    assert s.bad_row() is None, "the row at the ceiling stayed queued"
    (dead,) = [g for g in graveyard(s.paths, s.findings) if g.get("finding_id") == "f-bad"]
    assert dead["attempts"] == 2, dead

    assert s.tick(caplog) == 0, critical_text(caplog)
    assert s.served_bad() == 2, "a quarantined row was served again"
    later = {b: tip for b, tip in remote_branches(t.remote, LESSONS_PREFIX).items() if b not in known}
    assert [b for b, tip in later.items() if SIBLING_REL in touched(t.remote, merged, tip)] == []
    assert draft_entries(t) == []


# ---------------------------------------------------------------------------------------------
# Lead lane: run `a`'s claim refused, run `b`'s claim proceeds
# ---------------------------------------------------------------------------------------------


class _Planting:
    """The lead drain's `run_lead_author` seam: `_drain_support.LeadStep` (the REAL lead author),
    with, for the runs named in `plants`, a planted entry under the batch's draft skills lane
    placed first (inside the claim's window), and, for the sibling, a record of what the draft
    holds of the earlier claim when its turn comes."""

    def __init__(self, step: LeadStep, *, plants: dict, outside: Path, sibling: str) -> None:
        self.step, self.plants, self.outside, self.sibling = step, plants, outside, sibling
        self.sibling_saw: list[dict] = []

    def __call__(self, paths: Any, state: Any, run: Any, *, batch: Any, **kw: Any) -> None:
        name = Path(run.run_dir).name
        skills = draft_root_of(batch) / LEAD_DRAFT_LANES[0]
        if name == self.sibling:
            text = (skills / TEMPLATE).read_text(encoding="utf-8")
            self.sibling_saw.append({
                "edit": REFUSED_EDIT.strip() in text,
                "planted": os.path.lexists(skills / "gather" / PLANTED_NAME),
            })
        if name in self.plants:
            _plant(self.plants[name], skills / "gather" / PLANTED_NAME, self.outside)
        return self.step(paths, state, run, batch=batch, **kw)


class _LeadScene:
    def __init__(self, t: Any, tmp_path: Path, *, plant: str | None) -> None:
        self.t = t
        self.paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
        self.bad = queued_run(t, self.paths, "p4-refused-a").name
        self.good = queued_run(t, self.paths, "p4-refused-b").name
        self.inner = LeadStep(
            executed={self.bad: [executed_lead("cmdb.owner-by-tag")],
                      self.good: [executed_lead("cmdb.owner-by-tag", lead_id="l-002")]},
            edits={self.bad: {TEMPLATE: REFUSED_EDIT}, self.good: {TEMPLATE: SIBLING_EDIT}})
        self.step = _Planting(self.inner, plants={self.bad: plant} if plant else {},
                              outside=_outside(tmp_path), sibling=self.good)
        self.queue_dir = Path(location_path(self.paths.state_root)) / "author-queue"

    def tick(self, caplog: Any) -> int:
        with caplog.at_level(logging.INFO):
            return lead_author_drain(self.t, self.paths, box=BoxSpy(), run_lead_author=self.step,
                                     run_pitfalls=lambda *_a, **_k: 0)

    def record(self, label: str, folder: str = "") -> dict | None:
        path = self.queue_dir / folder / f"case-{label}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    def served(self, run: str) -> int:
        return self.inner.served.count(run)


@pytest.fixture
def lead_lane(monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "2")


def test_u10_control_an_unrefused_lead_batch_commits_both_claims(
        p4_tenant, tmp_path, lead_lane, caplog):
    """Positive control for the lead cases below, same scene, no plant: both runs' edits land
    on the one `lead-author/` branch (one PR), the sibling sees the first claim's committed edit
    in the draft, and both rows leave the queue (neither queued, in flight nor failed)."""
    t = p4_tenant
    bind_forge(t)
    s = _LeadScene(t, tmp_path, plant=None)
    assert s.record("p4-refused-a") is not None, "control: the queue is read where it was filed"
    main = t.origin_main()

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert s.step.sibling_saw == [{"edit": True, "planted": False}]
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert TEMPLATE_REL in touched(t.remote, main, tip)
    text = git(t.remote, "show", f"{tip}:{TEMPLATE_REL}")
    assert REFUSED_EDIT.strip() in text
    assert SIBLING_EDIT.strip() in text
    assert [c["head"] for c in t.forge.creates] == [branch]
    for label in ("p4-refused-a", "p4-refused-b"):
        assert [s.record(label, f) for f in ("", "inflight", "failed")] == [None, None, None]
    assert draft_entries(t) == []


@pytest.mark.parametrize("plant", ["link", "fifo"])
def test_u10_a_refused_lead_claim_is_reset_counted_and_left_queued_while_its_sibling_delivers(
        p4_tenant, tmp_path, lead_lane, caplog, plant):
    """U10, lead lane: run `a`'s claim leaves a planted link / FIFO in the draft's skills lane,
    so the commit-maker refuses it. Its draft changes are reset before `b` runs (`b` sees
    neither `a`'s edit nor the plant), nothing of `a` reaches the branch, `a`'s record is back
    at the top of the queue carrying one attempt (not in flight, not failed); `b`'s claim
    commits and is delivered, and `b`'s row leaves the queue."""
    t = p4_tenant
    bind_forge(t)
    s = _LeadScene(t, tmp_path, plant=plant)
    main = t.origin_main()

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert (s.served(s.bad), s.served(s.good)) == (1, 1)
    assert s.step.sibling_saw == [{"edit": False, "planted": False}], "the refused claim was not reset"
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert touched(t.remote, main, tip) == [TEMPLATE_REL]
    text = git(t.remote, "show", f"{tip}:{TEMPLATE_REL}")
    assert SIBLING_EDIT.strip() in text
    assert REFUSED_EDIT.strip() not in text
    assert [c["head"] for c in t.forge.creates] == [branch]
    queued = s.record("p4-refused-a")
    assert queued is not None, "the refused claim's row left the queue"
    assert queued.get("attempts") == 1, queued
    assert s.record("p4-refused-a", "inflight") is None
    assert s.record("p4-refused-a", "failed") is None
    assert [s.record("p4-refused-b", f) for f in ("", "inflight", "failed")] == [None, None, None]
    assert draft_entries(t) == []


def test_u10_a_refused_lead_row_is_retried_next_tick_and_quarantined_at_the_ceiling(
        p4_tenant, tmp_path, lead_lane, caplog):
    """U10 + #952, lead lane, ceiling 2 (`LEAD_AUTHOR_MAX_RETRIES`): after `b`'s PR is merged,
    the next tick serves `a` again (attempt 2) and not `b`; refused again at the ceiling, `a` is
    quarantined in `failed/` (out of the queue and of `inflight/`); a third tick serves
    nothing. No later branch is opened for either run."""
    t = p4_tenant
    bind_forge(t)
    s = _LeadScene(t, tmp_path, plant="link")

    assert s.tick(caplog) == 0, critical_text(caplog)
    (branch, _tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert s.record("p4-refused-a")["attempts"] == 1
    merge_on_remote(t.p3, t.scratch, branch)
    known = set(remote_branches(t.remote, LEAD_PREFIX))

    assert s.tick(caplog) == 0, critical_text(caplog)
    assert (s.served(s.bad), s.served(s.good)) == (2, 1)
    assert s.record("p4-refused-a") is None, "the row at the ceiling stayed queued"
    assert s.record("p4-refused-a", "inflight") is None
    failed = s.record("p4-refused-a", "failed")
    assert failed is not None, "the row at the ceiling was not quarantined"
    assert failed.get("failed"), failed

    assert s.tick(caplog) == 0, critical_text(caplog)
    assert (s.served(s.bad), s.served(s.good)) == (2, 1)
    assert set(remote_branches(t.remote, LEAD_PREFIX)) == known
    assert draft_entries(t) == []
