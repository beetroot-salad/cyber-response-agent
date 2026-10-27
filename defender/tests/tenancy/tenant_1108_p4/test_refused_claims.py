"""#1108 P4 U10: a claim the commit-maker refuses, at drain level.

The refused claim's draft is reset, the refusal counts one attempt on its row, and the row stays
queued and is retried until #952's attempt ceiling quarantines it; the batch's other claims
commit and deliver. A claim is one curator's work in the lessons lane (`author`, then
`questioner_curator`, in one batch) or one queued run in the lead lane. A ChangeSet carries only
plain regular files under `agent/`, so a symlink or FIFO the model left in the draft refuses it.

"Reset" is observed by the batch's next claim (the sibling) looking at the draft when its model
runs; each control shows it does see a committed edit there. Attempts and quarantine are the
lane's own queue state. Between ticks a human merges the sibling's PR, so the lane's writer lease
(our open PR holds the lane) does not hold the retry tick. The lessons lane's `hold_committed`
keeps the committed sibling's row pending until its lesson reaches `main`, so its re-serving is
not asserted, only that it is never committed twice.
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
    PitfallsStep,
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
    elif kind == "out-of-lane":
        where.write_text("a plain file outside the claim's lane\n", encoding="utf-8")
    else:
        os.mkfifo(where)


#: Where a lead claim's plant goes under the draft root: a link or FIFO inside the skills lane,
#: or a plain file outside the lane under `agent/` (also a commit-maker refusal).
_LEAD_PLANT_AT = {"link": f"{LEAD_DRAFT_LANES[0]}/gather/{PLANTED_NAME}",
                  "fifo": f"{LEAD_DRAFT_LANES[0]}/gather/{PLANTED_NAME}",
                  "out-of-lane": f"agent/{PLANTED_NAME}"}


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
    """Positive control, same scene with no plant: both claims commit on one branch with one PR,
    and the sibling sees the author's committed lesson in the draft."""
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
    """The author's model leaves a symlink beside its lesson, so its claim is refused: reset
    before the sibling runs, absent from the branch, one attempt counted with the row still
    queued; the questioner claim delivers. The tick completes (rc 0): a refused claim is the
    claim's outcome, not the tick's."""
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
    """Ceiling 2: after the sibling's PR merges, the next tick retries `f-bad`, is refused again
    and retires it to the graveyard; a third tick never serves it, and no later branch
    re-commits the sibling's lesson."""
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
    """The lead drain's `run_lead_author` seam: `LeadStep`, with a planted entry placed first
    (inside the claim's window) for the runs named in `plants`, and, for the sibling, a record
    of what the draft holds of the earlier claim when its turn comes."""

    def __init__(self, step: LeadStep, *, plants: dict, outside: Path, sibling: str) -> None:
        self.step, self.plants, self.outside, self.sibling = step, plants, outside, sibling
        self.sibling_saw: list[dict] = []

    def __call__(self, paths: Any, state: Any, run: Any, *, batch: Any, **kw: Any) -> None:
        name = Path(run.run_dir).name
        root = draft_root_of(batch)
        skills = root / LEAD_DRAFT_LANES[0]
        if name == self.sibling:
            text = (skills / TEMPLATE).read_text(encoding="utf-8")
            self.sibling_saw.append({
                "edit": REFUSED_EDIT.strip() in text,
                "planted": any(os.path.lexists(root / at) for at in set(_LEAD_PLANT_AT.values())),
            })
        if name in self.plants:
            kind = self.plants[name]
            _plant(kind, root / _LEAD_PLANT_AT[kind], self.outside)
        return self.step(paths, state, run, batch=batch, **kw)


class _LeadScene:
    def __init__(self, t: Any, tmp_path: Path, *, plant: str | None) -> None:
        self.t = t
        self.paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
        self.bad = queued_run(t, self.paths, "p4-refused-a").name
        self.good = queued_run(t, self.paths, "p4-refused-b").name
        # `a` runs an uncatalogued query, so the real draft synthesis mints a `_draft/` entry
        # inside `a`'s claim, which a refused `a` must take down with it. `b` runs the catalogued
        # template's own query and mints no draft, so the branch carries exactly the template.
        self.inner = LeadStep(
            executed={self.bad: [executed_lead("cmdb.owner-by-tag")],
                      self.good: [executed_lead("cmdb.host-owner", lead_id="l-002")]},
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
    """Positive control, same scene with no plant: both runs' edits land on one `lead-author/`
    branch with one PR, the sibling sees the first claim's committed edit, and both rows leave
    the queue."""
    t = p4_tenant
    bind_forge(t)
    s = _LeadScene(t, tmp_path, plant=None)
    assert s.record("p4-refused-a") is not None, "control: the queue is read where it was filed"
    main = t.origin_main()

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert s.step.sibling_saw == [{"edit": True, "planted": False}]
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    paths_touched = touched(t.remote, main, tip)
    assert TEMPLATE_REL in paths_touched
    # Control for the refused case's exact path set: unrefused, `a`'s claim does mint its draft.
    assert len([p for p in paths_touched if "/_draft/" in p]) == 1, paths_touched
    text = git(t.remote, "show", f"{tip}:{TEMPLATE_REL}")
    assert REFUSED_EDIT.strip() in text
    assert SIBLING_EDIT.strip() in text
    assert [c["head"] for c in t.forge.creates] == [branch]
    for label in ("p4-refused-a", "p4-refused-b"):
        assert [s.record(label, f) for f in ("", "inflight", "failed")] == [None, None, None]
    assert draft_entries(t) == []


@pytest.mark.parametrize("plant", ["link", "fifo", "out-of-lane"])
def test_u10_a_refused_lead_claim_is_reset_counted_and_left_queued_while_its_sibling_delivers(
        p4_tenant, tmp_path, lead_lane, caplog, plant):
    """Run `a`'s claim leaves a link or FIFO in the skills lane, or a plain file outside it, so
    it is refused: reset before `b` runs, absent from the branch, and back in the queue with one
    attempt; `b`'s claim delivers and leaves the queue."""
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
    """Ceiling 2: after `b`'s PR merges, the next tick retries only `a`, which, refused again, is
    quarantined in `failed/`; a third tick serves nothing and opens no branch."""
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


# ---------------------------------------------------------------------------------------------
# Lead lane, pitfalls step: its one claim refused
# ---------------------------------------------------------------------------------------------


class _PlantingPitfalls:
    """The lead drain's `run_pitfalls` seam: `PitfallsStep`, with, when `plant`, a link placed in
    the draft's skills lane first so the commit-maker refuses the claim."""

    def __init__(self, step: PitfallsStep, *, plant: bool, outside: Path) -> None:
        self.step, self.plant, self.outside = step, plant, outside
        self.calls = 0

    def __call__(self, paths: Any, state: Any, *, batch: Any, **kw: Any) -> int:
        self.calls += 1
        if self.plant:
            _plant("link", draft_root_of(batch) / _LEAD_PLANT_AT["link"], self.outside)
        return self.step(paths, state, batch=batch, **kw)


class _PitfallsScene:
    def __init__(self, t: Any, tmp_path: Path, *, plant: bool) -> None:
        from defender.learning.core.state import PITFALLS
        from defender.tests.support.learning.core._declared870 import shim_row

        self.t, self.channel = t, PITFALLS
        self.paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
        queue(self.paths, [shim_row(PITFALL_ID)], channel=PITFALLS)
        self.inner = PitfallsStep(PITFALL_BULLET)
        self.step = _PlantingPitfalls(self.inner, plant=plant, outside=_outside(tmp_path))

    def tick(self, caplog: Any) -> int:
        with caplog.at_level(logging.INFO):
            return lead_author_drain(self.t, self.paths, box=BoxSpy(), run_pitfalls=self.step,
                                     run_lead_author=lambda *_a, **_k: None)

    def row(self) -> dict | None:
        return pending_by_id(self.paths, self.channel).get(PITFALL_ID)

    def dead(self) -> list[dict]:
        return [g for g in graveyard(self.paths, self.channel)
                if g.get("pitfall_id") == PITFALL_ID]


PITFALL_ID = "p4-run:1"
PITFALL_BULLET = "- **Name the unnested column.** An anonymous unnest cannot be grouped."
PITFALLS_ADDON = "agent/skills/gather/defender-sql.pitfalls.md"


@pytest.fixture
def pitfalls_lane(monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "2")


def test_u10_control_an_unrefused_pitfalls_claim_delivers_and_leaves_the_queue(
        p4_tenant, tmp_path, pitfalls_lane, caplog):
    """Positive control, same scene with no plant: the curated bullet lands on the tenant add-on
    page on one `lead-author/` branch with its PR, and the row carries no attempt."""
    t = p4_tenant
    bind_forge(t)
    s = _PitfallsScene(t, tmp_path, plant=False)
    assert s.row() is not None, "control: the pitfall is queued where the drain reads it"
    main = t.origin_main()

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert s.inner.handoffs, "the pitfalls curation never spawned"
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert touched(t.remote, main, tip) == [PITFALLS_ADDON]
    assert [c["head"] for c in t.forge.creates] == [branch]
    row = s.row()
    assert row is None or int(row.get("attempts") or 0) == 0, row
    assert s.dead() == []
    assert draft_entries(t) == []


def test_u10_a_refused_pitfalls_claim_is_dead_lettered_as_refused_not_propagated(
        p4_tenant, tmp_path, pitfalls_lane, caplog):
    """The pitfalls claim leaves a link in the skills lane and is refused as the claim's outcome,
    not the tick's: rc 0, nothing reaches the origin or forge, one attempt is counted with the
    row queued, and at the ceiling (2) the next refusal dead-letters it, naming the refusal. A
    refusal propagated out of the step would end the tick instead."""
    t = p4_tenant
    bind_forge(t)
    s = _PitfallsScene(t, tmp_path, plant=True)

    rc = s.tick(caplog)

    assert rc == 0, critical_text(caplog)
    assert s.inner.handoffs, "the pitfalls curation never spawned, so nothing was refused"
    assert remote_branches(t.remote, LEAD_PREFIX) == {}
    assert t.forge.creates == []
    row = s.row()
    assert row is not None, "the refused pitfall left the queue on its first refusal"
    assert row.get("attempts") == 1, row
    assert s.dead() == []
    assert draft_entries(t) == []

    assert s.tick(caplog) == 0, critical_text(caplog)
    assert s.step.calls == 2, "the refused pitfall was not retried"
    assert s.row() is None, "the pitfall at the ceiling stayed queued"
    (dead,) = s.dead()
    assert dead.get("attempts") == 2, dead
    assert "DeliveryRefused" in json.dumps(dead), (
        f"the dead letter does not name the commit-maker's refusal: {dead}")
    assert remote_branches(t.remote, LEAD_PREFIX) == {}
    assert draft_entries(t) == []
