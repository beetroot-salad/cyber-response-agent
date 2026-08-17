"""#869 O3/RF6/RF7/FK-2/FK-17 — reported, never silently absorbed; and the durable record.

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared869.py`.

A membership refusal that leaves no trace is the failure O4 names: from inside a tick an
adapter that will exist tomorrow and an invented name are indistinguishable (N5), so both go
to human review — which requires there to BE a review surface.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning.author import drain
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests._declared869 import (
    ADAPTERS_REL,
    SKILLS_REL,
    Spawn,
    head_files,
    log_lines_naming,
    loop_log,
    marker_file,
    pitfall_row,
    read_rows,
    seed_tree,
    write,
)

DECLARED = frozenset({"elastic"})


def _mixed_batch(tmp_path: Path, monkeypatch, *, name: str = "repo"):
    """The mixed tick P9 executed: two `elastic` rows, one undeclared `elastik` row, and a
    curator edit that produces a REAL commit.

    P9 moved these demands onto the mixed batch on purpose. The all-dropped control is milder
    — its sha is `None` (C37) — and cannot see the defect at all: it takes a batch that DOES
    commit something for the dropped row to inherit a sha that has nothing to do with it."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), name=name)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / f"state-{name}")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "elastic"),
         pitfall_row("r:l-002:0", "elastik")],
        paths=paths,
    )
    spawn = Spawn(lambda root: write(
        marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- curated\n",
    ))
    return repo, paths, spawn


def test_dropped_names_are_named_in_the_log(tmp_path, monkeypatch, capsys):
    """A tick that drops rows naming `gather` and `fakesys` emits a line naming BOTH, the
    reason, and the SOURCE CONSULTED — which at this lane is ONE source, the adapters
    directory, and never the marker source.

    THE FOSSIL THIS CORRECTS (phase F, F2). `35-design-corrections.md` altered this demand to
    "name the source consulted, since there are now two" while the union still governed every
    site; §7 then resolved NF2 and handed THIS lane the adapter half alone. Requiring both
    directory names on the line would make the implementation print `defender/skills` on a
    line explaining a decision taken WITHOUT reading `defender/skills` — and would tell an
    operator the wrong thing about which half came back without the name, which is the exact
    failure the "source consulted" clause was added to prevent. So the line names the source
    this lane actually consulted, and the marker source is asserted ABSENT from it.

    This is what feeds a human review of names that are neither invented nor yet real: from
    inside a tick the two are indistinguishable and both go to review (N5), which is why the
    rejected branch here is "distinguish an adapter that will exist tomorrow from an invented
    name". WHAT THIS DEMAND DOES NOT REACH is site 3 — FK-3 mints that surface separately, and
    the parity across the three sites is not this demand's to assert.

    FK-16 rides here, stated as a decision rather than left as an implementation accident:
    for a DELETE under an undeclared directory MEMBERSHIP FIRES FIRST, and the reason reported
    follows the existing vocabulary — so the operator gets the name and the registry reason,
    not a deletion complaint about a directory that should never have been written to.
    RE-PINNED AT SITE 2 (phase F, F3): the premise FK-16 was answered from is explicit that
    the site is `lead_author._skills_path_rule`, where the in-scope test GAINS membership. At
    site 1 membership already precedes the delete branch at this base, so an assertion there
    certifies existing behaviour and leaves the decision unpinned exactly where an implementer
    could put the new check after the old one. Both sites are driven; site 2 is the one that
    would otherwise be free.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "gather"),
         pitfall_row("r:l-002:0", "fakesys")],
        paths=paths,
    )
    spawn = Spawn(lambda root: write(
        marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- curated\n",
    ))
    capsys.readouterr()
    pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn)

    log = loop_log(capsys)
    named = log_lines_naming(log, "gather", "fakesys", repo / ADAPTERS_REL)
    assert named, (
        f"no single line names both dropped systems and the source consulted: {log}"
    )
    assert [ln for ln in named if str(repo / SKILLS_REL) in ln] == [], (
        f"the drop line names the MARKER source, which this lane never consults under NF2 — "
        f"an operator reading it is told the wrong half came back without the name: {named}"
    )
    assert spawn.systems_seen == ["elastic"], "the declared row must still be handed over"

    # FK-16 at SITE 2, where membership is new: a `D ` under an undeclared directory reports
    # the NAME and the registry reason, not the deletion complaint.
    with pytest.raises(LeadAuthorError) as refusal:
        lead_author._skills_path_rule(
            repo, "D ", "defender/skills/fakesys/SKILL.md", systems=DECLARED)
    assert "fakesys" in str(refusal.value)
    assert "deleted" not in str(refusal.value), (
        "the undeclared name was absorbed into a deletion complaint about a directory that "
        "should never have been written to — O3's own failure shape, and the arm FK-16 "
        "chose against"
    )
    # The control on the same address and the same rule: a `D ` under a DECLARED system is
    # still the delete-prohibition's, so the channel demonstrably tells the two reasons apart
    # rather than having lost the deletion complaint altogether.
    with pytest.raises(LeadAuthorError, match="deleted"):
        lead_author._skills_path_rule(
            repo, "D ", "defender/skills/elastic/SKILL.md", systems=DECLARED)

    # Site 1 keeps its arm too — already ordered this way at this base, so it certifies rather
    # than decides, and it is here so the two sites cannot silently diverge.
    with pytest.raises(LeadAuthorError) as site1:
        pitfalls_curator._pitfalls_path_rule(
            "D ", "defender/skills/fakesys/execution.md", systems=DECLARED)
    assert "fakesys" in str(site1.value)
    assert "deleted" not in str(site1.value)


def test_a_dropped_row_is_never_labelled_committed(tmp_path, monkeypatch):
    """A dropped row is never stamped `consumed_committed`, and never carries a
    `consumed_commit` sha.

    RF7, moved onto the MIXED batch by P9 because the all-dropped case cannot see it.
    Executed at this base: with two `elastic` rows, one undeclared `elastik` row and a real
    commit, ALL THREE consumed rows carry `consumed_category: consumed_committed` and the same
    `consumed_commit` — a commit whose only content was `elastic/execution.md`. The dropped row
    is not merely mis-categorised: it carries the sha of a commit that contains NOTHING about
    it, and `_rewrite_queue` attaches that provenance precisely BECAUSE the category claims a
    commit, so fixing the category withdraws the false provenance as a side effect.

    This demand is the NEGATIVE half; `dropped_row_takes_the_undeclared_category` is the
    positive one on the same address. The two declared rows are the control here: they DO
    carry the category and the sha, so a rotation that stamped nothing would not pass.
    """
    repo, paths, spawn = _mixed_batch(tmp_path, monkeypatch)
    pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn)

    consumed = {r["pitfall_id"]: r for r in read_rows(paths.pitfalls.consumed)}
    assert set(consumed) == {"r:l-000:0", "r:l-001:0", "r:l-002:0"}
    assert "defender/skills/elastic/execution.md" in head_files(repo)

    dropped = consumed["r:l-002:0"]
    assert dropped["consumed_category"] != "consumed_committed"
    assert dropped.get("consumed_commit") is None

    for kept in ("r:l-000:0", "r:l-001:0"):
        assert consumed[kept]["consumed_category"] == "consumed_committed"
        assert consumed[kept]["consumed_commit"]


def test_a_dropped_row_takes_a_terminal_undeclared_category(tmp_path, monkeypatch):
    """A dropped row takes the DISTINCT TERMINAL category `consumed_unattributable` and goes to
    the graveyard record for a human to act on (FK-2, §7).

    `dropped_rows_are_never_labelled_committed`'s positive control on the same address: the
    negative alone is satisfied by any label at all, including one that reads like an ordinary
    skip. Over the same mixed batch, the two declared rows carry `consumed_committed` plus the
    real sha and the dropped row carries `consumed_unattributable` (#870 F4 renamed it:
    "undeclared" was false of a systemless row and of `../evil`), no `consumed_commit`, and a
    durable record naming it.

    REJECTED, and why: reusing `consumed_skip`, which already means something else to every
    one of the twelve assertion sites C39 censused; and leaving the row queued to be re-dropped
    every tick, which is the only reading that does not bound the queue. UN-GATED rather than
    merely recommended — P9 showed `batch_ids` is computed from the RAW rows before any
    dropping, so the dropped id IS inside it, pending goes to empty, and no path leaves an
    undeclared row stuck.
    """
    repo, paths, spawn = _mixed_batch(tmp_path, monkeypatch, name="undeclared")
    pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn)

    consumed = {r["pitfall_id"]: r for r in read_rows(paths.pitfalls.consumed)}
    assert consumed["r:l-002:0"]["consumed_category"] == "consumed_unattributable"
    assert "consumed_commit" not in consumed["r:l-002:0"]
    assert consumed["r:l-000:0"]["consumed_category"] == "consumed_committed"

    assert persist.read_pitfalls(paths) == [], "pending must go empty; the row is terminal"
    graveyard = {r.get("pitfall_id") for r in read_rows(drain.graveyard_file(paths.pitfalls))}
    assert "r:l-002:0" in graveyard, (
        "the dropped row leaves no durable record, so nothing reaches human review"
    )
    assert "r:l-000:0" not in graveyard
    assert repo.is_dir()


def test_an_empty_declared_set_refuses_the_lane(tmp_path, monkeypatch, capsys):
    """An empty declared set is NOT spendable as a gate: `run_pitfalls` over a tree that
    declares nothing leaves every queued row in `pitfalls.jsonl`, writes nothing to
    `pitfalls.consumed.jsonl`, and fails loud.

    RF6, human-resolved. This is the half M1 buys at the resolver and the consumers spend at
    an ordinary falsy test — C37, executed at this base: rc 0, the curator never spawned,
    pending 2 -> 0, and both rows stamped committed. An empty set applied as a membership "no"
    to every row is a silent per-row refusal, which is exactly the failure O4 names.

    The falsy value being a VALID answer at the resolver is a different demand
    (`declared_systems_empty_dir_reports`); this one is what the consumers may do with it.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=(), markers=(), skills=(), catalog=(),
                     non_systems=("gather",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], paths=paths,
    )
    spawn = Spawn()
    capsys.readouterr()

    with pytest.raises(LeadAuthorError):
        pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn)

    assert spawn.calls == [], "the curator must not be spawned against an empty set"
    assert len(persist.read_pitfalls(paths)) == 2
    assert not paths.pitfalls.consumed.exists()
    assert head_files(repo), "the fixture never committed anything"
    assert "execution.md" not in " ".join(head_files(repo))
    assert loop_log(capsys).strip(), "the refusal must be loud"


def test_a_membership_refusal_is_terminal_and_leaves_a_re_drivable_record(tmp_path, capsys):
    """A membership refusal on the lead-author leg is TERMINAL on the first tick and leaves
    one durable, re-drivable record — no retriable class, no burned attempts (FK-17, §7).

    PO-K/P6 refuted the judge's provisional outright before this reached the human:
    quarantine is terminal today, and `LEAD_AUTHOR_MAX_RETRIES` (3 TOTAL attempts, not 3
    retries) governs `_LeadAuthorRetry`, a class a membership refusal never raises. Driven over
    five ticks against a real marker queue with the lane refusing on membership: the marker is
    quarantined on the FIRST tick to `author-queue/failed/<case>.json` carrying the refusal
    reason and the name, the queued marker is unlinked, the lane is invoked exactly ONCE
    across the following ticks, and no attempt counter is burned.

    REJECTED, and asserted as rejected: the retriable class, whose automatic rescue costs
    three spawns per permanently-undeclared name, is reachable today only by raising the very
    `OSError`/`SubprocessError` class `resolver_failure_is_not_swallowed_as_a_successful_tick`
    forbids on the sibling pitfalls leg, and would leave an `attempts` counter on a requeued
    spec rather than a record.

    THE DEMAND STATES THAT THE RECORD EXISTS; IT DOES NOT ASSERT THE VIEW THAT READS IT.
    Re-driving it is #870's amendment and #903's view, neither of which is in this tree — so
    what is pinned is that the record retains everything a re-drive needs.
    """
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = tmp_path / "run-x"
    (run_dir / "gather_raw").mkdir(parents=True)
    write(paths.author_queue_dir / "case-1.json",
          json.dumps({"case_id": "case-1", "run_dir": str(run_dir)}) + "\n")

    calls: list[Path] = []

    def refusing_lane(_paths, rd, *, box=None):
        calls.append(rd)
        raise LeadAuthorError(
            "lead author refused: mcpsys is not a declared system in this tree")

    capsys.readouterr()
    for _tick in range(5):
        drains._drain_lead_author_markers(paths, refusing_lane)

    assert len(calls) == 1, f"the refusal was retried: {len(calls)} invocations"
    assert not (paths.author_queue_dir / "case-1.json").exists()
    assert not list((paths.author_queue_dir / "inflight").glob("*.json"))

    failed = paths.author_queue_dir / "failed" / "case-1.json"
    assert failed.is_file()
    record = json.loads(failed.read_text())
    assert "mcpsys" in record["failed"]
    assert record["run_dir"] == str(run_dir)
    assert record["case_id"] == "case-1"
    assert "attempts" not in record, (
        "an attempts counter means the retriable class was taken, which §7 declined"
    )
