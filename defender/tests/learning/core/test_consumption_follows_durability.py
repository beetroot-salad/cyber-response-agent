"""#952 — consumption follows durability in the lead-author lane.

#1278 (design r8 Flows, Lead-author lane, Locks, Schema "Retired files") replaced the lane's file queue, its drain and queue
locks, its inflight/failed folders, its ledgers and its by-hand entry with the store claim: an item is kept until its batch
ends and takes a per-kind fate (published at the merge, held, skipped, dead, or waiting again). What survives of #952 is
below: a served run's commit is handed back (`on_done`) or the sentinel written, and the pitfalls curator commits and
hands its partition back rather than consuming it.

Retired from this file:
- `test_952_o3_a_batch_that_passes_the_scrub_consumes_what_it_served`, `test_952_m1_the_disposition_applies_sentinels_and_unlinks_before_the_pitfalls_rotation`,
  `test_952_c_the_queue_lock_is_held_through_curation_and_finish_batch`, `test_952_d_a_failed_sentinel_write_leaves_the_claim_in_inflight`:
  consumption by rotating a file queue and unlinking inflight markers after the scrub; an item now stays `in_batch` until
  the PR merges and is published by the reconcile (`test_1278_curator_fates.py::test_d9_the_pitfalls_curator_is_handed_the_claims_pitfalls_and_its_commit_waits_in_the_batch_for_the_merge`,
  `test_store_1278.py::test_d9_a_lead_batchs_curation_requests_keep_their_own_fate_until_the_batch_ends`).
- `test_952_m1_the_deferred_rotation_reaches_the_queue_lock_with_a_deadline`, `..._the_immediate_rotation_is_bounded_under_the_drain_and_unbounded_by_hand`,
  `test_952_m5_*` (3 tests): the queue lock, its append-lock deadline and the by-hand entry are deleted (design r8 Locks: "lead-queue:
  by-hand run uses the same claim"; A3); a second tick over a held lane is `test_1278_tick.py::test_locks_a_tick_finding_a_live_batch_of_another_holder_authors_nothing_and_exits_quietly`.
- `test_952_o8_every_serve_is_an_attempt_and_the_run_is_quarantined_at_the_ceiling`: attempts are the item's counter stamped at claim; the
  drain-level bound on a failing request is `test_loop.py::test_lead_author_drain_bounds_the_retries_of_a_failing_request`.
- `test_952_o6_a_transient_serve_failure_neither_destroys_nor_supersedes_a_fresher_request`: a request returning to waiting beside
  a fresher one is now superseded in the same transaction (design r8 Schema: coalesce key, "the later run wins"; contract
  `test_items_1278.py::test_a_request_returning_to_waiting_beside_a_fresher_one_is_superseded`).
- `test_952_m1_a_malformed_lock_wait_refuses_the_tick_before_any_work` is ported below (the setting is still read before any work).
"""
from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.learning.store import Outcome
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._declared870 import (
    REDUCER_REL,
    Spawn,
    commit_all,
    curate_agent_execution_md,
    pitfall_row,
    reducer_surface_text,
    seed_agent_files,
    seed_product,
    seed_tree,
    shim_row,
    write_reducer_surface,
)
from defender.tests.support.learning.core._store1278 import call, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import (
    draft_lead_deps,
    product_lane,
    lead_deps,
)
from defender.tests.support.shared.contracts._repo import query_template, seed_skills_repo
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, lead_author_drain
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on

#: The commit a served lead-author run hands the drain in place of writing the sentinel itself.
SHA = "abc123"

_SENTINEL_RE = re.compile(r"\Acommit: (?P<sha>\S+)\nat: \S+\ncommit_made: (?P<made>True|False)\n\Z")


def _done(run_dir: Path) -> Path:
    return run_dir / "lead_author" / "done"


def _done_sha(run_dir: Path) -> str:
    """The commit the run's sentinel records — through the sentinel's own shape, so a
    look-alike file is a failure here rather than a match."""
    text = _done(run_dir).read_text(encoding="utf-8")
    m = _SENTINEL_RE.match(text)
    assert m, f"not a sentinel: {text!r}"
    return m["sha"]


@pytest.mark.postgres
def test_952_m1_a_malformed_lock_wait_refuses_the_tick_before_any_work(world, monkeypatch):  # noqa: F811 — the imported fixture
    from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir

    w = world
    run_dir = curation_run_dir("case-1")
    call(w.dsn, "enqueue_request", w.t.tenant_id, run_dir.name, "case-1", curation_row("case-1", run_dir))
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "soon")
    served: list = []
    box = BoxSpy()

    rc = lead_author_drain(w.t, w.paths, box=box, run_lead_author=lambda _p, _s, run, *, on_done, **_k: served.append(run.run_dir))

    assert rc == 2, "a malformed setting did not refuse the tick"
    assert served == []
    assert box.requests == [], "a box started for a refused tick"
    assert call(w.dsn, "batches", w.t.tenant_id) == [], "a batch was started for a refused tick"


# --- the curators' switch: consume now, or hand the consumption back -------------------------


def _lead(**kw) -> ExecutedLead:
    base = dict(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id="wazuh.newthing", system="wazuh", verb="newthing", params={}, raw_command="cli",
        goal_text="", what_to_summarize=(), raw_ref=None,
        payload_status="ok", payload_digest="", error_class=None,
    )
    base.update(kw)
    return ExecutedLead(**base)


def _curator_deps(repo: Path, **overrides):
    """Production lead-author deps over a seeded, committed skills tree, with the two tables
    bypassed (their own suite)."""
    deps = lead_deps(LoopPaths(repo_root=repo))
    seams = dict(
        extract=lambda _rd: ([], [_lead()]),
        synthesize=lambda executed, skills=None, where=None, catalog=None, systems=None: [],
        discover_system_drafts=lambda: [],
    )
    seams.update(overrides)
    return replace(deps, **seams)


#: The catalog in a batch draft: the lane commits `agent/...`.
_DRAFT_CATALOG = "agent/skills/gather/queries"


def _draft_curator_deps(lane, **overrides):
    """`_curator_deps` over a batch draft: the production lead-author deps
    (`build_lead_author_deps(..., batch=)`) over the draft of `seed_skills_repo`'s tree, the two
    tables bypassed (their own suite)."""
    seams = dict(
        extract=lambda _rd: ([], [_lead()]),
        synthesize=lambda executed, skills=None, where=None, catalog=None, systems=None: [],
        discover_system_drafts=lambda: [],
    )
    seams.update(overrides)
    return draft_lead_deps(lane, **seams)


def _promoting_draft_agent(root: Path):
    """`_promoting_agent` in the draft: promote `wazuh.newthing` out of `_draft/`."""
    def agent(_rd, _handoffs, _pending, *, box=None) -> int:
        (root / _DRAFT_CATALOG / "wazuh" / "newthing.md").write_text(
            query_template("wazuh.newthing", "established"), encoding="utf-8",
        )
        (root / _DRAFT_CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
        return 0

    return agent


def _agent_must_not_run(*_a, **_kw) -> int:
    raise AssertionError("the agent was spawned on a path that resolves no handoff")


@pytest.mark.parametrize("deferred", [False, True], ids=["default-writes", "on_done-defers"])
def test_952_m4_the_post_commit_sentinel_is_written_or_handed_over(
    tmp_path: Path, deferred: bool,
):
    """The `_run_locked` write site, after the commit (over a batch draft, so the commit is the
    batch branch's)."""
    lane = product_lane(tmp_path, seed_skills_repo(tmp_path / "repo"))
    run_dir = _state1135.curation_run_dir("lead-run")
    deps = _draft_curator_deps(
        lane,
        invoke_agent=_promoting_draft_agent(lane.root),
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
    )
    head_before = lane.tip()
    captured: list[str | None] = []

    run = _state1135.run_of(run_dir)
    rc = lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps,
                         on_done=captured.append) if deferred \
        else lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)

    assert rc == 0
    sha = lane.tip()
    assert sha != head_before, "the commit is not deferred — only the sentinel is"
    assert "agent/skills/gather/queries/wazuh/newthing.md" in lane.landed()
    if deferred:
        assert not _done(run_dir).exists(), "deferred mode still wrote the sentinel"
        assert captured == [sha]
    else:
        assert captured == []
        assert _done_sha(run_dir) == sha
        assert _done(run_dir).read_text(encoding="utf-8").endswith("commit_made: True\n")
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file(), \
        "the pitfalls_collected marker was deferred too"


@pytest.mark.parametrize("deferred", [False, True], ids=["default-writes", "on_done-defers"])
def test_952_m4_the_none_resolved_sentinel_is_written_or_handed_over(
    tmp_path: Path, deferred: bool,
):
    repo = seed_skills_repo(tmp_path / "repo")
    run_dir = _state1135.curation_run_dir("lead-run")
    deps = _curator_deps(
        repo,
        invoke_agent=_agent_must_not_run,
        build_handoff=lambda rd, ex, jl=None, **_: [],
    )
    head_before = _git.git_head_sha(repo)
    captured: list[str | None] = []

    run = _state1135.run_of(run_dir)
    rc = lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps,
                         on_done=captured.append) if deferred \
        else lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)

    assert rc == 0
    assert _git.git_head_sha(repo) == head_before, "a none-resolved run made a commit"
    if deferred:
        assert not _done(run_dir).exists()
        assert captured == [None]
    else:
        assert captured == []
        assert _done_sha(run_dir) == "none"
        assert _done(run_dir).read_text(encoding="utf-8").endswith("commit_made: False\n")

# --- the pitfalls curator hands its partition back, or consumes at once ----------------------


@pytest.fixture
def pitfalls_lane(tmp_path: Path, monkeypatch):
    """A batch draft of the tenant carrying the reducer add-on (elastic's
    marker and skill, `gather`), over a product checkout with the elastic and cmdb adapters;
    threshold 1."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    product = seed_product(tmp_path, adapters=("elastic", "cmdb"))
    files = seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=(),
                             non_systems=("gather",))
    files[REDUCER_REL.removeprefix("agent/")] = reducer_surface_text()
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files=files)


def _three_way_items() -> list[tuple[str, str, dict]]:
    """One row per partition: a declared-system row the curator teaches (committed), a reducer row the curator is offered
    and declines (held), and an undeclared-system row nothing can ever teach (unattributable), as a claim's items."""
    rows = [pitfall_row("c:l-000:0", "elastic"), shim_row("h:l-003:0"), pitfall_row("u:l-001:0", "newsys")]
    return [("pitfall", r["pitfall_id"], r) for r in rows]


def test_952_m4_run_pitfalls_hands_its_partition_to_on_curated_and_decides_only_the_unattributable_row(
    pitfalls_lane,
):
    """Deferred mode at the pitfalls curator (`run_pitfalls(..., batch=, items=)` over a batch draft): it commits and hands its
    committed/held partition to `on_curated`, deciding at once only the unattributable row (skipped, naming its system); the
    committed and held rows take their fates when the batch ends (design r8 Flows: items are kept until the batch ends)."""
    lane = pitfalls_lane
    head_before = lane.tip()
    spawn = Spawn(curate_agent_execution_md("elastic"), root=lane.root)
    captured: list = []
    outcomes: dict = {}

    with C.draft_trees(lane) as trees:
        assert pitfalls_curator.run_pitfalls(paths=lane.paths, invoke=spawn, on_curated=captured.append, trees=trees,
                                             batch=lane.batch, items=_three_way_items(), outcomes=outcomes) == 0

    sha = lane.tip()
    assert sha != head_before, "the commit is not deferred — only the consumption is"
    assert "agent/skills/elastic/execution.md" in lane.landed()
    assert [h.get("surface") for h in spawn.handoffs] == ["system", "reducer"], \
        "the reducer offer was never made, so the held arm is vacuous"
    assert captured == [pitfalls_curator.PitfallsDisposition(committed_ids=("c:l-000:0",), sha=sha, held_ids=("h:l-003:0",))]
    assert set(outcomes) == {("pitfall", "u:l-001:0")}, f"the claim's committed or held rows were decided early: {outcomes}"
    assert outcomes[("pitfall", "u:l-001:0")] == Outcome.skipped("undeclared-system:newsys")
