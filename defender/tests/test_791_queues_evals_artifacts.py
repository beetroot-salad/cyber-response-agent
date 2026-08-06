"""#791 part 4 — the queues the change makes production-facing, the evals that keep the
retired machinery alive, and everything left over that still SPELLS what this change retires:
the live stage the word also names, and the two artifacts outside the product that carry it.

Every test here is one demand of `spec-flow/specs/spec_graph_791-retire-offline-oracle.yaml`,
named by that demand's `discharged_by`. RED against HEAD is the expected state.

TWO INHERITED DEFECTS ARE FIXED IN SCOPE, and both are wider than "a wiring change":

* A marker orphaned in the claim directory by a crashed drain is never reclaimed — the drain
  enumerates the queue's own `*.json` and the claim directory is a SUBDIRECTORY, outside that
  glob by construction: no age-out, no reaper, no quarantine, and the operator's own count line
  reports zero queued while the marker sits there (P1). What earns the fix here is the CUTOVER:
  markers already on disk when the change ships can crash a drain mid-claim.
* The claim is a replace INTO that directory, which FREES the top-level slot — so a retry lands
  unobstructed and the next drain learns the same run a second time (P2, executed and refuted).
  Nothing between the human seam and the gate picked this up.

WHAT "THE EVALS STILL WORK" MEANS NOW: three of the four go dark. The prompt rewrite reaches
every caller that shares the two prompts (E5), so under any reading where they keep judging
they report numbers and measure nothing. They stop judging but keep RUNNING, and the skip
reason has to be loud — a passing eval whose result means nothing is a trap. Only the golden
replay keeps a positive, asserting witness: it binds the per-lead seam directly and never
touches the judge prompts.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

from defender.tests._by_path import load_lint_gate
from types import SimpleNamespace

import pytest
import yaml

from defender.learning.core import drains, run_cycle  # noqa: E402
from defender.learning.core import markers  # noqa: E402
from defender.tests._gate774 import (  # noqa: E402
    FakeReviewStages,
    StageFault,
    main_deps,
    spec_import,
    tail,
    worktree_package_guard,  # noqa: F401 — session-scoped autouse guard, see _gate774
)
from defender.tests._spec791 import (  # noqa: E402
    DEFENDER,
    LIVE_STAGE_WORD,
    OLDER_SPEC_GRAPH,
    PROJECT_PROFILE,
    RETIRED_DEAD_SYMBOLS,
    RETIRED_STAGE_WORD,
    RETIRED_TELEMETRY_WRITER,
    VULTURE_BASELINE,
    GroundedJudgeSubagents,
    SpecBranch,
    author_markers,
    learn_markers,
    loop_paths,
    make_run_dir,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
    satisfy_engine_keys,
)

ISSUE = "791"
SETTLED = [("the pivot was provisioned", "l-001", "the session was unauthorized")]


def _queued_run(tmp_path, name: str) -> Path:
    run_dir = tmp_path / "runs" / name
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    return run_dir


def test_791_a_marker_orphaned_by_a_crashed_drain_is_reclaimed(tmp_path, capsys):
    """orphaned_inflight_marker_is_reclaimed — a marker left in the claim directory by a drain
    that died mid-claim is picked up again by a later drain instead of sitting there forever.

    The orphan is invisible to the only instrument the operator has: the count line is computed
    from the top-level glob, so it reports zero queued while the marker exists. Driven exactly
    as the probe that refuted the reclaim was: one pass with nothing else queued, and one with
    real work on its way past — a drain that only reclaims when it happens to be busy is a
    different guarantee."""
    paths = loop_paths(tmp_path)
    orphan_run = _queued_run(tmp_path, "orphaned")
    inflight = paths.learn_queue_dir / "inflight"
    inflight.mkdir(parents=True)
    (inflight / "orphaned.json").write_text(
        json.dumps({"run_id": "orphaned", "run_dir": str(orphan_run.resolve())}) + "\n",
        encoding="utf-8",
    )

    learned: list[str] = []
    rc = run_cycle.learn_drain(
        paths, run_one_fn=lambda rd: learned.append(rd.name) or 0, render=lambda _rd: None,
    )
    assert rc == 0
    assert learned == ["orphaned"], \
        f"the orphaned claim was never reclaimed by an idle drain (saw {learned})"
    assert not (inflight / "orphaned.json").exists(), "the reclaimed marker was left in flight"

    second = _queued_run(tmp_path, "fresh")
    markers.enqueue_for_learning(second, paths)
    (inflight / "orphaned-2.json").write_text(
        json.dumps({"run_id": "orphaned-2", "run_dir": str(orphan_run.resolve())}) + "\n",
        encoding="utf-8",
    )
    learned.clear()
    capsys.readouterr()
    run_cycle.learn_drain(
        paths, run_one_fn=lambda rd: learned.append(rd.name) or 0, render=lambda _rd: None,
    )
    assert sorted(learned) == ["fresh", "orphaned"], \
        f"a busy drain walked past the orphan (saw {learned})"
    assert "0 run(s) queued" not in capsys.readouterr().err, \
        "the operator was told nothing was queued while a claimed marker existed"


def test_791_the_drain_tells_an_absent_queue_from_an_empty_one(tmp_path, capsys):
    """drain_distinguishes_absent_from_empty — the drain distinguishes a queue root that is not
    there from one that is there and empty, and says once that the automatic feed is gone.

    Cutting the feed converts a meaningful number into a permanent constant: the operator is
    told how much was queued and the answer is now always the same, because after this change
    the learn queue has NO writer at all — hand or automatic (H1 refuted, H1c). The count
    carries no information; only the absent/empty distinction does, and it is the only
    instrument the operator has left. The drain has no has-work probe — it globs the directory
    — so today the two produce the same output."""
    paths = loop_paths(tmp_path)
    assert not paths.learn_queue_dir.exists()
    run_cycle.learn_drain(paths, run_one_fn=lambda _rd: 0, render=lambda _rd: None)
    absent = capsys.readouterr().err

    paths.learn_queue_dir.mkdir(parents=True)
    run_cycle.learn_drain(paths, run_one_fn=lambda _rd: 0, render=lambda _rd: None)
    empty = capsys.readouterr().err

    assert absent != empty, \
        "an absent queue root and an empty one produce the same output; the operator cannot " \
        "tell a broken root from a queue that is empty by design"
    assert "no automatic" in empty.lower() or "no longer" in empty.lower(), \
        f"the drain never says the automatic feed is gone:\n{empty}"


def test_791_markers_queued_before_the_change_still_drain_after_it(tmp_path):
    """queues_survive_the_cutover — markers already on disk when the change ships still drain:
    the learn queue's backlog is still learned, and the curation lane still runs down the
    requests queued under the old trigger.

    Not academic. With no markers arriving the lead-author lane runs its pitfalls backlog once
    and then goes PERMANENTLY quiet — the silencing is total, not eventual (C9) — so the
    backlog on disk at the cutover is the last work either lane will see from the old world."""
    paths = loop_paths(tmp_path)
    pre_learn = _queued_run(tmp_path, "pre-cutover-learn")
    pre_author = _queued_run(tmp_path, "pre-cutover-author")
    markers.enqueue_for_learning(pre_learn, paths)
    markers.enqueue_for_authoring(pre_author, paths)

    learned: list[str] = []
    run_cycle.learn_drain(
        paths, run_one_fn=lambda rd: learned.append(rd.name) or 0, render=lambda _rd: None,
    )
    assert learned == ["pre-cutover-learn"], f"the pre-cutover backlog was dropped: {learned}"
    assert learn_markers(paths) == []

    served: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda _p, rd, *, box=None: served.append(rd),
        run_pitfalls=lambda *_a, **_kw: 0,
        branch=SpecBranch(tmp_path / "wt"),
        start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )
    assert served == [pre_author.resolve()], \
        f"a curation request queued before the change was never served: {served}"
    assert author_markers(paths) == []


def test_791_learn_queue_claim_is_idempotent_under_retry(tmp_path):
    """learn_queue_claim_is_idempotent_under_retry — a run claimed by a drain and then
    re-requested is learned exactly ONCE.

    The claim is a replace into the claim directory, which frees the top-level slot, so a retry
    arriving mid-claim lands unobstructed and the next drain learns the same run again (P2,
    executed and refuted). The count being right is exactly why this looked correct: one marker
    on the queue, two runs learned.

    The cutover backlog is why this is not retired by the queue losing its feed — markers on
    disk at the cutover are a real population."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "retried")
    markers.enqueue_for_learning(run_dir, paths)

    learned: list[str] = []

    def learn_and_retry(rd: Path) -> int:
        learned.append(rd.name)
        markers.enqueue_for_learning(rd, paths)  # the retry, arriving while the claim is held
        return 0

    run_cycle.learn_drain(paths, run_one_fn=learn_and_retry, render=lambda _rd: None)
    run_cycle.learn_drain(paths, run_one_fn=lambda rd: learned.append(rd.name) or 0,
                          render=lambda _rd: None)

    assert learned == ["retried"], \
        f"a claimed-then-retried run was learned {len(learned)} times: {learned}"


def test_791_the_golden_replay_still_drives_the_oracle_end_to_end(tmp_path, monkeypatch):
    """golden_replay_still_judges — the golden replay still drives the retired stage over a
    golden case and writes its projection, keyed by the audit tag.

    It is the ONE surviving entry point with a positive, asserting witness: it binds the
    per-lead seam directly and never touches the judge prompts, which is exactly why the prompt
    rewrite darkens its three siblings and not it.

    The replay hardcodes its stage function, so the stage seam is pinned as part of the
    contract here — without it there is no hermetic witness at all, and a survival demand with
    no witness discharges nothing."""
    from defender.evals.oracle_golden import replay

    monkeypatch.setenv("ORACLE_MODEL", "glm-5.2")
    monkeypatch.setenv("ORACLE_EFFORT", "medium")
    case = tmp_path / "golden-case"
    visible = case / "oracle_visible"
    (visible / "samples").mkdir(parents=True)
    (visible / "story.md").write_text("the actor's counter-story\n", encoding="utf-8")
    (visible / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-001", "goal": "check auth", "what_to_summarize": ["x"],
                    "queries": [{"query_id": "elastic.auth", "params": {"host": "h1"}}]}) + "\n",
        encoding="utf-8",
    )
    (visible / "samples" / "l-001.txt").write_text("### Raw Sample Events\n", encoding="utf-8")

    seen: list[str] = []

    def fake_oracle_fn(wiring, *, user, learning_run_dir, salt=None, **_kw):
        seen.append(wiring.label)
        return "events:\n  - {process: sshd, outcome: success}\n"

    rc = replay.main([str(case)], oracle_fn=fake_oracle_fn)
    assert rc == 0
    assert seen == ["oracle:l-001"], f"the replay drove {seen}, not the per-lead oracle seam"

    out = case / "projections" / "glm-5.2_effort-medium.yaml"
    assert out.is_file(), \
        f"the replay wrote no projection under its audit tag: " \
        f"{sorted(p.name for p in (case / 'projections').iterdir())}"
    assert "l-001" in out.read_text(encoding="utf-8")


def test_791_the_oracle_knobs_are_dead_for_learning_and_live_for_the_replay(tmp_path, monkeypatch):
    """retired_knobs_dead_for_learning_live_for_evals — the retired stage's tuning knobs are
    dead for the learning cycle and still live for the surviving measurement paths, and one of
    them is folded into that path's own output identity.

    The differential is the assertion: the SAME environment, two paths, one that never reads
    the knobs and one that does. A concurrency value that cannot be parsed proves the read did
    not happen — a knob that is merely unused would leave no trace either way, and "the leg
    completed" alone is consistent with the knob being read and ignored.

    The audit tag is where the effort knob becomes part of an output's identity. The consensus
    reading also had the prompt in that tag; the tag the code mints spells the model and the
    effort, and the prompt digest lives in the audit filenames beside it, so only what is
    actually keyed is asserted here."""
    from defender._env import FatalConfigError
    from defender.learning.pipeline.oracle.run import invoke_oracle

    satisfy_engine_keys(monkeypatch, "benign")
    monkeypatch.setenv("ORACLE_MAX_CONCURRENCY", "not-an-integer")
    monkeypatch.setenv("ORACLE_EFFORT", "spec791-effort")

    class _RealOracleLeg(GroundedJudgeSubagents):
        """The stage the retirement removes, driven for real below the model: if the leg still
        reaches it, the fan-out reads the concurrency knob and the garbage value says so."""

        def oracle(self, run_dir, actor_story_path, learning_run_dir):
            self.rec.record("oracle", run_dir=run_dir)
            return invoke_oracle(run_dir, actor_story_path, learning_run_dir,
                                 oracle_fn=lambda *_a, **_kw: "events: []\n")

    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, disposition="benign")
    rc = run_cycle.run_one(run_dir, paths=paths, agents=_RealOracleLeg(),
                           start_box=noop_start_box, stop_box=noop_stop_box)
    assert rc == 0, "the learning cycle still reads the retired stage's tuning knobs"

    with pytest.raises(FatalConfigError):
        invoke_oracle(run_dir, run_dir / "report.md", tmp_path / "lrd",
                      oracle_fn=lambda *_a, **_kw: "events: []\n")

    from defender.learning.core.config import oracle_effort

    assert oracle_effort() == "spec791-effort", \
        "the effort knob no longer reaches the surviving measurement path's output identity"


def test_791_every_new_dead_code_baseline_entry_names_this_issue(tmp_path):
    """dead_code_baseline_names_the_issue — every dead-code finding this change baselines
    carries a stated reason naming the issue that made it dead, and the gate REFUSES one that
    does not.

    The demand was written expecting the corpses to fall inside the retired package. They do
    not: `pipeline/oracle/` keeps every symbol live, because the secondary eval still projects
    (deliberately — its sibling demand says so in as many words) and the golden replay binds
    the per-lead seam. What this change actually orphans is the queue API the curation request
    replaced, and the A/B harness's verdict parser. Locating the demand by SYMBOL rather than
    by package is what makes it true of the shipped design; naming them is also stricter than
    the path scan, which any one entry anywhere under the package would have satisfied.

    The enforcement arm is the load-bearing one. "" meaning un-triaged was documented by the
    ratchet and enforced by nothing, so `--update-baseline` could bury any corpse silently —
    which is the shape that let the whole gate go blind for a month. A per-issue test cannot
    hold that; the gate has to, for every change, so it is asserted here against the gate."""
    baseline = json.loads(VULTURE_BASELINE.read_text(encoding="utf-8"))
    entries = baseline["entries"]

    for symbol in RETIRED_DEAD_SYMBOLS:
        ours = {fp: reason for fp, reason in entries.items() if f"'{symbol}'" in fp}
        assert ours, (
            f"{symbol!r} is not on the dead-code record — either it regained a caller (then "
            f"drop it from RETIRED_DEAD_SYMBOLS) or the baseline was never regenerated"
        )
        untriaged = sorted(fp for fp, reason in ours.items() if not reason.strip())
        assert untriaged == [], f"un-triaged dead-code entries: {untriaged}"
        unattributed = sorted(fp for fp, reason in ours.items() if ISSUE not in reason)
        assert unattributed == [], \
            f"dead-code entries with a reason that does not name #{ISSUE}: {unattributed}"

    # The gate itself refuses an un-triaged entry — otherwise every assertion above is one
    # `--update-baseline` away from being vacuous.
    ratchet = _load_lint_ratchet()
    finding = ratchet.Finding("f/x.py: unused function 'z'", "f/x.py:1: unused function 'z'")
    buried = tmp_path / "baseline.json"

    def _rc(reason: str) -> int:
        buried.write_text(
            json.dumps({"//": "h", "entries": {finding.fingerprint: reason}}), encoding="utf-8"
        )
        return ratchet.gate([finding], buried, [], label="l", header="h", require_reasons=True)

    assert _rc("") == 1, "the ratchet accepts a baseline entry nobody triaged"
    assert _rc("intentional: because") == 0, \
        "the ratchet rejects an entry that IS triaged, so the arm above proves nothing"


def _load_lint_ratchet():
    """`scripts/lint/` is a directory of standalone scripts, not an importable package — the
    gate is reached by path, the way CI reaches it."""
    return load_lint_gate("_baseline", name="_spec791_baseline")


def test_791_the_live_projection_stage_sheds_the_retired_stages_name(tmp_path):
    """live_projection_stage_sheds_the_retired_name — the review's surviving projection stage
    stops being spelled with the retired stage's name: the key it is dispatched under, the
    fault it reports, and the two trace files it writes into every run dir all name the LIVE
    stage, matching the role that shipped.

    The graph-side re-key justifies itself as "no name in the tree still joins by name to the
    offline oracle this change retires", and that sentence is false of the product. #791 is
    what makes the spelling wrong, because it is what removes the other thing the word could
    mean — after this change an operator opening a run dir finds `oracle` artifacts for a
    stage the spec says was retired, and the confusion is the same wrong join, relocated from
    a spec artifact into the run's own output.

    Every arm carries its positive control: the sibling stages keep their names and their
    traces, so none of these negatives is green because nothing was written. The stage fault
    is the review harness's own declared fault shape (a stage call that raises), not one
    invented here, and its message says nothing about any stage — so the only way a stage's
    name can reach the fault the run reports is the key the gate dispatched it under.

    Accepted cost, stated: this is the sixth widening, and it reaches the two shipped #774
    tests that assert the retired spelling in a trace filename."""
    pytest.importorskip("pydantic_ai")
    close_investigation = spec_import("defender.runtime.close_tool", "close_investigation")

    deps, run_dir = main_deps(tmp_path)
    close_investigation(deps, "malicious", stages=FakeReviewStages(challenger=[tail(SETTLED)]))
    traces = sorted(p.name for p in run_dir.glob("review_*_trace.jsonl"))
    assert len(traces) == 3, f"the review left {traces}, so this walk has nothing to check"
    assert [n for n in traces if LIVE_STAGE_WORD in n], \
        f"no trace names the live projection stage: {traces}"
    assert [n for n in traces if RETIRED_STAGE_WORD in n] == [], \
        f"the run dir still carries a trace named for the retired stage: {traces}"

    deps2, _run2 = main_deps(tmp_path / "faulting")
    broken = close_investigation(deps2, "malicious", stages=FakeReviewStages(
        challenger=[tail(SETTLED)],
        projection_fault=StageFault(raises=RuntimeError("stage transport failed")),
    ))
    assert LIVE_STAGE_WORD in (broken.detail or ""), \
        f"the projection stage's fault does not name it: {broken.detail!r}"
    assert RETIRED_STAGE_WORD not in (broken.detail or ""), \
        f"the fault still reports the live stage under the retired name: {broken.detail!r}"

    deps3, _run3 = main_deps(tmp_path / "control")
    challenger_fault = close_investigation(deps3, "malicious", stages=FakeReviewStages(
        challenger_fault=StageFault(raises=RuntimeError("stage transport failed")),
    ))
    assert "challenger" in (challenger_fault.detail or ""), (
        "control: a stage fault does not name the stage at all, so the assertion above is "
        "about an empty string"
    )

    from defender.runtime.review_roles import default_review_stages

    live_dir = tmp_path / "live-run"
    live_dir.mkdir(parents=True)
    stages = default_review_stages(live_dir, DEFENDER)
    with contextlib.suppress(BaseException):
        asyncio.run(stages.projection(SimpleNamespace(prompt="spec791", timeout=1.0)))
    live = sorted(p.name for p in live_dir.glob("review_*_live_trace.jsonl"))
    assert live, "the live projection stage opened no trace, so the name below is unobserved"
    assert [n for n in live if RETIRED_STAGE_WORD in n] == [], \
        f"the live stage still writes its trace under the retired stage's name: {live}"
    assert [n for n in live if LIVE_STAGE_WORD in n] == live


def test_791_the_project_profile_census_drops_the_retired_writer(tmp_path):
    """profile_census_drops_the_retired_writer — the project profile's shared-root census no
    longer names the projected-telemetry writer this change deletes.

    A stale census entry fails open BY CONSTRUCTION: a symbol that resolves to nothing reads
    exactly like a row nobody ever wrote, and this file is what seeds the NEXT change's
    grounding pass — the failure this run hit in its own first hour.

    Promoted from a clause. The downgrade rested on "it is an edit to a spec artifact rather
    than to the product", which two other tests in this suite refute by asserting on a
    committed lint baseline and on another test module's source. The assertion is one absent
    substring; it freezes no prose.

    The positive control is the rest of the census: the row this change deletes goes, the
    writers it does not touch stay, so a census emptied into green fails here."""
    profile = json.loads(PROJECT_PROFILE.read_text(encoding="utf-8"))
    resources = profile["specGraph"]["resources"]
    census = json.dumps(resources)

    assert RETIRED_TELEMETRY_WRITER not in census, (
        f"the profile's census still names {RETIRED_TELEMETRY_WRITER}, a writer this change "
        "deletes — the next grounding pass inherits a symbol that resolves to nothing"
    )
    survivors = [w for entry in resources.values() for w in entry.get("writers", [])]
    assert len(survivors) > 20, (
        f"the census carries only {len(survivors)} writers — it was emptied rather than "
        "corrected, and the absence above means nothing"
    )
    assert any("write_comparison_files" in w for w in survivors), (
        "the judge's own per-lead writer left the census with the retired one; this change "
        "does not touch it"
    )


def test_791_the_older_graph_stops_addressing_the_retired_id(tmp_path):
    """rekey_live_projection_graph_id — the older shipped spec-coverage graph names the live
    projection stage for what it is, so no demand address anywhere in the tree joins BY NAME to
    the offline stage this change retires.

    That graph models the live review stage under the retired stage's id. Until this change the
    collision was merely confusing; #791 is what makes it consequential, because it deletes the
    other referent — and a wrong join that RESOLVES is the worst kind, since every mechanical
    check that follows it reports success.

    Promoted from a clause, and asserted on ADDRESSES only — element ids and the addresses
    demands and gate entries bind. The graph's prose may go on discussing the offline oracle;
    it is the machine-joined half that must stop naming it."""
    graph = yaml.safe_load(OLDER_SPEC_GRAPH.read_text(encoding="utf-8"))
    structure = graph["structure"]
    ids = [e["id"] for kind in ("actors", "boundaries") for e in structure.get(kind, [])]
    assert ids, "the older graph declares no structure at all; re-site this demand"

    addresses = [a for d in graph["demands"] for a in d.get("binds", [])]
    addresses += [str(o.get("element", "")) for o in graph["gate"].get("obligations", [])]
    addresses += [str(h.get("element", "")) for h in graph["gate"].get("holes", [])]
    addresses += [str(p.get("element", "")) for p in graph["gate"].get("pre_discharged", [])]
    assert addresses, "the older graph binds no addresses; re-site this demand"

    assert RETIRED_STAGE_WORD not in ids, (
        f"the older graph still declares an element called {RETIRED_STAGE_WORD!r} — its "
        "review stage joins by name to the stage #791 retires"
    )
    joined = sorted({a for a in addresses if RETIRED_STAGE_WORD in a})
    assert joined == [], f"addresses in the older graph still join to the retired stage: {joined}"
    assert any(LIVE_STAGE_WORD in a for a in addresses) or LIVE_STAGE_WORD in ids, (
        "the re-key deleted the stage's addresses instead of re-spelling them — the demands "
        "that bound it now bind nothing"
    )
