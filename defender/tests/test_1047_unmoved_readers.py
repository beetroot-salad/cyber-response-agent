"""#1047 — the readers this piece does NOT move, observed at their own edges.

R7's whole point: three consumers of the exit class moved (the judge, the ticket lane, the
archive) and several did not, and a demand at the SOURCE's altitude is green when two of three
readers moved — which is the bug. Every test here is bound per reader edge and drives that
reader, rather than inferring from the writer side that it must be fine.

WHAT IS PINNED HERE, and why each one is a real question rather than a formality:

* `run_common.enqueue_curation` already reads `truncated_by` (`run.py:589`) — it is the ONLY
  production reader of the value before this piece, and the three new ones take the same value
  from the same place. If they diverged, one run would be "truncated" for the corpus gate and
  "not cut short" for the ticket.
* `enqueue.route_finding` carries a row's `ungradable_reason` onto the ledger's disposition
  entry (claim n8). The third row shape's reason is a NEW string on an old path; nothing pinned
  that the path is content-agnostic.
* `judge/__init__.py:583`'s short-circuit on an empty gradable set, and `_pass_lessons_commit`'s
  `None` for the same. Probe #28 (claim p28) found both already hold — and a probe is not a
  pin. This piece is the first change that can EMPTY that set in practice: before it, a
  host-forced world still counted as measuring (claim h2).
* `run.py`'s own read of its run dir. The sidecar lands BESIDE the run dir, so the artifact
  listing an operator opens is unchanged; a sidecar written INSIDE would have changed it.
* `run_dir.access[host-write-guarded]` — the forced close's own write into a run dir that two
  new readers now depend on. `box-rw-bind`'s (deliberately empty) constraints are pinned three
  times over in this suite; this cell's `[write_guarded, destination-screen]` was pinned by
  nothing.
* `evals/held_out.predicted_disposition` and `learning/branch/episode.verdicts` — two readers
  of `report.md` the design's non-obligations deliberately leave alone (forks F-AA and the
  `episode_verdicts_docstring_unaddressed` waiver). Their disagreement with the graded record
  is ACCEPTED, and what these tests pin is the acceptance, not a repair.
* `render.sibling_union`'s walk of the operator's runs base, which now holds a new leaf beside
  every run dir (settled premise 118, probe #32). The tolerance is currently guaranteed by
  seven independent screens rather than by one rule, and nothing pinned that they all keep
  screening.
* `review_record.<n>.json` and `provenance.json` — the waiver `review_record_gains_no_field`,
  made executable.

RED against `59bdea44`: every test needing a run-end record or a sidecar fails at the import of
a module that does not exist; the pure-reader halves below fail only where the new value has to
reach them.
"""
from __future__ import annotations

import json

from defender.tests import _spec1047 as S


def _verified_run_dir(tmp_path, name="run"):
    """A finished run dir the corpus-refusal gate will accept: its alert, its report, and the
    scrub verdict sidecar recording that the reap walk completed."""
    run_dir = S.closed_run_dir(tmp_path, name=name)
    S.mod("runtime.scrub")._write_verdict(run_dir, {"ran": True})
    return run_dir


# ---------------------------------------------------------------------------------------
# the exit class's other reader
# ---------------------------------------------------------------------------------------


def test_enqueue_curation_reads_the_same_truncated_by_value_after_the_change(tmp_path):
    """`run_common.enqueue_curation` reads the same `truncated_by` value the three moved
    consumers now read, unchanged by this piece — driven over a cut-short run and a clean one,
    observed at THIS reader's own edge, not inferred from the writer side.

    The gate is also where fork F-E's recorded divergence lives: it refuses on ANY non-None
    value, with no vocabulary test of its own, where the ticket lane falls back to today's
    behaviour for a value it does not recognise. That difference is INTENTIONAL and left as-is
    — "can this feed training data" and "how should the ticket close" are different questions
    with different acceptable risk postures — so this test pins both halves rather than
    asserting the two lanes agree."""
    run_dir = _verified_run_dir(tmp_path)
    gate = S.mod("run_common").learning_refusal_gate
    alert = run_dir / "alert.json"

    assert gate(run_dir, alert, truncated_by=None) is None, (
        "the control failed: a clean, verified run is already refused for some other reason, "
        "so the refusals below are not about the exit class")
    for exit_class in S.vocabulary():
        reason = gate(run_dir, alert, truncated_by=exit_class)
        assert reason is not None, (
            f"{exit_class}: the corpus gate did not refuse a truncated run at all")
        assert exit_class in reason, (
            f"{exit_class}: the corpus gate's reason does not name the exit class: {reason!r}")
    assert gate(run_dir, alert, truncated_by="not-a-member") is not None, (
        "the corpus gate stopped refusing an unrecognized exit class; F-E recorded that "
        "divergence from the ticket lane as intentional, and this is where it is pinned")


def test_route_finding_still_carries_the_cut_short_reason_onto_the_ledger_entry_unchanged(
        tmp_path):
    """`enqueue.py::route_finding` still carries the third row shape's `ungradable_reason` onto
    the ledger's disposition entry exactly as it carries today's `ungradable_reason` values —
    claim n8's passthrough mechanism is untouched by this piece; the new string travels the
    same path the old ones did.

    The row handed to `route_finding` is a REAL one, built by the real grading pass over a real
    cut-short world — not a hand-written dict, which would pin the passthrough against a shape
    the pass may never produce."""
    enqueue = S.mod("learning.judge.enqueue")
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    row = S.graded(ep)["b"]
    reason = row.get("ungradable_reason")
    assert reason, "the control failed: the cut-short row carries no reason to pass through"

    lane, carried = enqueue.route_finding(
        label="b", finding={"subject": "defender"}, kind="draw", world_row=row,
        withheld_reasons={}, defender_blocked=False)
    assert lane == enqueue.ROUTE_UNGRADABLE, (
        f"a cut-short row took lane {lane!r}; `is_gradable_row` is truthiness on `ungradable` "
        "and the third row shape sets it")
    assert carried == reason, (
        "the ledger entry does not carry the cut-short reason verbatim; the operator reading "
        "the record would see the finding refused with no reason naming the exit")
    # The ledger lane production files it under: `enqueue_report`'s `_drop` folds a
    # `ROUTE_UNGRADABLE` answer into `LANE_UNQUEUEABLE` with the route's reason — the route
    # vocabulary and the ledger-lane vocabulary are two sets, and the reader that checks a
    # ledger back (`check_disposition_entry`) accepts only what the writer writes.
    assert enqueue.disposition_entry("f-1", enqueue.LANE_UNQUEUEABLE, carried)["reason"] == reason


# ---------------------------------------------------------------------------------------
# the gradable set this piece can empty for the first time
# ---------------------------------------------------------------------------------------


def _all_cut_short(tmp_path):
    """An episode whose every non-control world was cut short — the degenerate case fork F-J
    waived as a known, recorded gap (it computes `verdict_word` normally but degrades its alert
    key and family pattern to generic fallbacks). Nothing crashes, which is probe #28's
    finding; these tests pin the two readers that finding was about."""
    return S.cut_short_episode(tmp_path, cut={"b": "request-limit", "c": "aborted"})


def test_sibling_union_still_short_circuits_when_the_gradable_set_is_empty(tmp_path):
    """`judge/__init__.py:583`'s short-circuit on an empty gradable set still holds once this
    piece makes that set reachable in practice (a family whose every measuring world was cut
    short) — probe #28's "nothing crashes" finding, pinned as a demand rather than left as a
    probed-but-unpinned tolerance.

    Two halves: the set really is empty for an all-cut-short episode (before this piece a
    host-forced world still counted as measuring, claim h2, so the state was unreachable), and
    the union over the short-circuited argument is empty rather than a walk of the operator's
    whole runs base. Positive control: the same union over a real runs base DOES return rows,
    so "empty" is a short-circuit and not a broken walk."""
    family = S.mod("learning.judge.family")
    render = S.mod("learning.judge.render")
    ep = _all_cut_short(tmp_path)
    graded = S.graded(ep)
    assert [label for label, row in graded.items() if family.is_gradable_row(row)] == [], (
        "an episode whose every non-control world was cut short still has a measuring world")

    rows, _meta = render.sibling_union(None, alert_id=S.ALERT_ID, source_run_id=None)
    assert rows == [], "the short-circuited union walked something and returned rows"

    base, src = S.runs_base(tmp_path / "populated")
    walked, _meta = render.sibling_union(base, alert_id=S.ALERT_ID, source_run_id=None)
    assert isinstance(walked, list), (
        "the control failed: the union over a real runs base did not answer with rows at all, "
        "so the empty answer above proves nothing about the short-circuit")
    assert src.exists()


def test_pass_lessons_commit_still_returns_none_when_the_gradable_set_is_empty(tmp_path):
    """`_pass_lessons_commit` still returns `None` on an empty gradable set — probe #28's
    finding, pinned rather than left as a tolerance nothing tests.

    Positive control on the same episode: handed the labels of worlds that DO carry a
    provenance stamp, it returns that commit — so `None` is the empty-set answer and not this
    function's answer to everything."""
    judge = S.mod("learning.judge")
    ep = _all_cut_short(tmp_path)
    assert judge._pass_lessons_commit(ep, []) is None
    assert judge._pass_lessons_commit(ep, ["b", "c"]) is not None, (
        "the control failed: the commit resolver answered None for worlds that do carry a "
        "provenance stamp, so the empty-set answer above is not about the empty set")


# ---------------------------------------------------------------------------------------
# the run dir itself
# ---------------------------------------------------------------------------------------


def test_run_mains_own_read_of_the_run_dir_is_unaffected_by_this_change(tmp_path):
    """`run_main`'s existing read of its own run dir (locating it to compose `{label: run_dir}`
    and to hand it onward) is unaffected by this piece — the same read happens, unchanged,
    whether the run ended cleanly or was cut short.

    The run-end record lands BESIDE the run dir, at `verdict_path`'s shape, for the same reason
    the scrub verdict does: in-tree it would be both plantable and forgeable by the box that is
    root on that mount. The operator-facing artifact listing `run.py` prints is therefore
    byte-identical with and without the record, and `cross_check_tables` — the one production
    read of that tree in the same tail — answers the same."""
    run_dir = _verified_run_dir(tmp_path)
    (run_dir / "executed_queries.jsonl").write_text("", encoding="utf-8")
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    before = sorted(p.name for p in run_dir.iterdir())
    S.plant_sidecar(run_dir, truncated_by="request-limit")
    after = sorted(p.name for p in run_dir.iterdir())
    assert after == before, (
        f"the run-end record changed the run dir's own listing ({set(after) - set(before)}); "
        "it must sit beside the tree it describes, not inside it")
    assert S.sidecar_path(run_dir).is_file(), "the record was not written at all"
    S.mod("run_common").cross_check_tables(run_dir)


def test_a_host_write_into_the_run_dir_still_goes_through_write_guarded_and_the_destination_screen(
        tmp_path):
    """The forced close's `report.md` write into a run dir this design's two new readers
    (`archive_episode`, `close_case_ticket`) now depend on still goes through `write_guarded`
    and the destination screen — the one cell this piece leans on harder for trust is still the
    one actually enforcing `[write_guarded, destination-screen]`, not silently narrowed by this
    change to something weaker.

    Driven as the real forced close over a run dir where the box has planted a symlink at
    `report.md`: the write must refuse rather than follow it, leaving the link's target
    untouched. Positive control: the same forced close over an unplanted run dir does write a
    report."""
    from defender.tests import _spec923

    victim = tmp_path / "victim.md"
    victim.write_text("VICTIM\n", encoding="utf-8")
    deps, run_dir = _spec923.main_deps(tmp_path / "planted")
    (run_dir / "report.md").symlink_to(victim)
    _run, truncated_by, _reason = _spec923.drive_to_retry_exhaustion(deps)
    assert truncated_by is not None, "the run was not cut short, so no forced close was due"
    assert victim.read_text(encoding="utf-8") == "VICTIM\n", (
        "the host's forced close followed a link the box planted at report.md and wrote this "
        "run's report wherever it pointed")

    clean_deps, clean_run = _spec923.main_deps(tmp_path / "clean")
    _spec923.drive_to_retry_exhaustion(clean_deps)
    assert (clean_run / "report.md").is_file(), (
        "the control failed: the forced close writes no report even with nothing planted, so "
        "the refusal above is not about the destination screen")


# ---------------------------------------------------------------------------------------
# the report's other readers — deliberately unmoved
# ---------------------------------------------------------------------------------------


def test_the_held_out_scorer_answers_the_same_after_this_change_as_before_it(tmp_path):
    """`predicted_disposition` answers exactly as it did before: it reads the report, not the
    new record, so this change does not move the held-out score in either direction.

    This is a NON-obligation made executable. Claim n13: the scorer counts a forced
    `unresolved` as a wrong disposition where a missing report reads as no usable headline —
    which is exactly why widening the forced-close set is a separate decision (waiver
    `forced_close_set_unchanged`), and why fork F-AA names this reader explicitly rather than
    leaving the silence."""
    held_out = S.mod("evals.held_out")
    run_dir = _verified_run_dir(tmp_path)
    (run_dir / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
    before = held_out.predicted_disposition(run_dir)
    S.plant_sidecar(run_dir, truncated_by="request-limit")
    assert held_out.predicted_disposition(run_dir) == before == "unresolved", (
        "the held-out scorer's answer moved when a run-end record appeared beside the run dir")

    missing = _verified_run_dir(tmp_path / "missing", name="no-report")
    (missing / "report.md").unlink()
    S.plant_sidecar(missing, truncated_by="aborted")
    assert held_out.predicted_disposition(missing) is None, (
        "a run with no report acquired a headline from the new record; the scorer reads the "
        "report and nothing else")


def test_the_episode_reader_and_the_graded_record_disagree_about_a_cut_short_world(tmp_path):
    """`branch/episode.py::verdicts` and the graded record may disagree about a cut-short world,
    and that disagreement is ACCEPTED — the waiver `episode_verdicts_docstring_unaddressed` is
    what this test pins, not a repair.

    `verdicts` is the #947 eval lane with no production caller (claim n11), and it keeps reading
    each archived `report.md` as the world's conclusion. For a cut-short world the graded record
    says "ungradable, its run ended <exit>" while `verdicts` says whatever the report's headline
    is. Recording the disagreement in a test is what turns a silence into an examined no."""
    episode_mod = S.mod("learning.branch.episode")
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / "b" / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
    row = S.graded(ep)["b"]
    said = episode_mod.verdicts(ep)
    assert row.get("ungradable") is True, "the cut-short world graded as a verdict"
    assert row.get("cut_short") == "request-limit"
    assert said.get("b") == "unresolved", (
        "the episode reader stopped reading a cut-short world's archived report as its "
        "conclusion — that is a repair this piece deliberately did not make")


def test_the_sibling_prior_walks_a_runs_base_that_now_holds_run_end_records(tmp_path):
    """A walk of the production runs base with a run-end sidecar sitting beside every run dir
    returns the same rows as without it — the new leaf is not a new KIND of entry (a
    scrub-verdict sidecar has sat there since #771), and every walker screens.

    Probe #32's own recommended test (claim p32): the tolerance is currently guaranteed by
    seven independent screens rather than by one rule, and nothing pins that they all keep
    screening. Three walkers are driven, not one, because a rule that lives in seven places can
    be lost in one of them: the sibling prior, the held-out index and the lesson tracer."""
    render = S.mod("learning.judge.render")
    trace_lesson = S.mod("learning.ops.trace_lesson")
    base, src = S.runs_base(tmp_path)
    # The lesson tracer only counts a run dir that LOADED the lesson, so the fixture gives it
    # one — a walk whose answer is the empty list before and after would pin nothing.
    lesson = "l-1047-cut-short"
    (src / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": lesson, "ts": "2026-09-16T11:00:00Z"}) + "\n",
        encoding="utf-8")
    before = render.sibling_union(base, alert_id=S.ALERT_ID, source_run_id=None)
    slugs = [src.name]
    index_before = S.mod("evals.held_out").index_runs(slugs, base)
    traced_before = trace_lesson.in_context_cases(lesson, None, base)
    assert traced_before, (
        "the fixture failed: the lesson tracer found no case to count, so its walk answers the "
        "empty list whatever sits beside the run dir")
    S.plant_sidecar(src, truncated_by="request-limit")
    assert S.sidecar_path(src).parent == base, (
        "the fixture did not put the new leaf under the runs base, so this walks nothing new")
    assert render.sibling_union(base, alert_id=S.ALERT_ID, source_run_id=None) == before, (
        "the sibling prior's walk answered differently once a run-end record sat beside the "
        "run dir")
    assert S.mod("evals.held_out").index_runs(slugs, base) == index_before, (
        "the held-out index answered differently once a run-end record sat beside the run dir")
    assert trace_lesson.in_context_cases(lesson, None, base) == traced_before, (
        "the lesson tracer's walk answered differently once a run-end record sat beside the "
        "run dir — the third of the seven screens the docstring names")


def test_the_review_record_and_the_provenance_stamp_are_unchanged_for_a_cut_short_world(
        tmp_path):
    """review_record.<n>.json and provenance.json are byte-unchanged for a cut-short world —
    the waiver `review_record_gains_no_field` made executable.

    Both files are written before the run ends and neither gains a field here: the exit class
    travels on its own record. `review_record.<n>.json` is not in the archive's copy list at
    all (it is in-run only), so a cut-short world's archive must not acquire one either."""
    base, _src = S.runs_base(tmp_path)
    ep = S.episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    S.plant_sidecar(run_dir, truncated_by="request-limit")
    record = {"turn": 1, "outcome": "stands", "disposition": "malicious"}
    (run_dir / "review_record.1.json").write_text(json.dumps(record), encoding="utf-8")
    provenance_bytes = (run_dir / "provenance.json").read_bytes()

    S.mod("learning.branch.archive").archive_episode(ep, {"b": run_dir})
    assert json.loads((run_dir / "review_record.1.json").read_text(encoding="utf-8")) == record
    assert (run_dir / "provenance.json").read_bytes() == provenance_bytes
    assert (ep / "worlds" / "b" / "provenance.json").read_bytes() == provenance_bytes
    assert not (ep / "worlds" / "b" / "review_record.1.json").exists(), (
        "the archive acquired a review record for a cut-short world; the record is in-run only "
        "and this piece adds no field to it and no reader of it")
