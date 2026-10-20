"""#1047 — the readers this piece does NOT move, observed at their own edges."""
from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

from defender.tests.support.learning.judge import _judge_921 as J


from defender.tests.support.shared.filesystem import _spec1047 as S


# the exit class's other reader


def test_a_cut_short_world_files_no_finding_and_its_reason_travels_on_its_row_unchanged(
        tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    judge = S.scripted_judge()
    record = S.graded_record(ep, judge=judge)
    row = S.rows(record)["b"]
    reason = row.get("ungradable_reason")
    assert reason, "the control failed: the cut-short row carries no reason to pass through"
    assert "request-limit" in reason, f"the cut-short reason does not name the exit: {reason!r}"

    assert S.judge_calls_for(judge, "b", episode_dir=ep) == [], "a cut-short world bought a world call"
    ledger = [e["finding_id"] for e in record.dispositions or []]
    assert not [f for f in ledger if f.split("/")[-3] == "b"], (
        f"the ledger names a finding of the cut-short world: {ledger}")
    assert [f for f in ledger if f.split("/")[-3] == "c"], (
        f"the control failed: the judged sibling's finding is not on the ledger: {ledger}")

    family = [p for p, a in zip(judge.prompts, judge.agent_ids, strict=True)
              if str(a).startswith(S.FAMILY_AGENT_PREFIX)]
    assert family, "the pass never made its family-scope call"
    assert reason in family[-1].split("## NOISE CONTEXT", 1)[-1], (
        "the family call's noise context does not carry the cut-short reason verbatim; the "
        "excluded world would reach it with no reason naming the exit")


# the gradable set this piece can empty for the first time


def _all_cut_short(tmp_path):
    """An episode whose every non-control world was cut short — the degenerate case fork F-J waived
    as a known, recorded gap (it computes `verdict_word` normally but degrades its alert key and
    family pattern to generic fallbacks)."""
    return S.cut_short_episode(tmp_path, cut={"b": "request-limit", "c": "aborted"})


def test_sibling_union_still_short_circuits_when_the_gradable_set_is_empty(tmp_path):
    family = S.mod("learning.judge.family")
    ep = _all_cut_short(tmp_path)
    graded = S.graded(ep)
    assert [label for label, row in graded.items() if family.is_gradable_row(row)] == [], (
        "an episode whose every non-control world was cut short still has a measuring world")


def test_pass_lessons_commit_still_returns_none_when_the_gradable_set_is_empty(tmp_path):
    """`_pass_lessons_commit` still returns `None` on an empty gradable set — probe #28's finding,
    pinned rather than left as a tolerance nothing tests."""
    judge = S.mod("learning.judge")
    ep = _all_cut_short(tmp_path)
    bound = S.mod("_io").bind(ep)  # #1049: the resolver takes the pass's bound, not the root
    assert judge._pass_lessons_commit(bound, []) is None
    assert judge._pass_lessons_commit(bound, [T.world_id(ep, label) for label in ("b", "c")]) is not None, (
        "the control failed: the commit resolver answered None for worlds that do carry a "
        "provenance stamp, so the empty-set answer above is not about the empty set")


# the run dir itself


def test_a_host_write_into_the_run_dir_still_goes_through_write_guarded_and_the_destination_screen(
        tmp_path):
    from defender.tests.support.runtime.engine import _spec923

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


# the report's other readers — deliberately unmoved


def test_the_episode_reader_and_the_graded_record_disagree_about_a_cut_short_world(tmp_path):
    episode_mod = S.mod("learning.branch.episode")
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
    row = S.graded(ep)["b"]
    said = J.through_view(ep, episode_mod.verdicts)
    assert row.get("ungradable") is True, "the cut-short world graded as a verdict"
    assert row.get("cut_short") == "request-limit"
    assert said.get("b") == "unresolved", (
        "the episode reader stopped reading a cut-short world's archived report as its "
        "conclusion — that is a repair this piece deliberately did not make")
