"""#921 — the judge's input: the four joined views, the withholding, and what the archive owes it.

THIS IS THE HALF THE EXPERIMENT SETTLED, and the amendment left it untouched. 45 K3 replies
graded by Fable 5.1 at xhigh against a frozen reference: a judge fed the manifest and the two
documents scored 0.2-0.3/3 recall and invented 2.0-2.8 false findings per reply, restating the
run's own close; fed the joined views plus the correlating prompt it scored 2.8 / 2.3 / 0.9 on
the three fixtures with false findings at or below 0.2 (C9). The cadence break went 0/5 -> 5/5
once the prompt demanded a derivation pass (C10). Without the counterfactual marking, 5/5
replies cited sibling worlds' injected facts as facts about world A and 2/5 declared a corpus
contradiction that does not exist (C11). Every assertion below is one of those measured edges.

THREE §7 RESOLUTIONS ARE APPLIED HERE AS SETTLED:
* **J8** — the sibling's recorded commit is resolved to a SHA once per pass and threaded; an
  absent commit or path renders as an explicit `unavailable: <reason>` line rather than failing
  the world; an `allow_dirty` family is surfaced as a caveat.
* **J9** — the union is the OPERATOR's runs base, the source run the episode branched from is
  EXCLUDED and said to be, only runs that reached a close are included, an unreadable sibling is
  skipped with a counted note, and the union is computed once per pass.
* **J14** — the withholding's scope is stated across ALL FOUR views, not the overlay alone.

RED against `d1b8b06a`: `learning/judge/render.py` does not exist, no reader anywhere indexes
the runs base by `alert_id`, and `archive.py` copies none of D7's three inputs.
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _judge_921 as J


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _render():
    return J.mod("learning.judge.render")


def _prompts(tmp_path, ep, **kw):
    """Drive the real episode-grading pass and hand back what the model seam was SHOWN.

    Every payload assertion in this file reads `judge.prompts`, never the canned reply: a fake
    that only returns answers leaves the whole outbound channel unpinned, and the outbound
    channel is what O4/O5/O9 are about.
    """
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    J.mod("learning.judge").grade_episode(
        ep, judge=judge, runs_base=tmp_path / "defender-runs", **kw)
    return judge


# ---------------------------------------------------------------------------------------
# O4 / D4 / M1 — the joined views and the correlating prompt
# ---------------------------------------------------------------------------------------


def test_921_judge_input_carries_per_lead_chain_coverage_siblings_lessons_spread(tmp_path):
    """The rendered input carries, PER LEAD, goal -> params -> payload -> summary -> document
    rows -> resolutions, plus coverage against the discriminator, the sibling trials of the same
    alert, the lessons loaded, and the trial spread.

    A judge input built from the two documents alone is O4's stated failing mode and is exactly
    what scored 0.2-0.3/3 while inventing 2.0-2.8 false findings per reply (C9). All four views
    are asserted as present, because the measured collapse was of the whole set.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    judge_input = _render().render(ep, "b", runs_base=base)

    chain = judge_input.leads["l-001"]
    for link in ("goal", "params", "payload", "summary", "document_rows", "resolutions"):
        assert link in chain, f"the per-lead chain is missing its {link} link"
    assert judge_input.coverage, "the coverage view is empty"
    assert judge_input.siblings is not None, "the sibling-trials view is absent, not empty"
    assert judge_input.lessons, "the lessons-loaded view is empty"
    assert judge_input.spread is not None, "the trial spread is absent"


def test_921_coverage_rows_carry_window_and_scope_key_against_the_discriminator(tmp_path):
    """Every coverage row names its window and its scope key, against the family's
    discriminator.

    Those two columns are what M1 adds to the ported view, and they are what makes
    `scope_discriminated` legible to a reader of the reply rather than a number it has to trust.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    judge_input = _render().render(ep, "b", runs_base=base)

    assert judge_input.coverage, "no coverage rows to check"
    for row in judge_input.coverage:
        assert "window" in row, f"coverage row without a window: {row}"
        assert "scope_key" in row, f"coverage row without a scope key: {row}"
    assert judge_input.discriminator["holding_system"] == J.HOLDING_SYSTEM


def test_921_sibling_union_is_the_runs_base_trials_sharing_the_alert_id(tmp_path):
    """The sibling union is the runs sharing the alert's `alert_id`.

    No reader at base indexes the runs base by `alert_id` — the queue's grouping key is
    `alert_rule_key`, a different key — so this is a NEW walk that opens each candidate run's
    `alert.json`, a file that is model-writable by construction. Driven with two runs under one
    alert id and one under another, so the union is a selection rather than "everything found".
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    for name, alert in (("trial-1", J.ALERT_ID), ("trial-2", J.ALERT_ID),
                        ("other", "unrelated-rule")):
        run = base / name
        run.mkdir(parents=True, exist_ok=True)
        (run / "alert.json").write_text(json.dumps({"alert_id": alert}), encoding="utf-8")
        (run / "report.md").write_text("disposition: benign\n", encoding="utf-8")

    union = {row["run_id"] for row in _render().render(ep, "b", runs_base=base).siblings}
    assert {"trial-1", "trial-2"} <= union
    assert "other" not in union, "a run under a different alert id entered the union"


def test_921_reply_without_the_three_pass_tables_is_refused(tmp_path):
    """The prompt demands the correlation, scope and derivation passes before findings, and a
    reply without the three pass tables is refused.

    This is the half the experiment measured directly: the cadence break, never noticed in ten
    replies, went 0/5 -> 5/5 once a derivation pass was demanded (C10). The demand has both
    halves — the prompt ASKS for the three passes, and a reply that omits them does not stand.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    judge = _prompts(tmp_path, ep)
    prompt = judge.prompts[0]
    for pass_name in ("correlation", "scope", "derivation"):
        assert pass_name in prompt.lower(), f"the prompt never asks for the {pass_name} pass"

    run_mod = J.mod("learning.judge.run")
    with pytest.raises(J.refusals()):
        run_mod.validate_reply(J.as_reply_text(J.reply_doc(passes=False)))
    # Positive control: the same reply WITH the three tables validates.
    assert run_mod.validate_reply(J.as_reply_text(J.reply_doc())).episode_outcome == "gradable"


def test_921_prompt_names_the_graded_world_and_keeps_the_cap_and_quoting_rule(tmp_path):
    """The prompt is the correlating prompt parameterised by the GRADED WORLD's label ("world X
    has run; grade it"), keeping the 20-row cap and the quote-any-colon rule that made 15/15
    replies parse strictly (C12). Its wording names hand-offs, never entities or systems.

    The parameterisation is what makes one call about one trajectory: the experiment's own text
    said "world A", and that sentence becomes "world X has run; grade it".
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")],
                                               "c": [J.staged_row("c")]})
    judge = _prompts(tmp_path, ep, draws=1)
    by_world = dict(zip([aid.split(":")[1] for aid in judge.agent_ids], judge.prompts,
                        strict=True))

    assert set(by_world) == {"b", "c"}
    for label, prompt in by_world.items():
        assert f"world {label}" in prompt
        other = "c" if label == "b" else "b"
        assert f"world {other} has run" not in prompt
        assert "20" in prompt, "the 20-row cap left the prompt"
        assert "colon" in prompt.lower(), (
            "the quote-any-colon rule left the prompt; it is what made 15/15 replies parse")


# ---------------------------------------------------------------------------------------
# O5 / N10 — counterfactual siblings, empty unions
# ---------------------------------------------------------------------------------------


def test_921_no_sibling_overlay_reaches_the_prompt(tmp_path):
    """Every world but the graded one is marked `counterfactual: true` in the RENDERED manifest
    and its overlay is WITHHELD: no sibling's injected facts reach the prompt.

    `counterfactual` is render-layer only — `_WORLD_FIELDS` is closed and `parse_world` refuses
    unknown fields (run1/G17), so it can never be a manifest field. Measured failing mode: 5/5
    replies cited sibling facts as facts about world A and 2/5 declared a corpus contradiction
    that does not exist (C11).

    J14, settled: the withholding's scope is stated across ALL FOUR views, not the overlay
    alone. A negative that bound only the manifest would leave the coverage rows, the lessons
    view and the trial spread ungoverned, and those three carry sibling-derived content too —
    which is the surface a leak actually ships through. The marker string is planted inside
    the sibling's own overlay AND inside each of the other three views' sibling-derived slots,
    and none of them may appear anywhere in the prompt.
    """
    secret = "SIBLING-ONLY-INJECTED-FACT"
    worlds = [
        J.world_doc("a", role="A", axis=None, disposition_declared="benign", ov={}),
        J.world_doc("b", disposition_declared="malicious",
                    ov=J.overlay(elastic=J.elastic_overlay(inject=[{"_id": "i-b"}]))),
        J.world_doc("c", disposition_declared="malicious",
                    ov=J.overlay(patches={"identity": {"web-1": {"owner": secret}}})),
    ]
    ep = J.accepted_episode(tmp_path, worlds=worlds,
                            ledgers={"b": [J.staged_row("b")], "c": [J.staged_row("c")]})
    # The other three views' sibling-derived slots carry the same marker.
    (ep / "worlds" / "c" / "gather_summaries" / "l-001.md").write_text(
        f"world c saw {secret}\n", encoding="utf-8")
    (ep / "worlds" / "c" / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": secret, "loaded_at": "2026-07-28T17:00:00Z",
                    "path": "defender/lessons/L1.md"}) + "\n", encoding="utf-8")

    judge = _prompts(tmp_path, ep, draws=1)
    graded_b = judge.prompts[judge.agent_ids.index("judge:b:0")]
    assert secret not in graded_b, (
        "a sibling world's content reached the prompt of a different world")
    assert "counterfactual" in graded_b, "no world is marked counterfactual at all"
    assert graded_b.count("counterfactual") >= 2, (
        "only one of the two non-graded worlds was marked")


def test_921_graded_world_keeps_its_own_overlay_and_is_not_marked_counterfactual(tmp_path):
    """The paired positive control: the graded world keeps its OWN overlay and is not marked
    counterfactual, so the withholding demand cannot pass on a render that withholds
    everything.

    Without it, `assert secret not in prompt` is also green on an empty prompt — which is the
    shape a bare negative fails in.
    """
    mine = "GRADED-WORLD-OWN-INJECTED-FACT"
    worlds = [
        J.world_doc("a", role="A", axis=None, disposition_declared="benign", ov={}),
        J.world_doc("b", disposition_declared="malicious",
                    ov=J.overlay(patches={"identity": {"web-1": {"owner": mine}}})),
    ]
    ep = J.accepted_episode(tmp_path, worlds=worlds, labels=("a", "b"),
                            dispositions={"a": "benign", "b": "malicious"},
                            ledgers={"b": [J.staged_row("b")]})
    judge = _prompts(tmp_path, ep, draws=1)
    prompt = judge.prompts[judge.agent_ids.index("judge:b:0")]

    assert mine in prompt, "the graded world's own overlay was withheld from its own grading"
    graded_block = prompt[prompt.index("world b"):prompt.index("world b") + 400]
    assert "counterfactual" not in graded_block, "the graded world was marked counterfactual"


def test_921_first_run_alert_coverage_view_states_the_empty_union(tmp_path):
    """A first-run alert has an empty sibling union and an empty spread, and the coverage view
    SAYS SO explicitly.

    Nothing is inferred from the absence — an unstated absence is what a model fills in, and
    C11 measured what a model fills a gap with. Driven against a runs base holding no run under
    this alert id at all.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    empty_base = tmp_path / "empty-runs"
    empty_base.mkdir(parents=True, exist_ok=True)
    judge_input = _render().render(ep, "b", runs_base=empty_base)

    assert judge_input.siblings == []
    assert judge_input.spread == []
    rendered = judge_input.as_prompt_sections()["coverage"]
    assert "no sibling" in rendered.lower() or "first run" in rendered.lower(), (
        "the coverage view is silent about an empty union; silence is what a model fills in")


def test_921_the_sibling_union_excludes_the_source_run_and_unclosed_siblings(tmp_path):
    """J9, settled with the human: the union is the OPERATOR's runs base; the SOURCE RUN the
    episode branched from is EXCLUDED and the coverage view says so; only runs that reached a
    close are included; an unreadable sibling is skipped with a COUNTED note; and the union is
    computed ONCE per pass and threaded to every world's render.

    This is why J9 is not hygiene. If the union were the runs base AND included the source run,
    the judge would be shown the run's own close as a "sibling trial" — precisely the `current`
    arm's measured failure (C9: 2.0-2.8 false findings per reply, restating the run's own
    close), so the default answer would partly undo the experiment this whole design rests on.

    The episode's own `{episode_dir}/runs/` are the graded trajectories themselves, not
    independent trials, and are not the root scanned.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")],
                                               "c": [J.staged_row("c")]})
    base, src = J.runs_base(tmp_path)
    (src / "alert.json").write_text(json.dumps({"alert_id": J.ALERT_ID}), encoding="utf-8")

    closed = base / "closed-trial"
    closed.mkdir(parents=True, exist_ok=True)
    (closed / "alert.json").write_text(json.dumps({"alert_id": J.ALERT_ID}), encoding="utf-8")
    (closed / "report.md").write_text("disposition: benign\n", encoding="utf-8")

    in_flight = base / "in-flight-trial"
    in_flight.mkdir(parents=True, exist_ok=True)
    (in_flight / "alert.json").write_text(json.dumps({"alert_id": J.ALERT_ID}), encoding="utf-8")

    unreadable = base / "unreadable-trial"
    unreadable.mkdir(parents=True, exist_ok=True)
    (unreadable / "alert.json").write_bytes(b"\xff\xfe not json")

    # The episode's own sibling runs live here, deliberately outside the operator's base.
    (ep / "runs").mkdir(parents=True, exist_ok=True)
    own = ep / "runs" / f"{J.EPISODE_ID}-b"
    own.mkdir(parents=True, exist_ok=True)
    (own / "alert.json").write_text(json.dumps({"alert_id": J.ALERT_ID}), encoding="utf-8")
    (own / "report.md").write_text("disposition: benign\n", encoding="utf-8")

    view = _render().render(ep, "b", runs_base=base)
    union = {row["run_id"] for row in view.siblings}
    assert union == {"closed-trial"}, f"the union is {sorted(union)}"
    assert view.union_notes["source_run_excluded"] == src.name, (
        "the source run was excluded silently; the coverage view has to say so")
    assert view.union_notes["skipped_unreadable"] == 1
    assert view.union_notes["skipped_unclosed"] == 1

    # Computed once per pass and threaded: both worlds see the identical union object's rows.
    other = _render().render(ep, "c", runs_base=base)
    judge = _prompts(tmp_path, ep, draws=1)
    assert other.siblings == view.siblings
    assert judge.prompts[0].count("closed-trial") >= 1


# ---------------------------------------------------------------------------------------
# O8 / D7 — reproducible from the archive, the runs base and the checkout
# ---------------------------------------------------------------------------------------


def test_921_render_reads_no_sibling_run_dir(tmp_path):
    """The render builds its input with every sibling run dir under `{episode_dir}/runs/`
    DELETED — #947's D3 says they may be gone.

    That is what D7's three archived inputs buy, and DELETING THE RUN DIRS IS THE DRIVE, not a
    mock: a render that still reached for one would fail on a path that is not there, rather
    than pass against a stub that answers.
    """
    import shutil

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    runs = ep / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / f"{J.EPISODE_ID}-b").mkdir(parents=True, exist_ok=True)
    shutil.rmtree(runs)

    view = _render().render(ep, "b", runs_base=base)
    assert view.leads, "the per-lead chain was empty once the run dir was gone"
    assert view.lessons, "the lessons view needed the sibling's run dir"


def test_921_render_builds_the_input_from_the_archive_the_runs_base_and_the_commit(tmp_path):
    """The paired positive control: with the run dirs PRESENT or ABSENT the render produces the
    same input, built from the archived world dir, the runs base and the checkout at the
    sibling's recorded commit.

    Without it, "the render reads no sibling run dir" is also satisfied by a render that reads
    nothing at all.
    """
    import shutil

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    runs = ep / "runs"
    J.sibling_run_dir(runs, "b")
    git_show = J.FakeGitShow(bodies={("deadbee", "defender/lessons/L1.md"): "# L1 body\n"})

    with_dirs = _render().render(ep, "b", runs_base=base, git_show=git_show)
    shutil.rmtree(runs)
    without = _render().render(ep, "b", runs_base=base, git_show=git_show)

    assert with_dirs.as_prompt_sections() == without.as_prompt_sections(), (
        "the rendered input changed when the sibling run dirs were removed")
    assert "# L1 body" in without.as_prompt_sections()["lessons"]


def test_921_archive_writes_gather_summaries_lessons_loaded_and_alert_json(tmp_path):
    """Each archived world gains `gather_summaries/`, `lessons_loaded.jsonl` and `alert.json`
    beside the four single files and two screened tables it already carries (C17).

    `_single_files` has TWO readers — the screen and the copy — so a name in one and not the
    other is an artifact that is checked and not copied (run1/G28); both halves are exercised by
    driving the real `archive_episode` over a real sibling run dir and reading the archive back.
    """
    archive = J.mod("learning.branch.archive")
    ep = J.episode(tmp_path)
    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    (run_dir / "gather_summaries").mkdir(parents=True, exist_ok=True)
    (run_dir / "gather_summaries" / "l-001.md").write_text("summary\n", encoding="utf-8")
    (run_dir / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L1"}) + "\n", encoding="utf-8")
    (run_dir / "alert.json").write_text(json.dumps({"alert_id": J.ALERT_ID}), encoding="utf-8")

    archived = archive.archive_episode(ep, {"b": run_dir})
    world = archived["b"]
    assert (world / "gather_summaries" / "l-001.md").is_file()
    assert (world / "lessons_loaded.jsonl").is_file()
    assert (world / "alert.json").is_file()
    # The four it already carried are untouched.
    for name in ("report.md", "investigation.md", "provenance.json", "executed_queries.jsonl"):
        assert (world / name).exists(), f"{name} stopped being archived"


def test_921_the_archived_directory_input_refuses_a_non_artifact_entry_and_keeps_the_rest(
        tmp_path):
    """`gather_summaries/` is a directory of model-written `{lead_id}.md` files and takes the
    per-entry-screened `stage_tables` walk, not a blind `copytree` and not `_screen` + `copy2`:
    a non-artifact entry at any depth is REFUSED AND REPORTED, and the rest of the world still
    archives.

    P10, executed: the screen IS all-or-nothing and `stage_tables` IS per-entry-screened — but
    the single-file `copy2` loop has NO rollback, so a genuine mid-copy I/O fault still leaves a
    half-populated `worlds/<label>/`. The archive's docstring guarantee ("archives NOTHING
    rather than a half-world") covers only screen-detected refusals, which is why J5's tier rule
    has to cover a partially archived world rather than relying on M7 to prevent one.

    The fault is real input through the real primitive: a symlink is planted inside the
    directory, pointing outside the tree.

    BOTH HALVES ARE DRIVEN, and the second is F-7, settled at the phase-F seam. The screen path
    keeps the world whole (first half). The path the screen does NOT cover leaves the world
    short, and that state is now MALFORMED: the judge pass refuses it, naming the input that was
    short, rather than grading it normally on a thinner view. This test used to cite the
    half-populated world in its docstring and drive only the screen — the one path P10 says IS
    all-or-nothing — so the state the citation is about reached no assertion at all.
    """
    archive = J.mod("learning.branch.archive")
    ep = J.episode(tmp_path)
    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    summaries = run_dir / "gather_summaries"
    summaries.mkdir(parents=True, exist_ok=True)
    (summaries / "l-001.md").write_text("a real summary\n", encoding="utf-8")
    outside = tmp_path / "outside-the-tree.md"
    outside.write_text("bytes no world wrote\n", encoding="utf-8")
    (summaries / "l-002.md").symlink_to(outside)

    archived = archive.archive_episode(ep, {"b": run_dir})
    world = archived["b"]
    kept = world / "gather_summaries" / "l-001.md"
    assert kept.is_file(), "one refused entry cost the world its whole directory"
    assert kept.read_text(encoding="utf-8") == "a real summary\n"
    assert not (world / "gather_summaries" / "l-002.md").exists(), (
        "a link's TARGET was copied into the archive as if the world had written it")
    assert (world / "report.md").exists(), "the rest of the world stopped archiving"

    # F-7 — the half the screen does not cover. The `copy2` loop has no rollback, so the state
    # a mid-copy I/O fault leaves is a world holding its five required inputs with a supporting
    # directory SHORT. P10 established that state is reachable; it is written to disk here
    # rather than induced by an imagined disk fault, and the assertion is that the pass refuses
    # it LOUDLY and says which input was short.
    partial = J.accepted_episode(tmp_path / "partial",
                                 ledgers={"b": [J.staged_row("b")], "c": []})
    family = J.mod("learning.judge.family")
    assert "b" in J.rows(family.grade_family(partial)), (
        "the control failed: the intact episode did not grade world b at all")
    (partial / "worlds" / "b" / "gather_summaries" / "l-001.md").unlink()

    with pytest.raises(J.refusals()) as short:
        family.grade_family(partial)
    assert "gather_summaries" in str(short.value), (
        "a world the archive left short graded, or was refused without naming the short input; "
        "the message is the whole difference between a partial archive and a malformed one")


def test_921_lesson_bodies_are_not_archived_and_are_read_at_the_recorded_commit(tmp_path):
    """Lesson BODIES are not archived: they are read from the checkout at the sibling's recorded
    commit, through the sanctioned git facade (`_git.git_show_file`).

    Any new `["git", …]` list literal under `defender/` is a new `lint_raw_git_subprocess`
    finding, so the facade is the contract and not a preference. Positive control on the same
    render: the body IS carried into the lessons view, so "not archived" cannot pass on a render
    that shows no lesson at all.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    git_show = J.FakeGitShow(
        bodies={("deadbee", "defender/lessons/L1.md"): "# L1\n\nthe body\n"})

    view = _render().render(ep, "b", runs_base=base, git_show=git_show)
    assert git_show.asked == [("deadbee", "defender/lessons/L1.md")], (
        "the lesson body was not read at the sibling's recorded commit")
    assert "the body" in view.as_prompt_sections()["lessons"]
    assert not list((ep / "worlds" / "b").glob("**/L1.md")), (
        "a lesson BODY was archived; D7 keeps them out of the archive on purpose")


def test_921_an_unavailable_lesson_body_is_marked_rather_than_rendered_as_nothing(tmp_path):
    """`git_show_file` RAISES NOTHING: a fabricated rev and a real-rev/absent-path both return a
    plain `None`, indistinguishable from each other AND from a legitimately empty lesson body
    (P1, the one probe in the set that actually ran anything).

    So the render cannot be written to catch anything here, and an unavailable lesson is SILENT
    unless the render marks it — a silently absent body changes what the judge concludes, which
    is D7's own stated hazard arriving with no signal anywhere in the system. J8, settled: the
    slot renders as an explicit `unavailable: <reason>` line rather than failing the world.

    Both indistinguishable causes are driven, because the demand is that the render marks the
    absence without being able to tell them apart.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)

    for commit, note in (("cafebabe", "absent commit"), ("deadbee", "absent path")):
        (ep / "worlds" / "b" / "provenance.json").write_text(
            json.dumps(J.provenance_record(commit=commit)), encoding="utf-8")
        git_show = J.FakeGitShow(bodies={})
        lessons = _render().render(
            ep, "b", runs_base=base, git_show=git_show).as_prompt_sections()["lessons"]
        assert git_show.asked, f"{note}: the render never asked for the body"
        assert "unavailable" in lessons.lower(), (
            f"{note}: the slot rendered as nothing, which the judge reads as a lesson with no "
            "content rather than as a lesson it was not shown")
        assert "L1" in lessons, f"{note}: the lesson vanished from the view entirely"


def test_921_the_lesson_commit_is_pinned_once_per_pass_and_allow_dirty_is_a_caveat(tmp_path):
    """J8, settled with the human: the sibling's recorded ref is resolved to a SHA ONCE per
    episode-grading pass and threaded to every world's render, and an `allow_dirty` family — one
    whose siblings did not demonstrably run against the recorded tree — is surfaced in the
    lessons view as a CAVEAT.

    O8 says grading is reproducible from "the episode dir plus the runs base plus the checkout
    at the sibling's recorded commit". A ref that moves mid-invocation makes that sentence false
    with nothing saying so, and `allow_dirty` appears nowhere in the design at all — so both
    halves are contract rather than style.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")],
                                               "c": [J.staged_row("c")]})
    git_show = J.FakeGitShow(bodies={("deadbee", "defender/lessons/L1.md"): "# L1 body\n"})
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", git_show=git_show, draws=1)

    assert set(git_show.revs) == {"deadbee"}, (
        "two worlds of one episode read their lesson bodies at different refs")
    assert J.judge_record(ep)["lessons_commit"] == "deadbee", (
        "the pass did not record the ref it pinned, so a later reader cannot reproduce it")

    # A dirty sibling tree is a caveat in the judge's own input, not a silent equivalence.
    dirty = J.accepted_episode(tmp_path / "dirty", ledgers={"b": [J.staged_row("b")], "c": []},
                               dirty=True)
    base, _src = J.runs_base(tmp_path / "dirty")
    lessons = _render().render(dirty, "b", runs_base=base,
                               git_show=J.FakeGitShow(bodies={})).as_prompt_sections()["lessons"]
    assert "dirty" in lessons.lower(), (
        "an allow_dirty family's lesson view claims a reproducibility it does not have")
