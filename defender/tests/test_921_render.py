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
* **J9** — RETIRED by #1105 PR 2 (J3): the same-alert sibling union over the operator's runs
  base, and its trial spread, left the judge's input — the judge reads only the episode it is
  handed — and the tests that pinned the union went with it.
* **J14** — the withholding's scope is stated across ALL FOUR views, not the manifest alone.

RED against `d1b8b06a`: `learning/judge/render.py` does not exist, no reader anywhere indexes
the runs base by `alert_id`, and `archive.py` copies none of D7's three inputs.
"""
from __future__ import annotations

import json

import pytest

from defender._episode_handle import Episode
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    # The learning STATE root too, so the shared findings queue this pass appends to is
    # this test's own and not the checkout's real `learning/_pending/`. Isolation belongs
    # here rather than in the appender: a production path that picks a different queue when
    # an env var is unset is a pass whose rows can land where no drain reads.
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _render():
    return J.mod("learning.judge.render")


def _lessons_view(ctx) -> str:
    """The judged world's lessons view as the prompt lays it out (`layout`'s `lessons` section
    body, `render._render_lessons` over `JudgeContext.focus.lessons`; #1234 retired
    `as_prompt_sections`)."""
    return _render()._render_lessons(ctx.focus.lessons)


def _world_prompt(ep, label: str = "b", **kw) -> str:
    """World `label`'s prompt from the real assembler over the real render
    (`run._build_prompt(ctx, manifest)`, #1234)."""
    manifest = J.read_manifest_at(ep)
    ctx = J.render_at(ep, label, **kw)
    return J.mod("learning.judge.run")._build_prompt(ctx, manifest)[0]


def _prompts(tmp_path, ep, **kw):
    """Drive the real episode-grading pass and hand back what the model seam was SHOWN.

    Every payload assertion in this file reads `judge.prompts`, never the canned reply: a fake
    that only returns answers leaves the whole outbound channel unpinned, and the outbound
    channel is what O4/O5/O9 are about.
    """
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    J.grade_at(
        ep, judge=judge, **{"state": _state1135.env_state(), **kw})
    return judge


# ---------------------------------------------------------------------------------------
# O4 / D4 / M1 — the joined views and the correlating prompt
# ---------------------------------------------------------------------------------------


def test_921_judge_input_carries_per_lead_chain_coverage_siblings_lessons_spread(tmp_path):
    """The rendered input carries, PER LEAD, goal -> params -> payload -> summary ->
    resolutions, plus coverage against the discriminator and the lessons loaded.

    A judge input built from the two documents alone is O4's stated failing mode and is exactly
    what scored 0.2-0.3/3 while inventing 2.0-2.8 false findings per reply (C9). Every view
    is asserted as present, because the measured collapse was of the whole set. (#1105 PR 2,
    J3: the same-alert sibling union and its trial spread left the judge's input — the judge
    reads only the episode it is handed — so their two assertions went with them.)

    `document_rows` — the lead's raw queries-table rows, stringified whole — left the chain with
    #1017 (D3): nothing in the prompt can act on `system_key`, `payload_sha256`, `payload_path`,
    `raw_command`, `exit_code` or `error_class`, and under an operator's cap the dump crowded
    out real evidence. `params` and `payload` are the semantic content and stay;
    `tests/e2e/test_1017_query_row_surface.py` pins what the leads view may and may not carry.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    ctx = _render().render(ep, "b")
    judge_input = ctx.focus

    chain = judge_input.leads["l-001"]
    for link in ("goal", "params", "payload", "summary", "resolutions"):
        assert link in chain, f"the per-lead chain is missing its {link} link"
    assert "document_rows" not in chain, \
        "the per-lead chain still carries the raw row dump #1017 removed"
    assert ctx.focus_calls, "the per-call view (#1224's successor to coverage) is empty"
    assert judge_input.lessons, "the lessons-loaded view is empty"


def test_921_call_rows_carry_window_and_scope_key_against_the_discriminator(tmp_path):
    """Every call the judged world made reaches the prompt with its decision word and the
    params it ran with — window and scope key included — beside the family's discriminator.

    Those two columns are what M1 added to the ported view; since #1224 the per-call view
    (`JudgeInput.calls`, never cut by the cap) carries them, and the discriminator is the
    family's predicate (`holding_system` is retired with cluster staging). #1234: the call
    list is the joined one (`JudgeContext.focus_calls`, A12), and what reaches the model is
    read off the real prompt.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    ctx = _render().render(ep, "b")

    assert ctx.focus_calls, "no call rows to check"
    for row in ctx.focus_calls:
        assert "window" in row["params"], f"call row without a window: {row}"
        assert "scope_key" in row["params"], f"call row without a scope key: {row}"
        assert row["source"] == "oracle", f"the call row names no decision word: {row}"
    prompt = _world_prompt(ep)
    assert "oracle" in prompt, "the prompt does not name the decision word"
    assert "host.name" in prompt, "the call's scope key never reached the prompt"
    assert "24h" in prompt, "the call's window never reached the prompt"
    assert ctx.focus.discriminator["predicate"] in prompt


def test_921_reply_without_the_three_pass_tables_is_refused(tmp_path):
    """The prompt demands the correlation, scope and derivation passes before findings, and a
    reply without the three pass tables is refused.

    This is the half the experiment measured directly: the cadence break, never noticed in ten
    replies, went 0/5 -> 5/5 once a derivation pass was demanded (C10). The demand has both
    halves — the prompt ASKS for the three passes, and a reply that omits them does not stand.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    judge = _prompts(tmp_path, ep)
    prompt = judge.prompts[0]
    for pass_name in ("correlation", "scope", "derivation"):
        assert pass_name in prompt.lower(), f"the prompt never asks for the {pass_name} pass"

    run_mod = J.mod("learning.judge.run")
    with pytest.raises(J.refusals()):
        run_mod.validate_reply(J.as_reply_text(J.reply_doc(passes=False)))
    # Positive control: the same reply WITH the three tables validates.
    assert run_mod.validate_reply(J.as_reply_text(J.reply_doc())).bucket == "lead-set"


def test_921_prompt_names_the_graded_world_and_keeps_the_cap_and_quoting_rule(tmp_path):
    """The prompt is the correlating prompt parameterised by the GRADED WORLD's label ("world X
    has run; grade it"), keeping the 20-row cap and the quote-any-colon rule that made 15/15
    replies parse strictly (C12). Its wording names hand-offs, never entities or systems.

    The parameterisation is what makes one call about one trajectory: the experiment's own text
    said "world A", and that sentence becomes "world X has run; grade it".
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")],
                                               "c": [J.oracle_row("c")]})
    judge = _prompts(tmp_path, ep, draws=1)
    # #1007 M5 adds a THIRD call (`judge:family:<n>`) beside the two per-world ones; excluded
    # here, since this test is about the per-world prompt's own parameterisation.
    by_world = {aid.split(":")[1]: prompt
               for aid, prompt in zip(judge.agent_ids, judge.prompts, strict=True)
               if aid.split(":")[1] != "family"}

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


def test_921_no_sibling_facts_reach_the_prompt(tmp_path):
    """#1234 rewrite (design M1, M3): the withholding this pinned is REVERSED. A world is now
    judged against its reference runs, so a sibling's facts DO reach its prompt — but only as
    that reference run's facts, in its own labelled section, and the task says so; no sentence
    claims any world's facts are withheld (the retired framing). The measured failing mode the
    withholding answered (C11: sibling facts cited as facts about the judged world) is now
    answered by the label and that sentence.
    """
    secret = "SIBLING-ONLY-INJECTED-FACT"
    worlds = [
        J.world_doc("a", role="A", axis=None, disposition_declared="benign", facts=[]),
        J.world_doc("b", disposition_declared="malicious", facts=[J.fact("f-b")]),
        J.world_doc("c", disposition_declared="malicious",
                    facts=[J.fact("f-c", f"web-1's owner is {secret}")]),
    ]
    ep = J.accepted_episode(tmp_path, worlds=worlds,
                            ledgers={"b": [J.oracle_row("b")], "c": [J.oracle_row("c")]})

    judge = _prompts(tmp_path, ep, draws=1)
    graded_b = judge.prompts[judge.agent_ids.index("judge:b:0")]
    assert secret in graded_b, "the reference run's facts never reached the judged world's prompt"
    assert ("Each reference run's facts sit only in that run's labelled section of the "
            "computed header; they are never facts about the judged world") in graded_b, (
        "the prompt never says a reference run's facts are not the judged world's")
    assert "withheld" not in graded_b.lower(), "the retired withholding sentence is still there"


def test_921_graded_world_keeps_its_own_facts_and_is_not_withheld(tmp_path):
    """The paired positive control: the graded world keeps its OWN facts and nothing marks them
    withheld (#1234: no world's facts are; the withholding framing is retired, M3).

    Without it, `assert secret in prompt` above is also green on a render that dumps every
    world's facts under the judged world's own label.
    """
    mine = "GRADED-WORLD-OWN-INJECTED-FACT"
    worlds = [
        J.world_doc("a", role="A", axis=None, disposition_declared="benign", facts=[]),
        J.world_doc("b", disposition_declared="malicious",
                    facts=[J.fact("f-b", f"web-1's owner is {mine}")]),
    ]
    ep = J.accepted_episode(tmp_path, worlds=worlds, labels=("a", "b"),
                            dispositions={"a": "benign", "b": "malicious"},
                            ledgers={"b": [J.oracle_row("b")]})
    judge = _prompts(tmp_path, ep, draws=1)
    prompt = judge.prompts[judge.agent_ids.index("judge:b:0")]

    assert mine in prompt, "the graded world's own facts were withheld from its own grading"
    assert "withheld" not in prompt.lower(), "the graded world's facts were marked withheld"


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

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    runs = ep / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / f"{J.EPISODE_ID}-b").mkdir(parents=True, exist_ok=True)
    shutil.rmtree(runs)

    view = _render().render(ep, "b").focus
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

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    # The scene's explicit RUNS step (`runs/`, then the roster naming every manifest world):
    # the arm planter reads the roster and never writes one (review-3 F33).
    T.plant_roster(ep)
    runs = ep / "runs"
    J.sibling_run_dir(runs, "b")
    git_show = J.FakeGitShow(bodies={("deadbee", "defender/lessons/L1.md"): "# L1 body\n"})

    with_dirs = _render().render(ep, "b", git_show=git_show)
    shutil.rmtree(runs)
    without = _render().render(ep, "b", git_show=git_show)

    assert with_dirs == without, (
        "the rendered input changed when the sibling run dirs were removed")
    assert "# L1 body" in _lessons_view(without)


def test_921_archive_writes_gather_summaries_lessons_loaded_and_alert_json(tmp_path):
    """Each archived world gains `gather_summaries/`, `lessons_loaded.jsonl` and `alert.json`
    beside the four single files and two screened tables it already carries (C17).

    `_single_files` has TWO readers — the screen and the copy — so a name in one and not the
    other is an artifact that is checked and not copied (run1/G28); both halves are exercised by
    driving the real `archive_episode` over a real sibling run dir and reading the archive back.
    """
    archive = J.mod("learning.branch.archive")
    ep = J.episode(tmp_path)
    # The scene's explicit RUNS step (`runs/`, then the roster naming every manifest world):
    # the arm planter reads the roster and never writes one (review-3 F33).
    T.plant_roster(ep)
    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    (run_dir / "gather_summaries").mkdir(parents=True, exist_ok=True)
    (run_dir / "gather_summaries" / "l-001.md").write_text("summary\n", encoding="utf-8")
    (run_dir / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L1"}) + "\n", encoding="utf-8")
    from defender.tests._alert_plant import plant_alert
    plant_alert(run_dir, {"alert_id": J.ALERT_ID})

    with Episode.open(ep) as episode:
        archived = archive.archive_episode(episode, {"b": run_dir})
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
    short, and that state is MALFORMED: the judge pass excludes that world, marks it malformed
    and names the input that was short, rather than grading it normally on a thinner view. This
    test used to cite the half-populated world in its docstring and drive only the screen — the
    one path P10 says IS all-or-nothing — so the state the citation is about reached no
    assertion at all.

    The exclusion is the WORLD's, not the pass's: a sibling whose own archive is whole still
    grades, because one world's bad artifact is not a reason to throw away a clean sibling's
    grade and leave no record of either.
    """
    archive = J.mod("learning.branch.archive")
    ep = J.episode(tmp_path)
    # The scene's explicit RUNS step (`runs/`, then the roster naming every manifest world):
    # the arm planter reads the roster and never writes one (review-3 F33).
    T.plant_roster(ep)
    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    summaries = run_dir / "gather_summaries"
    summaries.mkdir(parents=True, exist_ok=True)
    (summaries / "l-001.md").write_text("a real summary\n", encoding="utf-8")
    outside = tmp_path / "outside-the-tree.md"
    outside.write_text("bytes no world wrote\n", encoding="utf-8")
    (summaries / "l-002.md").symlink_to(outside)

    with Episode.open(ep) as episode:
        archived = archive.archive_episode(episode, {"b": run_dir})
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
    # rather than induced by an imagined disk fault, and the assertion is that the pass excludes
    # that world LOUDLY and says which input was short.
    partial = J.accepted_episode(tmp_path / "partial",
                                 ledgers={"b": [J.oracle_row("b")], "c": []})
    assert J.rows(J.grade(partial))["b"].get(
        "ungradable") is not True, (
        "the control failed: the intact episode did not grade world b at all")
    # The control's final grade would short-circuit the re-grade (`judge.yaml` is idempotent).
    (partial / "judge.yaml").unlink()
    (partial / "worlds" / "b" / "gather_summaries" / "l-001.md").unlink()

    rows = J.rows(J.grade(partial))
    assert rows["b"].get("malformed") is True, (
        "a world the archive left short graded normally, on a thinner view than it appears to "
        "have")
    assert "gather_summaries" in rows["b"]["ungradable_reason"], (
        "the world was excluded without naming the short input; the message is the whole "
        "difference between a partial archive and a malformed artifact")
    assert rows["c"].get("ungradable") is not True, (
        "world b's short directory cost world c its grade")


def test_921_lesson_bodies_are_not_archived_and_are_read_at_the_recorded_commit(tmp_path):
    """Lesson BODIES are not archived: they are read from the checkout at the sibling's recorded
    commit, through the sanctioned git facade (`_git.git_show_file`).

    Any new `["git", …]` list literal under `defender/` is a new `lint_raw_git_subprocess`
    finding, so the facade is the contract and not a preference. Positive control on the same
    render: the body IS carried into the lessons view, so "not archived" cannot pass on a render
    that shows no lesson at all.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    git_show = J.FakeGitShow(
        bodies={("deadbee", "defender/lessons/L1.md"): "# L1\n\nthe body\n"})

    view = _render().render(ep, "b", git_show=git_show)
    assert git_show.asked == [("deadbee", "defender/lessons/L1.md")], (
        "the lesson body was not read at the sibling's recorded commit")
    assert "the body" in _lessons_view(view)
    assert not list((ep / "worlds" / "b").glob("**/L1.md")), (
        "a lesson BODY was archived; D7 keeps them out of the archive on purpose")


def test_921_a_lesson_recorded_on_several_rows_renders_its_body_once_and_says_how_it_reached_the_model(tmp_path):
    """`lessons_loaded.jsonl` is an EVENT log — a row per time a lesson reached an agent, and
    since #936 the compaction fold writes a `push` row per matching lesson at every boundary
    on top of the read and write-return rows — while this view is the SET of what was in
    front of the model. Rendered per row, a lesson the run kept matching would put its whole
    body in the judge's prompt once per boundary, weighting the judge toward it by repetition;
    and a `push` row means the model saw a description, not the body, which the judge must be
    told or it weighs the body as read. Control on the same render: two DIFFERENT lessons
    still render two bodies."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    rows = [
        {"lesson_name": "L1", "ts": "2026-07-28T17:00:00Z", "kind": "read", "role": "main"},
        {"lesson_name": "L1", "ts": "2026-07-28T17:01:00Z", "kind": "push", "role": "main"},
        {"lesson_name": "L2", "ts": "2026-07-28T17:02:00Z", "kind": "push", "role": "main"},
        {"lesson_name": "L1", "ts": "2026-07-28T17:03:00Z", "kind": "push", "role": "main"},
    ]
    (ep / "worlds" / "b" / "lessons_loaded.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    git_show = J.FakeGitShow(bodies={
        ("deadbee", "defender/lessons/L1.md"): "# L1\n\nthe first body\n",
        ("deadbee", "defender/lessons/L2.md"): "# L2\n\nthe second body\n",
    })

    lessons = _lessons_view(_render().render(ep, "b", git_show=git_show))
    assert lessons.count("the first body") == 1, (
        f"a lesson on three rows rendered its body {lessons.count('the first body')} times")
    assert lessons.count("the second body") == 1, "control: the other lesson still renders"
    assert lessons.index("the first body") < lessons.index("the second body"), (
        "first-occurrence order — the order the lessons reached the model")
    # HOW each reached the model, beside its body — the record's one reader
    # (`hooks.record_lesson_load.exposures`) says `read` for L1 and `push` for L2, and a push
    # showed the model a description and dimensions, not the body the judge is handed here.
    l1 = lessons[lessons.index("### L1"):lessons.index("### L2")]
    l2 = lessons[lessons.index("### L2"):]
    assert "read by the model at 2026-07-28T17:00:00Z" in l1, l1
    assert "never the body below at 2026-07-28T17:02:00Z" in l2, l2
    assert l2.index("never the body below") < l2.index("the second body"), (
        "the exposure line must come before the body it qualifies")


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
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})

    for commit, note in (("cafebabe", "absent commit"), ("deadbee", "absent path")):
        (ep / "worlds" / "b" / "provenance.json").write_text(
            json.dumps(J.provenance_record(commit=commit)), encoding="utf-8")
        git_show = J.FakeGitShow(bodies={})
        lessons = _lessons_view(_render().render(ep, "b", git_show=git_show))
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
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")],
                                               "c": [J.oracle_row("c")]})
    git_show = J.FakeGitShow(bodies={("deadbee", "defender/lessons/L1.md"): "# L1 body\n"})
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        git_show=git_show, draws=1,
        state=_state1135.env_state())

    assert set(git_show.revs) == {"deadbee"}, (
        "two worlds of one episode read their lesson bodies at different refs")
    assert J.judge_record(ep)["lessons_commit"] == "deadbee", (
        "the pass did not record the ref it pinned, so a later reader cannot reproduce it")

    # A dirty sibling tree is a caveat in the judge's own input, not a silent equivalence.
    dirty = J.accepted_episode(tmp_path / "dirty", ledgers={"b": [J.oracle_row("b")], "c": []},
                               dirty=True)
    lessons = _lessons_view(_render().render(dirty, "b", git_show=J.FakeGitShow(bodies={})))
    assert "dirty" in lessons.lower(), (
        "an allow_dirty family's lesson view claims a reproducibility it does not have")
