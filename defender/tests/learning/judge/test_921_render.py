"""#921 — the judge's input: the four joined views, the withholding, and what the archive owes it."""
from __future__ import annotations

import json

import pytest

from defender._episode_handle import Episode
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
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
    from defender._io import bind

    with bind(ep) as bound:
        manifest = J.mod("learning.judge.family").read_manifest(bound)
    ctx = _render().render(ep, label, **kw)
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


def test_921_judge_input_carries_per_lead_chain_coverage_siblings_lessons_spread(tmp_path):
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


def test_921_no_sibling_facts_reach_the_prompt(tmp_path):
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


def test_921_render_reads_no_sibling_run_dir(tmp_path):
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
    import shutil

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
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
    archive = J.mod("learning.branch.archive")
    ep = J.episode(tmp_path)
    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    (run_dir / "gather_summaries").mkdir(parents=True, exist_ok=True)
    (run_dir / "gather_summaries" / "l-001.md").write_text("summary\n", encoding="utf-8")
    (run_dir / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L1"}) + "\n", encoding="utf-8")
    from defender.tests.support.storage._alert_plant import plant_alert
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

    with Episode.open(ep) as episode:
        archived = archive.archive_episode(episode, {"b": run_dir})
    world = archived["b"]
    kept = world / "gather_summaries" / "l-001.md"
    assert kept.is_file(), "one refused entry cost the world its whole directory"
    assert kept.read_text(encoding="utf-8") == "a real summary\n"
    assert not (world / "gather_summaries" / "l-002.md").exists(), (
        "a link's TARGET was copied into the archive as if the world had written it")
    assert (world / "report.md").exists(), "the rest of the world stopped archiving"

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
    l1 = lessons[lessons.index("### L1"):lessons.index("### L2")]
    l2 = lessons[lessons.index("### L2"):]
    assert "read by the model at 2026-07-28T17:00:00Z" in l1, l1
    assert "never the body below at 2026-07-28T17:02:00Z" in l2, l2
    assert l2.index("never the body below") < l2.index("the second body"), (
        "the exposure line must come before the body it qualifies")


def test_921_an_unavailable_lesson_body_is_marked_rather_than_rendered_as_nothing(tmp_path):
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
