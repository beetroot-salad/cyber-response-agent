"""#1025 — the stages section: the stage table, the two clocks, costs from traces and result
events, and the transcript blocks.

O4 as resolved (§7 Q9, J13a–c, J15, J17): one row per `Step` in `STEPS` order with `runs`
expanded per run dir; the wall from `timing.json` (the launcher's clock) and, without it, the
labelled lower bound "model calls + longest world"; cost from questioner / judge traces' response
rows through the pricing table and from each run's result event, every number saying what it
covers — an unpriced row reads "unpriced" and never $0.0000, a stage sum missing a call reads
"partial — N of M calls priced", a torn tail is dropped and counted, an empty comparator trace is
listed by stem with "0 rows"; the result event is read lstat-screened and type-tolerant — a
link or non-regular file reads "no result event (refused)", only the LAST row is a result event,
a non-numeric / non-finite / negative cost reads "unusable result event". Transcript blocks are
one per trace, family first then each roster world's draws in numeric order, the framed prompt as
the request (the request row's user-prompt part for the questioner seats, instructions collapsed),
one entry per response row, one control set per stream or none.

Every cost on the expected side is the fixture's declared figure (`E.SAMPLE`): kimi-k3's
$3/M in and $15/M out over round token counts. RED AGAINST HEAD: the page module does not exist.
"""
from __future__ import annotations

import json
import math
import time

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_stage_timing as ST

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
LOWER_BOUND = f"≈ {S.lower_bound} lower bound on wall: model calls + longest world"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def visualize_episode():
    """The target module, `defender.scripts.visualize.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(<dir>)` — the real entry point — then the page it
    wrote, parsed."""
    return E.render(ep, module=visualize_episode())


def cli(argv, capsys):
    """`visualize_episode().main(argv)` with its stdout / stderr captured."""
    return E.cli(argv, capsys, module=visualize_episode())


def _ordered(text: str, *needles: str) -> bool:
    """Whether `needles` occur in `text` in this order — each found AFTER the previous one, so
    an earlier, unrelated mention of a later word (a heading naming the verdict before the
    ladder) does not defeat a correctly ordered sequence."""
    position = 0
    for needle in needles:
        position = text.find(needle, position)
        if position < 0:
            return False
        position += len(needle)
    return True


def _stage_of(page: E.Page, tx_id: str) -> str | None:
    holder = page.section(tx_id).ancestor_with_id("stage-")
    return holder.id if holder is not None else None


def _tx_order(page: E.Page, stage: str) -> list[str]:
    return [n.id for n in page.section(stage).descendants() if n.id and n.id.startswith("tx-")]


# ---------------------------------------------------------------------------------------
# d26 / d27 / d28 / d29
# ---------------------------------------------------------------------------------------


def test_1025_the_stage_table_has_one_row_per_step_runs_expanded_per_run_dir_wall_only_rows_and_a_total_that_says_what_it_excludes(
        tmp_path):
    """Rows in `STEPS` order; `runs` expanded into `a`, `no_remote_session`,
    `prior_fake_key_precedent` sub-rows each with its result-event cost ($0.4000 / $0.2500 /
    $0.3500) and duration (10m00s / 3m00s / 5m00s); `staging` / `review` / `verify` read "no
    model calls"; the total row reads $3.5500 and names gather subagents and the review gate as
    excluded.
    """
    page = render(E.sample_episode(tmp_path))
    timing = page.text_of("stage-timing")
    assert _ordered(timing, *ST.EXPECTED_STEPS), timing
    runs = page.text_of("stage-runs")
    for label in E.WORLDS:
        assert _ordered(runs, label, f"${S.run_cost[label]:.4f}"), (label, runs)
    for wall in ("10m00s", "3m00s", "5m00s"):
        assert wall in runs, (wall, runs)
    assert timing.count("no model calls") == 3, timing
    assert S.total_cost in timing, timing
    assert "gather subagents" in timing, timing
    assert "review gate" in timing, timing


def test_1025_without_timing_json_the_axis_is_model_time_with_a_labelled_lower_bound_and_with_it_the_launchers_wall_per_step(
        tmp_path):
    """Sample (no `timing.json`): the wall column is empty with a one-line reason naming the
    absent record, the header reads "≈ 16m00s lower bound on wall: model calls + longest
    world", and the graph axis is labelled model-call time; the same copy with a
    `StageClock`-shaped six-step record renders each step's wall, the header as
    first-start-to-last-end (11m00s), and the changed caption; a three-step record renders
    three walls and three "not on the record" rows.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert LOWER_BOUND in page.one("header").text() or LOWER_BOUND in stages, stages
    assert "timing.json" in stages or "no timing record" in stages, stages
    assert "model-call time" in stages, stages

    E.write_timing(ep.dir, E.six_steps())
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert stages.count("1m00s") >= 6, stages
    assert "11m00s" in page.text, stages
    assert LOWER_BOUND not in page.text, stages
    assert "model-call time" not in stages, stages
    assert "not on the record" not in stages

    E.write_timing(ep.dir, E.six_steps()[:3])
    stages = render(ep).text_of("sec-stages")
    assert stages.count("1m00s") >= 3, stages
    # ">=", matching the tolerant pattern the "1m00s" check just above already uses: each
    # step's own wall/cost text is rendered twice by design — once in the compact `stage-timing`
    # overview, once more inside that step's own id-anchored block (`stage-questioner` etc.),
    # which is what lets `page.text_of("stage-questioner")` carry its own cost line independently
    # (asserted elsewhere in this file). A strict "== 3" only holds if that duplication did not
    # exist.
    assert stages.count("not on the record") >= 3, stages


def test_1025_stage_costs_sum_response_row_usage_and_each_runs_result_event_and_a_run_with_no_trace_shows_no_cost_not_zero(
        tmp_path):
    """Sample questioner cost $1.0500 over 3 traces / 2m00s, judge $1.5000 over 3 traces /
    4m00s, worlds $1.0000; a launcher-produced episode (no `tool_trace.jsonl`, no `_trace.jsonl`)
    renders "no cost recorded" per run rather than $0.0000; the render does not open
    `runs/*/wire_logs/llm_requests.jsonl` (a FIFO planted there is never read).
    """
    ep = E.sample_episode(tmp_path)
    fifo = ep.run(E.GRADED_WORLD) / "wire_logs" / "llm_requests.jsonl"
    fifo.parent.mkdir()
    E.plant_fifo(fifo)
    started = time.monotonic()
    with E.Rescue(fifo, after=2.0) as rescue:
        page = render(ep)
    assert time.monotonic() - started < 2.0, "the run wire log was opened"
    assert not rescue.fed, "the run wire log was opened"
    questioner, judge = page.text_of("stage-questioner"), page.text_of("stage-judge")
    assert S.questioner_cost in questioner, questioner
    assert "3 traces" in questioner, questioner
    assert S.questioner_wall in questioner, questioner
    assert S.judge_cost in judge, judge
    assert "3 traces" in judge, judge
    assert S.judge_wall in judge, judge
    assert S.worlds_cost in page.text_of("stage-runs"), page.text_of("stage-runs")

    launch = ST._launch(tmp_path)
    launched = E.read_page(launch.episode_dir)
    runs = launched.text_of("stage-runs")
    assert runs.count("no cost recorded") == len(launch.spawn.worlds), runs
    assert "$0.0000" not in launched.text_of("sec-stages")


def test_1025_each_questioner_and_judge_trace_renders_a_labelled_block_family_first_with_the_framed_prompt_and_every_response_row(
        tmp_path):
    """Sample: `tx-questioner_trace`, `tx-questioner_b_trace`, `tx-questioner_c_trace` under
    the questioner stage; `tx-judge_family_0_trace` first then the two world draws under the
    judge stage, each with the framed `prompt` as the request, one rendered entry per
    `kind: response` row carrying its model, usage and duration, and the framed `failure` when
    set; a launcher-produced episode with only `_framed` files still renders each call's prompt
    and reply.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for stem in ("questioner_trace", "questioner_b_trace", "questioner_c_trace"):
        assert _stage_of(page, f"tx-{stem}") == "stage-questioner", stem
    judge_blocks = _tx_order(page, "stage-judge")
    assert judge_blocks[0] == f"tx-judge_{E.FAMILY}_0_trace", judge_blocks
    assert set(judge_blocks) == {f"tx-judge_{E.FAMILY}_0_trace", f"tx-judge_{E.WITHHELD_WORLD}_0_trace",
                                 f"tx-judge_{E.GRADED_WORLD}_0_trace"}, judge_blocks
    family = page.text_of(f"tx-judge_{E.FAMILY}_0_trace")
    assert f"framed prompt for {E.FAMILY}" in family, family
    assert "reply of" not in family, family
    assert "kimi-k3" in family, family
    assert "100,000" in family or "100000" in family, family
    assert "2m00s" in family, family
    entries = page.section(f"tx-judge_{E.FAMILY}_0_trace").find_all(cls="tx-entry")
    assert len(entries) == 1, [e.text() for e in entries]

    E.write_framed(ep.dir, f"judge:{E.GRADED_WORLD}:0", prompt="P", reply=None, failure="the call FAILED-MARKER")
    assert "the call FAILED-MARKER" in render(ep).text_of(f"tx-judge_{E.GRADED_WORLD}_0_trace")

    launch = ST._launch(tmp_path)
    launched = E.read_page(launch.episode_dir)
    framed = sorted(p.name for p in (launch.episode_dir / "wire_logs").glob("judge_*_framed_trace.jsonl"))
    assert framed, "the control failed: no framed file"
    for name in framed:
        stem = name[: -len("_framed_trace.jsonl")] + "_trace"
        block = launched.text_of(f"tx-{stem}")
        row = json.loads((launch.episode_dir / "wire_logs" / name).read_text(encoding="utf-8"))
        # `block` is `.text()`'s whitespace-COLLAPSED view (every run of whitespace, a real
        # judge prompt's own paragraph breaks included, becomes one space); the raw prompt is
        # collapsed the same way before the containment check, or a genuine `\n\n` between
        # sentences — present in the page's raw HTML verbatim — reads as a false mismatch.
        assert " ".join(row["prompt"][:60].split()) in block, (stem, block[:200])
        assert " ".join((row["reply"] or "")[:40].split()) in block, (stem, block[:200])


# ---------------------------------------------------------------------------------------
# settled — clocks
# ---------------------------------------------------------------------------------------


def test_1025_a_steps_ended_at_sorts_before_its_started_at(tmp_path):
    """No negative duration is ever displayed: `read_stage_timings` returns a step whose
    `ended_at` precedes `started_at` unchanged (p5), so that step's row shows "—" and the header
    wall is min(start)–max(end); the whole-table refusal arm is NOT taken.
    """
    ep = E.sample_episode(tmp_path)
    steps = E.six_steps()
    steps[0] = ("questioner", "2026-09-09T10:00:05Z", "2026-09-09T10:00:01Z")
    E.write_timing(ep.dir, steps)
    page = render(ep)
    timing = page.text_of("stage-timing")
    assert "timing record unreadable" not in timing
    row = timing[timing.index("questioner"):timing.index("staging")]
    assert "—" in row, row
    assert "-" not in row.replace("—", "").replace("not on", ""), row
    # NOT "11m00s" (that is the CLEAN six-step header, asserted two tests up): with the first
    # step's own pair inverted, its untrustworthy timestamps contribute to neither side of
    # min(start)/max(end) — the same refusal its own "—" cell already makes — so the header
    # spans only the five valid steps, staging's start (10:02) to judge's end (10:11): 9m00s.
    assert "9m00s" in page.text


def test_1025_a_repeated_steps_own_wall_excludes_an_inverted_sibling_entry(tmp_path):
    """A repeated step's OWN wall (its first entry's start to its last entry's end, J15) is
    computed the same way the header wall already is (p5, the test above): an inverted entry
    among the repeats contributes to neither side of min(start)/max(end) for the row's own
    span, not only for the page-wide header. A buggy filter that excludes an inverted entry's
    pair from the header aggregate but not from this row's own aggregate would let one bad
    entry stretch a repeated step's displayed wall past what its trustworthy entries alone
    cover.
    """
    ep = E.sample_episode(tmp_path)
    steps = E.six_steps()
    steps.append(("staging", "2026-09-09T10:10:00Z", "2026-09-09T10:09:00Z"))
    E.write_timing(ep.dir, steps)
    page = render(ep)
    timing = page.text_of("stage-timing")
    row = timing[timing.index("staging"):timing.index("review")]
    assert "2 entries" in row, row
    # The clean single staging entry alone (10:02–10:03Z) is 1m00s. If the inverted second
    # entry's own timestamps (10:09–10:10Z) leaked into the span, min(start)=10:02 and
    # max(end)=10:09 would read 7m00s instead.
    assert "1m00s" in row, row
    assert "7m00s" not in row, row


def test_1025_what_the_header_wall_covers(tmp_path):
    """With `timing.json` present the header wall is labelled as the launcher's wall from the
    first step's `started_at` to the last step's `ended_at` (11m00s) — the label says it
    excludes preflight and the prime and includes the gaps between steps.
    """
    ep = E.sample_episode(tmp_path, timing=True)
    page = render(ep)
    text = page.one("header").text() + " " + page.text_of("sec-stages")
    assert "11m00s" in text, text
    lowered = text.lower()
    assert "preflight" in lowered, text
    assert "prime" in lowered, text
    assert "gaps" in lowered, text


def test_1025_the_runs_row_has_two_clocks(tmp_path):
    """The `runs` row shows the launcher's RUNS-step wall (1m00s from `timing.json`) labelled
    as the launcher's; each per-run sub-row shows its own result-event `duration_ms` labelled
    as the run's wall (10m00s / 3m00s / 5m00s); the two labels differ and neither number is
    summed into the other.
    """
    page = render(E.sample_episode(tmp_path, timing=True))
    runs = page.text_of("stage-runs")
    assert "1m00s" in runs, runs
    assert "10m00s" in runs, runs
    assert "3m00s" in runs, runs
    assert "5m00s" in runs, runs
    assert "launcher" in runs.lower(), runs
    assert "result event" in runs.lower(), runs
    assert "18m00s" not in runs, runs
    assert "19m00s" not in runs, runs


# ---------------------------------------------------------------------------------------
# settled — trace shapes
# ---------------------------------------------------------------------------------------


def test_1025_a_trace_with_a_request_row_and_no_response_row(tmp_path):
    """A trace with a request row and no response row renders the request with "no response
    recorded"; the call adds nothing to the stage cost or the model-time axis and is not shown
    as $0.0000; the stage sum reads "partial — 3 of 4 calls priced".
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:d", response=False, prompt="the unanswered prompt")
    page = render(ep)
    block = page.text_of("tx-questioner_d_trace")
    assert "the unanswered prompt" in block, block
    assert "no response recorded" in block, block
    assert "$0.0000" not in block
    questioner = page.text_of("stage-questioner")
    assert S.questioner_cost in questioner, questioner
    assert "partial — 3 of 4 calls priced" in questioner, questioner


def test_1025_trace_present_but_framed_absent(tmp_path):
    """A judge trace without its `_framed` twin renders its block's request from the plain
    trace's request row — `message.instructions` plus the user-prompt part (c8/F13) — through
    the untrusted escape; the block renders rather than showing nothing.
    """
    ep = E.sample_episode(tmp_path)
    (ep.dir / "wire_logs" / f"judge_{E.GRADED_WORLD}_0_framed_trace.jsonl").unlink()
    E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:0", prompt="PLAIN-PROMPT <b>x</b>",
                  instructions="PLAIN-INSTRUCTIONS", usage=S.judge_usage[2],
                  duration_ms=float(S.judge_ms[2]))
    page = render(ep)
    block = page.text_of(f"tx-judge_{E.GRADED_WORLD}_0_trace")
    assert "PLAIN-PROMPT <b>x</b>" in block, block
    assert "PLAIN-INSTRUCTIONS" in block, block
    assert "&lt;b&gt;x&lt;/b&gt;" in page.raw


def test_1025_a_framed_trace_row_carries_a_failure_field_instead_of_a_reply(tmp_path):
    """The block shows the framed prompt and the `failure` text (escaped) in place of a reply;
    no cost line for the call.
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:0", response=False)
    E.write_framed(ep.dir, f"judge:{E.GRADED_WORLD}:0", prompt="FRAMED-P", reply=None,
                   failure="did not complete: <TimeoutError>")
    page = render(ep)
    block = page.text_of(f"tx-judge_{E.GRADED_WORLD}_0_trace")
    assert "FRAMED-P" in block, block
    assert "did not complete: <TimeoutError>" in block, block
    assert "$" not in block
    assert "&lt;TimeoutError&gt;" in page.raw


def test_1025_a_comparator_trace_from_the_review_step(tmp_path):
    """A comparator trace (`comparator_1_trace.jsonl`, correction 3) renders its transcript
    block inside the review stage block; its response rows' cost ($0.60) is summed into the
    review row and the total ($4.1500); "no model calls" no longer describes the review row.
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "comparator:1", usage=(100_000, 20_000), duration_ms=5_000.0,
                  prompt="COMPARATOR PROMPT")
    page = render(ep)
    assert _stage_of(page, "tx-comparator_1_trace") == "stage-review"
    review = page.text_of("stage-review")
    assert "$0.6000" in review, review
    assert "no model calls" not in review, review
    assert "$4.1500" in page.text_of("stage-timing")


def test_1025_judge_trace_stems_with_underscored_labels_and_two_digit_draws(tmp_path):
    """Each judge trace is attributed to its (label, draw) and ordered family first, then each
    roster world in numeric draw order; the stem is composed from the known label and draw by
    the writer's `':'→'_'` rule (g2), never parsed back from the filename — draw 10 of
    `no_remote_session` sits after draw 9, under that world.
    """
    ep = E.sample_episode(tmp_path)
    for n in range(1, 11):
        E.write_trace(ep.dir, f"judge:{E.WITHHELD_WORLD}:{n}", prompt=f"draw {n} prompt")
        E.draw_document(ep.dir, E.WITHHELD_WORLD, n, E.draw_doc(findings=[]))
    page = render(ep)
    order = _tx_order(page, "stage-judge")
    assert order[0] == f"tx-judge_{E.FAMILY}_0_trace", order
    withheld = [i for i in order if i.startswith(f"tx-judge_{E.WITHHELD_WORLD}_")]
    assert withheld == [f"tx-judge_{E.WITHHELD_WORLD}_{n}_trace" for n in range(11)], withheld
    assert "draw 10 prompt" in page.text_of(f"tx-judge_{E.WITHHELD_WORLD}_10_trace")


def test_1025_response_rows_missing_usage_model_or_duration(tmp_path):
    """A response row without `usage` or with no `model` renders "unpriced" (never $0.0000); a
    row without `duration_ms` is excluded from the model-time axis; the stage sum and total say
    how many rows they priced.
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:c", usage=None, duration_ms=None, model=None)
    page = render(ep)
    block = page.text_of("tx-questioner_c_trace")
    assert "unpriced" in block, block
    assert "$0.0000" not in block, block
    questioner = page.text_of("stage-questioner")
    assert "$0.7500" in questioner, questioner
    assert "partial — 2 of 3 calls priced" in questioner, questioner
    assert "1m30s" in questioner, questioner
    assert S.questioner_wall not in questioner, questioner


def test_1025_a_trace_response_row_names_a_model_absent_from_the_pricing_table(tmp_path):
    """A response row naming a model the pricing table lacks reads "unpriced" (not "$0.0000"),
    the stage sum excludes it and says so, and the total is labelled partial — `usage_cost`'s
    zero (g21) is never shown as a dollar figure.
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:c", model="accounts/fireworks/models/no-such-model-9")
    page = render(ep)
    assert "unpriced" in page.text_of("tx-questioner_c_trace")
    assert "$0.0000" not in page.text_of("sec-stages")
    questioner = page.text_of("stage-questioner")
    assert "$0.7500" in questioner, questioner
    assert "partial — 2 of 3 calls priced" in questioner, questioner
    assert "partial" in page.text_of("stage-timing"), page.text_of("stage-timing")


def test_1025_trace_prompt_or_reply_contains_a_literal_pre_or_script_close_tag(tmp_path):
    """Every prompt and reply renders through `pre_text_untrusted`, so a literal `</pre>` or
    `</script>` appears as text (`&lt;/pre&gt;`) and closes nothing: the page's `<script` and
    `</script>` counts stay balanced, as do `<pre` and `</pre>`. Positive control: the escaped
    text is visible in the block.
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:b", prompt="before </pre> after", reply="x </script><script>alert(1)</script>")
    page = render(ep)
    block = page.text_of("tx-questioner_b_trace")
    assert "before </pre> after" in block, block
    assert "</script><script>alert(1)</script>" in block, block
    assert "&lt;/pre&gt;" in page.raw
    assert "&lt;/script&gt;" in page.raw
    assert page.raw.count("<script") == page.raw.count("</script>")
    assert page.raw.count("<pre") == page.raw.count("</pre>")
    assert "alert(1)</script>" not in page.raw


def test_1025_a_sibling_tool_trace_jsonls_final_row_is_not_a_result_event(tmp_path):
    """A run whose `tool_trace.jsonl` does not end in a result event reads "no result event" in
    its cost row; nothing is priced from a non-result row; the render never raises.
    """
    ep = E.sample_episode(tmp_path)
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [
        E.result_event(cost=9.99, duration_ms=1),
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "tail"}]}}])
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert "no result event" in runs, runs
    assert "$9.99" not in page.text, runs
    assert f"${S.run_cost[E.CONTROL]:.4f}" in runs


def test_1025_render_against_a_still_running_sibling_with_no_result_event_yet(tmp_path):
    """A sibling still running — a run dir with events and no result event yet — is
    indistinguishable from a crashed one by design: the section renders, the cost row reads
    "no result event", the link is rendered; no live-process inspection.
    """
    ep = E.sample_episode(tmp_path)
    E.run_dir(ep.dir, E.GRADED_WORLD, result=False)
    page = render(ep)
    assert f"world-{E.GRADED_WORLD}" in page.by_id
    assert "no result event" in page.text_of("stage-runs")
    assert f"runs/{E.EPISODE_ID}-{E.GRADED_WORLD}/runtime.html" in page.anchors_in(f"world-{E.GRADED_WORLD}")


def test_1025_a_very_long_unbroken_token(tmp_path):
    """A 70 KB single-line prompt, a spaceless params JSON and a thousands-character reason all
    render inside their blocks, and the page carries the run pages' shared stylesheet — the one
    with the wrapping fix (`overflow-wrap: anywhere` / `word-break`) — so a token never widens
    the page.
    """
    ep = E.sample_episode(tmp_path)
    token = "x" * 70_000
    E.write_trace(ep.dir, "questioner:b", prompt=token)
    doc = E.sample_grade()
    doc["worlds"][0]["withheld_reason"] = "r" * 3_000
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert token in page.text_of("tx-questioner_b_trace")
    assert "r" * 3_000 in page.text
    css = E.mod("scripts.visualize.visualize_run").CSS
    assert css in page.raw, "the shared stylesheet is not inlined"
    assert "overflow-wrap: anywhere" in css or "word-break: break-word" in css


# ---------------------------------------------------------------------------------------
# J13 — questioner request rows, partial cost, controls per stream
# ---------------------------------------------------------------------------------------


def test_1025_questioner_request_rows_have_no_framed_file(tmp_path):
    """A questioner trace has no `_framed` twin: the block renders the request row's user-prompt
    part (the captured past, attacker-influenced) through the untrusted escape, its
    `instructions` collapsed in a `details` element, and is labelled by its `agent_id`
    (`questioner:b`) (J13a).
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:b", prompt="THE CAPTURED PAST <b>x</b>",
                  instructions="THE SEAT INSTRUCTIONS")
    page = render(ep)
    block = page.section("tx-questioner_b_trace")
    text = block.text()
    assert "THE CAPTURED PAST <b>x</b>" in text, text
    assert "questioner:b" in text, text
    assert "&lt;b&gt;x&lt;/b&gt;" in page.raw
    collapsed = [d for d in block.find_all("details") if "THE SEAT INSTRUCTIONS" in d.text()]
    assert collapsed, "the instructions are not in a collapsed block"


def test_1025_a_trace_whose_last_line_is_torn(tmp_path):
    """A trace whose last line — the response row — is torn: the tolerant reader drops and
    counts it, the block shows "1 unreadable rows" and "no response recorded", the call's cost
    vanishes from the sum and the stage sum says so — "partial — 2 of 3 calls priced" (J13b).
    """
    ep = E.sample_episode(tmp_path)
    trace = ep.dir / "wire_logs" / "questioner_c_trace.jsonl"
    lines = trace.read_text(encoding="utf-8").splitlines()
    trace.write_text(lines[0] + "\n" + lines[1][: len(lines[1]) // 2], encoding="utf-8")
    page = render(ep)
    block = page.text_of("tx-questioner_c_trace")
    assert "1 unreadable rows" in block, block
    assert "no response recorded" in block, block
    questioner = page.text_of("stage-questioner")
    assert "$0.7500" in questioner, questioner
    assert "partial — 2 of 3 calls priced" in questioner, questioner


def test_1025_comparator_trace_present_but_empty(tmp_path):
    """An empty comparator trace file is listed by stem with "0 rows" in the review stage and
    prices nothing: the review row still reads "no model calls" and the total is unchanged
    (J13b).
    """
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "comparator:1", raw="")
    page = render(ep)
    review = page.text_of("stage-review")
    assert "comparator_1_trace" in review, review
    assert "0 rows" in review, review
    assert "no model calls" in review, review
    assert S.total_cost in page.text_of("stage-timing")


def test_1025_six_transcript_streams_and_one_set_of_controls(tmp_path):
    """Six transcript streams on one page: either no search / type / error controls at all, or
    one control set per stream scoped inside that stream's block — never one page-wide set that
    silently drives only the first stream (J13c).
    """
    page = render(E.sample_episode(tmp_path))
    streams = page.elements(cls="tx-stream")
    assert len(streams) == 6, len(streams)
    searches = page.elements(cls="tx-search")
    assert len(searches) in (0, len(streams)), len(searches)
    for control in searches:
        holder = control.ancestor_with_id("tx-")
        assert holder is not None, "a control outside its stream"
        assert holder.find_all(cls="tx-search") == [control], "a control outside its stream"


def test_1025_a_hostile_wire_logs_trace_stem(tmp_path):
    """A `wire_logs/*_trace.jsonl` stem built to break out of its `id="tx-…"` attribute never
    becomes an attribute at all: the stem is grammar-gated through `_safe_id` like every other
    filename-derived id on the page (`world-`/`leads-`/`f-`), so a stem outside the run-id
    alphabet renders as an "unnameable entry" line naming the stem as text, with no `tx-` id
    and no stream — and no element on the page carries an `onmouseover` attribute (J5,
    adversary finding 2; review of PR #1042). Positive control: a well-formed stem keeps its
    stream and its id.
    """
    ep = E.sample_episode(tmp_path)
    stem = 'questioner_hostile" onmouseover=alert(1) x="'
    E.write_trace(ep.dir, stem, reply="THE HOSTILE STREAM'S REPLY")
    page = render(ep)
    assert not [i for i in page.ids_with("tx-") if "hostile" in i], page.ids_with("tx-")
    assert not [n for n in page.root.descendants() if "onmouseover" in n.attrs]
    unnameable = [n for n in page.elements(cls="unnameable") if "hostile" in n.text()]
    assert len(unnameable) == 1, [n.text() for n in page.elements(cls="unnameable")]
    assert "wire log" in unnameable[0].text()
    assert "THE HOSTILE STREAM'S REPLY" not in page.text_of("stage-questioner")
    assert "tx-questioner_b_trace" in page.by_id



def test_1025_timing_json_lists_the_same_step_twice_or_out_of_launch_order(tmp_path):
    """A repeated step renders every entry it has — "2 entries", wall from that step's first
    start to its last end — the header wall is min(start)–max(end) over all entries, and the
    table stays in `STEPS` order however the document orders its entries (J15).
    """
    ep = E.sample_episode(tmp_path)
    steps = E.six_steps()
    steps.append(("staging", "2026-09-09T10:20:00Z", "2026-09-09T10:21:00Z"))
    E.write_timing(ep.dir, list(reversed(steps)))
    page = render(ep)
    timing = page.text_of("stage-timing")
    assert _ordered(timing, *ST.EXPECTED_STEPS), timing
    row = timing[timing.index("staging"):timing.index("review")]
    assert "2 entries" in row, row
    assert "19m00s" in row, row
    assert "21m00s" in page.text, "the header wall is not min(start)–max(end)"


def test_1025_a_result_event_that_is_forged_or_misplaced(tmp_path):
    """A result event with a string, `None`, NaN or negative `total_cost_usd` reads "unusable
    result event" with no dollar figure — never coerced, never a raise; only the LAST row is a
    result event, so an earlier `type: result` row followed by another row is not one and the run
    reads "no result event" (J17). `None` is its own case, not just a variant of the string arm:
    `isinstance(None, (int, float))` is `False` for the same reason the string arm is, but a
    caller that gated on `cost is not None` first (a plausible near-miss) would let this one
    through to a bare arithmetic op on `None` — the spec adversary's own probe caught exactly
    this shape (J17 finding, PR #1042).
    """
    ep = E.sample_episode(tmp_path)
    for forged in ("12.5", None, math.nan, -3.0):
        E.write_tool_trace(ep.run(E.GRADED_WORLD), [E.result_event(cost=forged)])
        page = render(ep)
        runs = page.text_of("stage-runs")
        assert "unusable result event" in runs, (forged, runs)
        assert "$12.5" not in page.text
        assert "$-3" not in page.text
        assert "nan" not in page.text.lower()
        assert f"${S.run_cost[E.CONTROL]:.4f}" in runs
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [
        E.result_event(cost=7.77), {"type": "assistant", "message": {"content": []}}])
    runs = render(ep).text_of("stage-runs")
    assert "no result event" in runs, runs
    assert "$7.77" not in runs, runs


def test_1025_a_result_event_with_no_total_cost_usd_key_at_all(tmp_path):
    """A result event that never carries `total_cost_usd` (not merely a null value — the key
    itself absent, as a truncated or hand-rolled writer might leave it) reads "unusable result
    event" the same as every other unusable shape, through the same `.get(...)` default rather
    than a `KeyError` (J17 finding, PR #1042).
    """
    ep = E.sample_episode(tmp_path)
    row = E.result_event()
    del row["total_cost_usd"]
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [row])
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert "unusable result event" in runs, runs
    assert f"${S.run_cost[E.CONTROL]:.4f}" in runs


def test_1025_a_symlinked_tool_trace_in_a_run_dir(tmp_path):
    """A `tool_trace.jsonl` that is a symlink is refused on the lstat screen: the run's cost row
    reads "no result event (refused)" and the link's target is never read — its cost appears
    nowhere (J17, F18).
    """
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside-trace.jsonl"
    outside.write_text(json.dumps(E.result_event(cost=8.88)) + "\n", encoding="utf-8")
    E.plant_link(ep.run(E.GRADED_WORLD) / "tool_trace.jsonl", outside)
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert "no result event (refused)" in runs, runs
    assert "$8.88" not in page.text, runs
    assert f"${S.run_cost[E.CONTROL]:.4f}" in runs


# ---------------------------------------------------------------------------------------
# The review of PR #1042 — a priced row is finite and non-negative; one digit alphabet
# ---------------------------------------------------------------------------------------


def test_1025_a_usage_block_with_a_negative_or_overflowing_count_is_unpriced(tmp_path):
    """A wire-log `usage` block is box-writable: token counts of `-50000000` and `1e999` priced
    straight into tile 4 and the stages total as `$-146.7500` / `$inf` while the chip beside
    the row already said "unpriced". `_priced` now answers `None` for a cost that is not a
    finite non-negative number — the same gate `_result_event` puts on `total_cost_usd`."""
    ep = E.sample_episode(tmp_path)
    rows = E.trace_rows("questioner:neg")
    rows[1]["usage"]["input_tokens"] = -50_000_000
    E.write_trace(ep.dir, "questioner:neg", rows)
    rows = E.trace_rows("questioner:inf")
    rows[1]["usage"]["input_tokens"] = 1e999
    E.write_trace(ep.dir, "questioner:inf", rows)
    page = render(ep)
    for stem in ("tx-questioner_neg_trace", "tx-questioner_inf_trace"):
        assert "unpriced" in page.text_of(stem), page.text_of(stem)
    stages = page.text_of("sec-stages")
    assert "$-" not in stages, stages
    assert "$inf" not in stages, stages
    assert "$nan" not in stages, stages
    assert "$-" not in page.text_of("sec-verdict")
    assert E.SAMPLE.total_cost in page.text_of("sec-verdict"), "positive control: the sample total"


def test_1025_a_big_integer_literal_is_that_fields_own_absence(tmp_path):
    """`json.loads` reads a 400-digit numeric literal as a Python int, not `inf` — and
    `math.isfinite(<that int>)` and `<that int> * <rate>` both raise `OverflowError`, which no
    gate caught: one box-writable digit string in a result event's `total_cost_usd`, a response
    row's `duration_ms` or a `usage` count took the whole page down (d01: only `family.yaml` is
    fatal). Each is now that field's own absence — "unusable result event", no wall on the
    call, "unpriced" — through the one coercer every numeric read shares (review of PR #1042)."""
    ep = E.sample_episode(tmp_path)
    huge = 10 ** 400
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [E.result_event(cost=huge)])
    rows = E.trace_rows("questioner:huge")
    rows[1]["usage"]["input_tokens"] = huge
    E.write_trace(ep.dir, "questioner:huge", rows)
    E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:1", duration_ms=huge)
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert "unusable result event" in runs, runs
    assert "unpriced" in page.text_of("tx-questioner_huge_trace")
    assert f"tx-judge_{E.GRADED_WORLD}_1_trace" in page.ids
    assert str(huge)[:20] not in page.text
    assert f"${S.run_cost[E.CONTROL]:.4f}" in runs, "positive control: a sibling still priced"


def test_1025_a_sum_of_finite_values_that_overflows_reads_the_dash(tmp_path):
    """Each row is gated finite, but the SUM is not: two result events at `1e308` add to `inf`
    and tile 4 read `$inf` — the exact string the per-row test forbids — while two response
    rows at `1e308 ms` summed to a wall `fmt_duration` could not `int()`, and the page was not
    written at all. The formatters answer a non-finite total with the same dash a missing value
    gets, so a total is gated where it is printed, not only where its addends are read (review
    of PR #1042)."""
    ep = E.sample_episode(tmp_path)
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [E.result_event(cost=1e308)])
    E.write_tool_trace(ep.run(E.CONTROL), [E.result_event(cost=1e308)])
    for draw in (1, 2):
        E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:{draw}", duration_ms=1e308)
    page = render(ep)
    verdict = page.text_of("sec-verdict")
    assert "$inf" not in verdict, verdict
    assert "$nan" not in verdict, verdict
    stages = page.text_of("sec-stages")
    assert "inf" not in stages.lower(), stages
    assert "$1000000" in page.text_of("stage-runs"), "positive control: each finite row prints"


def test_1025_a_judge_stem_with_a_non_ascii_digit_is_unattributed_not_a_draw(tmp_path):
    """`draws_on_disk_report` holds a draw stem to ASCII digits (the F-7 decision: `'١'` is
    UNDECODABLE); the transcript router must read the same alphabet. Before, `str.isdigit`
    admitted the Arabic-Indic digit, so `judge_<label>_١_trace` rendered as a second block of
    that world's draws and never reached the unattributed list."""
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:١", prompt="an odd-digit draw")
    page = render(ep)
    order = _tx_order(page, "stage-judge")
    assert f"tx-judge_{E.GRADED_WORLD}_١_trace" not in order, order
    assert "unattributed traces" in page.text_of("sec-stages")
    assert f"judge_{E.GRADED_WORLD}_١_trace" in page.text_of("sec-stages")
    assert f"tx-judge_{E.GRADED_WORLD}_0_trace" in order  # positive control
