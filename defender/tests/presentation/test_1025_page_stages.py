"""#1025 — the stages section: the stage table, the two clocks, costs from traces and result events,
and the transcript blocks."""
from __future__ import annotations

import json
import math
import time

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.presentation import test_1025_stage_timing as ST
from defender.tests.support.learning.core import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
LOWER_BOUND = f"≈ {S.lower_bound} lower bound on wall: model calls + longest world"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def visualize_episode():
    """The target module, `defender.presentation.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(runs, <episode id>)` — the real entry point — then
    the page it wrote, parsed."""
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


def test_1025_the_stage_table_has_one_row_per_step_runs_expanded_per_run_dir_wall_only_rows_and_a_total_that_says_what_it_excludes(
        tmp_path):
    page = render(E.sample_episode(tmp_path))
    timing = page.text_of("stage-timing")
    assert _ordered(timing, *ST.EXPECTED_STEPS), timing
    runs = page.text_of("stage-runs")
    for label in E.WORLDS:
        assert _ordered(runs, label, f"${S.run_cost[label]:.4f}"), (label, runs)
    for wall in ("10m00s", "3m00s", "5m00s"):
        assert wall in runs, (wall, runs)
    assert timing.count("no model calls") == 2, timing
    assert S.total_cost in timing, timing
    assert "gather subagents" in timing, timing


def test_1025_without_timing_json_the_axis_is_model_time_with_a_labelled_lower_bound_and_with_it_the_launchers_wall_per_step(
        tmp_path):
    """Sample (no `timing.json`): the wall column is empty with a one-line reason naming the absent
    record, the header reads "≈ 16m00s lower bound on wall: model calls +."""
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert LOWER_BOUND in page.one("header").text() or LOWER_BOUND in stages, stages
    assert "timing.json" in stages or "no timing record" in stages, stages
    assert "model-call time" in stages, stages

    E.write_timing(ep.dir, E.every_step())
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert stages.count("1m00s") >= len(ST.EXPECTED_STEPS), stages
    assert "9m00s" in page.text, stages
    assert LOWER_BOUND not in page.text, stages
    assert "model-call time" not in stages, stages
    assert "not on the record" not in stages

    E.write_timing(ep.dir, E.every_step()[:3])
    stages = render(ep).text_of("sec-stages")
    assert stages.count("1m00s") >= 3, stages
    assert stages.count("not on the record") >= len(ST.EXPECTED_STEPS) - 3, stages


def test_1025_stage_costs_sum_response_row_usage_and_each_runs_result_event_and_a_run_with_no_trace_shows_no_cost_not_zero(
        tmp_path):
    """Sample questioner cost $1.0500 over 3 traces / 2m00s, judge $1.5000 over 3 traces / 4m00s,
    worlds $1.0000."""
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
    """Sample: `tx-questioner_trace`, `tx-questioner_b_trace`, `tx-questioner_c_trace` under the
    questioner stage; `tx-judge_family_0_trace` first then the two world draws."""
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for stem in ("questioner_trace", "questioner_b_trace", "questioner_c_trace"):
        assert _stage_of(page, f"tx-{stem}") == "stage-questioner", stem
    judge_blocks = _tx_order(page, "stage-judge")
    assert judge_blocks[0] == f"tx-judge_{E.FAMILY}_0_trace", judge_blocks
    assert set(judge_blocks) == {f"tx-judge_{E.FAMILY}_0_trace", f"tx-judge_{T.fixture_world_id(E.PASSTHROUGH_WORLD)}_0_trace",
                                 f"tx-judge_{T.fixture_world_id(E.GRADED_WORLD)}_0_trace"}, judge_blocks
    family = page.text_of(f"tx-judge_{E.FAMILY}_0_trace")
    assert f"framed prompt for {E.FAMILY}" in family, family
    assert "reply of" not in family, family
    assert "kimi-k3" in family, family
    assert "100,000" in family or "100000" in family, family
    assert "2m00s" in family, family
    entries = page.section(f"tx-judge_{E.FAMILY}_0_trace").find_all(cls="tx-entry")
    assert len(entries) == 1, [e.text() for e in entries]

    E.write_framed(ep.dir, f"judge:{T.fixture_world_id(E.GRADED_WORLD)}:0", prompt="P", reply=None, failure="the call FAILED-MARKER")
    assert "the call FAILED-MARKER" in render(ep).text_of(f"tx-judge_{T.fixture_world_id(E.GRADED_WORLD)}_0_trace")

    launch = ST._launch(tmp_path)
    launched = E.read_page(launch.episode_dir)
    framed = sorted(p.name for p in (launch.episode_dir / "wire_logs").glob("judge_*_framed_trace.jsonl"))
    assert framed, "the control failed: no framed file"
    for name in framed:
        stem = name[: -len("_framed_trace.jsonl")] + "_trace"
        block = launched.text_of(f"tx-{stem}")
        row = json.loads((launch.episode_dir / "wire_logs" / name).read_text(encoding="utf-8"))
        assert " ".join(row["prompt"][:60].split()) in block, (stem, block[:200])
        assert " ".join((row["reply"] or "")[:40].split()) in block, (stem, block[:200])


def test_1025_what_the_header_wall_covers(tmp_path):
    """With `timing.json` present the header wall is labelled as the launcher's wall from the first
    step's `started_at` to the last step's `ended_at` (9m00s) ."""
    ep = E.sample_episode(tmp_path, timing=True)
    page = render(ep)
    text = page.one("header").text() + " " + page.text_of("sec-stages")
    assert "9m00s" in text, text
    lowered = text.lower()
    assert "prime" in lowered, text
    assert "gaps" in lowered, text


def test_1025_the_runs_row_has_two_clocks(tmp_path):
    """The `runs` row shows the launcher's RUNS-step wall (1m00s from `timing.json`) labelled as the
    launcher's."""
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


def test_1025_a_trace_with_a_request_row_and_no_response_row(tmp_path):
    """A trace with a request row and no response row renders the request with "no response
    recorded"."""
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
    """A judge trace without its `_framed` twin renders its block's request from the plain trace's
    request row ."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "wire_logs" / f"judge_{T.fixture_world_id(E.GRADED_WORLD)}_0_framed_trace.jsonl").unlink()
    E.write_trace(ep.dir, f"judge:{T.fixture_world_id(E.GRADED_WORLD)}:0", prompt="PLAIN-PROMPT <b>x</b>",
                  instructions="PLAIN-INSTRUCTIONS", usage=S.judge_usage[2],
                  duration_ms=float(S.judge_ms[2]))
    page = render(ep)
    block = page.text_of(f"tx-judge_{T.fixture_world_id(E.GRADED_WORLD)}_0_trace")
    assert "PLAIN-PROMPT <b>x</b>" in block, block
    assert "PLAIN-INSTRUCTIONS" in block, block
    assert "&lt;b&gt;x&lt;/b&gt;" in page.raw


def test_1025_a_framed_trace_row_carries_a_failure_field_instead_of_a_reply(tmp_path):
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, f"judge:{T.fixture_world_id(E.GRADED_WORLD)}:0", response=False)
    E.write_framed(ep.dir, f"judge:{T.fixture_world_id(E.GRADED_WORLD)}:0", prompt="FRAMED-P", reply=None,
                   failure="did not complete: <TimeoutError>")
    page = render(ep)
    block = page.text_of(f"tx-judge_{T.fixture_world_id(E.GRADED_WORLD)}_0_trace")
    assert "FRAMED-P" in block, block
    assert "did not complete: <TimeoutError>" in block, block
    assert "$" not in block
    assert "&lt;TimeoutError&gt;" in page.raw


def test_1025_trace_prompt_or_reply_contains_a_literal_pre_or_script_close_tag(tmp_path):
    """Every prompt and reply renders through `pre_text_untrusted`, so a literal `</pre>` or
    `</script>` appears as text (`&lt;/pre&gt;`) and closes nothing."""
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


def test_1025_a_trace_whose_last_line_is_torn(tmp_path):
    """A trace whose last line — the response row — is torn: the tolerant reader drops and counts
    it, the block shows "1 unreadable rows" and "no response recorded", the call's."""
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


def test_1025_a_hostile_wire_logs_trace_stem(tmp_path):
    """A `wire_logs/*_trace.jsonl` stem built to break out of its `id="tx-…"` attribute never
    becomes an attribute at all."""
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


def test_1025_a_result_event_that_is_forged_or_misplaced(tmp_path):
    """A result event with a string, `None`, NaN or negative `total_cost_usd` reads "unusable result
    event" with no dollar figure ."""
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


def test_1025_a_symlinked_tool_trace_in_a_run_dir(tmp_path):
    """A `tool_trace.jsonl` that is a symlink is refused on the lstat screen."""
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside-trace.jsonl"
    outside.write_text(json.dumps(E.result_event(cost=8.88)) + "\n", encoding="utf-8")
    E.plant_link(ep.run(E.GRADED_WORLD) / "tool_trace.jsonl", outside)
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert "no result event (refused)" in runs, runs
    assert "$8.88" not in page.text, runs
    assert f"${S.run_cost[E.CONTROL]:.4f}" in runs


def test_1025_a_usage_block_with_a_negative_or_overflowing_count_is_unpriced(tmp_path):
    """A wire-log `usage` block is box-writable."""
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
