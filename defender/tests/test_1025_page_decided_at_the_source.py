"""#1025 (PR #1042 review, fifth pass) — a fact is decided where it is produced, once.

Every finding this module pins is one of two shapes the earlier passes kept meeting: a fact
computed twice (the step wall, the role costs, the draw-read totals, the judge-trace census)
so two surfaces of one page could disagree, or a guard applied at one site and not its
sibling (the refusal scrub, the `esc`/`_uv` split, the duration gate, the gather-summary
read). Each fix here moves the decision to its owner — the model at load, the reader in the
package — and the test asks the two surfaces to agree by construction.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")

S = E.SAMPLE


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def visualize_episode():
    return E.page_module()


def render(ep) -> E.Page:
    return E.render(ep, module=visualize_episode())


def _world(page: E.Page, label: str) -> str:
    return page.text_of(f"world-{label}")


# ---------------------------------------------------------------------------------------
# The refusal scrub is anchored to a path boundary
# ---------------------------------------------------------------------------------------


def test_1025_a_short_relative_episode_dir_name_scrubs_only_itself(tmp_path):
    """The loader takes the episode directory's spelling out of every refusal sentence
    (d05/x24). Rendered from `re` — a directory named with a substring of `report.md` and
    `read` — the report slot's refusal still says `report.md` and `could not be read`: the
    scrub matches the root only at a path boundary, never inside a word. Before, the same
    page read "<episode>port.md could not be <episode>ad" (review of PR #1042). Positive
    control: the root's real occurrence in the sentence is still gone."""
    ep = E.sample_episode(tmp_path)
    short = tmp_path / "re"
    ep.dir.rename(short)
    (short / "worlds" / E.GRADED_WORLD / "report.md").unlink()
    (short / "worlds" / E.GRADED_WORLD / "report.md").mkdir()
    with contextlib.chdir(tmp_path):
        page = render(Path("re"))
    world = _world(page, E.GRADED_WORLD)
    assert "report.md" in world, world
    assert "<episode>port" not in world, world
    assert "<episode>ad" not in world, world
    assert f"'worlds/{E.GRADED_WORLD}/report.md'" in world, world
    assert "re/worlds" not in page.raw


# ---------------------------------------------------------------------------------------
# One step wall, one role cost, one census — decided at load
# ---------------------------------------------------------------------------------------


def test_1025_the_runs_launcher_line_and_the_runs_row_show_one_wall(tmp_path):
    """A repeated `runs` step whose FIRST entry is inverted and whose second spans four
    minutes: the stage table's `runs` row and the launcher line under it both read the step's
    trusted span, 4m00s. Before, the launcher line read the first entry verbatim — "—" beside
    a row that said 4m00s, or 1m00s under 4m00s with the entries swapped (review of
    PR #1042, J15/p5)."""
    ep = E.sample_episode(tmp_path)
    steps = [s for s in E.six_steps() if s[0] != "runs"]
    steps += [("runs", "2026-09-09T10:20:00Z", "2026-09-09T10:19:00Z"),
              ("runs", "2026-09-09T10:21:00Z", "2026-09-09T10:25:00Z")]
    E.write_timing(ep.dir, steps)
    page = render(ep)
    timing = page.text_of("stage-timing")
    row = timing[timing.index("runs"):timing.index("judge")]
    assert "4m00s" in row, row
    assert "2 entries" in row, row
    launcher = page.one(cls="rn-launcher-wall").text()
    assert launcher == "4m00s launcher", launcher

    steps[-2], steps[-1] = steps[-1], steps[-2]
    E.write_timing(ep.dir, steps)
    page = render(ep)
    assert page.one(cls="rn-launcher-wall").text() == "4m00s launcher"
    assert "1m00s launcher" not in page.text_of("stage-runs")


def test_1025_no_grand_total_when_no_call_priced(tmp_path):
    """An episode with no runs, no judge traces and one questioner trace whose `model` the
    pricing table does not know has priced nothing: the questioner row reads "partial — 0 of
    1 calls priced" and there is NO grand-total line — not "$0.0000 — excludes…". `costed`
    is gated on priced calls, as the review row already was (review of PR #1042)."""
    ep = E.sample_episode(tmp_path, traces=False, runs=False)
    E.write_trace(ep.dir, "questioner", model="nobody/prices-this")
    page = render(ep)
    questioner = page.text_of("stage-questioner")
    assert "partial — 0 of 1 calls priced" in questioner, questioner
    assert page.elements(cls="st-total") == [], page.text_of("sec-stages")


def test_1025_the_stage_table_reads_the_role_costs_the_model_decided(tmp_path):
    """The verdict tile's total, the header's lower bound and the stage table's per-role rows
    are one computation: `_Episode.role_costs`, filled at load, is what the table renders —
    the renderer holds no second walk of the wire logs. Pinned structurally (the render
    function names no `role_cost` / `comparator_cost` call) and by value (the model's numbers
    are the table's)."""
    module = visualize_episode()
    ep = E.sample_episode(tmp_path)
    loaded = module.load_episode(ep.dir)
    assert set(loaded.role_costs) == {"questioner", "judge"}
    assert f"${loaded.role_costs['questioner'].cost:.4f}" == S.questioner_cost
    assert f"${loaded.role_costs['judge'].cost:.4f}" == S.judge_cost
    source = Path(module.__file__).read_text(encoding="utf-8")
    render_src = source[source.index("def _render_stages("):source.index("def _role_cost_text(")]
    assert "role_cost(" not in render_src
    assert "comparator_cost(" not in render_src


def test_1025_a_framed_only_judge_trace_naming_no_roster_label_is_listed_as_unattributed(tmp_path):
    """A launcher-produced episode writes only the framed twin for a judge call. One naming
    a label off the roster is neither a world's block nor the family's — so it is listed on
    the "unattributed traces" line exactly as a plain-file stranger is; before, the census
    walked plain files alone and the framed-only stranger vanished (review of PR #1042)."""
    ep = E.sample_episode(tmp_path)
    E.write_framed(ep.dir, "judge:zz_gone:0", prompt="a world removed after a re-grade")
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "unattributed traces" in stages, stages
    assert "judge_zz_gone_0_trace" in stages, stages
    assert "tx-judge_zz_gone_0_trace" not in page.by_id


def test_1025_the_draw_read_totals_count_every_directory_the_world_sections_count(tmp_path):
    """A world present only as a `runs/` directory (no manifest entry, no grade row) whose
    draw directory holds one unparsable document: its world section says "1 draw documents
    unreadable", and the findings section's total says the same — one directory, one count.
    Before, the totals summed the WALKED labels alone and omitted it (review of PR #1042)."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / f"{E.EPISODE_ID}-orphan").mkdir()
    E.plant_raw(ep.dir / "worlds" / "orphan" / "judge" / "0.yaml", b"- not: [a mapping")
    page = render(ep)
    assert "1 draw documents unreadable" in _world(page, "orphan"), _world(page, "orphan")
    findings = page.text_of("sec-findings")
    assert "1 draw documents unreadable" in findings, findings


# ---------------------------------------------------------------------------------------
# Guards applied at the seam, on every sibling
# ---------------------------------------------------------------------------------------


def test_1025_a_negative_duration_is_that_slots_own_absence(tmp_path):
    """A negative `duration_ms` off a box-writable trace is gated like a negative cost: the
    control's result event with `duration_ms: -600000` contributes no wall, so the worlds'
    wall range spans the other two runs (3m00s–5m00s) and the lower bound reads over the
    longest REAL world; a questioner response row with a negative duration adds nothing to
    the questioner wall. Before, the range read "—–5m00s" and the estimate went backwards
    (review of PR #1042)."""
    ep = E.sample_episode(tmp_path)
    E.run_dir(ep.dir, E.CONTROL, cost=0.40, duration_ms=-600_000)
    page = render(ep)
    four = page.text_of("vd-tile-4")
    assert "3m00s–5m00s" in four, four
    assert "≈ 11m00s lower bound" in four, four
    assert "—–" not in four, four

    E.write_trace(ep.dir, "questioner", usage=(100_000, 10_000), duration_ms=-5_000_000.0)
    questioner = page_text = render(ep).text_of("stage-questioner")
    assert "$" in page_text, questioner
    assert "—" not in questioner.split("·")[2], questioner


def test_1025_a_refused_wire_trace_is_named_as_refused(tmp_path):
    """A link planted at a questioner trace's own name is refused at load and SAID in its
    block — "trace refused" — never the "no response recorded" a benign empty call reads
    as: a planted alias must not look like nothing happened (review of PR #1042). The stage
    row still counts it as a trace that did not price."""
    ep = E.sample_episode(tmp_path)
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    E.plant_link(ep.dir / "wire_logs" / "questioner_trace.jsonl", target)
    page = render(ep)
    block = page.text_of("tx-questioner_trace")
    assert "trace refused" in block, block
    assert "no response recorded" not in block, block
    assert "partial — 2 of 3 calls priced" in page.text_of("stage-questioner")


def test_1025_record_derived_refusals_take_the_untrusted_escape(tmp_path):
    """A refusal sentence quotes the record's own bytes (a YAML error echoes the offending
    line), so it is rendered through `_uv` like every other record field — the page's own O9
    rule — and a planted `onerror=alert(1)` inside a mis-indented `judge.yaml` value reaches
    the verdict band split across the element boundary, never as the literal substring.
    Same for `timing.json` and the records section's four slots."""
    ep = E.sample_episode(tmp_path)
    hostile = "onerror=alert(1)"
    E.plant_raw(ep.dir / "judge.yaml", f"worlds:\n  - world: b\n   bad: {hostile}\n")
    E.plant_raw(ep.dir / "timing.json", f'{{"steps": [{{"x": "{hostile}"}}')
    E.plant_raw(ep.dir / "samples.yaml", f"- {hostile}\n  :")
    page = render(ep)
    assert "grade record unreadable" in page.text_of("sec-verdict")
    assert "onerror=" not in page.raw, "a record-derived sentence reached the page unsplit"
    assert hostile in page.text, page.text[:400]


def test_1025_the_control_role_is_the_launchers_own_spelling():
    """The control world is the manifest row whose `role` is `BASE_ROLE`, imported from the
    launcher's family module — never a respelled `"A"` the page would keep after a rename."""
    module = visualize_episode()
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert '== "A"' not in source
    assert "BASE_ROLE" in source
    assert module.BASE_ROLE == E.mod("runtime.branch._family").BASE_ROLE


def test_1025_every_result_event_state_has_a_sentence():
    """`_ResultEvent.text` answers every state the loader can produce, `ok` included — a
    display helper must not be the one thing on the page that can raise (d01)."""
    module = visualize_episode()
    for state in ("absent", "refused", "none", "unusable", "ok"):
        assert isinstance(module._ResultEvent(None, None, state).text, str)


# ---------------------------------------------------------------------------------------
# The shared reader owns the gather-summary read
# ---------------------------------------------------------------------------------------


@NOT_ROOT
def test_1025_an_unreadable_gather_summary_is_the_chains_own_sentence_for_the_judge_and_the_page(
        tmp_path):
    """`family.lead_chain` reads the gather summary through `read_guarded`: a mode-000
    `gather_summaries/<lead>.md` makes that lead's summary a sentence naming the world-relative
    file and the fault — returned, not raised — so the grading pass keeps its grade and the
    page shows the same chain. Neither carries the operator's absolute path. Before, the read
    was a bare `read_text`: the page caught the `PermissionError` at its call site and printed
    "lead unreadable", while the grade unwound whole (review of PR #1042)."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    world = ep.world(E.GRADED_WORLD)
    summary = world / "gather_summaries" / "l-001.md"
    summary.chmod(0)
    try:
        chain = family.lead_chain(world, "l-001", {}, leads=family.leads_by_id(world))
        page = render(ep)
    finally:
        summary.chmod(0o644)
    assert "gather_summaries/l-001.md could not be read" in chain["summary"], chain
    assert str(tmp_path) not in chain["summary"], chain
    leads = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "gather_summaries/l-001.md could not be read" in leads, leads
    assert "lead unreadable" not in leads, leads
    assert str(tmp_path) not in page.raw
