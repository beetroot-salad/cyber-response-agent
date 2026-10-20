"""#1025 (PR #1042 review, fifth pass) — a fact is decided where it is produced, once."""
from __future__ import annotations

import contextlib
import inspect
import os

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")

S = E.SAMPLE


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def visualize_episode():
    return E.page_module()


def render(ep) -> E.Page:
    return E.render(ep, module=visualize_episode())


def _world(page: E.Page, label: str) -> str:
    return page.text_of(f"world-{label}")


def test_1025_a_short_relative_episode_dir_name_scrubs_only_itself(tmp_path):
    """Rendered from `re` — a directory named with a substring of `report.md` and `read` — the
    report slot's refusal still says `report.md` and `could not be read`, whole: no scrub runs
    over the sentence at all (#1049: the loader's `_sentence` is gone — the reader formats the
    relative name `worlds/<w>/report.md` at its source and never holds the root, so a short
    relative spelling of the root has nothing to leak from and nothing to be cut out of a
    word). Before, the same page read "<episode>port.md could not be <episode>ad" (review of
    PR #1042). Positive control: the root's spelling is absent from the page."""
    ep = E.sample_episode(tmp_path)
    copy = E.copy_episode(ep, tmp_path / "re" / ep.dir.name)
    short = copy.dir
    (short / "worlds" / T.world_id(short, E.GRADED_WORLD) / "report.md").unlink()
    (short / "worlds" / T.world_id(short, E.GRADED_WORLD) / "report.md").mkdir()
    with contextlib.chdir(tmp_path):
        page = render(short)
    world = _world(page, E.GRADED_WORLD)
    assert "report.md could not be read" in world, world
    assert "<episode>port" not in world, world
    assert "<episode>ad" not in world, world
    assert f"worlds/{T.fixture_world_id(E.GRADED_WORLD)}/report.md" in world, world
    # said bare — never as a quoted filename cut down from an absolute path
    assert f"'worlds/{T.fixture_world_id(E.GRADED_WORLD)}/report.md'" not in world, world
    assert "re/worlds" not in page.raw


def test_1025_the_runs_launcher_line_and_the_runs_row_show_one_wall(tmp_path):
    """A repeated `runs` step whose FIRST entry is inverted and whose second spans four minutes."""
    ep = E.sample_episode(tmp_path)
    steps = [s for s in E.every_step() if s[0] != "runs"]
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


def test_1025_the_stage_table_reads_the_role_costs_the_model_decided(tmp_path):
    """The verdict tile's total, the header's lower bound and the stage table's per-role rows are
    one computation."""
    module = visualize_episode()
    ep = E.sample_episode(tmp_path)
    loaded = E.load_episode(ep.dir, module=module)
    assert set(loaded.role_costs) == {"questioner", "judge"}
    assert f"${loaded.role_costs['questioner'].cost:.4f}" == S.questioner_cost
    assert f"${loaded.role_costs['judge'].cost:.4f}" == S.judge_cost
    render_src = inspect.getsource(module._render_stages)
    assert "role_cost(" not in render_src
    assert "comparator_cost(" not in render_src


def test_1025_a_framed_only_judge_trace_naming_no_roster_label_is_listed_as_unattributed(tmp_path):
    """A launcher-produced episode writes only the framed twin for a judge call."""
    ep = E.sample_episode(tmp_path)
    E.write_framed(ep.dir, "judge:zz_gone:0", prompt="a world removed after a re-grade")
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "unattributed traces" in stages, stages
    assert "judge_zz_gone_0_trace" in stages, stages
    assert "tx-judge_zz_gone_0_trace" not in page.by_id



def test_judge_trace_uuid_scope_is_shared_by_blocks_and_unattributed_list(tmp_path):
    """Declared UUID traces route once; unknown scopes stay separate from recorded draws."""
    ep = E.sample_episode(tmp_path)
    world_id = T.world_id(ep.dir, E.GRADED_WORLD)
    unknown_id = T.fixture_world_id("unknown_trace_world")
    grade_only_id = T.fixture_world_id("grade_only")
    grade = E.sample_grade()
    grade["worlds"].append(E.world_row("grade_only", declared="benign"))
    E.write_judge(ep.dir, grade)
    scopes = [(world_id, 0), ("family", 0), (world_id, 9),
              (unknown_id, 0), (grade_only_id, 0), ("grade_only", 0)]
    for scope, draw in scopes:
        E.write_framed(ep.dir, f"judge:{scope}:{draw}", prompt=f"scope {scope} draw {draw}")
    page = render(ep)
    blocks = [node.id for node in page.section("stage-judge").find_all(cls="tx-stream")]
    assert blocks[0] == "tx-judge_family_0_trace"
    assert f"tx-judge_{world_id}_0_trace" in blocks
    assert f"scope {world_id} draw 0" in page.text_of(f"tx-judge_{world_id}_0_trace")
    unmatched = page.one(cls="st-unattributed").text()
    assert f"judge_{world_id}_0_trace" not in unmatched
    assert "judge_family_0_trace" not in unmatched
    assert f"judge_{world_id}_9_trace" not in unmatched
    for scope in (unknown_id, grade_only_id, "grade_only"):
        assert f"judge_{scope}_0_trace" in unmatched
        assert f"tx-judge_{scope}_0_trace" not in page.by_id
    assert f"tx-judge_{world_id}_9_trace" not in page.by_id


def test_1025_the_draw_read_totals_count_every_directory_the_world_sections_count(tmp_path):
    """A world whose draw directory holds one unparsable document."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / f"{E.EPISODE_ID}-orphan").mkdir()
    orphan = T.fixture_world_id("orphan")
    E.plant_raw(ep.dir / "worlds" / orphan / "judge" / "0.yaml", b"- not: [a mapping")
    with pytest.raises(T.sym("runtime.branch._family", "FamilyError"), match="not declared"):
        render(ep)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc("orphan", role="B", axis="orphan fact"))
    T.write_family(ep.dir, manifest)
    (ep.dir / T.ROSTER_NAME).unlink()
    T.plant_roster(ep.dir)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row("orphan", declared="benign"))
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "1 draw documents unreadable" in _world(page, "orphan"), _world(page, "orphan")
    findings = page.text_of("sec-findings")
    assert "1 draw documents unreadable" in findings, findings


def test_1025_a_negative_duration_is_that_slots_own_absence(tmp_path):
    """A negative `duration_ms` off a box-writable trace is gated like a negative cost."""
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
    """A link planted at a questioner trace's own name is refused at load and SAID in its block ."""
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
    """A refusal sentence quotes the record's own bytes (a YAML error echoes the offending line), so
    it is rendered through `_uv` like every other record field ."""
    ep = E.sample_episode(tmp_path)
    hostile = "onerror=alert(1)"
    E.plant_raw(ep.dir / "judge.yaml", f"worlds:\n  - world: b\n   bad: {hostile}\n")
    E.plant_raw(ep.dir / "timing.json", f'{{"steps": [{{"x": "{hostile}"}}')
    E.plant_raw(ep.dir / "samples.yaml", f"- {hostile}\n  :")
    page = render(ep)
    assert "grade record unreadable" in page.text_of("sec-verdict")
    assert "onerror=" not in page.raw, "a record-derived sentence reached the page unsplit"
    assert hostile in page.text, page.text[:400]


@NOT_ROOT
def test_1025_an_unreadable_gather_summary_is_the_chains_own_sentence_for_the_judge_and_the_page(
        tmp_path):
    """`family.lead_chain` reads the gather summary through `read_guarded`."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    world = ep.world(E.GRADED_WORLD)
    summary = world / "gather_summaries" / "l-001.md"
    summary.chmod(0)
    try:
        chain = family.lead_chain(E.mod("_io").bind(ep.dir).under(f"worlds/{T.fixture_world_id(E.GRADED_WORLD)}"),
                                  "l-001", {}, leads=family.leads_by_id(world))
        page = render(ep)
    finally:
        summary.chmod(0o644)
    assert "gather_summaries/l-001.md could not be read" in chain["summary"], chain
    assert str(tmp_path) not in chain["summary"], chain
    leads = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "gather_summaries/l-001.md could not be read" in leads, leads
    assert "lead unreadable" not in leads, leads
    assert str(tmp_path) not in page.raw
