"""#1025 — the page decides each presentation question ONCE, in the model, and every surface reads the
answer (PR #1042 review, fourth pass)."""
from __future__ import annotations


import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
LOWER_BOUND = f"≈ {S.lower_bound} lower bound on wall: model calls + longest world"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def render(ep) -> E.Page:
    return E.render(ep, module=E.page_module())


def _inverted_steps() -> list[tuple[str, str, str]]:
    return [(step, ended, started) for step, started, ended in E.every_step()]


def _every_step_wall() -> str:
    """The wall `E.every_step()` spans: one minute per step, two minutes apart, from 10:00."""
    return f"{2 * (len(E.every_step()) - 1) + 1}m00s"


def test_1025_an_all_inverted_timing_record_is_unmeasured_on_every_surface(tmp_path):
    """Every row inverted: no trusted pair, so there is no wall. The stages header and the verdict
    tile BOTH fall back to the lower bound (before: the header did, the tile did."""
    ep = E.sample_episode(tmp_path)
    E.write_timing(ep.dir, _inverted_steps())
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "no timing record" not in stages, stages
    assert "no usable span" in page.text_of("stage-timing"), page.text_of("stage-timing")
    assert LOWER_BOUND in stages, stages
    assert LOWER_BOUND in page.text_of("vd-tile-4"), page.text_of("vd-tile-4")
    assert "timing record unreadable" not in stages


def test_1025_an_episode_whose_every_run_cost_nothing_still_owes_its_total(tmp_path):
    """Every result event prices its run at $0.0000 and no wire log exists."""
    ep = E.sample_episode(tmp_path, traces=False)
    for label in E.WORLDS:
        E.write_tool_trace(ep.run(label), [E.result_event(cost=0.0)])
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert page.elements(cls="rn-total"), runs
    assert page.elements(cls="st-total"), page.text_of("stage-timing")
    assert "$0.0000" in page.text_of("stage-timing")


@pytest.mark.parametrize(("plant", "sentence"), [
    ("unusable", "unusable result event"),
    ("absent", "no cost recorded"),
    ("none", "no result event"),
])
def test_1025_a_runs_result_state_reads_the_same_sentence_in_both_sections(tmp_path, plant, sentence):
    """The world section and the stages table show the same trace's state."""
    ep = E.sample_episode(tmp_path)
    trace = ep.run(E.GRADED_WORLD) / "tool_trace.jsonl"
    if plant == "unusable":
        E.write_tool_trace(ep.run(E.GRADED_WORLD), [E.result_event(cost=-3.0)])
    elif plant == "absent":
        trace.unlink()
    else:
        E.write_tool_trace(ep.run(E.GRADED_WORLD), [{"type": "assistant", "message": {"content": []}}])
    page = render(ep)
    world = page.text_of(f"world-{E.GRADED_WORLD}")
    runs = page.text_of("stage-runs")
    assert sentence in world, (plant, world)
    graded_row = [r.text() for r in page.elements(cls="rn-row") if E.GRADED_WORLD in r.text()]
    assert graded_row, (plant, runs)
    assert sentence in graded_row[0], (plant, runs)
    other = {"unusable result event", "no cost recorded", "no result event"} - {sentence}
    for wrong in other:
        # "no result event" is a prefix of "no result event (refused)" — none of these three
        # plants is a refusal, so the bare check is exact enough.
        assert wrong not in world.replace(sentence, ""), (plant, wrong, world)


def test_1025_a_manifest_id_that_names_no_token_reads_no_ledger_outside_the_episode(tmp_path):
    """`episode_id: ../../x` is an id the token builder refuses. Before, the model fell back to the
    raw id AS the token and joined it into `served/<token>.<label>.jsonl` — for."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["episode_id"] = "../../x"
    T.write_family(ep.dir, manifest)
    (ep.dir / "runs" / "stray").mkdir()
    outside = (ep.dir / "served" / ".." / ".." / "x.stray.jsonl").resolve()
    assert ep.dir.resolve() not in outside.parents or outside.parent == ep.dir.parent.resolve()
    outside.write_text("{torn\n{torn\n", encoding="utf-8")
    refused = E.sym("learning.judge", "JudgeRefused")
    with pytest.raises(refused, match=r"\.\./\.\./x") as caught:
        E.render_episode(ep.dir)
    assert "x.stray" not in str(caught.value), caught.value
    assert not ep.page.exists(), "a page was written for a manifest the reader refused"


def test_1025_a_runs_directory_wearing_a_worlds_label_is_sectioned_once(tmp_path):
    """`runs/<label>/` beside `runs/<ep>-<label>/`."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / E.GRADED_WORLD).mkdir()
    page = render(ep)
    dupes = sorted({i for i in page.all_ids if page.all_ids.count(i) > 1})
    assert dupes == [], dupes
    assert page.all_ids.count(f"world-{E.GRADED_WORLD}") == 1
    assert page.all_ids.count(f"leads-{E.GRADED_WORLD}") == 1
    assert "l-001" in page.text_of(f"leads-{E.GRADED_WORLD}")
    assert page.elements(cls="fr-shadowed-runs") == []
    assert "not sectioned twice" not in page.text
    assert f"Worlds ({len(E.WORLDS)})" in page.text_of("sec-worlds")


def test_1025_a_dropped_count_covers_only_the_draws_the_findings_walk_opens(tmp_path):
    """A bare `runs/<ep>-x` world — no manifest entry, no grade row — is a section with no findings:
    the walk never opens its draws. Its `dropped_findings: 4` was still summed."""
    ep = E.sample_episode(tmp_path)
    E.run_dir(ep.dir, "x")
    E.draw_document(ep.dir, "x", 0, E.draw_doc(
        findings=[E.finding(claim="one"), E.finding(claim="two")], dropped=4))
    page = render(ep)
    tile = page.text_of("vd-tile-3")
    assert "4 dropped" not in tile, tile
    assert "0 dropped" in tile, tile
    assert not [d for d in page.elements(cls="fr-dropped") if " of x:" in d.text()], \
        page.text_of("sec-findings")
    assert f"Worlds ({len(E.WORLDS)})" in page.text_of("sec-worlds")
    assert "world-x" not in page.by_id


def test_1025_a_finding_row_refuses_an_unknown_field():
    """`_Finding(clam=...)` raised nothing and rendered every row with no claim. A typo at any
    of the construction sites is now a `TypeError` at construction."""
    module = E.page_module()
    with pytest.raises(TypeError, match="clam"):
        module._Finding(row_id="f-x-0-0", clam="the claim")
    row = module._Finding(row_id="f-x-0-0", claim="the claim")
    assert row.claim == "the claim"
    assert row.topic is None


def test_1025_an_absent_archived_report_is_decided_after_the_guarded_read(tmp_path):
    """An absent `report.md` reads as the ABSENT STATE (`ReportRead.absent`."""
    family = E.mod("learning.judge.family")
    bound = E.mod("_io").bind(tmp_path)
    got = family.read_archived_report(bound, "report.md")
    assert got.disposition is None, got
    assert got.absent is True, got
    target = tmp_path / "elsewhere.md"
    target.write_text("---\ndisposition: malicious\n---\nnot this world's\n", encoding="utf-8")
    (tmp_path / "report.md").symlink_to(target)
    got = family.read_archived_report(bound, "report.md")
    assert got.disposition is None, got
    assert "aliased" in got.reason, got
    assert "not this world" not in got.body
    # Structurally, since the race itself cannot be staged: the reader never delegates to
    # `read_report` on any branch.
    assert "read_report" not in family.read_archived_report.__code__.co_names
