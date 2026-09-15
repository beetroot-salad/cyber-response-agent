"""#1025 — the page decides each presentation question ONCE, in the model, and every surface
reads the answer (PR #1042 review, fourth pass).

The episode model's docstring promised "everything a section renders, already typed" and
stopped short: it held the raw timing record, a bare cost float and a result-event state
string, and the three big render functions each finished the interpretation on their own —
"is there a real wall?", "was anything priced?", "what does this state read as?" — and
disagreed at the edges. Each test here plants one edge and asserts the surfaces agree.

Alongside: two per-site fallbacks that validated nothing (a token that fell back to the raw
id, and joined it into a path; a stray `runs/` directory allowed to wear a world's own label
and ids), a count read off a wider population than the split it heads, and a row type that
swallowed a misspelled field.
"""
from __future__ import annotations


import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
LOWER_BOUND = f"≈ {S.lower_bound} lower bound on wall: model calls + longest world"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def render(ep) -> E.Page:
    return E.render(ep, module=E.page_module())


def _inverted_six_steps() -> list[tuple[str, str, str]]:
    return [(step, ended, started) for step, started, ended in E.six_steps()]


# ---------------------------------------------------------------------------------------
# The clock: one `measured` bit for the header, the caption and the verdict tile
# ---------------------------------------------------------------------------------------


def test_1025_an_all_inverted_timing_record_is_unmeasured_on_every_surface(tmp_path):
    """Every row inverted: no trusted pair, so there is no wall. The stages header and the
    verdict tile BOTH fall back to the lower bound (before: the header did, the tile did not,
    keyed on the record merely being readable and non-empty), and the table's caption says
    what is true — the record is there and has no usable span — never "no timing record"."""
    ep = E.sample_episode(tmp_path)
    E.write_timing(ep.dir, _inverted_six_steps())
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "no timing record" not in stages, stages
    assert "no usable span" in page.text_of("stage-timing"), page.text_of("stage-timing")
    assert LOWER_BOUND in stages, stages
    assert LOWER_BOUND in page.text_of("vd-tile-4"), page.text_of("vd-tile-4")
    assert "timing record unreadable" not in stages


def test_1025_a_measured_record_repeats_no_fallback_on_the_tile(tmp_path):
    """The other side of the same bit: with a real wall the header carries the figure and the
    tile carries no fallback beside it."""
    page = render(E.sample_episode(tmp_path, timing=True))
    assert LOWER_BOUND not in page.text_of("vd-tile-4"), page.text_of("vd-tile-4")
    assert "11m00s" in page.text_of("sec-stages")
    assert "no usable span" not in page.text_of("stage-timing")


def test_1025_a_record_with_no_completed_step_reads_as_no_record(tmp_path):
    """`{"steps": []}` — an abort before the first step finished — is a legitimate record the
    reader answers with the same `[]` as an absent file, so the page cannot tell the two apart
    and says so with the absent sentence on every surface, consistently."""
    ep = E.sample_episode(tmp_path)
    E.write_timing(ep.dir, [])
    page = render(ep)
    assert "no timing record" in page.text_of("stage-timing")
    assert LOWER_BOUND in page.text_of("vd-tile-4")
    assert LOWER_BOUND in page.text_of("sec-stages")


# ---------------------------------------------------------------------------------------
# Cost: one `costed` flag, never the float's truthiness
# ---------------------------------------------------------------------------------------


def test_1025_an_episode_whose_every_run_cost_nothing_still_owes_its_total(tmp_path):
    """Every result event prices its run at $0.0000 and no wire log exists: the runs sub-total
    is rendered (a result event with a cost IS a priced run) and so is the grand total above
    it — before, the grand total was gated on `total_cost` being truthy, so a reader saw a
    runs total with no episode total."""
    ep = E.sample_episode(tmp_path, traces=False)
    for label in E.WORLDS:
        E.write_tool_trace(ep.run(label), [E.result_event(cost=0.0)])
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert page.elements(cls="rn-total"), runs
    assert page.elements(cls="st-total"), page.text_of("stage-timing")
    assert "$0.0000" in page.text_of("stage-timing")


def test_1025_an_episode_nothing_priced_owes_no_total_line(tmp_path):
    """And the same flag off: no result events, no traces — neither total line."""
    ep = E.sample_episode(tmp_path, traces=False, runs=False)
    page = render(ep)
    assert not page.elements(cls="rn-total")
    assert not page.elements(cls="st-total"), page.text_of("stage-timing")


# ---------------------------------------------------------------------------------------
# A run's result state reads as one sentence, wherever it is shown
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("plant", "sentence"), [
    ("unusable", "unusable result event"),
    ("absent", "no cost recorded"),
    ("none", "no result event"),
])
def test_1025_a_runs_result_state_reads_the_same_sentence_in_both_sections(tmp_path, plant, sentence):
    """The world section and the stages table show the same trace's state; each state has one
    sentence. Before, a present-but-unusable result read "no result event" in the world
    section and "unusable result event" in the stages table, and an absent trace read
    "no result event" in one and "no cost recorded" in the other."""
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


# ---------------------------------------------------------------------------------------
# Untrusted input is validated once, into a type — never fallen back on per site
# ---------------------------------------------------------------------------------------


def test_1025_a_manifest_id_that_names_no_token_reads_no_ledger_outside_the_episode(tmp_path):
    """`episode_id: ../../x` is an id the token builder refuses. Before, the model fell back
    to the raw id AS the token and joined it into `served/<token>.<label>.jsonl` — for a stray
    `runs/stray/` directory, `<episode>/served/../../x.stray.jsonl`, a file OUTSIDE the
    episode dir, whose malformed-row count the leads block then rendered. Now a refused id
    is no token: the leads block says the ledger cannot be named, and the outside file's
    contents never reach the page."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["episode_id"] = "../../x"
    T.write_family(ep.dir, manifest)
    (ep.dir / "runs" / "stray").mkdir()
    outside = (ep.dir / "served" / ".." / ".." / "x.stray.jsonl").resolve()
    assert ep.dir.resolve() not in outside.parents or outside.parent == ep.dir.parent.resolve()
    outside.write_text("{torn\n{torn\n", encoding="utf-8")
    page = render(ep)
    leads = page.text_of("leads-stray")
    assert "malformed" not in leads, leads
    assert "names no token" in leads, leads
    assert "x.stray" not in page.raw


def test_1025_a_runs_directory_wearing_a_worlds_label_is_sectioned_once(tmp_path):
    """`runs/<label>/` beside `runs/<ep>-<label>/`: the stray's roster label would be the
    world's own, so it was a second roster item under the same `world-`/`leads-` ids,
    silently overwriting the world's leads block. Now one item per label: every id on the
    page is unique, the world's own section and leads block render once, and the shadowed
    directory is named on the off-roster line rather than lost."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / E.GRADED_WORLD).mkdir()
    page = render(ep)
    dupes = sorted({i for i in page.all_ids if page.all_ids.count(i) > 1})
    assert dupes == [], dupes
    assert page.all_ids.count(f"world-{E.GRADED_WORLD}") == 1
    assert page.all_ids.count(f"leads-{E.GRADED_WORLD}") == 1
    assert "l-001" in page.text_of(f"leads-{E.GRADED_WORLD}")
    shadowed = page.one(cls="fr-shadowed-runs").text()
    assert E.GRADED_WORLD in shadowed, shadowed
    assert "not sectioned twice" in shadowed, shadowed
    assert f"Worlds ({len(E.WORLDS)})" in page.text_of("sec-worlds")


# ---------------------------------------------------------------------------------------
# One population for tile 3
# ---------------------------------------------------------------------------------------


def test_1025_a_dropped_count_covers_only_the_draws_the_findings_walk_opens(tmp_path):
    """A bare `runs/<ep>-x` world — no manifest entry, no grade row — is a section with no
    findings: the walk never opens its draws. Its `dropped_findings: 4` was still summed
    into tile 3's "dropped" while its two findings were counted nowhere, so the split did
    not sum to the total it headed. Now the dropped count is read off the same labels the
    findings are."""
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
    assert f"Worlds ({len(E.WORLDS) + 1})" in page.text_of("sec-worlds")


# ---------------------------------------------------------------------------------------
# A row type that refuses a misspelled field
# ---------------------------------------------------------------------------------------


def test_1025_a_finding_row_refuses_an_unknown_field():
    """`_Finding(clam=...)` raised nothing and rendered every row with no claim. A typo at any
    of the construction sites is now a `TypeError` at construction."""
    module = E.page_module()
    with pytest.raises(TypeError, match="clam"):
        module._Finding(row_id="f-x-0-0", clam="the claim")
    row = module._Finding(row_id="f-x-0-0", claim="the claim")
    assert row.claim == "the claim"
    assert row.topic is None


# ---------------------------------------------------------------------------------------
# The archived report's absent branch does not reopen the window
# ---------------------------------------------------------------------------------------


def test_1025_an_absent_archived_report_is_decided_after_the_guarded_read(tmp_path):
    """An absent `report.md` reads with `read_report`'s own "not found" sentence — but decided
    from the guarded read's refusal, never by handing the path to `read_report`, whose
    `is_file()` + `read_text` follow a link planted between the two."""
    family = E.mod("learning.judge.family")
    got = family.read_archived_report(tmp_path / "report.md")
    assert got.disposition is None, got
    assert "not found" in got.reason, got
    target = tmp_path / "elsewhere.md"
    target.write_text("---\ndisposition: malicious\n---\nnot this world's\n", encoding="utf-8")
    (tmp_path / "report.md").symlink_to(target)
    got = family.read_archived_report(tmp_path / "report.md")
    assert got.disposition is None, got
    assert "aliased" in got.reason, got
    assert "not this world" not in got.body
    # Structurally, since the race itself cannot be staged: the reader never delegates to
    # `read_report` on any branch.
    assert "read_report" not in family.read_archived_report.__code__.co_names
