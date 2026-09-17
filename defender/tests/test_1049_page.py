"""#1049 — the episode page (`scripts/visualize/visualize_episode.py`) over the bound readers.

O1 at the page boundary: no byte of `learning.html` names the directory the operator keeps
episodes in — as passed, as realpath, its parent, or the tree the archive was built in — and two
copies of one archive render byte-identical, with every arm in the readers' census planted at
once and NO scrub anywhere in the module (`_sentence` / `_root_pattern` are gone). O4: the page
distinguishes absent / present-unreadable / present-empty for each record off the reader's own
answer, with zero `entry_present` calls and no `artifact_dir` screen ahead of a reader — the
six listing/roster sites are the closed allow-list (D-V5).

Every arm is a real entry planted on the filesystem (`_record_1049`, `_episode_1025`); the page
is driven through `render_episode` (the real entry point); `judge.yaml` is written from the
rows `grade_family` computed over the same planted tree, so both `ungradable_reason` shapes
reach the page. Hard-link / fifo / mode-000 / symlinked-parent / dangling-parent arms are
planted PER COPY after `copy_episode` (copytree flattens a hard link and carries a symlink's
absolute target, g18); a hard link targets a scratch file, never a live record (RF-J5).

RED AGAINST BASE by construction: the readers name the root today and `_io.bind` does not
exist; every import goes through `mod()` per test.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
from pathlib import Path

import pytest
import yaml

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _record_1049 as R
from defender.tests import _triplet_947 as T

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _page():
    return E.page_module()


def _world(page: E.Page, label: str) -> str:
    return page.text_of(f"world-{label}")


def _leads(page: E.Page, label: str) -> str:
    return page.text_of(f"leads-{label}")


def _ledger_name(label: str) -> str:
    return f"served/{T.world_token(label)}.jsonl"


#: The two spare worlds the every-arm fixture rosters through their run dirs alone, so a
#: symlinked and a dangling `worlds/<w>` each get a section and a leads block.
LINKED_WORLD = "spare_link"
DANGLING_WORLD = "spare_dangle"


def _plant_shared_arms(built: E.Episode) -> None:
    """The arms planted in the BUILT tree, before copying: one instance of every arm that
    survives `copytree(symlinks=True)` — a symlink keeps its absolute target (into `built`,
    which is why `str(built)` is asserted absent), plain bytes copy as bytes."""
    E.plant_raw(built.dir / "review.yaml", R.UNDECODABLE)                 # read arm
    E.plant_raw(built.dir / "staged.yaml", "{\n  [")                     # parse arm
    E.plant_raw(built.dir / "provenance.json", '{"a": 1}')               # shape arm
    (built.dir / "samples.yaml").unlink()                                 # absent arm
    E.plant_link(built.dir / "timing.json", built.dir / "family.yaml")    # OSError-shaped, C-02
    E.plant_link(built.world(E.WITHHELD_WORLD) / "report.md", built.dir / "family.yaml")
    (built.dir / _ledger_name(E.WITHHELD_WORLD)).unlink()                 # absent ledger
    E.plant_link(built.dir / _ledger_name(E.CONTROL), built.dir / "family.yaml")  # aliased ledger
    withheld_summaries = built.world(E.WITHHELD_WORLD) / "gather_summaries"
    withheld_summaries.rename(built.world(E.WITHHELD_WORLD) / "summaries-real")
    E.plant_link(withheld_summaries, built.world(E.WITHHELD_WORLD) / "summaries-real")
    E.plant_link(built.world(E.CONTROL) / "gather_summaries" / "l-001.md", built.dir / "family.yaml")
    for label in (LINKED_WORLD, DANGLING_WORLD):
        E.run_dir(built.dir, label)


def _plant_per_copy_arms(copy: E.Episode) -> None:
    """The arms that must be planted per copy, after copying: a hard link (copytree flattens
    it) at the graded world's investigation.md, targeting a scratch file inside the copy; a
    symlinked and a dangling worlds/<w> (the link's target is inside THIS copy)."""
    R.plant_hard_link(copy.world(E.GRADED_WORLD) / "investigation.md",
                      copy.dir / "scratch" / "investigation-target.md")
    E.plant_link(copy.world(LINKED_WORLD), copy.world(E.CONTROL))
    E.plant_link(copy.world(DANGLING_WORLD), copy.world("nowhere-at-all"))


def _write_grade_over(copy: E.Episode) -> None:
    """`judge.yaml` written from the rows `grade_family` computes over the planted tree, so the
    record carries both `ungradable_reason` shapes: the reader's sentence (the hard-linked
    investigation) and `_missing_required_input`'s (the absent ledger). The review and samples
    records are handed over parsed, as the orchestration hands them (the planted review.yaml
    would otherwise refuse the whole pass, which is its contract)."""
    grade = R.family().grade_family(copy.dir, review={}, samples={})
    doc = E.sample_grade()
    doc["worlds"] = grade.worlds
    E.write_judge(copy.dir, doc)


def _every_arm(tmp_path: Path) -> tuple[E.Episode, E.Episode, E.Episode]:
    built = E.sample_episode(tmp_path, root=tmp_path / "build")
    _plant_shared_arms(built)
    one = E.copy_episode(built, tmp_path / "root-one" / "copy-one")
    two = E.copy_episode(built, tmp_path / "root-two" / "nested" / "renamed-two")
    for copy in (one, two):
        _plant_per_copy_arms(copy)
        _write_grade_over(copy)
    return built, one, two


# ---------------------------------------------------------------------------------------
# d-24 — no stat ahead of a reader, no scrub symbol
# ---------------------------------------------------------------------------------------


READER_SHAPED = ("_read_review", "_read_samples", "_read_staged", "_read_timing",
                 "_read_family_stamp", "_read_grade", "_strict_samples_reader",
                 "_load_world_archive", "_result_event")


def test_1049_the_page_module_has_no_stat_ahead_of_a_reader_and_no_scrub_symbol():
    """visualize_episode's AST has ZERO entry_present, artifact_dir or artifact_file calls
    ahead of a package or _io reader — none in the six _read_* record readers,
    _strict_samples_reader, _load_world_archive or _result_event, and none at all of
    entry_present anywhere (D-V5 is the closed allow-list of the six listing sites that
    remain) — no _sentence, _root_pattern or dataclasses.replace(report, reason=…), and family
    has no _without_path. Positive control: d-26 (every planted arm is said in its own slot).
    """
    page = _page()
    tree = R.module_tree(page)
    defined = R.defined_functions(tree)
    for gone in ("_sentence", "_root_pattern"):
        assert gone not in defined, f"{gone} is still defined"
        assert not hasattr(page, gone), f"{gone} is still an attribute of the page module"
    assert not hasattr(R.family(), "_without_path")
    calls = R.calls_by_function(tree, frozenset({"entry_present", "artifact_dir", "artifact_file"}))
    assert not any("entry_present" in c for c in calls.values()), calls
    for fn in READER_SHAPED:
        assert fn in defined, f"{fn} is gone from the page module"
        assert fn not in calls, (fn, calls.get(fn))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
            assert not any(kw.arg == "reason" for kw in node.keywords), "dataclasses.replace(report, reason=…) is still there"


# ---------------------------------------------------------------------------------------
# d-25 — the negative universal: no root in the page, byte-identical from two roots
# ---------------------------------------------------------------------------------------


def test_1049_an_episode_with_every_arm_planted_renders_no_root_and_byte_identically_from_two_roots(tmp_path):
    """The fixture plants, per copy after copy_episode: read/parse/shape/absent per
    episode-root reader (review.yaml undecodable, staged.yaml torn, provenance.json the wrong
    shape, samples.yaml absent); an absent ledger and an aliased ledger; a SYMLINKED
    worlds/<w> and a DANGLING worlds/<w'> (two spare worlds rostered by their run dirs); an
    OSError-shaped arm (a link) at timing.json and a hard link at the graded world's
    investigation (C-02, C-03: scratch target, RF-J5); a link at another world's report; a
    symlinked gather_summaries/ in one world and a symlinked summary in another; judge.yaml
    written from grade_family's rows over that tree (both ungradable_reason shapes). Asserts
    str(episode_dir), os.path.realpath(episode_dir), the EPISODES-BASE spelling
    str(episode_dir.parent) (the basename IS the episode id, which the title legitimately
    prints) and str(built) (a copied link keeps its absolute target) absent from learning.html
    for both copies, byte-identical (independently planted instances of one alias shape
    refuse byte-identically; enumeration order is stable) — with no scrub anywhere in the
    module (d-24). Rejected: the leads loader's bare `except Exception` is kept; facts_error's
    root-freedom is pinned HERE, not by an enumeration of what it can catch.
    """
    built, one, two = _every_arm(tmp_path)
    E.render(one)
    E.render(two)
    for copy in (one, two):
        text = copy.page.read_text(encoding="utf-8")
        for absent in (str(copy.dir), os.path.realpath(copy.dir), str(copy.dir.parent),
                       str(built.dir), str(tmp_path), "root-one", "copy-one", "renamed-two",
                       "nested", "build"):
            assert absent not in text, f"{absent!r} leaked into {copy.dir.name}'s page"
    assert one.page.read_bytes() == two.page.read_bytes(), "the two copies rendered differently"
    # the record the page rendered reasons from does carry both shapes (the control is real)
    rows = {r["world"]: r for r in J.judge_record(one.dir)["worlds"]}
    assert rows[E.GRADED_WORLD].get("malformed") is True, rows[E.GRADED_WORLD]
    assert "missing its served ledger" in rows[E.WITHHELD_WORLD]["ungradable_reason"], rows[E.WITHHELD_WORLD]


# ---------------------------------------------------------------------------------------
# d-26 — the positive control: every refusal is said, in its own slot
# ---------------------------------------------------------------------------------------


def test_1049_every_planted_refusal_is_said_in_its_own_slot(tmp_path):
    """For the tree d-25 plants, each slot says its refusal with the relative name: the four
    records (review.yaml / staged.yaml / provenance.json 'unreadable', samples.yaml 'absent'),
    the timing stage (timing.json), the world report (worlds/<w>/report.md), the investigation
    (worlds/<w>/investigation.md), the ledger note ('absent' for the absent one, 'unreadable …
    served/<token>.<label>.jsonl …' for the aliased one — and for a symlinked served/, rendered
    over a second tree), the chain summary (gather_summaries/<lead>.md), the findings row's
    ungradable sentence, AND for the symlinked and the dangling world dirs every archive/leads
    slot naming worlds/<w>/<leaf> — one slot's refusal never aborting another's (the page
    renders whole). The grade record's own arm is rendered over its own trees, because the
    two-roots tree must carry a valid judge.yaml as the record carrier (F-2): a link at
    judge.yaml, then each c-14 shape (a wrong-typed field, a non-string key, a row without its
    world, an entry naming no lane) — _read_grade's slot, the verdict band, says 'grade record
    unreadable' naming judge.yaml, and neither str(episode_dir), its realpath nor
    str(episode_dir.parent) is anywhere in the page (read_grade keeps the root, RF-C3; this is
    its only page-level root-free pin). The six mode-000 slots are d-03's per-name rows and
    test_1025_an_unreadable_regular_file_at_a_record_name's page arm.
    """
    _built, one, _two = _every_arm(tmp_path)
    page = E.render(one)
    records = page.text_of("sec-records")
    for slot, name in (("review record unreadable", "review.yaml"),
                       ("staging record unreadable", "staged.yaml"),
                       ("provenance record unreadable", "provenance.json")):
        assert slot in records, (slot, records)
        assert name in records, (slot, records)
    assert "absent" in records, records
    stages = page.text_of("sec-stages")
    assert 'timing record unreadable' in stages, stages
    assert 'timing.json' in stages, stages
    assert R.ALIAS in stages, stages

    withheld_report = page.section(f"world-{E.WITHHELD_WORLD}").find_all(cls="w-report")[0].text()
    assert f'worlds/{E.WITHHELD_WORLD}/report.md' in withheld_report, withheld_report
    assert R.ALIAS in withheld_report, withheld_report
    graded_leads = _leads(page, E.GRADED_WORLD)
    assert "investigation record unavailable" in graded_leads, graded_leads
    assert f'worlds/{E.GRADED_WORLD}/investigation.md' in graded_leads, graded_leads
    assert R.ALIAS in graded_leads, graded_leads
    assert "served ledger: absent" in _leads(page, E.WITHHELD_WORLD)
    control_leads = _leads(page, E.CONTROL)
    assert 'served ledger unreadable' in control_leads, control_leads
    assert _ledger_name(E.CONTROL) in control_leads, control_leads
    assert 'gather_summaries/l-001.md' in control_leads, control_leads
    assert R.ALIAS in control_leads, control_leads
    withheld_leads = _leads(page, E.WITHHELD_WORLD)
    assert 'gather_summaries/l-001.md' in withheld_leads, withheld_leads
    assert R.ALIAS in withheld_leads, withheld_leads

    graded_world = _world(page, E.GRADED_WORLD)
    assert 'ungradable' in graded_world, graded_world
    assert f'worlds/{E.GRADED_WORLD}/investigation.md' in graded_world, graded_world
    withheld_world = _world(page, E.WITHHELD_WORLD)
    assert 'missing its served ledger' in withheld_world, withheld_world
    assert _ledger_name(E.WITHHELD_WORLD) in withheld_world, withheld_world

    for label in (LINKED_WORLD, DANGLING_WORLD):
        world = _world(page, label)
        assert f'worlds/{label}/report.md' in world, (label, world)
        assert R.ALIAS in world, (label, world)
        assert "not archived" not in world, (label, world)
        leads = _leads(page, label)
        assert f'worlds/{label}/investigation.md' in leads, (label, leads)
        assert R.ALIAS in leads, (label, leads)
        assert "not archived" not in leads, (label, leads)
    linked_leads = _leads(page, LINKED_WORLD)
    assert "gather_summaries/l-001.md" in linked_leads, "the summaries under a symlinked world dir are not said"
    assert str(one.dir) not in page.raw
    assert str(tmp_path) not in page.raw

    served = E.sample_episode(tmp_path / "served-link")
    (served.dir / "served").rename(served.dir / "served-real")
    E.plant_link(served.dir / "served", served.dir / "served-real")
    block = _leads(E.render(served), E.GRADED_WORLD)
    assert 'served ledger unreadable' in block, block
    assert _ledger_name(E.GRADED_WORLD) in block, block
    assert R.ALIAS in block, block

    _grade_record_refused_over_its_own_trees(tmp_path)


def _grade_record_refused_over_its_own_trees(tmp_path: Path) -> None:
    """The grade record's arm (F-2): a link at judge.yaml over one tree, then each c-14 shape
    over another — the two-roots tree cannot carry them, its judge.yaml IS the record."""
    linked = E.sample_episode(tmp_path / "judge-link")
    E.plant_link(linked.dir / "judge.yaml", linked.dir / "family.yaml")
    band = _grade_record_unreadable(E.render(linked), linked.dir)
    assert R.ALIAS in band, band
    shaped = E.sample_episode(tmp_path / "judge-shape")
    sound = {"verdict_word": "caught", "worlds": [{"world": E.GRADED_WORLD, "verdict": "malicious"}]}
    for bad in ({**sound, "verdict_word": 5}, {1: "x"}, {**sound, "worlds": [{"verdict": "x"}]},
                {**sound, "not_graded": {"x": 1}}):
        E.plant_raw(shaped.dir / "judge.yaml", yaml.safe_dump(bad))
        band = _grade_record_unreadable(E.render(shaped), shaped.dir)
        assert "is not a family grade record" in band, band


def _grade_record_unreadable(page: E.Page, episode_dir: Path) -> str:
    """The verdict band of a page whose judge.yaml was refused: the slot's word, the record's
    relative name, never the 'no grade record' band — and no spelling of the root (as passed,
    its realpath, or the episodes base it sits in) anywhere in the page."""
    band = page.text_of("sec-verdict")
    assert "grade record unreadable" in band, band
    assert "judge.yaml" in band, band
    assert "no grade record" not in band, band
    for spelling in (str(episode_dir), os.path.realpath(episode_dir), str(episode_dir.parent)):
        assert spelling not in page.raw, (spelling, band)
    return band


# ---------------------------------------------------------------------------------------
# d-27 — _result_event through the JSONL twin
# ---------------------------------------------------------------------------------------


def test_1049_result_event_reads_the_tool_trace_through_the_jsonl_twin(tmp_path):
    """_result_event walks runs/<id>-<w>/tool_trace.jsonl under the EPISODE bind through the
    twin and answers 'absent' for no tool_trace.jsonl ('no cost recorded'), 'refused' for an
    alias or a directory at its name ('no result event (refused)'), 'none' for rows without a
    result ('no result event'), 'ok' otherwise (the cost) — with no entry_present ahead
    (state words, never a sentence; an AST census of its body names no entry_present and it
    takes no Path root). A symlinked runs/<id>-<w> never reaches it: the run_dirs listing
    (a roster question, D-V5) lists no link, and the section says 'run directory absent'.
    """
    page = _page()
    fn = R.function_def(R.parsed(page._result_event), "_result_event")
    assert "entry_present" not in R.called_names(fn), R.called_names(fn)
    assert not R.path_typed_parameters(fn), R.path_typed_parameters(fn)

    ep = E.sample_episode(tmp_path)
    trace = ep.run(E.GRADED_WORLD) / "tool_trace.jsonl"
    assert f"${E.SAMPLE.run_cost[E.GRADED_WORLD]:.4f}" in _world(E.render(ep), E.GRADED_WORLD)
    trace.unlink()
    assert "no cost recorded" in _world(E.render(ep), E.GRADED_WORLD)
    E.plant_link(trace, ep.dir / "family.yaml")
    assert "no result event (refused)" in _world(E.render(ep), E.GRADED_WORLD)
    trace.unlink()
    trace.mkdir()
    assert "no result event (refused)" in _world(E.render(ep), E.GRADED_WORLD)
    trace.rmdir()
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [{"type": "assistant"}])
    world = _world(E.render(ep), E.GRADED_WORLD)
    assert 'no result event' in world, world
    assert '(refused)' not in world, world
    run = ep.run(E.GRADED_WORLD)
    run.rename(ep.dir / "runs" / "run-real")
    E.plant_link(run, ep.dir / "runs" / "run-real")
    assert "run directory absent" in _world(E.render(ep), E.GRADED_WORLD)


# ---------------------------------------------------------------------------------------
# d-36 — the page's flags derive from the readers' states
# ---------------------------------------------------------------------------------------


def test_1049_investigation_present_and_archived_are_read_off_the_readers_states_not_a_stat(tmp_path):
    """A world archived without investigation.md renders 'investigation.md: not archived' from
    the investigation read's absent state, with no facts_error (the entry_present is gone); a
    world with no worlds/<w> directory renders every archive leaf as its own 'not archived'
    arm ('report.md: not archived' AND 'investigation.md: not archived') and its leads block
    from the same absent states (the artifact_dir(world_dir) screens are gone; the
    whole-section word is said only as a derivation of all leaves absent); a symlinked
    worlds/<w> renders every leaf's refusal naming worlds/<w>/<leaf> and no 'not archived'
    anywhere in its section or block. No per-world section is worded from a stat or a
    listing.
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "investigation.md").unlink()
    shutil.rmtree(ep.world(E.WITHHELD_WORLD))
    control = ep.world(E.CONTROL)
    control.rename(ep.dir / "worlds" / "control-real")
    E.plant_link(control, ep.dir / "worlds" / "control-real")
    page = E.render(ep)

    graded = _world(page, E.GRADED_WORLD)
    assert 'investigation.md: not archived' in graded, graded
    assert 'report.md: not archived' not in graded, graded
    graded_leads = _leads(page, E.GRADED_WORLD)
    assert "investigation record unavailable" not in graded_leads, graded_leads
    assert f"summary of l-001 for {E.GRADED_WORLD}" in graded_leads, graded_leads

    withheld = _world(page, E.WITHHELD_WORLD)
    assert 'report.md: not archived' in withheld, withheld
    assert 'investigation.md: not archived' in withheld, withheld
    assert "not archived" in _leads(page, E.WITHHELD_WORLD)

    linked = _world(page, E.CONTROL)
    assert f'worlds/{E.CONTROL}/report.md' in linked, linked
    assert R.ALIAS in linked, linked
    assert "not archived" not in linked, linked
    linked_leads = _leads(page, E.CONTROL)
    assert f'worlds/{E.CONTROL}/investigation.md' in linked_leads, linked_leads
    assert R.ALIAS in linked_leads, linked_leads
    assert "not archived" not in linked_leads, linked_leads
    assert str(ep.dir) not in page.raw
    assert str(tmp_path) not in page.raw


# ---------------------------------------------------------------------------------------
# D-V5 — the closed list of listing sites
# ---------------------------------------------------------------------------------------


#: The allow-list: which function may call which lstat helper, how many times — the six
#: listing/roster questions and nothing else (RF-R9).
ALLOWED_STAT_SITES = {
    "load_episode": {"artifact_dir": 1},       # archived_world_dirs
    "_entries_of": {"artifact_dir": 1},        # the listing helper's own directory question
    "_build_roster": {"artifact_dir": 2},      # run_dirs, reached_runs
    "_load_world_leads": {"artifact_file": 1},  # summary_stems
    "_load_wire_logs": {"artifact_dir": 1},    # is wire_logs/ a directory
}


def test_1049_the_page_keeps_artifact_dir_and_entry_present_only_in_the_six_listing_sites():
    """visualize_episode's AST names artifact_dir/artifact_file/entry_present ONLY in
    archived_world_dirs (load_episode), _entries_of, run_dirs and reached_runs (_build_roster),
    summary_stems (_load_world_leads) and _load_wire_logs — listing and roster questions whose
    answer is never a read's absent/refused split and never words a per-world section — with
    exactly those counts, and entry_present nowhere; the calls that stood ahead of the six
    record readers, the tool-trace read, the report read, the investigation_present flag and
    the two world_dir screens are gone. Positive control: d-26 (every planted arm is said in
    its own slot off the reader's state).
    """
    tree = R.module_tree(_page())
    calls = R.calls_by_function(tree, frozenset({"entry_present", "artifact_dir", "artifact_file"}))
    assert calls == ALLOWED_STAT_SITES, {k: v for k, v in calls.items() if ALLOWED_STAT_SITES.get(k) != v}


# ---------------------------------------------------------------------------------------
# s-66 — the timing slot tells absent from unreadable from no stages
# ---------------------------------------------------------------------------------------


def test_timing_json_present_empty_versus_empty_steps_versus_absent(tmp_path):
    """The page's _read_timing derives present from `rows is not None` (closing F8/g20: today
    present=bool(rows) conflates {"steps": []} with absent): an absent timing.json is the
    absent slot ('no timing record'), a zero-byte file the unreadable slot ('timing.json …
    not a JSON document', root-free), and {"steps": []} a present record whose caption says
    no stages — neither 'no timing record' nor 'unreadable'.
    """
    ep = E.sample_episode(tmp_path)
    absent = E.render(ep).text_of("sec-stages")
    assert 'no timing record' in absent, absent
    assert 'unreadable' not in absent, absent
    E.write_timing(ep.dir, raw="")
    unreadable = E.render(ep).text_of("sec-stages")
    assert 'timing record unreadable' in unreadable, unreadable
    assert 'timing.json' in unreadable, unreadable
    assert 'not a JSON document' in unreadable, unreadable
    assert str(ep.dir) not in unreadable, unreadable
    E.write_timing(ep.dir, [])
    empty = E.render(ep).text_of("sec-stages")
    assert 'no timing record' not in empty, empty
    assert 'unreadable' not in empty, empty
    assert re.search(r"no (completed |recorded )?(stages?|steps?)", empty), empty
    assert empty != absent
