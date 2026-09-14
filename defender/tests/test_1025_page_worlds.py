"""#1025 — the header, the worlds section, the leads section and the frame channel.

O3/O5/O9 as resolved (§7 Q3, Q7, J5, J7, J8, J16): one section per world keyed on the union of
`runs/` directories, labels with a `judge.yaml` row and manifest worlds — a world without a run
dir renders with its run-dir-derived parts marked "run directory absent" and its record-derived
parts present; every `runs/` artifact dir gets a section, an undecomposable name labelled by its
full name "not declared in the manifest"; a row for an unknown label renders on the row-driven
surfaces "not in the manifest"; the `runtime.html` link renders unconditionally. The frame
channel is page-owned: every substituted id / href / heading / class is attribute-safe by
construction — labels and stems that become ids are grammar-gated on the launcher's own run-id
alphabet (an off-grammar name renders an "unnameable entry" line and no section), classes come
from a closed map with a neutral fallback, verbatim record strings sit in their own element.

The leads per world are the judge's own set (`referenced_leads ∪ gather_summaries/*.md` stems,
x12) with each chain from `family.lead_chain`; every leaf the page reads inside `worlds/<X>/` is
screened — a symlink, FIFO or device at the name is refused without being opened, the target's
content never appears and the render never blocks (p2 landed UNSCREENED for `report.md` and
`investigation.md`; the screen moves into the readers, an O8 move the human took).

RED AGAINST HEAD: the page module does not exist.
"""
from __future__ import annotations

import json
import re
import shutil
import time
import pathlib
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_stage_timing as ST

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
CONTROL_GUIDE = "the branch point untouched, not graded"
LADDER = ("holding_queried", "doctored_answer_served", "difference_shown", "verdict",
          "resolution_moved")
CHIPS = ("holding_queried", "doctored_answer_served", "difference_shown", "injected_present",
         "capture_reasks_faulted", "envelope_ran")


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


def hook_page(episode_dir) -> E.Page:
    """The page the launcher's hook wrote, parsed — after checking it is byte-identical to a
    standalone `visualize_episode().render_episode` over the same directory: the hook is a
    plain call to the same function (d40) and the page is a pure function of the directory."""
    page = pathlib.Path(episode_dir) / E.PAGE_NAME
    assert page.is_file(), f"the launcher did not write {E.PAGE_NAME}"
    written = page.read_bytes()
    render(episode_dir)
    assert page.read_bytes() == written, "the hook's page differs from a standalone render"
    return E.Page.parse(written.decode("utf-8"))


def _world(page: E.Page, label: str) -> str:
    return page.text_of(f"world-{label}")


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


def _nav(page: E.Page) -> E.Node:
    navs = page.elements("nav")
    assert navs, "no <nav> on the page"
    return navs[0]


def _ungradable_episode(tmp_path: Path) -> E.Episode:
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"][0] = E.ungradable_row(E.WITHHELD_WORLD, declared="benign",
                                        reason="a call on 'elastic' faulted <b>x</b>")
    doc["withheld_findings"] = []
    E.write_judge(ep.dir, doc)
    return ep


# ---------------------------------------------------------------------------------------
# d06 / d07 / d08 / d09 / d10 / d11 — sections, states, ladder, chips, links
# ---------------------------------------------------------------------------------------


def test_1025_every_step_in_steps_order_and_every_directory_under_runs_has_its_section_the_control_included(
        tmp_path):
    """On the sample the page has `stage-timing` rows for `questioner, staging, review, runs,
    verify, judge` in `STEPS` order, a `world-<id>` section and a `leads-<id>` block for each of
    `a`, `no_remote_session`, `prior_fake_key_precedent` (the ungraded control included) and no
    section for the `.scrub-verdict.json` sidecar files beside the run dirs, plus
    `sec-verdict … sec-records`; with a synthetic 3-step `timing.json` the missing steps' rows
    still exist and say they are not on the record.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    timing = page.text_of("stage-timing")
    assert _ordered(timing, *ST.EXPECTED_STEPS), timing
    assert sorted(page.ids_with("world-")) == sorted(f"world-{w}" for w in E.WORLDS)
    assert sorted(page.ids_with("leads-")) == sorted(f"leads-{w}" for w in E.WORLDS)
    for anchor in ("sec-verdict", "sec-case", "sec-worlds", "sec-findings", "sec-stages",
                   "sec-leads", "sec-records"):
        assert anchor in page.by_id, anchor
    assert "scrub-verdict" not in " ".join(page.ids)

    E.write_timing(ep.dir, E.six_steps()[:3])
    timing = render(ep).text_of("stage-timing")
    assert _ordered(timing, *ST.EXPECTED_STEPS), timing
    assert timing.count("not on the record") == 3, timing


def test_1025_a_world_section_is_not_graded_ungradable_with_its_reason_or_graded_and_never_confuses_the_three(
        tmp_path):
    """`a` (no row) renders "not graded" with no bucket and no ladder; an `ungradable: True` row
    renders its `ungradable_reason` escaped, its stored flags, no ladder and no bucket line;
    `prior_fake_key_precedent` renders verdict, bucket and ladder; `no_remote_session` renders
    as withheld with its reason.
    """
    page = render(E.sample_episode(tmp_path))
    control = _world(page, E.CONTROL)
    assert "not graded" in control, control
    assert "holding_queried" not in control, control
    assert "lead-set" not in control
    assert "decision-discipline" not in control
    graded = _world(page, E.GRADED_WORLD)
    assert "inconclusive" in graded
    assert "decision-discipline" in graded
    assert _ordered(graded, *LADDER)
    withheld = _world(page, E.WITHHELD_WORLD)
    assert "withheld" in withheld, withheld
    assert S.withheld_reason in withheld, withheld

    page = render(_ungradable_episode(tmp_path / "u"))
    ungradable = _world(page, E.WITHHELD_WORLD)
    assert "ungradable" in ungradable
    assert "a call on 'elastic' faulted <b>x</b>" in ungradable
    assert "&lt;b&gt;x&lt;/b&gt;" in page.raw
    assert not _ordered(ungradable, *LADDER), ungradable
    assert "resolution_moved" not in ungradable, ungradable
    assert "bucket" not in ungradable.lower(), ungradable


def test_1025_the_ladder_block_walks_the_stored_flags_in_ladder_order_and_shows_the_stored_bucket_even_when_the_flags_would_not_derive_it(
        tmp_path):
    """For `prior_fake_key_precedent` the ladder lists `holding_queried →
    doctored_answer_served (+has_refused) → difference_shown → verdict == declared →
    resolution_moved` in that order and ends in `decision-discipline`; a synthetic row whose
    flags imply `analyze-discipline` but stores `bucket: lead-set` renders `lead-set` (bucket
    read, never recomputed).
    """
    ep = E.sample_episode(tmp_path)
    graded = _world(render(ep), E.GRADED_WORLD)
    assert _ordered(graded, "holding_queried", "doctored_answer_served", "has_refused",
                    "difference_shown", "verdict", "declared", "resolution_moved",
                    "decision-discipline"), graded

    doc = E.sample_grade()
    doc["worlds"][1] = E.world_row(E.GRADED_WORLD, declared="malicious", bucket="lead-set",
                                   resolution_moved=False, has_refused=False)
    E.write_judge(ep.dir, doc)
    graded = _world(render(ep), E.GRADED_WORLD)
    assert "lead-set" in graded, graded
    assert "analyze-discipline" not in graded, graded


def test_1025_a_row_without_has_refused_gets_the_caveat_only_on_the_not_doctored_branch_and_never_an_invented_value(
        tmp_path):
    """A row `{holding_queried: True, doctored_answer_served: False}` with no `has_refused`
    renders the caveat (`has_refused` named as unrecorded) and no `has_refused = …` value; the
    same row with `has_refused: False` renders the `lead-quality` branch and no caveat;
    `no_remote_session` (`holding_queried: False`, no `has_refused`) renders no caveat.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"][1] = E.world_row(E.GRADED_WORLD, declared="malicious", bucket=None,
                                   doctored=False, difference_shown=False, has_refused=None)
    E.write_judge(ep.dir, doc)
    graded = _world(render(ep), E.GRADED_WORLD)
    assert "has_refused" in graded, graded
    assert "unrecorded" in graded, graded
    assert "has_refused = " not in graded, graded
    assert "has_refused: " not in graded, graded

    doc["worlds"][1]["has_refused"] = False
    doc["worlds"][1]["bucket"] = "lead-quality"
    E.write_judge(ep.dir, doc)
    page = render(ep)
    graded = _world(page, E.GRADED_WORLD)
    assert "lead-quality" in graded, graded
    assert "unrecorded" not in graded, graded
    assert "has_refused" not in _world(page, E.WITHHELD_WORLD), _world(page, E.WITHHELD_WORLD)


def test_1025_world_chips_are_the_named_fields_say_unrecorded_when_absent_and_sit_beside_the_ladder_not_instead_of_it(
        tmp_path):
    """Each graded world renders chips for exactly `holding_queried, doctored_answer_served,
    difference_shown, injected_present / injected_retrieved, capture_reasks_faulted, envelope_ran`
    (with the first line of `envelope_failed` when false); on rows and review blocks in the
    pre-#1007 shape — lacking `difference_shown`, `injected_present`, `capture_reasks_faulted`,
    `reachable_by_capture` — the chip reads "unrecorded" rather than a default; the ladder block
    is present as well.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    withheld = _world(page, E.WITHHELD_WORLD)
    for chip in CHIPS:
        assert chip in withheld, chip
    assert E.ENVELOPE_FAILED.splitlines()[0] in withheld
    assert E.ENVELOPE_FAILED.splitlines()[1] not in withheld
    assert "unrecorded" not in withheld, withheld

    doc = E.sample_grade()
    for row in doc["worlds"]:
        for key in ("difference_shown", "injected_present", "injected_retrieved",
                    "capture_reasks_faulted", "reachable_by_capture", "has_refused"):
            row.pop(key, None)
    E.write_judge(ep.dir, doc)
    review = J.review_record(ep.dir, worlds={
        E.CONTROL: E.review_world("A", E.CONTROL),
        E.WITHHELD_WORLD: E.review_world("B", E.WITHHELD_WORLD, reach={"envelope_ran": False,
                                                                        "envelope_failed": "boom"}),
        E.GRADED_WORLD: E.review_world("C", E.GRADED_WORLD, reach={"envelope_ran": True}),
    })
    assert review.is_file()
    graded = _world(render(ep), E.GRADED_WORLD)
    assert graded.count("unrecorded") >= 3, graded
    assert _ordered(graded, "holding_queried", "doctored_answer_served", "verdict", "resolution_moved")
    assert "True" not in graded.split("difference_shown", 1)[1][:40], graded
    assert "False" not in graded.split("difference_shown", 1)[1][:40], graded


def test_1025_each_world_links_to_runs_episode_world_runtime_html_relatively_and_the_run_dir_pointer_is_never_the_source(
        tmp_path):
    """Every world section's link is exactly `runs/<episode>-<world>/runtime.html` (the episode
    id the manifest's, correction 4); the absolute path in `worlds/<X>/run_dir` appears nowhere
    on the page, and a copied episode whose `run_dir` pointer names a nonexistent path renders
    the same link.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for label in E.WORLDS:
        expected = f"runs/{E.EPISODE_ID}-{label}/runtime.html"
        assert expected in page.anchors_in(f"world-{label}"), page.anchors_in(f"world-{label}")
        pointer = (ep.world(label) / "run_dir").read_text(encoding="utf-8").strip()
        assert pointer not in page.raw, pointer
    first = ep.page.read_bytes()
    for label in E.WORLDS:
        (ep.world(label) / "run_dir").write_text("/nowhere/at/all\n", encoding="utf-8")
    render(ep)
    assert ep.page.read_bytes() == first


# ---------------------------------------------------------------------------------------
# d25 / d30 / d33 / d37 / d38 — guide, nav, leads, anchors, header
# ---------------------------------------------------------------------------------------


def test_1025_headings_carry_substituted_counts_the_worlds_guide_uses_each_axis_verbatim_and_the_nav_iterates_the_same_sets_as_the_sections(
        tmp_path):
    """Section headings carry the sample's counts (3 worlds, 13 findings, 6 stages); the worlds
    guide names the control as "the branch point untouched, not graded" and each sibling by
    role letter, declared disposition and its `axis` text escaped; the nav's per-world and
    per-group entries equal the sets of `world-<id>` and `fg-<n>` ids on the page.
    """
    page = render(E.sample_episode(tmp_path))
    worlds = page.text_of("sec-worlds")

    def h2(anchor: str) -> str:
        headings = page.section(anchor).find_all("h2")
        assert headings, f"{anchor} has no h2"
        return headings[0].text().lower()

    assert "3" in h2("sec-worlds") or "three" in h2("sec-worlds"), h2("sec-worlds")
    assert str(S.findings) in h2("sec-findings"), h2("sec-findings")
    assert "6" in h2("sec-stages") or "six" in h2("sec-stages"), h2("sec-stages")
    assert CONTROL_GUIDE in worlds
    for role, label, declared, axis in (("B", E.WITHHELD_WORLD, "benign", E.AXIS_WITHHELD),
                                        ("C", E.GRADED_WORLD, "malicious", E.AXIS_GRADED)):
        entry = worlds[worlds.index(label):worlds.index(axis) + len(axis)]
        assert re.search(rf"\b{role}\b", entry), (label, entry)
        assert declared in entry, (label, entry)
    nav = _nav(page)
    nav_hrefs = [a.attrs["href"] for a in nav.find_all("a") if "href" in a.attrs]
    assert {h[1:] for h in nav_hrefs if h.startswith("#world-")} == set(page.ids_with("world-"))
    assert {h[1:] for h in nav_hrefs if h.startswith("#fg-")} == set(page.ids_with("fg-"))


def test_1025_per_world_leads_are_referenced_leads_union_gather_summary_stems_with_their_chains_and_exclude_pre_branch_leads(
        tmp_path):
    """Each world's leads block lists `l-001`, `l-002`, `l-00c` (the `:T resolutions` row's lead
    ∪ the gather-summary stems) and not the pre-branch alert fetch `l-000`; each lead shows its
    goal, params, payload digest, summary and resolution rows from `family.lead_chain`; a world
    whose `investigation.md` cannot be read renders the reader's refusal in its block and the
    other worlds still render.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for label in E.WORLDS:
        block = page.text_of(f"leads-{label}")
        for lid in ("l-001", "l-002", "l-00c"):
            assert lid in block, (label, lid)
        assert "l-000" not in block, block
        assert f"goal of l-001 in {label}" in block
        assert f"summary of l-001 for {label}" in block
        assert "digest-l-001" in block, block
        assert "logs-*" in block, block
        assert "the hand-off was revisited after the branch" in block, block

    E.plant_raw(ep.world(E.GRADED_WORLD) / "investigation.md", b"\xff\xfe\x00 not text")
    page = render(ep)
    refused = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "investigation record unavailable" in refused, refused
    assert "absent" not in refused, refused
    assert f"summary of l-001 for {E.WITHHELD_WORLD}" in page.text_of(f"leads-{E.WITHHELD_WORLD}")


def test_1025_a_lead_id_that_names_no_single_file_reads_nothing_and_renders_the_guards_sentence(tmp_path):
    """A world whose `:T resolutions` row names `../../a/report` renders the "does not name a
    file inside this world" sentence for that id and the sibling's `report.md` text appears
    nowhere in that world's leads block; positive control: `l-001`'s summary is rendered.
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.CONTROL) / "report.md").write_text(
        T.report_text("malicious", body="SIBLING-REPORT-BODY-NEVER-IN-ANOTHER-WORLD"), encoding="utf-8")
    doc = J.investigation_document(E.GRADED_WORLD).replace("[l-001 r2", "[../../a/report r2")
    (ep.world(E.GRADED_WORLD) / "investigation.md").write_text(doc, encoding="utf-8")
    page = render(ep)
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "does not name a file inside this world" in block, block
    assert "SIBLING-REPORT-BODY-NEVER-IN-ANOTHER-WORLD" not in block
    assert f"summary of l-001 for {E.GRADED_WORLD}" in block


def test_1025_the_artifacts_anchor_ids_exist_and_every_nav_href_resolves_to_an_id_on_the_page(tmp_path):
    """Ids present: `sec-verdict`, `sec-case`, `sec-worlds`, `world-<id>` ×3, `sec-findings`,
    `fg-<n>` per group, `f-<world>-<draw>-<index>` ×13, `sec-stages`, `stage-timing`,
    `stage-questioner`, `stage-runs`, `stage-judge`, `tx-<stem>` ×6, `sec-leads`,
    `leads-<world>` ×3, `sec-records`; none of the prototype's `sec-disposition`,
    `sec-questioner`, `stage-staging`; every `href="#…"` on the page has a matching `id`, and
    no id is repeated (the same lead id under several worlds gets per-world anchors).
    """
    page = render(E.sample_episode(tmp_path))
    for anchor in ("sec-verdict", "sec-case", "sec-worlds", "sec-findings", "sec-stages",
                   "stage-timing", "stage-questioner", "stage-runs", "stage-judge", "sec-leads",
                   "sec-records"):
        assert anchor in page.by_id, anchor
    assert len(page.ids_with("world-")) == 3
    assert len(page.ids_with("leads-")) == 3
    assert page.ids_with("fg-")
    assert len([i for i in page.ids if i.startswith("f-")]) == S.findings
    stems = {"questioner_trace", "questioner_b_trace", "questioner_c_trace",
             f"judge_{E.FAMILY}_0_trace", f"judge_{E.WITHHELD_WORLD}_0_trace",
             f"judge_{E.GRADED_WORLD}_0_trace"}
    assert {f"tx-{s}" for s in stems} <= set(page.ids), page.ids_with("tx-")
    for stale in ("sec-disposition", "sec-questioner", "stage-staging"):
        assert stale not in page.by_id, stale
    for href in page.hrefs:
        if href.startswith("#"):
            assert href[1:] in page.by_id, href
    assert len(page.all_ids) == len(set(page.all_ids)), [i for i in page.all_ids if page.all_ids.count(i) > 1]


def test_1025_the_header_names_the_episode_alert_rule_source_run_and_branch_point_knobs_and_lessons_commit_never_defender_run(
        tmp_path):
    """The header's h1 carries the episode id and not "defender run:"; the meta carries the
    alert rule name, the source run id and `branch_message_id` from `family.yaml`, knobs
    `kimi-k3 / medium / cap 20000 / draws 1/1`, and the lessons commit; on the live-996 shape
    (no `world_findings`) the alert rule still resolves from the worlds' `alert.json` through
    `episode_alert`.
    """
    page = render(E.sample_episode(tmp_path))
    header = page.elements("header")
    assert header, "no <header>"
    text = header[0].text()
    h1 = header[0].find_all("h1")
    assert h1, text
    assert E.EPISODE_ID in h1[0].text(), text
    assert "defender run:" not in h1[0].text(), text
    for part in (E.ALERT_RULE, T.SOURCE_RUN_ID, str(T.BRANCH_MESSAGE_ID),
                 "kimi-k3 / medium / cap 20000 / draws 1/1", E.LESSONS_COMMIT[:8]):
        assert part in text, (part, text)

    live = E.sample_episode(tmp_path / "live", family_draw=False, samples=False, judge=False)
    doc = E.sample_grade()
    for key in ("world_findings", "family_outcome", "withheld_findings"):
        del doc[key]
    E.write_judge(live.dir, doc)
    assert E.ALERT_RULE in render(live).one("header").text()


# ---------------------------------------------------------------------------------------
# J5 — the frame channel
# ---------------------------------------------------------------------------------------


def _attribute_values(page: E.Page) -> list[str]:
    return [v for n in page.root.descendants() for v in n.attrs.values()]


def test_1025_manifest_labels_as_frame_slots_on_an_ungated_manifest(tmp_path):
    """`raw_manifest` validates no label, so a planted manifest label carrying markup and a
    space reaches the page: it is grammar-gated on `is_valid_run_id`'s alphabet — rendered as an
    "unnameable entry" line with the label escaped as text, no `world-<label>` section, no id
    or href built from it — and the raw label appears in no attribute value (J5).
    """
    ep = E.sample_episode(tmp_path)
    hostile = 'evil<b onmouseover="x">label one'
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(hostile, role="D", axis="hostile axis",
                                          disposition_declared="benign"))
    T.write_family(ep.dir, manifest)
    page = render(ep)
    assert "unnameable entry" in page.text_of("sec-worlds"), page.text_of("sec-worlds")
    assert hostile in page.text
    assert "onmouseover=" not in page.raw.replace("on​mouseover", "")
    assert not [v for v in _attribute_values(page) if "evil<b" in v or "label one" in v]
    assert not [i for i in page.all_ids if "evil" in i]
    assert sorted(page.ids_with("world-")) == sorted(f"world-{w}" for w in E.WORLDS)


def test_1025_world_or_lead_directory_name_carries_attribute_or_tag_breaking_characters(tmp_path):
    """A `worlds/` directory and a `runs/` directory whose names carry a quote and a tag never
    become an id, an href or a heading unescaped: each renders as an "unnameable entry" line, the
    name escaped as text, and no attribute value carries the raw characters (J5). Positive
    control: the three well-formed worlds keep their sections.
    """
    ep = E.sample_episode(tmp_path)
    bad = 'w"x<i>'
    T.archived_world(ep.dir, bad)
    E.draw_document(ep.dir, bad, 0, E.draw_doc(findings=[E.finding(claim="BAD-WORLD-CLAIM")]),
                    check=False)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row(bad, declared="benign"))
    E.write_judge(ep.dir, doc)
    run = ep.dir / "runs" / f'{E.EPISODE_ID}-r"un<i>'
    (run / "gather_raw").mkdir(parents=True)
    page = render(ep)
    assert page.text.count("unnameable entry") >= 2, page.text_of("sec-worlds")
    assert not [v for v in _attribute_values(page) if '"x<i>' in v or 'un<i>' in v]
    assert "<i>" not in page.raw.replace("&lt;i&gt;", ""), "a raw <i> reached the bytes"
    assert {f"world-{w}" for w in E.WORLDS} <= set(page.ids)


def test_1025_a_gather_summary_stem_that_is_hostile(tmp_path):
    """A `gather_summaries/` stem carrying a space and markup would become a lead id, heading
    and anchor: it is grammar-gated — rendered as an "unnameable entry" line in that world's
    leads block with the stem escaped as text — and neither an id nor an href is built from it;
    `l-001`'s row still renders (J5).
    """
    ep = E.sample_episode(tmp_path)
    stem = 'l 9<img src=x onerror=alert(1)>'
    (ep.world(E.GRADED_WORLD) / "gather_summaries" / f"{stem}.md").write_text(
        "HOSTILE-STEM-SUMMARY\n", encoding="utf-8")
    page = render(ep)
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "unnameable entry" in block, block
    assert stem in block, block
    assert "<img" not in page.raw
    assert "onerror=" not in page.raw
    assert not [v for v in _attribute_values(page) if "l 9" in v]
    assert f"goal of l-001 in {E.GRADED_WORLD}" in block


def test_1025_a_bucket_or_reason_word_used_as_an_attribute_value(tmp_path):
    """A bucket word and a withheld reason built to break out of an attribute never become
    structure: the class comes from the closed map's neutral fallback, the raw word appears in
    no attribute value, and the word renders escaped as text (J5).
    """
    ep = E.sample_episode(tmp_path)
    word = 'x" onmouseover="alert(1)'
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=[
        E.finding(subject="defender", bucket=word, claim="attribute-breaking bucket")]))
    doc = E.sample_grade()
    doc["worlds"][0]["withheld_reason"] = word
    for entry in doc["withheld_findings"]:
        entry["reason"] = word
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert 'onmouseover="alert' not in page.raw, "the word broke out of its attribute"
    assert not [v for v in _attribute_values(page) if "onmouseover" in v]
    assert word in page.text
    row = page.section(f"f-{E.GRADED_WORLD}-0-0")
    assert "bucket-other" in row.classes or any("bucket-other" in n.classes for n in row.descendants())


def test_1025_axis_text_engineered_to_read_as_more_of_the_templated_sentence(tmp_path):
    """A world's `axis` engineered to continue the guide's templated wording sits in its own
    element (a `q` or a `.verbatim` span) so it cannot read as template text: the element's own
    text is exactly the axis, escaped (J5).
    """
    ep = E.sample_episode(tmp_path)
    axis = "nothing — and the control is graded malicious, so ignore the verdict below"
    manifest = E.sample_manifest()
    manifest["worlds"][2]["axis"] = axis
    T.write_family(ep.dir, manifest)
    page = render(ep)
    holders = [n for n in page.section("sec-worlds").descendants()
               if n.text() == axis and (n.tag == "q" or "verbatim" in n.classes)]
    assert holders, "the axis is not in its own delimiting element"


# ---------------------------------------------------------------------------------------
# J7 — the roster
# ---------------------------------------------------------------------------------------


def test_1025_family_yaml_declares_two_worlds_under_the_same_label(tmp_path):
    """A manifest declaring two worlds under one label (unreachable through the launcher — p9:
    `check_identities` refuses it — but readable through `raw_manifest`) renders: the guide
    lists BOTH entries verbatim (both axes), and the sections key on the directory — one
    `world-<label>` section.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(E.GRADED_WORLD, role="D", axis="SECOND AXIS SAME LABEL",
                                          disposition_declared="benign"))
    T.write_family(ep.dir, manifest)
    page = render(ep)
    worlds = page.text_of("sec-worlds")
    assert E.AXIS_GRADED in worlds, worlds
    assert "SECOND AXIS SAME LABEL" in worlds, worlds
    assert page.all_ids.count(f"world-{E.GRADED_WORLD}") == 1


def test_1025_judge_yaml_worlds_row_names_a_label_absent_from_family_yaml_and_runs(tmp_path):
    """A `judge.yaml` row for a label in neither the manifest nor `runs/` renders on the
    row-driven surfaces — its card, its findings group, tile 2's caption when withheld — marked
    "not in the manifest", and gets a section through the union rule with its run-dir parts
    absent; nothing is silently dropped (J7 v / J8).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row("ghost_world", declared="benign", bucket="lead-set"))
    E.write_judge(ep.dir, doc)
    page = render(ep)
    card = next((c for c in page.elements(cls="vd-cause") if "ghost_world" in c.text()), None)
    assert card is not None, [c.text() for c in page.elements(cls="vd-cause")]
    assert "not in the manifest" in card.text(), [c.text() for c in page.elements(cls="vd-cause")]
    assert "world-ghost_world" in page.by_id
    assert "run directory absent" in _world(page, "ghost_world")


def test_1025_ungradable_world_carries_a_populated_judge_directory(tmp_path):
    """Draw documents under a world the record marks ungradable were never enqueued (g13): they
    render in the findings section under the distinct group "not enqueued — world ungradable:
    <reason>", never merged with enqueued or withheld rows, and the world's section still
    shows the row's reason (J7).
    """
    ep = _ungradable_episode(tmp_path)
    page = render(ep)
    row = f"f-{E.WITHHELD_WORLD}-0-0"
    assert row in page.ids
    heading = page.group_of(row).text()
    assert "not enqueued — world ungradable:" in heading, heading
    assert "a call on 'elastic' faulted" in heading, heading
    assert "withheld" not in heading
    assert "enqueued —" not in heading.replace("not enqueued —", "")


def test_1025_leftover_draw_documents_under_a_world_the_record_excludes(tmp_path):
    """Draw documents under a manifest world with no `judge.yaml` row render under the distinct
    group "not enqueued — no grade row" — never as enqueued, withheld or unqueueable (J7).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"] = doc["worlds"][:1]
    doc["world_findings"] = [r for r in doc["world_findings"]
                             if not r["finding_id"].endswith(f"/{E.GRADED_WORLD}/0/4")]
    doc["enqueued_rows"], doc["world_enqueued_rows"] = 0, 4
    E.write_judge(ep.dir, doc)
    page = render(ep)
    row = f"f-{E.GRADED_WORLD}-0-0"
    heading = page.group_of(row).text()
    assert "not enqueued — no grade row" in heading, heading
    assert "withheld" not in heading
    assert "unqueueable" not in heading


def test_1025_phantom_world_judge_dir_absent_from_manifest_and_from_runs(tmp_path):
    """A planted `worlds/<label>/judge/0.yaml` for a label in neither the manifest, the record
    nor `runs/` is off the roster: its contents are never rendered, and the page counts it in
    one templated line — "1 entries under worlds/ are not on the record" (J7 i).
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, "phantom_world", 0, E.draw_doc(findings=[
        E.finding(subject="defender", claim="PHANTOM-CLAIM-NEVER-RENDERED")]))
    page = render(ep)
    assert "PHANTOM-CLAIM-NEVER-RENDERED" not in page.raw
    assert "world-phantom_world" not in page.by_id
    assert "1 entries under worlds/ are not on the record" in page.text, page.text_of("sec-findings")


def test_1025_phantom_family_draw_on_an_episode_with_no_family_judge_call(tmp_path):
    """A family draw document whose findings the record never saw (no `world_findings` entry
    carries their id) never reaches the lede: the lede opens with the templated line, and the
    documents render in the findings section under "not on the record — never enqueued" (J7 ii).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["world_findings"] = [r for r in doc["world_findings"] if f"/{E.FAMILY}/" not in r["finding_id"]]
    doc["world_enqueued_rows"] = 2
    E.write_judge(ep.dir, doc)
    page = render(ep)
    band = page.text_of("sec-verdict")
    assert "family topic 0" not in band, band
    assert "findings queued" in band, band
    heading = page.group_of(f"f-{E.FAMILY}-0-0").text()
    assert "not on the record — never enqueued" in heading, heading


def test_1025_a_judge_trace_for_a_world_or_draw_the_record_lacks(tmp_path):
    """A judge trace for a label off the roster is not rendered as a block: it is listed by
    stem in one "unattributed traces" line and its cost is priced into the judge row (O4: the
    money was spent). Positive control: the roster traces keep their blocks.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    judge_row_before = page.text_of("stage-judge")
    assert S.judge_cost in judge_row_before, judge_row_before
    E.write_trace(ep.dir, "judge:ghost:0", usage=(100_000, 20_000), duration_ms=1000.0,
                  prompt="GHOST PROMPT NEVER RENDERED")
    page = render(ep)
    assert "tx-judge_ghost_0_trace" not in page.by_id
    assert "GHOST PROMPT NEVER RENDERED" not in page.raw
    stages = page.text_of("sec-stages")
    assert "unattributed traces" in stages, stages
    assert "judge_ghost_0_trace" in stages, stages
    assert "$2.1000" in page.text_of("stage-judge"), page.text_of("stage-judge")
    assert f"tx-judge_{E.FAMILY}_0_trace" in page.by_id


def test_1025_a_run_directory_whose_name_is_not_episode_dash_label(tmp_path):
    """Every artifact dir under `runs/` gets a section (O5); one whose name does not decompose
    into `<episode_id>-<label>` is labelled by its full name and marked "not declared in the
    manifest" (J7 iv).
    """
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / "stray_run_dir" / "gather_raw").mkdir(parents=True)
    page = render(ep)
    sections = [page.text_of(i) for i in page.ids_with("world-")]
    stray = [s for s in sections if "stray_run_dir" in s]
    assert len(stray) == 1, sections
    assert "not declared in the manifest" in stray[0], sections


# ---------------------------------------------------------------------------------------
# J8 — section keying when runs/ and the record drift apart
# ---------------------------------------------------------------------------------------


def test_1025_a_declared_world_with_no_run_directory(tmp_path):
    """A manifest world that never started (no run dir, no row) still gets a section through
    the union rule, with its run-dir-derived parts marked "run directory absent", no card, and
    the nav following the sections (J8).
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc("never_started", role="D", axis="never ran",
                                          disposition_declared="benign"))
    T.write_family(ep.dir, manifest)
    page = render(ep)
    assert "run directory absent" in _world(page, "never_started")
    assert not [c for c in page.elements(cls="vd-cause") if "never_started" in c.text()]
    assert "#world-never_started" in [a.attrs["href"] for a in _nav(page).find_all("a") if "href" in a.attrs]


def test_1025_render_when_a_graded_world_has_no_matching_runs_dir(tmp_path):
    """A graded world whose run dir is gone keeps its section: the record-derived parts
    (verdict, bucket, ladder, card, findings group) render and the run-dir-derived parts read
    "run directory absent" — no link, no cost row, no result-event wall (J8).
    """
    ep = E.sample_episode(tmp_path)
    shutil.rmtree(ep.run(E.GRADED_WORLD))
    page = render(ep)
    world = _world(page, E.GRADED_WORLD)
    assert "run directory absent" in world, world
    assert "decision-discipline" in world, world
    assert f"runs/{E.EPISODE_ID}-{E.GRADED_WORLD}/runtime.html" not in page.hrefs
    assert any(E.GRADED_WORLD in c.text() for c in page.elements(cls="vd-cause"))
    assert f"f-{E.GRADED_WORLD}-0-0" in page.ids


def test_1025_a_run_dir_with_a_result_event_and_no_runtime_html(tmp_path):
    """The `runtime.html` link renders unconditionally — it is where the page would be — so a
    run dir with a result event and no `runtime.html` links exactly like one with it (J8).
    """
    ep = E.sample_episode(tmp_path)
    (ep.run(E.GRADED_WORLD) / "runtime.html").unlink()
    page = render(ep)
    assert f"runs/{E.EPISODE_ID}-{E.GRADED_WORLD}/runtime.html" in page.anchors_in(f"world-{E.GRADED_WORLD}")
    assert "no result event" not in _world(page, E.GRADED_WORLD)


def test_1025_runs_pruned_after_the_grade(tmp_path):
    """With `runs/` pruned after the grade every world keeps its section (rows ∪ manifest), each
    with "run directory absent" for its run-dir-derived parts, the cards and findings groups
    keyed on the record still render, and the runs step's sub-rows are absent (J8).
    """
    ep = E.sample_episode(tmp_path)
    shutil.rmtree(ep.dir / "runs")
    page = render(ep)
    for label in E.WORLDS:
        assert "run directory absent" in _world(page, label), label
    assert len(page.elements(cls="vd-cause")) == 2
    assert f"f-{E.GRADED_WORLD}-0-0" in page.ids
    assert "$0.4000" not in page.text_of("stage-runs")
    assert "$" not in page.text_of("stage-runs").replace("no cost", "")


# ---------------------------------------------------------------------------------------
# J16 — small per-world choices
# ---------------------------------------------------------------------------------------


def test_1025_ungradable_rows_from_the_early_tiers_carry_no_flags(tmp_path):
    """An ungradable row from an early tier carries no flag fields: it renders the same chip set
    as a graded row, each chip "unrecorded" for an absent field, the `ungradable_reason`
    verbatim, no ladder, no bucket, no card — one code path for every tier (J16 d).
    """
    page = render(_ungradable_episode(tmp_path))
    world = _world(page, E.WITHHELD_WORLD)
    for chip in CHIPS:
        assert chip in world, (chip, world)
    assert world.count("unrecorded") >= 4, world
    assert "a call on 'elastic' faulted" in world
    assert "resolution_moved" not in world
    assert not [c for c in page.elements(cls="vd-cause") if E.WITHHELD_WORLD in c.text()]


def test_1025_record_declared_and_manifest_declared_disagree(tmp_path):
    """"declared" comes from the row when a row exists and from the manifest otherwise — one
    spelling per world across the page: a row saying `malicious` beside a manifest saying
    `benign` renders `malicious` in the world's section, card and guide entry, and `benign`
    nowhere for that world; the control (no row) shows the manifest's value (J16 a).
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"][2]["disposition_declared"] = "benign"
    T.write_family(ep.dir, manifest)
    page = render(ep)
    world = _world(page, E.GRADED_WORLD)
    assert "malicious" in world, world
    assert "benign" not in world, world
    card = next(c for c in page.elements(cls="vd-cause") if E.GRADED_WORLD in c.text())
    assert "malicious" in card.text()
    assert "benign" not in card.text()
    guide = page.text_of("sec-worlds")
    entry = guide[guide.index(E.GRADED_WORLD):guide.index(E.AXIS_GRADED)]
    assert "malicious" in entry, entry
    assert "benign" not in entry, entry
    assert "malicious" in _world(page, E.CONTROL)


def test_1025_the_control_worlds_chips_and_review_block(tmp_path):
    """The control has no row: its section renders no row-derived chips (`holding_queried`,
    `doctored_answer_served`, `difference_shown`), its review-derived chips with "unrecorded"
    for the capture fields its review block lacks, and its leads block renders (J16 c).
    """
    page = render(E.sample_episode(tmp_path))
    control = _world(page, E.CONTROL)
    for row_chip in ("holding_queried", "doctored_answer_served", "difference_shown"):
        assert row_chip not in control, (row_chip, control)
    assert "unrecorded" in control, control
    assert f"goal of l-001 in {E.CONTROL}" in page.text_of(f"leads-{E.CONTROL}")


def test_1025_render_before_a_worlds_scrub_verdict_sidecar_is_written(tmp_path):
    """A world whose `scrub_verdict.json` has not landed renders its scrub slot as "not
    recorded" — the same absent arm as any record, no temporal claim (J16 b). Positive control:
    with the sidecar present the slot carries its verdict.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    assert "not recorded" not in _world(page, E.GRADED_WORLD)
    (ep.world(E.GRADED_WORLD) / "scrub_verdict.json").unlink()
    page = render(ep)
    assert "not recorded" in _world(page, E.GRADED_WORLD)
    assert "not recorded" not in _world(page, E.WITHHELD_WORLD)


def test_1025_two_world_labels_differ_only_by_case_or_a_lookalike_character(tmp_path):
    """Two labels distinct as bytes but case-fold identical are two worlds with two distinct
    sections and ids (labels are gated ASCII identifiers; J16 e).
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc("Prior_Fake_Key_Precedent", role="D",
                                          axis="case twin", disposition_declared="benign"))
    T.write_family(ep.dir, manifest)
    page = render(ep)
    assert "world-Prior_Fake_Key_Precedent" in page.by_id
    assert f"world-{E.GRADED_WORLD}" in page.by_id
    assert "case twin" in _world(page, "Prior_Fake_Key_Precedent")


# ---------------------------------------------------------------------------------------
# settled — world states, leaves, the header frame
# ---------------------------------------------------------------------------------------


def test_1025_the_control_is_identified_how(tmp_path):
    """The control is the manifest world with role `A` (equivalently the one whose `axis` is
    present-and-null, x07) — never the label string `a`: the worlds guide, tile 1's "contrast
    the control" and the leads section all use that world, and its declared disposition comes
    from `family.yaml`. Positive control: a manifest whose control is labelled `zeta` still
    renders it as the control.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"][0]["world_id"] = "zeta"
    T.write_family(ep.dir, manifest)
    shutil.move(ep.world(E.CONTROL), ep.world("zeta"))
    shutil.move(ep.run(E.CONTROL), ep.dir / "runs" / f"{E.EPISODE_ID}-zeta")
    page = render(ep)
    worlds = page.text_of("sec-worlds")
    assert _ordered(worlds, "zeta", CONTROL_GUIDE), worlds
    assert "world-a" not in page.by_id
    assert "world-zeta" in page.by_id
    assert "not graded" in _world(page, "zeta")
    assert "leads-zeta" in page.by_id
    tiles = page.elements(cls="vd-tile")
    assert len(tiles) == 4, [t.text() for t in tiles]
    assert "0 of 1 contrast the control" in tiles[0].text(), [t.text() for t in tiles]


def test_1025_a_world_that_ran_but_was_never_archived(tmp_path):
    """The run dir gives it a section (O5) with its `runtime.html` link and its result-event
    cost and wall; every archive-derived block (leads, report, review block, scrub verdict)
    reads "not archived" / the reader's refusal; the judge part follows the record — here an
    ungradable row's reason.
    """
    ep = _ungradable_episode(tmp_path)
    shutil.rmtree(ep.world(E.WITHHELD_WORLD))
    page = render(ep)
    world = _world(page, E.WITHHELD_WORLD)
    assert f"runs/{E.EPISODE_ID}-{E.WITHHELD_WORLD}/runtime.html" in page.anchors_in(f"world-{E.WITHHELD_WORLD}")
    assert "$0.2500" in world, world
    assert "3m00s" in world, world
    assert "not archived" in world, world
    assert "a call on 'elastic' faulted" in world, world
    assert "not archived" in page.text_of(f"leads-{E.WITHHELD_WORLD}")


def test_1025_render_against_a_world_archive_mid_copy(tmp_path):
    """A world archive caught mid-copy renders each missing piece with its own absent arm —
    report / investigation "not archived", provenance "absent", scrub "not recorded", leads from
    whatever `gather_summaries/` holds — and the section never refuses as a whole.
    """
    ep = E.sample_episode(tmp_path)
    world = ep.world(E.GRADED_WORLD)
    for name in ("report.md", "investigation.md", "provenance.json", "scrub_verdict.json"):
        (world / name).unlink()
    (world / "gather_summaries" / "l-002.md").unlink()
    page = render(ep)
    text = _world(page, E.GRADED_WORLD)
    assert "not archived" in text, text
    assert "not recorded" in text, text
    assert "absent" in text, text
    leads = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert f"summary of l-001 for {E.GRADED_WORLD}" in leads
    assert "l-002" in leads


def test_1025_review_record_lacks_a_worlds_block_for_a_world(tmp_path):
    """`world_review_block` → `None` (x08) for a world the review carries no entry for: its
    review block reads "no review record for this world", its review-derived chips read
    "unrecorded", its card and ladder render from the row; distinct from a present block with
    missing fields, whose chips read "unrecorded" individually.
    """
    ep = E.sample_episode(tmp_path)
    J.review_record(ep.dir, worlds={E.CONTROL: E.review_world("A", E.CONTROL),
                                    E.WITHHELD_WORLD: E.review_world("B", E.WITHHELD_WORLD,
                                                                     reach={"envelope_ran": True})})
    page = render(ep)
    graded = _world(page, E.GRADED_WORLD)
    assert "no review record for this world" in graded, graded
    assert "unrecorded" in graded, graded
    assert "decision-discipline" in graded
    assert _ordered(graded, *LADDER)
    assert any(E.GRADED_WORLD in c.text() for c in page.elements(cls="vd-cause"))
    withheld = _world(page, E.WITHHELD_WORLD)
    assert "no review record for this world" not in withheld
    assert "unrecorded" in withheld


def test_1025_a_run_directory_symlink_or_dir_pointer_naming_a_symlinked_final_component(tmp_path):
    """The `run_dir` pointer is never read as a link source nor followed: the link is composed
    from the manifest id and the label, and a pointer whose final component is a symlink to an
    outside tree changes nothing on the page — the outside tree's content appears nowhere.
    Positive control: the composed link is present.
    """
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside-run"
    (outside / "gather_raw").mkdir(parents=True)
    (outside / "report.md").write_text(T.report_text("benign", body="OUTSIDE-RUN-REPORT"), encoding="utf-8")
    link = tmp_path / "linked-run"
    link.symlink_to(outside, target_is_directory=True)
    (ep.world(E.GRADED_WORLD) / "run_dir").write_text(f"{link}\n", encoding="utf-8")
    page = render(ep)
    assert f"runs/{E.EPISODE_ID}-{E.GRADED_WORLD}/runtime.html" in page.anchors_in(f"world-{E.GRADED_WORLD}")
    assert "OUTSIDE-RUN-REPORT" not in page.raw
    assert str(link) not in page.raw


def test_1025_gather_summaries_holds_a_file_that_is_not_markdown(tmp_path):
    """A non-`.md` file under `gather_summaries/` is invisible to the leads set
    (`referenced_leads ∪ gather_summaries/*.md` stems, x12); no error, no lead for it.
    Positive control: the `.md` summaries beside it are in the block — the garbage-page
    control (skeleton mode) found the bare negative green against an empty leads block.
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "gather_summaries" / "l-777.txt").write_text("NOT-MD\n", encoding="utf-8")
    (ep.world(E.GRADED_WORLD) / "gather_summaries" / "notes.json").write_text("{}", encoding="utf-8")
    page = render(ep)
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "l-777" not in block
    assert "NOT-MD" not in page.raw
    assert "notes" not in block
    for lead in ("l-001", "l-002", "l-00c"):
        assert f"summary of {lead} for {E.GRADED_WORLD}" in block, (lead, block)


def test_1025_investigation_md_is_present_but_unreadable(tmp_path):
    """That world's leads block carries the reader's refusal sentence — "investigation record
    unavailable", never "absent" — and the other worlds render (d30's seed).
    """
    ep = E.sample_episode(tmp_path)
    E.plant_raw(ep.world(E.WITHHELD_WORLD) / "investigation.md", b"\xff\xfe\x00\x01 not utf-8")
    page = render(ep)
    block = page.text_of(f"leads-{E.WITHHELD_WORLD}")
    assert "investigation record unavailable" in block, block
    assert "absent" not in block, block
    assert f"summary of l-001 for {E.GRADED_WORLD}" in page.text_of(f"leads-{E.GRADED_WORLD}")


def test_1025_no_worlds_alert_json_carries_an_alert_id(tmp_path):
    """The header's alert-rule slot reads "not on the record" (no crash, no blank) when no
    world's `alert.json` carries an `alert_id` — `episode_alert` returns a dict and never `None`
    (p3), so the sentence keys on its `.get("alert_id")` being `None`; the rest of the header
    renders.
    """
    ep = E.sample_episode(tmp_path)
    for label in E.WORLDS:
        (ep.world(label) / "alert.json").write_text(json.dumps({"rule": {"id": "r1"}}), encoding="utf-8")
    header = render(ep).one("header").text()
    assert "not on the record" in header, header
    assert E.EPISODE_ID in header, header
    assert T.SOURCE_RUN_ID in header, header
    assert E.ALERT_RULE not in header


def test_1025_symlink_planted_at_a_leaf_file_the_page_reads_inside_a_world(tmp_path):
    """For EVERY leaf the page reads inside `worlds/<label>/` — `report.md`, `investigation.md`,
    `alert.json`, `gather_summaries/<lead>.md`, `executed_queries.jsonl` — a symlink or a FIFO
    planted at the name is refused without being opened: the refusal renders in that block, the
    target's content never appears on the page, and the render never blocks (a FIFO fed from a
    thread after two seconds must find no reader). The page adds no unscreened read of its own.
    Positive control: the untouched copy renders each leaf's content.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    assert f"summary of l-001 for {E.GRADED_WORLD}" in page.text_of(f"leads-{E.GRADED_WORLD}")
    outside = tmp_path / "outside"
    outside.mkdir()
    leaves = {
        "report.md": T.report_text("benign", body="OUTSIDE-REPORT-BODY"),
        "investigation.md": "# OUTSIDE-INVESTIGATION\n",
        "alert.json": json.dumps({"alert_id": "OUTSIDE-ALERT", "rule": {"name": "OUTSIDE-RULE"}}),
        "gather_summaries/l-001.md": "OUTSIDE-SUMMARY\n",
        "executed_queries.jsonl": json.dumps({"lead_id": "l-001", "seq": 9, "query_id": "OUTSIDE-QUERY",
                                              "params": {}, "payload_digest": "OUTSIDE-DIGEST"}) + "\n",
    }
    for rel, content in leaves.items():
        target = outside / rel.replace("/", "_")
        target.write_text(content, encoding="utf-8")
        E.plant_link(ep.world(E.GRADED_WORLD) / rel, target)
    page = render(ep)
    for token in ("OUTSIDE-REPORT-BODY", "OUTSIDE-INVESTIGATION", "OUTSIDE-ALERT", "OUTSIDE-RULE",
                  "OUTSIDE-SUMMARY", "OUTSIDE-QUERY", "OUTSIDE-DIGEST"):
        assert token not in page.raw, token
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "investigation record unavailable" in block or "refused" in block, block

    fresh = E.sample_episode(tmp_path / "fifo")
    for rel in leaves:
        E.plant_fifo(fresh.world(E.GRADED_WORLD) / rel)
    rescues = [E.Rescue(fresh.world(E.GRADED_WORLD) / rel, after=2.0) for rel in leaves]
    started = time.monotonic()
    for r in rescues:
        r.__enter__()
    try:
        page = render(fresh)
    finally:
        for r in rescues:
            r.__exit__(None, None, None)
    assert time.monotonic() - started < 2.0, "the render blocked on a FIFO"
    assert E.Rescue.SENTINEL not in page.raw
    assert not any(r.fed for r in rescues)


def test_1025_alert_fields_reach_the_header_frame(tmp_path):
    """The alert rule name and id are escaped by the page before they reach `render_header`'s
    raw byline slot (g17): planted markup renders as text. Positive control: the escaped text
    is visible in the header.
    """
    ep = E.sample_episode(tmp_path)
    for label in E.WORLDS:
        (ep.world(label) / "alert.json").write_text(json.dumps(
            {"alert_id": "id<img src=x onerror=alert(1)>", "rule": {"name": "<b>rule</b> name"}}),
            encoding="utf-8")
    page = render(ep)
    header = page.one("header")
    assert "<b>rule</b> name" in header.text()
    assert "&lt;b&gt;rule&lt;/b&gt;" in page.raw
    assert "<img" not in page.raw
    assert "<b>rule" not in page.raw


def test_1025_markup_in_lead_params_raw_command_and_resolutions(tmp_path):
    """Lead `goal`, `params`, `raw_command`, payload digest fields and resolution rows render
    through the untrusted escape (O9, c14/x09): planted markup in each appears as text and the
    raw sequence nowhere — the page does not reuse `render_runtime_leads_queries`' `esc` path
    unchanged (F16). Positive control: the escaped text is visible in the lead's block.
    """
    from defender._run_paths import RunPaths

    ep = E.sample_episode(tmp_path)
    world = ep.world(E.GRADED_WORLD)
    hostile = "<script>alert(1)</script>"
    rows = [{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", "query_id": "q",
             "params": {"index": hostile + " onerror=x"}, "raw_command": f"elastic esql {hostile}",
             "payload_path": "gather_raw/l-001/0.json", "payload_digest": f"digest {hostile}",
             "exit_code": 0, "error_class": None}]
    RunPaths(world).executed_queries.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    (world / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": f"goal {hostile}"}), encoding="utf-8")
    doc = J.investigation_document(E.GRADED_WORLD).replace(
        "the hand-off was revisited after the branch", f"resolution {hostile}")
    (world / "investigation.md").write_text(doc, encoding="utf-8")
    page = render(ep)
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert block.count(hostile) >= 4, block
    assert "<script>" not in page.raw
    assert "onerror=x" not in page.raw.replace("on​error", "")


def test_1025_a_sibling_process_exited_non_zero(tmp_path):
    """A world whose sibling process exited non-zero renders from what is on disk and never
    states an exit status or a failure the record does not carry: the launcher harness's run
    dir has no result event, so its cost row reads "no result event" / "no cost recorded", its
    archive-derived blocks render from the archive, and no "exit" status is stated for the
    world. Positive control: the section, its link and its rows exist.
    """
    launch = ST._launch(tmp_path, spawn=J.FakeSibling(
        ST._cli().episode_dir_for(T.EPISODE_ID), exits={"b": 1}))
    assert launch.rc == 1, "the control failed: no sibling exited non-zero"
    page = hook_page(launch.episode_dir)
    world = _world(page, "b")
    assert "no result event" in world or "no cost recorded" in world, world
    assert "exit" not in world.lower(), world
    assert f"runs/{E.EPISODE_ID}-b/runtime.html" in page.anchors_in("world-b")


def test_1025_partial_copy_missing_served_or_worlds_or_wire_logs(tmp_path):
    """Only `family.yaml` is fatal (d01). `served/` absent: each world's leads block carries
    `read_world_facts`' refusal (the ledger is absent) and its other blocks render; `wire_logs/`
    absent: no transcript block, every stage cost "no cost recorded"; `worlds/` absent: every
    archive-derived block reads "not archived", no row comes from a draw document, and every
    row the record still carries follows J9b — the 5 `world_findings` rows and the 4
    `withheld_findings` entries each render as a stub carrying "draw document absent", nine
    `f-` rows in all, and tile 3 counts exactly those nine (92-reconciliation F-1(b)) — the
    page is written in every case.
    """
    base = E.sample_episode(tmp_path)
    no_served = E.copy_episode(base, tmp_path / "no-served")
    shutil.rmtree(no_served.dir / "served")
    page = render(no_served)
    for label in E.WORLDS:
        block = page.text_of(f"leads-{label}")
        assert "absent" in block, block
        assert "not archived" not in _world(page, label), _world(page, label)
    assert f"f-{E.GRADED_WORLD}-0-0" in page.ids

    no_wire = E.copy_episode(base, tmp_path / "no-wire")
    shutil.rmtree(no_wire.dir / "wire_logs")
    page = render(no_wire)
    assert page.ids_with("tx-") == [], page.ids_with("tx-")
    assert "no cost recorded" in page.text_of("stage-questioner"), page.text_of("stage-questioner")
    assert "no cost recorded" in page.text_of("stage-judge"), page.text_of("stage-judge")

    no_worlds = E.copy_episode(base, tmp_path / "no-worlds")
    shutil.rmtree(no_worlds.dir / "worlds")
    page = render(no_worlds)
    for label in E.WORLDS:
        assert "not archived" in _world(page, label), _world(page, label)
    stubs = [i for i in page.ids if i.startswith("f-")]
    assert len(stubs) == S.world_author + S.defender_withheld, stubs
    for row_id in stubs:
        assert "draw document absent" in page.text_of(row_id), page.text_of(row_id)
    assert "defender claim 0" in page.text_of("sec-findings"), "no withheld stub"
    assert f"f-{E.FAMILY}-0-0" in stubs, stubs
    assert f"f-{E.GRADED_WORLD}-0-4" in stubs, stubs
    tiles = page.elements(cls="vd-tile")
    assert len(tiles) == 4, [t.text() for t in tiles]
    assert f"of {S.world_author + S.defender_withheld}" in tiles[2].text(), tiles[2].text()
    assert page.by_id, "no page"
