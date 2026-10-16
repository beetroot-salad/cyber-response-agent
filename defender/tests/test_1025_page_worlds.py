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
from defender.tests._alert_plant import plant_source_copy
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_stage_timing as ST
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
CONTROL_GUIDE = "the branch point untouched, not graded"
#: The world block's one verdict line: the row's verdict against its declared disposition.
VERDICT_LINE = "verdict = declared"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def visualize_episode():
    """The target module, `defender.scripts.visualize.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(runs, <episode id>)` — the real entry point — then
    the page it wrote, parsed."""
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
    verdict line) does not defeat a correctly ordered sequence."""
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
    doc["worlds"][0] = E.ungradable_row(E.PASSTHROUGH_WORLD, declared="benign",
                                        reason="a call on 'elastic' faulted <b>x</b>")
    doc["enqueued_rows"] = S.defender_enqueued - 4  # the ungradable world's four never queue
    E.drop_lanes(doc, E.PASSTHROUGH_WORLD)  # the pass never walks an ungradable row's draws
    E.write_judge(ep.dir, doc)
    return ep


# ---------------------------------------------------------------------------------------
# d06 / d07 / d08 / d09 / d10 / d11 — sections, states, verdict line, bucket, chips, links
# ---------------------------------------------------------------------------------------


def test_1025_every_step_in_steps_order_and_every_directory_under_runs_has_its_section_the_control_included(
        tmp_path):
    """On the sample the page has `stage-timing` rows for `questioner, preflight, runs, verify,
    judge` in `STEPS` order, a `world-<id>` section and a `leads-<id>` block for each of
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

    E.write_timing(ep.dir, E.every_step()[:3])
    timing = render(ep).text_of("stage-timing")
    assert _ordered(timing, *ST.EXPECTED_STEPS), timing
    assert timing.count("not on the record") == len(ST.EXPECTED_STEPS) - 3, timing


def test_1025_a_world_section_is_not_graded_ungradable_with_its_reason_or_graded_and_never_confuses_the_three(
        tmp_path):
    """`a` (no row) renders "not graded" with no bucket and no verdict line; an `ungradable:
    True` row renders its `ungradable_reason` escaped, no verdict line and no bucket;
    `prior_fake_key_precedent` and `no_remote_session` render their verdict, the verdict line
    and the judge model's bucket.
    """
    page = render(E.sample_episode(tmp_path))
    control = _world(page, E.CONTROL)
    assert "not graded" in control, control
    assert VERDICT_LINE not in control, control
    assert "lead-set" not in control
    assert "decision-discipline" not in control
    graded = _world(page, E.GRADED_WORLD)
    assert "inconclusive" in graded
    assert "decision-discipline" in graded
    assert f"{VERDICT_LINE}: inconclusive == malicious" in graded, graded
    passthrough = _world(page, E.PASSTHROUGH_WORLD)
    assert f"{VERDICT_LINE}: inconclusive == benign" in passthrough, passthrough
    assert "lead-set" in passthrough, passthrough
    assert "not graded" not in passthrough, passthrough
    assert "ungradable" not in passthrough, passthrough

    page = render(_ungradable_episode(tmp_path / "u"))
    ungradable = _world(page, E.PASSTHROUGH_WORLD)
    assert "ungradable" in ungradable
    assert "a call on 'elastic' faulted <b>x</b>" in ungradable
    assert "&lt;b&gt;x&lt;/b&gt;" in page.raw
    assert VERDICT_LINE not in ungradable, ungradable
    assert not page.section(f"world-{E.PASSTHROUGH_WORLD}").find_all(cls="w-bucket"), ungradable
    assert "lead-set" not in ungradable, ungradable


def test_1025_the_world_block_shows_the_verdict_line_and_the_stored_bucket_never_a_recomputed_one(
        tmp_path):
    """For `prior_fake_key_precedent` the world block shows the verdict line (`verdict =
    declared: inconclusive == malicious`) and then the judge model's own bucket,
    `decision-discipline`, and its systems; a synthetic row whose facts imply
    `analyze-discipline` (resolutions did not move) but stores `bucket: lead-set` renders
    `lead-set` (bucket read, never recomputed).
    """
    ep = E.sample_episode(tmp_path)
    graded = _world(render(ep), E.GRADED_WORLD)
    assert _ordered(graded, VERDICT_LINE, "inconclusive", "malicious", "decision-discipline",
                    f"systems: {E.SYSTEM}"), graded

    doc = E.sample_grade()
    doc["worlds"][1] = E.world_row(E.GRADED_WORLD, declared="malicious", bucket="lead-set",
                                   resolution_moved=False)
    E.write_judge(ep.dir, doc)
    graded = _world(render(ep), E.GRADED_WORLD)
    assert "lead-set" in graded, graded
    assert "analyze-discipline" not in graded, graded


def test_1025_world_chips_carry_the_judge_models_systems_and_every_draws_answer_and_never_a_default(
        tmp_path):
    """Each graded world's chip names the systems the judge model's answer touched; a row whose
    draws disagree (`bucket: None`, `systems: None`, `draws_disagree: True`) shows "no bucket"
    and one chip per draw with that draw's own bucket and systems — never reduced to one, never
    a default; a row with no `systems` field shows no systems chip rather than an invented
    value; the verdict line is present as well.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        assert f"systems: {E.SYSTEM}" in _world(page, label), _world(page, label)

    doc = E.sample_grade()
    doc["worlds"][1] = E.world_row(
        E.GRADED_WORLD, declared="malicious", bucket=None, systems=None, draws_disagree=True,
        measured=None)
    doc["worlds"][1]["draws"] = [{"draw": 0, "bucket": "lead-quality", "systems": ["identity"]},
                                 {"draw": 1, "bucket": "lead-set", "systems": [E.SYSTEM]}]
    doc["worlds"][1]["systems"] = None
    del doc["worlds"][0]["systems"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    graded = _world(page, E.GRADED_WORLD)
    assert "no bucket" in graded, graded
    assert _ordered(graded, "draw 0", "lead-quality", "identity", "draw 1", "lead-set",
                    E.SYSTEM), graded
    assert "systems:" not in graded, graded
    assert VERDICT_LINE in graded, graded
    passthrough = _world(page, E.PASSTHROUGH_WORLD)
    assert "systems:" not in passthrough, passthrough
    assert "lead-set" in passthrough, passthrough


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
    """Section headings carry the sample's counts (3 worlds, 13 findings, 5 stages); the worlds
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
    assert str(len(ST.EXPECTED_STEPS)) in h2("sec-stages"), h2("sec-stages")
    assert CONTROL_GUIDE in worlds
    for role, label, declared, axis in (("B", E.PASSTHROUGH_WORLD, "benign", E.AXIS_PASSTHROUGH),
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
    assert f"summary of l-001 for {E.PASSTHROUGH_WORLD}" in page.text_of(f"leads-{E.PASSTHROUGH_WORLD}")


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
             f"judge_{E.FAMILY}_0_trace", f"judge_{E.PASSTHROUGH_WORLD}_0_trace",
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
    (no family draw, no family row) the alert rule still resolves from the worlds'
    `alert.json` through `episode_alert`.
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
    E.write_judge(live.dir, E.sample_grade(family=False))
    assert E.ALERT_RULE in render(live).one("header").text()


# ---------------------------------------------------------------------------------------
# J5 — the frame channel
# ---------------------------------------------------------------------------------------


def _attribute_values(page: E.Page) -> list[str]:
    return [v for n in page.root.descendants() for v in n.attrs.values()]


def test_1025_a_manifest_label_off_the_token_alphabet_never_reaches_a_frame_slot(tmp_path):
    """A planted manifest label carrying markup and a space is refused by the manifest reader
    the page shares with the judge (`family.read_manifest`, the runtime loader's world-token
    gate): `render_episode` raises `JudgeRefused` naming the alphabet, and no page carrying the
    label is written — the label never becomes an id, an href or a heading (J5). Positive
    control: the same episode with its own manifest renders.
    """
    ep = E.sample_episode(tmp_path)
    render(ep)
    before = ep.page.read_bytes()
    hostile = 'evil<b onmouseover="x">label one'
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(hostile, role="D", axis="hostile axis",
                                          disposition_declared="benign"))
    T.write_family(ep.dir, manifest)
    with pytest.raises(J.sym("learning.judge", "JudgeRefused"), match="world-token alphabet"):
        E.render_episode(ep.dir, module=visualize_episode())
    assert ep.page.read_bytes() == before, "a refused manifest still rewrote the page"
    assert b"evil<b" not in before
    assert b"onmouseover" not in before


def test_1025_world_or_lead_directory_name_carries_attribute_or_tag_breaking_characters(tmp_path):
    """A `worlds/` directory whose name carries a quote and a tag never becomes an id, an href or
    a heading unescaped: it renders as an "unnameable entry" line, the name escaped as text, and
    no attribute value carries the raw characters (J5). A `runs/` directory of the same shape is
    no roster label, so it is not shown at all (#1105 PR 2, declared change 4/J3: the roster is
    the manifest's; before, it too rendered an "unnameable entry" line). Positive control: the
    three well-formed worlds keep their sections.
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
    assert page.text.count("unnameable entry") == 1, page.text_of("sec-worlds")
    assert 'w"x<i>' in page.text_of("sec-worlds"), page.text_of("sec-worlds")
    assert 'r"un' not in page.text, "a stray runs/ entry was shown"
    assert "r&quot;un" not in page.raw, "a stray runs/ entry was shown"
    assert not [v for v in _attribute_values(page) if '"x<i>' in v or 'un<i>' in v]
    assert "<i>" not in page.raw.replace("&lt;i&gt;", ""), "a raw <i> reached the bytes"
    assert {f"world-{w}" for w in E.WORLDS} <= set(page.ids)


def test_1025_a_bucket_or_reason_word_used_as_an_attribute_value(tmp_path):
    """A finding's bucket word and a world row's bucket built to break out of an attribute never
    become structure: the class comes from the closed map's neutral fallback, the raw word
    appears in no attribute value, and the word renders escaped as text (J5).
    """
    ep = E.sample_episode(tmp_path)
    word = 'x" onmouseover="alert(1)'
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=[
        E.finding(subject="defender", bucket=word, claim="attribute-breaking bucket")]))
    doc = E.sample_grade()
    doc["worlds"][0]["bucket"] = word
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert 'onmouseover="alert' not in page.raw, "the word broke out of its attribute"
    assert not [v for v in _attribute_values(page) if "onmouseover" in v]
    assert word in page.text
    row = page.section(f"f-{E.GRADED_WORLD}-0-0")
    assert "bucket-other" in row.classes or any("bucket-other" in n.classes for n in row.descendants())
    world = page.section(f"world-{E.PASSTHROUGH_WORLD}")
    assert [n for n in world.find_all(cls="w-bucket") if "bucket-other" in n.classes], (
        "the row's bucket did not take the neutral fallback class")
    assert word in world.text()


# ---------------------------------------------------------------------------------------
# J7 — the roster
# ---------------------------------------------------------------------------------------


def test_1025_judge_yaml_worlds_row_names_a_label_absent_from_family_yaml_and_runs(tmp_path):
    """A `judge.yaml` row for a label in neither the manifest nor `runs/` renders on the
    row-driven surfaces — its card and its findings group — marked
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


def test_1025_a_run_directory_whose_name_is_not_episode_dash_label(tmp_path):
    """A dir under `runs/` whose name does not decompose into `<episode_id>-<label>` is no
    roster label, so it gets no section and is not named anywhere on the page (#1105 PR 2,
    declared change 4/J3: the arm roster is the manifest's runnable labels, each opened by id;
    before, every `runs/` dir got a section and this one was marked "not declared in the
    manifest"). Positive control: the manifest's worlds keep exactly their sections.
    """
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / "stray_run_dir" / "gather_raw").mkdir(parents=True)
    page = render(ep)
    assert sorted(page.ids_with("world-")) == sorted(f"world-{w}" for w in E.WORLDS), page.ids
    assert "stray_run_dir" not in page.raw
    assert "not declared in the manifest" not in page.text


# ---------------------------------------------------------------------------------------
# J8 — section keying when runs/ and the record drift apart
# ---------------------------------------------------------------------------------------


def test_1025_render_when_a_graded_world_has_no_matching_runs_dir(tmp_path):
    """A graded world whose run dir is gone keeps its section: the record-derived parts
    (verdict, bucket, verdict line, card, findings group) render and the run-dir-derived parts read
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


# ---------------------------------------------------------------------------------------
# J16 — small per-world choices
# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
# settled — world states, leaves, the header frame
# ---------------------------------------------------------------------------------------


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
    plant_source_copy(ep.dir, json.dumps(
        {"alert_id": "id<img src=x onerror=alert(1)>", "rule": {"name": "<b>rule</b> name"}}
    ).encode("utf-8"))
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
    from defender.run_repository import RunPaths

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


# ---------------------------------------------------------------------------------------
# The review of PR #1042 — headings count the list they head; the ledger and the document
# are two slots
# ---------------------------------------------------------------------------------------


def test_1025_the_worlds_and_leads_headings_count_exactly_the_sections_under_them(tmp_path):
    """"Worlds (N)" is the number of `world-*` sections rendered and "Leads (M)" the number of
    `leads-*` blocks — the roster is classified ONCE at load and both headings count that same
    list. Before, the worlds heading counted the entries (omitting the stray `runs/` dirs it
    still rendered sections for) and the leads heading counted every roster label (including
    the unnameable ones it then skipped): "Worlds (3)" over four sections plus one unnameable
    line, "Leads (5)" over four blocks.

    #1105 PR 2 (declared change 4/J3): `runs/` dirs are no longer roster lines — the stray and
    the `bad name!` dir under `runs/` get no section and are not named; the unnameable roster
    line now comes from a grade-record row labelled `bad name!` (the record's labels are still
    on the roster)."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / "stray_run_dir" / "gather_raw").mkdir(parents=True)
    (ep.dir / "runs" / "bad name!" / "gather_raw").mkdir(parents=True)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row("bad name!", declared="benign"))
    E.write_judge(ep.dir, doc)
    page = render(ep)
    world_sections = page.ids_with("world-")
    leads_blocks = page.ids_with("leads-")
    assert len(world_sections) == len(E.WORLDS), world_sections
    assert "stray_run_dir" not in page.raw
    assert len(leads_blocks) == len(world_sections), (leads_blocks, world_sections)
    worlds_heading = page.section("sec-worlds").find_all("h2")[0].text()
    leads_heading = page.section("sec-leads").find_all("h2")[0].text()
    assert worlds_heading == f"Worlds ({len(world_sections)})", worlds_heading
    assert leads_heading == f"Leads ({len(leads_blocks)})", leads_heading
    assert "unnameable entry" in page.text_of("sec-worlds")
    assert "bad name!" in page.text_of("sec-worlds")


def test_1025_a_missing_or_unreadable_served_ledger_costs_the_leads_block_only_the_ledger(tmp_path):
    """The served ledger and `investigation.md` are two records read by two readers: with the
    ledger gone (or a link planted at its name) the block reads the ledger's own note and STILL
    carries every investigation-derived fact — the resolutions, the hand-off note, the
    referenced-lead roster. Before, the page read both through the composed `read_world_facts`,
    which refuses on the ledger FIRST, so a missing ledger erased an intact document and the
    loss was reported under the wrong label, "investigation record unavailable"."""
    ep = E.sample_episode(tmp_path)
    ledger = ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl"
    ledger.unlink()
    E.plant_link(ep.dir / "served" / f"{T.world_token(E.PASSTHROUGH_WORLD)}.jsonl",
                 ep.dir / "family.yaml")
    page = render(ep)
    for label, note in ((E.GRADED_WORLD, "served ledger: absent"),
                        (E.PASSTHROUGH_WORLD, "served ledger unreadable")):
        block = page.text_of(f"leads-{label}")
        assert note in block, block
        assert "investigation record unavailable" not in block, block
        assert "the hand-off was revisited after the branch" in block, block
        assert f"summary of l-001 for {label}" in block, block
        assert "l-00c" in block, block
    # and the converse: an unreadable document with an intact ledger names the document
    E.plant_raw(ep.world(E.CONTROL) / "investigation.md", b"\xff\xfe\x00 not text")
    block = render(ep).text_of(f"leads-{E.CONTROL}")
    assert "investigation record unavailable" in block, block
    assert "served ledger" not in block, block


