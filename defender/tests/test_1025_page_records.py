"""#1025 — the records section, the per-record refusal policy, the value-channel escape, the
one-reader discipline, and the housekeeping the page PR owes.

O8/O9 and J6/J12 as the human resolved them (§7 Q5, Q10, Q11): only `family.yaml` refuses the
page; every other record a reader refuses renders the reader's refusal sentence, escaped, in
its own slot — "grade record unreadable" in the band, "timing record unreadable" with an empty
wall column, "staging record unreadable" / "review record unreadable" / "samples record
unreadable" / "provenance record unreadable" in the records section, "review block unreadable"
per world — never folded into "absent", each read inside its own boundary catching the reader's
refusal class AND `OSError` (three readers leak a bare `PermissionError` today, p6). Reader-side
moves this PR makes (O8, as the human restated Q5 at the second §7 sitting, 71-resolutions-f
F-4): the PAGE reads `samples.yaml` strictly — a strict reader passed through
`read_samples_record`'s existing `reader=` seam — while the
DEFAULT reader stays permissive, so `grade_episode` / `grade_family` / `judge_render` keep
grading an episode whose `samples.yaml` is malformed exactly as today (#1007 M4/O5; the
coherence test at the end of this file); the root `provenance.json` is read through a new
public accessor in the record-names home (`archive.read_family_stamp`, beside
`FAMILY_STAMP_NAME`, moved there from `branch/cli.py`) that refuses a directory or a document
that is not the stamp; the symlink/FIFO screen on `report.md` / `investigation.md` lives INSIDE
the world-archive reader path — `_read_archived_text` and the `read_report` call inside
`read_world_facts` — and NOT in the repo-wide `_report.read_report` (nine production callers
outside this graph), so the grading pass and the judge input builder read `world_archive`
through the same screen the page does (the two coherence demands minted at §7). The page
encodes with `errors="replace"` before `write_guarded`, lets no NUL byte through and puts
U+FFFD where a NUL stood (the R6 hole; F-7): a NUL or a lone surrogate in a record never fails
the render.

RED AGAINST HEAD: the page module does not exist; the reader-side accessor and screen do not
exist either, and their tests fail on the reader, once each.
"""
from __future__ import annotations

import ast
import json
import os
import time
from pathlib import Path

import pytest
import yaml

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_episode_reader as R
from defender.tests._by_path import load_lint_gate

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")

REPO_ROOT = Path(__file__).resolve().parents[2]
VULTURE_BASELINE = REPO_ROOT / "scripts" / "lint" / "lint_vulture_baseline.json"
PAGE_PATH = "scripts/visualize/visualize_episode.py"
RECORD_NAMES = ("judge.yaml", "review.yaml", "samples.yaml", "family.yaml", "staged.yaml",
                "timing.json", "provenance.json")
PACKAGE_READERS = ("read_grade", "draws_on_disk_report", "read_stage_timings", "raw_manifest",
                   "read_review_record", "read_samples_record", "read_staged",
                   # The ledger and the investigation document are TWO reads, each its own
                   # slot (#1025): the page never asks the composed `read_world_facts`, whose
                   # ledger-first refusal cost the leads block an intact `investigation.md`.
                   "world_review_block", "read_world_ledger", "read_investigation_facts",
                   "leads_by_id", "lead_chain", "json_mapping", "read_family_stamp")
MARKUP = "<script>alert(1)</script><img src=x onerror=alert(1)>"


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


def _records(page: E.Page) -> str:
    return page.text_of("sec-records")


def _sections(page: E.Page) -> dict[str, str]:
    return {s: page.text_of(s) for s in ("sec-verdict", "sec-worlds", "sec-findings",
                                          "sec-stages", "sec-leads", "sec-records")}


# ---------------------------------------------------------------------------------------
# d31 / d32 — records tolerate absence; the value channel is escaped
# ---------------------------------------------------------------------------------------


def test_1025_each_record_in_the_records_section_renders_as_absent_when_missing_and_its_content_when_present(
        tmp_path):
    """The live-996 shape renders `samples.yaml` as "absent" and the other three present; a
    copy with `staged.yaml`, `review.yaml` and `provenance.json` removed renders each as
    "absent" without raising; the sample renders the base story, the discriminator predicate,
    the three worlds, the two sample patterns, the staged names with the teardown's `at` and its
    failures, and the provenance stamp's `agreed` commit.
    """
    ep = E.sample_episode(tmp_path)
    review = yaml.safe_load((ep.dir / "review.yaml").read_text(encoding="utf-8"))
    review["teardown"] = {"at": "2026-09-09T17:20:00+00:00",
                          "failures": [{"name": "wv-stale-name", "detail": "still present after delete"}]}
    (ep.dir / "review.yaml").write_text(yaml.safe_dump(review, sort_keys=True), encoding="utf-8")
    text = _records(render(ep))
    for expected in (E.BASE_STORY, "p", E.WITHHELD_WORLD, E.GRADED_WORLD, "logs-system.auth-*",
                     "logs-falco.alerts-*", "wv-", "2026-09-09T17:20:00", "wv-stale-name",
                     "still present after delete", E.LESSONS_COMMIT[:8]):
        assert expected in text, (expected, text)
    assert "absent" not in text, text

    live = E.sample_episode(tmp_path / "live", samples=False)
    text = _records(render(live))
    assert "absent" in text, text
    assert "logs-falco.alerts-*" not in text, text

    for name in ("staged.yaml", "review.yaml", "provenance.json"):
        (live.dir / name).unlink()
    text = _records(render(live))
    assert text.count("absent") >= 4, text


def test_1025_markup_in_every_model_authored_field_renders_as_text_on_every_section(tmp_path):
    """A copied episode with `<script>alert(1)</script><img src=x onerror=alert(1)>` planted in
    a finding's `claim`, `root_cause`, `anchor`, `topic`, `evidence[0]`, a world's `axis`, the
    base story, an `ungradable_reason`, `envelope_failed`, a framed `prompt` and `reply`, a
    lead's goal and summary, `enqueued_to`, an `unqueueable_findings` entry and
    `discard_evidence` renders each occurrence escaped (`&lt;script&gt;`, the handler split) and
    the raw `<script>` nowhere; positive control: the planted text is visible, escaped, in every
    section and the header.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest(base_story=f"story {MARKUP}")
    manifest["worlds"][2]["axis"] = f"axis {MARKUP}"
    T.write_family(ep.dir, manifest)
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=[E.finding(
        subject="defender", claim=f"claim {MARKUP}", root_cause=f"root {MARKUP}",
        anchor=f"anchor {MARKUP}", topic=f"topic {MARKUP}", evidence=[f"evidence {MARKUP}"])]))
    doc = E.sample_grade()
    doc["worlds"][0] = E.ungradable_row(E.WITHHELD_WORLD, declared="benign", reason=f"reason {MARKUP}")
    doc["withheld_findings"] = []
    doc["enqueued_to"] = f"/queue/{MARKUP}"
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/1: {MARKUP}"]
    doc["discard_evidence"] = {"review_pointer": f"pointer {MARKUP}"}
    E.write_judge(ep.dir, doc)
    reach = E.reachability(envelope_ran=False, envelope_failed=f"failed {MARKUP}")
    J.review_record(ep.dir, worlds={E.CONTROL: E.review_world("A", E.CONTROL),
                                    E.WITHHELD_WORLD: E.review_world("B", E.WITHHELD_WORLD, reach=reach),
                                    E.GRADED_WORLD: E.review_world("C", E.GRADED_WORLD, reach=reach)})
    E.write_framed(ep.dir, f"judge:{E.GRADED_WORLD}:0", prompt=f"prompt {MARKUP}", reply=f"reply {MARKUP}")
    world = ep.world(E.GRADED_WORLD)
    (world / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": f"goal {MARKUP}"}), encoding="utf-8")
    (world / "gather_summaries" / "l-001.md").write_text(f"summary {MARKUP}\n", encoding="utf-8")
    for label in E.WORLDS:
        (ep.world(label) / "alert.json").write_text(json.dumps(
            {"alert_id": "id", "rule": {"name": f"rule {MARKUP}"}}), encoding="utf-8")
    page = render(ep)
    assert "<script>" not in page.raw
    assert "<img" not in page.raw
    assert "onerror=" not in page.raw.replace("on​error", ""), "an unsplit handler survived"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.raw
    for section, text in _sections(page).items():
        assert MARKUP in text, f"{section} shows no escaped occurrence"
    assert MARKUP in page.one("header").text()


def test_1025_markup_in_the_records_no_planted_field_covers(tmp_path):
    """Every record string the page renders passes the untrusted escape: markup planted in the
    samples, a staged name, a review invention and a mismatch key, a provenance `dirty_paths`
    entry, the envelope query, the continuation prompt, a `noise_floor_note`, a `spread` key,
    an unqueueable reason, `draws_failed_reason`, `family_failed_reason`, an integrity note, a
    correlation and a derivation is never on the page raw; positive control: the bound ones
    (samples, staged name, dirty path, envelope query, unqueueable reason,
    `family_failed_reason`) are visible escaped.
    """
    ep = E.sample_episode(tmp_path)
    E.write_samples(ep.dir, {f"pattern {MARKUP}": {"field": f"value {MARKUP}"}})
    (ep.dir / "staged.yaml").write_text(yaml.safe_dump([
        {"world": T.world_token(E.GRADED_WORLD), "name": f"wv-name {MARKUP}", "kind": "index",
         "derived_from": "logs-*", "created_at": "2026-09-09T16:52:11+00:00"}]), encoding="utf-8")
    review = yaml.safe_load((ep.dir / "review.yaml").read_text(encoding="utf-8"))
    review["worlds"][E.GRADED_WORLD]["inventions"] = [f"invention {MARKUP}"]
    review["worlds"][E.GRADED_WORLD]["consistency"]["control_mismatch_keys"] = [f"key {MARKUP}"]
    (ep.dir / "review.yaml").write_text(yaml.safe_dump(review, sort_keys=True), encoding="utf-8")
    E.write_stamp(ep.dir, dirty=True, dirty_paths=[f"path {MARKUP}"])
    manifest = E.sample_manifest(continuation_prompt=f"continue {MARKUP}")
    manifest["discriminator"]["envelope"]["params"]["query"] = f"FROM logs {MARKUP}"
    T.write_family(ep.dir, manifest)
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(
        findings=[E.finding(subject="defender")], noise_floor_note=f"noise {MARKUP}",
        correlations=[{"fact": f"corr {MARKUP}"}], derivations=[{"chain": f"deriv {MARKUP}"}]))
    doc = E.sample_grade()
    doc["worlds"][1]["spread"] = {f"spread {MARKUP}": 1}
    doc["worlds"][1]["integrity_notes"] = [f"integrity {MARKUP}"]
    doc["worlds"][1]["draws_failed_reason"] = f"draws {MARKUP}"
    doc["family_failed_reason"] = f"family {MARKUP}"
    doc["family_outcome"] = None
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/0: reason {MARKUP}"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "<script>" not in page.raw
    assert "<img" not in page.raw
    for bound in (f"pattern {MARKUP}", f"wv-name {MARKUP}", f"path {MARKUP}", f"FROM logs {MARKUP}",
                  f"reason {MARKUP}", f"family {MARKUP}"):
        assert bound in page.text, bound


def test_1025_non_ascii_and_control_characters_in_rendered_strings(tmp_path):
    """The page declares and writes UTF-8; an em dash, a zero-width space and a bidi override
    survive as text (only markup characters are escaped). A record string carrying a NUL or a
    lone surrogate — reachable through a YAML `"\\uD800"` scalar in a draw document and a JSON
    `\\ud800` escape in `alert.json` (p4) — does not crash the render: the page renders, the
    rest of the string survives, no 0x00 byte lands in `learning.html`, and the NUL is
    replaced by U+FFFD exactly where it stood (the human's F-7 decision: `errors="replace"`
    does nothing to a NUL, so the page substitutes it on the same path as a lone surrogate).
    """
    ep = E.sample_episode(tmp_path)
    exotic = "a—b​c‮d"
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(
        findings=[E.finding(subject="defender", claim=f"claim {exotic}")]))
    page = render(ep)
    assert 'charset="utf-8"' in page.raw.lower().replace("'", '"') or "charset=utf-8" in page.raw.lower()
    assert f"claim {exotic}" in page.text_of(f"f-{E.GRADED_WORLD}-0-0")

    draws = ep.world(E.GRADED_WORLD) / "judge"
    E.plant_raw(draws / "0.yaml",
                'episode_outcome: gradable\ndropped_findings: 0\nfindings:\n'
                '  - {subject: defender, bucket: lead-set, claim: "before\\uD800after",'
                ' root_cause: "nul\\0here", anchor: l-001, topic: t, evidence: [e]}\n')
    assert (draws / "0.yaml").read_text(encoding="utf-8")
    (ep.world(E.CONTROL) / "alert.json").write_text(
        '{"alert_id": "x", "rule": {"name": "rule\\ud800name"}}', encoding="utf-8")
    page = render(ep)
    raw_bytes = ep.page.read_bytes()
    assert b"\x00" not in raw_bytes, "a NUL byte landed in the page"
    row = page.text_of(f"f-{E.GRADED_WORLD}-0-0")
    assert "before" in row, row
    assert "after" in row, row
    assert "nul�here" in row, row
    assert "rule" in page.one("header").text()
    assert "name" in page.one("header").text()


def test_1025_the_page_encodes_with_errors_replace_before_the_guarded_write(tmp_path):
    """The R6 hole, resolved: the page encodes its document with `errors="replace"` before the
    guarded write, so a lone surrogate in a record becomes the encoder's replacement character
    rather than a `UnicodeEncodeError` out of the render (p4: `write_guarded` is strict), and a
    NUL — which `errors="replace"` leaves untouched (p4 writes it verbatim) — is substituted
    with U+FFFD on the same path, never written through (71-resolutions-f, F-7). Observable: a
    record with `"x\\uD800y and n\\0l"` renders to a page whose bytes decode as UTF-8, carry `x`
    and `y` with one replacement character between them, carry `n\\uFFFDl` where the NUL was,
    and carry no 0x00.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/1: x\ud800y and n\x00l"]
    E.write_judge(ep.dir, doc, check=False)
    visualize_episode().render_episode(ep.dir)
    raw = ep.page.read_bytes()
    text = raw.decode("utf-8")
    assert b"\x00" not in raw
    assert "x?y" in text or "x�y" in text, "the surrogate was not replaced"
    assert "n�l" in text, "the NUL was not replaced by U+FFFD where it stood"
    assert "\ud800" not in text


# ---------------------------------------------------------------------------------------
# J6 — the per-record refusal policy
# ---------------------------------------------------------------------------------------


def test_1025_judge_yaml_has_invalid_yaml_syntax(tmp_path):
    """A present-but-corrupt `judge.yaml` is a different state from absence: `read_grade`
    raises rather than returning `None` (F25), and the band renders "grade record unreadable"
    with the reader's reason — never the "no grade record" band — while every other section
    renders as on the intact episode.
    """
    ep = E.sample_episode(tmp_path)
    intact = _sections(render(ep))
    E.plant_raw(ep.dir / "judge.yaml", "worlds: [\n  {world: b")
    page = render(ep)
    band = page.text_of("sec-verdict")
    assert "grade record unreadable" in band, band
    assert "no grade record" not in band, band
    assert page.text_of("sec-stages") == intact["sec-stages"]
    assert page.text_of("sec-leads") == intact["sec-leads"]


def test_1025_timing_json_is_present_but_not_the_stageclock_record_shape(tmp_path):
    """A `timing.json` that is not the record's shape — planted, or torn mid-rewrite, the two
    are byte-identical to the reader — is a distinguishable REFUSED state: the stage table
    renders "timing record unreadable" with an empty wall column, never "not on the record"
    for every step, and the other sections render as on the intact episode.
    """
    ep = E.sample_episode(tmp_path)
    intact = _sections(render(ep))
    for raw in ('{"steps": [{"step": "questioner"}]}', '{"steps": [{"step": "questioner", "st'):
        E.write_timing(ep.dir, raw=raw)
        page = render(ep)
        stages = page.text_of("sec-stages")
        assert "timing record unreadable" in stages, stages
        assert "not on the record" not in stages, stages
        # Scoped to the TABLE (`stage-timing`), not the whole section: `sec-stages` also holds
        # every call's own transcript block, and the sample's real judge response durations
        # legitimately format to "1m00s" there — unrelated to whether `timing.json` itself
        # parsed. The docstring's own claim is about the table's wall column, not the section.
        assert "1m00s" not in page.text_of("stage-timing")
        assert page.text_of("sec-verdict") == intact["sec-verdict"]
        assert page.text_of("sec-worlds") == intact["sec-worlds"]


def test_1025_timing_json_names_a_step_outside_the_steps_vocabulary(tmp_path):
    """`read_stage_timings` raises `ValueError` on a step name outside `STEPS` (g23): the table
    takes the same refused arm — "timing record unreadable", an empty wall column — and nothing
    else on the page changes.
    """
    ep = E.sample_episode(tmp_path)
    intact = _sections(render(ep))
    E.write_timing(ep.dir, [("prologue", "2026-09-09T10:00:00Z", "2026-09-09T10:01:00Z")], check=False)
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "timing record unreadable" in stages, stages
    assert "prologue" not in stages, stages
    assert page.text_of("sec-findings") == intact["sec-findings"]


def test_1025_review_yaml_is_present_but_its_worlds_key_is_absent(tmp_path):
    """A `review.yaml` without a `worlds` key is read (the reader returns the mapping), so every
    world's review block reads "no review record for this world" and its review-derived chips
    "unrecorded", while the records section renders the record's own `episode` block — present,
    not "absent" and not "unreadable".
    """
    ep = E.sample_episode(tmp_path)
    (ep.dir / "review.yaml").write_text(yaml.safe_dump(
        {"episode": {"episode_id": E.EPISODE_ID, "decision": "accepted", "outcome": "accepted",
                     "reason": "", "unreadable_capture_rows": 0}}), encoding="utf-8")
    page = render(ep)
    for label in (E.WITHHELD_WORLD, E.GRADED_WORLD):
        world = page.text_of(f"world-{label}")
        assert "no review record for this world" in world, world
        assert "unrecorded" in world, world
    records = _records(page)
    assert "review record unreadable" not in records, records
    assert "accepted" in records, records


def test_1025_review_yaml_cannot_be_read_as_the_expected_record(tmp_path):
    """A `review.yaml` the reader refuses (`JudgeRefused` on a document that is not the record)
    renders "review record unreadable" in the records section and "review block unreadable" in
    every world section — distinct from "never written" — and nothing else changes.
    """
    ep = E.sample_episode(tmp_path)
    intact = _sections(render(ep))
    E.plant_raw(ep.dir / "review.yaml", "worlds: {\n  b: [")
    page = render(ep)
    assert "review record unreadable" in _records(page), _records(page)
    for label in (E.WITHHELD_WORLD, E.GRADED_WORLD):
        world = page.text_of(f"world-{label}")
        assert "review block unreadable" in world, world
        assert "absent" not in world, world
    assert page.text_of("sec-findings") == intact["sec-findings"]
    assert page.text_of("sec-stages") == intact["sec-stages"]


def test_1025_malformed_samples_or_provenance_reads_as_absent(tmp_path):
    """The inconsistency is closed (J6, an O8 move): a malformed `samples.yaml` and a malformed
    root `provenance.json` render "samples record unreadable" / "provenance record unreadable"
    in the records section — never "absent", which is reserved for absence. The page's strict
    reading of `samples.yaml` is the page's own (F-4: a strict reader through the `reader=`
    seam; the default the judge reads through stays permissive). Positive control: with the two
    files removed the section says "absent" for each.
    """
    ep = E.sample_episode(tmp_path)
    E.plant_raw(ep.dir / "samples.yaml", "logs-*: [\n  {")
    E.plant_raw(ep.dir / "provenance.json", "{\"agreed\": {")
    text = _records(render(ep))
    assert "samples record unreadable" in text, text
    assert "provenance record unreadable" in text, text
    assert "absent" not in text, text
    (ep.dir / "samples.yaml").unlink()
    (ep.dir / "provenance.json").unlink()
    text = _records(render(ep))
    assert text.count("absent") >= 2, text
    assert "unreadable" not in text, text


def test_1025_an_alias_planted_at_each_record_name(tmp_path):
    """A symlink planted at each record's name — `judge.yaml`, `timing.json`, `review.yaml`,
    `samples.yaml`, `staged.yaml`, `provenance.json` — is refused by that record's reader and
    renders that record's own refusal sentence in its own slot; the link's target content
    appears nowhere; `family.yaml` alone refuses the whole page (d01).
    """
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE-TARGET-CONTENT", encoding="utf-8")
    for name in ("judge.yaml", "timing.json", "review.yaml", "samples.yaml", "staged.yaml",
                 "provenance.json"):
        E.plant_link(ep.dir / name, outside)
    page = render(ep)
    assert "OUTSIDE-TARGET-CONTENT" not in page.raw
    assert "grade record unreadable" in page.text_of("sec-verdict")
    assert "timing record unreadable" in page.text_of("sec-stages")
    records = _records(page)
    for sentence in ("review record unreadable", "samples record unreadable",
                     "staging record unreadable", "provenance record unreadable"):
        assert sentence in records, (sentence, records)
    assert "absent" not in records, records
    E.plant_link(ep.dir / "family.yaml", outside)
    with pytest.raises(J.sym("learning.judge", "JudgeRefused")):
        visualize_episode().render_episode(ep.dir)


def test_1025_a_malformed_record_versus_an_absent_one(tmp_path):
    """For each of `samples.yaml`, `provenance.json`, `review.yaml`, `staged.yaml` the page
    shows two DIFFERENT states: "absent" when the file is missing and "<record> unreadable" when
    it is present and refused — the page reads each through a reader that refuses corruption
    (J6, O8): the root-stamp accessor for `provenance.json`, a strict samples reader through
    the `reader=` seam for `samples.yaml` (the default stays permissive, F-4), the package
    readers' own refusal classes for the other two.
    """
    ep = E.sample_episode(tmp_path)
    for name, sentence in (("samples.yaml", "samples record unreadable"),
                           ("provenance.json", "provenance record unreadable"),
                           ("review.yaml", "review record unreadable"),
                           ("staged.yaml", "staging record unreadable")):
        fresh = E.copy_episode(ep, tmp_path / f"absent-{name}")
        (fresh.dir / name).unlink()
        assert "absent" in _records(render(fresh)), name
        assert sentence not in _records(render(fresh)), name
        broken = E.copy_episode(ep, tmp_path / f"broken-{name}")
        E.plant_raw(broken.dir / name, "{\n  [")
        text = _records(render(broken))
        assert sentence in text, (name, text)
        assert "absent" not in text, (name, text)


def test_1025_a_torn_staging_record(tmp_path):
    """A `staged.yaml` caught mid-append (`StagingRefused`) renders "staging record unreadable"
    in the records section — not "no staged patterns" — while the staging STAGE ROW in the
    timing table is unaffected.
    """
    ep = E.sample_episode(tmp_path, timing=True)
    intact = render(ep).text_of("stage-timing")
    with (ep.dir / "staged.yaml").open("a", encoding="utf-8") as fh:
        fh.write("- world: {torn\n")
    page = render(ep)
    assert "staging record unreadable" in _records(page), _records(page)
    assert "no staged" not in _records(page).lower()
    assert page.text_of("stage-timing") == intact


@NOT_ROOT
def test_1025_an_unreadable_regular_file_at_a_record_name(tmp_path):
    """A permission-denied regular file at each record's name takes that record's refusal
    slot — `read_guarded` answers EACCES with a refusal tuple (p6) and the three readers that
    leak a bare `PermissionError` (`read_staged`, the served ledger, a lead summary) are held by
    the page's per-record boundary — so the render never raises and each slot reads
    "<record> unreadable"; a permission-denied `family.yaml` alone refuses the whole page
    (d01's arm: `render_episode` raises the manifest reader's `JudgeRefused`).
    """
    ep = E.sample_episode(tmp_path)
    names = ("judge.yaml", "timing.json", "review.yaml", "samples.yaml", "staged.yaml",
             "provenance.json")
    E.write_timing(ep.dir, E.six_steps())
    # Every path denied is restored — the ledger and the summary included, or they stay
    # mode 000 for the rest of the tmp tree's life.
    denied = [ep.dir / name for name in names] + [
        ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl",
        ep.world(E.GRADED_WORLD) / "gather_summaries" / "l-001.md"]
    for path in denied:
        path.chmod(0)
    try:
        page = render(ep)
    finally:
        for path in denied:
            path.chmod(0o644)
    assert "grade record unreadable" in page.text_of("sec-verdict")
    assert "timing record unreadable" in page.text_of("sec-stages")
    records = _records(page)
    for sentence in ("review record unreadable", "samples record unreadable",
                     "staging record unreadable", "provenance record unreadable"):
        assert sentence in records, (sentence, records)
    assert "unreadable" in page.text_of(f"leads-{E.GRADED_WORLD}")
    (ep.dir / "family.yaml").chmod(0)
    try:
        with pytest.raises(J.sym("learning.judge", "JudgeRefused")):
            visualize_episode().render_episode(ep.dir)
    finally:
        (ep.dir / "family.yaml").chmod(0o644)


def test_1025_a_served_ledger_present_but_truncated(tmp_path):
    """A served ledger truncated mid-append reads as partial content plus a malformed-row count
    (p7: `WorldFacts.malformed_rows`): the world's leads block renders its leads and says
    "1 malformed row", never "never run" and never a whole-block refusal.
    """
    ep = E.sample_episode(tmp_path)
    ledger = ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl"
    rows = [json.dumps(J.staged_row(E.GRADED_WORLD)), json.dumps(J.ledger_row(source="passthrough", world_label=E.GRADED_WORLD))]
    ledger.write_text(rows[0] + "\n" + rows[1][: len(rows[1]) // 2], encoding="utf-8")
    page = render(ep)
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "1 malformed row" in block, block
    assert f"goal of l-001 in {E.GRADED_WORLD}" in block, block
    assert "unreadable" not in block, block
    assert "never run" not in block, block


def test_1025_one_malformed_sidecar_record_sits_beside_otherwise_intact_ones(tmp_path):
    """Only the section fed by the bad record carries a refusal sentence; every other section
    renders exactly as on the intact episode — each record is read inside its own boundary.

    Spec resolution (human-authorized, see the PR body's "Spec resolution" note): this test
    and `test_1025_timing_json_is_present_but_not_the_stageclock_record_shape` asserted
    mutually exclusive behavior for `sec-verdict`'s own "lower bound on wall" fallback under a
    malformed `timing.json` — one wanted it to match the never-had-timing render, the other the
    had-valid-timing render, and no single implementation can satisfy both from the same
    on-disk bytes. The kept behavior: a `timing.json` that is present but does not parse gives
    the verdict tile nothing more to show than one that was never written at all, so its own
    "lower bound" fallback is owed in both cases — the sibling test now pins this directly.
    `sec-verdict` is therefore checked against a NEVER-had-timing baseline here, not against
    this test's own valid-timing `intact` snapshot; every other section is untouched by
    `timing.json`'s health either way and still checks against `intact`.
    """
    ep = E.sample_episode(tmp_path, timing=True)
    intact = _sections(render(ep))
    never_timing = _sections(render(E.sample_episode(tmp_path / "never-timing")))
    E.write_timing(ep.dir, raw="not json at all")
    page = render(ep)
    broken = _sections(page)
    assert "timing record unreadable" in broken["sec-stages"]
    assert broken["sec-verdict"] == never_timing["sec-verdict"]
    for section in ("sec-worlds", "sec-findings", "sec-leads", "sec-records"):
        assert broken[section] == intact[section], section


# ---------------------------------------------------------------------------------------
# J12 — the root stamp
# ---------------------------------------------------------------------------------------


def test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name(tmp_path):
    """The episode-root `provenance.json` has a reader of its own (fk-8/J12): a public accessor
    in the record-names home, `archive.read_family_stamp(episode_dir)`, distinct from the
    per-world run-stamp reader — `None` when nothing is at the name, the `{agreed, allow_dirty}`
    mapping when the stamp is there, a `ValueError` refusal for a directory or a document that
    is not the stamp — and `FAMILY_STAMP_NAME` lives beside the other record names in
    `learning/branch/archive.py`, bound nowhere else.
    """
    archive = E.mod("learning.branch.archive")
    assert archive.FAMILY_STAMP_NAME == "provenance.json"
    cli_source = (Path(E.mod("learning.branch.cli").__file__)).read_text(encoding="utf-8")
    assert "FAMILY_STAMP_NAME =" not in cli_source, "the constant is still bound in cli.py"
    ep = E.sample_episode(tmp_path, stamp=False)
    assert archive.read_family_stamp(ep.dir) is None
    E.write_stamp(ep.dir, commit="abc123", allow_dirty=True)
    stamp = archive.read_family_stamp(ep.dir)
    assert stamp["agreed"]["commit"] == "abc123"
    assert stamp["allow_dirty"] is True
    E.plant_raw(ep.dir / "provenance.json", json.dumps(T.provenance_record()))
    with pytest.raises(ValueError, match="provenance.json"):
        archive.read_family_stamp(ep.dir)
    (ep.dir / "provenance.json").unlink()
    (ep.dir / "provenance.json").mkdir()
    with pytest.raises(ValueError, match="provenance.json"):
        archive.read_family_stamp(ep.dir)


def test_1025_episode_root_provenance_json_is_a_directory(tmp_path):
    """A directory squatting the episode-root `provenance.json` is refused by the root-stamp
    reader and the records section renders "provenance record unreadable" — never "absent".
    """
    ep = E.sample_episode(tmp_path, stamp=False)
    (ep.dir / "provenance.json").mkdir()
    text = _records(render(ep))
    assert "provenance record unreadable" in text, text
    assert "absent" not in text, text


def test_1025_the_episode_root_and_a_worlds_provenance_json_use_different_key_shapes_at_the_same_file_name(
        tmp_path):
    """Two files share the name and not the shape: the root stamp `{agreed: {…}, allow_dirty}`
    renders its `agreed` fields (commit, model, dirty) and `allow_dirty` in the records section
    through the root-stamp reader, and a world's flat run stamp renders its own commit in that
    world's section through `json_mapping`; a root file in the WORLD shape is refused as not the
    stamp ("provenance record unreadable").
    """
    ep = E.sample_episode(tmp_path, stamp=False)
    E.write_stamp(ep.dir, commit="rootcommit0123", dirty=True, dirty_paths=["defender/x.py"], allow_dirty=True)
    (ep.world(E.GRADED_WORLD) / "provenance.json").write_text(
        json.dumps(T.provenance_record(commit="worldcommit456")), encoding="utf-8")
    page = render(ep)
    records = _records(page)
    for part in ("rootcommit0123", "glm-5.2", "defender/x.py", "allow_dirty"):
        assert part in records, (part, records)
    assert "worldcommit456" in page.text_of(f"world-{E.GRADED_WORLD}")
    (ep.dir / "provenance.json").write_text(json.dumps(T.provenance_record(commit="flatroot789")), encoding="utf-8")
    text = _records(render(ep))
    assert "provenance record unreadable" in text, text
    assert "flatroot789" not in text, text


# ---------------------------------------------------------------------------------------
# d34 / d35 / census — one reader, the baseline, the tree-read lint
# ---------------------------------------------------------------------------------------


def test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper():
    """The page module's AST contains no `yaml.safe_load` / `json.loads` call, no string
    constant equal to any of `judge.yaml`, `review.yaml`, `samples.yaml`, `family.yaml`,
    `staged.yaml`, `timing.json`, `provenance.json`, `judge`, and no `from … import _name`
    across modules; its reads resolve to the package readers (`read_grade`, `draws_on_disk_report`,
    `read_stage_timings`, `raw_manifest`, `read_review_record`, `read_samples_record`,
    `read_staged`, `world_review_block`, `read_world_facts`, `leads_by_id`, `lead_chain`,
    `json_mapping`, `read_family_stamp`, `read_archived_report` — the world-archive reader
    path's own screened `report.md` read), each named in the module; the repo-wide census of
    record-name literals has one home per name (x18).
    Rejected: `learning.judge.render.render` is never imported for a call. Rejected, the
    footer half of brief fact F15 (O6, 92-reconciliation F-3): the module never names
    `render_footer`, `_lesson_changes`, `_git` or `subprocess` — anywhere, as a name, an
    attribute or an import — because the run page's footer shells out to `git` at the
    checkout, and a page whose bytes depend on the checkout's lesson history is not rendered
    from the episode directory alone.
    """
    module = visualize_episode()
    source = Path(module.__file__).read_text(encoding="utf-8")
    strings, _bound = R._census(source, PAGE_PATH)
    assert not (strings & {*RECORD_NAMES, "judge"}), strings & {*RECORD_NAMES, "judge"}
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert (node.func.attr, getattr(node.func.value, "id", None)) not in (
                ("safe_load", "yaml"), ("loads", "json"), ("load", "yaml"), ("load", "json")), ast.dump(node)
        if isinstance(node, ast.ImportFrom):
            assert not [a.name for a in node.names if a.name.startswith("_")], ast.dump(node)
            assert not (node.module or "").endswith("judge.render") or "render" not in [a.name for a in node.names]
            imported |= set((node.module or "").split("."))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                imported |= set(alias.name.split(".")) | {alias.asname or ""}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for reader in PACKAGE_READERS:
        assert reader in names, f"the page never names {reader}"
    assert "read_archived_report" in names
    for checkout_bound in ("render_footer", "_lesson_changes", "_git", "subprocess"):
        assert checkout_bound not in names | imported, f"the page names {checkout_bound}"
    shipped = R._shipped_modules()
    assert PAGE_PATH in shipped
    for name in RECORD_NAMES:
        homes = [m for m, src in shipped.items() if name in R._string_constants(src, m)]
        assert len(homes) == 1, (name, homes)


def test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green():
    """`scripts/lint/lint_vulture_baseline.json` has no key naming `read_stage_timings`,
    `family_malformed_replies`, `unqueueable_findings` or `world_findings`, and `lint_vulture`
    reports no new finding (exit 0) — the four entries named this page as their reader and the
    page is now the reader.
    """
    baseline = json.loads(VULTURE_BASELINE.read_text(encoding="utf-8"))
    stale = [k for k in baseline.get("entries", baseline)
             if any(name in k for name in ("read_stage_timings", "family_malformed_replies",
                                           "unqueueable_findings", "world_findings"))]
    assert stale == [], stale
    lint_vulture = load_lint_gate("lint_vulture")
    if lint_vulture._vulture_bin() is not None:
        assert lint_vulture.main([]) == 0


def test_1025_the_new_modules_tree_reads_are_censused():
    """The page module is listed in `lint_tree_read_follows_link`'s `LINT_TREE_READER_MODULES`
    (it reads the episode tree, a tree three boxes had an rw bind on), and the lint reports no
    new finding over the tree.
    """
    lint_tree_read_follows_link = load_lint_gate("lint_tree_read_follows_link")
    assert PAGE_PATH in lint_tree_read_follows_link.LINT_TREE_READER_MODULES, sorted(
        lint_tree_read_follows_link.LINT_TREE_READER_MODULES)
    assert lint_tree_read_follows_link.main([]) == 0


# ---------------------------------------------------------------------------------------
# the two coherence demands minted at §7 — the same screen for every reader of world_archive
# ---------------------------------------------------------------------------------------


def _refused():
    return J.sym("learning.judge", "JudgeRefused")


def test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page(tmp_path):
    """`grade_episode` reads `world_archive` through `read_world_facts`, and the symlink/FIFO
    screen on `report.md` / `investigation.md` now lives in that reader (O8): a symlink at
    `report.md` reads as a refused report (no disposition, the target's body absent), a symlink
    at `investigation.md` is `JudgeRefused`, and the grading pass's row for that world carries
    an ungradable reason naming the leaf while the target's content reaches neither
    `judge.yaml` nor a draw document.
    """
    family = E.mod("learning.judge.family")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.md").write_text(T.report_text("benign", body="OUTSIDE-REPORT-BODY"), encoding="utf-8")
    (outside / "investigation.md").write_text("# OUTSIDE-INVESTIGATION\n", encoding="utf-8")
    E.plant_link(ep / "worlds" / "b" / "report.md", outside / "report.md")
    facts = family.read_world_facts(ep, "b", episode_token=T.EPISODE_TOKEN)
    assert facts.report.disposition is None
    assert "OUTSIDE-REPORT-BODY" not in facts.report.text
    E.plant_link(ep / "worlds" / "c" / "investigation.md", outside / "investigation.md")
    with pytest.raises(_refused()):
        family.read_world_facts(ep, "c", episode_token=T.EPISODE_TOKEN)

    grade = E.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), runs_base=tmp_path / "defender-runs")
    rows = J.rows(grade)
    assert rows["b"].get("ungradable"), rows["b"]
    assert "report.md" in rows["b"]["ungradable_reason"], rows["b"]
    assert rows["c"].get("ungradable"), rows["c"]
    assert "investigation.md" in rows["c"]["ungradable_reason"], rows["c"]
    written = (ep / "judge.yaml").read_text(encoding="utf-8")
    assert "OUTSIDE" not in written
    for draw in (ep / "worlds").rglob("judge/*.yaml"):
        assert "OUTSIDE" not in draw.read_text(encoding="utf-8")


def test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page(tmp_path):
    """The judge's input builder (`judge/render.py::render`) reads `world_archive` through the
    same `read_world_facts`, so it inherits the reader's screen: a FIFO at `investigation.md`
    is refused promptly (`JudgeRefused`, the render returns within two seconds, the FIFO is
    never opened) instead of blocking the pass (p2), and a symlink at `report.md` never puts the
    target's report into the judge's input.
    """
    render_mod = E.mod("learning.judge.render")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    fifo = E.plant_fifo(ep / "worlds" / "b" / "investigation.md")
    started = time.monotonic()
    with E.Rescue(fifo, after=2.0) as rescue, pytest.raises(_refused()):
        render_mod.render(ep, "b", tmp_path / "defender-runs")
    assert time.monotonic() - started < 2.0, "the input builder blocked on the FIFO"
    assert not rescue.fed, "the input builder blocked on the FIFO"

    outside = tmp_path / "outside-report.md"
    outside.write_text(T.report_text("benign", body="OUTSIDE-REPORT-BODY"), encoding="utf-8")
    E.plant_link(ep / "worlds" / "c" / "report.md", outside)
    rendered = render_mod.render(ep, "c", tmp_path / "defender-runs")
    assert "OUTSIDE-REPORT-BODY" not in repr(rendered.__dict__)


def test_1025_grade_episode_still_grades_an_episode_whose_samples_yaml_is_malformed(tmp_path):
    """The page's strict reading of `samples.yaml` is the page's alone (71-resolutions-f F-4):
    `read_samples_record`'s DEFAULT stays permissive (#1007 M4/O5), so on an episode whose
    `samples.yaml` is torn `grade_episode` still grades — `judge.yaml` lands, every graded
    world's row carries `sample_unavailable: True`, and the standalone judge input builder
    (`judge/render.py::render`, the other caller of the default reader) still returns an input
    rather than a `JudgeRefused` — while the page rendered over the SAME directory says
    "samples record unreadable" in its records section and carries the grade the judge wrote in
    its verdict band (never "no grade record", never "grade record unreadable"). Two readers of
    one source, deliberately different: the strictness lives in the reader the page passes
    through the `reader=` seam, not in the default.
    """
    judge_mod = E.mod("learning.judge")
    render_mod = E.mod("learning.judge.render")
    ep = E.sample_episode(tmp_path, judge=False)
    E.plant_raw(ep.dir / "samples.yaml", "logs-*: [\n  {")
    grade = judge_mod.grade_episode(
        ep.dir, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs")
    assert (ep.dir / "judge.yaml").is_file(), "the torn samples record took the grading pass down"
    rows = J.rows(grade)
    graded = [label for label, row in rows.items() if not row.get("ungradable")]
    assert graded, rows
    for label in graded:
        assert rows[label]["sample_unavailable"] is True, (label, rows[label])
    assert render_mod.render(ep.dir, graded[0], tmp_path / "defender-runs") is not None

    page = render(ep)
    records = _records(page)
    assert "samples record unreadable" in records, records
    band = page.text_of("sec-verdict")
    assert "no grade record" not in band, band
    assert "grade record unreadable" not in band, band
    assert J.word_of(grade) in band, (J.word_of(grade), band)
