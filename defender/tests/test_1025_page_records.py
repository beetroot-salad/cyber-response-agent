"""#1025 — the records section, the per-record refusal policy, the value-channel escape, the one-reader
discipline, and the housekeeping the page PR owes."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests._alert_plant import plant_source_copy
from defender.tests import _state1135
from defender.tests._state1135 import env_state

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")

REPO_ROOT = Path(__file__).resolve().parents[2]
VULTURE_BASELINE = REPO_ROOT / "scripts" / "lint" / "lint_vulture_baseline.json"
PAGE_PATH = "scripts/visualize/visualize_episode.py"
RECORD_NAMES = ("judge.yaml", "outcome.yaml", "samples.yaml", "family.yaml", "timing.json",
                "provenance.json")
PACKAGE_READERS = ("read_grade", "draws_on_disk_report", "read_stage_timings", "read_manifest",
                   "read_outcome", "failed_worlds", "read_samples_record",
                   # The ledger and the investigation document are TWO reads, each its own
                   # slot (#1025): the page never asks the composed `read_world_facts`, whose
                   # ledger-first refusal cost the leads block an intact `investigation.md`.
                   "read_world_ledger", "read_investigation_facts",
                   "leads_by_id", "lead_chain", "json_mapping", "read_family_stamp")
MARKUP = "<script>alert(1)</script><img src=x onerror=alert(1)>"


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
    """The live-996 shape renders `samples.yaml` as "absent" and the other records present."""
    ep = E.sample_episode(tmp_path)
    call = {"system": E.SYSTEM, "verb": "esql", "params": {"query": "FROM drifted-index"}}
    E.write_outcome(ep.dir, drift=[{**call, "status": "the live answer drifted"}],
                    not_replayable=[{"system": "identity", "verb": "get-user",
                                     "params": {"user": "never-replayed"},
                                     "reason": "the capture holds no answer"}],
                    unservable_worlds=[{"world": "ghost", "reason": "oracle unservable",
                                        "call": call, "detail": "no fit served answer"}])
    E.write_world_record(ep.dir, E.PASSTHROUGH_WORLD, "budget", call=call,
                         detail="the oracle budget ran out")
    text = _records(render(ep))
    for expected in (E.BASE_STORY, "p", ", ".join(T.SERVED_SYSTEMS), E.PASSTHROUGH_WORLD,
                     E.GRADED_WORLD, "accepted", E.OUTCOME_REASON, "FROM drifted-index",
                     "the live answer drifted", "never-replayed", "the capture holds no answer",
                     "ghost", "no fit served answer", "budget", "the oracle budget ran out",
                     E.SYSTEM, '"event.outcome": "success"',
                     "identity: unavailable — the adapter answered no example",
                     E.LESSONS_COMMIT[:8]):
        assert expected in text, (expected, text)
    assert "absent" not in text, text
    assert "no record" not in text, text

    live = E.sample_episode(tmp_path / "live", samples=False)
    text = _records(render(live))
    assert "absent" in text, text
    assert '"event.outcome": "success"' not in text, text

    (live.dir / "provenance.json").unlink()
    (live.dir / "outcome.yaml").unlink()
    text = _records(render(live))
    assert text.count("absent") >= 3, text   # samples, provenance, the outcome's own reason
    assert "no record" in text, text
    assert E.OUTCOME_REASON not in text, text


def test_1025_markup_in_every_model_authored_field_renders_as_text_on_every_section(tmp_path):
    """A copied episode with `<script>alert(1)</script><img src=x onerror=alert(1)>` planted in a
    finding's `claim`, `root_cause`, `anchor`, `topic`, `evidence[0]`, a world's."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest(base_story=f"story {MARKUP}")
    manifest["worlds"][2]["axis"] = f"axis {MARKUP}"
    manifest["worlds"][2]["facts"][0]["statement"] = f"fact {MARKUP}"
    T.write_family(ep.dir, manifest)
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=[E.finding(
        subject="defender", claim=f"claim {MARKUP}", root_cause=f"root {MARKUP}",
        anchor=f"anchor {MARKUP}", topic=f"topic {MARKUP}", evidence=[f"evidence {MARKUP}"])]))
    doc = E.sample_grade()
    doc["worlds"][0] = E.ungradable_row(E.PASSTHROUGH_WORLD, declared="benign", reason=f"reason {MARKUP}")
    doc["enqueued_to"] = f"/queue/{MARKUP}"
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/1: {MARKUP}"]
    E.write_judge(ep.dir, doc)
    E.write_framed(ep.dir, f"judge:{E.GRADED_WORLD}:0", prompt=f"prompt {MARKUP}", reply=f"reply {MARKUP}")
    world = ep.world(E.GRADED_WORLD)
    (world / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": f"goal {MARKUP}"}), encoding="utf-8")
    (world / "gather_summaries" / "l-001.md").write_text(f"summary {MARKUP}\n", encoding="utf-8")
    plant_source_copy(ep.dir, json.dumps(
        {"alert_id": "id", "rule": {"name": f"rule {MARKUP}"}}).encode("utf-8"))
    page = render(ep)
    assert "<script>" not in page.raw
    assert "<img" not in page.raw
    assert "onerror=" not in page.raw.replace("on​error", ""), "an unsplit handler survived"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.raw
    for section, text in _sections(page).items():
        assert MARKUP in text, f"{section} shows no escaped occurrence"
    assert MARKUP in page.one("header").text()
    assert f"fact {MARKUP}" in page.text_of(f"world-{E.GRADED_WORLD}")


def test_1025_non_ascii_and_control_characters_in_rendered_strings(tmp_path):
    """The page declares and writes UTF-8."""
    ep = E.sample_episode(tmp_path)
    exotic = "a—b​c‮d"
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(
        findings=[E.finding(subject="defender", claim=f"claim {exotic}")]))
    page = render(ep)
    assert 'charset="utf-8"' in page.raw.lower().replace("'", '"') or "charset=utf-8" in page.raw.lower()
    assert f"claim {exotic}" in page.text_of(f"f-{E.GRADED_WORLD}-0-0")

    draws = ep.world(E.GRADED_WORLD) / "judge"
    E.plant_raw(draws / "0.yaml",
                'bucket: lead-set\nsystems: [elastic]\ninvestigator_findings:\n'
                '  - {bucket: lead-set, claim: "before\\uD800after",'
                ' root_cause: "nul\\0here", anchor: l-001, topic: t, contrast_evidence: [e],'
                ' on_verdict_path: true}\n')
    assert (draws / "0.yaml").read_text(encoding="utf-8")
    plant_source_copy(ep.dir, b'{"alert_id": "x", "rule": {"name": "rule\\ud800name"}}')
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
    guarded write, so a lone surrogate in a record becomes the encoder's replacement."""
    ep = E.sample_episode(tmp_path)
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 1, "unqueueable",
                     "x\ud800y and n\x00l")
    E.write_judge(ep.dir, doc, check=False)
    E.render_episode(ep.dir, module=visualize_episode())
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
    """A present-but-corrupt `judge.yaml` is a different state from absence."""
    ep = E.sample_episode(tmp_path)
    intact_page = render(ep)
    intact = _sections(intact_page)
    E.plant_raw(ep.dir / "judge.yaml", "worlds: [\n  {world: b")
    page = render(ep)
    band = page.text_of("sec-verdict")
    assert "grade record unreadable" in band, band
    assert "no grade record" not in band, band
    assert page.text_of("stage-timing") == intact_page.text_of("stage-timing")
    assert page.text_of("sec-leads") == intact["sec-leads"]


def test_1025_timing_json_is_present_but_not_the_stageclock_record_shape(tmp_path):
    """A `timing.json` that is not the record's shape ."""
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


def test_1025_an_alias_planted_at_each_record_name(tmp_path):
    """A symlink planted at each record's name ."""
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE-TARGET-CONTENT", encoding="utf-8")
    for name in ("judge.yaml", "timing.json", "outcome.yaml", "samples.yaml", "provenance.json"):
        E.plant_link(ep.dir / name, outside)
    page = render(ep)
    assert "OUTSIDE-TARGET-CONTENT" not in page.raw
    assert "grade record unreadable" in page.text_of("sec-verdict")
    assert "timing record unreadable" in page.text_of("sec-stages")
    records = _records(page)
    for sentence in ("no record: outcome.yaml is refused", "samples record unreadable",
                     "provenance record unreadable"):
        assert sentence in records, (sentence, records)
    assert "absent" not in records, records
    E.plant_link(ep.dir / "family.yaml", outside)
    with pytest.raises(J.sym("learning.judge", "JudgeRefused")):
        E.render_episode(ep.dir, module=visualize_episode())


def test_1025_a_malformed_record_versus_an_absent_one(tmp_path):
    """For each of `samples.yaml`, `provenance.json`, `outcome.yaml` the page shows two DIFFERENT
    states."""
    ep = E.sample_episode(tmp_path)
    for name, absent, sentence in (
            ("samples.yaml", "absent", "samples record unreadable"),
            ("provenance.json", "absent", "provenance record unreadable"),
            ("outcome.yaml", "no record: outcome.yaml is absent", "does not parse")):
        fresh = E.copy_episode(ep, tmp_path / f"absent-{name}")
        (fresh.dir / name).unlink()
        assert absent in _records(render(fresh)), name
        assert sentence not in _records(render(fresh)), name
        broken = E.copy_episode(ep, tmp_path / f"broken-{name}")
        E.plant_raw(broken.dir / name, "{\n  [")
        text = _records(render(broken))
        assert sentence in text, (name, text)
        assert "absent" not in text, (name, text)


@NOT_ROOT
def test_1025_an_unreadable_regular_file_at_a_record_name(tmp_path):
    """A permission-denied regular file at each record's name takes that record's refusal slot ."""
    ep = E.sample_episode(tmp_path)
    names = ("judge.yaml", "timing.json", "outcome.yaml", "samples.yaml", "provenance.json")
    E.write_timing(ep.dir, E.every_step())
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
    for sentence in ("no record: outcome.yaml is refused", "samples record unreadable",
                     "provenance record unreadable"):
        assert sentence in records, (sentence, records)
    assert "unreadable" in page.text_of(f"leads-{E.GRADED_WORLD}")
    (ep.dir / "family.yaml").chmod(0)
    try:
        with pytest.raises(J.sym("learning.judge", "JudgeRefused")):
            E.render_episode(ep.dir, module=visualize_episode())
    finally:
        (ep.dir / "family.yaml").chmod(0o644)


def test_1025_one_malformed_sidecar_record_sits_beside_otherwise_intact_ones(tmp_path):
    """Only the section fed by the bad record carries a refusal sentence."""
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


# ---------------------------------------------------------------------------------------
# d34 / d35 / census — one reader, the baseline, the tree-read lint
# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
# the two coherence demands minted at §7 — the same screen for every reader of world_archive
# ---------------------------------------------------------------------------------------


def _refused():
    return J.sym("learning.judge", "JudgeRefused")


def test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page(tmp_path):
    """`grade_episode` reads `world_archive` through `read_world_facts`, and the symlink/FIFO screen
    on `report.md` / `investigation.md` now lives in that reader (O8)."""
    family = E.mod("learning.judge.family")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [E.served_row("b", "oracle")], "c": []})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.md").write_text(T.report_text("benign", body="OUTSIDE-REPORT-BODY"), encoding="utf-8")
    (outside / "investigation.md").write_text("# OUTSIDE-INVESTIGATION\n", encoding="utf-8")
    E.plant_link(ep / "worlds" / "b" / "report.md", outside / "report.md")
    bound = E.mod("_io").bind(ep)
    facts = family.read_world_facts(bound, "b", episode_token=T.EPISODE_TOKEN)
    assert facts.report.disposition is None
    assert "OUTSIDE-REPORT-BODY" not in facts.report.text
    E.plant_link(ep / "worlds" / "c" / "investigation.md", outside / "investigation.md")
    with pytest.raises(_refused()):
        family.read_world_facts(bound, "c", episode_token=T.EPISODE_TOKEN)

    grade = J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), state=env_state())
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
    """The judge's input builder (`judge/render.py::render`) reads `world_archive` through the same
    `read_world_facts`, so it inherits the reader's screen."""
    render_mod = E.mod("learning.judge.render")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [E.served_row("b", "oracle")], "c": []})
    fifo = E.plant_fifo(ep / "worlds" / "b" / "investigation.md")
    started = time.monotonic()
    with E.Rescue(fifo, after=2.0) as rescue, pytest.raises(_refused()):
        render_mod.render(ep, "b")
    assert time.monotonic() - started < 2.0, "the input builder blocked on the FIFO"
    assert not rescue.fed, "the input builder blocked on the FIFO"

    ep = J.accepted_episode(tmp_path / "linked",
                            ledgers={"b": [E.served_row("b", "oracle")], "c": []})
    outside = tmp_path / "outside-report.md"
    outside.write_text(T.report_text("benign", body="OUTSIDE-REPORT-BODY"), encoding="utf-8")
    E.plant_link(ep / "worlds" / "c" / "report.md", outside)
    rendered = render_mod.render(ep, "b")
    assert "OUTSIDE-REPORT-BODY" not in repr(rendered.__dict__)
    assert "c" not in rendered.contrast_rows, "the linked world is a reference run"


def test_1025_grade_episode_still_grades_an_episode_whose_samples_yaml_is_malformed(tmp_path):
    """The page's strict reading of `samples.yaml` is the page's alone (71-resolutions-f F-4)."""
    render_mod = E.mod("learning.judge.render")
    ep = E.sample_episode(tmp_path, judge=False)
    E.plant_raw(ep.dir / "samples.yaml", "logs-*: [\n  {")
    # The judge's door judges the container's tenant record (#1105 PR 2, second review round),
    # as the page's view does: the record the launcher leaves, planted before the grade.
    E.plant_container_record(ep.dir)
    grade = J.grade_at(
        ep.dir, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc(
            bucket="none", systems=[E.SYSTEM]))),
        state=env_state())
    assert (ep.dir / "judge.yaml").is_file(), "the torn samples record took the grading pass down"
    rows = J.rows(grade)
    graded = [label for label, row in rows.items() if not row.get("ungradable")]
    assert sorted(graded) == sorted([E.PASSTHROUGH_WORLD, E.GRADED_WORLD]), rows
    for label in graded:
        assert rows[label]["completed_draws"] == 1, (label, rows[label])
    assert render_mod.render(ep.dir, graded[0]) is not None

    page = render(ep)
    records = _records(page)
    assert "samples record unreadable" in records, records
    band = page.text_of("sec-verdict")
    assert "no grade record" not in band, band
    assert "grade record unreadable" not in band, band
    assert f"validity {grade.validity}" in band, (grade.validity, band)
