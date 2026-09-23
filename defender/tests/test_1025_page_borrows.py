"""#1025 (PR #1042 review) — the page BORROWS what the judge owns rather than copying it, and
READS what the pass decided rather than deciding again.

Two things the first cut of the page re-implemented, and each copy drifted: reading a file
safely (an ``lstat`` screen and then the tolerant reader's bare ``read_text``, per call site,
with the ``except`` forgotten at two of them) and deciding what the enqueue did with a finding
(a hand-mirrored precedence that read a faulted world's mechanical finding as "never enqueued"
while the pass had queued it). The reader now comes from one owner
(``_io.read_jsonl_rows_guarded``). The lane went one step further: borrowing the pass's rule
(``enqueue.route_finding``) still left the page rebuilding the rule's INPUTS from the record's
rows, and that rebuild disagreed with the pass on a record naming one world twice — so the
pass now writes its decision per finding to the record (``judge.yaml.dispositions``, the
ledger) and the page renders the ledger. These tests pin the places the copies were wrong and
the ledger's contract at both ends.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
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


def _restoring(paths: list[Path], mode: int):
    """chmod each path to `mode` for the body, then back to something the tmp-dir cleanup can
    remove — a `finally`, so a failing assertion never leaves a mode-000 tree behind."""
    class _Ctx:
        def __enter__(self):
            for p in paths:
                p.chmod(mode)

        def __exit__(self, *_):
            for p in paths:
                p.chmod(0o755 if p.is_dir() else 0o644)
            return False
    return _Ctx()


# ---------------------------------------------------------------------------------------
# One guarded reader — the leaks the per-site pattern left
# ---------------------------------------------------------------------------------------


@NOT_ROOT
def test_1025_a_permission_denied_trace_or_tool_trace_is_that_slots_refusal_never_the_pages_crash(
        tmp_path):
    """A mode-000 `wire_logs/<stem>.jsonl` and a mode-000 `runs/<ep>-<label>/tool_trace.jsonl`
    each land in their own slot — the transcript reads as refused, the run reads "no cost
    recorded" — and the page is written. Before: both reads were the tolerant reader's bare
    `read_text` behind an `lstat` screen, and the `PermissionError` took the whole render down.
    """
    ep = E.sample_episode(tmp_path)
    trace = ep.dir / "wire_logs" / f"{E.trace_stem('questioner')}.jsonl"
    tool_trace = ep.run(E.CONTROL) / "tool_trace.jsonl"
    with _restoring([trace, tool_trace], 0):
        page = render(ep)
    assert page.by_id, "no page"
    world = page.text_of(f"world-{E.CONTROL}")
    assert "no cost recorded" in world or "no result event" in world, world
    stages = page.text_of("sec-stages")
    refused = page.text_of("tx-questioner_trace")
    assert "You are the seat." not in refused, refused
    assert "$" not in refused, refused
    assert "You are the seat." in page.text_of("tx-questioner_b_trace")
    assert "partial — 2 of 3 calls priced" in page.text_of("stage-questioner"), stages
    assert "no result event (refused)" in stages, stages


@NOT_ROOT
def test_1025_a_world_directory_with_no_search_permission_is_that_worlds_refusal(tmp_path):
    """`worlds/<label>/` chmod 000: the world's archive block reads its refusal and every other
    section renders. Before: the archive loader asked `Path.exists()` of `report.md` inside a
    directory it had only `lstat`-screened, and the `PermissionError` out of `stat()` ended
    the render.
    """
    ep = E.sample_episode(tmp_path)
    with _restoring([ep.world(E.GRADED_WORLD)], 0):
        page = render(ep)
    assert page.by_id, "no page"
    assert "Permission denied" in page.text_of(f"world-{E.GRADED_WORLD}") or \
        "could not be read" in page.text_of(f"world-{E.GRADED_WORLD}"), \
        page.text_of(f"world-{E.GRADED_WORLD}")
    assert f"f-{E.GRADED_WORLD}-0-0" not in page.ids  # its draws are unreadable too
    assert f"f-{E.WITHHELD_WORLD}-0-0" in page.ids


@NOT_ROOT
def test_1025_an_unreadable_report_md_is_named_as_unreadable_not_as_an_alias(tmp_path):
    """`read_archived_report` on a mode-000 `report.md` says it could not be read and carries
    the errno; on a symlinked `report.md` it says the alias refusal ONCE. Before, the alias
    sentence was hard-coded in front of `read_guarded`'s own reason — doubled for a link,
    and wrong for a permission fault."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    bound = E.mod("_io").bind(ep.dir)
    report = ep.world(E.GRADED_WORLD) / "report.md"
    with _restoring([report], 0):
        got = family.read_archived_report(bound, f"worlds/{E.GRADED_WORLD}/report.md")
    assert got.disposition is None
    assert "Permission denied" in got.reason, got.reason
    assert "aliased" not in got.reason, got.reason

    target = tmp_path / "elsewhere.md"
    target.write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    link = ep.world(E.WITHHELD_WORLD) / "report.md"
    link.unlink()
    link.symlink_to(target)
    got = family.read_archived_report(bound, f"worlds/{E.WITHHELD_WORLD}/report.md")
    assert got.disposition is None
    assert got.reason.count("non-plain or aliased") == 1, got.reason


def test_1025_the_ledgers_malformed_row_count_is_the_judges_own(tmp_path):
    """A parseable ledger row whose `source` is outside the ledger's vocabulary is malformed
    to `read_world_facts` (p7: `WorldFacts.malformed_rows`) and the page's leads block says
    "1 malformed row" — the same count the `judge.yaml` row carries. Before, the page re-read
    the ledger through the raw tolerant reader and counted only physically torn lines: `None`
    here, 1 on the record."""
    ep = E.sample_episode(tmp_path)
    ledger = ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl"
    bogus = J.ledger_row(source="passthrough", world_label=E.GRADED_WORLD)
    bogus["source"] = "bogus-word"
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(bogus) + "\n")
    family = E.mod("learning.judge.family")
    facts = family.read_world_facts(E.mod("_io").bind(ep.dir), E.GRADED_WORLD,
                                    episode_token=E.EPISODE_TOKEN)
    assert facts.malformed_rows == 1
    block = render(ep).text_of(f"leads-{E.GRADED_WORLD}")
    assert "1 malformed row" in block, block


def test_1025_read_world_facts_refuses_an_absent_ledger_on_every_path(tmp_path):
    """p7: "only an ABSENT ledger refuses (JudgeRefused)". The guard is the reader's own, so
    the bare `render.render(..., facts=None)` path — which has no `_missing_required_input`
    gate ahead of it — cannot assemble a prompt over a world that reads as "served nothing".
    The page holds the refusal at the world's leads slot and still says "absent"."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    (ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl").unlink()
    with pytest.raises(J.sym("learning.judge", "JudgeRefused"), match="ledger"):
        family.read_world_facts(E.mod("_io").bind(ep.dir), E.GRADED_WORLD,
                                episode_token=E.EPISODE_TOKEN)
    block = render(ep).text_of(f"leads-{E.GRADED_WORLD}")
    assert "absent" in block, block


# ---------------------------------------------------------------------------------------
# One lane rule — `route_finding`, walked by the pass; its answers are the ledger below
# ---------------------------------------------------------------------------------------


def test_1025_an_ungradable_worlds_mechanical_finding_is_queued_and_the_page_says_so(tmp_path):
    """`enqueue_report` walks `mechanical_world_findings` for EVERY row, the ungradable ones
    included (M3: the finding IS the record of why the world could not be graded). The page
    renders that row "world author: enqueued" with the recorded id, and tile 3's world-author
    count includes it. Before, the page's mirror answered "not enqueued — world ungradable"
    for a finding `judge.yaml`'s own `world_findings` shows as queued."""
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    # the pass's own mint (`family._mechanical_world_finding`): the finding carries its
    # `pattern`/`holding_system`, which is what lets the questioner row validate
    mechanical = E.mod("learning.judge.family")._mechanical_world_finding(
        label=E.WITHHELD_WORLD, pattern="logs-system.auth-*", holding_system="elastic")
    row = E.ungradable_row(E.WITHHELD_WORLD, declared="benign")
    row["mechanical_world_findings"] = [mechanical]
    doc["worlds"][0] = row
    # what the pass itself does with that row — the oracle the page must agree with
    report = enqueue.enqueue_report(ep.dir, doc, queue_dir=tmp_path / "queue", drawn={},
                                    family_drawn={})
    coord = f"{E.EPISODE_ID}/{E.WITHHELD_WORLD}/mechanical/0"
    assert coord in [r["finding_id"] for r in report.world_rows], report.world_rows
    doc["world_findings"] = [r for r in report.world_rows if r["finding_id"] == coord]
    doc["withheld_findings"] = []
    doc["dispositions"] = report.dispositions
    E.write_judge(ep.dir, doc)

    page = render(ep)
    row_id = f"f-{E.WITHHELD_WORLD}-mechanical-0"
    assert row_id in page.ids, page.ids_with("f-")
    group = page.group_of(row_id).text()
    assert "world author: enqueued" in group, group
    assert "world ungradable" not in group, group
    assert coord in page.text_of(row_id), page.text_of(row_id)


def test_1025_route_finding_is_the_rule_enqueue_report_walks(tmp_path):
    """For every finding on the sample the lane `route_finding` names is the lane the pass
    put it on: the graded world's four defender findings → defender rows; its world finding
    → a world row; the withheld world's four → `withheld_findings`; a `subject` naming
    neither channel → `unqueueable_findings`; under `verdict_word: discard` the graded
    world's defender findings vanish (never eligible) and nothing else moves."""
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    graded = E._world_findings_rows(withheld=False)
    graded.append(E.finding(subject="Nobody", claim="off-channel"))
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=graded))

    def lanes(verdict_word):
        d = dict(doc, verdict_word=verdict_word)
        report = enqueue.enqueue_report(ep.dir, d, queue_dir=tmp_path / f"q-{verdict_word}")
        rows_by_row = {w["world"]: w for w in d["worlds"]}
        withheld = enqueue.withheld_reasons_of(d["worlds"])
        blocked = enqueue.defender_lane_blocked(verdict_word)
        routed = {}
        for label, docs in ((E.GRADED_WORLD, graded),
                            (E.WITHHELD_WORLD, E._world_findings_rows(withheld=True))):
            for i, f in enumerate(docs):
                routed[f"{label}/0/{i}"] = enqueue.route_finding(
                    label=label, finding=f, kind=enqueue.KIND_DRAW,
                    world_row=rows_by_row.get(label), withheld_reasons=withheld,
                    defender_blocked=blocked)[0]
        return report, routed

    report, routed = lanes("undecidable")
    world_ids = {r["finding_id"].split("/", 1)[1] for r in report.world_rows}
    withheld_ids = {f"{w['world']}/0/{E._world_findings_rows(withheld=True).index(w['finding'])}"
                    for w in report.withheld_findings}
    unqueueable_ids = {line.split(": ", 1)[0].split("/", 1)[1] for line in report.unqueueable}
    for coord, lane in routed.items():
        if lane == enqueue.ROUTE_WORLD:
            assert coord in world_ids, (coord, lane)
        elif lane == enqueue.ROUTE_WITHHELD:
            assert coord in withheld_ids, (coord, lane)
        elif lane == enqueue.ROUTE_NO_CHANNEL:
            assert coord in unqueueable_ids, (coord, lane)
        else:
            assert lane == enqueue.ROUTE_DEFENDER, (coord, lane)
            assert coord not in world_ids | withheld_ids | unqueueable_ids, (coord, lane)
    assert report.appended == 4, report
    assert sum(1 for lane in routed.values() if lane == enqueue.ROUTE_DEFENDER) == 4

    report, routed = lanes("discard")
    assert report.appended == 0, report
    assert sum(1 for lane in routed.values() if lane == enqueue.ROUTE_NEVER_ELIGIBLE) == 4
    assert len(report.withheld_findings) == 4, report.withheld_findings


def test_1025_a_withheld_entry_tagged_family_renders_beside_the_family_draws(tmp_path):
    """A `withheld_findings` entry carrying `world: family` and no ledger entry — a record the
    pass never writes (family findings are never withheld) — is no row: the ledger names no
    such finding, so the page shows the family draws as usual and says in the queue
    accounting that the withheld list and the ledger disagree by one. Before, the entry
    became a draw-less stub whose `None` draw key the lede's sort compared against `0`, and
    the whole page raised `TypeError` (d01: only `family.yaml` is fatal)."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["withheld_findings"].append(
        {"finding": E.finding(subject="defender", claim="a family-tagged withheld claim"),
         "world": E.FAMILY, "reason": S.withheld_reason})
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert f"f-{E.FAMILY}-0-0" in page.ids
    assert "a family-tagged withheld claim" not in page.text_of("sec-findings")
    acct = page.one(cls="vd-acct").text()
    assert "withheld list: 5 entries · 4 matched" in acct, acct
    assert "record and page disagree by 1" in acct, acct


def test_1025_a_world_spelled_family_never_doubles_the_family_lane(tmp_path):
    """`family` is the reserved label the family-level draws live under, never a world: a
    manifest row, a grade row or a `runs/<ep>-family` directory carrying the name makes no
    world section, and the family draws are walked exactly once — three `f-family-0-*` ids,
    each once, and tile 3's count unchanged."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(
        E.FAMILY, role="D", axis="a world wearing the reserved label",
        disposition_declared="benign", ov={}))
    T.write_family(ep.dir, manifest)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row(E.FAMILY, declared="benign", has_refused=None))
    E.write_judge(ep.dir, doc)
    (ep.dir / "runs" / f"{E.EPISODE_ID}-{E.FAMILY}").mkdir()
    page = render(ep)
    rows = [i for i in page.all_ids if i.startswith("f-")]
    assert len(rows) == len(set(rows)), rows
    assert [i for i in rows if i.startswith(f"f-{E.FAMILY}-")] == [
        f"f-{E.FAMILY}-0-{i}" for i in range(3)], rows
    assert f"world-{E.FAMILY}" not in page.ids, page.ids_with("world-")
    assert len(rows) == S.findings, rows


# ---------------------------------------------------------------------------------------
# Small things the review named
# ---------------------------------------------------------------------------------------


def test_1025_the_page_module_does_not_import_the_launcher():
    """The episode's `runs/` segment comes from `_episode_paths.py`, the layout owner, so the
    writer and the reader reach it through one accessor (#1077 D7; it was a constant on
    `branch/archive.py` before, and a second one on the page before that) — importing the page
    must not pull `branch/cli.py` (the whole launcher: argparse, the estate registry, the
    review runtime) into a static renderer, nor execute `cli.py` a second time when the
    launcher itself runs as a script."""
    code = ("import sys; import defender.scripts.visualize.visualize_episode; "
            "print('defender.learning.branch.cli' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True, cwd=str(Path(E.__file__).resolve().parents[2]))
    assert out.stdout.strip() == "False", out.stdout


def test_1025_a_response_row_with_an_empty_model_string_is_unpriced(tmp_path):
    """`model: ""` — a call whose model was never recorded — reads "unpriced", not a figure at
    the pricing table's absorbed-row rate: the stage sum excludes it and says so."""
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:c", model="")
    page = render(ep)
    block = page.text_of("tx-questioner_c_trace")
    assert "unpriced" in block, block
    questioner = page.text_of("stage-questioner")
    assert "$0.7500" in questioner, questioner
    assert "partial — 2 of 3 calls priced" in questioner, questioner


def test_1025_the_docstring_names_the_launchers_real_hook():
    source = Path(visualize_episode().__file__).read_text(encoding="utf-8")
    assert "cli.py::_render_page" in source
    assert "cli.py::_render_document" not in source
    cli_source = Path(E.mod("learning.branch.cli").__file__).read_text(encoding="utf-8")
    assert "def _render_page(" in cli_source


def test_1025_a_record_naming_one_world_twice_never_files_its_world_finding_as_a_defender_lesson(
        tmp_path):
    """`enqueue_report` walks `graded_labels` off the FIRST gradable row per label while `row_of`
    keeps the LAST, so a `judge.yaml` naming one world on two rows (gradable, then ungradable)
    reaches `route_finding` with the ungradable row and is answered `ROUTE_UNGRADABLE` — a lane
    the pass's if-chain did not handle, so the finding fell through to the DEFENDER row build:
    a `subject: world` finding appended to `findings.jsonl` as `subject: defender`, and no line
    said so. The dispatch is exhaustive now: the residue is named on `unqueueable` and the
    finding reaches neither channel."""
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"].append(E.ungradable_row(E.GRADED_WORLD))
    E.draw_document(ep.dir, E.GRADED_WORLD, 0,
                    E.draw_doc(findings=[E.finding(subject="world", claim="about the world")]))
    report = enqueue.enqueue_report(ep.dir, doc, queue_dir=tmp_path / "queue")
    coord = f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/0"
    assert report.appended == 0, report
    assert not [r for r in report.world_rows if r["finding_id"] == coord], report.world_rows
    assert any(line.startswith(coord) and "ungradable" in line for line in report.unqueueable), \
        report.unqueueable
    queue = tmp_path / "queue"
    for row_file in queue.rglob("*.jsonl"):
        assert "about the world" not in row_file.read_text(encoding="utf-8"), row_file


# ---------------------------------------------------------------------------------------
# The ledger — the pass writes what it decided; the page reads it and decides nothing
# ---------------------------------------------------------------------------------------


def _ledger_of(doc: dict) -> dict[str, tuple[str, str | None]]:
    return {e["finding_id"]: (e["lane"], e["reason"]) for e in doc["dispositions"]}


def test_1025_the_fixture_ledger_is_the_passes_own(tmp_path):
    """`sample_grade()["dispositions"]` — the ledger every page test renders from — is,
    entry for entry AND in walk order, what the real `enqueue_report` writes over the sample
    episode's own draw documents and rows; and the `withheld_findings` it hands the record
    carry the same `finding_id` the ledger keys them by. A fixture ledger the pass would not
    write is a fixture bug, and it fails here rather than as a page test that passed against
    a record no pass produces."""
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    report = enqueue.enqueue_report(ep.dir, doc, queue_dir=tmp_path / "queue")
    assert report.dispositions == doc["dispositions"]
    assert [w["finding_id"] for w in report.withheld_findings] == [
        w["finding_id"] for w in doc["withheld_findings"]]
    assert report.unqueueable == doc["unqueueable_findings"] == []

    report = enqueue.enqueue_report(ep.dir, dict(doc, verdict_word="discard"),
                                    queue_dir=tmp_path / "queue-discard")
    assert report.dispositions == E.block_defender_lane(E.sample_grade(), "discard")["dispositions"]


def test_1025_the_ledger_is_on_the_record_and_read_back_validated(tmp_path):
    """`judge.yaml` carries `dispositions` as `grade_episode` wrote it and `read_grade` hands
    it back unchanged; a record written before the ledger existed (no key) reads as `None`,
    distinct from a pass that walked nothing (`[]`); and a planted entry naming no lane, or
    no finding, is refused with the rest of the record — never a row of the wrong shape."""
    judge = E.mod("learning.judge")
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    grade = judge.read_grade(ep.dir)
    assert grade.dispositions == E.sample_dispositions()
    assert grade.dispositions[0] == enqueue.disposition_entry(
        E.finding_id(E.FAMILY, 0, 0), enqueue.LANE_WORLD)

    doc = E.sample_grade()
    del doc["dispositions"]
    E.write_judge(ep.dir, doc)
    assert judge.read_grade(ep.dir).dispositions is None

    doc = E.sample_grade()
    doc["dispositions"] = []
    E.write_judge(ep.dir, doc)
    assert judge.read_grade(ep.dir).dispositions == []

    for bad in ({"finding_id": E.finding_id(E.GRADED_WORLD, 0, 0), "lane": "teleported"},
                {"lane": "defender", "reason": None}):
        doc = E.sample_grade()
        doc["dispositions"].append(bad)
        E.write_judge(ep.dir, doc, check=False)
        with pytest.raises(judge.JudgeRefused, match="ledger entry"):
            judge.read_grade(ep.dir)
    render_text = render(ep).text_of("sec-verdict")
    assert "grade record unreadable" in render_text, render_text


def test_1025_the_page_shows_the_ledger_and_never_re_decides_a_lane(tmp_path):
    """The page's disposition for a finding is the ledger's entry, full stop — the rows, the
    verdict word and the withheld map are NOT consulted a second time. Pinned by a record no
    pass writes: the withheld world's row still says `withheld_reason: reachability_
    unmeasured` while its ledger entries are re-filed `defender`, and the measuring world's
    say `withheld` under a `verdict_word: discard`. A page that re-ran the lane rule over the
    rows would show the rows' answer; this one shows the ledger's, and the queue accounting
    says the withheld list and the ledger disagree."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["verdict_word"] = "discard"
    for i in range(4):
        E.set_lane(doc, E.WITHHELD_WORLD, 0, i, "defender")
        E.set_lane(doc, E.GRADED_WORLD, 0, i, "withheld", "a reason the rows never gave")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    for i in range(4):
        assert "defender: enqueued" in page.group_of(f"f-{E.WITHHELD_WORLD}-0-{i}").text()
        graded = page.group_of(f"f-{E.GRADED_WORLD}-0-{i}").text()
        assert "withheld — a reason the rows never gave" in graded, graded
        assert "never eligible" not in graded, graded
    acct = page.one(cls="vd-acct").text()
    assert "withheld list: 4 entries · 4 matched" in acct, acct
    assert "record and page disagree" not in acct, acct
    three = page.text_of("vd-tile-3")
    for part in ("4 defender", "4 withheld"):
        assert part in three, (part, three)
    assert "never eligible" not in three, three


def test_1025_a_record_naming_one_world_twice_renders_exactly_what_the_pass_filed(tmp_path):
    """The #1042 review's case: `judge.yaml` names the withheld world on TWO rows — the first
    with `withheld_reason` set, the second without. The pass takes every row into its
    withheld map (the first wins) and files the world's four defender findings withheld; a
    page that rebuilt that map from one row per label (the last) filed them enqueued, and
    tile 3 read "8 defender / 4 withheld" against a record of 4 and 8. With the ledger the
    page cannot disagree: it shows four withheld and four enqueued, exactly the pass's
    entries, and the accounting matches on both counts."""
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row(E.WITHHELD_WORLD, declared="benign", has_refused=None,
                                     bucket="lead-set"))
    report = enqueue.enqueue_report(ep.dir, doc, queue_dir=tmp_path / "queue")
    doc["dispositions"] = report.dispositions
    doc["withheld_findings"] = report.withheld_findings
    doc["enqueued_rows"] = report.appended
    E.write_judge(ep.dir, doc)
    page = render(ep)
    withheld = [e for e in report.dispositions if e["lane"] == enqueue.LANE_WITHHELD]
    assert len(withheld) == 4, report.dispositions
    assert report.appended == 4, report
    for i in range(4):
        assert "withheld" in page.group_of(f"f-{E.WITHHELD_WORLD}-0-{i}").text()
        assert "defender: enqueued" in page.group_of(f"f-{E.GRADED_WORLD}-0-{i}").text()
    three = page.text_of("vd-tile-3")
    for part in ("4 defender", "4 withheld"):
        assert part in three, (part, three)
    acct = page.one(cls="vd-acct").text()
    assert "record: 4 enqueued · page found: 4" in acct, acct
    assert "withheld list: 4 entries · 4 matched" in acct, acct
    assert "disagree" not in acct, acct


def test_1025_a_record_with_no_ledger_says_so_instead_of_guessing(tmp_path):
    """A `judge.yaml` written before the ledger existed (the two real archives the design doc
    quotes) renders every on-disk finding under one group, "record carries no disposition
    ledger — not enqueued": the page does not fall back to deciding lanes itself, tile 3
    counts nothing as queued, and no stub is invented off `world_findings`."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    del doc["dispositions"]
    E.write_judge(ep.dir, doc)
    (ep.world(E.GRADED_WORLD) / "judge" / "0.yaml").unlink()
    page = render(ep)
    for row_id in (f"f-{E.WITHHELD_WORLD}-0-0", f"f-{E.FAMILY}-0-0"):
        heading = page.group_of(row_id).text()
        assert "record carries no disposition ledger" in heading, heading
    assert not [i for i in page.ids if i.startswith(f"f-{E.GRADED_WORLD}-")], page.ids_with("f-")
    three = page.text_of("vd-tile-3")
    assert three.startswith("0 of 8"), three
