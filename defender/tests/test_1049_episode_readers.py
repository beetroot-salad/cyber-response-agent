"""#1049 — the episode-tree readers rewritten over the bound primitive.

Every reader in the design's census (`learning/judge/family.py`, `judge/__init__.py`,
`branch/staging.py`, `branch/timing.py`, `branch/archive.py`, `branch/episode.py`) takes the
BOUND reader `_io.bind(episode_dir)` answers, never a root it could format (D-V2); every
sentence it formats names the record's RELATIVE name — `review.yaml`, `staged.yaml`,
`worlds/<w>/report.md`, `served/<token>.<label>.jsonl`, `gather_summaries/<lead>.md` — and never
the directory the operator keeps episodes in; the three world-level readers answer the
primitive's absent STATE as a value (never `None`, never a sentence — F-I as a type), and the
parsing readers keep `value | None` with `None` their typed absent answer (RF-R1), coalesced
`or {}` at every read site. The `reader=` seam is `reader(bound, name)`.

Every fault is a real entry planted on the filesystem through the real readers; the grading
pass is driven through `grade_family` / `render.render` / `grade_episode`, the page through
`render_episode`. The one fake is `_world_1007.RecordingReader`, a counting pass-through
injected at the `reader=` / `review_reader=` seams.

RED AGAINST BASE by construction: `_io.bind` does not exist and the readers take a path today;
every import goes through `mod()` per test.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest
import yaml

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _record_1049 as R
from defender.tests import _triplet_947 as T
from defender.tests import _world_1007 as W

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = R.NOT_ROOT

TOKEN = T.EPISODE_TOKEN


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _episode(tmp_path: Path, *, labels: tuple[str, ...] = ("b", "c"), **kw) -> Path:
    """An accepted, archived episode under a root spelled with `SECRET`: the control `a`
    (benign) plus `labels` (malicious), every world archived, every non-control world
    carrying one served row."""
    root = tmp_path / R.SECRET
    return J.accepted_episode(
        root, root=root, labels=("a", *labels),
        dispositions={"a": "benign", **{label: "malicious" for label in labels}},
        ledgers={label: [J.staged_row(label)] for label in labels}, **kw)


def _ledger_name(label: str) -> str:
    return f"served/{T.world_token(label)}.jsonl"


def _rows(grade) -> dict[str, dict]:
    return {r["world"]: r for r in grade.worlds}


def _root_free(sentence: str, ep: Path) -> None:
    for spelling in (str(ep), os.path.realpath(ep), str(ep.parent), R.SECRET):
        assert spelling not in sentence, (spelling, sentence)


# ---------------------------------------------------------------------------------------
# d-08 — screened_yaml_mapping
# ---------------------------------------------------------------------------------------


def test_1049_screened_yaml_mapping_says_the_name_on_all_three_arms_and_none_on_absence(tmp_path):
    """screened_yaml_mapping(bound, name, what=…) raises JudgeRefused whose text names `name`
    and not the root on the read, parse and shape arms, and answers None when nothing is at
    the name — None being the typed absent answer of a value-returning parsing reader,
    decided by branching on RecordRead.absent, never on a sentence (RF-R1 / RF-V4).
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    refused = R.refused_class()

    assert family.screened_yaml_mapping(bound, "judge.yaml", what="the family grade") is None

    arms = {
        "read": lambda: R.plant_link(ep / "judge.yaml", ep / "family.yaml"),
        "parse": lambda: R.write_bytes(ep / "judge.yaml", "{\n  ["),
        "shape": lambda: R.write_bytes(ep / "judge.yaml", "- a list\n- not a mapping\n"),
    }
    for arm, plant in arms.items():
        plant()
        with pytest.raises(refused) as caught:
            family.screened_yaml_mapping(bound, "judge.yaml", what="the family grade")
        sentence = str(caught.value)
        assert 'judge.yaml' in sentence, (arm, sentence)
        assert 'the family grade' in sentence, (arm, sentence)
        _root_free(sentence, ep)
        (ep / "judge.yaml").unlink()
    R.plant_link(ep / "judge.yaml", ep / "family.yaml")
    with pytest.raises(refused, match=R.ALIAS):
        family.screened_yaml_mapping(bound, "judge.yaml", what="the family grade")
    (ep / "judge.yaml").unlink()

    R.write_bytes(ep / "judge.yaml", "verdict_word: caught\n")
    assert family.screened_yaml_mapping(bound, "judge.yaml", what="the family grade") == {
        "verdict_word": "caught"}
    # the manifest goes through the same reader and is still the one FATAL absence (d-33)
    assert family.episode_id_of(family.raw_manifest(ep)) == T.EPISODE_ID


# ---------------------------------------------------------------------------------------
# d-09 — the review reader
# ---------------------------------------------------------------------------------------


def test_1049_the_review_reader_says_review_yaml_and_answers_none_when_absent(tmp_path):
    """read_review_record's default reader, called (bound, name), refuses the read and parse
    arms with a sentence naming review.yaml and no root, answers None (not {}) when review.yaml
    is absent — branched off the primitive's absent state (RF-R1) — and D-J7's shape arms
    otherwise (a present mapping is the mapping).
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    refused = R.refused_class()

    present = family.read_review_record(bound)
    assert isinstance(present, dict)
    assert present['episode']['outcome'] == 'accepted'
    assert family._default_review_reader(bound, "review.yaml") == present

    (ep / "review.yaml").unlink()
    assert family.read_review_record(bound) is None, "absent must be None, not {}"
    assert family._default_review_reader(bound, "review.yaml") is None

    for arm, plant in (("read", lambda: R.plant_link(ep / "review.yaml", ep / "family.yaml")),
                       ("parse", lambda: R.write_bytes(ep / "review.yaml", "{\n  ["))):
        plant()
        with pytest.raises(refused) as caught:
            family.read_review_record(bound)
        sentence = str(caught.value)
        assert "review.yaml" in sentence, (arm, sentence)
        _root_free(sentence, ep)
        (ep / "review.yaml").unlink()


# ---------------------------------------------------------------------------------------
# d-10 — the permissive samples reader survives
# ---------------------------------------------------------------------------------------


def test_1049_the_permissive_samples_reader_still_answers_empty_for_absent_unreadable_and_unparseable(tmp_path):
    """read_samples_record's default reader answers {} for an absent, an aliased, an
    undecodable and an unparseable samples.yaml — #1007 M4 unchanged — through the bound
    primitive; a present mapping is the mapping.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    R.write_bytes(ep / "samples.yaml", "logs-*:\n  '@timestamp': '2026-07-28T16:00:00Z'\n")
    assert family.read_samples_record(bound) == {"logs-*": {"@timestamp": "2026-07-28T16:00:00Z"}}
    assert family._default_samples_reader(bound, "samples.yaml") == family.read_samples_record(bound)
    (ep / "samples.yaml").unlink()
    assert family.read_samples_record(bound) == {}
    for plant in (lambda: R.plant_link(ep / "samples.yaml", ep / "family.yaml"),
                  lambda: R.write_bytes(ep / "samples.yaml", R.UNDECODABLE),
                  lambda: R.write_bytes(ep / "samples.yaml", "{\n  ["),
                  lambda: R.write_bytes(ep / "samples.yaml", "- not\n- a mapping\n")):
        plant()
        assert family.read_samples_record(bound) == {}
        assert family._default_samples_reader(bound, "samples.yaml") == {}
        (ep / "samples.yaml").unlink()


# ---------------------------------------------------------------------------------------
# d-11 — read_archived_report
# ---------------------------------------------------------------------------------------


def test_1049_read_archived_report_says_report_md_on_the_read_and_absent_arms(tmp_path):
    """read_archived_report(bound, 'worlds/<w>/report.md') answers the absent STATE when
    nothing is at the name — ReportRead.absent is True, with no 'report.md not found'
    sentence and no None; a refused shape (a link, a hard link, a mode-000 file) answers a
    headline-less ReportRead whose reason names worlds/<w>/report.md exactly once ('report.md
    could not be read: <reason>' or the refusal verbatim) and no root; a readable report still
    goes through parse_report_text (d-35: a report with no frontmatter is exactly what that
    parser makes of the bytes). The entry_present after the read is gone.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    name = "worlds/b/report.md"

    read = family.read_archived_report(bound, name)
    assert read.absent is False, read
    assert read.disposition == 'malicious', read

    (ep / name).unlink()
    absent = family.read_archived_report(bound, name)
    assert absent is not None, absent
    assert absent.absent is True, absent
    assert absent.disposition is None
    assert absent.report is None
    assert not (absent.reason and "not found" in absent.reason), absent.reason
    assert not (absent.reason and str(ep) in absent.reason), absent.reason

    R.plant_link(ep / name, ep / "family.yaml")
    linked = family.read_archived_report(bound, name)
    assert linked.absent is False
    assert linked.disposition is None
    assert linked.reason.count(name) == 1, linked.reason
    assert R.ALIAS in linked.reason, linked.reason
    _root_free(linked.reason, ep)
    (ep / name).unlink()

    R.plant_hard_link(ep / name, tmp_path / "scratch" / "report-target.md")
    hard = family.read_archived_report(bound, name)
    assert hard.reason.count(name) == 1, hard.reason
    assert R.ALIAS in hard.reason, hard.reason
    _root_free(hard.reason, ep)

    (ep / name).unlink()
    R.write_bytes(ep / name, "no frontmatter at all\n")
    bare = family.read_archived_report(bound, name)
    assert bare.absent is False
    assert bare.disposition is None
    assert bare == R.mod("_report").parse_report_text("no frontmatter at all\n"), bare


# ---------------------------------------------------------------------------------------
# d-12 — the world ledger
# ---------------------------------------------------------------------------------------


def test_1049_the_world_ledger_refusal_names_served_token_label_jsonl(tmp_path):
    """read_world_ledger reads through bound.read_jsonl('served/<token>.<label>.jsonl') and
    answers (rows, malformed, RecordRead): an absent ledger is the absent state (D-J2 — no
    rows, no refusal, RecordRead.absent True); an alias, a directory, or a SYMLINKED served/
    makes it raise JudgeRefused naming served/<token>.<label>.jsonl (composed
    f'{token}.{label}.jsonl', RF-V3) and not the root; a torn line is still one counted
    malformed row, never a refusal. Clause (F-H): a ledger present at
    _missing_required_input's gate and gone at the open is the OPEN's answer — the absent
    refusal read_world_facts raises.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    refused = R.refused_class()
    name = _ledger_name("b")
    ledger = ep / name

    rows, malformed, read = family.read_world_ledger(bound, "b", episode_token=TOKEN)
    assert len(rows) == 1
    assert malformed == 0
    assert R.state(read) == 'present'

    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"torn": ')
    rows, malformed, read = family.read_world_ledger(bound, "b", episode_token=TOKEN)
    assert len(rows) == 1
    assert malformed == 1
    assert R.state(read) == 'present'

    ledger.unlink()
    rows, malformed, read = family.read_world_ledger(bound, "b", episode_token=TOKEN)
    assert (rows, malformed, R.state(read)) == ([], 0, "absent")

    for arm, plant in (("alias", lambda: R.plant_link(ledger, ep / "family.yaml")),
                       ("directory", lambda: ledger.mkdir())):
        plant()
        with pytest.raises(refused) as caught:
            family.read_world_ledger(bound, "b", episode_token=TOKEN)
        sentence = str(caught.value)
        assert sentence.count(name) == 1, (arm, sentence)
        assert R.ALIAS in sentence, (arm, sentence)
        _root_free(sentence, ep)
        ledger.unlink() if ledger.is_symlink() else ledger.rmdir()

    served = ep / "served"
    served.rename(ep / "served-real")
    R.plant_link(served, ep / "served-real")
    with pytest.raises(refused) as caught:
        family.read_world_ledger(bound, "b", episode_token=TOKEN)
    sentence = str(caught.value)
    assert sentence.count(name) == 1, sentence
    assert R.ALIAS in sentence, sentence
    _root_free(sentence, ep)


# ---------------------------------------------------------------------------------------
# d-13 — _missing_required_input's ledger arm
# ---------------------------------------------------------------------------------------


def test_1049_a_missing_served_ledger_is_recorded_as_served_token_jsonl(tmp_path):
    """_missing_required_input answers 'served ledger (served/<token>.<label>.jsonl)' for an
    absent ledger — and for a link at its name, which its kept lstat pre-filter refuses first
    (RF-R10) — so the judge.yaml row _grade_world writes reads 'world <w> is missing its
    served ledger (served/<token>.<label>.jsonl)' with no root — the ordinary ungradable path,
    the sibling graded in the same pass. The grading lane's two pre-filters
    (_missing_required_input, _check_gather_summaries) stay.
    """
    ep = _episode(tmp_path, labels=("b", "c", "d"))
    family = R.family()
    (ep / _ledger_name("b")).unlink()
    R.plant_link(ep / _ledger_name("c"), ep / "family.yaml")

    rows = _rows(family.grade_family(ep))
    for label in ("b", "c"):
        row = rows[label]
        assert row.get('ungradable') is True, row
        assert not row.get('malformed'), row
        reason = row["ungradable_reason"]
        assert reason == f"world {label!r} is missing its served ledger ({_ledger_name(label)})", reason
        _root_free(reason, ep)
    assert not rows["d"].get("ungradable"), rows["d"]


# ---------------------------------------------------------------------------------------
# d-14 — lead_chain
# ---------------------------------------------------------------------------------------


def test_1049_the_gather_summary_refusal_names_gather_summaries_lead_md_with_no_scrub(tmp_path):
    """lead_chain reads gather_summaries/<lead>.md through the world's DERIVED sub-bind
    (bound.under('worlds/<w>'), D-V2) with errors='replace', with NO artifact_dir(summaries_dir)
    and NO artifact_file(summary_path) ahead of it; an unreadable summary (a hard link, a
    symlink, a directory), or a symlinked gather_summaries/ itself, is the chain's own
    sentence naming gather_summaries/<lead>.md once and no root, with no _without_path scrub
    between (family has no such symbol); an undecodable summary is read with U+FFFD, not
    refused; a lead id that collides with a record name reads gather_summaries/family.md and
    aliases nothing; the judge prompt render.render builds carries the same root-free chain
    sentence, which is what the framed prompt copy the page renders as the transcript request
    is made of.
    """
    ep = _episode(tmp_path)
    family = R.family()
    world_dir = ep / "worlds" / "b"
    world = R.bind(ep).under("worlds/b")
    by_id = family.leads_by_id(world_dir)
    summary = world_dir / "gather_summaries" / "l-001.md"
    name = "gather_summaries/l-001.md"

    plain = family.lead_chain(world, "l-001", {}, leads=by_id)
    assert plain["summary"].startswith("summary for world b"), plain

    def sentence_for(plant) -> str:
        plant()
        chain = family.lead_chain(world, "l-001", {}, leads=by_id)
        text = chain["summary"]
        assert text is not None, text
        assert text.count(name) == 1, text
        assert R.ALIAS in text, text
        _root_free(text, ep)
        return text

    hard = sentence_for(lambda: R.plant_hard_link(summary, tmp_path / "scratch" / "summary-target.md"))
    summary.unlink()
    linked = sentence_for(lambda: R.plant_link(summary, ep / "family.yaml"))
    assert linked == hard, "a symlinked summary is not the same sentence a hard-linked one is"
    summary.unlink()
    sentence_for(lambda: summary.mkdir())
    summary.rmdir()
    summaries = world_dir / "gather_summaries"
    summaries.rename(world_dir / "summaries-real")
    sentence_for(lambda: R.plant_link(summaries, world_dir / "summaries-real"))
    summaries.unlink()
    (world_dir / "summaries-real").rename(summaries)

    R.write_bytes(summary, R.UNDECODABLE)
    replaced = family.lead_chain(world, "l-001", {}, leads=by_id)["summary"]
    assert '�' in replaced, replaced
    assert 'could not be read' not in replaced, replaced

    R.write_bytes(summaries / "family.md", "a lead named family\n")
    assert family.lead_chain(world, "family", {}, leads=by_id)["summary"] == "a lead named family\n"
    assert not hasattr(family, "_without_path"), "the reader-side scrub is still there"

    R.plant_link(summary, ep / "family.yaml")
    base, _src = J.runs_base(tmp_path)
    shown = R.mod("learning.judge.render").render(ep, "b", runs_base=base).leads["l-001"]["summary"]
    assert shown == linked, (shown, linked)


# ---------------------------------------------------------------------------------------
# d-15 — _read_archived_text
# ---------------------------------------------------------------------------------------


def test_1049_an_archived_documents_refusal_names_the_document_not_the_root(tmp_path):
    """_read_archived_text(bound, 'worlds/<w>/investigation.md', world=…, role=…) answers the
    absent state when nothing is at the name (D-J2: a RecordRead with absent True, never
    None); over undecodable bytes, a hard link or a link it raises JudgeRefused framed
    `world '<w>': …` whose text contains worlds/<w>/investigation.md exactly once and no root
    (the whole relative name, not the bare investigation.md — the world label in the frame
    is not the name said twice); read_investigation_facts(bound, world=…) passes the absent
    state up as InvestigationFacts.absent and parses a present document.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    refused = R.refused_class()
    name = "worlds/b/investigation.md"
    doc = ep / name

    read = family._read_archived_text(bound, name, world="b", role="investigation.md")
    assert R.state(read) == 'present'
    assert read.text.startswith('# investigation b')
    facts = family.read_investigation_facts(bound, world="b")
    assert facts.absent is False
    assert 'l-001' in facts.resolutions_by_lead

    doc.unlink()
    absent = family._read_archived_text(bound, name, world="b", role="investigation.md")
    assert R.state(absent) == "absent"
    facts = family.read_investigation_facts(bound, world="b")
    assert facts is not None, facts
    assert facts.absent is True, facts
    assert facts.resolutions_by_lead == {}

    for arm, plant in (("undecodable", lambda: R.write_bytes(doc, R.UNDECODABLE)),
                       ("hard link", lambda: R.plant_hard_link(doc, tmp_path / "scratch" / "inv-target.md")),
                       ("link", lambda: R.plant_link(doc, ep / "family.yaml"))):
        plant()
        with pytest.raises(refused) as caught:
            family._read_archived_text(bound, name, world="b", role="investigation.md")
        sentence = str(caught.value)
        assert sentence.startswith("world 'b':"), (arm, sentence)
        assert sentence.count(name) == 1, (arm, sentence)
        _root_free(sentence, ep)
        if arm == "link":
            assert R.ALIAS in sentence, sentence
        with pytest.raises(refused):
            family.read_investigation_facts(bound, world="b")
        doc.unlink()


# ---------------------------------------------------------------------------------------
# d-16 — _grade_from_document
# ---------------------------------------------------------------------------------------


def test_1049_a_document_that_is_not_the_grade_record_is_refused_as_judge_yaml(tmp_path):
    """read_grade over a judge.yaml with a wrong-typed field, a non-string key, a row without
    its world or an entry naming no lane raises JudgeRefused 'judge.yaml is not a family grade
    record: <bad>' — the name, not _judge_yaml_path(episode_dir) — and <bad> carries no root
    (c-14: episode_dir IS a field of EpisodeGrade, and still names nothing in <bad>). Positive
    control: the sound record reads back with that field set to the episode dir.
    """
    ep = _episode(tmp_path)
    judge = R.judge()
    refused = R.refused_class()
    sound = {"verdict_word": "caught", "worlds": [{"world": "b", "verdict": "malicious"}]}
    for bad in ({**sound, "verdict_word": 5}, {1: "x"}, {**sound, "worlds": [{"verdict": "x"}]},
                {**sound, "not_graded": {"x": 1}}):
        R.write_bytes(ep / "judge.yaml", yaml.safe_dump(bad))
        with pytest.raises(refused) as caught:
            judge.read_grade(ep)
        sentence = str(caught.value)
        assert "judge.yaml is not a family grade record" in sentence, sentence
        _root_free(sentence, ep)
    R.write_bytes(ep / "judge.yaml", yaml.safe_dump(sound))
    grade = judge.read_grade(ep)
    assert grade.verdict_word == 'caught'
    assert grade.episode_dir == ep


# ---------------------------------------------------------------------------------------
# d-17 / d-18 / d-19 — the three episode-root parsing readers
# ---------------------------------------------------------------------------------------


def test_1049_read_family_stamp_says_provenance_json_on_all_three_arms(tmp_path):
    """read_family_stamp(bound) raises ValueError naming provenance.json and no root on the
    read, parse and shape arms, and still answers None when nothing is at the name (RF-R1:
    the parsing reader's typed absent answer, branched off RecordRead.absent).
    """
    ep = _episode(tmp_path)
    archive = R.mod("learning.branch.archive")
    bound = R.bind(ep)
    stamp = ep / "provenance.json"
    stamp.unlink(missing_ok=True)
    assert archive.read_family_stamp(bound) is None
    for arm, plant in (("read", lambda: R.plant_link(stamp, ep / "family.yaml")),
                       ("parse", lambda: R.write_bytes(stamp, "{[")),
                       ("shape", lambda: R.write_bytes(stamp, '{"a": 1}'))):
        plant()
        with pytest.raises(ValueError, match="provenance.json") as caught:
            archive.read_family_stamp(bound)
        sentence = str(caught.value)
        assert "provenance.json" in sentence, (arm, sentence)
        _root_free(sentence, ep)
        stamp.unlink()
    R.write_bytes(stamp, json.dumps({"agreed": {"commit": "deadbee"}, "allow_dirty": False}))
    assert archive.read_family_stamp(bound)["agreed"]["commit"] == "deadbee"


def test_1049_read_staged_says_staged_yaml_and_answers_none_when_absent(tmp_path):
    """read_staged(bound) raises StagingRefused naming staged.yaml and no root on the read,
    parse and shape arms; answers None when staged.yaml is absent and [] when it is an empty
    document (a comment-only header is present-and-empty, #70); the rows otherwise.
    """
    ep = _episode(tmp_path)
    staging = R.mod("learning.branch.staging")
    bound = R.bind(ep)
    record = staging.staged_path(ep)
    assert staging.read_staged(bound) is None, "absent must be None, not []"
    R.write_bytes(record, "")
    assert staging.read_staged(bound) == []
    R.write_bytes(record, "# staged names — appended by the staging door\n")
    assert staging.read_staged(bound) == []
    for arm, plant in (("read", lambda: R.plant_link(record, ep / "family.yaml")),
                       ("parse", lambda: R.write_bytes(record, "- world: {torn\n")),
                       ("shape", lambda: R.write_bytes(record, "name: not-a-list\n"))):
        record.unlink()
        plant()
        with pytest.raises(staging.StagingRefused) as caught:
            staging.read_staged(bound)
        sentence = str(caught.value)
        assert "staged.yaml" in sentence, (arm, sentence)
        _root_free(sentence, ep)
    record.unlink()
    staging.record_staged(ep, {"name": "wv-one", "kind": "index"})
    assert [r["name"] for r in staging.read_staged(bound)] == ["wv-one"]


def test_1049_read_stage_timings_is_root_free_on_the_alias_arm_and_none_when_absent(tmp_path):
    """read_stage_timings(bound) over a link at timing.json raises ValueError naming
    timing.json and no root (today it quotes the absolute path, c-12); answers None when
    absent, ValueError 'not a JSON document' for a zero-byte file, and [] for {"steps": []};
    the recorded steps otherwise.
    """
    ep = _episode(tmp_path)
    timing = R.mod("learning.branch.timing")
    bound = R.bind(ep)
    record = timing.timing_path(ep)
    assert timing.read_stage_timings(bound) is None, "absent must be None, not []"
    R.plant_link(record, ep / "family.yaml")
    with pytest.raises(ValueError, match="timing.json") as caught:
        timing.read_stage_timings(bound)
    sentence = str(caught.value)
    assert 'timing.json' in sentence, sentence
    assert R.ALIAS in sentence, sentence
    _root_free(sentence, ep)
    record.unlink()
    R.write_bytes(record, b"")
    with pytest.raises(ValueError, match="not a JSON document"):
        timing.read_stage_timings(bound)
    R.write_bytes(record, '{"steps": []}')
    assert timing.read_stage_timings(bound) == []
    record.unlink()
    row = timing.StageClock(ep).record("questioner", started_at="2026-01-01T00:00:00+00:00",
                                       ended_at="2026-01-01T00:00:05+00:00")
    assert timing.read_stage_timings(bound) == [row]


# ---------------------------------------------------------------------------------------
# d-20 — branch/episode.verdicts (O3, the eval lane)
# ---------------------------------------------------------------------------------------


def test_1049_branch_episode_verdicts_decides_absent_vs_refused_by_the_open(tmp_path):
    """branch/episode.verdicts skips a world with no report.md and raises EpisodeError for a
    present-but-unreadable one (a link at the name), with no exists()/is_symlink() ahead of
    the read (an AST census of its body names neither); the sentence is terminal-only and
    may name the path.
    """
    ep = _episode(tmp_path, labels=("b", "c"))
    episode = R.mod("learning.branch.episode")
    assert episode.verdicts(ep) == {"a": "benign", "b": "malicious", "c": "malicious"}
    (ep / "worlds" / "c" / "report.md").unlink()
    assert episode.verdicts(ep) == {"a": "benign", "b": "malicious"}
    R.plant_link(ep / "worlds" / "b" / "report.md", ep / "family.yaml")
    with pytest.raises(episode.EpisodeError, match="'b'"):
        episode.verdicts(ep)
    tree = R.parsed(episode.verdicts)
    assert not (R.called_names(tree) & {"exists", "is_symlink", "is_file", "lstat", "stat",
                                        "entry_present", "artifact_file", "read_guarded"}), \
        R.called_names(tree)


# ---------------------------------------------------------------------------------------
# d-21 — the reader= seam
# ---------------------------------------------------------------------------------------


def test_1049_the_reader_seam_takes_the_bound_reader_and_a_name_and_may_answer_none(tmp_path):
    """read_review_record(bound, reader=…) and read_samples_record(bound, reader=…) call
    reader(bound, name) -> mapping | None and pass its None through; grade_family(episode_dir,
    …, review_reader=…) binds once at entry and hands the bound reader down, calling the
    injected reader exactly once; the page's _strict_samples_reader(bound, name) delegates to
    screened_yaml_mapping (None when absent, the mapping when present, JudgeRefused for a
    non-mapping). Every injector — the default readers, the page's strict reader,
    test_1007_ladder's RecordingReader over _world_1007.read_yaml_record — is called (bound,
    name), so no injected reader holds a root it could format; a reader that answers None for
    a PRESENT record is coalesced exactly as absent is — nothing tells them apart.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)

    def not_a_root(arg) -> None:
        assert not isinstance(arg, (str, bytes, os.PathLike)), f"the seam received a root: {arg!r}"
        assert callable(getattr(arg, "read", None)), f"the seam's first argument is not a bound reader: {arg!r}"

    recording = W.RecordingReader(W.read_yaml_record)
    assert family.read_review_record(bound, reader=recording)["episode"]["outcome"] == "accepted"
    (args, kwargs) = recording.calls[0]
    assert len(args) == 2, recording.calls
    assert kwargs == {}, recording.calls
    not_a_root(args[0])
    assert args[1] == "review.yaml"

    samples = W.RecordingReader(W.read_yaml_record)
    R.write_bytes(ep / "samples.yaml", "logs-*: {}\n")
    assert family.read_samples_record(bound, reader=samples) == {"logs-*": {}}
    not_a_root(samples.calls[0][0][0])
    assert samples.calls[0][0][1] == "samples.yaml"

    nothing = W.RecordingReader(lambda _bound, _name: None)
    assert family.read_review_record(bound, reader=nothing) is None, "None must pass through"

    counted = W.RecordingReader(W.read_yaml_record)
    family.grade_family(ep, review_reader=counted)
    assert counted.count == 1, counted.calls
    not_a_root(counted.calls[0][0][0])
    assert counted.calls[0][0][1] == "review.yaml"

    page = E.page_module()
    (ep / "samples.yaml").unlink()
    assert page._strict_samples_reader(bound, "samples.yaml") is None
    R.write_bytes(ep / "samples.yaml", "logs-*: {}\n")
    assert page._strict_samples_reader(bound, "samples.yaml") == {"logs-*": {}}
    R.write_bytes(ep / "samples.yaml", "- a list\n")
    with pytest.raises(R.refused_class()):
        page._strict_samples_reader(bound, "samples.yaml")


# ---------------------------------------------------------------------------------------
# d-22 — every caller coalesces at the read site
# ---------------------------------------------------------------------------------------


def test_1049_every_caller_coalesces_none_at_the_read_site(tmp_path):
    """With review.yaml, samples.yaml and staged.yaml absent, staging.teardown / sweep,
    judge._grade_episode (through grade_episode), family.grade_family and render.render each
    proceed over {} / [] — world_review_block never receives None (r7) — because the coalesce
    is `reader(...) or {}` at the read site, not an `is not None` hand-over (RF-R1: the eight
    sites are unchanged; the parsing readers' None is their typed absent answer). teardown
    and sweep coalesce `or []` and proceed identically (#70); review=None handed to
    grade_family means 'not supplied' and triggers its own coalesced read, a supplied {}
    passes through (F-L); the two reads of one review record across a pass are independent.
    """
    ep = _episode(tmp_path)
    family = R.family()
    staging = R.mod("learning.branch.staging")
    judge = R.judge()
    for name in ("review.yaml", "samples.yaml", "staged.yaml"):
        (ep / name).unlink(missing_ok=True)

    grade = family.grade_family(ep)
    assert set(_rows(grade)) == {'b', 'c'}
    assert not any(r.get('ungradable') for r in grade.worlds)
    assert family.grade_family(ep, review={}).verdict_word == grade.verdict_word
    assert family.grade_family(ep, review=None).verdict_word == grade.verdict_word
    # the read-site coalesce, observed: a reader injected at the seam that answers None for
    # the (present) review record is coalesced to {} — world_review_block never sees None
    (ep / "review.yaml").write_text("episode:\n  outcome: accepted\nworlds: {}\n", encoding="utf-8")
    none_reader = W.RecordingReader(lambda _bound, _name: None)
    assert family.grade_family(ep, review_reader=none_reader).verdict_word == grade.verdict_word
    assert none_reader.count == 1
    (ep / "review.yaml").unlink()

    base, _src = J.runs_base(tmp_path)
    shown = R.mod("learning.judge.render").render(ep, "b", runs_base=base)
    assert shown.world_label == 'b'
    assert 'l-001' in shown.leads

    door = T.FakeDoor()
    assert staging.teardown(ep, door=door) == []
    assert staging.sweep(ep, episode_token=TOKEN, door=door) == []

    record = judge.grade_episode(ep, judge=J.FakeJudge(), runs_base=base, git_show=J.FakeGitShow())
    assert record.not_graded is not None, record
    assert record.not_graded.reason == 'no review.yaml on disk', record


# ---------------------------------------------------------------------------------------
# d-28 — judge.yaml rows say relative names
# ---------------------------------------------------------------------------------------


def test_1049_grade_world_records_relative_names_in_ungradable_reason(tmp_path):
    """_grade_world, driven by grade_family over three worlds — a HARD LINK (not a symlink;
    C-03) at one world's worlds/<w>/investigation.md, an absent served ledger at the second,
    a SYMLINKED worlds/<w''> at the third (#27: the pre-filter's lstat follows the
    intermediate link and passes the regular leaf, so the reader IS reached and the walk
    refuses at the worlds/<w''> component) — writes rows whose ungradable_reason names
    worlds/<w>/investigation.md / served/<token>.<label>.jsonl / worlds/<w''>/<leaf> (the
    first leaf read_world_facts asks for under the aliased world) and not the root, and
    every sibling's row lands in the same pass (#52). Rejected: a LINK at investigation.md
    is 'missing its investigation.md' via artifact_file and never reaches the reader (c-13,
    RF-R10).
    """
    ep = _episode(tmp_path, labels=("b", "c", "d", "e"))
    family = R.family()
    R.plant_hard_link(ep / "worlds" / "b" / "investigation.md", tmp_path / "scratch" / "inv-target.md")
    (ep / _ledger_name("c")).unlink()
    real_d = ep / "worlds" / "d"
    real_d.rename(ep / "worlds" / "d-real")
    R.plant_link(real_d, ep / "worlds" / "d-real")

    rows = _rows(family.grade_family(ep))
    assert set(rows) == {"b", "c", "d", "e"}, "a refusal took a sibling's row with it"
    assert not rows["e"].get("ungradable"), rows["e"]
    b, c, d = rows["b"], rows["c"], rows["d"]
    assert b.get('ungradable'), b
    assert b.get('malformed') is True, b
    assert b['ungradable_reason'].count('worlds/b/investigation.md') == 1, b
    assert R.ALIAS in b['ungradable_reason'], b
    assert c.get('ungradable'), c
    assert not c.get('malformed'), c
    assert _ledger_name('c') in c['ungradable_reason'], c
    assert 'missing its served ledger' in c['ungradable_reason'], c
    assert d.get('ungradable'), d
    assert d.get('malformed') is True, d
    assert ("worlds/d/investigation.md" in d["ungradable_reason"]
            or "worlds/d/report.md" in d["ungradable_reason"]), d["ungradable_reason"]
    assert R.ALIAS in d["ungradable_reason"], d
    for row in (b, c, d):
        _root_free(row["ungradable_reason"], ep)

    R.plant_link(ep / "worlds" / "e" / "investigation.md", ep / "family.yaml")
    e = _rows(family.grade_family(ep))["e"]
    assert e["ungradable_reason"] == "world 'e' is missing its investigation.md", e


# ---------------------------------------------------------------------------------------
# d-37 — labels and lead ids are gated before any read
# ---------------------------------------------------------------------------------------


def test_1049_a_label_or_lead_id_that_names_no_path_inside_the_world_is_never_echoed_from_a_read(tmp_path):
    """A world label or lead id carrying a separator or `..` is refused by the grammar before
    any name is constructed — on the grading lane (_check_world_labels via grade_family,
    names_one_file via lead_chain) and on the page lane (names_one_file) alike — so the name
    a refusal echoes is never a model-authored path that left the world; under the component
    grammar (D-V1) this is the positive control, not the only defence (a traversing lead id
    cannot reach a sibling's summary either way). names_one_file now ALSO bars a NUL byte
    (D-V4); it still admits whitespace, HTML, newline, surrogates and backslash — plain
    components, read and echoed (s-34); world_label_names_directory keeps both spellings.
    """
    ep = _episode(tmp_path)
    family = R.family()
    refused = R.refused_class()
    manifest = family.raw_manifest(ep)
    manifest["worlds"].append({**manifest["worlds"][1], "world_id": "../../elsewhere"})
    T.write_family(ep, manifest)
    with pytest.raises(refused, match="cannot name a directory"):
        family.grade_family(ep)
    assert not family.world_label_names_directory(T.EPISODE_ID, "../../elsewhere")
    assert family.world_label_names_directory(T.EPISODE_ID, "b")

    world = R.bind(ep).under("worlds/b")
    by_id = family.leads_by_id(ep / "worlds" / "b")
    sibling = ep / "worlds" / "c" / "gather_summaries" / "l-001.md"
    assert "world c" in sibling.read_text(encoding="utf-8")
    for traversing in ("../../c/gather_summaries/l-001", "../c", "a/../../c", "l-0\x00x"):
        assert not family.names_one_file(traversing), traversing
        chain = family.lead_chain(world, traversing, {}, leads=by_id)
        assert "does not name a file inside this world" in chain["summary"], chain
        assert "world c" not in chain["summary"]
    summaries = ep / "worlds" / "b" / "gather_summaries"
    for odd in (" spaced", "<b>bold", "two\nlines", "\udcff", "back\\slash", ".hidden"):
        assert family.names_one_file(odd), odd
        R.write_bytes(summaries / f"{odd}.md", f"summary of {odd!r}\n".encode("utf-8", "surrogateescape"))
        chain = family.lead_chain(world, odd, {}, leads=by_id)
        assert chain["summary"].startswith("summary of"), (odd, chain)


# ---------------------------------------------------------------------------------------
# D-J2 — the three world-level readers answer the absent STATE; the page renders it
# ---------------------------------------------------------------------------------------


def test_1049_the_three_world_level_readers_answer_the_absent_state_and_the_page_renders_it(tmp_path):
    """read_archived_report, read_investigation_facts and read_world_ledger answer the
    primitive's ABSENT STATE when nothing is at the name — a value the caller branches on
    (its own `absent` flag), never None and never a sentence (the 'report.md not found'
    sentence is gone); read_world_facts refuses absent with JudgeRefused naming the relative
    name (worlds/<w>/report.md, worlds/<w>/investigation.md, served/<token>.<label>.jsonl —
    test_1025_read_world_facts_refuses_an_absent_ledger_on_every_path stays green: the
    ledger's sentence still says 'ledger'); the page renders 'served ledger: absent',
    'report.md: not archived' and 'investigation.md: not archived' with no facts_error, each
    off its read's state; _episode_has_any_served_row counts absent as no rows, so a
    two-world episode whose only sibling ledger is absent grades as episode-incomplete
    rather than refusing.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    refused = R.refused_class()
    world = ep / "worlds" / "b"

    (world / "report.md").unlink()
    (world / "investigation.md").unlink()
    (ep / _ledger_name("b")).unlink()

    report = family.read_archived_report(bound, "worlds/b/report.md")
    assert report is not None
    assert report.absent is True
    assert report.reason in (None, '')
    facts = family.read_investigation_facts(bound, world="b")
    assert facts is not None
    assert facts.absent is True
    rows, malformed, read = family.read_world_ledger(bound, "b", episode_token=TOKEN)
    assert (rows, malformed, read.absent) == ([], 0, True)

    with pytest.raises(refused) as caught:
        family.read_world_facts(bound, "b", episode_token=TOKEN)
    assert _ledger_name('b') in str(caught.value), caught.value
    assert 'ledger' in str(caught.value), caught.value
    _root_free(str(caught.value), ep)
    J.write_ledger(ep, "b", [J.staged_row("b")])
    with pytest.raises(refused) as caught:
        family.read_world_facts(bound, "b", episode_token=TOKEN)
    assert "worlds/b/investigation.md" in str(caught.value), caught.value
    _root_free(str(caught.value), ep)
    (world / "investigation.md").write_text(J.investigation_document("b"), encoding="utf-8")
    with pytest.raises(refused) as caught:
        family.read_world_facts(bound, "b", episode_token=TOKEN)
    assert "worlds/b/report.md" in str(caught.value), caught.value
    _root_free(str(caught.value), ep)

    # the page, over the sample episode: absent renders as absent, in each leaf's own words
    sample = E.sample_episode(tmp_path / "page")
    graded = sample.world(E.GRADED_WORLD)
    (graded / "report.md").unlink()
    (graded / "investigation.md").unlink()
    (sample.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl").unlink()
    page = E.render(sample)
    section = page.text_of(f"world-{E.GRADED_WORLD}")
    assert 'report.md: not archived' in section, section
    assert 'investigation.md: not archived' in section, section
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert 'served ledger: absent' in block, block
    assert 'investigation record unavailable' not in block, block
    assert 'not found' not in page.raw
    assert str(sample.dir) not in page.raw


# ---------------------------------------------------------------------------------------
# D-J3 — lead_chain with no lstat ahead of the summary read
# ---------------------------------------------------------------------------------------


def test_1049_a_symlinked_gather_summary_or_directory_is_the_chains_sentence_and_an_absent_one_is_none(tmp_path):
    """With neither lstat ahead of the read, a symlink, a hard link or (NOT_ROOT) a mode-000
    file at gather_summaries/<lead>.md — and a symlink AT gather_summaries/ itself — make the
    summary the chain's own sentence naming gather_summaries/<lead>.md and no root, in the
    judge prompt and on the page; an absent summary is the chain's absent answer (None). The
    reader is bound to the world dir by derivation from the episode handle (D-V2), so the
    page's leads block shows the same sentence for a symlinked summary where today it shows
    nothing.
    """
    ep = _episode(tmp_path)
    family = R.family()
    world_dir = ep / "worlds" / "b"
    world = R.bind(ep).under("worlds/b")
    by_id = family.leads_by_id(world_dir)
    summary = world_dir / "gather_summaries" / "l-001.md"

    summary.unlink()
    assert family.lead_chain(world, "l-001", {}, leads=by_id)["summary"] is None
    R.plant_link(summary, ep / "family.yaml")
    prompt = family.lead_chain(world, "l-001", {}, leads=by_id)["summary"]
    assert prompt.count('gather_summaries/l-001.md') == 1, prompt
    assert R.ALIAS in prompt, prompt
    _root_free(prompt, ep)
    if os.geteuid() != 0:
        summary.unlink()
        R.write_bytes(summary, "closed\n").chmod(0)
        with R.restoring_modes(summary):
            denied = family.lead_chain(world, "l-001", {}, leads=by_id)["summary"]
        assert 'gather_summaries/l-001.md' in denied, denied
        assert 'Permission denied' in denied, denied
        _root_free(denied, ep)
        summary.unlink()
        R.plant_link(summary, ep / "family.yaml")

    sample = E.sample_episode(tmp_path / "page")
    graded = sample.world(E.GRADED_WORLD)
    R.plant_link(graded / "gather_summaries" / "l-001.md", sample.dir / "family.yaml")
    withheld = sample.world(E.WITHHELD_WORLD)
    (withheld / "gather_summaries").rename(withheld / "summaries-real")
    R.plant_link(withheld / "gather_summaries", withheld / "summaries-real")
    page = E.render(sample)
    graded_block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert 'gather_summaries/l-001.md' in graded_block, graded_block
    assert R.ALIAS in graded_block, graded_block
    assert f"summary of l-002 for {E.GRADED_WORLD}" in graded_block, "the sibling summaries still read"
    withheld_block = page.text_of(f"leads-{E.WITHHELD_WORLD}")
    assert 'gather_summaries/l-001.md' in withheld_block, withheld_block
    assert R.ALIAS in withheld_block, withheld_block
    assert str(sample.dir) not in page.raw
    assert str(tmp_path) not in page.raw


# ---------------------------------------------------------------------------------------
# D-J7 — review / samples shape arms per reader
# ---------------------------------------------------------------------------------------


def test_1049_review_and_samples_shape_arms_absent_none_empty_mapping_non_mapping_per_reader(tmp_path):
    """_default_review_reader: absent → None, empty/null document → {}, list/scalar → {}
    (permissive, unchanged — _episode_outcome_from_review's 'no review.yaml on disk' is
    therefore still said of an empty file, FU-6); the page's strict samples reader
    (_strict_samples_reader over screened_yaml_mapping): absent → None → page 'absent',
    empty/null → {} → page 'present, empty' (no pattern, not 'absent', not 'unreadable'),
    non-mapping → JudgeRefused 'samples.yaml is not a mapping' → 'unreadable'; the pass's
    samples reader (_default_samples_reader via read_samples_record) stays permissive over
    the same shapes. The manifest's own empty-document refusal (test_1025_family_yaml_is_zero_
    bytes) is untouched: the present-empty tolerance is the strict samples reader's.
    """
    ep = _episode(tmp_path)
    family = R.family()
    bound = R.bind(ep)
    review = ep / "review.yaml"
    review.unlink()
    assert family._default_review_reader(bound, "review.yaml") is None
    for text in ("", "null\n", "- a list\n", "42\n"):
        R.write_bytes(review, text)
        assert family._default_review_reader(bound, "review.yaml") == {}, text
    R.write_bytes(review, "")
    assert R.judge()._episode_outcome_from_review(family.read_review_record(bound) or {}) == (
        "incomplete", "no review.yaml on disk")

    page = E.page_module()
    samples = ep / "samples.yaml"
    samples.unlink(missing_ok=True)
    assert page._strict_samples_reader(bound, "samples.yaml") is None
    for text in ("", "null\n"):
        R.write_bytes(samples, text)
        assert page._strict_samples_reader(bound, "samples.yaml") == {}, text
        assert family.read_samples_record(bound) == {}
    R.write_bytes(samples, "- a list\n")
    with pytest.raises(R.refused_class(), match="not a mapping"):
        page._strict_samples_reader(bound, "samples.yaml")
    assert family.read_samples_record(bound) == {}

    sample = E.sample_episode(tmp_path / "page")
    absent = E.copy_episode(sample, tmp_path / "absent")
    (absent.dir / "samples.yaml").unlink()
    empty = E.copy_episode(sample, tmp_path / "empty")
    R.write_bytes(empty.dir / "samples.yaml", "")
    broken = E.copy_episode(sample, tmp_path / "broken")
    R.write_bytes(broken.dir / "samples.yaml", "- a list\n")
    absent_text = E.render(absent).text_of("sec-records")
    empty_text = E.render(empty).text_of("sec-records")
    broken_text = E.render(broken).text_of("sec-records")
    assert 'absent' in absent_text
    assert 'samples record unreadable' not in absent_text
    assert 'absent' not in empty_text, empty_text
    assert 'samples record unreadable' not in empty_text, empty_text
    assert "logs-falco.alerts-*" not in empty_text
    assert 'samples record unreadable' in broken_text, broken_text
    assert 'not a mapping' in broken_text, broken_text


# ---------------------------------------------------------------------------------------
# D-V2 — the bind is the only root holder
# ---------------------------------------------------------------------------------------


#: The readers whose first argument is the bound reader (the design's census + the two RF2
#: rows), by module — resolved by symbol.
ROOTLESS_READERS = {
    "learning.judge.family": ("lead_chain", "read_archived_report", "_read_archived_text",
                              "read_investigation_facts", "_read_world_ledger", "read_world_ledger",
                              "read_world_facts", "screened_yaml_mapping", "_default_review_reader",
                              "_default_samples_reader"),
    "learning.branch.archive": ("read_family_stamp",),
    "learning.branch.staging": ("read_staged",),
    "learning.branch.timing": ("read_stage_timings",),
    "scripts.visualize.visualize_episode": ("_result_event",),
}


def test_1049_no_reader_in_the_census_receives_a_root_and_every_sub_bind_is_derived_by_no_follow_components(tmp_path, monkeypatch):
    """bind(root) is the only path-taking operation and the episode dir is the only path it is
    given (it FOLLOWS a symlinked episode dir — the operator's own spelling; three spellings of
    one directory, '.', absolute and via a symlink, render byte-identical). Every reader in the
    census takes the bound reader (an AST census: none has a Path root parameter —
    _grade_from_document's episode_dir is the record's own field, c-14, handed over by keyword
    and never formatted — so str(root)/os.path.realpath(root) are unreachable from any reader
    body) AND the bound reader's own surface offers neither spelling (F-3): no non-dunder,
    non-callable attribute of bind(root) or of bind(root).under(…) is a str, bytes or PathLike
    carrying str(root), os.path.realpath(root), str(root.parent) or the root's directory name,
    and repr/str of either carry none of them — the root lives in the bind as a handle, never
    as a spelling a reader body could reach; a bind below the root (worlds/<w> for lead_chain,
    bound.under) is derived from the episode handle by no-follow components, so a symlinked
    worlds/<w> makes every summary under it 'gather_summaries/<lead>.md: refusing to read
    through a non-plain or aliased entry' — never a followed read (RF-V2), on the page too. A
    file at the root → '<name>: Not a directory' per name; an absent root → every name absent;
    a mode-000 root is d-03's row; bind never raises for either, the fault is answered per
    name.
    """
    for module, names in ROOTLESS_READERS.items():
        for name in names:
            fn = R.function_def(R.parsed(getattr(R.mod(module), name)), name)
            assert not R.path_typed_parameters(fn), (module, name, R.path_typed_parameters(fn))
    grade_from_document = R.function_def(R.parsed(R.judge()._grade_from_document), "_grade_from_document")
    rooty = R.path_typed_parameters(grade_from_document)
    handed_over = {kw.value.id for node in ast.walk(grade_from_document)
                   if isinstance(node, ast.Call) for kw in node.keywords
                   if isinstance(kw.value, ast.Name)}
    for param in rooty:
        uses = [n for n in ast.walk(grade_from_document) if isinstance(n, ast.Name) and n.id == param
                and isinstance(n.ctx, ast.Load)]
        assert param in handed_over, (param, len(uses), 'formatted, not handed over')
        assert len(uses) == 1, (param, len(uses), 'formatted, not handed over')

    ep = _episode(tmp_path)
    family = R.family()
    real_b = ep / "worlds" / "b"
    real_b.rename(ep / "worlds" / "b-real")
    R.plant_link(real_b, ep / "worlds" / "b-real")
    world = R.bind(ep).under("worlds/b")
    by_id = family.leads_by_id(real_b)
    for lead in ("l-001", "l-002"):
        summary = family.lead_chain(world, lead, {}, leads=by_id)["summary"]
        assert summary is not None, summary
        assert summary.count(f'gather_summaries/{lead}.md') == 1, summary
        assert R.ALIAS in summary, summary
        _root_free(summary, ep)
    assert R.bind(ep).under("worlds/b-real").read("gather_summaries/l-001.md").text.startswith("summary")
    for bound in (R.bind(ep), world, R.bind(ep).under("worlds/b-real"), R.bind(ep / "worlds" / "b-real")):
        for attr, spelling in R.surface(bound).items():
            _root_free(spelling, ep)
            assert R.SECRET not in spelling, (attr, spelling)
    via_link = R.bind(ep / "worlds" / "b")
    assert R.state(via_link.read("gather_summaries/l-001.md")) == "present", "a path bind follows"

    afile = tmp_path / "a-file"
    afile.write_text("x", encoding="utf-8")
    assert R.bind(afile).read("family.yaml").refusal == f"family.yaml: {os.strerror(20)}"
    assert R.state(R.bind(tmp_path / "gone").read("family.yaml")) == "absent"

    sample = E.sample_episode(tmp_path / "page")
    absolute = E.render(sample).raw
    link = tmp_path / "episode-by-link"
    link.symlink_to(sample.dir)
    through_link = E.render(link).raw
    monkeypatch.chdir(sample.dir)
    relative = E.render(Path(".")).raw
    assert absolute == through_link == relative, "three spellings of one directory rendered differently"
    for spelling in (str(sample.dir), str(link), str(tmp_path)):
        assert spelling not in absolute, spelling


# ---------------------------------------------------------------------------------------
# D-V4 — names_one_file is the component grammar
# ---------------------------------------------------------------------------------------


def test_1049_a_lead_id_that_is_not_a_plain_component_never_reaches_name_construction_on_either_lane(tmp_path):
    """names_one_file refuses exactly what the component grammar refuses — '', '.', '..', a
    '/', and now a NUL byte — so a model-authored lead id 'l-0\\x00x' carried out of
    investigation.md (rg12) answers lead_chain's '(this lead id does not name a file inside
    this world …)' sentence on the grading lane (the prompt render.render builds; the world
    is not refused as short of that id by _check_gather_summaries, which asks names_one_file
    first) AND on the page (where _load_world_leads catches nothing), never the grammar's
    ValueError; a world label cannot carry any of these (is_valid_run_id). Positive control:
    'l-0.md'-shaped ids, a leading dot, whitespace, HTML, a newline and a surrogate are plain
    components and are read (s-34).
    """
    ep = _episode(tmp_path)
    family = R.family()
    nul = "l-0\x00x"
    for bad in ("", ".", "..", "a/b", "/abs", nul, "l-0\x00", "\x00", 1, None):
        assert not family.names_one_file(bad), repr(bad)
    for good in ("l-001", "l-0.md", ".hidden", " spaced", "<b>", "a\nb", "\udcff", "back\\slash"):
        assert family.names_one_file(good), repr(good)

    world_dir = ep / "worlds" / "b"
    doc = J.investigation_document("b").replace("[l-001 r1", f"[{nul} r1", 1)
    (world_dir / "investigation.md").write_text(doc, encoding="utf-8")
    bound = R.bind(ep)
    facts = family.read_investigation_facts(bound, world="b")
    assert nul in facts.resolutions_by_lead, "the fixture's NUL id did not parse (rg12)"

    grade = family.grade_family(ep)
    row = _rows(grade)["b"]
    assert not row.get("ungradable"), row
    base, _src = J.runs_base(tmp_path)
    shown = R.mod("learning.judge.render").render(ep, "b", runs_base=base).leads
    assert "does not name a file inside this world" in shown[nul]["summary"], shown[nul]

    sample = E.sample_episode(tmp_path / "page")
    graded = sample.world(E.GRADED_WORLD)
    inv = (graded / "investigation.md").read_text(encoding="utf-8")
    assert "l-001" in inv
    (graded / "investigation.md").write_text(inv.replace("l-001", nul, 1), encoding="utf-8")
    page = E.render(sample)
    block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "does not name a file inside this world" in block, block
    assert "investigation record unavailable" not in block, block


# ---------------------------------------------------------------------------------------
# s-45 — every refusal shape reaches the served-row swallow site as JudgeRefused
# ---------------------------------------------------------------------------------------


def test_every_refusal_shape_still_arrives_at_the_served_row_swallow_site_as_the_same_exception_type(tmp_path):
    """An alias, a directory, a symlinked served/ and (under NOT_ROOT) a mode-000 file at
    served/<token>.<label>.jsonl each arrive at _episode_has_any_served_row as JudgeRefused
    and are caught there (d-34: no new refusal type; rg1: every OSError is caught by type),
    so grade_family completes and the sibling whose ledger holds a served row is graded with
    the episode counted complete; absent arrives as the primitive's absent state and is
    counted as no rows — with every sibling ledger absent or refused the episode counts as
    incomplete, and the pass still completes. Undecodable bytes are NOT a refusal on this
    reader — the twin decodes with errors='replace' and counts malformed rows (d-07).
    """
    family = R.family()
    shapes = {
        "alias": lambda p, ep: R.plant_link(p, ep / "family.yaml"),
        "directory": lambda p, ep: p.mkdir(),
        "undecodable": lambda p, ep: R.write_bytes(p, R.UNDECODABLE),
        "absent": lambda p, ep: None,
    }
    if os.geteuid() != 0:
        shapes["mode_000"] = lambda p, ep: R.write_bytes(p, "").chmod(0)
    for shape, plant in shapes.items():
        ep = _episode(tmp_path / shape, labels=("b", "c"))
        ledger = ep / _ledger_name("b")
        ledger.unlink()
        plant(ledger, ep)
        with R.restoring_modes(ledger):
            grade = family.grade_family(ep)
        rows = _rows(grade)
        assert set(rows) == {"b", "c"}, shape
        assert not rows['c'].get('ungradable'), (shape, rows['c'])
        assert rows['c'].get('withheld_reason') != 'episode_incomplete', (shape, rows['c'])

    ep = _episode(tmp_path / "served-link", labels=("b", "c"))
    (ep / "served").rename(ep / "served-real")
    R.plant_link(ep / "served", ep / "served-real")
    grade = family.grade_family(ep)
    assert {r["world"] for r in grade.worlds} == {"b", "c"}
    assert all(r.get("ungradable") for r in grade.worlds), "a symlinked served/ reached no reader"

    ep = _episode(tmp_path / "all-absent", labels=("b", "c"))
    for label in ("b", "c"):
        (ep / _ledger_name(label)).unlink()
    grade = family.grade_family(ep)
    assert all(r.get("ungradable") for r in grade.worlds)
