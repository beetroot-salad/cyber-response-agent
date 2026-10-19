"""#1049 — the episode-tree readers rewritten over the bound primitive."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _record_1049 as R
from defender.tests import _triplet_947 as T
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = R.NOT_ROOT

TOKEN = T.EPISODE_TOKEN


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _episode(tmp_path: Path, *, labels: tuple[str, ...] = ("b", "c"), **kw) -> Path:
    """An accepted, archived episode under a root spelled with `SECRET`: the control `a`
    (benign) plus `labels` (malicious), every world archived, every non-control world
    carrying one served row."""
    root = tmp_path / R.SECRET
    return J.accepted_episode(
        root, root=root, labels=("a", *labels),
        dispositions={"a": "benign", **{label: "malicious" for label in labels}},
        ledgers={label: [J.staged_row(label)] for label in labels}, **kw)


#: The judge double's reply for every draw: a valid world answer that grades nothing.
_REPLY = J.as_reply_text(J.reply_doc(bucket="none", systems=[]))


def _grade(ep: Path, tmp_path: Path):
    """The real grading pass over `ep` (`grade_episode`), its model seam a `FakeJudge`. A
    record already on disk is removed first, so a scenario that re-plants a fault and grades
    again sees a fresh pass rather than the idempotent re-read of the earlier one."""
    (ep / "judge.yaml").unlink(missing_ok=True)
    return J.grade_at(ep, judge=J.FakeJudge(default=_REPLY), git_show=J.FakeGitShow(),
                      state=_state1135.env_state())


def _ledger_name(label: str) -> str:
    return f"served/{T.world_token(label)}.jsonl"


def _rows(grade) -> dict[str, dict]:
    return {r["world"]: r for r in grade.worlds}


def _root_free(sentence: str, ep: Path) -> None:
    for spelling in (str(ep), os.path.realpath(ep), str(ep.parent), R.SECRET):
        assert spelling not in sentence, (spelling, sentence)


# d-08 — screened_yaml_mapping


def test_1049_screened_yaml_mapping_says_the_name_on_all_three_arms_and_none_on_absence(tmp_path):
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


# d-10 — the permissive samples reader survives


# d-11 — read_archived_report


# d-12 — the world ledger


def test_1049_the_world_ledger_refusal_names_served_token_label_jsonl(tmp_path):
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


# d-13 — _missing_required_input's ledger arm


# d-14 — lead_chain


def test_1049_the_gather_summary_refusal_names_gather_summaries_lead_md_with_no_scrub(tmp_path):
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
    row = _rows(_grade(ep, tmp_path))["b"]
    assert row.get("ungradable"), row
    assert row.get("malformed") is True, row
    assert "gather_summaries" in row["ungradable_reason"], row
    assert R.ALIAS in row["ungradable_reason"], row
    _root_free(row["ungradable_reason"], ep)


# d-15 — _read_archived_text


# d-16 — _grade_from_document


# d-17 / d-18 / d-19 — the three episode-root parsing readers


# d-20 — branch/episode.verdicts (O3, the eval lane)


# d-21 — the reader= seam


# d-22 — every caller coalesces at the read site


# d-28 — judge.yaml rows say relative names


# d-37 — labels and lead ids are gated before any read


def test_1049_a_label_or_lead_id_that_names_no_path_inside_the_world_is_never_echoed_from_a_read(tmp_path):
    ep = _episode(tmp_path)
    family = R.family()
    refused = R.refused_class()
    manifest = family.raw_manifest(ep)
    manifest["worlds"].append({**manifest["worlds"][1], "world_id": "../../elsewhere"})
    T.write_family(ep, manifest)
    for read in (lambda: family.raw_manifest(ep), lambda: _grade(ep, tmp_path)):
        with pytest.raises(refused, match="outside the world-token alphabet"):
            read()
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


# D-J2 — the three world-level readers answer the absent STATE; the page renders it


# D-J3 — lead_chain with no lstat ahead of the summary read


def test_1049_a_symlinked_gather_summary_or_directory_is_the_chains_sentence_and_an_absent_one_is_none(tmp_path):
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
    quiet = sample.world(E.PASSTHROUGH_WORLD)
    (quiet / "gather_summaries").rename(quiet / "summaries-real")
    R.plant_link(quiet / "gather_summaries", quiet / "summaries-real")
    page = E.render(sample)
    graded_block = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert 'gather_summaries/l-001.md' in graded_block, graded_block
    assert R.ALIAS in graded_block, graded_block
    assert f"summary of l-002 for {E.GRADED_WORLD}" in graded_block, "the sibling summaries still read"
    quiet_block = page.text_of(f"leads-{E.PASSTHROUGH_WORLD}")
    assert 'gather_summaries/l-001.md' in quiet_block, quiet_block
    assert R.ALIAS in quiet_block, quiet_block
    assert str(sample.dir) not in page.raw
    assert str(tmp_path) not in page.raw


# D-J7 — review / samples shape arms per reader


# D-V2 — the bind is the only root holder


# D-V4 — names_one_file is the component grammar


def test_1049_a_lead_id_that_is_not_a_plain_component_never_reaches_name_construction_on_either_lane(tmp_path):
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

    grade = _grade(ep, tmp_path)
    row = _rows(grade)["b"]
    assert not row.get("ungradable"), row
    base, _src = J.runs_base(tmp_path)
    shown = R.mod("learning.judge.render").render(ep, "b").focus.leads
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


# s-45 — every refusal shape reaches the served-row swallow site as JudgeRefused
