"""#1025 O8 (prep 2 / 2b) — one episode reader, one home for each file name, and the stored
`has_refused` flag.

O8 (maintainer): the page, the grading pass and the judge input builder read the episode
archive through ONE reader — one spelling of each file name, one home for each derived
accessor. The observed failing is a fourth `REVIEW_NAME = "review.yaml"` (there are four
today, plus a fifth spelled `REVIEW_FILENAME`), or the page re-implementing a lead chain the
input builder already computes. Three decisions are pinned here:

1. **The file names live in `learning/branch/archive.py`** — `REVIEW_NAME`, `SAMPLES_NAME`,
   `JUDGE_NAME` — and NOWHERE ELSE: across the shipped code roots the literals `"review.yaml"`,
   `"samples.yaml"` and `"judge.yaml"` each occur in exactly one module, and the three
   assignments occur only there. O8's observable IS a name census, so this is the one suite
   where a grep over the tree is the honest test rather than a proxy for one.
2. **The derived accessors live in `learning/judge/family.py` under PUBLIC names** —
   `world_review_block`, `staged_patterns`, `world_pattern`, `own_h_rows`, `raw_manifest`, and,
   moved off `render.py`, `queries_by_lead`, `lead_chain` and `json_mapping`. The private
   spellings that crossed module lines are gone. Each accessor's behaviour is driven on the
   public name against a real archived world, so the move is a move and not a rename plus a
   rewrite.
3. **The tolerant `judge.yaml` reader is public: `judge.read_grade(episode_dir)`** — `None`
   for an ungraded episode, a refusal for a planted link or a non-mapping (real faults through
   the real primitive), a pre-#1007 record read with today's defaults and nothing invented,
   and the SAME record `grade_episode` returns on an already-graded episode.

Prep 2b / O3: the `lead-quality` vs `None` branch of the bucket ladder turns on `has_refused`,
which the pass computed and never wrote. It is now on every world row `judge.yaml` writes,
beside the other flags — true iff the world's served ledger holds a row on the holding system
whose `source` is the ledger's own `refused` — and it survives the round trip through
`read_grade`. The ladder pairing (a refused H row buckets `None`, the same world without one
buckets `lead-quality`) is the positive/negative control, driven through the real pass.

RED AGAINST HEAD is the expected state: the constants, the public names and the field do not
exist yet, and the census finds five modules spelling `review.yaml`. Every import goes through
`J.mod` / `J.sym` PER TEST so a missing target is one failure per test, never a collection
error.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender.tests import _judge_921 as J

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root inside `tmp_path`, so a pass this file drives lands in this test's
    own tree — never the checkout's runs base or its real `learning/_pending/`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _judge():
    return J.mod("learning.judge")


def _family():
    return J.mod("learning.judge.family")


def _render():
    return J.mod("learning.judge.render")


def _archive():
    return J.mod("learning.branch.archive")


def _refused():
    """The judge's own refusal class, resolved BEFORE the `raises` block opens — a missing
    target fails at the call rather than satisfying `raises(Exception)`."""
    return J.sym("learning.judge", "JudgeRefused")


def _grade(ep: Path, tmp_path: Path):
    """The real grading pass over `ep`, through its own seams — never a live provider."""
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    return _judge().grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs")


def _rows(grade: Any) -> dict[str, dict]:
    return {row["world"]: row for row in grade.worlds}


def _passthrough(label: str) -> dict:
    """A queried-and-undoctored H row: the shape that lands in `lead-quality` on its own."""
    return J.ledger_row(source="passthrough", world_label=label)


def _refused_row(label: str, *, system: str = J.HOLDING_SYSTEM) -> dict:
    """The ledger's own `refused` word, imported rather than re-spelled — the flag keys on it.

    Its OWN params: the ledger reader is first-row-wins on a duplicate pair-key (J3), so a
    refused row sharing the passthrough row's query would be read as that row's duplicate and
    never reach the flag — a real refusal is of a different query than the one that was served.
    """
    refused = J.sym("learning.branch.ledger", "REFUSED")
    return J.ledger_row(source=refused, world_label=label, system=system,
                        params={"index": f"{J.EVENTS_PATTERN},audit-*"},
                        payload="this ES|QL query's FROM clause addresses several corpora")


# ---------------------------------------------------------------------------------------
# Decision 1 — the file names: one home, one spelling
# ---------------------------------------------------------------------------------------

#: The shipped code roots (the project profile's `specGraph.codeRoots`), relative to the
#: `defender/` package the code under test is actually IMPORTED from — so a worktree census
#: reads the worktree, never the checkout the shared venv's editable install points at.
_CODE_ROOTS = ("learning", "runtime", "scripts", "evals", "run.py")
_ARCHIVE_MODULE = "learning/branch/archive.py"
_FILE_NAMES = ("review.yaml", "samples.yaml", "judge.yaml")
_CONSTANT_NAMES = ("REVIEW_NAME", "SAMPLES_NAME", "JUDGE_NAME")
#: An ASSIGNMENT to one of the three names at the start of a line — `NAME = ...` — and never
#: an `==`, an import, or a longer name that merely starts the same way (`REVIEW_FILENAME`).
_ASSIGNMENT = re.compile(
    r"^\s*(?:" + "|".join(_CONSTANT_NAMES) + r")\s*=(?!=)", re.MULTILINE)


def _shipped_modules() -> dict[str, str]:
    """`{relative posix path: source text}` for every `.py` under the shipped roots. The
    package dir is the one `archive.py` was imported from (`defender` is a namespace package
    and has no `__file__` of its own), so the tree censused is the tree under test."""
    package = Path(_archive().__file__).resolve().parents[2]
    assert package.name == "defender", f"the census root is not the package: {package}"
    out: dict[str, str] = {}
    for root in _CODE_ROOTS:
        base = package / root
        files = [base] if base.is_file() else sorted(base.rglob("*.py"))
        for path in files:
            out[path.relative_to(package).as_posix()] = path.read_text(encoding="utf-8")
    assert _ARCHIVE_MODULE in out, f"the census never saw {_ARCHIVE_MODULE}: {sorted(out)[:5]}"
    return out


def test_archive_is_the_one_home_for_the_three_episode_record_names():
    """`archive.py` — which already owns `WORLDS_DIRNAME`, `ALERT_NAME` and the other archived
    names — owns the three episode-level record names too, with the values every reader today
    spells for itself.

    Observably true: `archive.REVIEW_NAME == "review.yaml"`, `SAMPLES_NAME == "samples.yaml"`,
    `JUDGE_NAME == "judge.yaml"`.

    What failure looks like: the constants are absent (four modules keep their own), or one is
    present under a different value than the file the launcher actually writes.
    """
    archive = _archive()

    for name, value in zip(_CONSTANT_NAMES, _FILE_NAMES, strict=True):
        assert getattr(archive, name) == value, (
            f"archive.{name} is {getattr(archive, name)!r}, not {value!r}")


def test_each_episode_record_name_is_spelled_in_exactly_one_shipped_module():
    """O8's census, run as a grep over the tree: across the shipped code roots the literals
    `"review.yaml"`, `"samples.yaml"` and `"judge.yaml"` each occur in ONE module — `archive.py`
    — and an ASSIGNMENT to `REVIEW_NAME` / `SAMPLES_NAME` / `JUDGE_NAME` occurs only there.
    Every other module imports the name; an import is not an assignment and does not count.

    Observably true: the set of modules containing each literal is `{archive.py}`, and so is
    the set of modules assigning any of the three names.

    What failure looks like: today — `family.py`, `branch/episode.py`, `branch/review.py`,
    `branch/cli.py` and `branch/staging.py` (as `REVIEW_FILENAME`) each spell `review.yaml`,
    `judge/__init__.py` and `judge/run.py` spell `judge.yaml` and `samples.yaml` inline. A
    fourth definition is exactly O8's named failing: a rename of the file reaches some readers
    and not others, and the page reads a record the pass never wrote.
    """
    modules = _shipped_modules()

    for file_name in _FILE_NAMES:
        literal = re.compile(r"""["']""" + re.escape(file_name) + r"""["']""")
        spelled_in = sorted(m for m, text in modules.items() if literal.search(text))
        assert spelled_in == [_ARCHIVE_MODULE], (
            f"{file_name!r} is spelled as a literal in {spelled_in}; O8 wants exactly one "
            f"home, {_ARCHIVE_MODULE}, with every other module importing the name")

    assigned_in = sorted(m for m, text in modules.items() if _ASSIGNMENT.search(text))
    assert assigned_in == [_ARCHIVE_MODULE], (
        f"REVIEW_NAME / SAMPLES_NAME / JUDGE_NAME are ASSIGNED in {assigned_in}; only "
        f"{_ARCHIVE_MODULE} may define them — a re-export is an import, not an assignment")


# ---------------------------------------------------------------------------------------
# Decision 2 — the derived accessors: one home, public names, the same behaviour
# ---------------------------------------------------------------------------------------

#: The five `family.py` privates `render.py` imported across the module line, and the two
#: `render.py` privates the page needs — each as `(private spelling, public spelling)`.
_MOVED = (
    ("_world_review_block", "world_review_block"),
    ("_staged_patterns", "staged_patterns"),
    ("_world_pattern", "world_pattern"),
    ("_own_h_rows", "own_h_rows"),
    ("_raw_manifest", "raw_manifest"),
    ("_queries_by_lead", "queries_by_lead"),
    ("_lead_chain", "lead_chain"),
)


def test_family_is_the_one_home_for_the_derived_accessors_under_public_names():
    """The episode reader's derived accessors have ONE home, `judge/family.py`, and public
    names — nothing crosses a module line as a private any more.

    Observably true: `family` exposes `world_review_block`, `staged_patterns`, `world_pattern`,
    `own_h_rows`, `raw_manifest`, `queries_by_lead`, `lead_chain` and `json_mapping` as
    callables; neither `family` nor `render` carries the underscore spelling of any of them;
    and where `render` still exposes one of the public names (it imports them), it is the
    SAME object `family` owns — never a second implementation under the same name.

    This is a name census, which is what O8's observable is. What failure looks like: the page
    imports `render._lead_chain` (a private, across a module line — today's state), or the
    accessor is copied into a second home so the two drift.
    """
    family, render = _family(), _render()

    for private, public in _MOVED:
        assert callable(getattr(family, public, None)), (
            f"family.{public} is absent — the accessor still lives under {private!r}")
        for module, name in ((family, private), (render, private)):
            assert not hasattr(module, name), (
                f"{module.__name__}.{name} still exists; the private spelling crosses a module "
                f"line and O8 wants one public home, family.{public}")
        if hasattr(render, public):
            assert getattr(render, public) is getattr(family, public), (
                f"render.{public} is not family.{public} — two homes for one accessor")
    assert callable(getattr(family, "json_mapping", None)), (
        "family.json_mapping is absent — the JSON tolerance policy has no home in the reader")
    if hasattr(render, "json_mapping"):
        assert render.json_mapping is family.json_mapping, (
            "render.json_mapping is not family.json_mapping — two homes for one policy")


def test_queries_by_lead_groups_issued_rows_and_drops_conduct_rows_in_one_parse(tmp_path):
    """`queries_by_lead(world_dir)` reads the world's `executed_queries.jsonl` ONCE and hands
    back `{lead_id: [rows in file order]}` — the issued queries only.

    Observably true: two rows for `l-001` and one for `l-002` group under their leads in file
    order; a `∅.`-prefixed sentinel row (the writer's own conduct partition, `is_reserved_query_
    id`) and a row with no `lead_id` are in neither group.

    What failure looks like: the sentinel reaches VIEW 1 as a query the world issued — a
    defender failure invented out of a call the defender was refused (the bug `render.py`'s own
    docstring records being fixed once already).
    """
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-002", "query_id": "q3", "params": {"index": "alerts-*"},
         "payload_digest": "d3"},
        {"lead_id": "l-001", "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
        {"lead_id": "l-001", "query_id": "∅.above-repeat-guard", "params": {},
         "payload_digest": "dx"},
        {"query_id": "q9", "params": {}},
    ]
    (world_dir / "executed_queries.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")

    grouped = _family().queries_by_lead(world_dir)

    assert {lead: [r["query_id"] for r in group] for lead, group in grouped.items()} == {
        "l-001": ["q1", "q2"], "l-002": ["q3"]}, (
        f"the sentinel or the lead-less row reached a lead's group, or order was lost: {grouped}")


def test_queries_by_lead_refuses_a_planted_link_at_the_table_name(tmp_path):
    """The queries table is read through the archive's own `lstat` posture: a link at
    `executed_queries.jsonl` reads as NO table, not as the target's rows.

    Observably true: the same bytes as a regular file group into leads (positive control); as
    a real symlink to a file outside the world they group into nothing.

    What failure looks like: another tree's rows enter VIEW 1 as this world's own conduct.
    """
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    table = world_dir / "executed_queries.jsonl"
    line = json.dumps({"lead_id": "l-001", "query_id": "q1", "params": {}}) + "\n"
    table.write_text(line, encoding="utf-8")
    assert list(_family().queries_by_lead(world_dir)) == ["l-001"], (
        "positive control: a regular table did not group")

    outside = tmp_path / "planted.jsonl"
    outside.write_text(line, encoding="utf-8")
    table.unlink()
    table.symlink_to(outside)

    assert _family().queries_by_lead(world_dir) == {}, (
        "a symlink at the queries table's name was followed and its target's rows read as this "
        "world's issued queries")


def test_lead_chain_joins_goal_params_payload_summary_rows_and_resolutions_per_lead(tmp_path):
    """`lead_chain(world_dir, lead_id, resolutions_by_lead, *, queries_by_lead=...)` is the
    per-lead join the page needs and the input builder already computes: goal (off the lead's
    own `gather_raw/<lead>.lead.json`), params (the first issued query's), payload digests (in
    issue order), the gather summary, the document rows, and this lead's resolutions.

    Observably true: each link carries the value the archived world actually holds. A lead
    with queries but no lead file and no summary reads `goal: None`, `summary: None` — absence
    stays absence.

    What failure looks like: the page re-implements the chain and reads one link differently
    from the prompt (O8's second named failing).
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-001", "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
        {"lead_id": "l-002", "query_id": "q3", "params": {"index": "alerts-*"},
         "payload_digest": "d3"},
    ]
    (world_dir / "executed_queries.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    resolutions = {"l-001": [{"before": "open", "after": "held"}]}
    grouped = family.queries_by_lead(world_dir)

    chain = family.lead_chain(world_dir, "l-001", resolutions, queries_by_lead=grouped)

    assert chain["goal"] == "find the pivot"
    assert chain["params"] == {"index": "logs-*"}, "params is not the FIRST issued query's"
    assert chain["payload"] == ["d1", "d2"]
    assert chain["summary"] == (world_dir / "gather_summaries" / "l-001.md").read_text(
        encoding="utf-8")
    assert chain["document_rows"] == grouped["l-001"]
    assert chain["resolutions"] == resolutions["l-001"]

    bare = family.lead_chain(world_dir, "l-002", resolutions, queries_by_lead=grouped)
    assert (bare["goal"], bare["summary"], bare["resolutions"]) == (None, None, [])
    assert bare["payload"] == ["d3"], "a lead with queries but no lead file lost its payload"


def test_lead_chain_never_reads_outside_the_graded_world_for_a_traversing_lead_id(tmp_path):
    """A lead id is MODEL-authored text that becomes a path. One that would read outside the
    graded world reads nothing — not the sibling's lead file, not the sibling's summary.

    Observably true: with world `c`'s `gather_raw/l-001.lead.json` and `gather_summaries/
    l-001.md` both really on disk, a lead id that resolves to them from `b` yields `goal: None`
    and a summary that is not `c`'s text. Positive control: the honest id reads `b`'s own.

    What failure looks like: a counterfactual sibling's report enters this world's prompt as
    a fact about the world being graded (O5/J14).
    """
    family = _family()
    ep = J.accepted_episode(tmp_path)
    b_dir, c_dir = ep / "worlds" / "b", ep / "worlds" / "c"
    (c_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "SIBLING GOAL"}), encoding="utf-8")
    sibling_summary = (c_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "world c" in sibling_summary, "the fixture's sibling summary does not name world c"
    traversing = "../../c/gather_summaries/l-001"

    honest = family.lead_chain(b_dir, "l-001", {}, queries_by_lead={})
    leaked = family.lead_chain(b_dir, traversing, {}, queries_by_lead={})

    assert "world b" in (honest["summary"] or ""), "positive control: b's own summary not read"
    assert leaked["goal"] is None, f"the sibling's lead file was read: {leaked['goal']!r}"
    assert "world c" not in (leaked["summary"] or ""), (
        "a traversing lead id read world c's gather summary into world b's chain")


def test_json_mapping_answers_a_mapping_and_none_for_everything_else(tmp_path):
    """`json_mapping(path)` is the ONE tolerance policy for a JSON artifact: a mapping, or
    `None` for an absent file, a corrupt one, or a JSON document that is not a mapping.

    Observably true: four inputs through the real file, four answers.

    What failure looks like: a fifth reader spells its own `except` set and a class one site
    survives takes another site's whole grade down.
    """
    family = _family()
    path = tmp_path / "artifact.json"

    path.write_text(json.dumps({"alert_id": "a-1"}), encoding="utf-8")
    assert family.json_mapping(path) == {"alert_id": "a-1"}
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert family.json_mapping(path) is None, "a JSON list was answered as a mapping"
    path.write_text("{not json", encoding="utf-8")
    assert family.json_mapping(path) is None, "a corrupt document raised or was answered"
    assert family.json_mapping(tmp_path / "absent.json") is None


def test_world_review_block_joins_by_label_and_answers_none_for_an_absent_or_odd_entry():
    """`world_review_block(review, label)` is this world's `reachability` sub-block off the
    review record, joined BY NAME — or `None` when there is no mapping there to read.

    Observably true: a labelled entry with a mapping block is returned; an entry that is a
    string, an entry whose block is a list, a label the review never names, and a `worlds`
    that is not a mapping all read `None`.
    """
    family = _family()
    review = {"worlds": {
        "b": {"reachability": {"reachable_by_capture": True}},
        "c": "not an entry",
        "d": {"reachability": [1]},
    }}

    assert family.world_review_block(review, "b") == {"reachable_by_capture": True}
    for label in ("c", "d", "zz"):
        assert family.world_review_block(review, label) is None, (
            f"label {label!r} read a block where the review holds none")
    assert family.world_review_block({"worlds": []}, "b") is None


def test_staged_patterns_and_world_pattern_read_the_overlay_the_same_way():
    """`staged_patterns(overlay)` is EVERY staged pattern in a stable (sorted) order — O5's
    per-pattern domain; `world_pattern(overlay, *, holding_system=)` is the single
    representative anchor: the first of those, or the holding system's own name for a
    patch-only world.

    Observably true: a two-pattern overlay enumerates both, sorted, and anchors on the first;
    a patch-only overlay enumerates nothing and anchors on `holding_system`; an overlay that is
    not a mapping enumerates nothing.
    """
    family = _family()
    two = J.overlay(elastic={
        **J.elastic_overlay("logs-b", inject=[{"_id": 1}]),
        **J.elastic_overlay("alerts-a", exclude={"term": {"x": 1}}),
    })
    patch_only = J.overlay(patches={"p": "patched"})

    assert family.staged_patterns(two) == ["alerts-a", "logs-b"]
    assert family.world_pattern(two, holding_system="elastic") == "alerts-a"
    assert family.staged_patterns(patch_only) == []
    assert family.world_pattern(patch_only, holding_system="elastic") == "elastic"
    assert family.staged_patterns(None) == []
    assert family.staged_patterns({"elastic": {}}) == []


def test_own_h_rows_selects_the_holding_systems_rows_after_strip_and_casefold():
    """`own_h_rows(rows, holding_system)` is the world's rows ON H — `system` compared after
    strip+casefold, the same normalisation J1 validated H under; a row with no usable `system`
    is not H's.
    """
    family = _family()
    rows = [{"system": "elastic", "n": 1}, {"system": " Elastic ", "n": 2},
            {"system": "cmdb", "n": 3}, {"system": None, "n": 4}, {"n": 5}]

    assert [r["n"] for r in family.own_h_rows(rows, "elastic")] == [1, 2]


def test_raw_manifest_reads_the_screened_manifest_and_refuses_a_link_or_a_non_mapping(tmp_path):
    """`raw_manifest(episode_dir)` is the judge's own screened read of `family.yaml`: the
    document as a mapping, or this design's refusal.

    Observably true: the episode's real manifest reads back with its `episode_id`; a real
    symlink planted at the manifest's name (to a byte-identical file outside the episode) and
    a manifest that parses to a list both raise `JudgeRefused`.

    What failure looks like: the grader honours a link the launcher refuses, and decides which
    worlds exist off a document the model planted.
    """
    family, refused = _family(), _refused()
    ep = J.accepted_episode(tmp_path)
    manifest = ep / "family.yaml"
    assert family.raw_manifest(ep)["episode_id"] == J.EPISODE_ID

    outside = tmp_path / "planted-family.yaml"
    outside.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    manifest.unlink()
    manifest.symlink_to(outside)
    with pytest.raises(refused):
        family.raw_manifest(ep)

    manifest.unlink()
    manifest.write_text("- not\n- a mapping\n", encoding="utf-8")
    with pytest.raises(refused):
        family.raw_manifest(ep)


# ---------------------------------------------------------------------------------------
# Decision 3 — the tolerant grade reader, public
# ---------------------------------------------------------------------------------------


def test_read_grade_is_none_before_a_grade_and_the_same_record_grade_episode_returns_after(
        tmp_path):
    """`judge.read_grade(episode_dir)` is the ONE reader of `judge.yaml`: `None` for an
    ungraded episode, and afterwards the record — the same one `grade_episode` hands back on
    an already-graded episode, because that path reads through the same function.

    Observably true: before any pass `read_grade` is `None`; after one, `read_grade`'s
    `worlds`, `verdict_word`, `family_outcome` and `withheld_findings` equal the live pass's,
    and a second `grade_episode` (the existing-record path) equals `read_grade`.

    What failure looks like: the page parses YAML itself and disagrees with the pass on a
    truncated or pre-#1007 record — two readers of one file (O8).
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    read_grade = J.sym("learning.judge", "read_grade")
    assert read_grade(ep) is None, "an ungraded episode read as a grade"

    live = _grade(ep, tmp_path)
    stored = read_grade(ep)
    again = _grade(ep, tmp_path)

    assert stored is not None
    for field in ("worlds", "verdict_word", "family_outcome", "withheld_findings"):
        assert getattr(stored, field) == getattr(live, field), (
            f"read_grade's {field!r} differs from the pass that wrote it")
        assert getattr(again, field) == getattr(stored, field), (
            f"grade_episode's existing-record path and read_grade disagree on {field!r}")


def test_read_grade_refuses_a_planted_link_and_a_non_mapping_record(tmp_path):
    """The idempotency record is read through the screened read: a link at `judge.yaml`'s
    name and a document that is not a mapping are refusals, never a grade.

    Observably true: the same mapping bytes as a regular `judge.yaml` read back (positive
    control); as a real symlink to that file outside the episode they raise `JudgeRefused`;
    a `judge.yaml` holding a YAML list raises `JudgeRefused`.

    What failure looks like: a planted document parses as a mapping and `grade_episode` hands
    back an attacker-supplied grade without running the pass at all.
    """
    read_grade, refused = J.sym("learning.judge", "read_grade"), _refused()
    ep = J.accepted_episode(tmp_path)
    record = ep / "judge.yaml"
    outside = tmp_path / "planted-judge.yaml"
    outside.write_text(yaml.safe_dump(
        {"worlds": [{"world": "b", "bucket": None}], "verdict_word": "survived"}),
        encoding="utf-8")

    record.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    assert read_grade(ep).verdict_word == "survived", "positive control: a regular record"

    record.unlink()
    record.symlink_to(outside)
    with pytest.raises(refused):
        read_grade(ep)

    record.unlink()
    record.write_text("- not\n- a grade\n", encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)


def test_read_grade_reads_a_pre_1007_record_with_defaults_and_invents_nothing(tmp_path):
    """A record in the pre-#1007 shape — no `family_outcome`, no `world_enqueued_rows`, no
    `withheld_findings`, world rows without `has_refused` — reads without raising, with the
    reader's defaults for the family-level absences and NOTHING invented on the rows.

    Observably true: `family_outcome is None`, `world_enqueued_rows == 0`,
    `withheld_findings == []`, `graded_worlds == {"b"}`, and the world row comes back as
    written — no `has_refused` key the archive never stored (O3: where the ladder's branch
    depends on a fact the archive does not store, the page says so rather than inventing one).
    Positive control: the same record carrying the fields reads them back.
    """
    read_grade = J.sym("learning.judge", "read_grade")
    ep = J.accepted_episode(tmp_path)
    old_row = {"world": "b", "bucket": "lead-quality", "holding_queried": True,
               "doctored_answer_served": False, "difference_shown": False,
               "withheld_reason": None}
    old = {"worlds": [old_row], "verdict_word": "caught", "episode_outcome": "gradable",
           "enqueued_rows": 0, "enqueued_to": "", "draws": {"completed": 1}, "knobs": {},
           "lessons_commit": None, "discard_evidence": {}, "queue_malformed_rows": 0,
           "unqueueable_findings": []}
    (ep / "judge.yaml").write_text(yaml.safe_dump(old, sort_keys=False), encoding="utf-8")

    grade = read_grade(ep)

    assert grade.family_outcome is None
    assert grade.world_enqueued_rows == 0
    assert grade.withheld_findings == []
    assert grade.graded_worlds == frozenset({"b"})
    assert _rows(grade)["b"] == old_row, (
        "the reader rewrote a pre-#1007 world row — it invented a fact the archive never stored")
    assert "has_refused" not in _rows(grade)["b"]

    new = dict(old, family_outcome="gradable", withheld_findings=[{"world": "b"}],
               worlds=[dict(old_row, has_refused=True)])
    (ep / "judge.yaml").write_text(yaml.safe_dump(new, sort_keys=False), encoding="utf-8")
    grade = read_grade(ep)
    assert (grade.family_outcome, grade.withheld_findings) == ("gradable", [{"world": "b"}])
    assert _rows(grade)["b"]["has_refused"] is True, "positive control: a stored flag read back"


def test_read_grade_reads_back_a_not_graded_stamp(tmp_path):
    """An episode the pass declined to grade leaves a `not_graded` stamp, and the reader hands
    it back as one — `not_graded` set, `episode_outcome` the not-graded word — so a page can
    say "not graded, and here is why" rather than "graded, undecidable".

    Observably true: after a pass over an `incomplete` review, `read_grade(ep).not_graded` is
    the `{outcome, reason}` mapping the pass wrote and `episode_outcome == judge.NOT_GRADED`;
    positive control — a graded episode reads `not_graded is None`.
    """
    judge = _judge()
    read_grade = J.sym("learning.judge", "read_grade")
    skipped = J.accepted_episode(tmp_path, outcome="incomplete")
    graded = J.accepted_episode(tmp_path / "graded")

    _grade(skipped, tmp_path)
    _grade(graded, tmp_path)

    stamp = read_grade(skipped)
    assert stamp.not_graded is not None, "the not-graded stamp did not read back"
    assert stamp.not_graded.get("outcome") == "incomplete", repr(stamp.not_graded)
    assert stamp.episode_outcome == judge.NOT_GRADED
    assert read_grade(graded).not_graded is None, "positive control: a graded episode"


# ---------------------------------------------------------------------------------------
# Prep 2b / O3 — `has_refused`, stored beside the flags the ladder reads
# ---------------------------------------------------------------------------------------


def test_every_graded_world_row_stores_has_refused_beside_the_other_flags(tmp_path):
    """`has_refused: bool` is on every world row the pass writes, beside `holding_queried`,
    `doctored_answer_served` and `difference_shown` — true iff the world's served ledger holds
    a row on the HOLDING SYSTEM whose `source` is the ledger's `refused`.

    Observably true, three worlds through the real pass: `b` (a passthrough plus a refused row
    on H) stores `True`; `c` (the passthrough alone) stores `False`; `d` (the passthrough plus
    a refused row on ANOTHER system) stores `False` — the flag keys on H, as the ladder does.
    Every row carrying `holding_queried` carries `has_refused` as a bool, in the returned
    record and in the `judge.yaml` on disk.

    What failure looks like: the bucket ladder branches on a fact the record never shows, so a
    page reading the row cannot say why an undoctored, queried world has no bucket (O3).
    """
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={
            "b": [_passthrough("b"), _refused_row("b")],
            "c": [_passthrough("c")],
            "d": [_passthrough("d"), _refused_row("d", system="cmdb")],
        })

    grade = _grade(ep, tmp_path)

    for rows in (_rows(grade), J.world_rows(J.judge_record(ep))):
        for label, row in rows.items():
            if "holding_queried" in row:
                assert isinstance(row.get("has_refused"), bool), (
                    f"world {label!r} carries holding_queried but no bool has_refused: "
                    f"{sorted(row)}")
        assert rows["b"]["has_refused"] is True, "a refused row on H did not set the flag"
        assert rows["c"]["has_refused"] is False, "no refused row anywhere, yet the flag is set"
        assert rows["d"]["has_refused"] is False, (
            "a refused row on a system that is NOT H set the flag; the ladder keys on H's rows")


def test_a_refused_h_row_is_the_stored_fact_that_turns_lead_quality_into_no_bucket(tmp_path):
    """The ladder's own pairing, driven through the real pass: a queried, undoctored world
    buckets `lead-quality`; the same world with one `refused` row on H buckets `None` (F-1) —
    and the row now SAYS which case it is.

    Observably true: `c` (`has_refused: False`) reads `bucket: "lead-quality"`; `b`
    (`has_refused: True`) reads `bucket: None`; both have `holding_queried: True` and
    `doctored_answer_served: False`, so `has_refused` is the one stored fact that separates
    them.

    What failure looks like: the bucket and the flag disagree — a row saying `has_refused:
    True` under `lead-quality`, or `False` under no bucket — which is a flag computed from
    something other than what the ladder read.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [_passthrough("b"), _refused_row("b")],
        "c": [_passthrough("c")],
    })

    rows = _rows(_grade(ep, tmp_path))

    for label in ("b", "c"):
        assert rows[label]["holding_queried"] is True
        assert rows[label]["doctored_answer_served"] is False
        assert rows[label].get("ungradable") is not True
    assert (rows["c"]["has_refused"], rows["c"]["bucket"]) == (False, "lead-quality")
    assert (rows["b"]["has_refused"], rows["b"]["bucket"]) == (True, None), (
        f"a refused H row: {rows['b'].get('has_refused')!r} / {rows['b']['bucket']!r}")


def test_has_refused_survives_the_round_trip_through_read_grade(tmp_path):
    """The flag is WRITTEN, not re-derived: the `judge.yaml` on disk carries it, and
    `read_grade` hands back the same value on every row the pass returned.

    Observably true: after one pass, the raw document's world rows carry `has_refused` with
    the pass's values, and `read_grade(ep)`'s rows equal the live pass's rows key for key.

    What failure looks like: the field is on the returned record and not in the file, so a
    re-read episode (the existing-record path, the page) grades as if the fact was never known.
    """
    read_grade = J.sym("learning.judge", "read_grade")
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [_passthrough("b"), _refused_row("b")],
        "c": [_passthrough("c")],
    })

    live = _rows(_grade(ep, tmp_path))
    on_disk = J.world_rows(J.judge_record(ep))
    stored = _rows(read_grade(ep))

    assert {label: row.get("has_refused") for label, row in on_disk.items()} == {
        "b": True, "c": False}, "judge.yaml does not carry the flag the pass computed"
    assert stored == live, (
        "a per-world field written to judge.yaml did not survive the re-read through read_grade")
