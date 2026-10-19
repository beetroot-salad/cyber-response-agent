"""#1025 O8 (prep 2) — one episode reader and one home for each file name."""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml

from defender._io import bind
from defender.run_repository import RunPaths
from defender.tests import _judge_921 as J
from defender.tests._spec791 import PROJECT_PROFILE
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root inside `tmp_path`, so a pass this file drives lands in this test's
    own tree — never the checkout's runs base or its real `learning/_pending/`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _judge():
    return J.mod("learning.judge")


def _family():
    return J.mod("learning.judge.family")


def _world(ep: Path, label: str):
    """The reader `lead_chain` takes: the episode's bound primitive, bound one directory down
    at `worlds/<label>` by derivation (#1049 D-V2) — never a path it could format."""
    return J.mod("_io").bind(ep).under(f"worlds/{label}")


def _render():
    return J.mod("learning.judge.render")


def _io():
    return J.mod("_io")


def _archive():
    return J.mod("learning.branch.archive")


def _refused():
    """The judge's own refusal class, resolved BEFORE the `raises` block opens — a missing
    target fails at the call rather than satisfying `raises(Exception)`."""
    return J.sym("learning.judge", "JudgeRefused")


def _grade(ep: Path, tmp_path: Path):
    """The real grading pass over `ep`, through its own seams — never a live provider."""
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    return J.grade_at(ep, judge=judge, state=_state1135.env_state())


def _write_issued(world_dir: Path, rows: list[dict]) -> Path:
    """The world's queries table, written the one way this file writes it: one JSON object per
    line at the writer's own path (`RunPaths.executed_queries`), so the four scenarios that
    need a table spell neither the name nor the JSONL join."""
    table = RunPaths(world_dir).executed_queries
    table.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return table


# ---------------------------------------------------------------------------------------
# Decision 1 — the file names: one home, one spelling
# ---------------------------------------------------------------------------------------

#: The shipped code roots — the project profile's `sourceRoots`, READ from the profile
#: rather than re-spelled so a root added there is censused here — relative to the `defender/`
#: package the code under test is actually IMPORTED from, so a worktree census reads the
#: worktree, never the checkout the shared venv's editable install points at.
_CODE_ROOTS = tuple(
    Path(root).relative_to("defender").as_posix()
    for root in json.loads(PROJECT_PROFILE.read_text(encoding="utf-8"))["sourceRoots"])
#: The ONE home of the three names — `_episode_paths.py`, the episode-layout owner (#1077 D1
#: re-homed them off `learning/branch/archive.py`, which now binds them by import). The
#: run-level owner is censused beside it: the family stamp's name is its `PROVENANCE`.
_OWNER_MODULE = "_episode_paths.py"
#: The run-layout owner, by its path under `defender/` since #1105 moved it into the runs
#: repository package (D1.1). A stale path here would silently drop it from the census (`rglob`
#: of a missing path yields nothing), so `_shipped_modules` asserts the census saw it.
_LAYOUT_MODULE = "run_repository/_layout.py"
_OWNER_MODULES = (_OWNER_MODULE, _LAYOUT_MODULE)
_ARCHIVE_MODULE = "learning/branch/archive.py"
#: The three names and the three files, one mapping.
_RECORD_NAMES = {"REVIEW_NAME": "review.yaml", "SAMPLES_NAME": "samples.yaml",
                 "JUDGE_NAME": "judge.yaml"}

#: Every shipped module that reads one of the three records, and the attribute it reads the
#: name through. Each must be `archive`'s OWN object — an import, never a re-spelling.
_IMPORTERS: tuple[tuple[str, str], ...] = (
    ("learning.branch.cli", "REVIEW_NAME"),
    ("learning.branch.cli", "SAMPLES_NAME"),
    ("learning.branch.episode", "REVIEW_NAME"),
    ("learning.judge.enqueue", "SAMPLES_NAME"),
    ("learning.judge.family", "REVIEW_NAME"),
    ("learning.judge.family", "SAMPLES_NAME"),
    ("learning.judge.run", "REVIEW_NAME"),
    ("learning.judge.run", "SAMPLES_NAME"),
    ("learning.judge.run", "JUDGE_NAME"),
    ("learning.judge", "JUDGE_NAME"),
    ("learning.judge", "REVIEW_NAME"),
)


def _shipped_modules() -> dict[str, str]:
    """`{relative posix path: source text}` for every `.py` under the shipped roots. The
    package dir is the one `archive.py` was imported from (`defender` is a namespace package
    and has no `__file__` of its own), so the tree censused is the tree under test."""
    package = Path(_archive().__file__).resolve().parents[2]
    assert package.name == "defender", f"the census root is not the package: {package}"
    out: dict[str, str] = {}
    for root in (*_CODE_ROOTS, *_OWNER_MODULES):
        base = package / root
        files = [base] if base.is_file() else sorted(base.rglob("*.py"))
        for path in files:
            out[path.relative_to(package).as_posix()] = path.read_text(encoding="utf-8")
    assert _ARCHIVE_MODULE in out, f"the census never saw {_ARCHIVE_MODULE}: {sorted(out)[:5]}"
    assert _OWNER_MODULE in out, f"the census never saw {_OWNER_MODULE}"
    assert _LAYOUT_MODULE in out, (
        f"the census never saw the run-layout owner {_LAYOUT_MODULE} — a stale owner path drops "
        "it from the census silently")
    return out


def _folded_string(node: ast.AST) -> str | None:
    """The string a node denotes when it is a constant expression, else `None`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded_string(node.left), _folded_string(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded_string(v) for v in node.values]
        return None if any(p is None for p in parts) else "".join(parts)
    return None


def _census(source: str, path: str) -> tuple[set[str], set[str]]:
    """`(code strings, bound names)` for one module, off ONE parse."""
    tree = ast.parse(source, filename=path)
    docstrings = {
        id(node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    strings: set[str] = set()
    bound: set[str] = set()
    for node in ast.walk(tree):
        if id(node) in docstrings:
            continue
        if (folded := _folded_string(node)) is not None:
            strings.add(folded)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)
    return strings, bound


def _string_constants(source: str, path: str) -> set[str]:
    """Every code string a module's AST denotes as a constant expression — see `_census`."""
    return _census(source, path)[0]


# ---------------------------------------------------------------------------------------
# Decision 2 — the derived accessors: one home, public names, the same behaviour
# ---------------------------------------------------------------------------------------

#: The `family.py` private `render.py` imported across the module line, and the two
#: `render.py` privates the page needs — each as `(private spelling, public spelling)`. The
#: overlay and holding-system accessors (`staged_patterns`, `world_pattern`, `own_h_rows`) and
#: the review join retired with #1224.
_MOVED = (
    ("_raw_manifest", "raw_manifest"),
    ("_leads_by_id", "leads_by_id"),
    ("_lead_chain", "lead_chain"),
)


def test_the_input_builders_leads_view_is_what_family_lead_chain_answers(tmp_path):
    """The per-lead chain the judge is SHOWN is the chain `family.lead_chain` computes ."""
    family = _family()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    world_dir = ep / "worlds" / "b"
    # #1234 A12/A21: b's own calls have b's host-written ids (`<token>/<n>`, past the served
    # row's `/0`) — a row with no id of the run is an inherited pre-branch row, and one no other
    # world's table shares makes b's table refused as edited. #1255 G4/G6: the ids are not on
    # the rows; b's host-only call-join record names them by each row's `(lead_id, seq)`.
    token = J.world_token("b")
    rows = [
        {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "query",
         "query_id": "q1", "params": {"index": "logs-*"}, "payload_digest": "d1"},
        {"lead_id": "l-001", "seq": 1, "system": "elastic", "verb": "query",
         "query_id": "q2", "params": {"index": "logs-2"}, "payload_digest": "d2"},
    ]
    _write_issued(world_dir, rows)
    J.write_call_join(world_dir, [J.call_join_entry(r["lead_id"], r["seq"], f"{token}/{n}")
                                  for n, r in enumerate(rows, start=1)])
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    base, _src = J.runs_base(tmp_path)

    shown = _render().render(ep, "b").focus.leads
    facts = family.read_world_facts(J.mod("_io").bind(ep), "b", episode_token=J.EPISODE_TOKEN)
    expected = family.lead_chain(_world(ep, "b"), "l-001", facts.resolutions_by_lead,
                                 leads=family.leads_by_id(world_dir))

    assert expected["goal"] == "find the pivot", "the fixture's lead file was not read"
    assert expected["payload"] == ["d1", "d2"], "the fixture's queries were not read"
    assert shown["l-001"] == expected, (
        "the judge is shown a per-lead chain that differs from family.lead_chain's over the "
        f"same world:\n{shown['l-001']}\n!=\n{expected}")


def test_leads_by_id_is_the_canonical_surface_indexed_once(tmp_path):
    """`leads_by_id(world_dir)` is `lead_repository.joined` over the archived world, keyed by lead
    id ."""
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    rows = [
        {"lead_id": "l-001", "seq": 2, "query_id": "q2", "params": {"index": "logs-2"},
         "payload_digest": "d2"},
        {"lead_id": "l-001", "seq": 1, "query_id": "q1", "params": {"index": "logs-*"},
         "payload_digest": "d1"},
        {"lead_id": "l-001", "seq": 3, "query_id": "∅.above-repeat-guard", "params": {},
         "payload_digest": "dx"},
    ]
    table = _write_issued(world_dir, rows)
    for lid, goal in (("l-001", "find the pivot"), ("l-002", "queryless")):
        (world_dir / "gather_raw" / f"{lid}.lead.json").write_text(
            json.dumps({"lead_id": lid, "goal": goal}), encoding="utf-8")

    by_id = family.leads_by_id(world_dir)

    assert [q.query_id for q in by_id["l-001"].queries] == ["q1", "q2"], (
        "the sentinel reached the issued queries, or seq order was lost")
    assert [q.query_id for q in by_id["l-001"].sentinels] == ["∅.above-repeat-guard"]
    assert (by_id["l-002"].goal, by_id["l-002"].queries) == ("queryless", [])

    outside = tmp_path / "planted.jsonl"
    outside.write_text(table.read_text(encoding="utf-8"), encoding="utf-8")
    table.unlink()
    table.symlink_to(outside)
    linked = family.leads_by_id(world_dir)
    assert {lid: lead.goal for lid, lead in linked.items()} == {
        "l-001": "find the pivot", "l-002": "queryless"}, (
        "a link at the table cost the leads their goals — the two halves are refused "
        "separately")
    assert all(not lead.queries for lead in linked.values()), (
        "a symlink at the queries table's name was followed and its target's rows read as "
        "this world's issued queries")


def test_lead_chain_joins_goal_params_payload_summary_rows_and_resolutions_per_lead(tmp_path):
    """`lead_chain(world, lead_id, resolutions_by_lead, *, leads=...)` ."""
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
    _write_issued(world_dir, rows)
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    resolutions = {"l-001": [{"before": "open", "after": "held"}]}
    by_id = family.leads_by_id(world_dir)

    chain = family.lead_chain(_world(ep, "b"), "l-001", resolutions, leads=by_id)

    assert chain["goal"] == "find the pivot"
    assert chain["params"] == {"index": "logs-*"}, "params is not the FIRST issued query's"
    assert chain["payload"] == ["d1", "d2"]
    assert chain["summary"] == (world_dir / "gather_summaries" / "l-001.md").read_text(
        encoding="utf-8")
    assert "document_rows" not in chain, "the raw rows are back in the chain"
    assert chain["resolutions"] == resolutions["l-001"]

    bare = family.lead_chain(_world(ep, "b"), "l-002", resolutions, leads=by_id)
    assert (bare["goal"], bare["summary"], bare["resolutions"]) == (None, None, [])
    assert bare["payload"] == ["d3"], "a lead with queries but no lead file lost its payload"


def test_lead_chain_never_reads_outside_the_graded_world_for_a_traversing_lead_id(tmp_path):
    """A lead id is MODEL-authored text that becomes a path. One that would read outside the graded
    world reads nothing — not the sibling's lead file, not the sibling's summary."""
    family = _family()
    ep = J.accepted_episode(tmp_path)
    b_dir, c_dir = ep / "worlds" / "b", ep / "worlds" / "c"
    (b_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "OWN GOAL"}), encoding="utf-8")
    (c_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "SIBLING GOAL"}), encoding="utf-8")
    sibling_summary = (c_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "world c" in sibling_summary, "the fixture's sibling summary does not name world c"

    by_id = family.leads_by_id(b_dir)
    world_b = _world(ep, "b")
    honest = family.lead_chain(world_b, "l-001", {}, leads=by_id)
    leaked_goal = family.lead_chain(world_b, "../../c/gather_raw/l-001", {}, leads=by_id)
    leaked_summary = family.lead_chain(world_b, "../../c/gather_summaries/l-001", {},
                                       leads=by_id)

    assert honest["goal"] == "OWN GOAL", "positive control: b's own lead file not read"
    assert "world b" in (honest["summary"] or ""), "positive control: b's own summary not read"
    assert leaked_goal["goal"] is None, (
        f"a traversing lead id read world c's lead file: {leaked_goal['goal']!r}")
    assert "world c" not in (leaked_summary["summary"] or ""), (
        "a traversing lead id read world c's gather summary into world b's chain")


def test_json_mapping_answers_a_mapping_and_none_for_everything_else(tmp_path):
    """`json_mapping(bound, name)` is the ONE tolerance policy for a JSON artifact."""
    family = _family()
    path = tmp_path / "artifact.json"
    bound = _io().bind(tmp_path)

    path.write_text(json.dumps({"alert_id": "a-1"}), encoding="utf-8")
    assert family.json_mapping(bound, "artifact.json") == {"alert_id": "a-1"}
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert family.json_mapping(bound, "artifact.json") is None, "a JSON list was answered as a mapping"
    path.write_text("{not json", encoding="utf-8")
    assert family.json_mapping(bound, "artifact.json") is None, "a corrupt document raised or was answered"
    assert family.json_mapping(bound, "absent.json") is None


def test_json_mapping_refuses_a_planted_link_and_reads_the_same_bytes_as_a_regular_file(
        tmp_path):
    """`json_mapping` is ONE home for the link policy as well as the tolerance policy."""
    family, render = _family(), _render()
    outside = tmp_path / "planted.json"
    outside.write_text(json.dumps({"commit": "a" * 40, "dirty": False}), encoding="utf-8")
    regular = tmp_path / "artifact.json"
    regular.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    bound = _io().bind(tmp_path)
    assert family.json_mapping(bound, "artifact.json") == {"commit": "a" * 40, "dirty": False}, (
        "positive control: a regular file did not read")

    linked = tmp_path / "linked.json"
    linked.symlink_to(outside)
    assert family.json_mapping(bound, "linked.json") is None, "a symlink at the artifact's name was followed"

    ep = J.accepted_episode(tmp_path)
    stamp = ep / "worlds" / "b" / "provenance.json"
    stamp.unlink()
    stamp.symlink_to(outside)
    episode = _io().bind(ep)
    assert render._read_provenance(episode.under("worlds/b")) == {}, (
        "a planted link at provenance.json handed the pass the planted commit")
    (ep / "worlds" / "b").rename(ep / "worlds" / "b-real")
    (ep / "worlds" / "b-real" / "provenance.json").unlink()
    (ep / "worlds" / "b-real" / "provenance.json").write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    (ep / "worlds" / "b").symlink_to(ep / "worlds" / "b-real")
    assert render._read_provenance(episode.under("worlds/b")) == {}, (
        "a planted link at worlds/<X> handed the pass the planted commit")


def test_lead_chain_refuses_a_planted_link_at_the_gather_raw_directory(tmp_path):
    """The lead file is screened at the DIRECTORY as well as the leaf, and the screen is the
    surface's own."""
    family = _family()
    ep = J.accepted_episode(tmp_path)
    world_dir = ep / "worlds" / "b"
    (world_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "find the pivot"}), encoding="utf-8")
    chain = family.lead_chain(_world(ep, "b"), "l-001", {}, leads=family.leads_by_id(world_dir))
    assert chain["goal"] == "find the pivot", "positive control: the real lead file was not read"

    outside = tmp_path / "planted-gather_raw"
    outside.mkdir()
    (outside / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "goal": "SIBLING GOAL"}), encoding="utf-8")
    import shutil
    shutil.rmtree(world_dir / "gather_raw")
    (world_dir / "gather_raw").symlink_to(outside, target_is_directory=True)

    chain = family.lead_chain(_world(ep, "b"), "l-001", {}, leads=family.leads_by_id(world_dir))
    assert chain["goal"] is None, (
        "a link planted at gather_raw/ was followed to another tree's lead file")


def test_raw_manifest_reads_the_screened_manifest_and_refuses_a_link_or_a_non_mapping(tmp_path):
    """`raw_manifest(episode_dir)` is the judge's own screened read of `family.yaml`: the document
    as a mapping, or this design's refusal."""
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
    """`judge.read_grade(episode_dir)` is the ONE reader of `judge.yaml`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    read_grade = J.sym("learning.judge", "read_grade")
    assert read_grade(ep) is None, "an ungraded episode read as a grade"

    live = _grade(ep, tmp_path)
    stored = read_grade(ep)
    again = _grade(ep, tmp_path)

    assert stored is not None
    for field in ("worlds", "family", "user", "dispositions"):
        assert getattr(stored, field) == getattr(live, field), (
            f"read_grade's {field!r} differs from the pass that wrote it")
        assert getattr(again, field) == getattr(stored, field), (
            f"grade_episode's existing-record path and read_grade disagree on {field!r}")


def test_read_grade_refuses_a_planted_link_a_non_mapping_and_a_torn_record(tmp_path):
    """The idempotency record is read through the screened read AND the pass's own conversion."""
    read_grade, refused = J.sym("learning.judge", "read_grade"), _refused()
    ep = J.accepted_episode(tmp_path)
    record = ep / "judge.yaml"
    outside = tmp_path / "planted-judge.yaml"
    outside.write_text(yaml.safe_dump(
        {"worlds": [{"world": "b", "bucket": None}], "validity": "usable"}),
        encoding="utf-8")

    record.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    assert read_grade(ep).validity == "usable", "positive control: a regular record"

    record.unlink()
    record.symlink_to(outside)
    with pytest.raises(refused):
        read_grade(ep)

    record.unlink()
    record.write_text("- not\n- a grade\n", encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)

    record.write_text("worlds: [\n  {world: b", encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)


def test_read_grade_reads_back_a_not_graded_stamp(tmp_path):
    """An episode the pass declined to grade leaves a `not_graded` stamp, and the reader hands it
    back as one ."""
    read_grade = J.sym("learning.judge", "read_grade")
    skipped = J.accepted_episode(tmp_path, outcome="refused")
    graded = J.accepted_episode(tmp_path / "graded")

    _grade(skipped, tmp_path)
    _grade(graded, tmp_path)

    stamp = read_grade(skipped)
    assert stamp.not_graded is not None, "the not-graded stamp did not read back"
    assert stamp.not_graded.outcome == "refused", repr(stamp.not_graded)
    assert read_grade(graded).not_graded is None, "positive control: a graded episode"


@pytest.mark.parametrize("damage", [
    pytest.param({"dispositions": 5}, id="scalar-for-list"),
    pytest.param({"draws": 5}, id="scalar-for-mapping"),
    pytest.param({"enqueued_to": None}, id="null-for-str"),
    pytest.param({"enqueued_rows": "3"}, id="numeric-text-for-int"),
    pytest.param({"worlds": [{"bucket": None}]}, id="row-naming-no-world"),
    pytest.param({"not_graded": {}}, id="empty-stamp"),
    pytest.param({"not_graded": "yes"}, id="non-mapping-stamp"),
    pytest.param({"not_graded": {"outcome": "refused", "reason": "x"},
                  "dispositions": 5}, id="damaged-stamp"),
    # A YAML mapping may key on `1:` — splatted as keywords that is `TypeError: keywords must
    # be strings` out of the constructor, a class no handler on the path converts.
    pytest.param({1: "planted"}, id="non-string-key"),
])
def test_a_record_of_the_wrong_shape_is_refused_not_defaulted_and_not_re_graded(
        tmp_path, damage):
    """The record is validated against `EpisodeGrade`'s own schema, strictly, and one that fails is
    `JudgeRefused` ."""
    read_grade, refused = J.sym("learning.judge", "read_grade"), _refused()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    sound = {"worlds": [{"world": "b", "bucket": None}], "validity": "usable"}
    record = ep / "judge.yaml"

    record.write_text(yaml.safe_dump(sound), encoding="utf-8")
    assert read_grade(ep).validity == "usable", "positive control: the sound record"

    planted = yaml.safe_dump({**sound, **damage})
    record.write_text(planted, encoding="utf-8")
    with pytest.raises(refused):
        read_grade(ep)
    with pytest.raises(refused):
        _grade(ep, tmp_path)
    assert record.read_text(encoding="utf-8") == planted, (
        "the pass re-graded past a record it could not read, replacing the planted file")


def test_draws_on_disk_skips_a_link_planted_at_a_draws_name(tmp_path):
    """The one reader of the draw files reads each leaf through the screened read, like every other
    reader of the episode tree."""
    enqueue = J.mod("learning.judge.enqueue")
    owner = J.mod("_episode_paths")
    # `draws_on_disk` now takes the episode-root view plus the label (#1133 rev 2): the draws
    # dir it reads is `worlds/<label>/judge`, derived from the episode root, never handed in
    # directly as a path.
    episode_dir = tmp_path / "ep"
    label = "b"
    draw_dir = owner.EpisodePaths(episode_dir).world(label).draws
    draw_dir.mkdir(parents=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("findings: [{bucket: planted}]\n", encoding="utf-8")
    (draw_dir / "0.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "1.yaml").symlink_to(outside)

    with bind(episode_dir) as view:
        assert enqueue.draws_on_disk(view, label) == {0: {"findings": []}}, (
            "a link planted at a draw's name was followed: its target's findings were read "
            "back as this episode's draw")

    (draw_dir / "1.yaml").unlink()
    (draw_dir / "1.yaml").write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
    with bind(episode_dir) as view:
        assert sorted(enqueue.draws_on_disk(view, label)) == [0, 1], (
            "positive control: the same bytes as a regular file were not read")
