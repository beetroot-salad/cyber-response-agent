"""Tree-level invariants for the oracle-calibration golden set (#693, #711).

What is pinned here is the CASE TREE, not the scorer: the files every case promises,
the identity a manifest claims, the one leak the hidden/visible split cannot catch, and
the provenance every committed score must carry. The scorer's own behaviour moved to
`tests/evals/test_score.py` when `score.py` stopped being pure — the judge runs inside
it now, so `test_every_checked_in_score_reproduces` pinned a function that no longer
exists.

What replaces that pin is `test_every_checked_in_score_names_the_judge_in_its_tag`. A
score is no longer reproducible by re-running it, so the artifact has to carry who
produced it: the tag names the resolved judge model, the effort, and a hash over both
prompts. Editing either prompt changes the hash and fails every committed score at once
— which is the intended cost of a prompt edit, not an accident.

`test_no_story_states_the_expected_result` guards the other direction: a story is an
oracle INPUT, and the seed negative control announced in its own story that a faithful
oracle "must therefore return `0` for every lead". The hidden/visible split cannot catch
an answer leaked inside oracle_visible/.
"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime
from pathlib import Path

import pytest
import yaml

DEFENDER_DIR = Path(__file__).resolve().parents[1]
GOLDEN_DIR = DEFENDER_DIR / "evals" / "oracle_golden"
CASES_DIR = GOLDEN_DIR / "cases"

sys.path.insert(0, str(DEFENDER_DIR.parent))

from defender.evals.oracle_golden import judge, score  # noqa: E402

CASE_DIRS = sorted(p for p in CASES_DIR.iterdir() if p.is_dir())


def test_there_are_cases_to_check():
    """Every sweep below would pass vacuously against an empty cases/ tree."""
    assert CASE_DIRS


#: `expected.yaml` stopped being a per-case requirement when the judge redesign landed
#: (#711 §9). It held HAND labels, which were the scoring contract; the contract is now
#: the judge's own measurement of the telemetry, and the surviving hand labels are the
#: label pass's calibration set — carried by the four seed cases and nothing else. A
#: recruited case has no hand labels by design, so requiring them of every case would
#: force someone to invent the answers the suite exists to measure.
CALIBRATION_FILE = "expected.yaml"


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_every_case_has_the_files_the_readme_promises(case_dir):
    for rel in ("manifest.yaml", "environment.yaml",
                "oracle_visible/story.md", "oracle_visible/leads.jsonl"):
        assert (case_dir / rel).is_file(), f"{case_dir.name} is missing {rel}"


def test_the_calibration_set_still_exists_somewhere():
    """`expected.yaml` is optional per case but must not vanish from the tree: it is
    what `audit_judge.py` calibrates the label pass against, and a calibration set of
    zero leads is not a calibration."""
    labelled = [d for d in CASE_DIRS if (d / CALIBRATION_FILE).is_file()]
    assert len(labelled) >= 4, f"only {len(labelled)} cases carry hand labels"


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_manifest_and_expected_agree_on_the_case_identity(case_dir):
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8"))
    assert manifest["case_id"] == case_dir.name
    if not (case_dir / CALIBRATION_FILE).is_file():
        pytest.skip("no hand labels — a recruited case is measured, not labelled")
    expected = yaml.safe_load((case_dir / CALIBRATION_FILE).read_text(encoding="utf-8"))
    assert expected["case_id"] == case_dir.name, "a copied labels file would score the wrong case"
    assert manifest["kind"] == expected["kind"]


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_an_observed_case_carries_the_hidden_ground_truth_it_was_labelled_from(case_dir):
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8"))
    if manifest["kind"] != "observed":
        pytest.skip("derived cases re-run the oracle over a base case's captured leads")
    assert (case_dir / "hidden" / "controls.yaml").is_file()
    assert list((case_dir / "hidden" / "observed").iterdir())


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_every_labelled_lead_has_an_oracle_visible_envelope(case_dir):
    if not (case_dir / CALIBRATION_FILE).is_file():
        pytest.skip("no hand labels — a recruited case is measured, not labelled")
    expected = yaml.safe_load((case_dir / CALIBRATION_FILE).read_text(encoding="utf-8"))
    rows = [json.loads(x) for x
            in (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8").splitlines()
            if x.strip()]
    assert {r["lead_id"] for r in rows} == set(expected["leads"])


# Vocabulary that only an eval author writes — the scoring frame, not the
# operation. A story mentioning any of it is telling the oracle what it is being
# tested on, or what to answer.
_EVAL_TELLS = ("oracle", "negative control", "golden", "projection", "every lead",
               "each lead", "expected result", "+event", "+noise", "-noise",
               "result class", "standard environment noise", "suppressed:")


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_no_story_states_the_expected_result(case_dir):
    """A story is an ORACLE INPUT — the one file the hidden/visible split cannot
    protect, because it is deliberately visible. The seed negative control's story
    announced that it WAS a negative control and that the oracle "must therefore
    return `0` for every lead", which is the scoring answer written into the
    prompt. Rationale belongs in expected.yaml / manifest.yaml, which the oracle
    never reads."""
    story = (case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8").lower()
    assert not [tell for tell in _EVAL_TELLS if tell in story], (
        f"{case_dir.name}/oracle_visible/story.md leaks the evaluation frame to the "
        f"oracle: {[t for t in _EVAL_TELLS if t in story]}")


# the committed scores — provenance, since they no longer reproduce

def _committed_scores():
    for case_dir in CASE_DIRS:
        for path in sorted((case_dir / "scores").glob("*.json")):
            yield case_dir, path


SCORE_FILES = list(_committed_scores())


@pytest.mark.parametrize(("case_dir", "score_path"), SCORE_FILES,
                         ids=lambda p: p.name)
def test_every_checked_in_score_names_the_judge_in_its_tag(case_dir, score_path):
    """§6: the judge runs at score time, so it is part of the tag. A score whose tag does
    not match the judge recorded inside it was filed under a judge that did not produce
    it — the failure two machines with different `JUDGE_MODEL` defaults would cause.

    This also fails EVERY committed score the moment either prompt is edited, because
    the tag carries a hash over both. That is the design's rule made mechanical: editing
    a prompt is a new tag requiring a full re-score, exactly like an oracle change."""
    doc = json.loads(score_path.read_text(encoding="utf-8"))
    assert doc["tag"] == score_path.stem, "the artifact disagrees with its own filename"
    recorded = doc["judge"]
    assert score_path.stem.endswith(
        judge.tag_suffix(recorded["model"], recorded["effort"])), (
        f"{score_path.name} was produced by {recorded['model']}/{recorded['effort']} at "
        f"prompts {recorded['prompts_sha8']}, but the current prompts hash to "
        f"{judge.prompts_sha8()} — re-score, do not rename")


@pytest.mark.parametrize(("case_dir", "score_path"), SCORE_FILES,
                         ids=lambda p: p.name)
def test_every_checked_in_score_carries_the_rows_the_reporter_reads(case_dir, score_path):
    """`report.py` slices on `delta_kind` and rates on `faithful`. A row missing either
    would be a case silently dropped from a headline."""
    doc = json.loads(score_path.read_text(encoding="utf-8"))
    if not doc["judged"]:
        assert doc["rows"] == []
        assert doc["why_unjudged"], "a case that contributes nothing must say why"
        return
    for row in doc["rows"]:
        assert row["delta_kind"] in judge.LABEL_KINDS, row
        assert row["faithful"] in (True, False, None), row
        assert row["cause"] is None or row["cause"] in (
            judge.CAUSES | score.MECHANICAL_CAUSES), row
        if row["faithful"] is None:
            assert row["undecidable_reason"], "an abstention must name what it lacked"


@pytest.mark.parametrize(("case_dir", "proj_path"),
                         [(d, p) for d in CASE_DIRS
                          for p in sorted((d / "projections").glob("*.yaml"))],
                         ids=lambda p: p.name)
def test_no_checked_in_projection_has_a_lead_set_mismatch(case_dir, proj_path):
    """The mechanical half of scoring, swept over the tree. A missing lead is not an
    empty one, and an all-quiet case is exactly where a truncated projection would pass
    unnoticed."""
    leads = [row["lead_id"] for row in judge.load_case_leads(case_dir)]
    proj = yaml.safe_load(proj_path.read_text(encoding="utf-8")) or {}
    preds, duplicates = score.load_predictions(proj)
    assert score.integrity(leads, preds, duplicates) == {
        "missing_leads": [], "unscored_leads": [], "duplicate_leads": []}


@pytest.mark.parametrize(("case_dir", "proj_path"),
                         [(d, p) for d in CASE_DIRS
                          for p in sorted((d / "projections").glob("*.yaml"))],
                         ids=lambda p: p.name)
def test_every_checked_in_projection_has_a_score(case_dir, proj_path):
    """A projection with no score is a model call that was paid for and never read."""
    tags = {json.loads(p.read_text(encoding="utf-8"))["projection"]
            for p in (case_dir / "scores").glob("*.json")}
    assert proj_path.name in tags, (
        f"{case_dir.name}/{proj_path.name} has no scores/ artifact — run score.py")


# no checked-in projection carries a YAML-typed instant (#951, O4)
#
# The containment checks read a projection's values as the text in the file, so what they
# compare against the author's literal is whatever the PRODUCER wrote. `yaml.safe_dump` quotes
# any string that would resolve as a timestamp, so in a dumped projection an unquoted
# instant can only be a `datetime` the producer had already parsed the model's text into —
# and re-spelled as `2026-07-25 07:48:37.065000+00:00`, which no author's `T…Z` literal will
# ever match. This sweep catches that producer at commit time. (A producer that wrote the
# model's raw text with an unquoted instant would trip it too; the checks read that correctly,
# and the fix would be to narrow this sweep, not to edit the model's output.) The author's
# side needs no sweep: `validate_cases.check_clause_text` refuses an unquoted clause entry.

PROJECTION_FILES = sorted(CASES_DIR.glob("*/projections/*.yaml"))


def _typed_instants(doc, path: str = "") -> list[str]:
    """Every place in a loaded document — keys included — that is a `date`/`datetime`."""
    if isinstance(doc, date | datetime):
        return [path or "<root>"]
    found: list[str] = []
    if isinstance(doc, dict):
        for key, value in doc.items():
            found += _typed_instants(key, f"{path}/<key {key!r}>")
            found += _typed_instants(value, f"{path}/{key}")
    elif isinstance(doc, list):
        for i, value in enumerate(doc):
            found += _typed_instants(value, f"{path}[{i}]")
    return found


def test_there_are_projections_to_scan():
    """The sweep below would pass vacuously over an empty glob."""
    assert len(PROJECTION_FILES) > 50


@pytest.mark.parametrize(("typed", "where"), [
    ({"a": date(2026, 7, 25)}, "/a"),
    ({"projections": [{"events": [{"@timestamp": datetime(2026, 7, 25, 7, 48)}]}]},
     "/projections[0]/events[0]/@timestamp"),
    ({datetime(2026, 7, 25, 7, 48): "x"}, "/<key datetime.datetime(2026, 7, 25, 7, 48)>"),
    ([[date(2026, 7, 25)]], "[0][0]"),
])
def test_the_typed_instant_walker_fires_on_a_synthetic_document(typed, where):
    """The tree sweep is green today (design C9: 0 typed values in 101 projections), so
    this proves its detector can fire — on a value, a nested value, a key, and inside a
    bare list — and that a quoted instant does not trip it."""
    assert _typed_instants(typed) == [where]
    assert _typed_instants(yaml.safe_load("a: '2026-07-25T07:48:37.065Z'\nb: 2026-07-25")) == ["/b"]
    assert _typed_instants(yaml.safe_load("a: '2026-07-25'\nb: [x, 22, ~]")) == []


@pytest.mark.parametrize("path", PROJECTION_FILES,
                         ids=lambda p: str(p.relative_to(CASES_DIR)))
def test_no_checked_in_projection_carries_a_yaml_typed_instant(path):
    """Under plain `yaml.safe_load`, no value (or key) anywhere in a committed projection
    is a `date`/`datetime` — see the block comment above for what that detects."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert _typed_instants(doc) == [], (
        f"{path.relative_to(CASES_DIR)} carries YAML-typed instant(s): a parse-then-dump "
        f"producer re-spelled the model's text, and the containment checks compare text")
