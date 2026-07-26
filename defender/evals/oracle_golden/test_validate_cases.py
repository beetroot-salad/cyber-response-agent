"""Pins for the case linter's rules (#711).

`validate_cases.py` checks SAMPLES; this checks the linter. The distinction
matters: the real cases are validated by running the tool, and these tests make
sure the tool would actually catch a violation rather than passing vacuously —
which is the failure mode a linter is most prone to.

Every case built here is synthetic and minimal. Nothing reads the committed
cases, so a change to the real suite cannot make these go green or red.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


VALIDATE = _load("oracle_golden_validate", GOLDEN_DIR / "validate_cases.py")
SCORE = _load("oracle_golden_score_v", GOLDEN_DIR / "score.py")


def _make_case(root: Path, case_id: str, **overrides) -> Path:
    """A minimal case that validates, before any perturbation."""
    case = root / case_id
    (case / "oracle_visible").mkdir(parents=True, exist_ok=True)
    (case / "scores").mkdir(parents=True, exist_ok=True)
    (case / "projections").mkdir(parents=True, exist_ok=True)

    manifest = {
        "case_id": case_id, "kind": "negative-control", "split": "dev",
        "unit": {"activity_family": "f", "host_pair": "a->b"},
        "capture_environment": "env-1",
    }
    manifest.update(overrides.pop("manifest", {}))
    expected = {"case_id": case_id, "kind": manifest["kind"],
                "leads": {"l-1": {"system": "elastic", "class": "0"}}}
    expected.update(overrides.pop("expected", {}))

    (case / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (case / "expected.yaml").write_text(yaml.safe_dump(expected), encoding="utf-8")
    (case / "oracle_visible" / "story.md").write_text(
        overrides.pop("story", "An engineer restarted a service on web-1.\n"),
        encoding="utf-8")
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-1", "goal": "g", "what_to_summarize": [],
                    "queries": []}) + "\n", encoding="utf-8")

    events = overrides.pop("events", [])
    proj = {"projections": [{"lead_id": "l-1", "events": events}]}
    (case / "projections" / "t.yaml").write_text(yaml.safe_dump(proj), encoding="utf-8")
    summary = SCORE.score_projection(expected, proj, "t.yaml")
    (case / "scores" / "t.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    for name, body in overrides.pop("extra_files", {}).items():
        (case / name).write_text(body, encoding="utf-8")
    return case


def _problems(root: Path) -> list[str]:
    by_id = {d.name: yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
             for d in root.iterdir() if (d / "manifest.yaml").is_file()}
    out = []
    for case_dir in sorted(d for d in root.iterdir() if d.is_dir()):
        out += VALIDATE.check_case(case_dir, by_id)
    return out


def test_a_well_formed_case_validates(tmp_path):
    """Without this, every assertion below could pass because everything fails."""
    _make_case(tmp_path, "case-a")
    assert _problems(tmp_path) == []


def test_a_missing_split_is_caught(tmp_path):
    _make_case(tmp_path, "case-a", manifest={"split": None})
    assert any("split must be dev|held-out" in p for p in _problems(tmp_path))


def test_a_missing_unit_is_caught(tmp_path):
    _make_case(tmp_path, "case-a", manifest={"unit": {"activity_family": "f"}})
    assert any("unit needs" in p for p in _problems(tmp_path))


def test_a_derived_case_on_the_other_side_of_the_split_is_caught(tmp_path):
    """The failure: a derived case reuses its base's envelope byte-for-byte, so a
    differing split puts one capture on both sides of the boundary."""
    _make_case(tmp_path, "case-a")
    _make_case(tmp_path, "mut-a", manifest={"split": "held-out", "base_case": "case-a"})
    assert any("split 'held-out' != base case-a split 'dev'" in p
               for p in _problems(tmp_path))


def test_a_derived_case_claiming_its_own_unit_is_caught(tmp_path):
    """It is the base's unit shown again, not a second independent trial."""
    _make_case(tmp_path, "case-a")
    _make_case(tmp_path, "mut-a", manifest={
        "base_case": "case-a", "unit": {"activity_family": "other", "host_pair": "c->d"}})
    assert any("unit != base" in p for p in _problems(tmp_path))


def test_a_story_stating_the_expected_result_is_caught(tmp_path):
    """The one leak the hidden/visible split cannot catch."""
    _make_case(tmp_path, "case-a",
               story="This is a negative control, so every lead is 0.\n")
    assert any("leaks the evaluation frame" in p for p in _problems(tmp_path))


def test_a_stale_score_artifact_is_caught(tmp_path):
    case = _make_case(tmp_path, "case-a")
    stored = json.loads((case / "scores" / "t.json").read_text(encoding="utf-8"))
    stored["class_agreement"] = "99/99"
    (case / "scores" / "t.json").write_text(json.dumps(stored, indent=2) + "\n",
                                            encoding="utf-8")
    assert any("is stale" in p for p in _problems(tmp_path))


def test_an_error_with_no_cause_code_is_caught(tmp_path):
    """AC 7 in the direction people expect: a disagreement must be explained."""
    _make_case(tmp_path, "case-a", expected={
        "leads": {"l-1": {"system": "elastic", "class": "+event"}}}, events=[])
    assert any("but no scores/t.causes.yaml" in p for p in _problems(tmp_path))


def test_a_cause_code_for_a_clean_lead_is_caught(tmp_path):
    """AC 7 in the other direction, which is the one that rots: a sidecar left
    behind after a projection improved would keep asserting a failure that no
    longer happens."""
    _make_case(tmp_path, "case-a", extra_files={
        "scores/t.causes.yaml": yaml.safe_dump(
            {"causes": {"l-1": {"cause": "C-INTENT-SCOPE"}}})})
    assert any("no errors" in p for p in _problems(tmp_path))


def test_a_cause_entry_without_a_code_is_caught(tmp_path):
    _make_case(tmp_path, "case-a",
               expected={"leads": {"l-1": {"system": "elastic", "class": "+event"}}},
               events=[], extra_files={
                   "scores/t.causes.yaml": yaml.safe_dump({"causes": {"l-1": {"note": "x"}}})})
    assert any("no cause code" in p for p in _problems(tmp_path))


# --------------------------------------------------------------------------
# the held-out ledger (AC 2)
# --------------------------------------------------------------------------

def _ledger(tmp_path: Path, entries: list[dict]) -> None:
    VALIDATE.LEDGER = tmp_path / "ledger.yaml"
    VALIDATE.LEDGER.write_text(yaml.safe_dump({"entries": entries}), encoding="utf-8")


def test_a_held_out_score_with_no_ledger_entry_is_caught(tmp_path, monkeypatch):
    case = _make_case(tmp_path, "case-a", manifest={"split": "held-out"})
    monkeypatch.setattr(VALIDATE, "LEDGER", tmp_path / "ledger.yaml")
    (tmp_path / "ledger.yaml").write_text(yaml.safe_dump({"entries": []}), encoding="utf-8")
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))
    problems = VALIDATE.check_held_out_ledger([(case, manifest)])
    assert any("no ledger entry" in p for p in problems)


def test_a_rewritten_held_out_score_is_caught(tmp_path, monkeypatch):
    """The mechanism behind "results appended and never overwritten": a held-out
    run kept for a second, better attempt under the same tag no longer matches
    its recorded hash."""
    case = _make_case(tmp_path, "case-a", manifest={"split": "held-out"})
    score_path = case / "scores" / "t.json"
    monkeypatch.setattr(VALIDATE, "LEDGER", tmp_path / "ledger.yaml")
    (tmp_path / "ledger.yaml").write_text(yaml.safe_dump({"entries": [
        {"case": "case-a", "tag": "t",
         "sha256": hashlib.sha256(score_path.read_bytes()).hexdigest()}]}),
        encoding="utf-8")
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))
    assert VALIDATE.check_held_out_ledger([(case, manifest)]) == []

    score_path.write_text(score_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    problems = VALIDATE.check_held_out_ledger([(case, manifest)])
    assert any("does not match its ledger hash" in p for p in problems)


def test_a_dev_case_needs_no_ledger_entry(tmp_path, monkeypatch):
    case = _make_case(tmp_path, "case-a")
    monkeypatch.setattr(VALIDATE, "LEDGER", tmp_path / "ledger.yaml")
    (tmp_path / "ledger.yaml").write_text(yaml.safe_dump({"entries": []}), encoding="utf-8")
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))
    assert VALIDATE.check_held_out_ledger([(case, manifest)]) == []


def test_the_replay_boundary_check_is_not_vacuous():
    """It asserts on the REAL replay.py, and the check itself guards against
    finding no literals at all."""
    assert VALIDATE.check_replay_boundary() == []
