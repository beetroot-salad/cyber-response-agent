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
        "capture_environment": "env-1", "ground_truth": "hand",
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

def _ledger(tmp_path: Path, entries: list[dict] | None = None) -> Path:
    """A throwaway ledger, passed in rather than patched — `check_held_out_ledger`
    takes its path as a parameter precisely so a test never has to reach into the
    module."""
    path = tmp_path / "ledger.yaml"
    path.write_text("# why this ledger exists\n" +
                    yaml.safe_dump({"entries": entries or []}), encoding="utf-8")
    return path


def test_a_held_out_score_with_no_ledger_entry_is_caught(tmp_path):
    case = _make_case(tmp_path, "case-a", manifest={"split": "held-out"})
    ledger = _ledger(tmp_path)
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))
    problems = VALIDATE.check_held_out_ledger([(case, manifest)], ledger)
    assert any("no ledger entry" in p for p in problems)


def test_a_rewritten_held_out_score_is_caught(tmp_path):
    """The mechanism behind "results appended and never overwritten": a held-out
    run kept for a second, better attempt under the same tag no longer matches
    its recorded hash."""
    case = _make_case(tmp_path, "case-a", manifest={"split": "held-out"})
    score_path = case / "scores" / "t.json"
    ledger = _ledger(tmp_path, [{"case": "case-a", "tag": "t",
                                 "sha256": hashlib.sha256(score_path.read_bytes()).hexdigest()}])
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))
    assert VALIDATE.check_held_out_ledger([(case, manifest)], ledger) == []

    score_path.write_text(score_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    problems = VALIDATE.check_held_out_ledger([(case, manifest)], ledger)
    assert any("does not match its ledger hash" in p for p in problems)


def test_a_dev_case_needs_no_ledger_entry(tmp_path):
    case = _make_case(tmp_path, "case-a")
    ledger = _ledger(tmp_path)
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))
    assert VALIDATE.check_held_out_ledger([(case, manifest)], ledger) == []


def test_the_replay_boundary_check_is_not_vacuous():
    """It asserts on the REAL replay.py, and the check itself guards against
    finding no literals at all."""
    assert VALIDATE.check_replay_boundary() == []


def test_a_ledgered_result_cannot_vanish_without_a_reason(tmp_path):
    """The failure this catches: a held-out score deleted because someone did not
    like the number. The ledger entry outlives the file, so its absence is loud."""
    ledger = _ledger(tmp_path, [{"case": "gone", "tag": "t", "sha256": "abc"}])
    problems = VALIDATE.check_held_out_ledger([], ledger)
    assert any("carries no `retired:` reason" in p for p in problems)


def test_a_retired_entry_may_have_no_file(tmp_path):
    """Retiring is how a DEFECTIVE case leaves the suite — #711 retired two whose
    stories contradicted themselves. The entry stays with its reason, so the
    result is recorded as retired rather than unmade."""
    ledger = _ledger(tmp_path, [{"case": "gone", "tag": "t", "sha256": "abc",
                                 "retired": "story named two different targets"}])
    assert VALIDATE.check_held_out_ledger([], ledger) == []


# --------------------------------------------------------------------------
# ground-truth provenance (#728 review): a case says how its labels were made,
# and a `generated` one must still follow from the generator
# --------------------------------------------------------------------------

def test_a_case_that_does_not_say_how_its_ground_truth_was_made_fails(tmp_path):
    """Not defaulted. An unmarked case reads as generated-and-verified whichever
    it is, and `check_derivation` would silently skip it."""
    case = _make_case(tmp_path, "case-1", manifest={"ground_truth": None})
    problems = VALIDATE.check_case(case, {"case-1": {}})
    assert any("ground_truth must be hand|generated" in p for p in problems)


def _generated_case(root: Path) -> Path:
    """A `generated` case whose committed expected.yaml matches the generator."""
    case = _make_case(root, "case-g", manifest={
        "kind": "observed", "ground_truth": "generated", "state_classes": {"cmdb": "0"}})
    (case / "hidden" / "observed").mkdir(parents=True, exist_ok=True)
    (case / "hidden" / "controls.yaml").write_text("{}\n", encoding="utf-8")
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-1", "queries": [
            {"query_id": "cmdb.host-trust-edges", "params": {"host": "web-1"}}]}) + "\n",
        encoding="utf-8")
    (case / "expected.yaml").write_text(yaml.safe_dump(
        {"case_id": "case-g", "kind": "observed",
         "leads": {"l-1": {"system": "cmdb", "class": "0", "template": "host-trust-edges"}}}),
        encoding="utf-8")
    return case


def test_a_generated_case_matching_its_generator_passes(tmp_path):
    """The gate must not fire on the case it is meant to allow, or every future
    capture arrives with a wall of overrides and they stop being read."""
    case = _generated_case(tmp_path)
    assert VALIDATE.check_derivation(
        case, yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8")),
        yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))) == []


def test_ground_truth_drifting_from_the_telemetry_fails_unless_declared(tmp_path):
    """The finding this gate exists for: case-005's `fields` diverged from the
    committed generator on 8 of 11 leads, only two of them recorded as
    deliberate, and nothing said so. A hand correction stays legal — it just has
    to be written down."""
    case = _generated_case(tmp_path)
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    expected["leads"]["l-1"]["class"] = "+event"          # the tool derives "0"
    manifest = yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8"))

    problems = VALIDATE.check_derivation(case, manifest, expected)
    assert any("no `overrides:` entry says why" in p for p in problems)

    expected["overrides"] = {"l-1": {"class": "hand-set from the environment"}}
    assert VALIDATE.check_derivation(case, manifest, expected) == []


def test_an_override_the_generator_has_caught_up_with_is_stale(tmp_path):
    """The direction that rots. A leftover override keeps asserting a
    disagreement that no longer exists, and silently licenses the next real one."""
    case = _generated_case(tmp_path)
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    expected["overrides"] = {"l-1": {"class": "was hand-set once"}}
    problems = VALIDATE.check_derivation(
        case, yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8")), expected)
    assert any("the generator now agrees" in p for p in problems)


def test_an_override_with_no_reason_is_not_a_declaration(tmp_path):
    case = _generated_case(tmp_path)
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    expected["leads"]["l-1"]["class"] = "+event"
    expected["overrides"] = {"l-1": {"class": "  "}}
    problems = VALIDATE.check_derivation(
        case, yaml.safe_load((case / "manifest.yaml").read_text(encoding="utf-8")), expected)
    assert any("carries no reason" in p for p in problems)
