"""FP-direction loop integration: benign judge validation, direction-aware
findings append, environment-observation append, and the shared author gate."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"
sys.path.insert(0, str(LEARNING_SRC))

import author  # type: ignore[import-not-found]
import loop  # type: ignore[import-not-found]
import verify_forward  # type: ignore[import-not-found]


# --------------------------------------------------------------------------
# validate_judge_benign_doc
# --------------------------------------------------------------------------


def _valid_benign_doc() -> dict:
    return {
        "outcome": "survived",
        "outcome_rationale": "routine story consistent with all leads",
        "encounter_analysis": "lead by lead ...",
        "defender_findings": [
            {
                "type": "lead-set",
                "subject_anchor": "no-lead-exists",
                "subject_topic": "monitor-account authorization",
                "finding": "never grounded the authorization anchor",
                "citations": [],
            }
        ],
        "environment_observations": [
            {
                "subject": "monitoring-port-probe",
                "alert_rule_ids": ["v2-falco-suspicious-network-tool"],
                "entities": [
                    {"type": "process", "class": "nc"},
                    {"type": "socket", "class": "tcp"},
                ],
                "relevance_criteria": "nc -z probe from a container",
                "fact": "svc.monitoring runs the documented probe pattern",
                "citations": [],
            }
        ],
        "confidence": "moderate-high",
    }


def test_validate_benign_doc_accepts_valid() -> None:
    assert loop.validate_judge_benign_doc(_valid_benign_doc())


def test_validate_benign_doc_rejects_adversarial_outcome() -> None:
    doc = _valid_benign_doc()
    doc["outcome"] = "caught"  # adversarial enum, not benign
    with pytest.raises(loop.LoopError, match="outcome keyword"):
        loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_accepts_refuted_and_skip() -> None:
    doc = _valid_benign_doc()
    doc["outcome"] = "refuted"
    assert loop.validate_judge_benign_doc(doc)
    skip = {"outcome": "skip-passthrough", "outcome_rationale": "not ours",
            "defender_findings": []}
    assert loop.validate_judge_benign_doc(skip)


def test_validate_benign_doc_rejects_bad_finding_type() -> None:
    doc = _valid_benign_doc()
    doc["defender_findings"][0]["type"] = "detection-confirmed"  # adversarial-only
    with pytest.raises(loop.LoopError, match="not in"):
        loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_accepts_disposition_confirmed() -> None:
    doc = _valid_benign_doc()
    doc["defender_findings"][0]["type"] = "disposition-confirmed"
    assert loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_rejects_empty_rule_anchor() -> None:
    doc = _valid_benign_doc()
    doc["environment_observations"][0]["alert_rule_ids"] = []
    with pytest.raises(loop.LoopError, match="alert_rule_ids"):
        loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_rejects_malformed_entity_selector() -> None:
    doc = _valid_benign_doc()
    doc["environment_observations"][0]["entities"] = [{"type": "process"}]
    with pytest.raises(loop.LoopError, match="type, class"):
        loop.validate_judge_benign_doc(doc)


# --------------------------------------------------------------------------
# append_findings (direction-aware) + append_environment_observations
# --------------------------------------------------------------------------


@pytest.fixture
def loop_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect REPO_ROOT + queue files to tmp so appends stay isolated."""
    monkeypatch.setattr(loop, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(loop, "PENDING_DIR", tmp_path / "_pending")
    monkeypatch.setattr(loop, "PENDING_FILE", tmp_path / "_pending" / "findings.jsonl")
    monkeypatch.setattr(loop, "ENVIRONMENT_OBSERVATIONS_FILE",
                        tmp_path / "_pending" / "environment_observations.jsonl")
    monkeypatch.setattr(loop, "ENVIRONMENT_OBSERVATIONS_CONSUMED_FILE",
                        tmp_path / "_pending" / "environment_observations.consumed.jsonl")
    monkeypatch.setattr(loop, "ENVIRONMENT_OBSERVATIONS_LOCK_FILE",
                        tmp_path / "_pending" / ".environment.lock")
    lrd = tmp_path / "runs" / "case-1"
    lrd.mkdir(parents=True)
    return lrd


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def test_append_findings_benign_namespace_and_direction(loop_paths: Path) -> None:
    lrd = loop_paths
    doc = _valid_benign_doc()
    # add an audit-only finding that must be filtered out
    doc["defender_findings"].append({
        "type": "disposition-confirmed", "subject_anchor": "l-001",
        "subject_topic": "justified", "finding": "x", "citations": [],
    })
    n = loop.append_findings(doc, "case-1", "rule-x", lrd, direction="benign")
    assert n == 1  # disposition-confirmed filtered
    rows = _read_jsonl(loop.PENDING_FILE)
    assert len(rows) == 1
    assert rows[0]["finding_id"] == "case-1/benign/0"
    assert rows[0]["direction"] == "benign"
    assert rows[0]["judge_outcome"] == "survived"


def test_append_findings_adversarial_unchanged(loop_paths: Path) -> None:
    lrd = loop_paths
    doc = {
        "outcome": "survived",
        "defender_findings": [
            {"type": "lead-set", "subject_anchor": "no-lead-exists",
             "subject_topic": "t", "finding": "f", "citations": []},
            {"type": "detection-confirmed", "subject_anchor": "l-001",
             "subject_topic": "t", "finding": "f", "citations": []},
        ],
    }
    n = loop.append_findings(doc, "case-1", "rule-x", lrd)
    assert n == 1
    rows = _read_jsonl(loop.PENDING_FILE)
    assert rows[0]["finding_id"] == "case-1/0"  # no benign/ namespace
    assert rows[0]["direction"] == "adversarial"


def test_append_environment_observations(loop_paths: Path) -> None:
    lrd = loop_paths
    doc = _valid_benign_doc()
    n = loop.append_environment_observations(doc, "case-1", "rule-x", lrd)
    assert n == 1
    rows = _read_jsonl(loop.ENVIRONMENT_OBSERVATIONS_FILE)
    assert rows[0]["observation_id"] == "case-1/0"
    assert rows[0]["alert_rule_ids"] == ["v2-falco-suspicious-network-tool"]
    assert rows[0]["entities"] == [
        {"type": "process", "class": "nc"}, {"type": "socket", "class": "tcp"}]
    assert rows[0]["subject"] == "monitoring-port-probe"
    # idempotent re-append writes nothing new
    assert loop.append_environment_observations(doc, "case-1", "rule-x", lrd) == 0


def test_append_environment_observations_skip_passthrough(loop_paths: Path) -> None:
    doc = {"outcome": "skip-passthrough", "outcome_rationale": "x",
           "defender_findings": [], "environment_observations": []}
    assert loop.append_environment_observations(doc, "case-1", "rule-x", loop_paths) == 0


# --------------------------------------------------------------------------
# author.py direction-aware ground-truth gate
# --------------------------------------------------------------------------


def test_ground_truth_gate_direction_aware() -> None:
    # adversarial finding confirmed only on a benign disposition (confident FN)
    assert author._has_confident_ground_truth("adversarial", "benign")
    assert not author._has_confident_ground_truth("adversarial", "malicious")
    # benign finding confirmed only on a malicious disposition (confident FP)
    assert author._has_confident_ground_truth("benign", "malicious")
    assert not author._has_confident_ground_truth("benign", "benign")
    # inconclusive / unknown confirm neither
    assert not author._has_confident_ground_truth("adversarial", "inconclusive")
    assert not author._has_confident_ground_truth("benign", "inconclusive")
    assert not author._has_confident_ground_truth("benign", None)


def test_verifier_expected_disposition_direction_aware() -> None:
    # Adversarial lessons must PRESERVE the recorded (benign) call — pass it
    # through. Benign (FP) lessons exist to drive the agent OFF the recorded
    # `malicious` over-escalation toward `benign`, so the verifier must target
    # `benign`, not the recorded malicious (else every FP lesson is held BAD).
    assert verify_forward.expected_disposition("adversarial", "benign") == "benign"
    assert verify_forward.expected_disposition("benign", "malicious") == "benign"
    # Direction, not the recorded value, decides the benign target.
    assert verify_forward.expected_disposition("benign", "inconclusive") == "benign"


# --------------------------------------------------------------------------
# extract_case_entities — prologue (:V) parsing for benign-actor retrieval
# --------------------------------------------------------------------------


def test_extract_case_entities_emits_qualified_class_tokens(tmp_path: Path) -> None:
    """The dense `class` column is already `type:class`-qualified; emit it
    verbatim (no double-prefix) so it matches lessons_env_retrieve selectors."""
    inv = tmp_path / "investigation.md"
    inv.write_text(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|endpoint|endpoint:linux|web-04.prod|role=asset-server\n"
        "v-002|process|process:nc|nc[2188]|cmdline_via=shell\n"
        "v-003|socket|socket:tcp|10.20.7.118:9100|\n"
        "v-002|process|process:nc|nc[2190]|\n"  # dup type:class — de-duped
        "\n"
        ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-001|connected|v-002|v-003|2026-05-05T03:42:11Z|siem-event:wazuh|\n"
        "```\n"
    )
    # Each token is the retrieval's `type:class` input verbatim — a single
    # type prefix, never `process:process:nc`. Dup rows collapse.
    assert loop.extract_case_entities(inv) == "endpoint:linux,process:nc,socket:tcp"


def test_extract_case_entities_absent_block(tmp_path: Path) -> None:
    inv = tmp_path / "investigation.md"
    inv.write_text("```invlang\n:H hypothesize.hypotheses\n```\n")
    assert loop.extract_case_entities(inv) == ""
    assert loop.extract_case_entities(tmp_path / "missing.md") == ""
