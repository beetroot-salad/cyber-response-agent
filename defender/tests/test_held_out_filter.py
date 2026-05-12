"""Persist-stage filter — held-out runs must not feed _pending/ queues."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"
sys.path.insert(0, str(LEARNING_SRC))

import loop  # type: ignore[import-not-found]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "20260512T120000Z-case"
    d.mkdir()
    return d


def test_is_held_out_true(run_dir: Path) -> None:
    (run_dir / "ground_truth.yaml").write_text(
        "held_out: true\ndisposition: benign\nrationale: x\n"
    )
    assert loop.is_held_out(run_dir) is True


def test_is_held_out_false_when_flag_missing(run_dir: Path) -> None:
    # ground_truth file with disposition but no held_out key — should not
    # trigger the filter; the marker is explicit.
    (run_dir / "ground_truth.yaml").write_text(
        "disposition: benign\nrationale: x\n"
    )
    assert loop.is_held_out(run_dir) is False


def test_is_held_out_false_when_no_file(run_dir: Path) -> None:
    assert loop.is_held_out(run_dir) is False


def test_read_ground_truth_rejects_non_mapping(run_dir: Path) -> None:
    (run_dir / "ground_truth.yaml").write_text("- not\n- a\n- mapping\n")
    with pytest.raises(loop.LoopError):
        loop.read_ground_truth(run_dir)


def test_run_one_gate_short_circuits_before_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Patch run_one's pre-append helpers and verify the held-out gate fires
    before append_findings would have run.

    Strategy: monkeypatch every step from normalize through judge to return
    minimal valid outputs; then check that ``append_findings`` is NOT
    called when ground_truth.yaml carries ``held_out: true``.
    """
    calls = {"append": 0}

    def fake_append(*a, **kw):
        calls["append"] += 1
        return 0

    # Build a minimal run dir.
    run_dir = tmp_path / "case"
    run_dir.mkdir()
    (run_dir / "alert.json").write_text(json.dumps({"rule": {"id": "5710"}}))
    (run_dir / "report.md").write_text(
        "---\ncase_id: case\ndisposition: benign\nconfidence: high\n---\nbody\n"
    )
    (run_dir / "investigation.md").write_text("stub\n")
    (run_dir / "lead_sequence.yaml").write_text("entries: []\n")
    (run_dir / "ground_truth.yaml").write_text(
        "held_out: true\ndisposition: benign\nrationale: x\n"
    )

    # Patch the loop module's network-y / claude-spawning steps.
    monkeypatch.setattr(loop, "project_actor_input", lambda *a, **kw: None)
    monkeypatch.setattr(loop, "invoke_actor", lambda *a, **kw: "story body\n")
    monkeypatch.setattr(loop, "is_skip_story", lambda *_: False)
    monkeypatch.setattr(loop, "invoke_oracle", lambda *a, **kw: "- position: 0\n  events: []\n")
    monkeypatch.setattr(
        loop, "validate_oracle_doc", lambda *a, **kw: None
    )
    judge_yaml = (
        "outcome: caught\n"
        "defender_findings:\n"
        "  - type: detection-confirmed\n"
        "    subject_anchor: a\n"
        "    subject_topic: t\n"
        "    finding: n\n"
        "    citations: []\n"
    )
    monkeypatch.setattr(loop, "invoke_judge", lambda *a, **kw: judge_yaml)
    monkeypatch.setattr(
        loop, "validate_judge_doc",
        lambda doc: doc,
    )
    monkeypatch.setattr(loop, "assemble_exemplar_bundle",
                        lambda *a, **kw: "exemplars\n")
    monkeypatch.setattr(loop, "persist_run", lambda *a, **kw: None)
    monkeypatch.setattr(loop, "append_findings", fake_append)
    monkeypatch.setattr(loop, "RUNS_DIR", tmp_path / "lrun")

    rc = loop.run_one(run_dir)
    assert rc == 0
    assert calls["append"] == 0, "append_findings must not be called for held-out runs"
