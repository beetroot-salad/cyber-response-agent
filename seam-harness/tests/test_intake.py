from __future__ import annotations

import json

import pytest
from pydantic_ai import models

from seam_harness.cli import main
from seam_harness.journal import digest
from seam_harness.models import (
    HarnessSpec,
    IntakeAssessment,
    IntakeReadiness,
    IntakeRecord,
    SourceEnvelope,
    TaskFrame,
)


def test_intake_compiles_natural_request_and_preserves_source(tmp_path) -> None:
    models.ALLOW_MODEL_REQUESTS = False
    material = tmp_path / "notes.md"
    material.write_text("Observed behavior from the real system.", encoding="utf-8")
    target = tmp_path / "task.json"

    assert (
        main(
            [
                "intake",
                str(target),
                "--request",
                "Design a safe migration plan without losing active sessions.",
                "--title",
                "Session-safe migration",
                "--decision",
                "Downtime is not acceptable.",
                "--material",
                str(material),
                "--test-model",
            ]
        )
        == 0
    )

    spec = HarnessSpec.model_validate_json(target.read_text(encoding="utf-8"))
    assert spec.source_envelope is not None
    assert "active sessions" in spec.source_envelope.raw_request
    assert spec.source_envelope.materials[0].content.startswith("Observed behavior")
    assert spec.intake is not None
    assert spec.intake.generated_by_model == "test"
    assert spec.intake.assessment.readiness == IntakeReadiness.NEEDS_CLARIFICATION
    assert spec.intake.source_sha256
    assert spec.intake.frame_sha256

    spec.frame.title = "Edited after intake"
    target.write_text(spec.model_dump_json(), encoding="utf-8")
    with pytest.raises(SystemExit, match="Compiled frame changed"):
        main(
            [
                "run",
                str(target),
                "--test-model",
                "--runs-dir",
                str(tmp_path / "runs"),
            ]
        )


def test_run_rejects_unresolved_intake_without_explicit_override(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="x", task="x", product_intent="x"),
        source_envelope=SourceEnvelope(raw_request="Explore what x should become."),
        intake=IntakeRecord(
            assessment=IntakeAssessment(
                readiness=IntakeReadiness.EXPLORATORY,
                derivations=[],
                assumptions=[],
                unresolved=["The desired outcome is not stable."],
                clarification_questions=[],
                framing_notes="Keep this in discovery.",
            ),
            source_sha256="abc",
            frame_sha256="abc",
            generated_by_model="test",
            elapsed_ms=1,
            usage={},
        ),
    )
    spec.intake.source_sha256 = digest(spec.source_envelope)
    spec.intake.frame_sha256 = digest(spec.frame)
    target = tmp_path / "exploratory.json"
    target.write_text(spec.model_dump_json(), encoding="utf-8")

    with pytest.raises(SystemExit, match="Intake is exploratory"):
        main(["run", str(target), "--test-model", "--runs-dir", str(tmp_path)])


def test_intake_json_contains_no_api_credential(tmp_path, monkeypatch) -> None:
    models.ALLOW_MODEL_REQUESTS = False
    monkeypatch.setenv("FIREWORKS_API_KEY", "secret-that-must-not-be-written")
    target = tmp_path / "task.json"
    main(
        [
            "intake",
            str(target),
            "--request",
            "Produce a concise report.",
            "--test-model",
        ]
    )
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert "secret-that-must-not-be-written" not in json.dumps(payload)
