from __future__ import annotations

import asyncio
import json

from pydantic_ai import models

from seam_harness.models import HarnessSpec, SourceEnvelope
from seam_harness.orchestrator import SeamHarness


def test_complete_workflow_with_test_model(tmp_path) -> None:
    models.ALLOW_MODEL_REQUESTS = False
    spec = HarnessSpec.model_validate_json(
        open("examples/essay/spec.json", encoding="utf-8").read()
    ).model_copy(
        update={
            "source_envelope": SourceEnvelope(
                raw_request="Original natural-language request"
            )
        }
    )
    result = asyncio.run(SeamHarness(spec, runs_dir=tmp_path, test_model=True).run())

    assert result.questioner_reports
    assert result.frozen_results
    assert result.audits
    assert result.adjudication.decision
    run_directory = tmp_path / result.run_id
    manifest = json.loads((run_directory / "manifest.json").read_text(encoding="utf-8"))
    questioner_input = next(
        event
        for event in manifest["events"]
        if event["stage"] == "01-call-inputs"
        and event["metadata"].get("role") == "questioner"
    )
    context = json.loads(
        (run_directory / questioner_input["path"]).read_text(encoding="utf-8")
    )["context"]
    assert context["source_envelope"]["raw_request"] == (
        "Original natural-language request"
    )
