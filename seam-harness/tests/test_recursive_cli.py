from __future__ import annotations

import json

import pytest
from pydantic_ai import models

from seam_harness.cli import main
from seam_harness.journal import RunJournal
from seam_harness.models import HarnessSpec, SourceEnvelope, TaskFrame
from seam_harness.recursive_models import RecursivePolicy
from seam_harness.workspace import normalize_relative_path, snapshot_workspace


def test_workspace_snapshot_is_utf8_content_addressed_and_contained(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "binary.bin").write_bytes(b"\x00not-text")
    (source / ".git").mkdir()
    (source / ".git" / "secret").write_text("ignored", encoding="utf-8")

    snapshot = snapshot_workspace(source, RecursivePolicy())

    assert [entry.path for entry in snapshot.entries] == ["module.py"]
    assert snapshot.documents(["./module.py"])[0].content == "VALUE = 1\n"
    with pytest.raises(ValueError, match="relative and contained"):
        normalize_relative_path("../outside.py")
    with pytest.raises(ValueError, match="relative and contained"):
        normalize_relative_path("/absolute.py")


def test_solve_cli_preserves_request_and_indexes_workspace(tmp_path) -> None:
    models.ALLOW_MODEL_REQUESTS = False
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "facts.txt").write_text("grounded fact\n", encoding="utf-8")
    spec = HarnessSpec(
        frame=TaskFrame(
            title="CLI recursive test",
            task="Produce an answer.",
            product_intent="Exercise recursive tasking.",
        ),
        source_envelope=SourceEnvelope(raw_request="The original natural request."),
    )
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(spec.model_dump_json(), encoding="utf-8")
    output = tmp_path / "answer.txt"
    runs = tmp_path / "runs"

    assert (
        main(
            [
                "solve",
                str(spec_path),
                "--execution",
                "recursive",
                "--workspace",
                str(workspace),
                "--output",
                str(output),
                "--runs-dir",
                str(runs),
                "--test-model",
            ]
        )
        == 0
    )

    assert output.read_text(encoding="utf-8").strip()
    run_dir = next(runs.iterdir())
    journal = RunJournal.open(run_dir)
    assert journal.verify() == []
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    planner_event = next(
        event
        for event in manifest["events"]
        if event["stage"] == "01-call-inputs"
        and event["metadata"].get("role") == "recursive_planner"
    )
    planner_context = json.loads(
        (run_dir / planner_event["path"]).read_text(encoding="utf-8")
    )["context"]
    assert planner_context["workspace_index"][0]["path"] == "facts.txt"
    assert planner_context["source_materials"][0]["id"] == "request"
    assert (
        planner_context["source_materials"][0]["content"]
        == "The original natural request."
    )
