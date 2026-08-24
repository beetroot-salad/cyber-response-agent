from __future__ import annotations


import pytest

from seam_harness.cli import main
from seam_harness.journal import RunJournal
from seam_harness.models import HarnessSpec
from seam_harness.orchestrator import ensure_model_credentials
from seam_harness.postmortem import build_postmortem, render_markdown


def test_fireworks_credential_is_checked(monkeypatch) -> None:
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="FIREWORKS_API_KEY"):
        ensure_model_credentials(
            HarnessSpec.model_validate(
                {"frame": {"title": "x", "task": "x", "product_intent": "x"}}
            ),
            test_model=False,
        )


def test_init_creates_a_runnable_spec(tmp_path) -> None:
    target = tmp_path / "task.json"
    assert (
        main(
            [
                "init",
                str(target),
                "--title",
                "My task",
                "--task",
                "Do the work",
                "--intent",
                "Produce the result",
                "--demand",
                "Preserve the invariant",
            ]
        )
        == 0
    )
    spec = HarnessSpec.model_validate_json(target.read_text(encoding="utf-8"))
    assert spec.frame.demands[0].id == "D1"
    assert spec.policy.root_model.endswith("/kimi-k3")


def test_postmortem_reports_failure_and_call_trace(tmp_path) -> None:
    journal = RunJournal.create(tmp_path, "failed run")
    journal.write_record(
        "00-input",
        "spec",
        {
            "intake": {
                "assessment": {
                    "readiness": "needs_clarification",
                    "derivations": [],
                    "assumptions": ["Assumed scope"],
                    "unresolved": ["Unknown owner"],
                    "clarification_questions": [
                        {
                            "question": "Who owns it?",
                            "why_it_matters": "Ownership changes the cut.",
                            "default_if_unanswered": None,
                        }
                    ],
                    "framing_notes": "A provisional frame.",
                },
                "generated_by_model": "test",
                "source_sha256": "abc",
                "elapsed_ms": 1,
                "usage": {},
            }
        },
    )
    journal.write_record(
        "01-call-inputs",
        "call-0001-planner",
        {
            "call_id": "call-0001-planner",
            "role": "planner",
            "model": "fireworks:accounts/fireworks/models/kimi-k3",
            "dependency_type": "PlannerDeps",
            "input_sha256": "abc",
            "context": {"frame": {"task": "x"}},
        },
    )
    journal.write_record(
        "02-call-errors",
        "call-0001-planner",
        {"type": "RuntimeError", "message": "provider unavailable"},
        metadata={
            "call_id": "call-0001-planner",
            "role": "planner",
            "model": "fireworks:accounts/fireworks/models/kimi-k3",
            "input_sha256": "abc",
        },
    )
    journal.write_record(
        "99-result",
        "failure",
        {"type": "RuntimeError", "message": "provider unavailable"},
    )
    journal.finish("failed")

    report = build_postmortem(journal)
    assert report["integrity"]["chain_valid"] is True
    assert report["calls"][0]["status"] == "failed"
    assert report["intake"]["readiness"] == "needs_clarification"
    markdown = render_markdown(report)
    assert "provider unavailable" in markdown
    assert "Who owns it?" in markdown
