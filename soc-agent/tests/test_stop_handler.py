"""Tests for hooks.scripts.stop_handler.

Focuses on step isolation: a crash in one step must not prevent subsequent
steps from running. The step-ordering guarantee is the entire reason
stop_handler.py exists (vs two separate Hook registrations whose ordering
would be harness-defined).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts import stop_handler


# ---------------------------------------------------------------------------
# _run_step unit tests
# ---------------------------------------------------------------------------


class TestRunStep:
    def test_calls_func_with_payload(self):
        calls = []

        def _track(payload):
            calls.append(payload)

        stop_handler._run_step("test", _track, {"x": 1})
        assert calls == [{"x": 1}]

    def test_swallows_exception(self):
        """_run_step must never propagate an exception out."""

        def _bad(payload):
            raise RuntimeError("boom")

        # Must not raise
        stop_handler._run_step("test", _bad, {})

    def test_exception_printed_to_stderr(self, capsys):
        def _bad(payload):
            raise ValueError("oops")

        stop_handler._run_step("my-step", _bad, {})
        captured = capsys.readouterr()
        assert "my-step" in captured.err
        assert "oops" in captured.err


# ---------------------------------------------------------------------------
# Step isolation: crash in step N must not prevent step N+1
# ---------------------------------------------------------------------------


class TestStepIsolation:
    def test_summary_failure_does_not_prevent_action(self, monkeypatch):
        """If investigation_summary.main raises, close_ticket_action.main still runs."""
        from hooks.scripts import close_ticket_action, investigation_summary

        raised = []
        dispatched = []

        def _bad_summary(payload):
            raised.append(True)
            raise RuntimeError("summary exploded")

        def _track_action(payload):
            dispatched.append(payload)

        monkeypatch.setattr(investigation_summary, "main", _bad_summary)
        monkeypatch.setattr(close_ticket_action, "main", _track_action)

        payload = {"session_id": "test-isolation"}
        stop_handler._run_step("investigation_summary", investigation_summary.main, payload)
        stop_handler._run_step("close_ticket_action", close_ticket_action.main, payload)

        assert len(raised) == 1, "summary should have been called"
        assert len(dispatched) == 1, "action must run even after summary crash"
        assert dispatched[0] == payload

    def test_action_failure_does_not_raise(self, monkeypatch):
        """If close_ticket_action.main raises, _run_step swallows it."""
        from hooks.scripts import close_ticket_action

        def _bad_action(payload):
            raise RuntimeError("action exploded")

        monkeypatch.setattr(close_ticket_action, "main", _bad_action)

        # Must not raise
        stop_handler._run_step("close_ticket_action", close_ticket_action.main, {})

    def test_both_steps_called_on_happy_path(self, monkeypatch):
        from hooks.scripts import close_ticket_action, investigation_summary

        order = []

        monkeypatch.setattr(investigation_summary, "main", lambda p: order.append("summary"))
        monkeypatch.setattr(close_ticket_action, "main", lambda p: order.append("action"))

        payload = {"session_id": "sess-ok"}
        stop_handler._run_step("investigation_summary", investigation_summary.main, payload)
        stop_handler._run_step("close_ticket_action", close_ticket_action.main, payload)

        assert order == ["summary", "action"]
