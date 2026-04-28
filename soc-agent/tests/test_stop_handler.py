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


# ---------------------------------------------------------------------------
# Post-mortem detached spawn
# ---------------------------------------------------------------------------


import json  # noqa: E402


class TestPostmortemSpawn:
    @pytest.fixture
    def runs_dir(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        runs.mkdir()
        sessions = runs / ".sessions"
        sessions.mkdir()
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))
        return runs

    def _seed_run(self, runs_dir, session_id, *, has_adhoc: bool):
        run_id = "run-" + session_id
        run_dir = runs_dir / run_id
        run_dir.mkdir()
        # Map session → run dir via the session-anchored convention.
        session_path = runs_dir / ".sessions" / f"{session_id}.json"
        session_path.write_text(json.dumps({"run_dir": str(run_dir)}))
        (run_dir / "meta.json").write_text(
            json.dumps({"signature_id": "wazuh-rule-100001", "salt": "x"})
        )
        if has_adhoc:
            fixtures = (
                Path(__file__).parent / "fixtures" / "postmortem_leads"
            )
            (run_dir / "investigation.md").write_text(
                (fixtures / "inv_with_adhoc.md").read_text()
            )
        else:
            # Empty narrative — has_ad_hoc_leads short-circuits to False.
            (run_dir / "investigation.md").write_text("# REPORT\n\n(empty)\n")
        return run_dir

    def test_spawns_when_run_has_adhoc(self, runs_dir, monkeypatch):
        run_dir = self._seed_run(runs_dir, "sess-adhoc", has_adhoc=True)
        captured: list[dict] = []

        def fake_popen(*args, **kwargs):
            captured.append({"args": args, "kwargs": kwargs})

            class _Proc:
                pid = 12345
            return _Proc()

        monkeypatch.setattr(stop_handler.subprocess, "Popen", fake_popen)
        stop_handler._maybe_spawn_postmortem({"session_id": "sess-adhoc"})

        assert len(captured) == 1
        argv = captured[0]["args"][0]
        assert argv[0] == sys.executable
        assert argv[1:5] == ["-m", "scripts.postmortem.leads.run", "--run-dir", str(run_dir)]
        # Out dir is under runs/postmortem/<run_id>/leads/
        out_dir_arg = argv[argv.index("--out-dir") + 1]
        assert out_dir_arg == str(runs_dir / "postmortem" / run_dir.name / "leads")
        # Detached
        assert captured[0]["kwargs"]["start_new_session"] is True
        # run.log gets created
        assert (Path(out_dir_arg) / "run.log").exists()

    def test_skips_when_no_adhoc_leads(self, runs_dir, monkeypatch):
        self._seed_run(runs_dir, "sess-clean", has_adhoc=False)
        called = []
        monkeypatch.setattr(
            stop_handler.subprocess, "Popen",
            lambda *a, **kw: called.append(("popen", a, kw)),
        )
        stop_handler._maybe_spawn_postmortem({"session_id": "sess-clean"})
        assert called == []

    def test_skips_when_session_id_missing(self, runs_dir, monkeypatch):
        called = []
        monkeypatch.setattr(
            stop_handler.subprocess, "Popen",
            lambda *a, **kw: called.append(("popen", a, kw)),
        )
        stop_handler._maybe_spawn_postmortem({})
        assert called == []

    def test_skips_when_meta_json_absent(self, runs_dir, monkeypatch):
        run_dir = self._seed_run(runs_dir, "sess-no-meta", has_adhoc=True)
        (run_dir / "meta.json").unlink()
        called = []
        monkeypatch.setattr(
            stop_handler.subprocess, "Popen",
            lambda *a, **kw: called.append(("popen", a, kw)),
        )
        stop_handler._maybe_spawn_postmortem({"session_id": "sess-no-meta"})
        assert called == []

    def test_popen_failure_does_not_crash_handler(self, runs_dir, monkeypatch):
        self._seed_run(runs_dir, "sess-popen-fail", has_adhoc=True)

        def boom(*a, **kw):
            raise OSError("popen unavailable")

        monkeypatch.setattr(stop_handler.subprocess, "Popen", boom)
        # _run_step wraps it; should not raise, must still log.
        stop_handler._run_step(
            "postmortem_leads",
            stop_handler._maybe_spawn_postmortem,
            {"session_id": "sess-popen-fail"},
        )
