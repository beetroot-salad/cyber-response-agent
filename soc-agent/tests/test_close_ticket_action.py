"""Unit tests for hooks.scripts.close_ticket_action.

These exercise the deterministic precondition gate and the subprocess
dispatch path against the stub_ticket_cli.py reference connector. No LLM
calls, no network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts import close_ticket_action

STUB_CONNECTOR = "scripts/tools/stub_ticket_cli.py"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runs_dir(tmp_path, monkeypatch):
    """Isolated runs dir."""
    path = tmp_path / "runs"
    path.mkdir()
    monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(path))
    return path


def _make_run(
    runs_dir: Path,
    run_name: str = "run-001",
    signature_id: str = "test-sig",
    ticket_id: str = "SEC-42",
    status: str = "resolved",
    confidence: str = "high",
    matched_archetype: str = "monitoring-probe",
    disposition: str = "benign",
    include_archetype: bool = True,
    include_ticket: bool = True,
) -> Path:
    run_dir = runs_dir / run_name
    run_dir.mkdir()
    (run_dir / "meta.json").write_text(
        json.dumps(
            {
                "run_id": run_name,
                "signature_id": signature_id,
                "salt": "deadbeef",
                "created_at": "2026-04-14T10:00:00+00:00",
            }
        )
    )

    frontmatter_lines = [
        f"ticket_id: {ticket_id}" if include_ticket else "ticket_id:",
        f"signature_id: {signature_id}",
        f"status: {status}",
        f"disposition: {disposition}",
        f"confidence: {confidence}",
    ]
    if include_archetype:
        frontmatter_lines.append(f"matched_archetype: {matched_archetype}")
    frontmatter_lines.append("leads_pursued: 3")

    frontmatter = "\n".join(frontmatter_lines)
    (run_dir / "report.md").write_text(
        f"---\n{frontmatter}\n---\n\nbody\n"
    )
    return run_dir


def _write_permissions(
    monkeypatch,
    tmp_path: Path,
    signature_id: str,
    *,
    mode_default: str | None = "act",
    close_ticket_policy: str | None = "auto",
    other_permissions: dict | None = None,
):
    """Write a permissions.yaml under a soc-agent-root-like tree and
    monkeypatch both close_ticket_action and permissions modules so lookups
    resolve to it.
    """
    fake_root = tmp_path / "soc-agent-fake"
    perms_dir = fake_root / "config" / "signatures" / signature_id
    perms_dir.mkdir(parents=True, exist_ok=True)

    lines = []
    if mode_default is not None:
        lines.append("mode:")
        lines.append(f"  default: {mode_default}")
    if close_ticket_policy is not None or other_permissions is not None:
        lines.append("mitigation:")
        lines.append("  actions:")
        if close_ticket_policy is not None:
            lines.append(f"    close_ticket: {close_ticket_policy}")
        if other_permissions:
            for key, value in other_permissions.items():
                lines.append(f"    {key}: {value}")

    (perms_dir / "permissions.yaml").write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(close_ticket_action, "SOC_AGENT_ROOT", fake_root)
    return fake_root


def _write_actions_yaml(fake_root: Path, connector: str = STUB_CONNECTOR):
    """Write a config/actions.yaml inside fake_root that binds close_ticket."""
    config_dir = fake_root / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "actions.yaml").write_text(
        "schema_version: \"1.0\"\n"
        "actions:\n"
        "  close_ticket:\n"
        f"    connector: {connector}\n"
        "    required_env_vars: []\n"
    )


def _symlink_connector(fake_root: Path):
    """Mirror the real scripts/tools layout inside fake_root via symlink
    so subprocess dispatch can find stub_ticket_cli.py under the fake root.
    """
    fake_tools = fake_root / "scripts" / "tools"
    fake_tools.mkdir(parents=True, exist_ok=True)
    link = fake_tools / "stub_ticket_cli.py"
    real = SOC_AGENT_ROOT / "scripts" / "tools" / "stub_ticket_cli.py"
    if not link.exists():
        link.symlink_to(real)

    # The fake .claude-plugin/plugin.json lets _plugin_version() find something
    plugin_dir = fake_root / ".claude-plugin"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.json").write_text(json.dumps({"version": "3.4.0-test"}))


def _read_audit(runs_dir: Path) -> list[dict]:
    audit = runs_dir / "action_audit.jsonl"
    if not audit.exists():
        return []
    return [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]


def _make_session(runs_dir: Path, session_id: str, run_dir: Path, signature_id: str):
    sessions_dir = runs_dir / ".sessions"
    sessions_dir.mkdir(exist_ok=True)
    (sessions_dir / f"{session_id}.json").write_text(
        json.dumps({"run_dir": str(run_dir), "signature_id": signature_id})
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_dispatches_and_logs_success(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig")
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-happy", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-happy"})

        entries = _read_audit(runs_dir)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["status"] == "success"
        assert entry["action"] == "close_ticket"
        assert entry["ticket_id"] == "SEC-42"
        assert entry["signature_id"] == "test-sig"
        assert entry["connector"] == STUB_CONNECTOR
        assert entry["exit_code"] == 0
        assert entry["skip_reason"] is None
        # Stub writes its own log when --execute is passed
        stub_log = runs_dir / "stub_ticket_actions.jsonl"
        assert stub_log.exists()
        stub_entry = json.loads(stub_log.read_text().splitlines()[0])
        assert stub_entry["target"] == "SEC-42"
        assert stub_entry["dry_run"] is False


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------


class TestSkipCases:
    def test_recommend_mode_skips(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig")
        fake_root = _write_permissions(
            monkeypatch, tmp_path, "test-sig", mode_default="recommend"
        )
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-rec", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-rec"})

        entries = _read_audit(runs_dir)
        assert len(entries) == 1
        assert entries[0]["status"] == "skipped"
        assert entries[0]["skip_reason"] == "mode=recommend"
        assert not (runs_dir / "stub_ticket_actions.jsonl").exists()

    def test_action_not_enabled(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig")
        fake_root = _write_permissions(
            monkeypatch,
            tmp_path,
            "test-sig",
            mode_default="act",
            close_ticket_policy=None,
            other_permissions={"block_ip": "auto"},
        )
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-nop", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-nop"})

        entries = _read_audit(runs_dir)
        assert len(entries) == 1
        assert entries[0]["skip_reason"] == "action_not_enabled"

    def test_low_confidence_skips(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig", confidence="low")
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-low", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-low"})

        entries = _read_audit(runs_dir)
        assert entries[0]["skip_reason"] == "preconditions_unmet"

    def test_escalated_status_skips(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig", status="escalated")
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-esc", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-esc"})

        entries = _read_audit(runs_dir)
        assert entries[0]["skip_reason"] == "preconditions_unmet"

    def test_missing_archetype_skips(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig", include_archetype=False)
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-arch", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-arch"})

        entries = _read_audit(runs_dir)
        assert entries[0]["skip_reason"] == "preconditions_unmet"

    def test_missing_ticket_id_skips(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig", include_ticket=False)
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-tkt", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-tkt"})

        entries = _read_audit(runs_dir)
        assert entries[0]["skip_reason"] == "preconditions_unmet"

    def test_missing_actions_yaml(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig")
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        # Deliberately skip _write_actions_yaml
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-na", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-na"})

        entries = _read_audit(runs_dir)
        assert entries[0]["skip_reason"] == "no_connector_configured"


# ---------------------------------------------------------------------------
# Failure cases — hook still exits cleanly
# ---------------------------------------------------------------------------


class TestFailures:
    def test_connector_exits_nonzero(self, runs_dir, tmp_path, monkeypatch):
        """Point actions.yaml at a connector that exits 1; expect failure entry."""
        run_dir = _make_run(runs_dir, signature_id="test-sig")
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")

        broken = fake_root / "scripts" / "tools" / "broken_cli.py"
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "print('bad', file=sys.stderr)\n"
            "sys.exit(1)\n"
        )
        broken.chmod(0o755)

        (fake_root / "config").mkdir(exist_ok=True)
        (fake_root / "config" / "actions.yaml").write_text(
            "schema_version: \"1.0\"\n"
            "actions:\n"
            "  close_ticket:\n"
            "    connector: scripts/tools/broken_cli.py\n"
        )
        (fake_root / ".claude-plugin").mkdir(exist_ok=True)
        (fake_root / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"version": "3.4.0-test"})
        )
        _make_session(runs_dir, "sess-bad", run_dir, "test-sig")

        close_ticket_action.main({"session_id": "sess-bad"})

        entries = _read_audit(runs_dir)
        assert len(entries) == 1
        assert entries[0]["status"] == "failure"
        assert entries[0]["exit_code"] == 1
        assert "bad" in (entries[0]["error"] or "")

    def test_connector_subprocess_timeout(self, runs_dir, tmp_path, monkeypatch):
        run_dir = _make_run(runs_dir, signature_id="test-sig")
        fake_root = _write_permissions(monkeypatch, tmp_path, "test-sig")
        _write_actions_yaml(fake_root)
        _symlink_connector(fake_root)
        _make_session(runs_dir, "sess-timeout", run_dir, "test-sig")

        class _Timeout(Exception):
            pass

        import subprocess as real_subprocess

        def _raise_timeout(*_a, **_kw):
            raise real_subprocess.TimeoutExpired(cmd=["stub"], timeout=1)

        monkeypatch.setattr(
            close_ticket_action.subprocess, "run", _raise_timeout
        )

        close_ticket_action.main({"session_id": "sess-timeout"})

        entries = _read_audit(runs_dir)
        assert len(entries) == 1
        assert entries[0]["status"] == "failure"
        assert "timeout" in (entries[0]["error"] or "")
