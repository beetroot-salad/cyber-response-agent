#!/usr/bin/env python3
"""Stop-stage hook: deterministic close-ticket dispatch.

Reads the Stop payload, resolves the run directory via the session-anchored
resolver, parses report.md frontmatter, evaluates preconditions, looks up
the connector binding in config/actions.yaml, and (only if everything
passes) dispatches to the configured connector with --execute. Every
decision — success, failure, or skip — is logged to runs/action_audit.jsonl
so the operator has a single grep-able source of truth for action events.

The hook always exits 0. A broken connector, a stale config, or an
unexpected exception must never crash the agent session. Failures are
captured in the audit log.

This file is importable as a module (main(payload)) and runnable directly
via stdin for unit tests and manual dispatch. The production plugin.json
Stop matcher goes through stop_handler.py, which composes this step after
investigation_summary.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts import permissions as permissions_module  # noqa: E402
from hooks.scripts.frontmatter import parse_yaml_frontmatter  # noqa: E402
from hooks.scripts.run_context import get_runs_dir, resolve_run_dir  # noqa: E402

SUBPROCESS_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_ACTION_TIMEOUT_SECONDS", "30")
)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit_log_path() -> Path:
    return get_runs_dir() / "action_audit.jsonl"


def _append_audit(entry: dict) -> None:
    """Append one entry to runs/action_audit.jsonl. Creates parent dir if needed."""
    path = _audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _skip(
    run_id: str,
    signature_id: str,
    ticket_id: str,
    reason: str,
    connector: str | None = None,
) -> None:
    _append_audit(
        {
            "timestamp": _now_iso(),
            "run_id": run_id,
            "signature_id": signature_id,
            "action": "close_ticket",
            "ticket_id": ticket_id,
            "connector": connector,
            "status": "skipped",
            "skip_reason": reason,
            "dry_run": False,
            "exit_code": None,
            "duration_ms": 0,
            "response_summary": None,
            "error": None,
        }
    )


# ---------------------------------------------------------------------------
# Config loaders
# ---------------------------------------------------------------------------


def _load_actions_config() -> dict | None:
    """Load config/actions.yaml. Returns None if missing or unparseable."""
    path = SOC_AGENT_ROOT / "config" / "actions.yaml"
    if not path.exists():
        return None
    text = path.read_text()
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except Exception:
        # Use the permissions fallback parser shape — actions.yaml has the
        # same indentation conventions.
        data = permissions_module._fallback_parse(text)  # noqa: SLF001
    if not isinstance(data, dict):
        return None
    return data


def _resolve_connector(actions_config: dict, action: str) -> dict | None:
    """Return the connector binding for `action`, or None if not declared."""
    actions = actions_config.get("actions")
    if not isinstance(actions, dict):
        return None
    entry = actions.get(action)
    if not isinstance(entry, dict):
        return None
    connector = entry.get("connector")
    if not isinstance(connector, str) or not connector:
        return None
    return entry


def _plugin_version() -> str:
    path = SOC_AGENT_ROOT / ".claude-plugin" / "plugin.json"
    try:
        data = json.loads(path.read_text())
    except Exception:
        return "unknown"
    version = data.get("version")
    return version if isinstance(version, str) and version else "unknown"


def _connector_python(connector_path: Path) -> str:
    """Pick the python interpreter for running an adapter — prefer the shared venv."""
    venv_python = connector_path.parent / ".venv" / "bin" / "python"
    if venv_python.is_file():
        return str(venv_python)
    return "python3"


# ---------------------------------------------------------------------------
# Precondition gate
# ---------------------------------------------------------------------------


REQUIRED_FRONTMATTER_FIELDS = (
    "status",
    "confidence",
    "matched_archetype",
    "ticket_id",
    "signature_id",
)


def _preconditions_hold(frontmatter: dict) -> bool:
    """Check the precondition gate. All conditions must hold."""
    if frontmatter.get("status") != "resolved":
        return False
    if frontmatter.get("confidence") != "high":
        return False
    for key in REQUIRED_FRONTMATTER_FIELDS:
        value = frontmatter.get(key)
        if not isinstance(value, str) or not value:
            return False
    return True


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------


def main(payload: dict) -> None:
    """Dispatch close_ticket after a Stop event. Never raises."""
    try:
        _main(payload)
    except Exception as exc:  # noqa: BLE001 — top-level safety net
        try:
            _append_audit(
                {
                    "timestamp": _now_iso(),
                    "run_id": None,
                    "signature_id": None,
                    "action": "close_ticket",
                    "ticket_id": None,
                    "connector": None,
                    "status": "failure",
                    "skip_reason": None,
                    "dry_run": False,
                    "exit_code": None,
                    "duration_ms": 0,
                    "response_summary": None,
                    "error": f"close_ticket_action exception: {exc!r}"[:200],
                }
            )
        except Exception:
            pass


def _main(payload: dict) -> None:
    session_id = payload.get("session_id") if isinstance(payload, dict) else None
    if not session_id:
        _skip("", "", "", "no_session_id")
        return

    runs_dir = get_runs_dir()
    run_dir, resolved_signature_id = resolve_run_dir(session_id, runs_dir)
    if run_dir is None:
        _skip("", resolved_signature_id or "", "", "no_active_run")
        return

    run_id = run_dir.name

    report_path = run_dir / "report.md"
    if not report_path.exists():
        _skip(run_id, resolved_signature_id or "", "", "no_report")
        return

    frontmatter = parse_yaml_frontmatter(report_path.read_text())
    signature_id = frontmatter.get("signature_id") or resolved_signature_id or ""
    ticket_id = frontmatter.get("ticket_id") or ""

    if not _preconditions_hold(frontmatter):
        _skip(run_id, signature_id, ticket_id, "preconditions_unmet")
        return

    perms = permissions_module.load_permissions(signature_id, root=SOC_AGENT_ROOT)
    mode = permissions_module.get_mode(perms)
    if mode != "act":
        _skip(run_id, signature_id, ticket_id, "mode=recommend")
        return

    action_policy = permissions_module.get_mitigation_action(perms, "close_ticket")
    if action_policy != "auto":
        _skip(run_id, signature_id, ticket_id, "action_not_enabled")
        return

    actions_config = _load_actions_config()
    if actions_config is None:
        _skip(run_id, signature_id, ticket_id, "no_connector_configured")
        return

    binding = _resolve_connector(actions_config, "close_ticket")
    if binding is None:
        _skip(run_id, signature_id, ticket_id, "no_connector_configured")
        return

    connector_rel = binding["connector"]
    connector_path = SOC_AGENT_ROOT / connector_rel
    if not connector_path.exists():
        _append_audit(
            {
                "timestamp": _now_iso(),
                "run_id": run_id,
                "signature_id": signature_id,
                "action": "close_ticket",
                "ticket_id": ticket_id,
                "connector": connector_rel,
                "status": "failure",
                "skip_reason": None,
                "dry_run": False,
                "exit_code": None,
                "duration_ms": 0,
                "response_summary": None,
                "error": f"connector not found: {connector_rel}",
            }
        )
        return

    # Construct call payload from frontmatter fields.
    matched_archetype = frontmatter.get("matched_archetype") or ""
    disposition = frontmatter.get("disposition") or ""
    reason = f"{disposition} ({matched_archetype})" if disposition else matched_archetype
    author = f"soc-agent v{_plugin_version()}"
    documentation = (
        f"Investigation: {run_id}; archetype: {matched_archetype}"
    )

    python_exe = _connector_python(connector_path)
    cmd = [
        python_exe,
        str(connector_path),
        "close",
        "--ticket-id",
        ticket_id,
        "--reason",
        reason,
        "--author",
        author,
        "--documentation",
        documentation,
        "--run-dir",
        str(run_dir),
        "--execute",
    ]

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            cwd=str(SOC_AGENT_ROOT),
        )
    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        _append_audit(
            {
                "timestamp": _now_iso(),
                "run_id": run_id,
                "signature_id": signature_id,
                "action": "close_ticket",
                "ticket_id": ticket_id,
                "connector": connector_rel,
                "status": "failure",
                "skip_reason": None,
                "dry_run": False,
                "exit_code": None,
                "duration_ms": duration_ms,
                "response_summary": None,
                "error": f"timeout after {SUBPROCESS_TIMEOUT_SECONDS}s",
            }
        )
        return
    except Exception as exc:  # noqa: BLE001
        duration_ms = int((time.monotonic() - start) * 1000)
        _append_audit(
            {
                "timestamp": _now_iso(),
                "run_id": run_id,
                "signature_id": signature_id,
                "action": "close_ticket",
                "ticket_id": ticket_id,
                "connector": connector_rel,
                "status": "failure",
                "skip_reason": None,
                "dry_run": False,
                "exit_code": None,
                "duration_ms": duration_ms,
                "response_summary": None,
                "error": f"subprocess error: {exc!r}"[:200],
            }
        )
        return

    duration_ms = int((time.monotonic() - start) * 1000)
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    status = "success" if result.returncode == 0 else "failure"
    _append_audit(
        {
            "timestamp": _now_iso(),
            "run_id": run_id,
            "signature_id": signature_id,
            "action": "close_ticket",
            "ticket_id": ticket_id,
            "connector": connector_rel,
            "status": status,
            "skip_reason": None,
            "dry_run": False,
            "exit_code": result.returncode,
            "duration_ms": duration_ms,
            "response_summary": stdout[:200] if stdout else None,
            "error": stderr[:200] if stderr else None,
        }
    )


if __name__ == "__main__":
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        payload: Any = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    main(payload)
    sys.exit(0)
