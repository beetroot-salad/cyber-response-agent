"""Shared pytest configuration and fixtures for soc-agent tests."""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# Add soc-agent root to sys.path so schemas can be imported
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures"


def pytest_configure(config):
    config.addinivalue_line("markers", "llm: tests requiring LLM (Claude CLI + API)")
    config.addinivalue_line("markers", "live: tests requiring live SIEM (Wazuh playground)")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InvestigationResult:
    """Result of a claude investigation invocation."""
    run_dir: Path
    stdout: str
    stderr: str
    returncode: int
    alert: dict = field(default_factory=dict)
    signature_id: str = ""
    timed_out: bool = False

    @property
    def state_json(self) -> dict:
        path = self.run_dir / "state.json"
        return json.loads(path.read_text()) if path.exists() else {}

    @property
    def report_md(self) -> str:
        path = self.run_dir / "report.md"
        return path.read_text() if path.exists() else ""

    @property
    def investigation_md(self) -> str:
        path = self.run_dir / "investigation.md"
        return path.read_text() if path.exists() else ""

    @property
    def meta_json(self) -> dict:
        path = self.run_dir / "meta.json"
        return json.loads(path.read_text()) if path.exists() else {}

    @property
    def budget_json(self) -> dict:
        path = self.run_dir / "budget.json"
        return json.loads(path.read_text()) if path.exists() else {}


# ---------------------------------------------------------------------------
# Helpers — resolve signature knowledge
# ---------------------------------------------------------------------------

def resolve_signature_knowledge(signature_id: str) -> str:
    """Run resolve_imports.py to bake signature knowledge into a string."""
    result = subprocess.run(
        [sys.executable, str(SOC_AGENT_ROOT / "scripts" / "resolve_imports.py"), signature_id],
        capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"resolve_imports.py failed (exit {result.returncode}): {result.stderr}"
        )
    return result.stdout


def setup_run_dir(signature_id: str, alert: dict, runs_dir: Path | None = None) -> Path:
    """Create a run directory via setup_run.py. Returns the run_dir path."""
    env = os.environ.copy()
    if runs_dir is not None:
        env["SOC_AGENT_RUNS_DIR"] = str(runs_dir)

    result = subprocess.run(
        [
            sys.executable,
            str(SOC_AGENT_ROOT / "scripts" / "setup_run.py"),
            signature_id,
            json.dumps(alert),
        ],
        capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT), env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"setup_run.py failed (exit {result.returncode}): {result.stderr}"
        )

    # Parse run directory from stdout: "Run directory: /path/to/run"
    for line in result.stdout.splitlines():
        if line.startswith("Run directory:"):
            return Path(line.split(":", 1)[1].strip())

    raise RuntimeError(f"setup_run.py did not output run directory: {result.stdout}")


# ---------------------------------------------------------------------------
# Investigation runners
# ---------------------------------------------------------------------------

def _build_base_prompt(
    signature_id: str,
    alert: dict,
    run_dir: Path,
    resolved_knowledge: str,
) -> str:
    """Build the common prompt prefix used by both mock and live runners."""
    return f"""You are running a security alert investigation. Your working directory is the soc-agent plugin root.

SIGNATURE KNOWLEDGE (resolved at skill load time):
{resolved_knowledge}

ALERT DATA:
```json
{json.dumps(alert, indent=2)}
```

RUN DIRECTORY: {run_dir}

"""


def run_investigation_mock(
    run_dir: Path,
    alert: dict,
    siem_fixture: str = "wazuh-5710-monitoring-probe.json",
    timeout: int = 300,
) -> InvestigationResult:
    """Invoke claude with mock SIEM data baked into the prompt.

    This is the refactored version of the original _run_investigator() from
    test_e2e_mock.py. Uses mock SIEM data, skips subagents, no live queries.
    """
    sig_id = alert.get("signature_id", "wazuh-rule-5710")
    resolved_knowledge = resolve_signature_knowledge(sig_id)

    siem_path = FIXTURES / "siem_responses" / siem_fixture
    siem_data = json.loads(siem_path.read_text()) if siem_path.exists() else {}

    prompt = _build_base_prompt(sig_id, alert, run_dir, resolved_knowledge)
    prompt += f"""MOCK SIEM DATA (use this instead of querying live SIEM — no MCP tools are available in this test):
```json
{json.dumps(siem_data, indent=2)}
```

INSTRUCTIONS:
1. Read the investigate skill instructions from skills/investigate/SKILL.md
2. The signature knowledge above is already resolved — do not re-read context.md, playbook.md, or checklist.md
3. Follow the investigation loop: CONTEXTUALIZE -> PREDICT -> GATHER -> ANALYZE -> REPORT
4. At each phase, call write_state.py: python3 hooks/scripts/write_state.py {run_dir} <PHASE> {alert['ticket_id']} {sig_id}
5. For the GATHER phase, use the MOCK SIEM DATA above instead of querying live tools
6. Skip the Explore subagent for precedents in this test — use the mock data
7. Write investigation.md and report.md to {run_dir}/
8. The report.md MUST have YAML frontmatter with all required fields

Complete the full investigation loop. Do not skip phases."""

    result = subprocess.run(
        [
            "claude", "-p",
            "--plugin-dir", str(SOC_AGENT_ROOT),
            "--allowedTools", "Bash", "Read", "Write", "Edit", "Glob", "Grep",
            "--output-format", "text",
            "--max-budget-usd", "2.00",
            prompt,
        ],
        capture_output=True, text=True, timeout=timeout,
        cwd=str(SOC_AGENT_ROOT),
    )

    return InvestigationResult(
        run_dir=run_dir,
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        alert=alert,
        signature_id=sig_id,
    )


def run_investigation_live(
    alert: dict,
    runs_dir: Path,
    signature_id: str = "wazuh-rule-5710",
    timeout: int = 600,
    extra_instructions: str = "",
    env_overrides: dict | None = None,
    budget_usd: str = "3.00",
) -> InvestigationResult:
    """Invoke claude against live SIEM — real wazuh_cli.py queries, real subagents.

    Creates run_dir via setup_run.py, resolves knowledge, then launches claude -p
    with the investigation skill prompt. The agent queries Wazuh via wazuh_cli.py
    and spawns subagents as needed.
    """
    run_dir = setup_run_dir(signature_id, alert, runs_dir=runs_dir)
    resolved_knowledge = resolve_signature_knowledge(signature_id)

    prompt = _build_base_prompt(signature_id, alert, run_dir, resolved_knowledge)
    prompt += f"""INSTRUCTIONS:
1. Read the investigate skill instructions from skills/investigate/SKILL.md
2. The signature knowledge above is already resolved — do not re-read context.md, playbook.md, or checklist.md
3. Follow the investigation loop as described in the skill
4. At each phase, call write_state.py: python3 hooks/scripts/write_state.py {run_dir} <PHASE> {alert.get('ticket_id', 'UNKNOWN')} {signature_id}
5. For SIEM queries, use wazuh_cli.py:
   python3 scripts/tools/wazuh_cli.py query --query '<lucene_query>' --start <iso_time> --window <duration> --run-dir {run_dir}
6. Write investigation.md and report.md to {run_dir}/
7. The report.md MUST have YAML frontmatter with all required fields
8. If SIEM queries fail or return errors, document the failure and escalate — do not guess at data
"""
    if extra_instructions:
        prompt += f"\nADDITIONAL INSTRUCTIONS:\n{extra_instructions}\n"

    prompt += "\nComplete the investigation. Do not skip phases."

    env = os.environ.copy()
    env["SOC_AGENT_RUNS_DIR"] = str(runs_dir)
    if env_overrides:
        env.update(env_overrides)

    try:
        result = subprocess.run(
            [
                "claude", "-p",
                "--plugin-dir", str(SOC_AGENT_ROOT),
                "--allowedTools", "Bash", "Read", "Write", "Edit", "Glob", "Grep", "Agent",
                "--output-format", "text",
                "--max-budget-usd", budget_usd,
                prompt,
            ],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(SOC_AGENT_ROOT),
            env=env,
        )
        return InvestigationResult(
            run_dir=run_dir,
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            alert=alert,
            signature_id=signature_id,
        )
    except subprocess.TimeoutExpired as e:
        return InvestigationResult(
            run_dir=run_dir,
            stdout=(e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            stderr=(e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or ""),
            returncode=-1,
            alert=alert,
            signature_id=signature_id,
            timed_out=True,
        )


# ---------------------------------------------------------------------------
# Live SIEM fixtures
# ---------------------------------------------------------------------------

def _wazuh_health_check() -> bool:
    """Run wazuh_cli.py health-check. Returns True if healthy."""
    try:
        result = subprocess.run(
            [sys.executable, str(SOC_AGENT_ROOT / "scripts" / "tools" / "wazuh_cli.py"),
             "health-check"],
            capture_output=True, text=True, timeout=30,
            cwd=str(SOC_AGENT_ROOT),
        )
        return result.returncode == 0 and "indexer: healthy" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _ssh_attempt(username: str, target: str = "target-endpoint"):
    """Attempt SSH login with a nonexistent user — generating an 'Invalid user' sshd log.

    Rule 5710 fires on 'Invalid user' messages. The username must NOT exist
    on the target system — valid users generate a different log line that
    doesn't match the rule.
    """
    subprocess.run(
        ["ssh",
         "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=5",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR",
         f"{username}@{target}", "exit"],
        capture_output=True, timeout=10,
    )


def _inject_ssh_alerts():
    """Generate SSH alerts by attempting failed logins to target-endpoint.

    Creates both monitoring-probe (single attempt) and brute-force
    (multiple varied usernames) scenarios. All usernames must be nonexistent
    on the target — rule 5710 only fires on 'Invalid user' sshd messages.
    """
    # Monitoring probe: single attempt with a monitoring-style nonexistent user
    _ssh_attempt("probe-test01")

    # Brute force: multiple attempts with varied nonexistent usernames
    for username in ["badmin", "r00t", "cracker", "haxor", "intruder",
                     "attacker", "scanner01", "scanner02", "scanner03",
                     "exploit", "payload", "backdoor"]:
        _ssh_attempt(username)


def _wait_for_alerts(query: str, min_count: int = 1, timeout: int = 90) -> bool:
    """Poll Wazuh indexer until alerts matching query appear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            [sys.executable, str(SOC_AGENT_ROOT / "scripts" / "tools" / "wazuh_cli.py"),
             "query", "--query", query, "--window", "15m", "--limit", "1", "--raw"],
            capture_output=True, text=True, timeout=30,
            cwd=str(SOC_AGENT_ROOT),
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout.strip())
                if isinstance(data, list) and len(data) >= min_count:
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
        time.sleep(5)
    return False


@pytest.fixture(scope="session")
def wazuh_healthy():
    """Skip all live tests if Wazuh is unreachable."""
    if not _wazuh_health_check():
        pytest.skip(
            "Wazuh SIEM is not reachable. "
            "Start the playground: cd .devcontainer && docker compose up -d"
        )


@pytest.fixture(scope="session")
def live_alerts_ready(wazuh_healthy):
    """Inject SSH alerts and wait for Wazuh to index them.

    Returns the approximate timestamp of injection for query windows.
    """
    from datetime import datetime, timezone

    inject_time = datetime.now(timezone.utc)
    _inject_ssh_alerts()

    # Wait for at least one rule 5710 alert to appear
    found = _wait_for_alerts("rule.id:5710", min_count=1, timeout=90)
    if not found:
        pytest.skip(
            "Wazuh did not index SSH alerts within timeout. "
            "Check that target-endpoint has sshd running and Wazuh agent is connected."
        )

    return inject_time


@pytest.fixture(scope="session")
def live_runs_dir(tmp_path_factory):
    """Session-scoped temporary directory for all live test runs."""
    return tmp_path_factory.mktemp("live-runs")


# ---------------------------------------------------------------------------
# Alert fixtures
# ---------------------------------------------------------------------------

def make_monitoring_probe_alert(timestamp: str | None = None) -> dict:
    """Create a monitoring-probe alert for wazuh-rule-5710.

    Uses an internal IP and a monitoring-style username. The username
    'probe-test01' matches the injected SSH attempt in _inject_ssh_alerts().
    """
    from datetime import datetime, timezone
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "ticket_id": f"TEST-PROBE-{int(time.time())}",
        "signature_id": "wazuh-rule-5710",
        "alert_data": {
            "srcip": "10.0.1.50",
            "srcuser": "probe-test01",
            "agent": "target-endpoint",
            "rule_id": 5710,
            "timestamp": ts,
        },
    }


def make_brute_force_alert(timestamp: str | None = None) -> dict:
    """Create a brute-force alert for wazuh-rule-5710.

    Uses an external IP and a common attack username. The SIEM will have
    matching multi-username attempts from _inject_ssh_alerts().
    """
    from datetime import datetime, timezone
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "ticket_id": f"TEST-BRUTE-{int(time.time())}",
        "signature_id": "wazuh-rule-5710",
        "alert_data": {
            "srcip": "203.0.113.50",
            "srcuser": "badmin",
            "agent": "target-endpoint",
            "rule_id": 5710,
            "timestamp": ts,
        },
    }


def make_nagios_probe_alert(timestamp: str | None = None) -> dict:
    """Create a monitoring-probe alert with nagios-style username (internal, monitoring pattern)."""
    from datetime import datetime, timezone
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "ticket_id": f"TEST-NAGIOS-{int(time.time())}",
        "signature_id": "wazuh-rule-5710",
        "alert_data": {
            "srcip": "10.0.1.50",
            "srcuser": "nagios",
            "agent": "target-endpoint",
            "rule_id": 5710,
            "timestamp": ts,
        },
    }


# ---------------------------------------------------------------------------
# Seeding helpers for fast-resolve tests
# ---------------------------------------------------------------------------

def seed_prior_investigation(runs_dir: Path, alert: dict, signature_id: str = "wazuh-rule-5710"):
    """Seed a completed prior investigation for fast-resolve testing.

    Creates a run directory with report.md, state.json, meta.json, and appends
    an entry to audit.jsonl — simulating a past resolved investigation.
    """
    import secrets
    from datetime import datetime, timezone

    prior_run_id = f"prior-{int(time.time())}"
    prior_dir = runs_dir / prior_run_id
    prior_dir.mkdir(parents=True, exist_ok=True)

    salt = secrets.token_hex(8)

    # meta.json
    (prior_dir / "meta.json").write_text(json.dumps({
        "run_id": prior_run_id,
        "signature_id": signature_id,
        "salt": salt,
    }, indent=2))

    # alert.json
    (prior_dir / "alert.json").write_text(json.dumps(alert, indent=2))

    # state.json — completed investigation
    (prior_dir / "state.json").write_text(json.dumps({
        "run_id": prior_run_id,
        "ticket_id": alert.get("ticket_id", "PRIOR-001"),
        "signature_id": signature_id,
        "phase": "REPORT",
        "history": ["CONTEXTUALIZE", "SCREEN", "REPORT"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2))

    # report.md — valid resolved report
    (prior_dir / "report.md").write_text(f"""---
ticket_id: {alert.get('ticket_id', 'PRIOR-001')}
signature_id: {signature_id}
status: resolved
disposition: benign
confidence: high
leads_pursued: 2
matched_archetype: monitoring-probe
matched_ticket_id: SEC-2024-001
trust_anchors_consulted:
  - anchor: approved-monitoring-sources
    kind: org-authority
    result: confirmed
    citation: playground monitoring-host cron
---

# Investigation Report

Prior investigation resolved as benign monitoring probe.

## Trace
authentication-history(1 fail, testuser) -> source-reputation(internal) -> benign:monitoring-probe
""")

    # investigation.md
    (prior_dir / "investigation.md").write_text("""# Investigation Log

## CONTEXTUALIZE
Alert from internal monitoring IP. Single SSH failure with testuser.

## SCREEN
Pattern match: monitoring-probe. Internal IP, monitoring username, single attempt.

## REPORT
Resolved as benign monitoring probe matching archetype monitoring-probe.
""")

    # Append to audit.jsonl
    audit_entry = {
        "run_id": prior_run_id,
        "ticket_id": alert.get("ticket_id", "PRIOR-001"),
        "signature_id": signature_id,
        "status": "resolved",
        "disposition": "benign",
        "confidence": "high",
        "matched_archetype": "monitoring-probe",
        "matched_ticket_id": "SEC-2024-001",
        "leads_pursued": 2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    audit_path = runs_dir / "audit.jsonl"
    with open(audit_path, "a") as f:
        f.write(json.dumps(audit_entry) + "\n")

    return prior_dir
