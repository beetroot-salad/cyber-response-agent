#!/usr/bin/env python3
"""
Investigation Runner

Manages the lifecycle of a Claude Code investigation:
1. Creates isolated runtime directory
2. Copies knowledge (skills) and configuration
3. Spawns Claude Code process
4. Captures and parses output
5. Cleans up (optional)

Usage:
    from runner import InvestigationRunner

    runner = InvestigationRunner(
        ticket_id="SEC-2024-001",
        signature_id="wazuh-rule-5710",
        alert_data={"srcip": "10.0.1.50", "srcuser": "testuser", ...}
    )
    result = runner.run()
"""

import json
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from app.agent.models import ReproductionRequest


# Base paths
APP_DIR = Path("/workspace/app")
KNOWLEDGE_DIR = APP_DIR / "knowledge"
CONFIG_DIR = APP_DIR / "config"
INVESTIGATION_DIR = APP_DIR / "agent" / "investigation"
RUNS_DIR = INVESTIGATION_DIR / "runs"


@dataclass
class InvestigationConfig:
    """Configuration for an investigation run."""

    # From permissions.yaml
    allowed_dispositions: list[str] = field(default_factory=lambda: ["benign", "false_positive"])
    allowed_capabilities: list[str] = field(default_factory=lambda: ["query_siem", "read_knowledge"])
    auto_close_enabled: bool = True
    escalation_patterns: dict[str, list[str]] = field(default_factory=dict)
    reproduction_enabled: bool = False
    log_level: str = "standard"

    @classmethod
    def load(cls, signature_id: str) -> "InvestigationConfig":
        """Load configuration for a signature."""
        config_path = CONFIG_DIR / "signatures" / signature_id / "permissions.yaml"

        if not config_path.exists():
            # Fall back to template
            config_path = CONFIG_DIR / "signatures" / "_template" / "permissions.yaml"

        if not config_path.exists():
            # Use defaults
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f)

        return cls(
            allowed_dispositions=data.get("allowed_dispositions", ["benign", "false_positive"]),
            allowed_capabilities=data.get("allowed_capabilities", ["query_siem", "read_knowledge"]),
            auto_close_enabled=data.get("auto_close", {}).get("enabled", True),
            escalation_patterns=data.get("escalation_patterns", {}),
            reproduction_enabled=data.get("reproduction", {}).get("enabled", False),
            log_level=data.get("log_level", "standard"),
        )


@dataclass
class InvestigationResult:
    """Result of an investigation run."""

    success: bool
    recommendation: str = "escalate"
    confidence: str = "low"
    matched_ticket: Optional[str] = None
    matched_tier: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    report_body: str = ""

    # For reproduction handoff
    hypothesis: Optional[str] = None

    # Metadata
    ticket_id: str = ""
    signature_id: str = ""
    run_id: str = ""
    run_url: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "matched_ticket": self.matched_ticket,
            "matched_tier": self.matched_tier,
            "evidence": self.evidence,
            "report_body": self.report_body,
            "hypothesis": self.hypothesis,
            "ticket_id": self.ticket_id,
            "signature_id": self.signature_id,
            "run_id": self.run_id,
            "run_url": self.run_url,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


class InvestigationRunner:
    """
    Manages a Claude Code investigation process.

    Creates an isolated environment with:
    - .claude/skills/ containing signature + common knowledge
    - .claude/mcp_config.json for MCP servers
    - CLAUDE.md system prompt
    - alert.json with ticket data
    """

    def __init__(
        self,
        ticket_id: str,
        signature_id: str,
        alert_data: dict[str, Any],
        timeout_seconds: int = 300,
        cleanup: bool = False,
    ):
        self.ticket_id = ticket_id
        self.signature_id = signature_id
        self.alert_data = alert_data
        self.timeout_seconds = timeout_seconds
        self.cleanup = cleanup

        # Generate unique run ID
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        short_uuid = uuid.uuid4().hex[:8]
        self.run_id = f"{ticket_id}_{timestamp}_{short_uuid}"

        # Runtime directory
        self.run_dir = RUNS_DIR / self.run_id

        # Load configuration
        self.config = InvestigationConfig.load(signature_id)

    def setup(self) -> None:
        """Create runtime directory and copy resources."""
        # Create directory structure
        self.run_dir.mkdir(parents=True, exist_ok=True)
        skills_dir = self.run_dir / ".claude" / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)

        # Copy signature knowledge as skill
        sig_knowledge = KNOWLEDGE_DIR / "signatures" / self.signature_id
        if sig_knowledge.exists():
            shutil.copytree(sig_knowledge, skills_dir / self.signature_id)
        else:
            # Fall back to template
            template_knowledge = KNOWLEDGE_DIR / "signatures" / "_template"
            if template_knowledge.exists():
                shutil.copytree(template_knowledge, skills_dir / self.signature_id)

        # Copy common knowledge as skill
        common_knowledge = KNOWLEDGE_DIR / "common"
        if common_knowledge.exists():
            shutil.copytree(common_knowledge, skills_dir / "common")

        # Copy MCP config
        mcp_source = INVESTIGATION_DIR / ".claude" / "mcp_config.json"
        mcp_dest = self.run_dir / ".claude" / "mcp_config.json"
        if mcp_source.exists():
            shutil.copy(mcp_source, mcp_dest)

        # Copy settings (includes hooks)
        settings_source = INVESTIGATION_DIR / ".claude" / "settings.json"
        settings_dest = self.run_dir / ".claude" / "settings.json"
        if settings_source.exists():
            shutil.copy(settings_source, settings_dest)

        # Copy system prompt
        claude_md_source = INVESTIGATION_DIR / "CLAUDE.md"
        claude_md_dest = self.run_dir / "CLAUDE.md"
        if claude_md_source.exists():
            shutil.copy(claude_md_source, claude_md_dest)

        # Write alert data
        alert_file = self.run_dir / "alert.json"
        with open(alert_file, "w") as f:
            json.dump({
                "ticket_id": self.ticket_id,
                "signature_id": self.signature_id,
                **self.alert_data,
            }, f, indent=2)

        # Create scratchpad directory
        scratchpad = self.run_dir / "scratchpad"
        scratchpad.mkdir(exist_ok=True)

    def build_prompt(self) -> str:
        """Build the investigation prompt for Claude Code."""
        alert_summary = json.dumps(self.alert_data, indent=2)

        return f"""Investigate security alert {self.ticket_id}.

## Alert Details
- **Ticket ID**: {self.ticket_id}
- **Signature**: {self.signature_id}
- **Alert Data**:
```json
{alert_summary}
```

## Instructions
1. Read the alert data from `alert.json`
2. Use your skills to understand this signature and known patterns
3. Gather context using available tools (Wazuh MCP)
4. Follow the investigation process in CLAUDE.md
5. Output your Investigation Report with JSON findings block and narrative

## Output
Provide your Investigation Report as specified in CLAUDE.md:
- Start with the JSON findings block
- Follow with the human-readable narrative sections
"""

    def run_claude_code(self) -> tuple[str, str, int]:
        """
        Spawn Claude Code process and capture output.

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        prompt = self.build_prompt()

        # Build command
        cmd = [
            "claude",
            "--print",  # Non-interactive, print response
            "--cwd", str(self.run_dir),
            "-p", prompt,
        ]

        # Environment for hooks
        env = os.environ.copy()
        env["INVESTIGATION_RUN_DIR"] = str(self.run_dir)
        env["SIGNATURE_ID"] = self.signature_id
        env["TICKET_ID"] = self.ticket_id

        # Run process
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=self.timeout_seconds,
                cwd=str(self.run_dir),
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Investigation timed out after {self.timeout_seconds}s", -1
        except FileNotFoundError:
            return "", "Claude Code CLI not found. Is it installed?", -1

    def parse_output(self, stdout: str) -> InvestigationResult:
        """Parse Claude Code output into InvestigationResult."""
        import re

        # Try to extract JSON block
        json_match = re.search(r"```json\s*\n(.*?)\n```", stdout, re.DOTALL)

        if not json_match:
            return InvestigationResult(
                success=False,
                ticket_id=self.ticket_id,
                signature_id=self.signature_id,
                run_id=self.run_id,
                run_url=str(self.run_dir),
                error="No JSON findings block in output",
                report_body=stdout,
            )

        try:
            findings = json.loads(json_match.group(1))
        except json.JSONDecodeError as e:
            return InvestigationResult(
                success=False,
                ticket_id=self.ticket_id,
                signature_id=self.signature_id,
                run_id=self.run_id,
                run_url=str(self.run_dir),
                error=f"Invalid JSON in findings block: {e}",
                report_body=stdout,
            )

        # Extract report body (everything after JSON block)
        json_end = json_match.end()
        report_body = stdout[json_end:].strip()

        return InvestigationResult(
            success=True,
            recommendation=findings.get("recommendation", "escalate"),
            confidence=findings.get("confidence", "low"),
            matched_ticket=findings.get("matched_ticket"),
            matched_tier=findings.get("matched_tier"),
            evidence=findings.get("evidence", {}),
            report_body=report_body,
            hypothesis=findings.get("hypothesis"),
            ticket_id=self.ticket_id,
            signature_id=self.signature_id,
            run_id=self.run_id,
            run_url=str(self.run_dir),
        )

    def create_reproduction_request(
        self,
        result: InvestigationResult,
        hypothesis: Optional[str] = None,
    ) -> Optional[ReproductionRequest]:
        """
        Create a ReproductionRequest from investigation result.

        Args:
            result: The investigation result
            hypothesis: Override hypothesis (uses result.hypothesis if not provided)

        Returns:
            ReproductionRequest if reproduction is enabled, None otherwise
        """
        if not self.config.reproduction_enabled:
            return None

        # Use provided hypothesis, or from result, or generate from evidence
        final_hypothesis = hypothesis or result.hypothesis
        if not final_hypothesis and result.evidence:
            # Generate a basic hypothesis from evidence
            evidence_summary = ", ".join(
                f"{k}: {v}" for k, v in list(result.evidence.items())[:3]
            )
            final_hypothesis = (
                f"Alert {self.ticket_id} ({self.signature_id}) "
                f"is {result.recommendation} based on: {evidence_summary}"
            )

        if not final_hypothesis:
            return None

        return ReproductionRequest(
            ticket_id=self.ticket_id,
            hypothesis=final_hypothesis,
            signature_id=self.signature_id,
            context_url=str(self.run_dir),
        )

    def teardown(self) -> None:
        """Clean up runtime directory if configured."""
        if self.cleanup and self.run_dir.exists():
            shutil.rmtree(self.run_dir)

    def run(self) -> InvestigationResult:
        """
        Execute the full investigation lifecycle.

        Returns:
            InvestigationResult with findings or error
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Setup
            self.setup()

            # Run Claude Code
            stdout, stderr, returncode = self.run_claude_code()

            if returncode != 0:
                return InvestigationResult(
                    success=False,
                    ticket_id=self.ticket_id,
                    signature_id=self.signature_id,
                    run_id=self.run_id,
                    run_url=str(self.run_dir),
                    error=f"Claude Code exited with code {returncode}: {stderr}",
                    duration_seconds=(datetime.now(timezone.utc) - start_time).total_seconds(),
                )

            # Parse output
            result = self.parse_output(stdout)
            result.duration_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

            return result

        except Exception as e:
            return InvestigationResult(
                success=False,
                ticket_id=self.ticket_id,
                signature_id=self.signature_id,
                run_id=self.run_id,
                run_url=str(self.run_dir),
                error=f"Investigation failed: {type(e).__name__}: {e}",
                duration_seconds=(datetime.now(timezone.utc) - start_time).total_seconds(),
            )

        finally:
            if self.cleanup:
                self.teardown()


def investigate(ticket_id: str, signature_id: str, alert_data: dict) -> dict:
    """
    Convenience function matching the old interface.

    Used by orchestrator for backwards compatibility.
    """
    runner = InvestigationRunner(
        ticket_id=ticket_id,
        signature_id=signature_id,
        alert_data=alert_data,
    )
    result = runner.run()

    # Convert to old format for backwards compatibility
    return {
        "recommendation": result.recommendation,
        "confidence": result.confidence,
        "matched_ticket": result.matched_ticket,
        "matched_tier": result.matched_tier,
        "evidence": result.evidence,
        "reasoning": result.report_body[:500] if result.report_body else "",  # Truncate for old format
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Investigation Runner")
    parser.add_argument("--ticket-id", required=True, help="Ticket ID")
    parser.add_argument("--signature-id", required=True, help="Signature ID")
    parser.add_argument("--alert-json", required=True, help="Alert data as JSON string")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    parser.add_argument("--cleanup", action="store_true", help="Remove runtime dir after completion")

    args = parser.parse_args()

    try:
        alert_data = json.loads(args.alert_json)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid alert JSON: {e}"}))
        exit(1)

    runner = InvestigationRunner(
        ticket_id=args.ticket_id,
        signature_id=args.signature_id,
        alert_data=alert_data,
        timeout_seconds=args.timeout,
        cleanup=args.cleanup,
    )

    result = runner.run()
    print(json.dumps(result.to_dict(), indent=2))
