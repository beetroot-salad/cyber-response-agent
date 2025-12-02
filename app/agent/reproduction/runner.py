#!/usr/bin/env python3
"""
Reproduction Runner

Manages the lifecycle of a Claude Code reproduction test:
1. Creates isolated runtime directory with hypothesis context
2. Spawns Claude Code process
3. Captures and parses output
4. Cleans up sandbox containers

Usage:
    from app.agent.reproduction.runner import ReproductionRunner
    from app.agent.models import ReproductionRequest

    # Using ReproductionRequest (preferred)
    request = ReproductionRequest(
        ticket_id="SEC-2024-001",
        hypothesis="On target-endpoint, benign_activity.sh creates /tmp/backup-*.tar.gz",
    )
    runner = ReproductionRunner.from_request(request)
    result = runner.run()

    # Direct instantiation (legacy)
    runner = ReproductionRunner(
        ticket_id="SEC-2024-001",
        hypothesis="File /tmp/backup.tar.gz was created by backup.sh",
    )
    result = runner.run()
"""

import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.agent.models import ReproductionRequest, ReproductionResult


# Base paths
APP_DIR = Path("/workspace/app")
KNOWLEDGE_DIR = APP_DIR / "knowledge"
REPRODUCTION_DIR = APP_DIR / "agent" / "reproduction"
RUNS_DIR = REPRODUCTION_DIR / "runs"


class ReproductionRunner:
    """
    Manages a Claude Code reproduction process.

    Creates an isolated environment with:
    - hypothesis.json with test context
    - CLAUDE.md system prompt
    - .claude/skills/ containing signature knowledge
    - output/ directory for reproduction report
    """

    def __init__(
        self,
        ticket_id: str,
        hypothesis: str,
        signature_id: Optional[str] = None,
        context_url: Optional[str] = None,
        environment_hint: Optional[str] = None,
        timeout_seconds: int = 300,
    ):
        self.ticket_id = ticket_id
        self.hypothesis = hypothesis
        self.signature_id = signature_id
        self.context_url = context_url
        self.environment_hint = environment_hint
        self.timeout_seconds = timeout_seconds

        # Generate unique run ID
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        short_uuid = uuid.uuid4().hex[:8]
        self.run_id = f"{ticket_id}_{timestamp}_{short_uuid}"

        # Runtime directory
        self.run_dir = RUNS_DIR / self.run_id

    @classmethod
    def from_request(cls, request: ReproductionRequest) -> "ReproductionRunner":
        """Create a ReproductionRunner from a ReproductionRequest."""
        return cls(
            ticket_id=request.ticket_id,
            hypothesis=request.hypothesis,
            signature_id=request.signature_id,
            context_url=request.context_url,
            environment_hint=request.environment_hint,
            timeout_seconds=request.timeout_seconds,
        )

    def setup(self) -> None:
        """Create runtime directory and copy resources."""
        # Create directory structure
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "output").mkdir(exist_ok=True)
        (self.run_dir / "scratchpad").mkdir(exist_ok=True)

        # Create .claude directory for skills
        skills_dir = self.run_dir / ".claude" / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)

        # Copy signature knowledge as skill (if exists)
        if self.signature_id:
            sig_knowledge = KNOWLEDGE_DIR / "signatures" / self.signature_id
            if sig_knowledge.exists():
                shutil.copytree(sig_knowledge, skills_dir / self.signature_id)

        # Copy common knowledge as skill (if exists)
        common_knowledge = KNOWLEDGE_DIR / "common"
        if common_knowledge.exists():
            shutil.copytree(common_knowledge, skills_dir / "common")

        # Copy system prompt
        claude_md_source = REPRODUCTION_DIR / "CLAUDE.md"
        claude_md_dest = self.run_dir / "CLAUDE.md"
        if claude_md_source.exists():
            shutil.copy(claude_md_source, claude_md_dest)

        # Write hypothesis context
        hypothesis_file = self.run_dir / "hypothesis.json"
        with open(hypothesis_file, "w") as f:
            json.dump({
                "ticket_id": self.ticket_id,
                "hypothesis": self.hypothesis,
                "signature_id": self.signature_id,
                "context_url": self.context_url,
                "environment_hint": self.environment_hint,
                "run_id": self.run_id,
            }, f, indent=2)

    def build_prompt(self) -> str:
        """Build the reproduction prompt for Claude Code.

        Provides task-specific context only. General methodology, output format,
        and safety constraints are defined in CLAUDE.md.
        """
        context_section = ""
        if self.context_url:
            context_section = f"\n- **Investigation Context**: {self.context_url}"

        env_section = ""
        if self.environment_hint:
            env_section = f"\n- **Environment Hint**: {self.environment_hint}"

        return f"""## Hypothesis to Test

{self.hypothesis}

## Runtime Context

- **Ticket ID**: {self.ticket_id}
- **Signature**: {self.signature_id or "unknown"}
- **Run ID**: {self.run_id}{context_section}{env_section}

## Input Files

- `hypothesis.json` - Full hypothesis context and metadata
- `.claude/skills/` - Relevant signature knowledge (if available)

## Task

Follow the reproduction framework to validate this hypothesis. Discover the source environment, build an isolated sandbox, execute the test, and compare observed behavior against expected patterns.

Write your findings to `output/reproduction-report.md` as you work, then return your JSON result block.
"""

    def run_claude_code(self) -> tuple[str, str, int]:
        """
        Spawn Claude Code process and capture output.

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        prompt = self.build_prompt()

        # Build command
        # Allow specific Docker commands needed for reproduction:
        # - docker inspect/ps: environment discovery
        # - docker exec: read files from source container
        # - docker run: create isolated sandbox
        # - docker cp: copy files to/from containers
        # - docker rm: cleanup
        cmd = [
            "claude",
            "--print",  # Non-interactive, print response
            "--allowedTools", "Bash(docker:*)",
            "Read", "Write", "Edit", "Glob", "Grep",
            "-p", prompt,
        ]

        # Environment
        env = os.environ.copy()
        env["REPRODUCTION_RUN_DIR"] = str(self.run_dir)
        env["REPRODUCTION_RUN_ID"] = self.run_id
        env["TICKET_ID"] = self.ticket_id
        if self.signature_id:
            env["SIGNATURE_ID"] = self.signature_id
        if self.environment_hint:
            env["ENVIRONMENT_HINT"] = self.environment_hint

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
            return "", f"Reproduction timed out after {self.timeout_seconds}s", -1
        except FileNotFoundError:
            return "", "Claude Code CLI not found. Is it installed?", -1

    def parse_output(self, stdout: str) -> ReproductionResult:
        """Parse Claude Code output into ReproductionResult."""
        # Check for report file
        report_path = self.run_dir / "output" / "reproduction-report.md"
        report_url = str(report_path) if report_path.exists() else None

        # Try to extract JSON block
        json_match = re.search(r"```json\s*\n(.*?)\n```", stdout, re.DOTALL)

        if not json_match:
            return ReproductionResult(
                success=False,
                hypothesis_tested=self.hypothesis,
                run_id=self.run_id,
                run_url=str(self.run_dir),
                report_url=report_url,
                error="No JSON result block in output",
            )

        try:
            findings = json.loads(json_match.group(1))
        except json.JSONDecodeError as e:
            return ReproductionResult(
                success=False,
                hypothesis_tested=self.hypothesis,
                run_id=self.run_id,
                run_url=str(self.run_dir),
                report_url=report_url,
                error=f"Invalid JSON in result block: {e}",
            )

        return ReproductionResult(
            success=True,
            result=findings.get("result", "inconclusive"),
            hypothesis_tested=findings.get("hypothesis_tested", self.hypothesis),
            observations=findings.get("observations", []),
            not_reproducible_reason=findings.get("not_reproducible_reason"),
            report_url=report_url,
            run_id=self.run_id,
            run_url=str(self.run_dir),
        )

    def cleanup_containers(self) -> None:
        """Remove any sandbox containers created during this run."""
        try:
            # Find containers matching our run_id pattern
            find_cmd = [
                "docker", "ps", "-aq",
                "--filter", f"name=repro-{self.run_id}",
            ]
            find_result = subprocess.run(
                find_cmd, capture_output=True, text=True, timeout=10
            )

            container_ids = find_result.stdout.strip().split("\n")
            container_ids = [c for c in container_ids if c]  # Filter empty

            if container_ids:
                # Remove containers
                rm_cmd = ["docker", "rm", "-f"] + container_ids
                subprocess.run(rm_cmd, capture_output=True, timeout=30)

        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            # Best effort cleanup - don't fail the run
            pass

    def run(self) -> ReproductionResult:
        """
        Execute the full reproduction lifecycle.

        Returns:
            ReproductionResult with findings or error
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Setup
            self.setup()

            # Run Claude Code
            stdout, stderr, returncode = self.run_claude_code()

            if returncode != 0:
                return ReproductionResult(
                    success=False,
                    hypothesis_tested=self.hypothesis,
                    run_id=self.run_id,
                    run_url=str(self.run_dir),
                    duration_seconds=(datetime.now(timezone.utc) - start_time).total_seconds(),
                    error=f"Claude Code exited with code {returncode}: {stderr}",
                )

            # Parse output
            result = self.parse_output(stdout)
            result.duration_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

            return result

        except Exception as e:
            return ReproductionResult(
                success=False,
                hypothesis_tested=self.hypothesis,
                run_id=self.run_id,
                run_url=str(self.run_dir),
                duration_seconds=(datetime.now(timezone.utc) - start_time).total_seconds(),
                error=f"Reproduction failed: {type(e).__name__}: {e}",
            )

        finally:
            # Always attempt container cleanup
            self.cleanup_containers()


def reproduce(request: ReproductionRequest) -> ReproductionResult:
    """
    Convenience function for reproduction tests.

    Args:
        request: ReproductionRequest with hypothesis and context

    Returns:
        ReproductionResult with findings or error
    """
    runner = ReproductionRunner.from_request(request)
    return runner.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reproduction Runner")
    parser.add_argument("--ticket-id", required=True, help="Ticket ID")
    parser.add_argument("--hypothesis", required=True, help="Hypothesis to test")
    parser.add_argument("--signature-id", help="Signature ID")
    parser.add_argument("--context-url", help="URL/path to investigation artifacts")
    parser.add_argument("--environment-hint", help="Environment hint (container, VM, etc.)")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")

    args = parser.parse_args()

    request = ReproductionRequest(
        ticket_id=args.ticket_id,
        hypothesis=args.hypothesis,
        signature_id=args.signature_id,
        context_url=args.context_url,
        environment_hint=args.environment_hint,
        timeout_seconds=args.timeout,
    )

    runner = ReproductionRunner.from_request(request)
    result = runner.run()
    print(json.dumps(result.to_dict(), indent=2))
