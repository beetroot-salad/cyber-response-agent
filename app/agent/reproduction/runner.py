#!/usr/bin/env python3
"""
Reproduction Runner

Manages the lifecycle of a Claude Code reproduction test:
1. Creates isolated runtime directory with hypothesis context
2. Spawns Claude Code process
3. Captures and parses output
4. Cleans up sandbox containers

Usage:
    from runner import ReproductionRunner

    runner = ReproductionRunner(
        hypothesis="File /tmp/backup.tar.gz was created by backup.sh",
        source_container="target-endpoint",
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
        hypothesis: str,
        source_container: str,
        investigation_context: Optional[dict[str, Any]] = None,
        signature_id: str = "unknown",
        timeout_seconds: int = 300,
    ):
        self.hypothesis = hypothesis
        self.source_container = source_container
        self.investigation_context = investigation_context or {}
        self.signature_id = signature_id
        self.timeout_seconds = timeout_seconds

        # Generate unique run ID
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        short_uuid = uuid.uuid4().hex[:8]
        self.run_id = f"{source_container}_{timestamp}_{short_uuid}"

        # Runtime directory
        self.run_dir = RUNS_DIR / self.run_id

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
                "hypothesis": self.hypothesis,
                "source_container": self.source_container,
                "run_id": self.run_id,
                "investigation_context": self.investigation_context,
            }, f, indent=2)

    def build_prompt(self) -> str:
        """Build the reproduction prompt for Claude Code."""
        return f"""Test this reproduction hypothesis.

## Hypothesis
{self.hypothesis}

## Source Environment
- **Container**: {self.source_container}
- **Run ID**: {self.run_id}

## Instructions
1. Read the hypothesis context from `hypothesis.json`
2. Discover the source environment using `docker inspect` and `docker exec`
3. Create an isolated sandbox container with the required isolation flags
4. Execute the reproduction steps in the sandbox
5. Compare observed behavior to expected patterns
6. Write your detailed report to `output/reproduction-report.md`
7. Output your JSON result block

## Container Naming
When creating sandbox containers, use names starting with `repro-{self.run_id}-` so they can be cleaned up.

## Output
Provide your result as specified in CLAUDE.md:
- JSON result block with result, hypothesis_tested, observations
- Detailed report in output/reproduction-report.md
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
        env["SOURCE_CONTAINER"] = self.source_container

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

    def parse_output(self, stdout: str) -> dict[str, Any]:
        """Parse Claude Code output into result dict."""
        result = {
            "success": False,
            "result": "inconclusive",
            "hypothesis_tested": self.hypothesis,
            "observations": [],
            "not_reproducible_reason": None,
            "report_path": None,
            "run_id": self.run_id,
            "run_dir": str(self.run_dir),
            "duration_seconds": 0.0,
            "error": None,
        }

        # Try to extract JSON block
        json_match = re.search(r"```json\s*\n(.*?)\n```", stdout, re.DOTALL)

        if not json_match:
            result["error"] = "No JSON result block in output"
            return result

        try:
            findings = json.loads(json_match.group(1))
        except json.JSONDecodeError as e:
            result["error"] = f"Invalid JSON in result block: {e}"
            return result

        # Update result with findings
        result["success"] = True
        result["result"] = findings.get("result", "inconclusive")
        result["hypothesis_tested"] = findings.get("hypothesis_tested", self.hypothesis)
        result["observations"] = findings.get("observations", [])
        result["not_reproducible_reason"] = findings.get("not_reproducible_reason")

        # Check for report file
        report_path = self.run_dir / "output" / "reproduction-report.md"
        if report_path.exists():
            result["report_path"] = str(report_path)

        return result

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

    def run(self) -> dict[str, Any]:
        """
        Execute the full reproduction lifecycle.

        Returns:
            Dict with reproduction results or error
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Setup
            self.setup()

            # Run Claude Code
            stdout, stderr, returncode = self.run_claude_code()

            if returncode != 0:
                return {
                    "success": False,
                    "result": "inconclusive",
                    "hypothesis_tested": self.hypothesis,
                    "observations": [],
                    "not_reproducible_reason": None,
                    "report_path": None,
                    "run_id": self.run_id,
                    "run_dir": str(self.run_dir),
                    "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
                    "error": f"Claude Code exited with code {returncode}: {stderr}",
                }

            # Parse output
            result = self.parse_output(stdout)
            result["duration_seconds"] = (datetime.now(timezone.utc) - start_time).total_seconds()

            return result

        except Exception as e:
            return {
                "success": False,
                "result": "inconclusive",
                "hypothesis_tested": self.hypothesis,
                "observations": [],
                "not_reproducible_reason": None,
                "report_path": None,
                "run_id": self.run_id,
                "run_dir": str(self.run_dir),
                "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
                "error": f"Reproduction failed: {type(e).__name__}: {e}",
            }

        finally:
            # Always attempt container cleanup
            self.cleanup_containers()


def reproduce(hypothesis: str, source_container: str, context: Optional[dict] = None) -> dict:
    """
    Convenience function for simple reproduction tests.

    Args:
        hypothesis: What to test/reproduce
        source_container: Container name to use as reference environment
        context: Optional investigation context

    Returns:
        Dict with reproduction results
    """
    runner = ReproductionRunner(
        hypothesis=hypothesis,
        source_container=source_container,
        investigation_context=context,
    )
    return runner.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reproduction Runner")
    parser.add_argument("--hypothesis", required=True, help="Hypothesis to test")
    parser.add_argument("--source-container", required=True, help="Source container name")
    parser.add_argument("--context-json", help="Investigation context as JSON string")
    parser.add_argument("--signature-id", default="unknown", help="Signature ID")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")

    args = parser.parse_args()

    context = {}
    if args.context_json:
        try:
            context = json.loads(args.context_json)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Invalid context JSON: {e}"}))
            exit(1)

    runner = ReproductionRunner(
        hypothesis=args.hypothesis,
        source_container=args.source_container,
        investigation_context=context,
        signature_id=args.signature_id,
        timeout_seconds=args.timeout,
    )

    result = runner.run()
    print(json.dumps(result, indent=2))
