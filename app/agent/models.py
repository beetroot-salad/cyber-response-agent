"""
Shared data models for agent communication.

These models define the contracts between agents (investigation, reproduction, etc.)
and are intentionally minimal to allow flexibility while maintaining structure.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ReproductionRequest:
    """
    Schema for triggering reproduction - used by both investigation and direct requests.

    The hypothesis is natural language and should include environment context when relevant.
    Example: "On target-endpoint container, the benign_activity.sh script creates
    /tmp/backup-*.tar.gz files when executed via cron."

    Attributes:
        ticket_id: Case identifier. Agent can fetch alert details if needed.
        hypothesis: Natural language hypothesis to test. Should describe what
            behavior to reproduce and in what environment context.
        signature_id: Optional. Links to signature knowledge and permissions.
            If not provided, agent uses generic reproduction approach.
        context_url: Optional. Path or URL to investigation artifacts.
            Examples:
              - file:///workspace/app/agent/investigation/runs/ABC123/
              - s3://bucket/investigations/ABC123/
            If not provided, agent works without prior investigation context.
        environment_hint: Optional hint about the environment (container name,
            VM ID, k8s pod, etc.). If not provided, agent infers from hypothesis.
        timeout_seconds: Maximum time for reproduction. Default 300s (5 min).
    """

    # Required
    ticket_id: str
    hypothesis: str

    # Optional context
    signature_id: Optional[str] = None
    context_url: Optional[str] = None
    environment_hint: Optional[str] = None

    # Overrides
    timeout_seconds: int = 300

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "ticket_id": self.ticket_id,
            "hypothesis": self.hypothesis,
            "signature_id": self.signature_id,
            "context_url": self.context_url,
            "environment_hint": self.environment_hint,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReproductionRequest":
        """Deserialize from dictionary."""
        return cls(
            ticket_id=data["ticket_id"],
            hypothesis=data["hypothesis"],
            signature_id=data.get("signature_id"),
            context_url=data.get("context_url"),
            environment_hint=data.get("environment_hint"),
            timeout_seconds=data.get("timeout_seconds", 300),
        )


@dataclass
class ReproductionResult:
    """
    Result from reproduction agent.

    Attributes:
        success: Whether reproduction completed without errors.
        result: Outcome - "confirmed", "refuted", or "inconclusive".
        hypothesis_tested: The hypothesis that was actually tested (may differ
            slightly from input if agent refined it).
        observations: List of what was observed during reproduction.
        not_reproducible_reason: If result is inconclusive, explains why
            reproduction couldn't be completed.
        report_url: Path/URL to detailed reproduction report.
        run_id: Unique identifier for this reproduction run.
        run_url: Path/URL to the reproduction run directory.
        duration_seconds: How long reproduction took.
        error: Error message if success is False.
    """

    success: bool
    result: str = "inconclusive"  # confirmed, refuted, inconclusive
    hypothesis_tested: str = ""
    observations: list[str] = field(default_factory=list)
    not_reproducible_reason: Optional[str] = None
    report_url: Optional[str] = None
    run_id: str = ""
    run_url: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "success": self.success,
            "result": self.result,
            "hypothesis_tested": self.hypothesis_tested,
            "observations": self.observations,
            "not_reproducible_reason": self.not_reproducible_reason,
            "report_url": self.report_url,
            "run_id": self.run_id,
            "run_url": self.run_url,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReproductionResult":
        """Deserialize from dictionary."""
        return cls(
            success=data.get("success", False),
            result=data.get("result", "inconclusive"),
            hypothesis_tested=data.get("hypothesis_tested", ""),
            observations=data.get("observations", []),
            not_reproducible_reason=data.get("not_reproducible_reason"),
            report_url=data.get("report_url"),
            run_id=data.get("run_id", ""),
            run_url=data.get("run_url"),
            duration_seconds=data.get("duration_seconds", 0.0),
            error=data.get("error"),
        )
