"""
Data models for the orchestrator.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import json


class Disposition(Enum):
    """Possible dispositions for a security alert."""

    TRUE_POSITIVE = "true_positive"  # Confirmed security incident
    FALSE_POSITIVE = "false_positive"  # Alert fired but no actual threat
    BENIGN = "benign"  # Activity is legitimate/expected
    ESCALATED = "escalated"  # Requires human review
    INCONCLUSIVE = "inconclusive"  # Unable to determine


class Decision(Enum):
    """Routing decisions made by the orchestrator."""

    AUTO_CLOSE = "auto_close"  # Close automatically
    REPRODUCE = "reproduce"  # Run reproduction agent
    ESCALATE = "escalate"  # Escalate to human


def utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


@dataclass
class AlertData:
    """
    Alert metadata from SIEM.

    Core fields are explicit, incident-specific fields go in `raw`.
    """

    # Core metadata
    ticket_id: str
    signature_id: str
    timestamp: datetime
    agent: str  # Host/agent where alert originated

    # Flexible incident data (srcip, srcuser, etc.)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "AlertData":
        """Parse and validate alert data from dictionary."""
        # Required metadata fields
        required = ["ticket_id", "signature_id", "agent"]
        missing = [f for f in required if f not in data]
        if missing:
            raise ValueError(f"Missing required alert fields: {missing}")

        # Parse timestamp
        ts = data.get("timestamp")
        if isinstance(ts, str):
            timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif isinstance(ts, datetime):
            timestamp = ts
        else:
            timestamp = utc_now()

        # Everything except core fields goes into raw
        core_fields = {"ticket_id", "signature_id", "timestamp", "agent"}
        raw = {k: v for k, v in data.items() if k not in core_fields}

        return cls(
            ticket_id=str(data["ticket_id"]),
            signature_id=str(data["signature_id"]),
            timestamp=timestamp,
            agent=str(data["agent"]),
            raw=raw,
        )

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "signature_id": self.signature_id,
            "timestamp": self.timestamp.isoformat(),
            "agent": self.agent,
            **self.raw,  # Flatten raw into output
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get a field from raw data."""
        return self.raw.get(key, default)


@dataclass
class AgentFindings:
    """
    Structured findings returned by the investigation agent.

    The agent synthesizes evidence and provides a recommendation.
    The orchestrator performs sanity checks and handles engineering concerns
    (logging, error handling, reproduction triggers).

    Fields:
        recommendation: Agent's recommended disposition ("benign", "false_positive",
            "true_positive", "escalate"). The orchestrator may override this.
        matched_ticket: ID of a similar past ticket that informed the recommendation
            (e.g., "SEC-2024-001"). None if no precedent found.
        matched_tier: Quality tier from matched ticket ("gold", "silver", "bronze").
            Used by orchestrator for confidence calculation.
        reasoning: Free-form explanation of the verdict. Should include:
            - Why this disposition was chosen
            - What evidence supports it
            - Reference to matched ticket if applicable
            Example: "False positive - maintenance job. Recurring weekly pattern
            matching SEC-2024-001. Same signature, user (svc-backup), and srcip (10.0.3.25)."
        evidence: Dict mapping evidence type to pointer/reference. Encourages reuse
            of utilities. Keys are evidence types, values are references.
            Example: {"auth_logs": "wazuh:5710:last_24h", "ip_class": "internal:rfc1918"}
    """

    recommendation: str = "escalate"  # Default safe: escalate if unsure
    matched_ticket: Optional[str] = None
    matched_tier: Optional[str] = None
    reasoning: str = ""
    evidence: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> "AgentFindings":
        """Parse agent JSON response into AgentFindings."""
        return cls(
            recommendation=data.get("recommendation", "escalate"),
            matched_ticket=data.get("matched_ticket"),
            matched_tier=data.get("matched_tier"),
            reasoning=data.get("reasoning", ""),
            evidence=data.get("evidence", {}),
        )

    def to_dict(self) -> dict:
        return {
            "recommendation": self.recommendation,
            "matched_ticket": self.matched_ticket,
            "matched_tier": self.matched_tier,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
        }


@dataclass
class InvestigationSummary:
    """
    Complete summary of an investigation, including orchestrator decision.

    This is the final output of the investigation pipeline.
    """

    # Input alert
    alert: AlertData

    # Agent findings
    findings: AgentFindings

    # Orchestrator decision
    confidence_score: float
    decision: Decision
    disposition: Optional[Disposition] = None

    # Timing
    started_at: datetime = field(default_factory=utc_now)
    completed_at: Optional[datetime] = None

    # Error (if any)
    error: Optional[str] = None

    @property
    def ticket_id(self) -> str:
        return self.alert.ticket_id

    @property
    def signature_id(self) -> str:
        return self.alert.signature_id

    @property
    def duration_ms(self) -> Optional[int]:
        if self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds() * 1000)
        return None

    def to_audit_dict(self) -> dict:
        """Format as audit log entry."""
        return {
            "timestamp": utc_now().isoformat(),
            "event": "investigation_summary",
            "ticket_id": self.ticket_id,
            "signature_id": self.signature_id,
            "alert": self.alert.to_dict(),
            "findings": self.findings.to_dict(),
            "confidence_score": self.confidence_score,
            "decision": self.decision.value if isinstance(self.decision, Decision) else self.decision,
            "disposition": self.disposition.value if isinstance(self.disposition, Disposition) else self.disposition,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_audit_dict(), indent=2)


