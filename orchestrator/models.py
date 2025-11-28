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


class PrecedentTier(Enum):
    """Quality tiers for precedents."""

    GOLD = "gold"
    SILVER = "silver"
    BRONZE = "bronze"


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

    Fields:
        precedent_matched: ID of the matched precedent from the signature's
            knowledge (e.g., "prec-5710-001"). None if no match.
        precedent_tier: Quality tier of matched precedent ("gold", "silver", "bronze").
        conditions_met: Number of "safe_when" or "escalate_when" conditions
            satisfied for the matched precedent.
        conditions_total: Total conditions defined for the matched precedent.
        evidence_available: Whether the agent successfully gathered required
            evidence (e.g., SIEM queries returned data, files were readable).
        findings: List of observations made during investigation.
        reasoning: Explanation of why precedent matched or didn't match.
    """

    precedent_matched: Optional[str] = None
    precedent_tier: Optional[str] = None
    conditions_met: int = 0
    conditions_total: int = 0
    evidence_available: bool = False
    findings: list[str] = field(default_factory=list)
    reasoning: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "AgentFindings":
        """Parse agent JSON response into AgentFindings."""
        return cls(
            precedent_matched=data.get("precedent_matched"),
            precedent_tier=data.get("precedent_tier"),
            conditions_met=data.get("conditions_met", 0),
            conditions_total=data.get("conditions_total", 0),
            evidence_available=data.get("evidence_available", False),
            findings=data.get("findings", []),
            reasoning=data.get("reasoning", ""),
        )

    def to_dict(self) -> dict:
        return {
            "precedent_matched": self.precedent_matched,
            "precedent_tier": self.precedent_tier,
            "conditions_met": self.conditions_met,
            "conditions_total": self.conditions_total,
            "evidence_available": self.evidence_available,
            "findings": self.findings,
            "reasoning": self.reasoning,
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


