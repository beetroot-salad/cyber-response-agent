"""
Data models for the orchestrator.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
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
class AgentFindings:
    """Structured findings returned by the investigation agent."""

    precedent_matched: Optional[str] = None
    precedent_tier: Optional[str] = None  # "gold", "silver", "bronze", or None
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
class AlertData:
    """Validated alert data from SIEM."""

    srcip: str
    srcuser: str
    agent: str
    rule_id: int
    timestamp: datetime
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "AlertData":
        """Parse and validate alert data from dictionary."""
        # Required fields
        required = ["srcip", "srcuser", "agent", "rule_id"]
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

        return cls(
            srcip=str(data["srcip"]),
            srcuser=str(data["srcuser"]),
            agent=str(data["agent"]),
            rule_id=int(data["rule_id"]),
            timestamp=timestamp,
            raw=data,
        )

    def to_dict(self) -> dict:
        return {
            "srcip": self.srcip,
            "srcuser": self.srcuser,
            "agent": self.agent,
            "rule_id": self.rule_id,
            "timestamp": self.timestamp.isoformat(),
            "raw": self.raw,
        }


@dataclass
class InvestigationResult:
    """Complete result of an investigation, including orchestrator decision."""

    # Input
    ticket_id: str
    signature_id: str
    alert_data: dict

    # Agent findings
    findings: AgentFindings

    # Orchestrator decision
    confidence_score: float
    decision: Decision
    disposition: Optional[Disposition] = None

    # Metadata
    started_at: datetime = field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    def to_audit_dict(self) -> dict:
        """Format as audit log entry."""
        return {
            "timestamp": utc_now().isoformat(),
            "event": "investigation_complete",
            "ticket_id": self.ticket_id,
            "signature_id": self.signature_id,
            "alert_data": self.alert_data,
            "findings": self.findings.to_dict(),
            "confidence_score": self.confidence_score,
            "decision": self.decision.value if isinstance(self.decision, Decision) else self.decision,
            "disposition": self.disposition.value if isinstance(self.disposition, Disposition) else self.disposition,
            "duration_ms": int((self.completed_at - self.started_at).total_seconds() * 1000) if self.completed_at else None,
            "error": self.error,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_audit_dict(), indent=2)
