"""
Data models for the orchestrator.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


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
    decision: str  # "auto_close", "reproduce", "escalate"
    disposition: Optional[str] = None  # "benign", "escalated", etc.

    # Metadata
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    def to_audit_log(self) -> dict:
        """Format as audit log entry for stdout."""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "investigation_complete",
            "ticket_id": self.ticket_id,
            "signature_id": self.signature_id,
            "alert_data": self.alert_data,
            "findings": self.findings.to_dict(),
            "confidence_score": self.confidence_score,
            "decision": self.decision,
            "disposition": self.disposition,
            "duration_ms": int((self.completed_at - self.started_at).total_seconds() * 1000) if self.completed_at else None,
            "error": self.error,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_audit_log(), indent=2)
