"""
Cyber Response Agent Orchestrator

Pure manager that invokes Claude Code agent and processes results.
Does NOT fetch context - that's the agent's job.
"""

from .confidence import calculate_confidence, get_decision
from .logging_config import log_event, setup_logging
from .manager import (
    InvestigationError,
    ValidationError,
    process_ticket,
)
from .models import (
    AgentFindings,
    AlertData,
    Decision,
    Disposition,
    InvestigationResult,
    PrecedentTier,
)

__all__ = [
    # Confidence
    "calculate_confidence",
    "get_decision",
    # Logging
    "log_event",
    "setup_logging",
    # Manager
    "InvestigationError",
    "ValidationError",
    "process_ticket",
    # Models
    "AgentFindings",
    "AlertData",
    "Decision",
    "Disposition",
    "InvestigationResult",
    "PrecedentTier",
]
