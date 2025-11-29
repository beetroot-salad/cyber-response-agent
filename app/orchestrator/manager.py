"""
Orchestrator Manager - Pure manager that invokes investigation agent.

Responsibilities:
- Receive alert data
- Validate input
- Invoke investigation agent subprocess
- Parse structured JSON response
- Calculate confidence score
- Make routing decision
- Log audit trail

Does NOT:
- Build investigation prompts (agent's job)
- Fetch context/knowledge (agent's job)
- Query SIEM (agent's job)
"""

import json
import logging
from typing import Optional

from .confidence import calculate_confidence, get_decision
from app.config.logging_config import log_event, setup_logging
from .models import (
    AgentFindings,
    AlertData,
    Decision,
    Disposition,
    InvestigationSummary,
    utc_now,
)

# Import investigator directly
from app.agent.investigation.investigate import investigate as run_investigation


class InvestigationError(Exception):
    """Raised when investigation fails."""

    pass


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def validate_alert_data(alert_data: dict) -> AlertData:
    """
    Validate and parse alert data into AlertData.

    Args:
        alert_data: Raw alert dictionary

    Returns:
        Validated AlertData instance

    Raises:
        ValidationError: If validation fails
    """
    if not alert_data:
        raise ValidationError("alert_data is required")
    if not isinstance(alert_data, dict):
        raise ValidationError("alert_data must be a dictionary")

    try:
        return AlertData.from_dict(alert_data)
    except ValueError as e:
        raise ValidationError(str(e))


def invoke_agent(
    alert: AlertData,
    logger: Optional[logging.Logger] = None,
) -> dict:
    """
    Invoke investigation agent directly via Python import.

    Args:
        alert: Validated alert data
        logger: Logger for audit events

    Returns:
        Agent findings as dictionary

    Raises:
        InvestigationError: If agent fails
    """
    if logger:
        log_event(
            logger,
            event="agent_invoked",
            message=f"Invoking investigation agent for {alert.ticket_id}",
            ticket_id=alert.ticket_id,
            signature_id=alert.signature_id,
            data={"alert": alert.to_dict()},
        )

    try:
        result = run_investigation(
            ticket_id=alert.ticket_id,
            signature_id=alert.signature_id,
            alert_data=alert.to_dict(),
        )

        if logger:
            log_event(
                logger,
                event="agent_completed",
                message=f"Agent completed for {alert.ticket_id}",
                ticket_id=alert.ticket_id,
                signature_id=alert.signature_id,
            )

        return result

    except Exception as e:
        if logger:
            log_event(
                logger,
                event="agent_error",
                message=f"Agent error for {alert.ticket_id}: {e}",
                ticket_id=alert.ticket_id,
                signature_id=alert.signature_id,
                data={"error": str(e)},
                level=logging.ERROR,
            )
        raise InvestigationError(f"Agent failed: {e}")


def parse_agent_response(response: dict) -> AgentFindings:
    """
    Parse the agent's response dict into AgentFindings.

    Args:
        response: Dictionary from agent

    Returns:
        AgentFindings dataclass

    Raises:
        InvestigationError: If parsing fails
    """
    if not response:
        raise InvestigationError("Agent returned empty response")

    if not isinstance(response, dict):
        raise InvestigationError(f"Agent returned non-dict response: {type(response)}")

    return AgentFindings.from_json(response)


def determine_disposition(decision: Decision, findings: AgentFindings) -> Disposition:
    """
    Determine disposition based on decision and agent's recommendation.

    Args:
        decision: Orchestrator's routing decision
        findings: Agent findings including recommendation

    Returns:
        Disposition enum value
    """
    if decision == Decision.ESCALATE:
        return Disposition.ESCALATED

    if decision == Decision.REPRODUCE:
        return Disposition.INCONCLUSIVE

    # AUTO_CLOSE - use agent's recommendation
    recommendation = findings.recommendation.lower()
    if recommendation == "true_positive":
        return Disposition.TRUE_POSITIVE
    elif recommendation == "false_positive":
        return Disposition.FALSE_POSITIVE
    elif recommendation == "benign":
        return Disposition.BENIGN
    else:
        # Fallback - shouldn't happen if agent is well-behaved
        return Disposition.BENIGN


def process_alert(
    alert_data: dict,
    asset_criticality: str = "standard",
    reproduction_result: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> InvestigationSummary:
    """
    Process a security alert through the investigation pipeline.

    This is the main entry point for the orchestrator.

    Args:
        alert_data: Raw alert data from SIEM (must include ticket_id, signature_id, agent)
        asset_criticality: "standard", "elevated", or "critical"
        reproduction_result: "confirmed", "refuted", or None
        logger: Logger for audit events

    Returns:
        InvestigationSummary with decision and audit trail
    """
    if logger is None:
        logger = setup_logging()

    started_at = utc_now()

    # Placeholder alert for error cases
    error_alert = AlertData(
        ticket_id=alert_data.get("ticket_id", "UNKNOWN"),
        signature_id=alert_data.get("signature_id", "UNKNOWN"),
        timestamp=utc_now(),
        agent=alert_data.get("agent", "UNKNOWN"),
        raw=alert_data,
    )

    try:
        # 1. Validate and parse alert
        alert = validate_alert_data(alert_data)

        # Log investigation start
        log_event(
            logger,
            event="investigation_started",
            message=f"Starting investigation for {alert.ticket_id}",
            ticket_id=alert.ticket_id,
            signature_id=alert.signature_id,
            data={"alert": alert.to_dict(), "asset_criticality": asset_criticality},
        )

        # 2. Invoke agent
        response = invoke_agent(alert, logger)

        # 3. Parse response
        findings = parse_agent_response(response)

        log_event(
            logger,
            event="findings_parsed",
            message=f"Parsed findings for {alert.ticket_id}",
            ticket_id=alert.ticket_id,
            signature_id=alert.signature_id,
            data=findings.to_dict(),
        )

        # 4. Calculate confidence
        confidence = calculate_confidence(
            matched_tier=findings.matched_tier,
            reproduction_result=reproduction_result,
            asset_criticality=asset_criticality,
        )

        log_event(
            logger,
            event="confidence_calculated",
            message=f"Confidence for {alert.ticket_id}: {confidence:.2f}",
            ticket_id=alert.ticket_id,
            signature_id=alert.signature_id,
            data={"confidence": confidence, "asset_criticality": asset_criticality},
        )

        # 5. Make decision
        decision = get_decision(confidence, findings.matched_ticket is not None)

        # 6. Determine disposition
        disposition = determine_disposition(decision, findings)

        summary = InvestigationSummary(
            alert=alert,
            findings=findings,
            confidence_score=confidence,
            decision=decision,
            disposition=disposition,
            started_at=started_at,
            completed_at=utc_now(),
        )

        log_event(
            logger,
            event="investigation_completed",
            message=f"Investigation completed for {alert.ticket_id}: {decision.value}",
            ticket_id=alert.ticket_id,
            signature_id=alert.signature_id,
            data={
                "decision": decision.value,
                "disposition": disposition.value,
                "confidence": confidence,
                "duration_ms": summary.duration_ms,
            },
        )

        return summary

    except ValidationError as e:
        log_event(
            logger,
            event="validation_failed",
            message=f"Validation failed: {e}",
            ticket_id=error_alert.ticket_id,
            signature_id=error_alert.signature_id,
            data={"error": str(e)},
            level=logging.ERROR,
        )

        return InvestigationSummary(
            alert=error_alert,
            findings=AgentFindings(),
            confidence_score=0.0,
            decision=Decision.ESCALATE,
            disposition=Disposition.ESCALATED,
            started_at=started_at,
            completed_at=utc_now(),
            error=f"Validation error: {e}",
        )

    except InvestigationError as e:
        log_event(
            logger,
            event="investigation_failed",
            message=f"Investigation failed for {error_alert.ticket_id}: {e}",
            ticket_id=error_alert.ticket_id,
            signature_id=error_alert.signature_id,
            data={"error": str(e)},
            level=logging.ERROR,
        )

        return InvestigationSummary(
            alert=error_alert,
            findings=AgentFindings(),
            confidence_score=0.0,
            decision=Decision.ESCALATE,
            disposition=Disposition.ESCALATED,
            started_at=started_at,
            completed_at=utc_now(),
            error=str(e),
        )

    except Exception as e:
        log_event(
            logger,
            event="investigation_error",
            message=f"Unexpected error for {error_alert.ticket_id}: {e}",
            ticket_id=error_alert.ticket_id,
            signature_id=error_alert.signature_id,
            data={"error": str(e), "error_type": type(e).__name__},
            level=logging.ERROR,
        )

        return InvestigationSummary(
            alert=error_alert,
            findings=AgentFindings(),
            confidence_score=0.0,
            decision=Decision.ESCALATE,
            disposition=Disposition.ESCALATED,
            started_at=started_at,
            completed_at=utc_now(),
            error=f"Unexpected error: {type(e).__name__}: {e}",
        )
