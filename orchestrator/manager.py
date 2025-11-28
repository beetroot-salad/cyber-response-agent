"""
Orchestrator Manager - Pure manager that invokes investigation agent.

Responsibilities:
- Receive ticket (alert data)
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
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .confidence import calculate_confidence, get_decision
from .logging_config import log_event, setup_logging
from .models import (
    AgentFindings,
    Decision,
    Disposition,
    InvestigationResult,
    utc_now,
)


# Configuration
AGENT_SCRIPT = Path("/workspace/agent/investigation/investigate.py")
DEFAULT_TIMEOUT_SECONDS = 600  # 10 minutes
MAX_TIMEOUT_SECONDS = 1800  # 30 minutes


class InvestigationError(Exception):
    """Raised when investigation fails."""

    pass


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def validate_ticket_id(ticket_id: str) -> str:
    """Validate and sanitize ticket ID."""
    if not ticket_id:
        raise ValidationError("ticket_id is required")
    if not isinstance(ticket_id, str):
        raise ValidationError("ticket_id must be a string")
    # Basic sanitization - alphanumeric, dash, underscore only
    sanitized = "".join(c for c in ticket_id if c.isalnum() or c in "-_")
    if len(sanitized) != len(ticket_id):
        raise ValidationError("ticket_id contains invalid characters")
    if len(sanitized) > 100:
        raise ValidationError("ticket_id too long (max 100 chars)")
    return sanitized


def validate_signature_id(signature_id: str) -> str:
    """Validate and sanitize signature ID."""
    if not signature_id:
        raise ValidationError("signature_id is required")
    if not isinstance(signature_id, str):
        raise ValidationError("signature_id must be a string")
    # Basic sanitization - alphanumeric, dash, underscore only
    sanitized = "".join(c for c in signature_id if c.isalnum() or c in "-_")
    if len(sanitized) != len(signature_id):
        raise ValidationError("signature_id contains invalid characters")
    if len(sanitized) > 100:
        raise ValidationError("signature_id too long (max 100 chars)")
    return sanitized


def validate_alert_data(alert_data: dict) -> dict:
    """Validate alert data structure."""
    if not alert_data:
        raise ValidationError("alert_data is required")
    if not isinstance(alert_data, dict):
        raise ValidationError("alert_data must be a dictionary")

    # Required fields for SSH alerts
    required_fields = ["srcip", "srcuser"]
    missing = [f for f in required_fields if f not in alert_data]
    if missing:
        raise ValidationError(f"alert_data missing required fields: {missing}")

    return alert_data


def invoke_agent(
    ticket_id: str,
    signature_id: str,
    alert_data: dict,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    logger: logging.Logger = None,
) -> str:
    """
    Invoke investigation agent as subprocess.

    Args:
        ticket_id: Ticket identifier
        signature_id: Alert signature ID
        alert_data: Alert data dictionary
        timeout: Maximum time in seconds
        logger: Logger for audit events

    Returns:
        Agent's JSON response as string

    Raises:
        InvestigationError: If agent fails
    """
    if timeout > MAX_TIMEOUT_SECONDS:
        timeout = MAX_TIMEOUT_SECONDS

    alert_json = json.dumps(alert_data)

    cmd = [
        sys.executable,
        str(AGENT_SCRIPT),
        "--ticket-id",
        ticket_id,
        "--signature-id",
        signature_id,
        "--alert-json",
        alert_json,
    ]

    if logger:
        log_event(
            logger,
            event="agent_invoked",
            message=f"Invoking investigation agent for {ticket_id}",
            ticket_id=ticket_id,
            signature_id=signature_id,
            data={"timeout": timeout, "alert_data": alert_data},
        )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(AGENT_SCRIPT.parent),
        )

        if logger:
            log_event(
                logger,
                event="agent_completed",
                message=f"Agent completed for {ticket_id}",
                ticket_id=ticket_id,
                signature_id=signature_id,
                data={
                    "return_code": result.returncode,
                    "stdout_length": len(result.stdout),
                    "stderr_length": len(result.stderr),
                },
            )

        if result.returncode != 0:
            raise InvestigationError(f"Agent failed with code {result.returncode}: {result.stderr}")

        return result.stdout

    except subprocess.TimeoutExpired:
        if logger:
            log_event(
                logger,
                event="agent_timeout",
                message=f"Agent timed out for {ticket_id}",
                ticket_id=ticket_id,
                signature_id=signature_id,
                data={"timeout": timeout},
                level=logging.ERROR,
            )
        raise InvestigationError(f"Agent timed out after {timeout} seconds")


def parse_agent_response(response: str) -> AgentFindings:
    """
    Parse the agent's JSON response into AgentFindings.

    Args:
        response: JSON string from agent

    Returns:
        AgentFindings dataclass

    Raises:
        InvestigationError: If parsing fails
    """
    response = response.strip()

    # Handle empty response
    if not response:
        raise InvestigationError("Agent returned empty response")

    try:
        data = json.loads(response)
        return AgentFindings.from_json(data)
    except json.JSONDecodeError as e:
        raise InvestigationError(f"Failed to parse agent response: {e}. Response: {response[:200]}")


def determine_disposition(decision: Decision, findings: AgentFindings) -> Disposition:
    """
    Determine disposition based on decision and findings.

    Args:
        decision: Routing decision
        findings: Agent findings

    Returns:
        Disposition enum value
    """
    if decision == Decision.ESCALATE:
        return Disposition.ESCALATED

    if decision == Decision.REPRODUCE:
        return Disposition.INCONCLUSIVE

    # AUTO_CLOSE - determine if benign or false positive based on findings
    if findings.precedent_matched:
        # Check if precedent indicates true positive or false positive
        precedent = findings.precedent_matched.lower()
        if "brute" in precedent or "attack" in precedent:
            return Disposition.TRUE_POSITIVE
        else:
            return Disposition.FALSE_POSITIVE

    return Disposition.BENIGN


def process_ticket(
    ticket_id: str,
    signature_id: str,
    alert_data: dict,
    asset_criticality: str = "standard",
    reproduction_result: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    logger: logging.Logger = None,
) -> InvestigationResult:
    """
    Process a security ticket through the investigation pipeline.

    This is the main entry point for the orchestrator.

    Args:
        ticket_id: Unique ticket identifier
        signature_id: The alert signature (e.g., "wazuh-rule-5710")
        alert_data: Raw alert data from SIEM
        asset_criticality: "standard", "elevated", or "critical"
        reproduction_result: "confirmed", "refuted", or None
        timeout: Agent timeout in seconds
        logger: Logger for audit events

    Returns:
        InvestigationResult with decision and audit trail
    """
    if logger is None:
        logger = setup_logging()

    started_at = utc_now()

    # Log investigation start
    log_event(
        logger,
        event="investigation_started",
        message=f"Starting investigation for {ticket_id}",
        ticket_id=ticket_id,
        signature_id=signature_id,
        data={"alert_data": alert_data, "asset_criticality": asset_criticality},
    )

    try:
        # 1. Validate inputs
        ticket_id = validate_ticket_id(ticket_id)
        signature_id = validate_signature_id(signature_id)
        alert_data = validate_alert_data(alert_data)

        # 2. Invoke agent
        response = invoke_agent(ticket_id, signature_id, alert_data, timeout, logger)

        # 3. Parse response
        findings = parse_agent_response(response)

        log_event(
            logger,
            event="findings_parsed",
            message=f"Parsed findings for {ticket_id}",
            ticket_id=ticket_id,
            signature_id=signature_id,
            data=findings.to_dict(),
        )

        # 4. Calculate confidence
        confidence = calculate_confidence(
            precedent_tier=findings.precedent_tier,
            conditions_met=findings.conditions_met,
            conditions_total=findings.conditions_total,
            evidence_available=findings.evidence_available,
            reproduction_result=reproduction_result,
            asset_criticality=asset_criticality,
        )

        log_event(
            logger,
            event="confidence_calculated",
            message=f"Confidence for {ticket_id}: {confidence:.2f}",
            ticket_id=ticket_id,
            signature_id=signature_id,
            data={"confidence": confidence, "asset_criticality": asset_criticality},
        )

        # 5. Make decision
        decision = get_decision(confidence, findings.precedent_matched is not None)

        # 6. Determine disposition
        disposition = determine_disposition(decision, findings)

        result = InvestigationResult(
            ticket_id=ticket_id,
            signature_id=signature_id,
            alert_data=alert_data,
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
            message=f"Investigation completed for {ticket_id}: {decision.value}",
            ticket_id=ticket_id,
            signature_id=signature_id,
            data={
                "decision": decision.value,
                "disposition": disposition.value,
                "confidence": confidence,
                "duration_ms": int((result.completed_at - result.started_at).total_seconds() * 1000),
            },
        )

        return result

    except (ValidationError, InvestigationError) as e:
        log_event(
            logger,
            event="investigation_failed",
            message=f"Investigation failed for {ticket_id}: {e}",
            ticket_id=ticket_id,
            signature_id=signature_id,
            data={"error": str(e)},
            level=logging.ERROR,
        )

        return InvestigationResult(
            ticket_id=ticket_id,
            signature_id=signature_id,
            alert_data=alert_data,
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
            message=f"Unexpected error for {ticket_id}: {e}",
            ticket_id=ticket_id,
            signature_id=signature_id,
            data={"error": str(e), "error_type": type(e).__name__},
            level=logging.ERROR,
        )

        return InvestigationResult(
            ticket_id=ticket_id,
            signature_id=signature_id,
            alert_data=alert_data,
            findings=AgentFindings(),
            confidence_score=0.0,
            decision=Decision.ESCALATE,
            disposition=Disposition.ESCALATED,
            started_at=started_at,
            completed_at=utc_now(),
            error=f"Unexpected error: {type(e).__name__}: {e}",
        )
