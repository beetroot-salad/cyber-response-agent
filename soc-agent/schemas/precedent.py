"""Precedent schema and validation.

Validates precedent JSON files in knowledge/signatures/*/precedents/.
Precedents are past resolved investigations used for pattern matching.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from schemas.enums import (
    VALID_DISPOSITIONS,
    VALID_HYPOTHESIS_STATUSES,
    VALID_STATUSES,
)

# Default maximum age (days) for a precedent to be considered fresh.
# Overridable per-signature via permissions.yaml `precedent_max_age_days`.
DEFAULT_MAX_AGE_DAYS = 90


@dataclass
class Hypothesis:
    """A hypothesis that was tested during the investigation."""
    id: str
    status: str  # active | confirmed | refuted | untested
    reasoning: str

    def validate(self) -> list[str]:
        errors = []
        if not self.id:
            errors.append("hypothesis id is required")
        if self.status not in VALID_HYPOTHESIS_STATUSES:
            errors.append(
                f"hypothesis status must be one of {VALID_HYPOTHESIS_STATUSES}, "
                f"got '{self.status}'"
            )
        return errors


@dataclass
class FlowStep:
    """A step in the investigation flow."""
    lead: str
    observation: str
    assessment: str  # e.g., "++ monitoring-probe, -- brute-force"

    def validate(self) -> list[str]:
        errors = []
        if not self.lead:
            errors.append("flow step lead is required")
        if not self.observation:
            errors.append("flow step observation is required")
        return errors


@dataclass
class Precedent:
    """A past investigation used as a reference for future triage."""
    ticket_id: str
    signature_id: str
    status: str  # resolved | escalated
    disposition: str  # benign | false_positive | true_positive | inconclusive
    hypotheses: list[Hypothesis]
    flow: list[FlowStep]
    trace: str
    reasoning: dict  # conditions (list[str]) + refutes (list[str])
    key_indicators: list[str]
    alert_data: dict  # raw alert fields from the original investigation
    validated_at: Optional[str] = None  # ISO 8601 date of last validation

    def validate(self) -> list[str]:
        """Validate the precedent. Returns list of error messages."""
        errors = []

        if not self.ticket_id:
            errors.append("ticket_id is required")
        if not self.signature_id:
            errors.append("signature_id is required")
        if self.status not in VALID_STATUSES:
            errors.append(
                f"status must be one of {VALID_STATUSES}, got '{self.status}'"
            )
        if self.disposition not in VALID_DISPOSITIONS:
            errors.append(
                f"disposition must be one of {VALID_DISPOSITIONS}, got '{self.disposition}'"
            )
        if not self.hypotheses:
            errors.append("at least one hypothesis is required")
        if not self.flow:
            errors.append("at least one flow step is required")
        if not self.trace:
            errors.append("trace is required")
        if not self.key_indicators:
            errors.append("at least one key_indicator is required")

        if not isinstance(self.alert_data, dict) or not self.alert_data:
            errors.append("alert_data must be a non-empty dict")

        for h in self.hypotheses:
            for err in h.validate():
                errors.append(f"hypothesis '{h.id}': {err}")

        for i, step in enumerate(self.flow):
            for err in step.validate():
                errors.append(f"flow step {i}: {err}")

        if not isinstance(self.reasoning, dict):
            errors.append("reasoning must be a dict with 'conditions' and 'refutes' keys")
        else:
            if "conditions" not in self.reasoning:
                errors.append("reasoning must have 'conditions' key")
            if "refutes" not in self.reasoning:
                errors.append("reasoning must have 'refutes' key")

        if self.validated_at:
            try:
                parse_validated_at(self.validated_at)
            except ValueError as e:
                errors.append(f"validated_at: {e}")
        else:
            errors.append("validated_at is required (ISO 8601 date, e.g. '2026-03-15')")

        if self.status == "resolved":
            confirmed = [h for h in self.hypotheses if h.status == "confirmed"]
            if not confirmed:
                errors.append(
                    "resolved precedent must have at least one confirmed hypothesis"
                )

        return errors


def parse_validated_at(value: str) -> datetime:
    """Parse a validated_at string to a datetime. Raises ValueError on bad format."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f"invalid date format: {value!r} (expected ISO 8601)")


def check_recency(validated_at: str, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> tuple[bool, str]:
    """Check whether a precedent is recent enough.

    Returns (is_fresh, message). message is empty when fresh.
    """
    try:
        dt = parse_validated_at(validated_at)
    except ValueError as e:
        return False, str(e)

    now = datetime.now(timezone.utc)
    age_days = (now - dt).days
    if age_days > max_age_days:
        return False, (
            f"precedent validated_at {validated_at} is {age_days} days old "
            f"(max {max_age_days})"
        )
    return True, ""


def parse_precedent(data: dict) -> tuple[Optional[Precedent], list[str]]:
    """Parse a dict into a Precedent. Returns (precedent, errors)."""
    errors = []

    required = ["ticket_id", "signature_id", "status", "disposition", "hypotheses", "flow", "trace", "reasoning", "key_indicators", "alert_data"]
    for f in required:
        if f not in data:
            errors.append(f"missing required field: {f}")

    if errors:
        return None, errors

    hypotheses = []
    for h in data.get("hypotheses", []):
        if isinstance(h, dict):
            hypotheses.append(Hypothesis(
                id=h.get("id", ""),
                status=h.get("status", ""),
                reasoning=h.get("reasoning", ""),
            ))

    flow_steps = []
    for step in data.get("flow", []):
        if isinstance(step, dict):
            flow_steps.append(FlowStep(
                lead=step.get("lead", ""),
                observation=step.get("observation", ""),
                assessment=step.get("assessment", ""),
            ))

    precedent = Precedent(
        ticket_id=data["ticket_id"],
        signature_id=data["signature_id"],
        status=data["status"],
        disposition=data["disposition"],
        hypotheses=hypotheses,
        flow=flow_steps,
        trace=data.get("trace", ""),
        reasoning=data.get("reasoning", {}),
        key_indicators=data.get("key_indicators", []),
        alert_data=data.get("alert_data", {}),
        validated_at=data.get("validated_at"),
    )

    validation_errors = precedent.validate()
    errors.extend(validation_errors)

    return precedent, errors
