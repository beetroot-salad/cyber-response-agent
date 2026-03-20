"""Precedent schema and validation.

Validates precedent JSON files in knowledge/signatures/*/precedents/.
Precedents are past resolved investigations used for pattern matching.
"""

from dataclasses import dataclass
from typing import Optional


VALID_DISPOSITIONS = ("benign", "false_positive", "true_positive", "escalated")
VALID_HYPOTHESIS_STATUSES = ("confirmed", "refuted", "untested")


@dataclass
class Hypothesis:
    """A hypothesis that was tested during the investigation."""
    id: str
    status: str  # confirmed | refuted | untested
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
    disposition: str
    hypotheses: list[Hypothesis]
    flow: list[FlowStep]
    trace: str
    reasoning: dict  # conditions (list[str]) + refutes (list[str])
    key_indicators: list[str]

    def validate(self) -> list[str]:
        """Validate the precedent. Returns list of error messages."""
        errors = []

        if not self.ticket_id:
            errors.append("ticket_id is required")
        if not self.signature_id:
            errors.append("signature_id is required")
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

        if self.disposition != "escalated":
            confirmed = [h for h in self.hypotheses if h.status == "confirmed"]
            if not confirmed:
                errors.append(
                    "non-escalated precedent must have at least one confirmed hypothesis"
                )

        return errors


def parse_precedent(data: dict) -> tuple[Optional[Precedent], list[str]]:
    """Parse a dict into a Precedent. Returns (precedent, errors)."""
    errors = []

    required = ["ticket_id", "signature_id", "disposition", "hypotheses", "flow", "trace", "reasoning", "key_indicators"]
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
        disposition=data["disposition"],
        hypotheses=hypotheses,
        flow=flow_steps,
        trace=data.get("trace", ""),
        reasoning=data.get("reasoning", {}),
        key_indicators=data.get("key_indicators", []),
    )

    validation_errors = precedent.validate()
    errors.extend(validation_errors)

    return precedent, errors
