"""Precedent schema and validation.

Validates precedent JSON files living next to their parent archetype under
`knowledge/signatures/{sig}/archetypes/{archetype}/{TICKET-ID}.json`.

A precedent is a cached pointer to a real past ticket that was closed under
a particular archetype. The source of truth is the ticketing system; this
KB file is a snapshot used for pattern-matching and few-shot grounding.
Precedents age — recency is enforced via `captured_at` — and stale entries
are replaced, not refreshed in place.

Shape:

    Precedent {
        ticket_id        # pointer into the source-of-truth ticketing system
        archetype        # name of the parent archetype (matches dir name)
        captured_at      # ISO 8601 date when this snapshot was taken
        alert            # raw alert snapshot as it was at ticket close
        disposition      # benign | false_positive | true_positive | inconclusive
        anchors_at_time  # list of { anchor, result, citation } seen at close
        narrative        # short prose: why this instance matched the archetype
    }
"""

from dataclasses import dataclass, field
from datetime import datetime, UTC

from schemas.enums import (
    VALID_CONSULTATION_RESULTS,
    VALID_DISPOSITIONS,
)

# Default maximum age (days) for a precedent to be considered fresh.
# Overridable per-signature via permissions.yaml `precedent_max_age_days`.
DEFAULT_MAX_AGE_DAYS = 90


@dataclass
class Precedent:
    """A cached ticket snapshot used as a reference for future triage."""
    ticket_id: str
    archetype: str
    disposition: str  # benign | false_positive | true_positive | inconclusive
    narrative: str
    alert: dict
    anchors_at_time: list = field(default_factory=list)
    captured_at: str | None = None  # ISO 8601 date — required at validate time

    def validate(self) -> list[str]:
        """Validate the precedent. Returns list of error messages."""
        errors = []

        if not self.ticket_id:
            errors.append("ticket_id is required")
        if not self.archetype:
            errors.append("archetype is required")
        if self.disposition not in VALID_DISPOSITIONS:
            errors.append(
                f"disposition must be one of {VALID_DISPOSITIONS}, "
                f"got '{self.disposition}'"
            )
        if not self.narrative:
            errors.append("narrative is required")

        if not isinstance(self.alert, dict) or not self.alert:
            errors.append("alert must be a non-empty dict")

        if not isinstance(self.anchors_at_time, list):
            errors.append("anchors_at_time must be a list")
        else:
            for i, entry in enumerate(self.anchors_at_time):
                if not isinstance(entry, dict):
                    errors.append(
                        f"anchors_at_time[{i}] must be a dict"
                    )
                    continue
                if not entry.get("anchor"):
                    errors.append(
                        f"anchors_at_time[{i}]: anchor name is required"
                    )
                result = entry.get("result", "")
                if result not in VALID_CONSULTATION_RESULTS:
                    errors.append(
                        f"anchors_at_time[{i}]: result must be one of "
                        f"{VALID_CONSULTATION_RESULTS}, got '{result}'"
                    )
                # temporal: bool — marks anchor confirmations that depended
                # on time-bounded state (on-call windows, change tickets,
                # deploy runs). When true, the historical confirmation does
                # NOT transfer to current matches — the judge flags stale
                # grounding, and the precedent-matching skill filters these
                # out when ranking past tickets. Default false (permanent).
                temporal = entry.get("temporal", False)
                if not isinstance(temporal, bool):
                    errors.append(
                        f"anchors_at_time[{i}]: temporal must be a bool "
                        f"(got {type(temporal).__name__})"
                    )

        if self.captured_at:
            try:
                parse_captured_at(self.captured_at)
            except ValueError as e:
                errors.append(f"captured_at: {e}")
        else:
            errors.append(
                "captured_at is required (ISO 8601 date, e.g. '2026-04-11')"
            )

        return errors


def parse_captured_at(value: str) -> datetime:
    """Parse a captured_at string to a datetime. Raises ValueError on bad format."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    raise ValueError(f"invalid date format: {value!r} (expected ISO 8601)")


def check_recency(captured_at: str, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> tuple[bool, str]:
    """Check whether a precedent snapshot is recent enough.

    Returns (is_fresh, message). message is empty when fresh.
    """
    try:
        dt = parse_captured_at(captured_at)
    except ValueError as e:
        return False, str(e)

    now = datetime.now(UTC)
    age_days = (now - dt).days
    if age_days > max_age_days:
        return False, (
            f"precedent captured_at {captured_at} is {age_days} days old "
            f"(max {max_age_days})"
        )
    return True, ""


def parse_precedent(data: dict) -> tuple[Precedent | None, list[str]]:
    """Parse a dict into a Precedent. Returns (precedent, errors)."""
    errors = []

    required = [
        "ticket_id",
        "archetype",
        "captured_at",
        "disposition",
        "narrative",
        "alert",
    ]
    for f_name in required:
        if f_name not in data:
            errors.append(f"missing required field: {f_name}")

    if errors:
        return None, errors

    precedent = Precedent(
        ticket_id=data["ticket_id"],
        archetype=data["archetype"],
        disposition=data["disposition"],
        narrative=data["narrative"],
        alert=data.get("alert", {}),
        anchors_at_time=data.get("anchors_at_time", []),
        captured_at=data.get("captured_at"),
    )

    validation_errors = precedent.validate()
    errors.extend(validation_errors)

    return precedent, errors
