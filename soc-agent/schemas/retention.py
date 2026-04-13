"""Retention policy configuration and validation.

Defaults and a loader for the three env vars that control how long
soc-agent keeps run directories and JSONL log entries before cleanup_runs.py
prunes them.

Shape:

    RetentionPolicy {
        run_max_age_days    # run/{uuid}/ directories
        audit_max_age_days  # audit.jsonl and tool_audit.jsonl (compliance records)
        trace_max_age_days  # tool_trace.jsonl (debug noise)
    }

Env vars (all optional — defaults apply when unset):

    SOC_AGENT_RUN_MAX_AGE_DAYS    (default 90)
    SOC_AGENT_AUDIT_MAX_AGE_DAYS  (default 365)
    SOC_AGENT_TRACE_MAX_AGE_DAYS  (default 30)
"""

import os
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Per-run UUID directories.  90 days covers post-incident review windows
# while keeping disk use manageable at 100–1000 alerts/day.
DEFAULT_RUN_MAX_AGE_DAYS = 90

# audit.jsonl and tool_audit.jsonl — security compliance records.
# 365 days (one year) matches common compliance requirements (SOC 2, ISO 27001).
DEFAULT_AUDIT_MAX_AGE_DAYS = 365

# tool_trace.jsonl — read-only tool call debug log.  Short-lived utility;
# no compliance value.
DEFAULT_TRACE_MAX_AGE_DAYS = 30


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class RetentionPolicy:
    """Parsed and validated retention configuration."""

    run_max_age_days: int
    audit_max_age_days: int
    trace_max_age_days: int

    def validate(self) -> list[str]:
        """Return a list of validation error messages (empty = valid)."""
        errors = []
        for field_name, value in [
            ("run_max_age_days",   self.run_max_age_days),
            ("audit_max_age_days", self.audit_max_age_days),
            ("trace_max_age_days", self.trace_max_age_days),
        ]:
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"{field_name} must be an integer, got {type(value).__name__}")
            elif value <= 0:
                errors.append(f"{field_name} must be a positive integer, got {value}")
        return errors


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_retention_policy() -> RetentionPolicy:
    """Load retention config from environment variables with defaults.

    Exits with code 1 and a clear message if any variable is set to a
    non-positive-integer value — bad config is a fatal startup error.
    """
    _ENV_DEFAULTS = {
        "SOC_AGENT_RUN_MAX_AGE_DAYS":   DEFAULT_RUN_MAX_AGE_DAYS,
        "SOC_AGENT_AUDIT_MAX_AGE_DAYS": DEFAULT_AUDIT_MAX_AGE_DAYS,
        "SOC_AGENT_TRACE_MAX_AGE_DAYS": DEFAULT_TRACE_MAX_AGE_DAYS,
    }
    values = {}
    for env_var, default in _ENV_DEFAULTS.items():
        raw = os.environ.get(env_var, "").strip()
        if not raw:
            values[env_var] = default
            continue
        try:
            parsed = int(raw)
        except ValueError:
            print(
                f"error: {env_var}: expected a positive integer, got {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        if parsed <= 0:
            print(
                f"error: {env_var}: must be a positive integer, got {parsed}",
                file=sys.stderr,
            )
            sys.exit(1)
        values[env_var] = parsed

    return RetentionPolicy(
        run_max_age_days=values["SOC_AGENT_RUN_MAX_AGE_DAYS"],
        audit_max_age_days=values["SOC_AGENT_AUDIT_MAX_AGE_DAYS"],
        trace_max_age_days=values["SOC_AGENT_TRACE_MAX_AGE_DAYS"],
    )
