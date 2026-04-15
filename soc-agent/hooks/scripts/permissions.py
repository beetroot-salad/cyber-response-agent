"""Shared permissions.yaml parser for hooks.

Multiple hooks read `config/signatures/{signature_id}/permissions.yaml` and
need consistent parsing. This module centralizes the parse + getters so both
`validate_report.py` and `close_ticket_action.py` share one implementation.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


def load_permissions(signature_id: str, root: Path | None = None) -> dict:
    """Load and parse a signature's permissions.yaml.

    Returns an empty dict when the file is missing or unparseable.

    `root` lets callers (and tests) point at an alternate soc-agent root.
    """
    if not signature_id:
        return {}
    base = root if root is not None else SOC_AGENT_ROOT
    perms_path = base / "config" / "signatures" / signature_id / "permissions.yaml"
    if not perms_path.exists():
        return {}

    text = perms_path.read_text()
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


# ---------------------------------------------------------------------------
# Getters
# ---------------------------------------------------------------------------


def get_mode(permissions: dict) -> str:
    """Return the default mode ('recommend' or 'act'), defaulting to 'recommend'."""
    mode = permissions.get("mode")
    if not isinstance(mode, dict):
        return "recommend"
    default = mode.get("default")
    if isinstance(default, str) and default:
        return default
    return "recommend"


def get_mitigation_action(permissions: dict, action: str) -> str | None:
    """Return the policy for a named mitigation action ('auto', 'approve') or None."""
    mitigation = permissions.get("mitigation")
    if not isinstance(mitigation, dict):
        return None
    actions = mitigation.get("actions")
    if not isinstance(actions, dict):
        return None
    value = actions.get(action)
    if isinstance(value, str) and value:
        return value
    return None


def get_precedent_max_age(signature_id: str, root: Path | None = None) -> int:
    """Load precedent_max_age_days from permissions.yaml, or use default."""
    from schemas.precedent import DEFAULT_MAX_AGE_DAYS

    data = load_permissions(signature_id, root=root)
    raw = data.get("precedent_max_age_days")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw)
        except ValueError:
            return DEFAULT_MAX_AGE_DAYS
    return DEFAULT_MAX_AGE_DAYS
