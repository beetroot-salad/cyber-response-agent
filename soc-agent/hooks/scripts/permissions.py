"""Shared permissions.yaml parser for hooks.

Multiple hooks read `config/signatures/{signature_id}/permissions.yaml` and
need tolerant parsing: PyYAML is preferred, but the hook must still function
in stdlib-only environments (e.g., the judge subprocess). This module
centralizes the parse + getters so both `validate_report.py` and
`close_ticket_action.py` share one implementation.
"""

from __future__ import annotations

import os
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


def load_permissions(signature_id: str, root: Path | None = None) -> dict:
    """Load and parse a signature's permissions.yaml.

    Returns an empty dict when the file is missing or entirely unparseable.
    Uses PyYAML when available; falls back to a line-scanner for the few
    scalar keys the hooks need.

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
        import yaml  # type: ignore
    except Exception:
        return _fallback_parse(text)
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        return _fallback_parse(text)
    if not isinstance(data, dict):
        return {}
    return data


def _fallback_parse(text: str) -> dict:
    """Stdlib-only approximation of the subset of permissions.yaml the
    hooks actually read: `precedent_max_age_days`, `mode.default`,
    `mitigation.actions.*`.
    """
    data: dict = {}
    current_top: str | None = None
    current_sub: str | None = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if indent == 0:
            if ":" not in line:
                current_top = None
                current_sub = None
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val == "":
                current_top = key
                current_sub = None
                data.setdefault(key, {})
                continue
            current_top = None
            current_sub = None
            data[key] = _coerce(val)
            continue

        if current_top is None:
            continue

        if indent == 2:
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val == "":
                current_sub = key
                if isinstance(data[current_top], dict):
                    data[current_top].setdefault(key, {})
                continue
            current_sub = None
            if isinstance(data[current_top], dict):
                data[current_top][key] = _coerce(val)
            continue

        if indent >= 4 and current_sub is not None:
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            top_dict = data.get(current_top)
            if isinstance(top_dict, dict):
                sub = top_dict.get(current_sub)
                if isinstance(sub, dict):
                    sub[key] = _coerce(val)

    return data


def _coerce(val: str):
    """Best-effort scalar coercion for fallback parser."""
    val = val.strip()
    # Only strip quotes when both delimiters match (same character).
    # Checking startswith+endswith alone would accept mismatched pairs like 'foo".
    if len(val) >= 2 and val[0] in ("'", '"') and val[0] == val[-1]:
        return val[1:-1]
    if val.lower() in ("true", "yes"):
        return True
    if val.lower() in ("false", "no"):
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val


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
