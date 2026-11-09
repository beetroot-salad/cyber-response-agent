"""The tenant's feedback setting (#1414 O1): which run outcomes open an issue for a person's feedback.

`settings/feedback.yaml`: `open_issue_on:` a list of outcome words. Absent: nothing opens (#1390 P4).
"""
from __future__ import annotations

from pathlib import Path

from defender._vocab import DISPOSITION_VALUES
from defender.records import run_end
from defender.tenancy.tenant_settings import read_regular_bytes

SETTING_FILE = "feedback.yaml"
KEY = "open_issue_on"
UNREADABLE = "unreadable"
#: Every word the setting may list.
OUTCOME_VOCABULARY = frozenset({*DISPOSITION_VALUES, *run_end.ESCALATED_EXITS, UNREADABLE})


class FeedbackSettingError(Exception):
    pass


def load_feedback_outcomes(settings: Path) -> frozenset[str] | None:
    """The outcomes the setting lists, `None` when the tenant has no file; `FeedbackSettingError`
    when it cannot stand."""
    import yaml

    from defender._yaml import duplicate_key_paths, reject_unread_keys, safe_load

    path = Path(settings) / SETTING_FILE
    try:
        raw = read_regular_bytes(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise FeedbackSettingError(f"settings/{SETTING_FILE} cannot be read: {e.strerror}") from None
    shown = f"settings/{SETTING_FILE}"
    try:
        text = raw.decode("utf-8")
        duplicates = duplicate_key_paths(text)
        data = safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError):
        raise FeedbackSettingError(f"{shown} is not valid YAML text") from None
    if duplicates:
        raise FeedbackSettingError(f"{shown} has duplicate key(s) {list(duplicates)}; write each key once")
    if isinstance(data, dict):
        reject_unread_keys(shown, data, (KEY,), error=FeedbackSettingError)
    listed = data.get(KEY) if isinstance(data, dict) else None
    if not isinstance(listed, list) or not all(isinstance(o, str) for o in listed):
        raise FeedbackSettingError(f"settings/{SETTING_FILE} must hold `open_issue_on:` as a list of outcomes")
    unknown = sorted(set(listed) - OUTCOME_VOCABULARY)
    if unknown:
        raise FeedbackSettingError(
            f"settings/{SETTING_FILE} names unknown outcome(s) {unknown}; known: {sorted(OUTCOME_VOCABULARY)}")
    return frozenset(listed)
