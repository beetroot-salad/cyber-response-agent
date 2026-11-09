"""Step 3 of the feedback tick (#1414 F2): the model decides each eligible comment once, in order per issue.

The model answers which of the framing run's captured lookups the comment approves (by index), an earlier
review date it names, instruction text, or nothing with a reason (A3). The host validates the answer whole,
assigns entry ids, records the decision under the comment's id, and writes the lessons row (D11).
"""
from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from typing import Any

from defender._clock import parse_iso_utc
from defender.learning.core.state import (
    FEEDBACK_DECISIONS,
    FEEDBACK_ITEMS,
    FEEDBACK_LESSONS,
    LearningState,
)
from defender.systems import tacit_registry

_logger = logging.getLogger(__name__)

#: Counted failed answers of one comment before it is closed as "could not be processed" (A4).
MAX_ATTEMPTS = 3
REVIEW_DAYS = tacit_registry.TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS
NO_LOOKUP = "the run made no registry lookup this could approve"


#: The answer's whole schema (A3): exactly these keys, each present.
ANSWER_KEYS = frozenset({"approve", "review_by", "instruction", "reason"})


class InvalidAnswer(Exception):
    """The model's answer breaks A3's schema; it is refused whole and the comment asked again."""


def comment_day(item: dict) -> dt.date:
    parsed = parse_iso_utc(item["date"])
    if parsed is None:
        raise ValueError(f"the comment's date is no ISO date: {item['date']!r}")
    return parsed.date()


def _indexes(answer: dict, lookups: list[dict]) -> list[int]:
    """The distinct lookup indexes the answer approves, in order; a bad one refuses the answer."""
    approve = answer["approve"]
    if not isinstance(approve, list):
        raise InvalidAnswer("`approve` is not a list")
    if not lookups:
        return []  # nothing to approve: the host records its own no-change (A9)
    found: list[int] = []
    for index in approve:
        if type(index) is not int or not 0 <= index < len(lookups):
            raise InvalidAnswer(f"`approve` names {index!r}, outside the {len(lookups)} lookup(s)")
        if index not in found:
            found.append(index)
    return found


def _review_by(answer: dict, added: dt.date) -> str | None:
    """The review date the comment names, capped at added_at + 180 (O6's "earlier of"); a date that is not
    an ISO date, or falls before the comment's own day, refuses the answer."""
    named = answer["review_by"]
    if named is None:
        return None
    parsed = tacit_registry.parse_date(named) if isinstance(named, str) else None
    if parsed is None:
        raise InvalidAnswer(f"`review_by` {named!r} is not an ISO date")
    if parsed < added:
        raise InvalidAnswer(f"`review_by` {named!r} is before the comment's day {added}")
    return min(parsed, added + dt.timedelta(days=REVIEW_DAYS)).isoformat()


def _answer_text(answer: dict, field: str) -> str | None:
    value = answer[field]
    if value is not None and not isinstance(value, str):
        raise InvalidAnswer(f"`{field}` is not text")
    return value.strip() or None if value else None


def validate_answer(answer: Any, item: dict) -> dict:
    """The decision the answer means, or `InvalidAnswer`."""
    if not isinstance(answer, dict):
        raise InvalidAnswer("the answer is not an object")
    if set(answer) != ANSWER_KEYS:
        raise InvalidAnswer(f"the answer's keys are {sorted(answer)}, not exactly {sorted(ANSWER_KEYS)}")
    lookups = item["lookups"]
    approved = _indexes(answer, lookups)
    review_by = _review_by(answer, comment_day(item))
    instruction, reason = _answer_text(answer, "instruction"), _answer_text(answer, "reason")
    asked_without_lookups = isinstance(answer.get("approve"), list) and answer["approve"] and not lookups
    no_change = None
    if asked_without_lookups:
        no_change = NO_LOOKUP
    elif not approved and not instruction:
        no_change = reason or "nothing to learn"
    return {"approved": [{"index": i, "lookup": lookups[i],
                          "id": f"fb-{item['issue']}-{item['comment_id']}-{n}", "settled": None}
                         for n, i in enumerate(approved, 1)],
            "review_by": review_by, "instruction": instruction, "no_change": no_change}


def _record_decision(state: LearningState, item: dict, made: dict) -> dict:
    decision = {"comment_id": item["comment_id"], "issue": item["issue"], "issue_url": item["issue_url"],
                "author": item["author"], "date": item["date"], "body": item["body"],
                "case_id": item["case_id"], "settled": False, **made}
    state.put_record(FEEDBACK_DECISIONS, str(item["comment_id"]), decision)
    return decision


def _lesson_row(decision: dict) -> dict:
    return {"comment_id": str(decision["comment_id"]), "issue": decision["issue"], "author": decision["author"],
            "case_id": decision["case_id"], "instruction": decision["instruction"]}


def _failed(state: LearningState, item: dict, why: str) -> bool:
    """One counted failure of a comment. At the ceiling the host records the no-change decision that the
    normal reply path posts; answers whether the comment is closed now (A4)."""
    attempts = int(item.get("attempts", 0)) + 1
    if attempts < MAX_ATTEMPTS:
        _logger.error(f"feedback: comment {item['comment_id']} on issue {item['issue']} was not decided "
                      f"(attempt {attempts}/{MAX_ATTEMPTS}): {why}")
        state.put_record(FEEDBACK_ITEMS, str(item["comment_id"]), {**item, "attempts": attempts})
        return False
    _logger.warning(f"feedback: comment {item['comment_id']} on issue {item['issue']} could not be processed "
                    f"after {attempts} attempts ({why}); recorded as no change")
    _record_decision(state, item, {"approved": [], "review_by": None, "instruction": None,
                          "no_change": f"could not be processed ({why})"})
    return True


def _ask(state: LearningState, item: dict, decide: Callable[..., Any]) -> dict | None:
    """The comment's decision, recorded, or None when this attempt failed (counted)."""
    try:
        made = validate_answer(decide(dict(item)), item)
    except InvalidAnswer as bad:
        why = str(bad)
    except Exception as e:  # noqa: BLE001 — a model or box fault is a failed attempt, never a crashed tick
        why = f"{type(e).__name__}: {e}"
    else:
        return _record_decision(state, item, made)
    closed = _failed(state, item, why)
    return state.get_record(FEEDBACK_DECISIONS, str(item["comment_id"])) if closed else None


def decide_items(state: LearningState, decide: Callable[..., Any]) -> None:
    """Every queued item with no decision yet, in order per issue; a failing comment holds back its issue's
    later ones for this tick. An item that has a decision only has its lessons row written if missing."""
    stopped: set[int] = set()
    items = sorted(state.records(FEEDBACK_ITEMS).values(), key=lambda i: (i["issue"], i["comment_id"]))
    for item in items:
        if item["issue"] in stopped:
            continue
        key = str(item["comment_id"])
        decision = state.get_record(FEEDBACK_DECISIONS, key) or _ask(state, item, decide)
        if decision is None:
            stopped.add(item["issue"])
            continue
        if decision.get("instruction"):
            state.append(FEEDBACK_LESSONS, [_lesson_row(decision)], dedup_key="comment_id")
        state.drop_record(FEEDBACK_ITEMS, key)
