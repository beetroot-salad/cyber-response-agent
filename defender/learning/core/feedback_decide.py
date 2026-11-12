"""Step 3 of the feedback tick (#1414 F2): the model decides each eligible comment once, in order per issue.

The model answers which of the framing run's captured lookups the comment approves (by index), an earlier
review date it names, instruction text, or nothing with a reason (A3). The host validates the answer whole,
assigns entry ids, and records the decision on the comment's row together with its instruction's lessons item
(D11), in one store transaction (#1278 A4 P8).
"""
from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from typing import Any

from defender._clock import parse_iso_utc
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
    # "No change" means the comment led to nothing; an approval that cannot be met over a run with no lookup is its
    # own line, so a comment that still hands on an instruction is never answered "no change" (ruling 2026-11-10).
    unapprovable = NO_LOOKUP if asked_without_lookups else None
    no_change = None
    if not approved and not instruction:
        no_change = unapprovable or reason or "nothing to learn"
        unapprovable = None
    return {"approved": [{"index": i, "lookup": lookups[i],
                          "id": f"fb-{item['issue']}-{item['comment_id']}-{n}", "settled": None}
                         for n, i in enumerate(approved, 1)],
            "review_by": review_by, "instruction": instruction, "no_change": no_change, "unapprovable": unapprovable}


def decision_view(comment: Any) -> dict:
    """A decided comment as steps 4 and the replies read it: the comment's own fields (as #1414's decision record
    carried them) beside its decision's."""
    return {"comment_id": int(comment.comment_id), "issue": comment.issue_number, "issue_url": comment.issue_url,
            "author": comment.author, "date": comment.created, "body": comment.body, **(comment.decision or {})}


def _item(comment: Any, run: Any) -> dict:
    """The decide seam's item (A3): the comment, and the outcome and captured lookups of the run whose issue it is
    on (ruling 5)."""
    return {"comment_id": int(comment.comment_id), "issue": comment.issue_number, "issue_url": comment.issue_url,
            "author": comment.author, "date": comment.created, "body": comment.body, "case_id": run.case_id,
            "run_id": run.run_id, "outcome": run.outcome, "lookups": [dict(lk) for lk in run.lookups]}


def _stored(made: dict) -> dict:
    """The decision as the store keeps it (A4): the model's texts as the store can hold them."""
    from defender.learning.core.feedback import storable

    return {**made, **{k: storable(made[k]) for k in ("instruction", "no_change", "unapprovable")
                       if isinstance(made.get(k), str)}}


def _lesson_row(item: dict, decision: dict) -> dict:
    return {"comment_id": str(item["comment_id"]), "issue": item["issue"], "author": item["author"],
            "case_id": item["case_id"], "instruction": decision["instruction"]}


def _record_decision(ctx: Any, item: dict, made: dict) -> dict:
    """Record the comment's decision and, in the same transaction, its instruction's lessons item (D11, P8). The one
    write a fault costs a model call: one that fails short of a stop is tried once more before the tick gives up."""
    from defender.learning.core.feedback import _halts

    decision = _stored(made)
    row = _lesson_row(item, decision) if decision.get("instruction") else None
    try:
        ctx.store.record_decision(ctx.held, item["comment_id"], decision, instruction=row)
    except _halts():
        raise
    except Exception as first:  # noqa: BLE001 — retried once; a second failure is the step's
        _logger.warning(f"feedback: recording the decision of comment {item['comment_id']} failed ({first!r}); "
                        "trying once more")
        ctx.store.record_decision(ctx.held, item["comment_id"], decision, instruction=row)
    return decision


def _failed(ctx: Any, item: dict, why: str) -> dict | None:
    """One counted failure of a comment. At the ceiling the host records the no-change decision that the
    normal reply path posts, and returns it (A4)."""
    attempts = int(ctx.store.count_failed_answer(ctx.held, item["comment_id"]))
    if attempts < MAX_ATTEMPTS:
        _logger.error(f"feedback: comment {item['comment_id']} on issue {item['issue']} was not decided "
                      f"(attempt {attempts}/{MAX_ATTEMPTS}): {why}")
        return None
    _logger.warning(f"feedback: comment {item['comment_id']} on issue {item['issue']} could not be processed "
                    f"after {attempts} attempts ({why}); recorded as no change")
    return _record_decision(ctx, item, {"approved": [], "review_by": None, "instruction": None,
                                        "no_change": f"could not be processed ({why})", "unapprovable": None})


def _ask(ctx: Any, item: dict, decide: Callable[..., Any]) -> dict | None:
    """The comment's decision, recorded, or None when this attempt failed (counted)."""
    try:
        made = validate_answer(decide(dict(item)), item)
    except InvalidAnswer as bad:
        why = str(bad)
    except Exception as e:  # noqa: BLE001 — a model or box fault is a failed attempt, never a crashed tick
        why = f"{type(e).__name__}: {e}"
    else:
        return _record_decision(ctx, item, made)
    return _failed(ctx, item, why)


def decide_comments(ctx: Any, decide: Callable[..., Any]) -> None:
    """Every comment taken in with no decision yet, in order per issue; a failing comment holds back its issue's
    later ones for this tick."""
    runs = {r.run_id: r for r in ctx.issues()}
    stopped: set[int] = set()
    for comment in ctx.comments():
        if comment.decision is not None or comment.issue_number in stopped:
            continue
        ctx.hold.check()
        if _ask(ctx, _item(comment, runs[comment.run_id]), decide) is None:
            stopped.add(comment.issue_number)
