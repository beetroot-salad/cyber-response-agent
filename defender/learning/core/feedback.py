"""The feedback tick (#1414 F2): a person's comment on a Forgejo issue becomes a lesson row or a
registry entry on a PR a person merges.

One tick, four steps (`tick`): open issues for finished runs, read the comments of people who may
merge, decide each once, draft approved entries onto a registry PR; then post the replies owed.
Everything but the host's few records is derived from what Forgejo shows each tick, so a crash at
any step boundary is a redo (P5). Steps 3 and 4 live in `feedback_decide` and `feedback_registry`.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import os
import re
from collections.abc import Callable
from typing import Any

from defender.learning.author.version_control.forgejo import ForgeError
from defender.learning.core import feedback_decide, feedback_registry
from defender.learning.core.config import FEEDBACK_DRAIN_LABEL, LoopPaths
from defender.learning.core.state import (
    FEEDBACK_CASES,
    FEEDBACK_ITEMS,
    FEEDBACK_POSITIONS,
    FEEDBACK_REQUESTS,
    LearningState,
)

_logger = logging.getLogger(__name__)

FEEDBACK_LABEL = "defender-feedback"
#: How long the service's merge-eligibility record may be before the tick reads no comments (D13/D15).
ELIGIBILITY_MAX_AGE_ENV = "LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE"
DEFAULT_ELIGIBILITY_MAX_AGE = dt.timedelta(seconds=60)
#: Counted refusals of one request before it is set aside (A4; the lead-author lane's ceiling).
MAX_ATTEMPTS = 3
_RUN_MARKER = re.compile(r"<!-- defender-feedback-run:(\S+) -->")


def run_marker(run_id: str) -> str:
    return f"<!-- defender-feedback-run:{run_id} -->"


def _first_line(case_id: str) -> str:
    return f"<!-- defender-feedback case:{case_id} -->"


def _fence(text: str) -> str:
    return "```\n" + str(text).replace("`", "'") + "\n```"


def _summary(request: dict) -> str:
    """A run's summary, fenced like run content (P4) under the marker that names the run (A6)."""
    lookups = "\n".join(f"lookup: {lk['actor']} / {lk['host']} / {lk['pattern']}"
                        for lk in request.get("lookups", []))
    return (run_marker(request["run_id"]) + "\n"
            + _fence(f"run {request['run_id']} ended {request['outcome']}\n{lookups}"))


def _when(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


@dataclasses.dataclass
class Tick:
    """What one tick works over."""

    state: LearningState
    forge: Any
    bots: frozenset[str]
    tenant_id: str
    eligible: frozenset[str] | None = None


def eligibility_bound(seam: dt.timedelta | None) -> dt.timedelta:
    """The staleness bound: the seam, else the env (seconds), else 60 s (D15)."""
    if seam is not None:
        return seam
    raw = os.environ.get(ELIGIBILITY_MAX_AGE_ENV)
    try:
        return dt.timedelta(seconds=float(raw)) if raw else DEFAULT_ELIGIBILITY_MAX_AGE
    except ValueError:
        _logger.error(f"feedback: {ELIGIBILITY_MAX_AGE_ENV}={raw!r} is not a number of seconds; "
                      f"using {DEFAULT_ELIGIBILITY_MAX_AGE.total_seconds():.0f}")
        return DEFAULT_ELIGIBILITY_MAX_AGE


def _eligible_logins(records: Any, tenant_id: Any, bound: dt.timedelta, bots: frozenset[str]) -> frozenset[str] | None:
    """Who may merge as of the service's latest pass, or None when the record is absent or older than
    `bound` (fail closed: the tick reads and decides nothing, logs why, moves no position)."""
    record = records.merge_eligibility(tenant_id)
    if record is None:
        _logger.warning("feedback: no merge-eligibility record for this tenant yet (the management service "
                        "has not written one): reading and deciding no comments this tick")
        return None
    age = dt.datetime.now(dt.UTC) - record.read_at
    if age > bound:
        _logger.warning(f"feedback: the merge-eligibility record is {age.total_seconds():.0f}s old, past the "
                        f"{bound.total_seconds():.0f}s bound: reading and deciding no comments this tick")
        return None
    return frozenset(record.logins) - bots


def tick(paths: LoopPaths, state: LearningState, open_delivery: Callable[[], Any], records: Any,
         *, decide: Callable[..., dict], eligibility_max_age: dt.timedelta | None = None) -> int:
    from defender.learning.core import drains

    tenant = paths.tenant
    bots = frozenset(g.bot_login for g in records.generations(tenant.id))
    with open_delivery() as opened:
        delivery = dataclasses.replace(opened, branch_prefix=drains._branch_prefix(FEEDBACK_DRAIN_LABEL))
        ctx = Tick(state, delivery.repository.forge, bots, str(tenant.id))
        ctx.eligible = _eligible_logins(records, tenant.id, eligibility_bound(eligibility_max_age), bots)
        _open(ctx)
        if ctx.eligible is not None:
            _read(ctx)
            feedback_decide.decide_items(ctx.state, decide)
        feedback_registry.draft(ctx.state, delivery, bots, drains)
        feedback_registry.reply(ctx.state, ctx.forge, bots)
    return 0


# ------------------------------------------------------------------ step 1: open

def _recover(ctx: Tick, case_id: str) -> int | None:
    """The case's issue when the forge holds one this host made but never recorded: labelled, created by one
    of the tenant's bots (any generation), whose first line is exactly the host's own for this case."""
    for bot in sorted(ctx.bots):
        for issue in ctx.forge.list_issues(label=FEEDBACK_LABEL, created_by=bot, state="all"):
            first = (issue.get("body") or "").splitlines()[:1]
            if first == [_first_line(case_id)] and issue["user"]["login"] in ctx.bots:
                return issue["number"]
    return None


def _bot_text(ctx: Tick, number: int, issue: dict) -> str:
    """The issue body and every bot comment on it: where a run's marker or a reply's is looked for."""
    return "\n".join([issue.get("body") or "", *(c["body"] for c in ctx.forge.list_comments(number)
                                                  if c["user"]["login"] in ctx.bots)])


def _record_run(ctx: Tick, case_id: str, number: int, request: dict) -> None:
    case = ctx.state.get_record(FEEDBACK_CASES, case_id) or {"issue": number, "runs": {}}
    case["runs"][request["run_id"]] = {"outcome": request["outcome"], "lookups": request.get("lookups", [])}
    ctx.state.put_record(FEEDBACK_CASES, case_id, case)


def _serve(ctx: Tick, case_id: str, request: dict) -> None:
    case = ctx.state.get_record(FEEDBACK_CASES, case_id)
    number = case["issue"] if case else _recover(ctx, case_id)
    if number is None:
        made = ctx.forge.create_issue(
            title=f"Feedback on case {case_id} ({request['outcome']})",
            body=_first_line(case_id) + "\n\n" + _summary(request), label=FEEDBACK_LABEL)
        _record_run(ctx, case_id, made["number"], request)
        ctx.state.drop_record(FEEDBACK_REQUESTS, case_id)
        return
    try:
        issue = ctx.forge.get_issue(number)
    except ForgeError as e:
        if e.status != 404:
            raise
        _logger.warning(f"feedback: issue {number} of case {case_id} is gone from the forge; treated as closed")
        ctx.state.drop_record(FEEDBACK_REQUESTS, case_id)
        return
    if issue["state"] == "open":
        _record_run(ctx, case_id, number, request)
        if run_marker(request["run_id"]) not in _bot_text(ctx, number, issue):
            ctx.forge.create_comment(number, _summary(request))
    ctx.state.drop_record(FEEDBACK_REQUESTS, case_id)


def _fail_request(ctx: Tick, case_id: str, request: dict, failure: ForgeError) -> None:
    """A forge call of a request failed. An unreachable forge (transport fault, 5xx) counts for nothing; a
    refusal counts, and at the ceiling the request is kept apart with its reason (A4/A8)."""
    if not failure.refused:
        _logger.error(f"feedback: opening the issue of case {case_id} failed, retried next tick: {failure}")
        return
    attempts = int(request.get("attempts", 0)) + 1
    if attempts >= MAX_ATTEMPTS:
        _logger.error(f"feedback: the request of case {case_id} was refused {attempts} times ({failure}); "
                      "set aside")
        ctx.state.put_record(f"{FEEDBACK_REQUESTS}/failed", case_id,
                             {**request, "attempts": attempts, "failed": f"refused {attempts} times: {failure}"})
        ctx.state.drop_record(FEEDBACK_REQUESTS, case_id)
        return
    _logger.error(f"feedback: the request of case {case_id} was refused (attempt {attempts}/{MAX_ATTEMPTS}): {failure}")
    ctx.state.put_record(FEEDBACK_REQUESTS, case_id, {**request, "attempts": attempts})


def _open(ctx: Tick) -> None:
    for case_id, request in sorted(ctx.state.records(FEEDBACK_REQUESTS).items()):
        if request.get("tenant_id") != ctx.tenant_id:
            _logger.error(f"feedback: request {case_id} names another tenant; left")
            continue
        try:
            _serve(ctx, case_id, request)
        except ForgeError as e:
            _fail_request(ctx, case_id, request, e)


# ------------------------------------------------------------------ step 2: read

def _framing(case: dict, issue: dict, comments: list[dict], bots: frozenset[str], comment_id: int) -> dict:
    """The run a comment answers: the latest run marker a bot wrote above it, the issue body first, in the
    forge's comment order (A6). `{}` when no known run precedes it."""
    run_id = None
    for text in [issue.get("body") or "",
                 *(c["body"] for c in comments if c["id"] < comment_id and c["user"]["login"] in bots)]:
        found = _RUN_MARKER.findall(text)
        run_id = found[-1] if found else run_id
    run = case["runs"].get(run_id) if run_id else None
    return {"run_id": run_id, "outcome": run["outcome"], "lookups": run["lookups"]} if run else {
        "run_id": run_id, "outcome": None, "lookups": []}


def _readable(issue: dict, new: list[dict]) -> list[dict]:
    """The comments of `new` a tick may read: all of them on an open issue, only those written before
    the close on a closed one (D12)."""
    if issue["state"] == "open":
        return new
    closed_at = issue.get("closed_at")
    if not closed_at:
        return []
    return [c for c in new if _when(c["created_at"]) < _when(closed_at)]


def _queue_comment(ctx: Tick, case_id: str, case: dict, issue: dict, comments: list[dict], c: dict) -> None:
    ctx.state.put_record(FEEDBACK_ITEMS, str(c["id"]), {
        "comment_id": c["id"], "issue": issue["number"], "issue_url": issue["html_url"],
        "author": c["user"]["login"], "date": c["created_at"], "body": c["body"], "case_id": case_id,
        **_framing(case, issue, comments, ctx.bots, c["id"])})


def _read_issue(ctx: Tick, case_id: str, case: dict) -> None:
    number = case["issue"]
    try:
        issue = ctx.forge.get_issue(number)
        comments = ctx.forge.list_comments(number)
    except ForgeError as e:
        if e.status == 404:
            _logger.warning(f"feedback: issue {number} of case {case_id} is gone from the forge; nothing to read")
        else:
            _logger.error(f"feedback: reading issue {number} failed, position kept: {e}")
        return
    position = (ctx.state.get_record(FEEDBACK_POSITIONS, str(number)) or {}).get("last", 0)
    new = sorted((c for c in comments if c["id"] > position), key=lambda c: c["id"])
    if not new:
        return
    skipped: set[str] = set()
    for c in _readable(issue, new):
        if c["user"]["login"] in (ctx.eligible or ()):
            _queue_comment(ctx, case_id, case, issue, comments, c)
        else:
            skipped.add(c["user"]["login"])
    if skipped:
        _logger.info(f"feedback: issue {number}: skipped comments by accounts that may not merge: {sorted(skipped)}")
    ctx.state.put_record(FEEDBACK_POSITIONS, str(number), {"last": new[-1]["id"]})


def _read(ctx: Tick) -> None:
    for case_id, case in sorted(ctx.state.records(FEEDBACK_CASES).items()):
        _read_issue(ctx, case_id, case)
