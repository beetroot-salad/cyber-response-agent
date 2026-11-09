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
from collections.abc import Callable
from typing import Any

from defender._clock import parse_iso_utc
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
#: How far ahead of this host's clock the service's record may be dated and still count as fresh.
CLOCK_SKEW = dt.timedelta(seconds=5)


def _first_line(case_id: str, run_id: str) -> str:
    """The host-written first line of a run's issue: it names the case and the run (ruling 5: one issue per run)."""
    return f"<!-- defender-feedback case:{case_id} run:{run_id} -->"


def _fence(text: str) -> str:
    return "```\n" + str(text).replace("`", "'") + "\n```"


def _summary(request: dict) -> str:
    """A run's summary, fenced like run content (P4); it follows the host-written first line."""
    lookups = "\n".join(f"lookup: {lk['actor']} / {lk['host']} / {lk['pattern']}"
                        for lk in request.get("lookups", []))
    return _fence(f"run {request['run_id']} ended {request['outcome']}\n{lookups}")


def _forge_time(text: str) -> dt.datetime:
    parsed = parse_iso_utc(text)
    if parsed is None:
        raise ValueError(f"the forge sent a timestamp that is no ISO date: {text!r}")
    return parsed


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
    if age < -CLOCK_SKEW:
        _logger.warning(f"feedback: the merge-eligibility record is dated {-age.total_seconds():.0f}s ahead of "
                        "this host's clock: a clock is wrong; reading and deciding no comments this tick")
        return None
    if age > bound:
        _logger.warning(f"feedback: the merge-eligibility record is {age.total_seconds():.0f}s old, past the "
                        f"{bound.total_seconds():.0f}s bound: reading and deciding no comments this tick")
        return None
    return frozenset(record.logins) - bots


def tick(paths: LoopPaths, state: LearningState, open_delivery: Callable[[], Any], records: Any,
         *, decide: Callable[..., dict], eligibility_max_age: dt.timedelta | None = None) -> int:
    from defender.learning.core import drains

    tenant = paths.tenant
    assert tenant is not None, "the feedback tick runs for one selected tenant"
    bots = frozenset(g.bot_login for g in records.generations(tenant.id))
    with open_delivery() as opened:
        delivery = dataclasses.replace(opened, branch_prefix=drains._branch_prefix(FEEDBACK_DRAIN_LABEL))
        ctx = Tick(state, delivery.repository.forge, bots, str(tenant.id))
        ctx.eligible = _eligible_logins(records, tenant.id, eligibility_bound(eligibility_max_age), bots)
        _open_requests(ctx)
        if ctx.eligible is not None:
            _read_comments(ctx)
            feedback_decide.decide_items(ctx.state, decide)
        feedback_registry.draft(ctx.state, delivery, bots, drains)
        feedback_registry.reply(ctx.state, ctx.forge, bots)
    return 0


# ------------------------------------------------------------------ step 1: open

def _recover(ctx: Tick, case_id: str, run_id: str) -> int | None:
    """The run's issue when the forge holds one this host made but never recorded: labelled, created by one of
    the tenant's bots (any generation), open or closed, whose first line is exactly the host's own for this run."""
    for bot in sorted(ctx.bots):
        for issue in ctx.forge.list_issues(label=FEEDBACK_LABEL, created_by=bot, state="all"):
            first = (issue.get("body") or "").split("\n")[:1]
            if first == [_first_line(case_id, run_id)] and issue["user"]["login"] in ctx.bots:
                return issue["number"]
    return None


def _record_run(ctx: Tick, request: dict, number: int) -> None:
    ctx.state.put_record(FEEDBACK_CASES, request["run_id"], {
        "issue": number, "case_id": request["case_id"], "run_id": request["run_id"],
        "outcome": request["outcome"], "lookups": request.get("lookups", [])})


def _serve_request(ctx: Tick, key: str, request: dict) -> None:
    """Give the run its own issue (ruling 5), unless it has one: recorded, or found on the forge by its first line."""
    run_id, case_id = request["run_id"], request["case_id"]
    if ctx.state.get_record(FEEDBACK_CASES, run_id) is None:
        number = _recover(ctx, case_id, run_id)
        if number is None:
            number = ctx.forge.create_issue(
                title=f"Feedback on case {case_id} run {run_id} ({request['outcome']})",
                body=_first_line(case_id, run_id) + "\n" + _summary(request), label=FEEDBACK_LABEL)["number"]
        _record_run(ctx, request, number)
    ctx.state.drop_record_if(FEEDBACK_REQUESTS, key, request)


def _fail_request(ctx: Tick, key: str, request: dict, failure: ForgeError) -> None:
    """A forge call of a request failed. An unreachable forge (transport fault, 5xx) counts for nothing; a
    refusal counts, and at the ceiling the request is kept apart with its reason (A4/A8)."""
    case_id = request.get("case_id", key)
    if not failure.refused:
        _logger.error(f"feedback: opening the issue of case {case_id} failed, retried next tick: {failure}")
        return
    attempts = int(request.get("attempts", 0)) + 1
    if attempts >= MAX_ATTEMPTS:
        _logger.error(f"feedback: the request of case {case_id} was refused {attempts} times ({failure}); "
                      "set aside")
        ctx.state.put_record(f"{FEEDBACK_REQUESTS}/failed", key,
                             {**request, "attempts": attempts, "failed": f"refused {attempts} times: {failure}"})
        ctx.state.drop_record_if(FEEDBACK_REQUESTS, key, request)  # a newer request stays queued
        return
    _logger.error(f"feedback: the request of case {case_id} was refused (attempt {attempts}/{MAX_ATTEMPTS}): {failure}")
    ctx.state.replace_record_if(FEEDBACK_REQUESTS, key, request, {**request, "attempts": attempts})


def _open_requests(ctx: Tick) -> None:
    for key, request in sorted(ctx.state.records(FEEDBACK_REQUESTS).items()):
        if request.get("tenant_id") != ctx.tenant_id:
            _logger.error(f"feedback: request {key} names another tenant; left")
            continue
        try:
            _serve_request(ctx, key, request)
        except ForgeError as e:
            _fail_request(ctx, key, request, e)
        except UnicodeEncodeError as e:  # text the forge cannot be sent: a refusal, counted, never a wedge
            _fail_request(ctx, key, request, ForgeError(f"the request holds text that is not UTF-8: {e}", status=400))


# ------------------------------------------------------------------ step 2: read

def _readable(issue: dict, new: list[dict]) -> list[dict]:
    """The comments of `new` a tick may read: all of them on an open issue, only those written before
    the close, or in the same second as it, on a closed one (D12: as the tick observes it)."""
    if issue["state"] == "open":
        return new
    closed_at = issue.get("closed_at")
    if not closed_at:
        return []
    return [c for c in new if _forge_time(c["created_at"]) <= _forge_time(closed_at)]


def _queue_comment(ctx: Tick, run: dict, issue: dict, c: dict) -> None:
    """A comment is decided against the run whose issue it is on (ruling 5)."""
    ctx.state.put_record(FEEDBACK_ITEMS, str(c["id"]), {
        "comment_id": c["id"], "issue": issue["number"], "issue_url": issue["html_url"],
        "author": c["user"]["login"], "date": c["created_at"], "body": c["body"], "case_id": run["case_id"],
        "run_id": run["run_id"], "outcome": run["outcome"], "lookups": run["lookups"]})


def _read_issue(ctx: Tick, run: dict) -> None:
    number = run["issue"]
    try:
        issue = ctx.forge.get_issue(number)
        comments = ctx.forge.list_comments(number)
    except ForgeError as e:
        if e.status == 404:
            _logger.warning(f"feedback: issue {number} of case {run['case_id']} is gone from the forge; "
                            "read as closed, nothing to read")
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
            _queue_comment(ctx, run, issue, c)
        else:
            skipped.add(c["user"]["login"])
    if skipped:
        _logger.info(f"feedback: issue {number}: skipped comments by accounts that may not merge: {sorted(skipped)}")
    ctx.state.put_record(FEEDBACK_POSITIONS, str(number), {"last": new[-1]["id"]})


def _read_comments(ctx: Tick) -> None:
    for _run_id, run in sorted(ctx.state.records(FEEDBACK_CASES).items()):
        _read_issue(ctx, run)
