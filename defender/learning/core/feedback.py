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
    FEEDBACK_CURSOR,
    FEEDBACK_DECISIONS,
    FEEDBACK_ITEMS,
    FEEDBACK_REQUESTS,
    FEEDBACK_SEEN,
    LearningState,
)

_logger = logging.getLogger(__name__)

FEEDBACK_LABEL = "defender-feedback"
#: How long the service's merge-eligibility record may be before the tick reads no comments (D13/D15).
ELIGIBILITY_MAX_AGE_ENV = "LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE"
DEFAULT_ELIGIBILITY_MAX_AGE = dt.timedelta(seconds=60)
#: The longest issue title the forge takes; the host's own title is cut to it, so it is never refused for length.
TITLE_LIMIT = 255
#: How far back of the last comment read each tick asks again: a comment the forge dated just before it but
#: listed only later is still found. A comment already recorded (an item or a decision) is not read twice.
COMMENT_OVERLAP = dt.timedelta(seconds=60)
#: How far ahead of this host's clock the service's record may be dated and still count as fresh.
CLOCK_SKEW = dt.timedelta(seconds=5)


def _first_line(case_id: str, run_id: str) -> str:
    """The host-written first line of a run's issue: it names the case and the run (ruling 5: one issue per run)."""
    return f"<!-- defender-feedback case:{case_id} run:{run_id} -->"


def sendable(text: str) -> str:
    """`text` as the forge can be sent it: valid UTF-8 (a lone surrogate becomes a replacement mark). Every byte the
    host sends it composes itself, so no request can be refused for its text and none is ever given up."""
    return text.encode("utf-8", "replace").decode("utf-8")


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
    #: First line -> issue number of every feedback issue a tenant bot made: read once per tick, when needed.
    made: dict[str, int] | None = None


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

    from defender.tenancy import RecordsUnreachable

    tenant = paths.tenant
    assert tenant is not None, "the feedback tick runs for one selected tenant"
    with open_delivery() as opened:
        try:
            bots = frozenset(g.bot_login for g in records.generations(tenant.id))
            eligible = _eligible_logins(records, tenant.id, eligibility_bound(eligibility_max_age), bots)
        except RecordsUnreachable as down:
            raise drains._Refused(f"the tenant {tenant.id}'s records could not be read: {down}", transient=True) from None
        delivery = dataclasses.replace(opened, branch_prefix=drains._branch_prefix(FEEDBACK_DRAIN_LABEL))
        ctx = Tick(state, delivery.repository.forge, bots, str(tenant.id), eligible)
        _isolated_step("opening issues", lambda: _open_requests(ctx))
        if ctx.eligible is not None:
            _isolated_step("reading comments", lambda: _read_comments(ctx))
            _isolated_step("deciding comments", lambda: feedback_decide.decide_items(ctx.state, decide))
        _isolated_step("drafting registry entries", lambda: feedback_registry.draft(ctx.state, delivery, bots, drains))
        _isolated_step("replying", lambda: feedback_registry.reply(ctx.state, ctx.forge, bots))
    return 0


def _isolated_step(name: str, run: Callable[[], None]) -> None:
    """One step of the tick. Every step is a redo from what the forge and the records show (P5), so a failure of
    any kind is logged and the next step still runs: a broken registry file stops the draft, never the replies
    (ruling 2026-11-10: steps are isolated)."""
    try:
        run()
    except Exception as e:  # noqa: BLE001 — one step's failure never costs the tick its other steps
        _logger.error(f"feedback: {name} failed, retried next tick: {e!r}", exc_info=True)


# ------------------------------------------------------------------ step 1: open

def _recover(ctx: Tick, case_id: str, run_id: str) -> int | None:
    """The run's issue when the forge holds one this host made but never recorded: labelled, created by one of
    the tenant's bots (any generation), open or closed, whose first line is exactly the host's own for this run.
    Read from the index `_open_requests` made before serving any request."""
    assert ctx.made is not None, "the issue index is read before any request is served"
    return ctx.made.get(_first_line(case_id, run_id))


def _issue_index(ctx: Tick) -> dict[str, int]:
    """First line -> number of every feedback issue a tenant bot made, read whole or not at all: a listing that
    fails raises, and no request is served from part of one."""
    made: dict[str, int] = {}
    for bot in sorted(ctx.bots):
        for issue in ctx.forge.list_issues(label=FEEDBACK_LABEL, created_by=bot, state="all"):
            if issue["user"]["login"] in ctx.bots:
                made.setdefault((issue.get("body") or "").split("\n")[0], issue["number"])
    return made


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
            title = sendable(f"Feedback on case {case_id} run {run_id} ({request['outcome']})")[:TITLE_LIMIT]
            number = ctx.forge.create_issue(
                title=title, body=sendable(_first_line(case_id, run_id) + "\n" + _summary(request)),
                label=FEEDBACK_LABEL)["number"]
        _record_run(ctx, request, number)
    ctx.state.drop_record_if(FEEDBACK_REQUESTS, key, request)


def _open_requests(ctx: Tick) -> None:
    """Serve every queued request. When any has no record yet, the forge's feedback issues are listed first, whole:
    a listing that fails leaves every request queued for the next tick (a request is never served from part of it,
    which could make a second issue for a run whose first was never recorded)."""
    requests = sorted(ctx.state.records(FEEDBACK_REQUESTS).items())
    if any(ctx.state.get_record(FEEDBACK_CASES, r.get("run_id", "")) is None for _, r in requests):
        try:
            ctx.made = _issue_index(ctx)
        except ForgeError as e:
            _logger.error(f"feedback: listing the feedback issues failed, every request waits for the next tick: {e}")
            return
    for key, request in requests:
        if request.get("tenant_id") != ctx.tenant_id:
            _logger.error(f"feedback: request {key} names another tenant; left")
            continue
        try:
            _serve_request(ctx, key, request)
        except ForgeError as e:
            # Never given up: the text is the host's own and always sendable, so a failure is the forge's state
            # (down, throttling, or a bot not yet granted issues), and the request waits for it (ruling 2026-11-10: no refusal ceiling).
            _logger.error(f"feedback: opening the issue of case {request.get('case_id', key)} failed, "
                          f"retried next tick: {e}")


# ------------------------------------------------------------------ step 2: read

def _readable(issue: dict, new: list[dict]) -> list[dict]:
    """The comments of `new` a tick may read: all of them on an open issue, only those written before
    the close, or in the same second as it, on a closed one (D12: as the tick observes it)."""
    if issue["state"] == "open":
        return new
    return [c for c in new if _forge_time(c["created_at"]) <= _forge_time(issue["closed_at"])]


def _queue_comment(ctx: Tick, run: dict, issue: dict, c: dict) -> None:
    """A comment is decided against the run whose issue it is on (ruling 5)."""
    ctx.state.put_record(FEEDBACK_ITEMS, str(c["id"]), {
        "comment_id": c["id"], "issue": issue["number"], "issue_url": issue["html_url"],
        "author": c["user"]["login"], "date": c["created_at"], "body": c["body"], "case_id": run["case_id"],
        "run_id": run["run_id"], "outcome": run["outcome"], "lookups": run["lookups"]})


def _read_issue(ctx: Tick, run: dict, comments: list[dict]) -> bool:
    """Read the listed `comments` of the run's issue. False when the issue could not be read (retried next tick)."""
    number = run["issue"]
    try:
        issue = ctx.forge.get_issue(number)
    except ForgeError as e:
        if e.status == 404:
            _logger.warning(f"feedback: issue {number} of case {run['case_id']} is gone from the forge; "
                            "read as closed, nothing to read")
            return True
        _logger.error(f"feedback: reading issue {number} failed, position kept: {e}")
        return False
    if issue["state"] != "open" and not issue.get("closed_at"):
        _logger.error(f"feedback: issue {number} is closed with no close time; its comments are read once the forge "
                      "shows one")
        return False
    # A comment is judged once, by its id: taken in, or passed over (by an account that may not merge, or written
    # after the close, which a reopen does not revive). No high-water mark, so a comment the forge lists late, under
    # a lower id than one already judged, is still read (ruling 2026-11-10: comments judged by id).
    seen = set((ctx.state.get_record(FEEDBACK_SEEN, str(number)) or {}).get("ids", []))
    new = sorted((c for c in comments if c["id"] not in seen and _no_item_or_decision(ctx, c)), key=lambda c: c["id"])
    if not new:
        return True
    skipped: set[str] = set()
    for c in _readable(issue, new):
        if c["user"]["login"] in (ctx.eligible or ()):
            _queue_comment(ctx, run, issue, c)
        else:
            skipped.add(c["user"]["login"])
    if skipped:
        _logger.info(f"feedback: issue {number}: skipped comments by accounts that may not merge: {sorted(skipped)}")
    ctx.state.put_record(FEEDBACK_SEEN, str(number), {"ids": sorted(seen | {c["id"] for c in new})})
    return True


def _no_item_or_decision(ctx: Tick, comment: dict) -> bool:
    """No queued item and no decision is recorded for the comment (one queued before its issue's judged ids were
    written, by a tick that died between the two)."""
    key = str(comment["id"])
    return ctx.state.get_record(FEEDBACK_ITEMS, key) is None and ctx.state.get_record(FEEDBACK_DECISIONS, key) is None


def _issue_number(comment: dict) -> int | None:
    """The issue a repository comment is on, from its `issue_url` (a PR's comment carries none)."""
    tail = str(comment.get("issue_url") or "").rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdecimal() else None


def _catch_up(ctx: Tick, run_id: str, run: dict) -> bool:
    """A newly recorded issue's first read lists its own comments whole: a comment written before the tick that
    recorded it (an issue made, its reply lost, recovered later) may already be behind the repository cursor."""
    try:
        comments = ctx.forge.list_comments(run["issue"])
    except ForgeError as e:
        if e.status != 404:
            _logger.error(f"feedback: reading issue {run['issue']} failed, position kept: {e}")
            return False
        comments = []
    if not _read_issue(ctx, run, comments):
        return False
    ctx.state.replace_record_if(FEEDBACK_CASES, run_id, run, {**run, "listed": True})
    return True


def _read_comments(ctx: Tick) -> None:
    """Read the comments made since the last tick, in one repository listing: only issues with new comments are
    looked at, so the work follows the comments, not every issue the tenant ever had. The cursor is the forge's own
    time of the newest comment read, and moves only when every issue named was read."""
    cursor = ctx.state.get_record(FEEDBACK_CURSOR, "comments") or {}
    since = None
    if cursor.get("since"):
        since = (_forge_time(cursor["since"]) - COMMENT_OVERLAP).isoformat().replace("+00:00", "Z")
    try:
        listed = ctx.forge.list_repo_comments(since=since)
    except ForgeError as e:
        _logger.error(f"feedback: listing the repository's comments failed, read next tick: {e}")
        return
    by_issue: dict[int, list[dict]] = {}
    for c in listed:
        if (number := _issue_number(c)) is not None:
            by_issue.setdefault(number, []).append(c)
    runs = {run["issue"]: (run_id, run) for run_id, run in ctx.state.records(FEEDBACK_CASES).items()}
    read_all = True
    for number in sorted(set(by_issue) & set(runs)):
        if runs[number][1].get("listed"):
            read_all = _read_issue(ctx, runs[number][1], by_issue[number]) and read_all
    for _number, (run_id, run) in sorted(runs.items()):
        if not run.get("listed"):
            read_all = _catch_up(ctx, run_id, run) and read_all
    stamps = [_forge_time(c.get("updated_at") or c["created_at"]) for c in listed]
    if read_all and stamps:
        newest = max(stamps).isoformat().replace("+00:00", "Z")
        ctx.state.put_record(FEEDBACK_CURSOR, "comments", {"since": newest})
