"""The feedback tick (#1414 F2): a person's comment on a Forgejo issue becomes a lesson row or a
registry entry on a PR a person merges.

One tick, four steps (`run`): open issues for finished runs, read the comments of people who may
merge, decide each once, draft approved entries onto a registry PR; then post the replies owed.
Everything but the host's few records is derived from what Forgejo shows each tick, so a crash at
any step boundary is a redo (P5). Steps 3 and 4 live in `feedback_decide` and `feedback_registry`.

The records are rows of the learning store (#1278 A4): a run's request and its issue are one
`feedback_issues` row, a comment taken in and its decision one `feedback_comments` row, the comment
cursor and the tick's lease the tenant's `feedback_tick` row. The tick runs under that lease, taken
try-once (one tick per tenant, O12) and renewed from a thread; every write it makes is fenced by the
lease's token, and it confirms the lease before each forge write. A lost lease, a cancel and a tenant
gone off active halt the tick; any other fault is contained to its step (P9).
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
from defender.learning.core.config import FEEDBACK_DRAIN_LABEL, FatalConfigError, LoopPaths

_logger = logging.getLogger(__name__)

FEEDBACK_LABEL = "defender-feedback"
#: How long the service's merge-eligibility record may be before the tick reads no comments (D13/D15).
ELIGIBILITY_MAX_AGE_ENV = "LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE"
DEFAULT_ELIGIBILITY_MAX_AGE = dt.timedelta(seconds=60)
#: The longest issue title the forge takes; the host's own title is cut to it, so it is never refused for length.
TITLE_LIMIT = 255
#: How far back of the last comment read each tick asks again: a comment the forge dated just before it but
#: listed only later is still found. A comment already judged (its id recorded) is not read twice.
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


def storable(text: str) -> str:
    """`text` as the learning store can hold it (A4): a NUL and a lone surrogate, which jsonb and the wire refuse,
    each become U+FFFD. Applied to every text from the forge or the model before it is stored."""
    return "".join("�" if ch == "\x00" or "\ud800" <= ch <= "\udfff" else ch for ch in str(text))


def _fence(text: str) -> str:
    return "```\n" + str(text).replace("`", "'") + "\n```"


def _summary(run_id: str, outcome: str, lookups: Any) -> str:
    """A run's summary, fenced like run content (P4); it follows the host-written first line."""
    lines = "\n".join(f"lookup: {lk['actor']} / {lk['host']} / {lk['pattern']}" for lk in lookups)
    return _fence(f"run {run_id} ended {outcome}\n{lines}")


def _forge_time(text: str) -> dt.datetime:
    parsed = parse_iso_utc(text)
    if parsed is None:
        raise ValueError(f"the forge sent a timestamp that is no ISO date: {text!r}")
    return parsed


def _forge_stamp(when: dt.datetime) -> str:
    return when.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


@dataclasses.dataclass
class Tick:
    """What one tick works over: the store (sync face), the tick's lease and its holding, the forge."""

    store: Any
    held: Any
    hold: Any
    forge: Any
    bots: frozenset[str]
    tenant_id: str
    eligible: frozenset[str] | None = None
    #: First line -> issue number of every feedback issue a tenant bot made: read once per tick, when needed.
    made: dict[str, int] | None = None

    def confirm(self) -> None:
        """Before a forge write: the tick still holds its lease (A4 F2 step 0). A stop halts the tick (P9)."""
        self.hold.check()
        self.store.renew_feedback_tick(self.held)

    def issues(self) -> list[Any]:
        return list(self.store.feedback_issues(self.tenant_id))

    def comments(self) -> list[Any]:
        return list(self.store.feedback_comments(self.tenant_id))


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


# ------------------------------------------------------------------ the tick's lease (O12) and its stops (P9)

def _knobs() -> dict[str, Any]:
    """The store's knobs, refused when a late forge write could outlive the lease that fenced it: the forge's
    network bound must be shorter than lease + grace (A4 F2 step 0, fail closed)."""
    from defender.learning.author.version_control.repository import NETWORK_TIMEOUT
    from defender.learning.core.store_tick import store_knobs
    from defender.learning.store._store import DEFAULT_GRACE_SECONDS, DEFAULT_LEASE_SECONDS

    knobs = store_knobs()
    lease, grace = float(knobs.get("lease", DEFAULT_LEASE_SECONDS)), float(knobs.get("grace", DEFAULT_GRACE_SECONDS))
    if lease + grace <= NETWORK_TIMEOUT:
        raise FatalConfigError(f"the feedback tick's lease ({lease:.0f}s) plus its grace ({grace:.0f}s) must outlast "
                               f"the forge's network bound ({NETWORK_TIMEOUT:.0f}s): a late issue create could "
                               "otherwise follow a takeover")
    return knobs


def _halts() -> tuple[type[BaseException], ...]:
    """What ends the tick rather than one step: a lost lease or a cancel (`Stop`), a tenant off active."""
    from defender.learning.store import Stop, TenantInactive

    return (Stop, TenantInactive)


def run(paths: LoopPaths, open_delivery: Callable[[], Any], records: Any, *, decide: Callable[..., dict],
        eligibility_max_age: dt.timedelta | None = None) -> int:
    """One feedback tick for the selected tenant, under its feedback tick lease, over the learning store at
    `DEFENDER_DATABASE_DSN` (opened through `defender.learning.store.blocking`). Another live holder of the lease,
    or a tenant off active, is a clean exit 0 that does nothing."""
    from defender.learning import store as store_mod
    from defender.learning.core.store_tick import DSN_ENV, owner_name

    tenant = paths.tenant
    if tenant is None:
        raise FatalConfigError("the feedback tick serves one selected tenant: none is selected")
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        raise FatalConfigError(f"the learning store is read from {DSN_ENV}, which is not set")
    knobs = _knobs()
    with store_mod.blocking(dsn, **knobs) as store:
        try:
            held = store.begin_feedback_tick(str(tenant.id), owner=owner_name(str(FEEDBACK_DRAIN_LABEL)))
        except store_mod.TenantInactive:
            _logger.info("feedback_drain: the tenant is not active — exiting")
            return 0
        if held is None:
            _logger.warning("feedback_drain: another feedback tick holds the lease — exiting")
            return 0
        return _under_lease(paths, store, held, open_delivery, records, decide=decide,
                            eligibility_max_age=eligibility_max_age)


def _under_lease(paths: LoopPaths, store: Any, held: Any, open_delivery: Callable[[], Any], records: Any, *,
                 decide: Callable[..., dict], eligibility_max_age: dt.timedelta | None) -> int:
    """The tick's steps under its lease, and the lease's end: released at once on any end but a lost lease (A2 D4's
    clean stop); a lost lease does nothing more."""
    from defender.learning.core.store_tick import Holding, TickStopped
    from defender.learning.store import LeaseLost

    lost = False
    try:
        with Holding(store, held, renew=store.renew_feedback_tick) as hold:
            _steps(paths, store, held, hold, open_delivery, records, decide=decide,
                   eligibility_max_age=eligibility_max_age)
    except TickStopped as stopped:
        lost = stopped.why == "lease"
        _logger.warning(f"feedback_drain: the tick stopped ({stopped.why}); nothing more is done")
        if stopped.why == "sigterm":
            _release(store, held)
            raise
    except LeaseLost:
        lost = True
        _logger.warning("feedback_drain: the tick's lease was lost (taken over, or it ran out); nothing more is done")
    except _halts() as stop:
        _logger.warning(f"feedback_drain: the tick stopped ({type(stop).__name__}: {stop}); nothing more is done")
    except BaseException:
        _release(store, held)
        raise
    if not lost:
        _release(store, held)
    return 0


def _release(store: Any, held: Any) -> None:
    from defender.learning.store import LeaseLost

    try:
        store.end_feedback_tick(held)
    except LeaseLost:
        _logger.warning("feedback_drain: the tick's lease was no longer its own at the end; nothing released")


def _steps(paths: LoopPaths, store: Any, held: Any, hold: Any, open_delivery: Callable[[], Any], records: Any, *,
           decide: Callable[..., dict], eligibility_max_age: dt.timedelta | None) -> None:
    from defender.learning.core import drains, store_tick
    from defender.tenancy import RecordsUnreachable

    tenant = paths.tenant
    assert tenant is not None, "the feedback tick runs for one selected tenant"
    with open_delivery() as opened:
        try:
            bots = frozenset(g.bot_login for g in records.generations(tenant.id))
            eligible = _eligible_logins(records, tenant.id, eligibility_bound(eligibility_max_age), bots)
        except RecordsUnreachable as down:
            raise drains._Refused(f"the tenant {tenant.id}'s records could not be read: {down}", transient=True) from None
        delivery = dataclasses.replace(opened, branch_prefix=store_tick.PREFIX_OF[store_tick.FEEDBACK_LANE])
        ctx = Tick(store, held, hold, delivery.repository.forge, bots, str(tenant.id), eligible)
        lane = store_tick.Tick(paths=paths, lane=store_tick.FEEDBACK_LANE, label=FEEDBACK_DRAIN_LABEL, store=store,
                               open_delivery=open_delivery, author_work=_no_work, start_box=None,
                               stop_box=_no_box, reconcile_lanes=(store_tick.FEEDBACK_LANE,), boxed=False,
                               parent=hold)
        _isolated_step("opening issues", lambda: _open_requests(ctx))
        if ctx.eligible is not None:
            _isolated_step("reading comments", lambda: _read_comments(ctx))
            _isolated_step("deciding comments", lambda: feedback_decide.decide_comments(ctx, decide))
        _isolated_step("drafting registry entries", lambda: feedback_registry.draft(ctx, delivery, lane))
        _isolated_step("replying", lambda: feedback_registry.reply(ctx))


def _no_work(*_args: Any, **_kw: Any) -> None:
    raise AssertionError("the registry lane authors only through its own claim")


def _no_box(_box: Any) -> None:
    """The registry lane runs no box (no model runs in it)."""


def _isolated_step(name: str, run: Callable[[], None]) -> None:
    """One step of the tick. Every step is a redo from what the forge and the records show (P5), so a failure of
    any kind is logged and the next step still runs: a broken registry file stops the draft, never the replies
    (ruling 2026-11-10: steps are isolated). A stop is not a failure: it ends the tick (P9)."""
    try:
        run()
    except _halts():
        raise
    except Exception as e:  # noqa: BLE001 — one step's failure never costs the tick its other steps
        _logger.error(f"feedback: {name} failed, retried next tick: {e!r}", exc_info=True)


# ------------------------------------------------------------------ step 1: open

def _issue_index(ctx: Tick) -> dict[str, int]:
    """First line -> number of every feedback issue a tenant bot made, read whole or not at all: a listing that
    fails raises, and no request is served from part of one."""
    made: dict[str, int] = {}
    for bot in sorted(ctx.bots):
        for issue in ctx.forge.list_issues(label=FEEDBACK_LABEL, created_by=bot, state="all"):
            if issue["user"]["login"] in ctx.bots:
                made.setdefault((issue.get("body") or "").split("\n")[0], issue["number"])
    return made


def _serve_request(ctx: Tick, request: Any) -> None:
    """Give the run its own issue (ruling 5): found on the forge by its first line (made by a tick that never
    recorded it), else created; then recorded on the run's row, where it has none yet."""
    assert ctx.made is not None, "the issue index is read before any request is served"
    run_id, case_id = request.run_id, request.case_id
    number = ctx.made.get(_first_line(case_id, run_id))
    if number is None:
        title = sendable(f"Feedback on case {case_id} run {run_id} ({request.outcome})")[:TITLE_LIMIT]
        ctx.confirm()
        number = ctx.forge.create_issue(
            title=title,
            body=sendable(_first_line(case_id, run_id) + "\n" + _summary(run_id, request.outcome, request.lookups)),
            label=FEEDBACK_LABEL)["number"]
    ctx.store.record_feedback_issue(ctx.held, run_id, int(number))


def _open_requests(ctx: Tick) -> None:
    """Serve every run owed an issue. The forge's feedback issues are listed first, whole: a listing that fails
    leaves every request for the next tick (a request is never served from part of it, which could make a second
    issue for a run whose first was never recorded)."""
    requests = [r for r in ctx.issues() if r.issue_number is None]
    if not requests:
        return
    try:
        ctx.made = _issue_index(ctx)
    except ForgeError as e:
        _logger.error(f"feedback: listing the feedback issues failed, every request waits for the next tick: {e}")
        return
    for request in requests:
        try:
            _serve_request(ctx, request)
        except ForgeError as e:
            # Never given up: the text is the host's own and always sendable, so a failure is the forge's state
            # (down, throttling, or a bot not yet granted issues), and the request waits for it (ruling 2026-11-10: no refusal ceiling).
            _logger.error(f"feedback: opening the issue of case {request.case_id} failed, retried next tick: {e}")


# ------------------------------------------------------------------ step 2: read

def _readable(issue: dict, new: list[dict]) -> list[dict]:
    """The comments of `new` a tick may read: all of them on an open issue, only those written before
    the close, or in the same second as it, on a closed one (D12: as the tick observes it)."""
    if issue["state"] == "open":
        return new
    return [c for c in new if _forge_time(c["created_at"]) <= _forge_time(issue["closed_at"])]


def _taken(issue: dict, c: dict) -> dict[str, Any]:
    """A comment taken in, as the store keeps it (A4): its text as the store can hold it."""
    return {"comment_id": int(c["id"]), "author": storable(c["user"]["login"]), "created": storable(c["created_at"]),
            "body": storable(c["body"]), "issue_url": storable(issue["html_url"])}


def _read_issue(ctx: Tick, run: Any, comments: list[dict], *, listed: bool = False) -> bool:
    """Read the listed `comments` of the run's issue, judging each new one once, in one store write (`listed`: this
    read was the issue's own whole listing). False when the issue could not be read (retried next tick)."""
    number = run.issue_number
    try:
        issue = ctx.forge.get_issue(number)
    except ForgeError as e:
        if e.status == 404:
            _logger.warning(f"feedback: issue {number} of case {run.case_id} is gone from the forge; "
                            "read as closed, nothing to read")
            if listed:
                ctx.store.judge_comments(ctx.held, run.run_id, taken=[], judged=[], listed=True)
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
    seen = set(run.judged_comment_ids)
    new = sorted((c for c in comments if c["id"] not in seen), key=lambda c: c["id"])
    if not new:
        if listed and not run.listed:
            ctx.store.judge_comments(ctx.held, run.run_id, taken=[], judged=[], listed=True)
        return True
    taken: list[dict[str, Any]] = []
    skipped: set[str] = set()
    for c in _readable(issue, new):
        if c["user"]["login"] in (ctx.eligible or ()):
            taken.append(_taken(issue, c))
        else:
            skipped.add(c["user"]["login"])
    if skipped:
        _logger.info(f"feedback: issue {number}: skipped comments by accounts that may not merge: {sorted(skipped)}")
    ctx.store.judge_comments(ctx.held, run.run_id, taken=taken, judged=[c["id"] for c in new], listed=listed)
    return True


def _issue_number(comment: dict) -> int | None:
    """The issue a repository comment is on, from its `issue_url` (a PR's comment carries none)."""
    tail = str(comment.get("issue_url") or "").rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdecimal() else None


def _catch_up(ctx: Tick, run: Any) -> bool:
    """A newly recorded issue's first read lists its own comments whole: a comment written before the tick that
    recorded it (an issue made, its reply lost, recovered later) may already be behind the repository cursor."""
    try:
        comments = ctx.forge.list_comments(run.issue_number)
    except ForgeError as e:
        if e.status != 404:
            _logger.error(f"feedback: reading issue {run.issue_number} failed, position kept: {e}")
            return False
        comments = []
    return _read_issue(ctx, run, comments, listed=True)


def _read_comments(ctx: Tick) -> None:
    """Read the comments made since the last tick, in one repository listing: only issues with new comments are
    looked at, so the work follows the comments, not every issue the tenant ever had. The cursor is the forge's own
    time of the newest comment read, and moves only when every issue named was read."""
    cursor = ctx.held.comments_since
    since = _forge_stamp(cursor - COMMENT_OVERLAP) if cursor is not None else None
    try:
        listed = ctx.forge.list_repo_comments(since=since)
    except ForgeError as e:
        _logger.error(f"feedback: listing the repository's comments failed, read next tick: {e}")
        return
    by_issue: dict[int, list[dict]] = {}
    for c in listed:
        if (number := _issue_number(c)) is not None:
            by_issue.setdefault(number, []).append(c)
    runs = {r.issue_number: r for r in ctx.issues() if r.issue_number is not None}
    read_all = True
    for number in sorted(set(by_issue) & set(runs)):
        if runs[number].listed:
            read_all = _read_issue(ctx, runs[number], by_issue[number]) and read_all
    for _number, run in sorted(runs.items()):
        if not run.listed:
            read_all = _catch_up(ctx, run) and read_all
    stamps = [_forge_time(c.get("updated_at") or c["created_at"]) for c in listed]
    if read_all and stamps:
        newest = max(stamps)
        if cursor is None or newest > cursor:
            ctx.store.advance_comment_cursor(ctx.held, _forge_stamp(newest))
