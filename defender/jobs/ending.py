"""How a job row ends (#1546 PR9): a pure decision from what its helper staged, what it uploaded and what ended it, and a
pure weakening of a decision the store refused. The store's `apply` is the one writer of what a decision says.

`decide(facts, uploads, ended_by, *, kind)`:
- `facts` is the claim's staged facts, `{name: body}`, in the closed shapes the helper stages (PR2); `uploads` its upload
  rows, `{object: {"status", "scrub"}}`. Neither is changed.
- `ended_by` is one of the closed members below; anything else is a `TypeError`.
- `kind` is `investigation`, `learning` or `host_request` (readiness, adoption and drain are decided alike).
It answers an `End` (every terminal value of the row, the evidence state, the uploads to promote and the follow-ons as
values) or a `HandBack` (a stopped job that decided nothing: its lease lapses at once, with its last cost and knowledge,
and no state).

The stage rules are the worker's before #1546 (`_ending_from`, the learning and host-request fallbacks), moved: a run's
stage reads `scrub = clean` where it read a verified scrub. The evidence state is the first of r8's rules 1-7 that matches,
the same on every path (D8). Imports nothing of the runtime: the API loads `defender.jobs`."""

from __future__ import annotations

import copy
import dataclasses
from collections.abc import Mapping
from typing import Any

from defender.records.job_facts import (
    BAD_RECORD,
    BOX_START_FAILED,
    EXITED_WITHOUT_RESULT,
    EXPIRED,
    LEASE_LAPSED,
    NO_RECORD,
    OFFBOARD_MESSAGE,
    SETUP_DONE,
    SETUP_REFUSED,
    TENANT_OFFBOARDED,
    WORKER_ERROR,
    WORKER_LOST,
    WORKER_LOST_MESSAGE,
    WORKER_STOPPED,
)

INVESTIGATION, LEARNING, HOST_REQUEST = "investigation", "learning", "host_request"
KINDS = (INVESTIGATION, LEARNING, HOST_REQUEST)

#: The objects every owner pushes, and the page a rendered run or arm owes (PR8).
#: Evidence store object names under a claim (PR8), not the run's or the episode's record names.
BUNDLE = "bundle"
RUN_PAGE = "page/runtime.html"  # lint-run-records: ok — an evidence object's name under its claim, not the run record's
EPISODE_PAGE = "page/learning.html"  # lint-run-records: ok — an evidence object's name, not the episode record's
_ARM_PAGE = "page/runs/{}/runtime.html"  # lint-run-records: ok — an arm page's evidence object name (PR8)
UPLOADED = "uploaded"
#: The evidence states whose uploaded rows the ending promotes.
_KEEPS = ("complete", "partial", "lost")

_COMPLETED, _FAILED, _UNPARSEABLE, _ABORTED, _SKIPPED = "completed", "failed", "unparseable", "aborted", "skipped"
_NO_REPORT, _CANCELLED = "no_report", "cancelled"
#: A learning job's own end record saying it was stopped: it ends nothing (it is handed back).
_STOPPED = "stopped"
_CLEAN, _TAINTED, _NOT_RUN = "clean", "tainted", "not_run"

#: The fixed words of a refused end (the lesser-ends ladder's last rung).
REFUSED_WORDS = "the store refused the job's ending as decided"
_REQUEST_REFUSED_WORDS = "the store refused the request's ending as decided"
_NO_RECORD_WORDS = "the run left no job-end record; its container's status is in the helper's log"
_BAD_RECORD_WORDS = "the job's end record is not one its helper takes; none of it is kept"
_LEARNING_NO_END_WORDS = "the job left no readable end record; its container's status is in the helper's log"
_LAPSED_WORDS = "its worker stopped renewing its lease; it is retried"
_EXPIRED_WORDS = "it waited in the queue longer than the age limit before a learning slot reached it"
_NOT_LAUNCHED_WORDS = "the job was ended before its helper ran"

#: The worker's own words for each reason a host request's row can end with (#1471 surface §6, P-2): a fixed sentence per
#: reason, never a record's text.
HOST_WORDS = {
    "start_failed": "the request's helper could not start its container or open its socket",
    WORKER_ERROR: "the request's helper failed while preparing it",
    "handover": "the request's helper and its container did not agree on the request",
    "census_unavailable": "the request's container could not take the tenant's census",
    "system_gone": "the system's record was gone when the request ran",
    "no_base_files": "this release ships no base files for the system",
    "tenant_not_active": "the tenant was not active when the request ran",
    "setup_refused": "the request's helper refused to set it up",
    "repository_busy": "the tenant's repository clone was busy with another change",
    "delivery_failed": "the adoption could not be delivered to the tenant's repository",
    BAD_RECORD: "the request's record is not one its helper or container writes; none of it is kept",
    NO_RECORD: "the request's helper served it to its end and left no record",
    WORKER_STOPPED: "the worker stopped before the request recorded its end",
    WORKER_LOST: WORKER_LOST_MESSAGE,
    TENANT_OFFBOARDED: OFFBOARD_MESSAGE,
}


# --- what ended the job: the closed members ------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Exited:
    """The job's helper exited by itself: `status` 0 when it served the job to its end, else its own failure."""

    status: int = 0


@dataclasses.dataclass(frozen=True)
class Stopped:
    """The worker's stop signal reached the child."""


@dataclasses.dataclass(frozen=True)
class Lapsed:
    """The row's lease lapsed and another worker took it over."""


@dataclasses.dataclass(frozen=True)
class Cancelled:
    """A person cancelled the investigation."""


@dataclasses.dataclass(frozen=True)
class Offboarded:
    """The tenant's offboard ended the row."""


@dataclasses.dataclass(frozen=True)
class ExpiredInQueue:
    """A learning job's first attempt waited in the queue past the age limit; `words` the store's sentence for it."""

    words: str | None = None


@dataclasses.dataclass(frozen=True)
class NotLaunched:
    """The row ended before a helper ran (the worker's own fault, a fence before the start); `words` say why."""

    words: str | None = None


EndedBy = Exited | Stopped | Lapsed | Cancelled | Offboarded | ExpiredInQueue | NotLaunched
_MEMBERS = (Exited, Stopped, Lapsed, Cancelled, Offboarded, ExpiredInQueue, NotLaunched)
#: The endings that cut a running job short: its cost is the last staged progress, a lower limit (D15).
_CUT = (Lapsed, Cancelled, Offboarded)


# --- the decision ----------------------------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class FollowOns:
    """What the applier does beside the row, as values: queue the investigation's auto learning job (only when its evidence
    is `complete`), copy a completed verdict to the alert's outcome, arm the tenant's check clock."""

    auto_learning_job: bool = False
    alert_outcome: bool = False
    arm_check_clock: bool = False


@dataclasses.dataclass(frozen=True)
class Basis:
    """What an ending's evidence state was derived from, kept so `lesser` re-derives it for a lesser stage."""

    started: bool
    decided: bool
    uploaded: frozenset[str]
    owed: frozenset[str]


@dataclasses.dataclass(frozen=True)
class End:
    """A row's ending: every terminal value, the evidence state (None for a host request), the uploads to promote and the
    follow-ons. `stage` and `failure_reason` read the same for every kind (a learning row's `status` and `reason` columns
    take them). `sibling_cost_usd`, `fork_message_id` and `family_stage` are a learning job's progress; `result` a host
    request's."""

    kind: str
    ended_by: EndedBy
    stage: str
    basis: Basis
    failure_reason: str | None = None
    failure_message: str | None = None
    disposition: str | None = None
    cost_usd: float | None = None
    cost_is_lower_limit: bool = False
    #: None (a stated ending only): the row's sibling cost and progress are kept.
    sibling_cost_usd: float | None = 0.0
    sibling_cost_is_lower_limit: bool = False
    fork_message_id: str | None = None
    family_stage: str | None = None
    knowledge: dict[str, Any] | None = None
    scrub: str | None = None
    publish_state: str = "none"
    findings: dict[str, list[dict[str, Any]]] | None = None
    result: Any = None
    evidence_state: str | None = None
    promote: tuple[str, ...] = ()
    follow_ons: FollowOns = FollowOns()

    @property
    def status(self) -> str:
        """A learning row's `status`: the stage."""
        return self.stage

    @property
    def reason(self) -> str | None:
        """A learning row's `reason`: the failure reason."""
        return self.failure_reason

    @property
    def message(self) -> str | None:
        return self.failure_message


@dataclasses.dataclass(frozen=True)
class HandBack:
    """A stopped job that decided nothing: the row stays running, its lease lapses at once and its last cost and knowledge
    (a learning job's progress) are written; it gets its state at its take-over."""

    kind: str
    cost_usd: float | None = None
    cost_is_lower_limit: bool = False
    knowledge: dict[str, Any] | None = None
    #: None: the row's sibling cost and progress are kept.
    sibling_cost_usd: float | None = 0.0
    sibling_cost_is_lower_limit: bool = False
    fork_message_id: str | None = None
    family_stage: str | None = None


Decision = End | HandBack


def stated(kind: str, stage: str, **values: Any) -> End:
    """An ending its caller states value by value instead of deciding it from staged facts: the store's pre-#1546 writers
    (`finish`, `finish_learning_job`, `finish_host_request`) keep their signatures through it until their callers move to
    `decide`. Nothing was staged for it, so its evidence is `none` and it promotes nothing; a completed investigation
    copies its verdict to the alert, a completed learning job arms the check clock."""
    basis = Basis(started=False, decided=True, uploaded=frozenset(), owed=frozenset())
    end = End(kind, Exited(0), stage, basis, evidence_state=None if kind == HOST_REQUEST else "none", **values)
    return dataclasses.replace(end, follow_ons=FollowOns(alert_outcome=kind == INVESTIGATION and stage == _COMPLETED,
                                                         arm_check_clock=kind == LEARNING and stage == _COMPLETED))


def decide(facts: Mapping[str, Any], uploads: Mapping[str, Mapping[str, Any]], ended_by: EndedBy, *,
           kind: str) -> Decision:
    """The ending of a row of `kind` from its claim's staged `facts` and `uploads`, ended by `ended_by`. Pure: the same
    inputs give equal decisions, and the inputs are not changed."""
    if not isinstance(ended_by, _MEMBERS):
        raise TypeError(f"{ended_by!r} is not one of the endings ({', '.join(m.__name__ for m in _MEMBERS)})")
    if kind not in KINDS:
        raise ValueError(f"{kind!r} is not a kind of row ({', '.join(KINDS)})")
    owned: dict[str, Any] = copy.deepcopy(dict(facts))
    uploaded = frozenset(name for name, row in uploads.items() if row.get("status") == UPLOADED)
    if kind == INVESTIGATION:
        return _investigation_end(owned, uploaded, ended_by)
    if kind == LEARNING:
        return _learning(owned, uploaded, ended_by)
    return _host_request(owned, ended_by)


def lesser(decision: Decision) -> Decision:
    """The next weaker ending, for one the store refused: the knowledge replaced by the unreadable-knowledge marker (a
    learning job's findings refused), then the barest `failed`/`worker_error` with no cost, knowledge or follow-on. Each
    re-derives its evidence state; the barest is its own lesser, and a hand-back stays a hand-back."""
    if isinstance(decision, HandBack):
        return decision
    if decision.kind == LEARNING and decision.findings is not None:
        return dataclasses.replace(decision, findings=None, publish_state="refused")
    if decision.knowledge is not None and decision.knowledge != UNREADABLE_KNOWLEDGE:
        return dataclasses.replace(decision, knowledge=dict(UNREADABLE_KNOWLEDGE))
    barest = dataclasses.replace(
        decision, stage=_FAILED, failure_reason=WORKER_ERROR,
        failure_message=_REQUEST_REFUSED_WORDS if decision.kind == HOST_REQUEST else REFUSED_WORDS,
        disposition=None, cost_usd=None, cost_is_lower_limit=False, knowledge=None, publish_state="none",
        findings=None, result=None, follow_ons=FollowOns())
    if decision.kind == HOST_REQUEST:
        return barest
    state = _evidence_state(barest.ended_by, barest.basis, _FAILED)
    return dataclasses.replace(barest, evidence_state=state, promote=_promoted(state, barest.basis))


#: A started run's knowledge when it cannot be stored as read: stale, operator kind, no commit (the API's shape of
#: `records.job_lane.JobLane.unreadable_knowledge()`).
UNREADABLE_KNOWLEDGE: Mapping[str, str | None] = {"status": "stale", "commit": None, "stale_kind": "operator"}


# --- the evidence state (r8 rules 1-7) -------------------------------------------------------------------------------------

def _evidence_state(ended_by: EndedBy, basis: Basis, stage: str) -> str:
    """The first rule that matches."""
    if not basis.started:
        return "none"
    if isinstance(ended_by, Cancelled | Offboarded):
        return "none"
    if isinstance(ended_by, Lapsed) and not basis.decided:
        return "none"
    if stage == _COMPLETED:
        return "complete" if basis.owed <= basis.uploaded else "lost"
    return "partial" if BUNDLE in basis.uploaded else "none"


def _promoted(state: str, basis: Basis) -> tuple[str, ...]:
    return tuple(sorted(basis.uploaded)) if state in _KEEPS else ()


def _with_evidence(end: End) -> End:
    state = _evidence_state(end.ended_by, end.basis, end.stage)
    return dataclasses.replace(end, evidence_state=state, promote=_promoted(state, end.basis))


# --- investigations --------------------------------------------------------------------------------------------------------

def _staged_outcome(facts: Mapping[str, Any]) -> dict[str, Any] | None:
    found = facts.get("outcome")
    return found if isinstance(found, dict) else None


def _investigation_decided(outcome: dict[str, Any] | None) -> bool:
    """An outcome is staged and setup refused, or the run is tainted (D9), or its close committed with a clean scrub."""
    if outcome is None:
        return False
    return (outcome.get("setup") == SETUP_REFUSED or outcome.get("scrub") == _TAINTED
            or (bool(outcome.get("report_committed")) and outcome.get("scrub") == _CLEAN))


def _investigation_end(facts: dict[str, Any], uploaded: frozenset[str], ended_by: EndedBy) -> Decision:
    outcome = _staged_outcome(facts)
    decided = _investigation_decided(outcome)
    knowledge = facts.get("knowledge")
    cost, marked = _investigation_cost(facts, outcome, ended_by)
    if isinstance(ended_by, Stopped) and not decided:
        return HandBack(INVESTIGATION, cost_usd=cost, cost_is_lower_limit=marked, knowledge=knowledge)
    page = facts.get("page")
    owed = {BUNDLE} | ({RUN_PAGE} if isinstance(page, dict) and page.get("page") == "rendered" else set())
    basis = Basis(started="started" in facts, decided=decided, uploaded=uploaded, owed=frozenset(owed))
    stage, reason, words, disposition = _investigation_stage(facts, outcome, decided, ended_by)
    scrub = outcome.get("scrub") if outcome is not None and outcome.get("scrub") in (_CLEAN, _TAINTED, _NOT_RUN) \
        else _NOT_RUN
    end = _with_evidence(End(
        INVESTIGATION, ended_by, stage, basis, failure_reason=reason, failure_message=words, disposition=disposition,
        cost_usd=cost, cost_is_lower_limit=marked, knowledge=knowledge, scrub=scrub))
    complete = end.evidence_state == "complete"
    return dataclasses.replace(end, follow_ons=FollowOns(
        auto_learning_job=complete, alert_outcome=stage == _COMPLETED, arm_check_clock=complete))


def _investigation_cost(facts: Mapping[str, Any], outcome: dict[str, Any] | None,
                        ended_by: EndedBy) -> tuple[float | None, bool]:
    """D15: after a cut (cancel, offboard, take-over), the last staged progress, a lower limit; after an exit or a stop,
    the outcome's figure with its own mark, else the last progress as a lower limit. With no progress: unknown (null,
    unmarked) once the container started, exactly 0 when nothing started (a queued row cancelled, a launch refused)."""
    if isinstance(ended_by, NotLaunched):
        return 0.0, False
    if outcome is not None and not isinstance(ended_by, _CUT):
        figure = outcome.get("cost_usd")
        if isinstance(figure, int | float) and not isinstance(figure, bool):
            return float(figure), bool(outcome.get("cost_is_lower_limit"))
    progress = facts.get("progress")
    figure = progress.get("cost_usd") if isinstance(progress, dict) else None
    if isinstance(figure, int | float) and not isinstance(figure, bool):
        return float(figure), True
    return (None, False) if "started" in facts else (0.0, False)


def _investigation_stage(facts: Mapping[str, Any], outcome: dict[str, Any] | None, decided: bool,
                         ended_by: EndedBy) -> tuple[str, str | None, str | None, str | None]:
    """`(stage, failure reason, words, disposition)`."""
    if isinstance(ended_by, Cancelled):
        return _ABORTED, _CANCELLED, None, None
    if isinstance(ended_by, Offboarded):
        return _ABORTED, TENANT_OFFBOARDED, OFFBOARD_MESSAGE, None
    if isinstance(ended_by, NotLaunched):
        return _FAILED, WORKER_ERROR, ended_by.words or _NOT_LAUNCHED_WORDS, None
    if isinstance(ended_by, ExpiredInQueue):
        raise ValueError("an investigation does not expire in the queue")
    if isinstance(ended_by, Lapsed) and not decided:
        return _FAILED, LEASE_LAPSED, _LAPSED_WORDS, None
    if outcome is None:
        if "refused/outcome" in facts:
            return _FAILED, BAD_RECORD, _BAD_RECORD_WORDS, None
        if isinstance(ended_by, Exited) and ended_by.status != 0:
            return _FAILED, WORKER_ERROR, _exit_status_words(ended_by.status), None
        return _FAILED, _NO_REPORT, _NO_RECORD_WORDS, None
    return _run_end_stage(outcome)


def _run_end_stage(outcome: dict[str, Any]) -> tuple[str, str | None, str | None, str | None]:
    """Today's rules 1-5 from the job-end facts, the closing record read once the close committed with a clean scrub."""
    if outcome.get("setup") == SETUP_REFUSED:
        return _FAILED, "setup_refused", "run setup refused the job", None
    if outcome.get("box") == BOX_START_FAILED:
        return _FAILED, WORKER_ERROR, "the run's box did not start", None
    if outcome.get("report_committed") and outcome.get("scrub") == _CLEAN:
        return _closing_stage(outcome.get("closing"))
    if outcome.get("setup") != SETUP_DONE:
        why = "run setup crashed"
    elif not outcome.get("report_committed"):
        why = "the host committed no report"
    else:
        why = "the scrub did not verify the run folder after the box stopped"
    cut = outcome.get("cut_short")
    if isinstance(cut, str):
        why = f"{why}; the run was cut short ({cut})"
    return _FAILED, _NO_REPORT, why, None


def _closing_stage(closing: Any) -> tuple[str, str | None, str | None, str | None]:
    """A committed run's stage from its closing record's lookup: its disposition; `unparseable` with the lookup's fixed
    wording, or the committed-without-record wording."""
    found = closing.get("found") if isinstance(closing, dict) else None
    if found == "record":
        return _COMPLETED, None, None, closing.get("disposition")
    if found == "could_not_look" and isinstance(closing.get("wording"), str):
        return _UNPARSEABLE, None, closing["wording"], None
    from defender.records.closing import COMMITTED_WITHOUT_RECORD, FAULT_WORDING

    return _UNPARSEABLE, None, FAULT_WORDING[COMMITTED_WITHOUT_RECORD], None


def _exit_status_words(status: int) -> str:
    how = f"was killed by signal {-status}" if status < 0 else f"exited with code {status}"
    return f"the job's helper {how} before the job recorded its end"


# --- learning jobs ---------------------------------------------------------------------------------------------------------

def _learning(facts: dict[str, Any], uploaded: frozenset[str], ended_by: EndedBy) -> Decision:
    outcome = _staged_outcome(facts)
    status = outcome.get("status") if outcome is not None else None
    decided = outcome is not None and status != _STOPPED
    progress = _learning_progress(facts, outcome, ended_by)
    if not decided and (isinstance(ended_by, Stopped) or (status == _STOPPED and isinstance(ended_by, Exited))):
        return HandBack(LEARNING, **progress)
    owed = {BUNDLE, EPISODE_PAGE} | {_ARM_PAGE.format(name[len('arm/'):]) for name, body in facts.items()
                                    if name.startswith("arm/") and isinstance(body, dict) and body.get("page") == "rendered"}
    basis = Basis(started="started" in facts, decided=decided, uploaded=uploaded, owed=frozenset(owed))
    stage, reason, words = _learning_stage(facts, outcome, decided, ended_by)
    publish, findings = "none", None
    if stage == _COMPLETED and outcome is not None:
        screened = outcome.get("findings")
        if isinstance(screened, dict) and screened.get("state") == "screened" and isinstance(screened.get("rows"), dict):
            publish, findings = "done", {channel: list(rows) for channel, rows in screened["rows"].items()}
        else:
            publish = "refused"
    end = _with_evidence(End(LEARNING, ended_by, stage, basis, failure_reason=reason, failure_message=words,
                             publish_state=publish, findings=findings, **progress))
    # `auto_learning_job` reads as for every owner (its evidence is `complete`); the applier queues one only from an
    # investigation.
    return dataclasses.replace(end, follow_ons=FollowOns(auto_learning_job=end.evidence_state == "complete",
                                                         arm_check_clock=stage == _COMPLETED))


def _learning_progress(facts: Mapping[str, Any], outcome: dict[str, Any] | None, ended_by: EndedBy) -> dict[str, Any]:
    """The family step's progress and the siblings' cost (D15): the outcome's after an exit or a stop, else the last staged
    progress, a lower limit (0 with none, since the column is required)."""
    if isinstance(ended_by, ExpiredInQueue | NotLaunched):
        return {"sibling_cost_usd": 0.0, "sibling_cost_is_lower_limit": False}
    source: Mapping[str, Any] | None = None
    marked = True
    if outcome is not None and not isinstance(ended_by, _CUT):
        source, marked = outcome, False
    elif isinstance(facts.get("progress"), dict):
        source = facts["progress"]
    if source is None:  # the column is required: 0, a lower limit once the container started
        return {"sibling_cost_usd": 0.0, "sibling_cost_is_lower_limit": "started" in facts}
    cost = source.get("sibling_cost_usd")
    figure = float(cost) if isinstance(cost, int | float) and not isinstance(cost, bool) else 0.0
    return {"sibling_cost_usd": figure, "sibling_cost_is_lower_limit": marked,
            "fork_message_id": source.get("fork_message_id"), "family_stage": source.get("stage")}


def _learning_stage(facts: Mapping[str, Any], outcome: dict[str, Any] | None, decided: bool,
                    ended_by: EndedBy) -> tuple[str, str | None, str | None]:
    if isinstance(ended_by, Offboarded | Cancelled):
        return _SKIPPED, TENANT_OFFBOARDED, OFFBOARD_MESSAGE
    if isinstance(ended_by, ExpiredInQueue):
        return _SKIPPED, EXPIRED, ended_by.words or _EXPIRED_WORDS
    if isinstance(ended_by, NotLaunched):
        return _FAILED, WORKER_ERROR, ended_by.words or _NOT_LAUNCHED_WORDS
    if isinstance(ended_by, Lapsed) and not decided:
        return _FAILED, LEASE_LAPSED, _LAPSED_WORDS
    if decided and outcome is not None:
        status = outcome.get("status")
        if status in (_COMPLETED, _FAILED, _SKIPPED):
            return status, outcome.get("reason"), outcome.get("message")
    if "refused/outcome" in facts:
        return _FAILED, BAD_RECORD, _BAD_RECORD_WORDS
    if isinstance(ended_by, Exited) and ended_by.status != 0:
        return _FAILED, WORKER_ERROR, _exit_status_words(ended_by.status)
    return _FAILED, EXITED_WITHOUT_RESULT, _LEARNING_NO_END_WORDS


# --- host requests ---------------------------------------------------------------------------------------------------------

def _host_request(facts: dict[str, Any], ended_by: EndedBy) -> End:
    """Readiness, adoption, drain: decided by a staged `result`; never handed back, never retried."""
    basis = Basis(started="started" in facts, decided="result" in facts, uploaded=frozenset(), owed=frozenset())
    if isinstance(ended_by, Offboarded | Cancelled):
        return _host_request_failed(ended_by, basis, TENANT_OFFBOARDED)
    if "result" in facts:
        result = facts["result"]
        if isinstance(result, dict) and result.get("outcome") == _FAILED and isinstance(result.get("reason"), str):
            return _host_request_failed(ended_by, basis, result["reason"])
        if isinstance(result, dict) and "knowledge" in facts:
            result = {**result, "knowledge": facts["knowledge"]}
        return End(HOST_REQUEST, ended_by, _COMPLETED, basis, result=result)
    if isinstance(ended_by, Stopped):
        return _host_request_failed(ended_by, basis, WORKER_STOPPED)
    if isinstance(ended_by, Lapsed):
        return _host_request_failed(ended_by, basis, WORKER_LOST)
    if "refused/result" in facts:
        return _host_request_failed(ended_by, basis, BAD_RECORD)
    if isinstance(ended_by, Exited) and ended_by.status != 0:
        return _host_request_failed(ended_by, basis, WORKER_ERROR, _exit_status_words(ended_by.status))
    if isinstance(ended_by, NotLaunched | ExpiredInQueue):
        return _host_request_failed(ended_by, basis, WORKER_ERROR, ended_by.words)
    return _host_request_failed(ended_by, basis, NO_RECORD)


def _host_request_failed(ended_by: EndedBy, basis: Basis, reason: str, words: str | None = None) -> End:
    return End(HOST_REQUEST, ended_by, _FAILED, basis, failure_reason=reason,
               failure_message=words or HOST_WORDS.get(reason, HOST_WORDS[WORKER_ERROR]))


__all__ = ["BUNDLE", "EPISODE_PAGE", "HOST_WORDS", "KINDS", "REFUSED_WORDS", "RUN_PAGE", "UNREADABLE_KNOWLEDGE", "Basis",
           "Cancelled", "Decision", "End", "EndedBy", "Exited", "ExpiredInQueue", "FollowOns", "HandBack", "Lapsed",
           "NotLaunched", "Offboarded", "Stopped", "decide", "lesser", "stated"]
