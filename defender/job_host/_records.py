"""The records a job sends on its socket, parsed on receipt (#1546 PR2, D11): each verb's record is held to its closed
shape (exact keys, typed values, bounded text) and answered as the body the helper stages, or `Malformed` with the reason
the helper stages under `refused/<name>`. Pure: no store, no session, no file.

The shapes are the design's (`outcome`, `page`, `arms`, `arm/<run id>`, `progress`, `result`). A learning
outcome's findings are screened here (#1487's channel rules, `learning.judge.enqueue.screen_findings`, under the 8 MiB
text cap): what passes is staged as rows by channel, anything else as `refused{reason}` inside the outcome, never the job's
text. The `knowledge` fact is the helper's own (`served_knowledge`, mapped once by `api_knowledge`): no job sends one."""
from __future__ import annotations

import json
import logging
import math
from collections.abc import Callable, Mapping
from typing import Any

from defender.records import job_facts, job_lane

_logger = logging.getLogger(__name__)

#: The most a record (its JSON) may hold; a learning outcome's findings text is capped on its own (8 MiB) below it.
RECORD_CAP_BYTES = 12 * 1024 * 1024
#: The longest text in any one record field but the findings text.
_TEXT_CAP = 64 * 1024

_SCRUBS = ("clean", "tainted", "not_run")
_PAGES = ("rendered", "render_failed", "none")
_SETUPS = (job_facts.SETUP_REFUSED, job_facts.SETUP_CRASHED, job_facts.SETUP_DONE)
_BOXES = (job_facts.BOX_NOT_STARTED, job_facts.BOX_START_FAILED, job_facts.BOX_STARTED)
_INV_OUTCOME = ("setup", "box", "report_committed", "scrub", "cut_short", "closing", "cost_usd", "cost_is_lower_limit")
_LEARNING_OUTCOME = ("status", "reason", "message", "fork_message_id", "stage", "sibling_cost_usd", "findings")
_LEARNING_STATUSES = (job_lane.LEARNING_COMPLETED, job_lane.LEARNING_SKIPPED, job_lane.LEARNING_FAILED,
                      job_lane.LEARNING_STOPPED)


class Malformed(Exception):  # noqa: N818 — named for what it reports
    """The record is not one of its verb's shapes; the message is the reason staged under `refused/<name>`."""


def _object(record: Any, keys: tuple[str, ...], what: str, *, optional: tuple[str, ...] = ()) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise Malformed(f"the {what} record is a {type(record).__name__}, not an object")
    missing = set(keys) - set(record)
    extra = set(record) - set(keys) - set(optional)
    if missing or extra:
        raise Malformed(f"the {what} record's fields are not its shape (missing {sorted(missing)}, "
                        f"unknown {sorted(extra)[:5]})")
    try:
        size = len(json.dumps(record, ensure_ascii=False).encode("utf-8", "surrogatepass"))
    except (TypeError, ValueError, RecursionError):
        raise Malformed(f"the {what} record does not encode as JSON") from None
    if size > RECORD_CAP_BYTES:
        raise Malformed(f"the {what} record is over {RECORD_CAP_BYTES} bytes")
    return record


def _one_of(value: Any, allowed: tuple[Any, ...], field: str) -> Any:
    if not isinstance(value, str) or value not in allowed:
        raise Malformed(f"{field} is not one of {list(allowed)}")
    return value


def _flag(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise Malformed(f"{field} is not true or false")
    return value


def _text_field(value: Any, field: str, *, nullable: bool = True) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > _TEXT_CAP:
        raise Malformed(f"{field} is not text of at most {_TEXT_CAP} characters")
    return value


def _cost_field(value: Any, field: str, *, nullable: bool = False) -> float | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise Malformed(f"{field} is not a finite number of dollars at or above 0")
    return float(value)


def _closing(value: Any) -> dict[str, Any] | None:
    """`closing`: the run's closing lookup (`found: record{disposition, review_outcome, summary}`, `never_closed`,
    `could_not_look[{wording}]`), or None before the run closed anything."""
    from defender._vocab import DISPOSITION_VALUES

    if value is None:
        return None
    if not isinstance(value, dict):
        raise Malformed("closing is not an object")
    found = value.get("found")
    if found == "record":
        _object(value, ("found", "disposition", "review_outcome", "summary"), "closing")
        _one_of(value["disposition"], DISPOSITION_VALUES, "closing.disposition")
        _text_field(value["review_outcome"], "closing.review_outcome")
        _text_field(value["summary"], "closing.summary")
    elif found == "never_closed":
        _object(value, ("found",), "closing")
    elif found == "could_not_look":
        _object(value, ("found",), "closing", optional=("wording",))
        if "wording" in value:
            _text_field(value["wording"], "closing.wording", nullable=False)
    else:
        raise Malformed("closing.found is not record, never_closed or could_not_look")
    return value


def investigation_outcome(record: Any) -> dict[str, Any]:
    """An investigation's outcome, staged as sent."""
    from defender.records.run_end import TRUNCATED_BY_VALUES

    r = _object(record, _INV_OUTCOME, "outcome")
    _one_of(r["setup"], _SETUPS, "setup")
    _one_of(r["box"], _BOXES, "box")
    _flag(r["report_committed"], "report_committed")
    _one_of(r["scrub"], _SCRUBS, "scrub")
    if r["cut_short"] is not None:
        _one_of(r["cut_short"], tuple(TRUNCATED_BY_VALUES), "cut_short")
    _closing(r["closing"])
    _cost_field(r["cost_usd"], "cost_usd", nullable=True)
    _flag(r["cost_is_lower_limit"], "cost_is_lower_limit")
    return dict(r)


def _screened(findings: Any, job_id: str) -> dict[str, Any] | None:
    """The findings field as staged: `screened{rows by channel}` when it is `ok` text whose every channel passes the
    screen, else `refused{reason}` (a closed reason, never the job's text). None stays None (no findings)."""
    from defender.learning.judge.enqueue import JudgeRefused, screen_findings

    if findings is None:
        return None
    if not isinstance(findings, dict) or not isinstance(findings.get("state"), str):
        raise Malformed("findings is not a findings field (an object with a state)")
    channels, why = job_lane.findings_of(findings)
    if channels is None:
        # #1487 r5.1 item 3: each refusal is logged with the job id and the refusal's kind (D11: the screen is the helper's).
        _logger.warning("learning job %s: its findings were refused (shape): %s", job_id, why)
        return {"state": "refused", "reason": str(why)}
    for channel in job_lane.FINDINGS_CHANNELS:
        try:
            screen_findings(channel, channels[channel], job_id)
        except JudgeRefused as refused:
            _logger.warning("learning job %s: its %s findings were refused (row rule): %s", job_id, channel, refused)
            return {"state": "refused", "reason": f"the {channel} rows were refused by the screen: {refused}"[:1000]}
    return {"state": "screened", "rows": {c: list(channels[c]) for c in job_lane.FINDINGS_CHANNELS}}


def learning_outcome(record: Any, job_id: str) -> dict[str, Any]:
    """A learning job's outcome: its end fields as sent, its findings screened (`_screened`)."""
    r = _object(record, _LEARNING_OUTCOME, "outcome")
    _one_of(r["status"], _LEARNING_STATUSES, "status")
    for field in ("reason", "message", "fork_message_id", "stage"):
        _text_field(r[field], field)
    _cost_field(r["sibling_cost_usd"], "sibling_cost_usd")
    return {**{k: r[k] for k in _LEARNING_OUTCOME if k != "findings"}, "findings": _screened(r["findings"], job_id)}


def page(record: Any) -> dict[str, Any]:
    r = _object(record, ("page",), "page")
    _one_of(r["page"], _PAGES, "page")
    return dict(r)


def canonical_run_id(value: Any) -> str | None:
    """`value` when it is a canonical run id, else None."""
    from defender.records import RunId, RunRefused

    if not isinstance(value, str):
        return None
    try:
        return value if str(RunId.parse(value)) == value else None
    except (RunRefused, ValueError):
        return None


def arms(record: Any) -> dict[str, Any]:
    """The arms roster: each arm's run id (canonical, once) and its world's id."""
    r = _object(record, ("roster",), "arms")
    roster = r["roster"]
    if not isinstance(roster, list) or not roster:
        raise Malformed("roster is not a non-empty list")
    seen: set[str] = set()
    for entry in roster:
        e = _object(entry, ("run_id", "world_id"), "arms roster entry")
        run = canonical_run_id(e["run_id"])
        if run is None or run in seen:
            raise Malformed("a roster entry's run_id is not a canonical run id, or names a run twice")
        if not _text_field(e["world_id"], "world_id", nullable=False):
            raise Malformed("a roster entry's world_id is empty")
        seen.add(run)
    return {"roster": [{"run_id": e["run_id"], "world_id": e["world_id"]} for e in roster]}


def arm(record: Any) -> dict[str, Any]:
    r = _object(record, ("scrub", "page"), "arm")
    _one_of(r["scrub"], _SCRUBS, "scrub")
    _one_of(r["page"], _PAGES, "page")
    return dict(r)


def investigation_progress_record(record: Any) -> dict[str, Any]:
    r = _object(record, ("cost_usd",), "progress")
    _cost_field(r["cost_usd"], "cost_usd")
    return dict(r)


def learning_progress_record(record: Any) -> dict[str, Any]:
    r = _object(record, ("fork_message_id", "stage", "sibling_cost_usd"), "progress")
    _text_field(r["fork_message_id"], "fork_message_id")
    _text_field(r["stage"], "stage")
    _cost_field(r["sibling_cost_usd"], "sibling_cost_usd")
    return dict(r)


def _parsed_record(record: Any, parse: Callable[[str], Any], what: str) -> dict[str, Any]:
    """A result record held to its job-lane record's exact shape: it parses, and parsed it is the same object."""
    if not isinstance(record, dict):
        raise Malformed(f"the {what} result is a {type(record).__name__}, not an object")
    _object(record, tuple(record), what)
    parsed = parse(json.dumps(record))
    if parsed is None or json.loads(parsed.text()) != record:
        raise Malformed(f"the {what} result is not one of its record's shapes")
    return dict(record)


def readiness_result(record: Any) -> dict[str, Any]:
    return _parsed_record(record, job_lane.ReadinessRecord.parse, "readiness")


def adoption_result(record: Any) -> dict[str, Any]:
    return _parsed_record(record, job_lane.AdoptionRecord.parse, "adoption")


def drain_result(record: Any) -> int:
    """A drain's result: its tick's exit status, an int."""
    if isinstance(record, bool) or not isinstance(record, int) or not -255 <= record <= 255:
        raise Malformed("the drain's result is not an exit status (an int)")
    return record


def served_knowledge(host_record: Mapping[str, Any]) -> dict[str, Any] | None:
    """The served shape `{status, commit, stale_kind}` of the knowledge record the helper itself holds (its own source's,
    main's `{kind, commit, reason}`, #1618), or None when it is not one: `current` or `pinned` only, since the helper maps
    its own source and never a stale one (#1546 r10, U-3; a job sends no knowledge record)."""
    from defender.records.formats import api_knowledge, knowledge_status

    try:
        text = json.dumps(dict(host_record))
    except (TypeError, ValueError):
        return None
    status = knowledge_status(text, stamp_names_source=True)
    served = api_knowledge(status) if status is not None and status != knowledge_status(None, stamp_names_source=True) \
        else None
    if served is None or served.get("status") not in ("current", "pinned"):
        return None
    return dict(served)


#: Each result verb's parser, by job kind.
RESULTS: dict[str, Callable[[Any], Any]] = {
    "readiness": readiness_result, "adoption": adoption_result, "drain": drain_result,
}
