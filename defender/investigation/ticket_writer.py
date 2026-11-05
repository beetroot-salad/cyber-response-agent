#!/usr/bin/env python3
"""The host's one write to a case (#1359): at the end of a run started with `--update-ticket`, add
one comment to the ticket the alert names, through the case system's adapter. The product decides
what and when (exit class, body, agent tag, stale sentence, bound, receipt); the adapter decides
how (request shape, text format, what a status means, the ticket's web link). Nothing is created
or transitioned here, and nothing is called at run start."""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path

from defender.kit.faults import AdapterFault, ConfigFault, TransportFault, UpstreamFault
from defender.kit.settings import config_pointer
from defender.records import Run, RunPaths, formats, run_end
from defender.systems import case_system
from defender.systems.run_tenant import RunTenant
from defender.systems.verbs import VerbContext, redact_settings_path
from defender.tenancy import case_ticket

_logger = logging.getLogger(__name__)


def _verb_context(tenant: RunTenant, defender_dir: Path, run_dir: Path,
                  env: Mapping[str, str], request_token: str | None = None,
                  proxy_url: str | None = None) -> VerbContext:
    """The adapter's context, built wholly from what `run.py` handed this leg: the run's record
    (its settings and the case-record file resolved from them when the run began), the code tree,
    the run dir and the run's environment. Nothing here finds its own location or reads the
    process (#1107). `request_token` and `proxy_url` are the write-back grant and the proxy's
    address for a store reached through the credential proxy (#1163), handed by run.py."""
    return VerbContext(defender_dir=defender_dir, run_dir=run_dir, env=env, tenant=tenant,
                       request_token=request_token, proxy_url=proxy_url)


#: The receipt words: `commented` (the record) and `escalated` (the cut-short note) are the two
#: comments the host can make; `error` is a failed call; `unknown` is a comment whose answer was
#: lost after it may have reached the store and which the read-back could not settle (#1374).
#: There is no `closed`: the host never transitions a case.
RECEIPT_COMMENTED = "commented"
RECEIPT_ESCALATED = "escalated"
RECEIPT_ERROR = "error"
RECEIPT_UNKNOWN = "unknown"
_RECEIPT_OK = frozenset({RECEIPT_COMMENTED, RECEIPT_ESCALATED})

#: Receipt reasons whose wording the product owns (O5).
REASON_NO_TICKET = (
    "the alert names no ticket: the tenant's alert mapping maps no `case_key`, or the alert "
    "holds none a ticket key can be made of")
REASON_NO_TOKEN = (
    "the write-back token could not be minted, so the comment was not sent (see the run log)")


def _comment_body(
    run: Run, truncated_by: str | None, settings: case_ticket.CaseRecordSettings,
) -> tuple[str, str]:
    """The comment text and its receipt word.

    An unreadable report (`ReportNotParsable`) gets the fixed unreadable-branch sentence — or,
    on a forced-close exit, the escalation note, since the host's own forced close failed and
    there is no verdict. Any other `CaseTicketError` (a template that does not render)
    propagates to the caller's refusal branch (no call, a warning, an `error` receipt)."""
    try:
        rec = case_ticket.read_case_record(run)
    except case_ticket.ReportNotParsable:
        if truncated_by in run_end.FORCED_CLOSE_EXITS:
            return case_ticket.escalation_comment_body(truncated_by), RECEIPT_ESCALATED
        return case_ticket.unreadable_comment_body(), RECEIPT_COMMENTED
    return case_ticket.case_record_to_comment(rec, settings=settings), RECEIPT_COMMENTED


def _ticket_key(run: Run) -> str | None:
    """The ticket the alert names: the `case_key` fact recorded from the alert when the run began
    (#1359 P3), or `None`. Never read off the alert again."""
    record = formats.parse_alert_record(run.facts.alert_record.read() or "")
    return None if record is None else record.facts.case_key


def comments_on(truncated_by: str | None, closed_before_cut: bool) -> bool:
    """Does a run that ended this way comment on its case? Not a run cut short by its budget,
    its store or its model provider before it reached a verdict: it leaves the case open and
    writes no receipt. The one rule, read by the record step and by `run.py`, which signs no
    write-back token for a run that will not comment."""
    return closed_before_cut or run_end.normalized_truncated_by(truncated_by) not in (
        run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE,
        run_end.TRUNCATED_BY_PROVIDER_DOWN)


def record_case_ticket(  # noqa: PLR0913 — the lane's inputs are the run's exit record (#1047)
    run: Run, *, tenant: RunTenant, defender_dir: Path, env: Mapping[str, str],
    truncated_by: str | None = None, closed_before_cut: bool = False,
    request_token: str | None = None, proxy_url: str | None = None,
    case: case_system.CaseTarget | case_system.CaseSettingsFault | None = None,
) -> None:
    """Record the investigation into the case, never close it: at most one comment on the ticket
    the alert names, no transition. Closing is a person's act, which is what lets the store's
    `closed` mean "a person reviewed this". Every path that meant to call out but did not leaves
    a warning and an `error` receipt.

    `case` is the case system's verdict run start made (`case_system.case_verdict`), the one the
    write-back token was minted on; without it (a direct caller) the step judges the record."""
    run_dir = run.run_dir
    key = ""
    try:
        key = _ticket_key(run) or ""
        truncated_by = run_end.normalized_truncated_by(truncated_by)  # F-I — first act
        if not comments_on(truncated_by, closed_before_cut):
            clear_receipt(run)
            _logger.info(f"{run_dir.name}: run ended ({truncated_by}) with no verdict; "
                         "leaving ticket open")
            return
        target = case if case is not None else case_system.case_verdict(
            tenant, defender_dir=defender_dir)
        if isinstance(target, case_system.CaseSettingsFault):
            _leg_refused(run, key, redact_settings_path(str(target), tenant.settings))
            return
        if not key:
            _leg_refused(run, key, REASON_NO_TICKET)
            return
        proxied = target.system in tenant.access  # reached through the credential proxy
        if proxied and not request_token:
            _leg_refused(run, key, REASON_NO_TOKEN)
            return
        try:
            if truncated_by == run_end.TRUNCATED_BY_ABORTED and not closed_before_cut:
                body, word = case_ticket.escalation_comment_body(truncated_by), RECEIPT_ESCALATED
            else:
                body, word = _comment_body(run, truncated_by, target.template)
        except case_ticket.CaseTicketError as e:
            # The template refused: no call, but the receipt still says so.
            _leg_refused(run, key, redact_settings_path(f"{case_system.CASE_RECORD_POINTER}: {e}",
                                                   tenant.settings))
            return
        _post_comment(run, target, key, body, word,
                      _verb_context(tenant, defender_dir, run_dir, env, request_token, proxy_url))
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _logger.warning(f"record raised, ignored: {e!r}")
        # Only the exception's type reaches the receipt (and so the page): its text may carry a
        # host path or a store's body; the log line above has it whole.
        _write_receipt(run, None, key, RECEIPT_ERROR,
                       f"the record step failed unexpectedly ({type(e).__name__}); see the run log")


def _leg_refused(run: Run, key: str, reason: str) -> None:
    """No call was made: a warning and an `error` receipt carrying `reason`."""
    _logger.warning(f"record {key or run.run_dir.name}: {reason}; not recording")
    _write_receipt(run, None, key, RECEIPT_ERROR, reason)


def _fault_reason(fault: AdapterFault, *, tenant: RunTenant, system: str) -> str:
    """The receipt reason for a fault the case system's comment action raised (O5): its subject
    is the credential proxy when the fault is the proxy's own (`proxy_own`, #1404), else the
    store or the settings, chosen by class; from the fault's data, never the route or its text.
    The fault's own detail follows, redacted."""
    detail = redact_settings_path(fault.detail, tenant.settings)
    if fault.proxy_own:
        # It failed (perhaps after the store took the comment: no claim of non-delivery) or it
        # refused the call (#1398).
        if isinstance(fault, TransportFault):
            return f"the credential proxy failed: {detail}"
        return f"the credential proxy refused the call: {detail}"
    if isinstance(fault, UpstreamFault):
        status = fault.status
        shown = "" if status is None else f" (HTTP {status}{', not found' if status == 404 else ''})"
        return f"the store refused the comment{shown}: {detail}"
    if isinstance(fault, TransportFault):
        return f"the store could not be reached: {detail}"
    if isinstance(fault, ConfigFault):
        return f"{config_pointer(system)}: {detail}"
    return f"the write was refused before it was sent: {detail}"


#: The one sentence a stale run's every comment carries (#1108 P4, O-WARN): the kind in the
#: customer's words and the commit used, never the publish's raw reason (no URL, error text or
#: credential hint reaches a ticket). Fresh and pinned runs carry none.
STALE_SENTENCE = {
    formats.TRANSIENT: (
        "Knowledge notice: this investigation used the tenant's knowledge as of an earlier "
        "version (commit {commit}) because newer approved knowledge could not be loaded due to "
        "a temporary problem."),
    formats.OPERATOR: (
        "Knowledge notice: this investigation used the tenant's knowledge as of an earlier "
        "version (commit {commit}) because newer approved knowledge could not be loaded; this "
        "is awaiting operator action."),
}
#: OD22': the run's knowledge record is unreadable, so no version can be named.
UNREADABLE_SENTENCE = (
    "Knowledge notice: this investigation may have used an earlier version of the tenant's "
    "knowledge because the record of which version it used could not be read; this is awaiting "
    "operator action.")


def stale_sentence(run_dir: Path) -> str | None:
    """The stale sentence for the run at `run_dir`, from its HOST-held knowledge record (U12),
    or `None` for a fresh, pinned or pre-P4 run. The stamp in the run dir decides nothing here
    beyond whether a record should exist (OD22')."""
    paths = RunPaths(run_dir)
    status = formats.read_knowledge_status(paths.knowledge_source(), paths.provenance)
    if status is None or not status.stale:
        return None
    if status.commit is None:
        return UNREADABLE_SENTENCE
    return STALE_SENTENCE[status.stale_kind or formats.OPERATOR].format(
        commit=status.commit)


def _with_stale_sentence(run: Run, body: str) -> str:
    """`body` with the stale sentence opening it when the run's knowledge was stale. First, so the
    wire bound — which cuts from the end — never takes it off a long verdict."""
    sentence = stale_sentence(run.run_dir)
    return body if sentence is None else f"{sentence}\n\n{body}"


def _post_comment(  # noqa: PLR0913 — one call site's worth of context, threaded not re-derived
    run: Run, target: case_system.CaseTarget, key: str, body: str, word: str, ctx: VerbContext,
) -> None:
    """The one write the host makes to a case: one comment whose body opens with the agent tag
    naming this run (`case_ticket.posted_comment`, #1221 — here, so no comment kind can leave
    untagged), then the stale sentence when the run's knowledge was stale (O-WARN, every branch
    alike), and a receipt either way. No read-back first: whether a person has closed the case
    changes nothing, since every comment is served to later runs and ours are tagged (#1221 A1)."""
    posted = case_ticket.posted_comment(_with_stale_sentence(run, body), run_id=str(run.id))
    try:
        link = target.add_case_comment(ctx, key=key, body=posted)
    except AdapterFault as fault:
        reason = _fault_reason(fault, tenant=ctx.tenant, system=target.system)
        if isinstance(fault, TransportFault) and fault.maybe_delivered:
            _settle_lost_answer(run, target, key, posted, word, ctx, reason)
            return
        _logger.warning(f"record {key}: {reason}")
        _write_receipt(run, None, key, RECEIPT_ERROR, reason)
        return
    _logger.info(f"record {key}: comment posted ({word}); run_dir={run.run_dir}")
    _commented(run, key, posted, word, link)


def _commented(run: Run, key: str, posted: str, word: str, link: object) -> None:
    """The store holds the comment: record it and write the success receipt."""
    _record_posted_comment(run, key, posted)
    _write_receipt(run, link if isinstance(link, str) and link else None, key, word, None)


def _settle_lost_answer(  # noqa: PLR0913 — the write's own context, threaded not re-derived
    run: Run, target: case_system.CaseTarget, key: str, posted: str, word: str, ctx: VerbContext,
    lost: str,
) -> None:
    """The comment's answer was lost after it may have reached the store (#1374 P1): read the case
    back once (P4) and decide from this run's tag line (P3). Found is a success; a read that saw
    no such comment is an error; anything else (no read-back, any exception) is `unknown`, which
    names the ticket and the tag to look for. Never a second write."""
    tag = case_ticket.agent_comment_tag(str(run.id))
    lost = f"the store's answer to the comment was lost ({lost})"
    look = f"check ticket {key} for a comment tagged {tag}"
    read_back = target.find_case_comment
    if read_back is None:
        _unknown(run, key, f"{lost}, and {target.system}'s connector cannot read the case back: {look}")
        return
    try:
        found, link = read_back(ctx, key=key, tag=tag)
        if not isinstance(found, bool):
            raise TypeError(f"the read-back answered {type(found).__name__}, not a bool")
    except AdapterFault as fault:
        why = redact_settings_path(fault.detail, ctx.tenant.settings)
        _unknown(run, key, f"{lost}, and reading the case back failed ({why}): {look}")
        return
    except Exception as e:  # noqa: BLE001 — once the write may have landed, only a completed read decides
        _logger.warning(f"record {key}: the read-back raised: {e!r}")
        # Only the type reaches the receipt, as in the record step's own catch-all.
        _unknown(run, key, f"{lost}, and reading the case back failed ({type(e).__name__}): {look}")
        return
    if found:
        _logger.info(f"record {key}: the answer was lost; the read-back found the comment ({word})")
        _commented(run, key, posted, word, link)
        return
    reason = f"{lost}, and reading the case back found no comment from this run: it was not posted"
    _logger.warning(f"record {key}: {reason}")
    _write_receipt(run, None, key, RECEIPT_ERROR, reason)


def _unknown(run: Run, key: str, reason: str) -> None:
    _logger.warning(f"record {key}: {reason}")
    _write_receipt(run, None, key, RECEIPT_UNKNOWN, reason)


def _record_posted_comment(run: Run, key: str, body: str) -> None:
    """@owns ticket_comments — append the comment the store just accepted, `{key, body}`, to the
    run's host-only record of its writes to the world (`RunPaths.ticket_comments`, beside the
    run folder). A world branched from this run serves the case as it stood at the fork, so its
    oracle is handed these writes (#1255 P5, O6; `case_ticket.read_posted_comments`). `key` is the
    ticket's. Best-effort like every post-step: a failed append is a warning and never changes
    the receipt."""
    try:
        run.observability.ticket_comments.append([{"key": key, "body": body}])
    except OSError as e:
        _logger.warning(f"record {key}: the posted comment could not be recorded: {e}")


def receipt_path(run_dir: Path) -> Path:
    """The receipt: a sidecar beside the run dir, keyed by the run's name, like the scrub verdict.
    Never inside the run dir, where the box is root while it runs and could plant a receipt or
    block the host's write with a directory at its name."""
    run_dir = Path(run_dir)
    return RunPaths(run_dir).ticket_write()


def clear_receipt(run: Run) -> None:
    """Remove the receipt an earlier attempt on this run dir left, if any: a record-step branch
    that writes no receipt must not leave one for the page to show."""
    try:
        run.observability.ticket_write.delete()
    except OSError as e:
        _logger.warning(f"could not clear the stale receipt: {e}")


def _write_receipt(
    run: Run, url: str | None, key: str, status: str, reason: str | None,
) -> None:
    """@owns ticket_write receipt — `{key, status, url, ok, reason}`, the one shape the page
    reads. `key` is the ticket's (empty when the alert names none); `url` is the ticket's web link
    when the adapter gave one and null on every error receipt; `reason` is null on a success and
    the redacted failing text on every other status."""
    receipt = {
        "key": key,
        "status": status,
        "url": url,
        "ok": status in _RECEIPT_OK,
        "reason": reason,
    }
    try:
        run.observability.ticket_write.write(json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _logger.warning(f"could not write receipt: {e}")


# The path accessor remains the public read-side compatibility surface for run pages.
__all__ = ["comments_on", "record_case_ticket", "receipt_path", "clear_receipt"]
