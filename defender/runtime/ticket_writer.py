#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

from defender.records import _alert_input, _knowledge_status
from defender._model import model
from defender.records import Run, RunPaths
from defender.runtime import case_ticket, run_end
from defender.runtime.run_tenant import RunTenant
from defender.kit.settings import SETTINGS_POINTER
from defender.runtime.verbs import VerbContext, redact_settings_path
from defender.integrations import _stub_transport as transport
from defender.kit.faults import AdapterFault, TransportFault

_logger = logging.getLogger(__name__)

SYSTEM = "case-history"
PREFIX = "CASE_HISTORY"
_CONFIG_KEYS = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")
_CONFIG_FILE = f"{SETTINGS_POINTER}systems/{SYSTEM}/config.env"


def _verb_context(tenant: RunTenant, defender_dir: Path, run_dir: Path,
                  env: Mapping[str, str]) -> VerbContext:
    """The transport's context, built wholly from what `run.py` handed this leg: the run's record
    (its settings and the case-history entry resolved from them when the run began), the code
    tree, the run dir and the run's environment. Nothing here finds its own location or reads the
    process (#1107): the same record a lead-zero or query call reads is the one this writes by."""
    return VerbContext(defender_dir=defender_dir, run_dir=run_dir, env=env, tenant=tenant)


def _request(
    config: dict[str, str], method: str, path: str, body: dict | None = None,
    *, ctx: VerbContext,
) -> tuple[str | None, str]:
    """One call to the store, over the context the caller built from the run's record."""
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    try:
        rc, stdout, stderr = transport.docker_exec_curl(
            ctx, bastion, url, method=method, body=body, timeout_sec=timeout, system=SYSTEM,
        )
    except TransportFault as e:
        return None, f"transport error: {e.detail}"
    body_text, status = transport.split_status(stdout)
    if not status:
        return None, f"no/malformed response (rc={rc}, stderr={stderr.strip()!r})"
    return status, body_text


@model(frozen=True)
class TicketWriterDeps:
    #: The one seam: the call to the store. The store's address is read from the run's record, not
    #: through a seam of its own (#1107), so a test steers WHERE the writer goes by the tenant's
    #: `config.env`, and WHAT the store answers through this.
    request: Callable[..., tuple[str | None, str]] = _request


DEFAULT_DEPS = TicketWriterDeps()


def _config_of(ctx: VerbContext) -> dict[str, str]:
    """The case-history store's config from the run's record — `ConfigFault` (an `AdapterFault`)
    when it is absent, on another access method, or missing or blank on a required key."""
    return transport.load_config(ctx, SYSTEM, PREFIX, _CONFIG_KEYS)


def _reason_of(fault: BaseException, tenant: RunTenant) -> str:
    """A failure's receipt reason: the fault's own text, the host's settings folder named by the
    pointer instead of the path, and the file the fix lives in said up front — so the text names
    the file even for a fault (a bad timeout) whose own wording does not."""
    text = redact_settings_path(str(fault), tenant.settings)
    return f"{_CONFIG_FILE}: {text}"


def open_case_ticket(
    run: Run, deps: TicketWriterDeps = DEFAULT_DEPS, *, tenant: RunTenant,
    defender_dir: Path, env: Mapping[str, str],
) -> None:
    """Open the case for this run. `tenant` is the run's record (#1107): the store's address
    (`case-history/config.env`) and the payload's shape (`mapping.yaml`) are both that tenant's,
    resolved once when the run began. `defender_dir` and `env` are run.py's — the code tree and
    the run's environment — never found from the process. The open leg writes no receipt, on any
    path: a store that cannot be reached is a warning here and an error receipt at the record."""
    run_dir = run.run_dir
    try:
        ctx = _verb_context(tenant, defender_dir, run_dir, env)
        try:
            config = _config_of(ctx)
        except AdapterFault as e:
            _logger.warning(f"open: {_reason_of(e, tenant)}; skipping ticket write")
            return
        # The open leg meets the run's RECORD alone: the facts were settled once at run start,
        # and no byte of the alert is read here.
        record = _alert_input.parse_alert_record(run.facts.alert_record.read() or "")
        if record is None:
            _logger.warning(f"{run_dir.name} has no readable record of its alert; skipping open")
            return
        case_id = run_dir.name
        payload = case_ticket.alert_to_open_payload(
            record.facts, case_id, mapping=tenant.ticket_mapping)
        # A receipt from an earlier attempt must not outlive this open: only a refusal below
        # leaves one, for the record leg to carry on.
        clear_receipt(run)
        status, body = deps.request(config, "POST", "/tickets", payload, ctx=ctx)
        if status is None:
            _logger.warning(f"open {case_id}: {body}")
        elif status == "409":
            _logger.info(f"open {case_id}: already exists (409) — proceeding")
        elif status.startswith("2"):
            _logger.info(f"open {case_id}: created ({status})")
        else:
            _logger.warning(f"open {case_id}: HTTP {status}: {body}")
            # A store that REFUSED the ticket is said so where the operator looks (the receipt
            # and the run page), quoting the store's reason; the record leg keeps it.
            _write_receipt(
                run, config, case_id, RECEIPT_ERROR,
                redact_settings_path(f"{OPEN_REFUSED}: HTTP {status}: {body}", tenant.settings))
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _logger.warning(f"open raised, ignored: {e!r}")


#: The receipt words: `commented` (the record) and `escalated` (the cut-short note) are the two
#: comments the host can make; `error` is a failed call. There is no `closed`: the host never
#: transitions a case.
RECEIPT_COMMENTED = "commented"
RECEIPT_ESCALATED = "escalated"
RECEIPT_ERROR = "error"
#: What the open leg's refusal receipt opens with: the store would not take the case ticket.
OPEN_REFUSED = "the store refused the case ticket"
_RECEIPT_OK = frozenset({RECEIPT_COMMENTED, RECEIPT_ESCALATED})


def _build_comment_payload(
    run: Run, case_id: str, truncated_by: str | None, mapping: case_ticket.CaseMapping | case_ticket.CaseTicketError,
) -> tuple[dict, str]:
    """The outbound `{author, body}` for `record_case_ticket` and its receipt word.

    An unreadable report (`ReportNotParsable`) gets the fixed unreadable-branch sentence — or,
    on a forced-close exit, the escalation note, since the host's own forced close failed and
    there is no verdict. Any other `CaseTicketError` propagates to the caller's refusal branch
    (no POST, a warning, an `error` receipt)."""
    try:
        rec = replace(case_ticket.read_case_record(run, mapping=mapping), case_id=case_id)
    except case_ticket.ReportNotParsable:
        if truncated_by in run_end.FORCED_CLOSE_EXITS:
            return (case_ticket.escalation_comment_payload(truncated_by, mapping=mapping),
                    RECEIPT_ESCALATED)
        return case_ticket.unreadable_comment_payload(mapping=mapping), RECEIPT_COMMENTED
    return case_ticket.case_record_to_comment(rec, mapping=mapping), RECEIPT_COMMENTED


def record_case_ticket(  # noqa: PLR0913 — the lane's inputs are the run's exit record (#1047)
    run: Run, deps: TicketWriterDeps = DEFAULT_DEPS, *, tenant: RunTenant,
    defender_dir: Path, env: Mapping[str, str],
    key: str | None = None, truncated_by: str | None = None, closed_before_cut: bool = False,
) -> None:
    """Record the investigation into the case, never close it: at most one
    `POST /tickets/{key}/comments`, no transition. Closing is a person's act, which is what lets
    the store's `closed` mean "a person reviewed this"."""
    run_dir = run.run_dir
    case_id = key if key is not None else run_dir.name
    try:
        truncated_by = run_end.normalized_truncated_by(truncated_by)  # F-I — first act
        if (truncated_by in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE,
                             run_end.TRUNCATED_BY_PROVIDER_DOWN)
                and not closed_before_cut):
            clear_receipt(run)
            _logger.info(f"{case_id}: run ended ({truncated_by}) with no verdict; leaving ticket open")
            return
        ctx = _verb_context(tenant, defender_dir, run_dir, env)
        try:
            config = _config_of(ctx)
        except AdapterFault as e:
            reason = _reason_of(e, tenant)
            _logger.warning(f"record {case_id}: {reason}; not recording")
            _write_receipt(run, None, case_id, RECEIPT_ERROR, reason)
            return
        try:
            if truncated_by == run_end.TRUNCATED_BY_ABORTED and not closed_before_cut:
                payload, word = (
                    case_ticket.escalation_comment_payload(
                        truncated_by, mapping=tenant.ticket_mapping),
                    RECEIPT_ESCALATED)
            else:
                payload, word = _build_comment_payload(
                    run, case_id, truncated_by, tenant.ticket_mapping)
        except case_ticket.CaseTicketError as e:
            # The mapping (or a template in it) refused: no POST, but the receipt still says
            # so — a WARN, a receipt and a return on every arm that meant to call out.
            reason = redact_settings_path(str(e), tenant.settings)
            _logger.warning(f"record {case_id}: {reason}; not recording")
            _write_receipt(run, config, case_id, RECEIPT_ERROR, reason)
            return
        _post_comment(run, deps, config, case_id, payload, word, ctx)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _logger.warning(f"record raised, ignored: {e!r}")
        # Only the exception's type reaches the receipt (and so the page): its text may carry a
        # host path or a store's body; the log line above has it whole.
        _write_receipt(run, None, case_id, RECEIPT_ERROR,
                       f"the record step failed unexpectedly ({type(e).__name__}); see the run log")


#: The one sentence a stale run's every comment carries (#1108 P4, O-WARN): the kind in the
#: customer's words and the commit used, never the publish's raw reason (no URL, error text or
#: credential hint reaches a ticket). Fresh and pinned runs carry none.
STALE_SENTENCE = {
    _knowledge_status.TRANSIENT: (
        "Knowledge notice: this investigation used the tenant's knowledge as of an earlier "
        "version (commit {commit}) because newer approved knowledge could not be loaded due to "
        "a temporary problem."),
    _knowledge_status.OPERATOR: (
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
    status = _knowledge_status.read_knowledge_status(paths.knowledge_source(), paths.provenance)
    if status is None or not status.stale:
        return None
    if status.commit is None:
        return UNREADABLE_SENTENCE
    return STALE_SENTENCE[status.stale_kind or _knowledge_status.OPERATOR].format(
        commit=status.commit)


def _with_stale_sentence(run: Run, payload: dict) -> dict:
    """`payload` with the stale sentence opening its body when the run's knowledge was stale.
    First, so the wire bound — which cuts from the end — never takes it off a long verdict."""
    sentence = stale_sentence(run.run_dir)
    if sentence is None:
        return payload
    return {**payload, "body": f"{sentence}\n\n{payload['body']}"}


def _post_comment(  # noqa: PLR0913 — one call site's worth of context, threaded not re-derived
    run: Run, deps: TicketWriterDeps, config: dict[str, str], case_id: str,
    payload: dict, word: str, ctx: VerbContext,
) -> None:
    """The one write the host makes to a case: one `POST /tickets/{key}/comments` whose body
    opens with the agent tag naming this run (`case_ticket.posted_comment`, #1221 — here, so no
    comment kind can leave untagged), then the stale sentence when the run's knowledge was
    stale (O-WARN, every branch alike), and a receipt either way. No read-back first: whether a
    person has closed the case changes nothing, since every comment is served to later runs
    and ours are tagged (#1221 A1)."""
    quoted = urllib.parse.quote(case_id, safe="")
    payload = case_ticket.posted_comment(_with_stale_sentence(run, payload), run_id=str(run.id))
    status, body = deps.request(config, "POST", f"/tickets/{quoted}/comments", payload, ctx=ctx)
    ok = status is not None and status.startswith("2")
    if not ok:
        reason = f"{'HTTP ' + status if status else 'transport error'}: {body}"
        reason = redact_settings_path(reason, ctx.tenant.settings)
        refused = _prior_open_refusal(run)
        if refused is not None:
            # The comment fell with the ticket: the cause worth reading is the refusal.
            reason = f"{refused} (the record comment then failed: {reason})"
        _logger.warning(f"record {case_id}: {reason}")
    else:
        reason = None
        _logger.info(f"record {case_id}: comment posted ({status}, {word})")
        _record_posted_comment(run, case_id, payload)
    _write_receipt(run, config, case_id, word if ok else RECEIPT_ERROR, reason)


def _record_posted_comment(run: Run, case_id: str, payload: Mapping[str, object]) -> None:
    """@owns ticket_comments — append the comment the store just accepted, `{key, body}`, to the
    run's host-only record of its writes to the world (`RunPaths.ticket_comments`, beside the
    run folder). A world branched from this run serves the case as it stood at the fork, so its
    oracle is handed these writes (#1255 P5, O6; `case_ticket.read_posted_comments`).
    Best-effort like every post-step: a failed append is a warning and never changes the receipt."""
    try:
        run.observability.ticket_comments.append([{"key": case_id, "body": payload.get("body")}])
    except OSError as e:
        _logger.warning(f"record {case_id}: the posted comment could not be recorded: {e}")


def _prior_open_refusal(run: Run) -> str | None:
    """The open leg's refusal text this attempt left in the receipt, or `None`."""
    text = run.observability.ticket_write.read()
    try:
        prior = json.loads(text) if text is not None else None
    except ValueError:
        return None
    reason = prior.get("reason") if isinstance(prior, dict) else None
    return reason if isinstance(reason, str) and reason.startswith(OPEN_REFUSED) else None


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
    run: Run, config: dict[str, str] | None, case_id: str, status: str, reason: str | None,
) -> None:
    """@owns ticket_write receipt — `{key, status, url, ok, reason}`, the one shape the page
    reads. `url` is null when there was no usable config to name a store; `reason` is null on a
    success and the redacted failing text on every other status."""
    receipt = {
        "key": case_id,
        "status": status,
        "url": (f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}" if config else None),
        "ok": status in _RECEIPT_OK,
        "reason": reason,
    }
    try:
        run.observability.ticket_write.write(json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _logger.warning(f"could not write receipt: {e}")


# The path accessor remains the public read-side compatibility surface for run pages.
__all__ = [
    "TicketWriterDeps", "DEFAULT_DEPS", "open_case_ticket", "record_case_ticket",
    "receipt_path", "clear_receipt",
]
