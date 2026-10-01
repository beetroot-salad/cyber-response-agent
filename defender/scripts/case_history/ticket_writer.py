#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

from defender._io import write_guarded
from defender._model import model
from defender._run_paths import RunPaths
from defender.runtime import run_end
from defender.runtime.run_tenant import RunTenant
from defender.runtime.verbs import SETTINGS_POINTER, VerbContext, redact_settings_path
from defender.scripts.case_history import case_ticket
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import AdapterFault, TransportFault

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
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, tenant: RunTenant,
    defender_dir: Path, env: Mapping[str, str],
) -> None:
    """Open the case for this run. `tenant` is the run's record (#1107): the store's address
    (`case-history/config.env`) and the payload's shape (`mapping.yaml`) are both that tenant's,
    resolved once when the run began. `defender_dir` and `env` are run.py's — the code tree and
    the run's environment — never found from the process. The open leg writes no receipt, on any
    path: a store that cannot be reached is a warning here and an error receipt at the record."""
    try:
        ctx = _verb_context(tenant, defender_dir, run_dir, env)
        try:
            config = _config_of(ctx)
        except AdapterFault as e:
            _logger.warning(f"open: {_reason_of(e, tenant)}; skipping ticket write")
            return
        alert_path = RunPaths(run_dir).alert
        if not alert_path.is_file():
            _logger.warning(f"alert.json not found in {run_dir}; skipping open")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            return
        alert = json.loads(alert_path.read_text(encoding="utf-8"))
        case_id = run_dir.name
        payload = case_ticket.alert_to_open_payload(alert, case_id, mapping=tenant.ticket_mapping)
        status, body = deps.request(config, "POST", "/tickets", payload, ctx=ctx)
        if status is None:
            _logger.warning(f"open {case_id}: {body}")
        elif status == "409":
            _logger.info(f"open {case_id}: already exists (409) — proceeding")
        elif status.startswith("2"):
            _logger.info(f"open {case_id}: created ({status})")
        else:
            _logger.warning(f"open {case_id}: HTTP {status}: {body}")
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _logger.warning(f"open raised, ignored: {e!r}")


#: The receipt words. `commented` is the record (#767 D2) and `escalated` the cut-short note
#: (#1047 O2) — the two comments the host can make; `refused-released` is a record the writer
#: declined because a person had already released the case; `error` is a call that failed.
#: There is no `closed`: the host never transitions a case, so a receipt claiming it would
#: record a false event.
RECEIPT_COMMENTED = "commented"
RECEIPT_ESCALATED = "escalated"
RECEIPT_REFUSED_RELEASED = "refused-released"
RECEIPT_ERROR = "error"
_RECEIPT_OK = frozenset({RECEIPT_COMMENTED, RECEIPT_ESCALATED})


def _build_comment_payload(
    run_dir: Path, case_id: str, truncated_by: str | None, mapping: case_ticket.CaseMapping | case_ticket.CaseTicketError,
) -> tuple[dict, str]:
    """The outbound `{author, body}` for `record_case_ticket` and its receipt word. §7 R10: an
    unreadable report takes the FIXED unreadable-branch sentence, never a second, bespoke
    emptiness check — `case_ticket.ReportNotParsable` is `read_case_record`'s own signal for
    exactly that case. #1047 F-K: for a forced-close-set exit that same signal means the
    host's own forced close failed, so there is no verdict to propose and the escalation note
    goes instead. Any other `CaseTicketError` (a bad mapping, a broken template) propagates
    to the caller's refusal branch — no POST, a warning and an `error` receipt (§7 R1/FAM-1)."""
    try:
        rec = replace(case_ticket.read_case_record(run_dir, mapping=mapping), case_id=case_id)
    except case_ticket.ReportNotParsable:
        if truncated_by in run_end.FORCED_CLOSE_EXITS:
            return (case_ticket.escalation_comment_payload(truncated_by, mapping=mapping),
                    RECEIPT_ESCALATED)
        return case_ticket.unreadable_comment_payload(mapping=mapping), RECEIPT_COMMENTED
    return case_ticket.case_record_to_comment(rec, mapping=mapping), RECEIPT_COMMENTED


def _ticket_is_released(  # noqa: PLR0913 — one call site's context, threaded not re-derived
    config: dict[str, str], deps: TicketWriterDeps, case_id: str, quoted: str,
    ctx: VerbContext,
) -> tuple[bool | None, str]:
    """Read the case back and answer `(released, why_not)`: whether a person has released it —
    `None` when that cannot be established (the read failed, the reply is not a ticket object, or
    the mapping cannot say what "released" is spelled), with `why_not` the reason in the failing
    check's own words (empty when it could be established).

    A person's close is a statement about the comments ON THE TICKET WHEN THEY CLOSED IT, so
    the writer looks before it appends and declines when the case is already released.
    This is a COURTESY, not the gate: it is one read followed by one write, and a close that
    lands between the two still gets the comment. What makes `closed` mean "a person did this"
    is that the host cannot transition a case at all — this module has no transition call, and
    `test_767_writer.py` keeps it that way — not this check. Undecidable reads as released,
    the direction that writes nothing. The released status's spelling is the mapping's, read
    through the same predicate the screen decides with (O5)."""
    status, body = deps.request(config, "GET", f"/tickets/{quoted}", ctx=ctx)
    if status is None or not status.startswith("2"):
        why = f"could not read the case back ({status or 'transport error'}: {body})"
        _logger.warning(f"record {case_id}: {why}; not recording")
        return None, why
    try:
        ticket = json.loads(body)
    except json.JSONDecodeError:
        why = "the case read back is not JSON"
        _logger.warning(f"record {case_id}: {why}; not recording")
        return None, why
    if not isinstance(ticket, dict):
        why = "the case read back is not a ticket object"
        _logger.warning(f"record {case_id}: {why}; not recording")
        return None, why
    try:
        return case_ticket.release_predicate(ctx.tenant.ticket_mapping).is_released(ticket), ""
    except case_ticket.CaseTicketError as e:
        why = f"{e}; cannot tell whether the case is released"
        _logger.warning(f"record {case_id}: {why}; not recording")
        return None, why


def record_case_ticket(  # noqa: PLR0913 — the lane's inputs are the run's exit record (#1047)
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, tenant: RunTenant,
    defender_dir: Path, env: Mapping[str, str],
    key: str | None = None, truncated_by: str | None = None, closed_before_cut: bool = False,
) -> None:
    """D2: the host RECORDS its investigation into the case rather than closing it — at most
    one `POST /tickets/{key}/comments`, never a transition. Closing is a person's act; the
    host's client has no transition call, which is what lets the store's own `closed` mean
    "a person reviewed this" to every later reader (#767 O1/O2).

    #1047 O2 — WHICH comment is decided per exit class, taken as an IN-PROCESS PARAMETER from
    `run.py` (fork F3 reading A), never read off anything inside the run dir:

        aborted                        -> the escalation note: no verdict, a person escalates
        request-limit, retry-exhausted -> the record, proposing the host's own forced
                                          `unresolved`; no usable report (the forced close
                                          itself failed, fork F-K) -> the escalation note
        budget, store                  -> no call at all, no receipt
        anything else (None, a real
        vocabulary member with no arm, an out-of-vocabulary string)
                                        -> the record, proposing the report's disposition

    `closed_before_cut` (fork F-A reading B) makes the two no-verdict arms (`aborted`,
    `budget`/`store`) defer to a genuine model verdict instead: a run whose model had already
    decided when the cut landed records off its own report exactly as an ordinary run would.

    §7 R6/FAM-3: a failed or colliding open does NOT suppress this attempt (the two post-steps
    are independent statements under one flag); every write fault is caught, warned once, and
    leaves the run's exit code exactly what it would have been (O7). `key` is a parameter (§7
    R8/FK04) so a vendor-minted, pre-existing key on a later deployment is a call-site edit —
    today's deployment keeps `case_id = run_dir.name`. Keyword-only, so a bare string in the
    second position cannot bind as `deps` and vanish into the catch-all. The key is the
    case's identity EVERYWHERE this write names it: the two paths, the receipt and the
    rendered `{case_id}`.

    #1107 O6 — `tenant` is the run's record, `defender_dir` and `env` are run.py's. The #1047
    no-verdict check runs BEFORE the config is read, so a budget- or store-cut run writes no
    receipt whatever its tenant's config says, and every branch that writes no receipt first
    unlinks any receipt already in the run dir (a link at that name is removed, never followed),
    so a page never shows a ticket line this run did not write. Every other failure — no usable
    config, a refused mapping, a store that cannot be reached or answers an error — writes an
    `error` receipt whose `reason` is the failing check's own text with the host's settings
    path redacted (`redact_settings_path`); `url` is null when there was no usable config to
    name a store, and the store's address otherwise."""
    case_id = key if key is not None else run_dir.name
    try:
        truncated_by = run_end.normalized_truncated_by(truncated_by)  # F-I — first act
        if (truncated_by in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE)
                and not closed_before_cut):
            _clear_receipt(run_dir)
            _logger.info(f"{case_id}: run ended ({truncated_by}) with no verdict; leaving ticket open")
            return
        ctx = _verb_context(tenant, defender_dir, run_dir, env)
        try:
            config = _config_of(ctx)
        except AdapterFault as e:
            reason = _reason_of(e, tenant)
            _logger.warning(f"record {case_id}: {reason}; not recording")
            _write_receipt(run_dir, None, case_id, RECEIPT_ERROR, reason)
            return
        try:
            if truncated_by == run_end.TRUNCATED_BY_ABORTED and not closed_before_cut:
                payload, word = (
                    case_ticket.escalation_comment_payload(
                        truncated_by, mapping=tenant.ticket_mapping),
                    RECEIPT_ESCALATED)
            else:
                payload, word = _build_comment_payload(
                    run_dir, case_id, truncated_by, tenant.ticket_mapping)
        except case_ticket.CaseTicketError as e:
            # The mapping (or a template in it) refused: no POST, but the receipt still says
            # so — a WARN, a receipt and a return on every arm that meant to call out.
            reason = redact_settings_path(str(e), tenant.settings)
            _logger.warning(f"record {case_id}: {reason}; not recording")
            _write_receipt(run_dir, config, case_id, RECEIPT_ERROR, reason)
            return
        _post_comment(run_dir, deps, config, case_id, payload, word, ctx)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _logger.warning(f"record raised, ignored: {e!r}")


def _post_comment(  # noqa: PLR0913 — one call site's worth of context, threaded not re-derived
    run_dir: Path, deps: TicketWriterDeps, config: dict[str, str], case_id: str,
    payload: dict, word: str, ctx: VerbContext,
) -> None:
    """The one write the host makes to a case: look (`_ticket_is_released`), then one
    `POST /tickets/{key}/comments`, then the receipt on every branch (fork F-L: a failed call
    never breaks the run and its outcome lands in the receipt)."""
    quoted = urllib.parse.quote(case_id, safe="")
    released, why_not = _ticket_is_released(config, deps, case_id, quoted, ctx)
    if released is None:
        _write_receipt(run_dir, config, case_id, RECEIPT_ERROR,
                       redact_settings_path(why_not, ctx.tenant.settings))
        return
    if released:
        _logger.warning(f"record {case_id}: a person has already released this case; a new comment "
              "would go out under that release unseen — not recording")
        _write_receipt(run_dir, config, case_id, RECEIPT_REFUSED_RELEASED,
                       "a person has already released this case; no comment was added")
        return
    status, body = deps.request(config, "POST", f"/tickets/{quoted}/comments", payload, ctx=ctx)
    ok = status is not None and status.startswith("2")
    if not ok:
        reason = f"{'HTTP ' + status if status else 'transport error'}: {body}"
        reason = redact_settings_path(reason, ctx.tenant.settings)
        _logger.warning(f"record {case_id}: {reason}")
    else:
        reason = None
        _logger.info(f"record {case_id}: comment posted ({status}, {word})")
    _write_receipt(run_dir, config, case_id, word if ok else RECEIPT_ERROR, reason)


def _clear_receipt(run_dir: Path) -> None:
    """Remove the run dir's receipt, if one is there, WITHOUT following a link at its name: a
    record-step branch that writes no receipt must not leave an earlier run's (or a planted)
    one for the page to show. `unlink` removes the link itself, never its target."""
    try:
        RunPaths(run_dir).ticket_write.unlink(missing_ok=True)
    except OSError as e:
        _logger.warning(f"could not clear the stale receipt: {e}")


def _write_receipt(
    run_dir: Path, config: dict[str, str] | None, case_id: str, status: str, reason: str | None,
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
        # The run dir is the box's rw bind: the receipt goes through the alias-refusing seam
        # like every other host write into it, so a link planted at its name is refused, not
        # followed.
        write_guarded(RunPaths(run_dir).ticket_write, json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _logger.warning(f"could not write receipt: {e}")
