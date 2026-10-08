#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

from defender._io import read_text_utf8, write_guarded
from defender._model import model
from defender.run_repository import RunPaths
from defender.runtime import case_ticket, run_end
from defender.runtime.run_tenant import RunTenant
from defender.runtime.verbs import SETTINGS_POINTER, VerbContext, redact_settings_path
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
        alert = json.loads(read_text_utf8(alert_path))
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


#: The receipt words: `commented` (the record) and `escalated` (the cut-short note) are the two
#: comments the host can make; `error` is a failed call. There is no `closed`: the host never
#: transitions a case.
RECEIPT_COMMENTED = "commented"
RECEIPT_ESCALATED = "escalated"
RECEIPT_ERROR = "error"
_RECEIPT_OK = frozenset({RECEIPT_COMMENTED, RECEIPT_ESCALATED})


def _build_comment_payload(
    run_dir: Path, case_id: str, truncated_by: str | None, mapping: case_ticket.CaseMapping | case_ticket.CaseTicketError,
) -> tuple[dict, str]:
    """The outbound `{author, body}` for `record_case_ticket` and its receipt word.

    An unreadable report (`ReportNotParsable`) gets the fixed unreadable-branch sentence — or,
    on a forced-close exit, the escalation note, since the host's own forced close failed and
    there is no verdict. Any other `CaseTicketError` propagates to the caller's refusal branch
    (no POST, a warning, an `error` receipt)."""
    try:
        rec = replace(case_ticket.read_case_record(run_dir, mapping=mapping), case_id=case_id)
    except case_ticket.ReportNotParsable:
        if truncated_by in run_end.FORCED_CLOSE_EXITS:
            return (case_ticket.escalation_comment_payload(truncated_by, mapping=mapping),
                    RECEIPT_ESCALATED)
        return case_ticket.unreadable_comment_payload(mapping=mapping), RECEIPT_COMMENTED
    return case_ticket.case_record_to_comment(rec, mapping=mapping), RECEIPT_COMMENTED


def record_case_ticket(  # noqa: PLR0913 — the lane's inputs are the run's exit record (#1047)
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, tenant: RunTenant,
    defender_dir: Path, env: Mapping[str, str],
    key: str | None = None, truncated_by: str | None = None, closed_before_cut: bool = False,
) -> None:
    """Record the investigation into the case, never close it: at most one
    `POST /tickets/{key}/comments`, no transition. Closing is a person's act, which is what lets
    the store's `closed` mean "a person reviewed this".

    Which comment depends on the exit class, passed in-process from `run.py` (never read from
    the run dir):

        aborted                        -> the escalation note: no verdict, a person escalates
        request-limit, retry-exhausted -> the record, proposing the host's own forced
                                          `unresolved`; no usable report (the forced close
                                          itself failed) -> the escalation note
        budget, store                  -> no call at all, no receipt
        anything else (None, a real
        vocabulary member with no arm, an out-of-vocabulary string)
                                        -> the record, proposing the report's disposition

    `closed_before_cut` makes the no-verdict arms (`aborted`, `budget`/`store`) record off the
    model's own report instead, when it had already decided before the cut.

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
    removes any receipt an earlier attempt on this run dir left (a resumed run drives this step
    again), so a page never shows a ticket line this attempt did not write. Every other failure —
    no usable config, a refused mapping, a store that cannot be reached or answers an error, or an
    unexpected error anywhere in the step — writes an `error` receipt whose `reason` is the failing check's own text with the host's settings
    path redacted (`redact_settings_path`); `url` is null when there was no usable config to
    name a store, and the store's address otherwise."""
    case_id = key if key is not None else run_dir.name
    try:
        truncated_by = run_end.normalized_truncated_by(truncated_by)  # F-I — first act
        if (truncated_by in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE)
                and not closed_before_cut):
            clear_receipt(run_dir)
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
        # Only the exception's type reaches the receipt (and so the page): its text may carry a
        # host path or a store's body; the log line above has it whole.
        _write_receipt(run_dir, None, case_id, RECEIPT_ERROR,
                       f"the record step failed unexpectedly ({type(e).__name__}); see the run log")


def _post_comment(  # noqa: PLR0913 — one call site's worth of context, threaded not re-derived
    run_dir: Path, deps: TicketWriterDeps, config: dict[str, str], case_id: str,
    payload: dict, word: str, ctx: VerbContext,
) -> None:
    """The one write the host makes to a case: one `POST /tickets/{key}/comments` whose body
    opens with the agent tag naming this run (`case_ticket.posted_comment`, #1221 — here, so no
    comment kind can leave untagged), and a receipt either way. No read-back first: whether a
    person has closed the case changes nothing, since every comment is served to later runs
    and ours are tagged (#1221 A1)."""
    quoted = urllib.parse.quote(case_id, safe="")
    payload = case_ticket.posted_comment(payload, run_id=run_dir.name)
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


def receipt_path(run_dir: Path) -> Path:
    """The receipt: a sidecar beside the run dir, keyed by the run's name, like the scrub verdict.
    Never inside the run dir, where the box is root while it runs and could plant a receipt or
    block the host's write with a directory at its name."""
    run_dir = Path(run_dir)
    return RunPaths(run_dir).ticket_write(run_dir.parent)


def clear_receipt(run_dir: Path) -> None:
    """Remove the receipt an earlier attempt on this run dir left, if any: a record-step branch
    that writes no receipt must not leave one for the page to show."""
    try:
        receipt_path(run_dir).unlink(missing_ok=True)
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
        write_guarded(receipt_path(run_dir), json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _logger.warning(f"could not write receipt: {e}")
