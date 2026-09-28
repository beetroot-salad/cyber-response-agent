#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import urllib.parse
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from defender._io import write_guarded
from defender._model import model
from defender._paths import process_defender_dir
from defender._run_paths import RunPaths
from defender.run_common import run_env
from defender.runtime import run_end
from defender.runtime.verbs import VerbContext
from defender.scripts.case_history import case_ticket
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import TransportFault

_logger = logging.getLogger(__name__)

SYSTEM = "case-history"
PREFIX = "CASE_HISTORY"
_CONFIG_KEYS = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")


def _verb_context(settings_dir: Path) -> VerbContext:
    """The transport's context: the process's code tree (`process_defender_dir`) and the run's
    tenant `settings/` folder, which `run.py` hands every leg."""
    defender_dir = process_defender_dir()
    run_dir = Path.cwd()
    return VerbContext(
        defender_dir=defender_dir, run_dir=run_dir, env=run_env(defender_dir, run_dir),
        settings_dir=Path(settings_dir),
    )


def _load_config(settings_dir: Path) -> dict[str, str] | None:
    """The case-history store's config from the run's tenant folder."""
    path = transport._config_path(_verb_context(settings_dir), SYSTEM)
    if not path.exists():
        _logger.warning(f"config not found: {path}; skipping ticket write")
        return None
    raw = transport._parse_env_file(path)
    cfg: dict[str, str] = {}
    for key in _CONFIG_KEYS:
        val = os.environ.get(f"{PREFIX}_{key}") or raw.get(f"{PREFIX}_{key}")
        if val:
            cfg[key] = val
    missing = [k for k in _CONFIG_KEYS if not cfg.get(k)]
    if missing:
        _logger.warning(f"missing config keys {[f'{PREFIX}_{k}' for k in missing]} in {path}; skipping")
        return None
    if not cfg["TIMEOUT_SEC"].isdigit():
        _logger.warning(f"{PREFIX}_TIMEOUT_SEC={cfg['TIMEOUT_SEC']!r} is not a non-negative "
              f"integer in {path}; skipping")
        return None
    return cfg


def _request(
    config: dict[str, str], method: str, path: str, body: dict | None = None,
    *, settings_dir: Path,
) -> tuple[str | None, str]:
    """One call to the store. `settings_dir` is the tenant folder `config` was read from."""
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    try:
        rc, stdout, stderr = transport.docker_exec_curl(
            _verb_context(settings_dir), bastion, url, method=method,
            body=body, timeout_sec=timeout,
        )
    except TransportFault as e:
        return None, f"transport error: {e.detail}"
    body_text, status = transport.split_status(stdout)
    if not status:
        return None, f"no/malformed response (rc={rc}, stderr={stderr.strip()!r})"
    return status, body_text


@model(frozen=True)
class TicketWriterDeps:
    #: Both are handed the run's tenant `settings/` folder (`request` as keyword
    #: `settings_dir`).
    load_config: Callable[[Path], dict[str, str] | None] = _load_config
    request: Callable[..., tuple[str | None, str]] = _request


DEFAULT_DEPS = TicketWriterDeps()


def open_case_ticket(
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, settings_dir: Path,
) -> None:
    """Open the case for this run. `settings_dir` is the run's tenant folder, holding both the
    store's address and the payload mapping."""
    try:
        config = deps.load_config(settings_dir)
        if config is None:
            return
        alert_path = RunPaths(run_dir).alert
        if not alert_path.is_file():
            _logger.warning(f"alert.json not found in {run_dir}; skipping open")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            return
        alert = json.loads(alert_path.read_text(encoding="utf-8"))
        case_id = run_dir.name
        payload = case_ticket.alert_to_open_payload(alert, case_id, settings_dir=settings_dir)
        status, body = deps.request(config, "POST", "/tickets", payload, settings_dir=settings_dir)
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
#: comments the host can make; `refused-released` means a person had already released the case;
#: `error` is a failed call. There is no `closed`: the host never transitions a case.
RECEIPT_COMMENTED = "commented"
RECEIPT_ESCALATED = "escalated"
RECEIPT_REFUSED_RELEASED = "refused-released"
RECEIPT_ERROR = "error"
_RECEIPT_OK = frozenset({RECEIPT_COMMENTED, RECEIPT_ESCALATED})


def _build_comment_payload(
    run_dir: Path, case_id: str, truncated_by: str | None, settings_dir: Path,
) -> tuple[dict, str]:
    """The outbound `{author, body}` for `record_case_ticket` and its receipt word.

    An unreadable report (`ReportNotParsable`) gets the fixed unreadable-branch sentence — or,
    on a forced-close exit, the escalation note, since the host's own forced close failed and
    there is no verdict. Any other `CaseTicketError` propagates to the caller's refusal branch
    (no POST, a warning, an `error` receipt)."""
    try:
        rec = replace(case_ticket.read_case_record(run_dir, settings_dir=settings_dir),
                      case_id=case_id)
    except case_ticket.ReportNotParsable:
        if truncated_by in run_end.FORCED_CLOSE_EXITS:
            return (case_ticket.escalation_comment_payload(truncated_by, settings_dir=settings_dir),
                    RECEIPT_ESCALATED)
        return case_ticket.unreadable_comment_payload(settings_dir=settings_dir), RECEIPT_COMMENTED
    return case_ticket.case_record_to_comment(rec, settings_dir=settings_dir), RECEIPT_COMMENTED


def _ticket_is_released(  # noqa: PLR0913 — one call site's context, threaded not re-derived
    config: dict[str, str], deps: TicketWriterDeps, case_id: str, quoted: str,
    settings_dir: Path,
) -> bool | None:
    """Whether a person has released the case — `None` when that cannot be established (read
    failed, not a ticket object, or the mapping cannot say what "released" is).

    A courtesy, not the gate: a close landing between this read and the write still gets the
    comment. What makes `closed` mean "a person did this" is that the host has no transition
    call at all (`test_767_writer.py` keeps it that way). Undecidable is treated as not
    recordable. Uses the same release predicate as the screen."""
    status, body = deps.request(config, "GET", f"/tickets/{quoted}", settings_dir=settings_dir)
    if status is None or not status.startswith("2"):
        _logger.warning(f"record {case_id}: could not read the case back ({status or 'transport error'}: "
              f"{body}); not recording")
        return None
    try:
        ticket = json.loads(body)
    except json.JSONDecodeError:
        _logger.warning(f"record {case_id}: the case read back is not JSON; not recording")
        return None
    if not isinstance(ticket, dict):
        _logger.warning(f"record {case_id}: the case read back is not a ticket object; not recording")
        return None
    try:
        return case_ticket.release_predicate(settings_dir).is_released(ticket)
    except case_ticket.CaseTicketError as e:
        _logger.warning(f"record {case_id}: {e}; cannot tell whether the case is released; not recording")
        return None


def record_case_ticket(  # noqa: PLR0913 — the lane's inputs are the run's exit record
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, settings_dir: Path,
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

    A failed open does not suppress this attempt; every write fault is caught and warned once,
    leaving the run's exit code unchanged. `key` is a parameter so a vendor-minted key is a
    call-site edit (today `run_dir.name`), and it names the case everywhere: both paths, the
    receipt and the rendered `{case_id}`. Keyword-only, so a stray string cannot bind as
    `deps`."""
    try:
        truncated_by = run_end.normalized_truncated_by(truncated_by)  # first, before any branch
        config = deps.load_config(settings_dir)
        if config is None:
            return
        case_id = key if key is not None else run_dir.name
        if (truncated_by in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE)
                and not closed_before_cut):
            _logger.info(f"{case_id}: run ended ({truncated_by}) with no verdict; leaving ticket open")
            return
        try:
            if truncated_by == run_end.TRUNCATED_BY_ABORTED and not closed_before_cut:
                payload, word = (
                    case_ticket.escalation_comment_payload(truncated_by, settings_dir=settings_dir),
                    RECEIPT_ESCALATED)
            else:
                payload, word = _build_comment_payload(
                    run_dir, case_id, truncated_by, settings_dir)
        except case_ticket.CaseTicketError as e:
            # The mapping refused: no POST, but still a warning and a receipt.
            _logger.warning(f"record {case_id}: {e}; not recording")
            _write_receipt(run_dir, config, case_id, RECEIPT_ERROR)
            return
        _post_comment(run_dir, deps, config, case_id, payload, word, settings_dir)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _logger.warning(f"record raised, ignored: {e!r}")


def _post_comment(  # noqa: PLR0913 — one call site's worth of context, threaded not re-derived
    run_dir: Path, deps: TicketWriterDeps, config: dict[str, str], case_id: str,
    payload: dict, word: str, settings_dir: Path,
) -> None:
    """The one write the host makes to a case: check `_ticket_is_released`, one
    `POST /tickets/{key}/comments`, and a receipt on every branch."""
    quoted = urllib.parse.quote(case_id, safe="")
    released = _ticket_is_released(config, deps, case_id, quoted, settings_dir)
    if released is None:
        _write_receipt(run_dir, config, case_id, RECEIPT_ERROR)
        return
    if released:
        _logger.warning(f"record {case_id}: a person has already released this case; a new comment "
              "would go out under that release unseen — not recording")
        _write_receipt(run_dir, config, case_id, RECEIPT_REFUSED_RELEASED)
        return
    status, body = deps.request(config, "POST", f"/tickets/{quoted}/comments", payload,
                                settings_dir=settings_dir)
    ok = status is not None and status.startswith("2")
    if not ok:
        _logger.warning(f"record {case_id}: {status or 'transport error'}: {body}")
    else:
        _logger.info(f"record {case_id}: comment posted ({status}, {word})")
    _write_receipt(run_dir, config, case_id, word if ok else RECEIPT_ERROR)


def _write_receipt(run_dir: Path, config: dict[str, str], case_id: str, status: str) -> None:
    receipt = {
        "key": case_id,
        "status": status,
        "url": f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}",
        "ok": status in _RECEIPT_OK,
    }
    try:
        # The run dir is box-writable: the guarded write refuses a planted link.
        write_guarded(RunPaths(run_dir).ticket_write, json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _logger.warning(f"could not write receipt: {e}")
