#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.parse
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from defender._io import write_guarded
from defender._model import model
from defender._run_paths import RunPaths
from defender.run_common import run_env
from defender.runtime import run_end
from defender.runtime.verbs import VerbContext
from defender.scripts.case_history import case_ticket
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import TransportFault

SYSTEM = "case-history"
PREFIX = "CASE_HISTORY"
_CONFIG_KEYS = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")


#: The code tree this module ships in — the child env's PATH/PYTHONPATH root, and nothing
#: else. The SETTINGS are never found from here (or from `$DEFENDER_DIR`): every leg is handed
#: the run's tenant's `settings/` folder by `run.py` (#1106).
_DEFENDER_DIR = Path(__file__).resolve().parents[2]

#: The key under which `_load_config` records the settings folder its values were read from,
#: so the transport's verb context names the same tenant's folder as the config it carries.
SETTINGS_DIR_KEY = "SETTINGS_DIR"


def _verb_context(settings_dir: Path) -> VerbContext:
    run_dir = Path.cwd()
    return VerbContext(
        defender_dir=_DEFENDER_DIR, run_dir=run_dir, env=run_env(_DEFENDER_DIR, run_dir),
        settings_dir=Path(settings_dir),
    )


def _log(msg: str) -> None:
    print(f"[ticket_writer] {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"[ticket_writer] WARN {msg}", file=sys.stderr)


def _load_config(settings_dir: Path) -> dict[str, str] | None:
    """The case-history store's config from the run's tenant folder. @owns SETTINGS_DIR —
    the one place the config dict records which folder it came from; `_request` reads it."""
    path = transport._config_path(_verb_context(settings_dir), SYSTEM)
    if not path.exists():
        _warn(f"config not found: {path}; skipping ticket write")
        return None
    raw = transport._parse_env_file(path)
    cfg: dict[str, str] = {}
    for key in _CONFIG_KEYS:
        val = os.environ.get(f"{PREFIX}_{key}") or raw.get(f"{PREFIX}_{key}")
        if val:
            cfg[key] = val
    missing = [k for k in _CONFIG_KEYS if not cfg.get(k)]
    if missing:
        _warn(f"missing config keys {[f'{PREFIX}_{k}' for k in missing]} in {path}; skipping")
        return None
    if not cfg["TIMEOUT_SEC"].isdigit():
        _warn(f"{PREFIX}_TIMEOUT_SEC={cfg['TIMEOUT_SEC']!r} is not a non-negative "
              f"integer in {path}; skipping")
        return None
    cfg[SETTINGS_DIR_KEY] = str(settings_dir)
    return cfg


def _request(
    config: dict[str, str], method: str, path: str, body: dict | None = None
) -> tuple[str | None, str]:
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    try:
        rc, stdout, stderr = transport.docker_exec_curl(
            _verb_context(Path(config[SETTINGS_DIR_KEY])), bastion, url, method=method,
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
    #: Handed the run's tenant `settings/` folder (#1106) — the one place the case-history
    #: store's address is read from.
    load_config: Callable[[Path], dict[str, str] | None] = _load_config
    request: Callable[..., tuple[str | None, str]] = _request


DEFAULT_DEPS = TicketWriterDeps()


def open_case_ticket(
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, settings_dir: Path,
) -> None:
    """Open the case for this run. `settings_dir` is the run's tenant's folder (#1106): the
    store's address (`case-history/config.env`) and the payload's shape (`mapping.yaml`) are
    both that tenant's."""
    try:
        config = deps.load_config(settings_dir)
        if config is None:
            return
        alert_path = RunPaths(run_dir).alert
        if not alert_path.is_file():
            _warn(f"alert.json not found in {run_dir}; skipping open")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            return
        alert = json.loads(alert_path.read_text(encoding="utf-8"))
        case_id = run_dir.name
        payload = case_ticket.alert_to_open_payload(alert, case_id, settings_dir=settings_dir)
        status, body = deps.request(config, "POST", "/tickets", payload)
        if status is None:
            _warn(f"open {case_id}: {body}")
        elif status == "409":
            _log(f"open {case_id}: already exists (409) — proceeding")
        elif status.startswith("2"):
            _log(f"open {case_id}: created ({status})")
        else:
            _warn(f"open {case_id}: HTTP {status}: {body}")
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _warn(f"open raised, ignored: {e!r}")


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
    run_dir: Path, case_id: str, truncated_by: str | None, settings_dir: Path,
) -> tuple[dict, str]:
    """The outbound `{author, body}` for `record_case_ticket` and its receipt word. §7 R10: an
    unreadable report takes the FIXED unreadable-branch sentence, never a second, bespoke
    emptiness check — `case_ticket.ReportNotParsable` is `read_case_record`'s own signal for
    exactly that case. #1047 F-K: for a forced-close-set exit that same signal means the
    host's own forced close failed, so there is no verdict to propose and the escalation note
    goes instead. Any other `CaseTicketError` (a bad mapping, a broken template) propagates
    to the caller's refusal branch — no POST, a warning and an `error` receipt (§7 R1/FAM-1)."""
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
    """Read the case back and answer whether a person has released it — `None` when that
    cannot be established (the read failed, the reply is not a ticket object, or the mapping
    cannot say what "released" is spelled).

    A person's close is a statement about the comments ON THE TICKET WHEN THEY CLOSED IT, so
    the writer looks before it appends and declines when the case is already released.
    This is a COURTESY, not the gate: it is one read followed by one write, and a close that
    lands between the two still gets the comment. What makes `closed` mean "a person did this"
    is that the host cannot transition a case at all — this module has no transition call, and
    `test_767_writer.py` keeps it that way — not this check. Undecidable reads as released,
    the direction that writes nothing. The released status's spelling is the mapping's, read
    through the same predicate the screen decides with (O5)."""
    status, body = deps.request(config, "GET", f"/tickets/{quoted}")
    if status is None or not status.startswith("2"):
        _warn(f"record {case_id}: could not read the case back ({status or 'transport error'}: "
              f"{body}); not recording")
        return None
    try:
        ticket = json.loads(body)
    except json.JSONDecodeError:
        _warn(f"record {case_id}: the case read back is not JSON; not recording")
        return None
    if not isinstance(ticket, dict):
        _warn(f"record {case_id}: the case read back is not a ticket object; not recording")
        return None
    try:
        return case_ticket.release_predicate(settings_dir).is_released(ticket)
    except case_ticket.CaseTicketError as e:
        _warn(f"record {case_id}: {e}; cannot tell whether the case is released; not recording")
        return None


def record_case_ticket(  # noqa: PLR0913 — the lane's inputs are the run's exit record (#1047)
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *, settings_dir: Path,
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
    rendered `{case_id}`."""
    try:
        truncated_by = run_end.normalized_truncated_by(truncated_by)  # F-I — first act
        config = deps.load_config(settings_dir)
        if config is None:
            return
        case_id = key if key is not None else run_dir.name
        if (truncated_by in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE)
                and not closed_before_cut):
            _log(f"{case_id}: run ended ({truncated_by}) with no verdict; leaving ticket open")
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
            # The mapping (or a template in it) refused: no POST, but the receipt still says
            # so — a WARN, a receipt and a return on every arm that meant to call out.
            _warn(f"record {case_id}: {e}; not recording")
            _write_receipt(run_dir, config, case_id, RECEIPT_ERROR)
            return
        _post_comment(run_dir, deps, config, case_id, payload, word, settings_dir)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _warn(f"record raised, ignored: {e!r}")


def _post_comment(  # noqa: PLR0913 — one call site's worth of context, threaded not re-derived
    run_dir: Path, deps: TicketWriterDeps, config: dict[str, str], case_id: str,
    payload: dict, word: str, settings_dir: Path,
) -> None:
    """The one write the host makes to a case: look (`_ticket_is_released`), then one
    `POST /tickets/{key}/comments`, then the receipt on every branch (fork F-L: a failed call
    never breaks the run and its outcome lands in the receipt)."""
    quoted = urllib.parse.quote(case_id, safe="")
    released = _ticket_is_released(config, deps, case_id, quoted, settings_dir)
    if released is None:
        _write_receipt(run_dir, config, case_id, RECEIPT_ERROR)
        return
    if released:
        _warn(f"record {case_id}: a person has already released this case; a new comment "
              "would go out under that release unseen — not recording")
        _write_receipt(run_dir, config, case_id, RECEIPT_REFUSED_RELEASED)
        return
    status, body = deps.request(config, "POST", f"/tickets/{quoted}/comments", payload)
    ok = status is not None and status.startswith("2")
    if not ok:
        _warn(f"record {case_id}: {status or 'transport error'}: {body}")
    else:
        _log(f"record {case_id}: comment posted ({status}, {word})")
    _write_receipt(run_dir, config, case_id, word if ok else RECEIPT_ERROR)


def _write_receipt(run_dir: Path, config: dict[str, str], case_id: str, status: str) -> None:
    receipt = {
        "key": case_id,
        "status": status,
        "url": f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}",
        "ok": status in _RECEIPT_OK,
    }
    try:
        # The run dir is the box's rw bind: the receipt goes through the alias-refusing seam
        # like every other host write into it, so a link planted at its name is refused, not
        # followed.
        write_guarded(RunPaths(run_dir).ticket_write, json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _warn(f"could not write receipt: {e}")
