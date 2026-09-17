#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender._run_paths import RunPaths
from defender.run_common import run_env
from defender.runtime import session_store
from defender.runtime.driver import FORCED_CLOSE_SET
from defender.runtime.session_store import normalized_truncated_by
from defender.runtime.verbs import VerbContext
from defender.scripts.case_history import case_ticket
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import TransportFault

SYSTEM = "case-history"
PREFIX = "CASE_HISTORY"
_CONFIG_KEYS = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")


def _verb_context() -> VerbContext:
    defender_dir = Path(os.environ.get("DEFENDER_DIR", Path(__file__).resolve().parents[2]))
    run_dir = Path.cwd()
    return VerbContext(
        defender_dir=defender_dir, run_dir=run_dir, env=run_env(defender_dir, run_dir)
    )


def _log(msg: str) -> None:
    print(f"[ticket_writer] {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"[ticket_writer] WARN {msg}", file=sys.stderr)


def _load_config() -> dict[str, str] | None:
    path = transport._config_path(_verb_context(), SYSTEM)
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
    return cfg


def _request(
    config: dict[str, str], method: str, path: str, body: dict | None = None
) -> tuple[str | None, str]:
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    try:
        rc, stdout, stderr = transport.docker_exec_curl(
            _verb_context(), bastion, url, method=method, body=body, timeout_sec=timeout
        )
    except TransportFault as e:
        return None, f"transport error: {e.detail}"
    body_text, status = transport.split_status(stdout)
    if not status:
        return None, f"no/malformed response (rc={rc}, stderr={stderr.strip()!r})"
    return status, body_text


@dataclass(frozen=True)
class TicketWriterDeps:
    load_config: Callable[[], dict[str, str] | None] = _load_config
    request: Callable[..., tuple[str | None, str]] = _request


DEFAULT_DEPS = TicketWriterDeps()


def open_case_ticket(run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS) -> None:
    try:
        config = deps.load_config()
        if config is None:
            return
        alert_path = RunPaths(run_dir).alert
        if not alert_path.is_file():
            _warn(f"alert.json not found in {run_dir}; skipping open")
            return
        alert = json.loads(alert_path.read_text(encoding="utf-8"))
        case_id = run_dir.name
        payload = case_ticket.alert_to_open_payload(alert, case_id)
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


def close_case_ticket(
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, *,
    truncated_by: str | None = None, closed_before_cut: bool = False,
) -> None:
    """#1047 O2 — the lane decides per exit class, taken as an IN-PROCESS PARAMETER from
    `run.py` (fork F3 reading A), never read off anything inside the run dir:

        aborted                        -> leave open, add the breaker's escalation note
        request-limit, retry-exhausted -> close `unresolved` off the host's forced report;
                                           no usable report (its own forced close failed,
                                           fork F-K) -> leave open with the escalation instead
        budget, store                  -> leave open, no call at all
        anything else (None, a real
        vocabulary member with no arm, an out-of-vocabulary string)
                                        -> today's report-driven close

    `closed_before_cut` (fork F-A reading B) makes the LEAVE-OPEN arms (`aborted`, `budget`,
    `store`) defer to a genuine model verdict instead: a run whose model had already decided
    when the cut landed closes off its own report exactly as an ordinary run would. It does
    NOT change the forced-close-set arm — a `request-limit`/`retry-exhausted` run always tries
    its own report first regardless, and falls to the escalation only when there genuinely is
    none (F-K's intersection with F-A: there is no verdict on disk to defer to, so the
    escalation wins over inventing one)."""
    try:
        truncated_by = normalized_truncated_by(truncated_by)  # F-I — first act, own parameter
        config = deps.load_config()
        if config is None:
            return
        case_id = run_dir.name  # F-D — positional, same namespace `open_case_ticket` writes
        if truncated_by == session_store.TRUNCATED_BY_ABORTED and not closed_before_cut:
            _leave_open_with_escalation(run_dir, deps, config, case_id, truncated_by)
            return
        if (truncated_by in (session_store.TRUNCATED_BY_BUDGET, session_store.TRUNCATED_BY_STORE)
                and not closed_before_cut):
            return
        if truncated_by in FORCED_CLOSE_SET:
            try:
                rec = case_ticket.read_case_record(run_dir)
            except case_ticket.CaseTicketError:
                _leave_open_with_escalation(run_dir, deps, config, case_id, truncated_by)
                return
            _close_off_report(run_dir, deps, config, rec)
            return
        # Every other case: `truncated_by is None`, a real vocabulary member with no arm here
        # (F7 — `dead-end`), an out-of-vocabulary string (already normalized to `None` above),
        # or a leave-open class whose model HAD closed (F-A) — today's report-driven close.
        try:
            rec = case_ticket.read_case_record(run_dir)
        except case_ticket.CaseTicketError as e:
            _warn(f"no usable report.md; leaving ticket open: {e}")
            return
        _close_off_report(run_dir, deps, config, rec)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _warn(f"close raised, ignored: {e!r}")


def _close_off_report(
    run_dir: Path, deps: TicketWriterDeps, config: dict[str, str], rec: case_ticket.CaseRecord,
) -> None:
    payload = case_ticket.case_record_to_close(rec)
    key = urllib.parse.quote(rec.case_id, safe="")
    status, body = deps.request(config, "POST", f"/tickets/{key}/transitions", payload)
    ok = status is not None and status.startswith("2")
    if not ok:
        _warn(f"close {rec.case_id}: {status or 'transport error'}: {body}")
    else:
        _log(f"close {rec.case_id}: {rec.disposition} ({status})")
    _write_receipt(run_dir, config, rec.case_id, ok)


def _leave_open_with_escalation(
    run_dir: Path, deps: TicketWriterDeps, config: dict[str, str], case_id: str,
    truncated_by: str,
) -> None:
    """Fork F4 reading A — a real second call to the operator's ticket system, addressed at the
    SAME ticket key the open leg wrote (`case_id = run_dir.name`), asking a person to escalate.
    Fork F-L: a failed note call never breaks the run and its outcome lands in the receipt."""
    text = (
        f"Investigation ended without a verdict (exit: {truncated_by}) — the environment "
        "appears unreachable or the investigation could not complete automatically. "
        "Escalate for manual review; this ticket is left open."
    )
    key = urllib.parse.quote(case_id, safe="")
    status, body = deps.request(
        config, "POST", f"/tickets/{key}/comments", {"author": "defender", "body": text})
    ok = status is not None and status.startswith("2")
    if not ok:
        _warn(f"note {case_id}: {status or 'transport error'}: {body}")
    else:
        _log(f"note {case_id}: escalation recorded ({status})")
    _write_receipt(run_dir, config, case_id, ok, status_when_ok="escalated")




def _write_receipt(
    run_dir: Path, config: dict[str, str], case_id: str, ok: bool, *,
    status_when_ok: str = "closed",
) -> None:
    receipt = {
        "key": case_id,
        "status": status_when_ok if ok else "error",
        "url": f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}",
        "ok": ok,
    }
    try:
        (run_dir / "ticket_write.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        _warn(f"could not write receipt: {e}")
