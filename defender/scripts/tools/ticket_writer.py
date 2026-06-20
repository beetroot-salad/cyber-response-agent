#!/usr/bin/env python3
"""Case-history ticket writer — the run.py/run_pai.py post-step (issue #317, write path).

Turns the (empty) ticket store into the accruing case-history store: a thin **bridge**
creates an OPEN ticket when the run materializes, and a post-run step **closes** it
with the disposition. This is the realistic lifecycle — the ticket pre-exists (raised
with the alert), the defender responds and closes — and it makes idempotency natural:
create-once (409 ⇒ already there), close-is-idempotent.

This is NOT the read-side gather adapter (`ticket_cli.py`, deliberately read-only and
inside the gather gate regime). It runs as a driver post-step *outside* that regime,
and it talks to a **separate** config (`CASE_HISTORY_*`) so the case-history store and
the customer ticketing SoR stay decoupled even when they're the same server today.

Discipline: a post-step must never break the run (matches `cross_check_tables` /
`visualize`). Every failure — missing config, unreachable stub, HTTP error, missing
report.md — is a WARN to stderr and a return, never a raise/exit. That's also why this
uses the low-level `docker_exec_curl` + `split_status` rather than `http_post`, which
`sys.exit`s on error (correct for a CLI adapter, fatal for an in-process post-step).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from defender.scripts.tools import _stub_transport as transport
from defender.scripts.tools import case_ticket

SYSTEM = "case-history"
PREFIX = "CASE_HISTORY"
_CONFIG_KEYS = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")


def _log(msg: str) -> None:
    print(f"[ticket_writer] {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"[ticket_writer] WARN {msg}", file=sys.stderr)


def _load_config() -> dict[str, str] | None:
    """Load `CASE_HISTORY_*` from the case-history system config, non-fatally.

    Mirrors `transport.load_config` but returns None (a WARN) instead of `sys.exit`,
    so a missing/incomplete config under `--update-ticket` degrades the post-step
    rather than aborting the run."""
    path = transport._config_path(SYSTEM)
    if not path.exists():
        _warn(f"config not found: {path}; skipping ticket write")
        return None
    raw = transport._parse_env_file(path)
    cfg: dict[str, str] = {}
    for key in _CONFIG_KEYS:
        # Env vars override the file for ops convenience (mirrors transport.load_config).
        val = os.environ.get(f"{PREFIX}_{key}") or raw.get(f"{PREFIX}_{key}")
        if val:
            cfg[key] = val
    missing = [k for k in _CONFIG_KEYS if not cfg.get(k)]
    if missing:
        _warn(f"missing config keys {[f'{PREFIX}_{k}' for k in missing]} in {path}; skipping")
        return None
    return cfg


def _post(config: dict[str, str], path: str, body: dict) -> tuple[str | None, str]:
    """POST to the stub via the docker-exec transport, non-fatally.

    Returns (http_status, body_text); http_status is None on a transport-level
    failure (docker missing / timeout / no response)."""
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    try:
        rc, stdout, stderr = transport.docker_exec_curl(
            bastion, url, method="POST", body=body, timeout_sec=timeout
        )
    except transport.TransportError as e:
        return None, f"transport error: {e}"
    body_text, status = transport.split_status(stdout)
    if not status:
        return None, f"no/malformed response (rc={rc}, stderr={stderr.strip()!r})"
    return status, body_text


def open_case_ticket(run_dir: Path) -> None:
    """Bridge: create an OPEN case-history ticket for this alert (call at materialize).

    409 means the ticket already exists (a replay against a populated store) — that's
    success, not an error. Never raises."""
    try:
        config = _load_config()
        if config is None:
            return
        alert_path = run_dir / "alert.json"
        if not alert_path.is_file():
            _warn(f"alert.json not found in {run_dir}; skipping open")
            return
        alert = json.loads(alert_path.read_text())
        case_id = run_dir.name
        payload = case_ticket.alert_to_open_payload(alert, case_id)
        status, body = _post(config, "/tickets", payload)
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


def close_case_ticket(run_dir: Path) -> None:
    """Close the case-history ticket with the disposition (call after the run).

    Writes a `ticket_write.json` receipt — the seam the read PR / offline enrichment
    keys on. A missing/invalid report.md leaves the ticket open (non-fatal). Never
    raises."""
    try:
        config = _load_config()
        if config is None:
            return
        try:
            rec = case_ticket.read_case_record(run_dir)
        except case_ticket.CaseTicketError as e:
            _warn(f"no usable report.md; leaving ticket open: {e}")
            return
        payload = case_ticket.case_record_to_close(rec)
        status, body = _post(config, f"/tickets/{rec.case_id}/transitions", payload)
        ok = status is not None and status.startswith("2")
        if not ok:
            _warn(f"close {rec.case_id}: {status or 'transport error'}: {body}")
        else:
            _log(f"close {rec.case_id}: {rec.disposition} ({status})")
        _write_receipt(run_dir, config, rec.case_id, ok)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _warn(f"close raised, ignored: {e!r}")


def _write_receipt(run_dir: Path, config: dict[str, str], case_id: str, ok: bool) -> None:
    receipt = {
        "key": case_id,
        "status": "closed" if ok else "error",
        "url": f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}",
        "ok": ok,
    }
    try:
        (run_dir / "ticket_write.json").write_text(json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _warn(f"could not write receipt: {e}")
