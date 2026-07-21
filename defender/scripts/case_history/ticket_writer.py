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


def close_case_ticket(run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS) -> None:
    try:
        config = deps.load_config()
        if config is None:
            return
        try:
            rec = case_ticket.read_case_record(run_dir)
        except case_ticket.CaseTicketError as e:
            _warn(f"no usable report.md; leaving ticket open: {e}")
            return
        payload = case_ticket.case_record_to_close(rec)
        key = urllib.parse.quote(rec.case_id, safe="")
        status, body = deps.request(config, "POST", f"/tickets/{key}/transitions", payload)
        ok = status is not None and status.startswith("2")
        if not ok:
            _warn(f"close {rec.case_id}: {status or 'transport error'}: {body}")
        else:
            _log(f"close {rec.case_id}: {rec.disposition} ({status})")
        _write_receipt(run_dir, config, rec.case_id, ok)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _warn(f"close raised, ignored: {e!r}")


def annotate_case_ticket(
    case_id: str, outcome: str, deps: TicketWriterDeps = DEFAULT_DEPS
) -> None:
    try:
        config = deps.load_config()
        if config is None:
            return
        key = urllib.parse.quote(case_id, safe="")
        status, body = deps.request(config, "GET", f"/tickets/{key}")
        if status is None:
            _warn(f"annotate {case_id}: {body}")
            return
        if status == "404":
            _warn(f"annotate {case_id}: ticket not found (404); skipping")
            return
        if not status.startswith("2"):
            _warn(f"annotate {case_id}: GET HTTP {status}: {body}")
            return
        try:
            ticket = json.loads(body)
        except json.JSONDecodeError as e:
            _warn(f"annotate {case_id}: unparseable ticket: {e}")
            return
        if case_ticket.parse_survival_from_comments(ticket.get("comments")) is not None:
            _log(f"annotate {case_id}: already flagged — skipping")
            return
        payload = case_ticket.enrichment_to_comment(outcome)
        status, body = deps.request(config, "POST", f"/tickets/{key}/comments", payload)
        if status is None or not status.startswith("2"):
            _warn(f"annotate {case_id}: POST {status or 'transport error'}: {body}")
        else:
            _log(f"annotate {case_id}: seed-eligibility from {outcome} ({status})")
    except Exception as e:  # noqa: BLE001 — an offline post-step must never break the learn
        _warn(f"annotate raised, ignored: {e!r}")


def _fetch_enrich_ticket(
    case_id: str, key: str, config: dict[str, str], deps: TicketWriterDeps
) -> dict | None:
    status, body = deps.request(config, "GET", f"/tickets/{key}")
    if status is None:
        _warn(f"enrich-resolution {case_id}: {body}")
        return None
    if status == "404":
        _warn(f"enrich-resolution {case_id}: ticket not found (404); skipping")
        return None
    if not status.startswith("2"):
        _warn(f"enrich-resolution {case_id}: GET HTTP {status}: {body}")
        return None
    try:
        ticket = json.loads(body)
    except json.JSONDecodeError as e:
        _warn(f"enrich-resolution {case_id}: unparseable ticket: {e}")
        return None
    if case_ticket.ticket_resolution_method(ticket) is not None:
        _log(f"enrich-resolution {case_id}: already grounded — skipping")
        return None
    return ticket


def _enriched_resolution(case_id: str, ticket: dict, method: str) -> str | None:
    resolution = ticket.get("resolution")
    if not isinstance(resolution, str) or case_ticket.ticket_disposition(ticket) is None:
        _warn(f"enrich-resolution {case_id}: no decodable close resolution; skipping")
        return None
    new_resolution = case_ticket.append_resolution_method(resolution, method)
    if new_resolution == resolution:
        return None
    return new_resolution


def enrich_case_resolution(
    case_id: str, method: str, deps: TicketWriterDeps = DEFAULT_DEPS
) -> None:
    try:
        if not method or not method.strip():
            return
        config = deps.load_config()
        if config is None:
            return
        key = urllib.parse.quote(case_id, safe="")
        ticket = _fetch_enrich_ticket(case_id, key, config, deps)
        if ticket is None:
            return
        new_resolution = _enriched_resolution(case_id, ticket, method)
        if new_resolution is None:
            return
        payload = {"status": "closed", "resolution": new_resolution, "author": "learning"}
        status, body = deps.request(config, "POST", f"/tickets/{key}/transitions", payload)
        if status is None or not status.startswith("2"):
            _warn(f"enrich-resolution {case_id}: POST {status or 'transport error'}: {body}")
        else:
            _log(f"enrich-resolution {case_id}: grounded resolution-method ({status})")
    except Exception as e:  # noqa: BLE001 — an offline post-step must never break the learn
        _warn(f"enrich-resolution raised, ignored: {e!r}")


def _write_receipt(run_dir: Path, config: dict[str, str], case_id: str, ok: bool) -> None:
    receipt = {
        "key": case_id,
        "status": "closed" if ok else "error",
        "url": f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}",
        "ok": ok,
    }
    try:
        (run_dir / "ticket_write.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        _warn(f"could not write receipt: {e}")
