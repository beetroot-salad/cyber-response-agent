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


def _build_comment_payload(run_dir: Path, case_id: str) -> dict | None:
    """The outbound `{author, body}` for `record_case_ticket`, or `None` with a warning already
    printed. §7 R10: an unreadable report takes the FIXED unreadable-branch sentence, never a
    second, bespoke emptiness check — `case_ticket.ReportNotParsable` is `read_case_record`'s
    own signal for exactly that case. Any other `CaseTicketError` (a bad mapping, a template
    naming a key the context does not carry) refuses to POST at all (§7 R1/FAM-1)."""
    try:
        rec = case_ticket.read_case_record(run_dir)
    except case_ticket.ReportNotParsable:
        try:
            return case_ticket.unreadable_comment_payload()
        except case_ticket.CaseTicketError as e:
            _warn(f"record {case_id}: {e}; skipping")
            return None
    except case_ticket.CaseTicketError as e:
        _warn(f"record {case_id}: {e}; skipping")
        return None
    try:
        return case_ticket.case_record_to_comment(rec)
    except case_ticket.CaseTicketError as e:
        _warn(f"record {case_id}: {e}; skipping")
        return None


def record_case_ticket(
    run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS, key: str | None = None,
) -> None:
    """D2: the host RECORDS its investigation into the case rather than closing it — one
    `POST /tickets/{key}/comments`, no transition. §7 R6/FAM-3: a failed or colliding open does
    NOT suppress this attempt (the two post-steps are independent statements under one flag);
    every write fault is caught, warned once, and leaves the run's exit code exactly what it
    would have been (O7). `key` is a parameter now (§7 R8/FK04) so a vendor-minted, pre-existing
    key on a later deployment is a call-site edit — today's deployment keeps `case_id =
    run_dir.name`."""
    try:
        config = deps.load_config()
        if config is None:
            return
        case_id = key if key is not None else run_dir.name
        payload = _build_comment_payload(run_dir, case_id)
        if payload is None:
            return
        quoted = urllib.parse.quote(case_id, safe="")
        try:
            status, body = deps.request(config, "POST", f"/tickets/{quoted}/comments", payload)
        except TransportFault as e:
            status, body = None, f"transport error: {e.detail}"
        ok = status is not None and status.startswith("2")
        if not ok:
            _warn(f"record {case_id}: {status or 'transport error'}: {body}")
        else:
            _log(f"record {case_id}: comment posted ({status})")
        _write_receipt(run_dir, config, case_id, ok)
    except Exception as e:  # noqa: BLE001 — a post-step must never break the run
        _warn(f"record raised, ignored: {e!r}")


def _write_receipt(run_dir: Path, config: dict[str, str], case_id: str, ok: bool) -> None:
    receipt = {
        "key": case_id,
        # §7 R6/FK29: "commented", not "closed" — after D2 nothing closes, and the old literal
        # would record a false event. The receipt has zero readers (c5), which is why this word
        # is free to change and why no fault below is escalated beyond the warning.
        "status": "commented" if ok else "error",
        "url": f"{config['URL_BASE'].rstrip('/')}/tickets/{case_id}",
        "ok": ok,
    }
    try:
        (run_dir / "ticket_write.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        _warn(f"could not write receipt: {e}")
