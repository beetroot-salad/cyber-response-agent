#!/usr/bin/env python3
"""Case-history ticket writer — the run.py post-step (issue #317, write path).

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
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender.scripts.case_history import case_ticket
from defender.scripts.adapters import _stub_transport as transport  # shared transport (adapter family)

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
    # Validate TIMEOUT_SEC here, where we can say *which* key is wrong. Otherwise
    # a typo'd value (e.g. "10s") only surfaces as a ValueError from int() deep in
    # _request, which the post-step's broad except swallows into a generic WARN.
    if not cfg["TIMEOUT_SEC"].isdigit():
        _warn(f"{PREFIX}_TIMEOUT_SEC={cfg['TIMEOUT_SEC']!r} is not a non-negative "
              f"integer in {path}; skipping")
        return None
    return cfg


def _request(
    config: dict[str, str], method: str, path: str, body: dict | None = None
) -> tuple[str | None, str]:
    """Call the stub via the docker-exec transport, non-fatally.

    Returns (http_status, body_text); http_status is None on a transport-level
    failure (docker missing / timeout / no response)."""
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    try:
        rc, stdout, stderr = transport.docker_exec_curl(
            bastion, url, method=method, body=body, timeout_sec=timeout
        )
    except transport.TransportError as e:
        return None, f"transport error: {e}"
    body_text, status = transport.split_status(stdout)
    if not status:
        return None, f"no/malformed response (rc={rc}, stderr={stderr.strip()!r})"
    return status, body_text


@dataclass(frozen=True)
class TicketWriterDeps:
    """Injected config + transport seam for the case-history write entrypoints.

    Two callables, each defaulted to the production module function, so the
    entrypoints read `deps.load_config()` / `deps.request(...)` instead of
    hard-calling module globals. Tests pass a `TicketWriterDeps(load_config=...,
    request=...)` (or `dataclasses.replace`) instead of monkeypatching the module.
    Mirrors the `AuthorConfig`/`CuratorConfig` injection shape (#380); there's no
    path layout to thread, so field defaults are the production wiring — no factory.
    `request` covers both GET and POST (POST is just `request(config, "POST", ...)`)."""
    load_config: Callable[[], dict[str, str] | None] = _load_config
    request: Callable[..., tuple[str | None, str]] = _request


DEFAULT_DEPS = TicketWriterDeps()


def open_case_ticket(run_dir: Path, deps: TicketWriterDeps = DEFAULT_DEPS) -> None:
    """Bridge: create an OPEN case-history ticket for this alert (call at materialize).

    409 means the ticket already exists (a replay against a populated store) — that's
    success, not an error. Never raises."""
    try:
        config = deps.load_config()
        if config is None:
            return
        alert_path = run_dir / "alert.json"
        if not alert_path.is_file():
            _warn(f"alert.json not found in {run_dir}; skipping open")
            return
        alert = json.loads(alert_path.read_text())
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
    """Close the case-history ticket with the disposition (call after the run).

    Writes a `ticket_write.json` receipt — the seam the read PR / offline enrichment
    keys on. A missing/invalid report.md leaves the ticket open (non-fatal). Never
    raises."""
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
        # Percent-encode the key for the path: run_dir.name carries the alert
        # filename stem, which can hold spaces / other reserved chars that would
        # otherwise produce a URL that doesn't match the stored key.
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
    """Stamp the seed-eligibility flag onto a closed case-history ticket (issue
    #317, offline enrichment). `outcome` is the adversarial-probe verdict; the
    polarity (which outcomes seed) is decided by the mapper.

    Idempotent at this boundary (mirrors `open_case_ticket`'s 409 handling): GET
    the ticket, and if a seed-eligibility comment is already present, skip the POST
    — the store is the source of truth, so a re-drained learn never double-stamps.
    Non-fatal: every failure (config absent, unreachable, 404, HTTP error) is a WARN
    and a return. Never raises."""
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


def enrich_case_resolution(
    case_id: str, method: str, deps: TicketWriterDeps = DEFAULT_DEPS
) -> None:
    """Stamp the grounded resolution-method onto a closed case-history ticket (issue
    #338, offline enrichment). `method` is the resolution method the adversarial judge
    confirmed (grounded predicates + policy/authority); it rides INSIDE the existing
    `resolution` as a pure-literal-marked suffix — no new field — so the benign judge
    later reads a cited closed case's grounded conditions.

    Re-uses the close transition (`POST /tickets/{key}/transitions` with `status:
    closed`, which overwrites `resolution`) — the store exposes no resolution PATCH.
    Idempotent at this boundary (mirrors `annotate_case_ticket`): GET the ticket, and
    if a grounded segment is already present, skip the write — the store is the source
    of truth, so a re-drained learn never double-stamps. Non-fatal: every failure
    (config absent, unreachable, 404, HTTP error, unwritten/foreign resolution) is a
    WARN and a return. Never raises."""
    try:
        if not method or not method.strip():
            return
        config = deps.load_config()
        if config is None:
            return
        key = urllib.parse.quote(case_id, safe="")
        status, body = deps.request(config, "GET", f"/tickets/{key}")
        if status is None:
            _warn(f"enrich-resolution {case_id}: {body}")
            return
        if status == "404":
            _warn(f"enrich-resolution {case_id}: ticket not found (404); skipping")
            return
        if not status.startswith("2"):
            _warn(f"enrich-resolution {case_id}: GET HTTP {status}: {body}")
            return
        try:
            ticket = json.loads(body)
        except json.JSONDecodeError as e:
            _warn(f"enrich-resolution {case_id}: unparseable ticket: {e}")
            return
        if case_ticket.ticket_resolution_method(ticket) is not None:
            _log(f"enrich-resolution {case_id}: already grounded — skipping")
            return
        resolution = ticket.get("resolution")
        # Only stamp a close-resolution we wrote (disposition decodes) — a missing or
        # human-edited resolution is left untouched (append would corrupt it / be
        # un-decodable downstream).
        if not isinstance(resolution, str) or case_ticket.ticket_disposition(ticket) is None:
            _warn(f"enrich-resolution {case_id}: no decodable close resolution; skipping")
            return
        new_resolution = case_ticket.append_resolution_method(resolution, method)
        if new_resolution == resolution:  # nothing to add (no template / already marked)
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
        (run_dir / "ticket_write.json").write_text(json.dumps(receipt, indent=2) + "\n")
    except OSError as e:
        _warn(f"could not write receipt: {e}")
