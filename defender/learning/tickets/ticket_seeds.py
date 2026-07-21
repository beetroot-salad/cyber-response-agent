from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC

from defender.learning.core.config import REPO_ROOT, make_logger
from defender.scripts.case_history import case_ticket

_TICKET_CLI = REPO_ROOT / "defender" / "scripts" / "adapters" / "ticket_adapter.py"
_LIST_TIMEOUT_SEC = 15

WINDOW_RECENT = timedelta(hours=24)
WINDOW_MAX = timedelta(days=90)

SEED_COUNT_MIN = 3
SEED_COUNT_MAX = 5


@dataclass(frozen=True)
class Seed:

    case_id: str
    disposition: str
    reason: str


_log = make_logger("ticket_seeds")


def _seed_int(run_id: str) -> int:
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def _list_closed(label: str) -> list:
    cmd = [
        sys.executable, str(_TICKET_CLI), "list-tickets",
        "--status", "closed", "--label", label,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_LIST_TIMEOUT_SEC, cwd=str(REPO_ROOT), encoding="utf-8"
        )
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"list-tickets failed to run ({e!r}); empty pool")
        return []
    if proc.returncode != 0:
        _log(f"list-tickets exited {proc.returncode}; empty pool "
             f"(stderr: {proc.stderr.strip()[-200:]!r})")
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        _log("list-tickets returned non-JSON; empty pool")
        return []
    tickets = payload.get("tickets") if isinstance(payload, dict) else None
    return tickets if isinstance(tickets, list) else []


def _parse_iso(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _is_eligible(ticket, self_case_id: str, lo: datetime, hi: datetime) -> bool:
    key = case_ticket.ticket_key(ticket)
    if not key or key == self_case_id:
        return False
    if case_ticket.ticket_disposition(ticket) != "benign":
        return False
    if case_ticket.ticket_seed_eligible(ticket) is not True:
        return False
    event_time = _parse_iso(case_ticket.ticket_event_time(ticket))
    return event_time is not None and lo <= event_time <= hi


def _to_seed(ticket) -> Seed:
    reason = case_ticket.ticket_reason(ticket) or "(no reason recorded)"
    reason = " ".join(reason.split())
    return Seed(case_id=case_ticket.ticket_key(ticket) or "?",
                disposition="benign", reason=reason)


def sample_seeds(
    alert: dict, self_case_id: str, run_id: str, *, now: datetime | None = None,
    list_closed_fn=_list_closed, signature_label_fn=case_ticket.signature_label,
) -> list[Seed]:
    try:
        label = signature_label_fn(alert)
        if not label:
            return []
        if now is None:
            now = _parse_iso(case_ticket.alert_event_time(alert)) or datetime.now(UTC)
        lo, hi = now - WINDOW_MAX, now - WINDOW_RECENT
        eligible = [
            t for t in list_closed_fn(label) if _is_eligible(t, self_case_id, lo, hi)
        ]
        if not eligible:
            return []
        eligible.sort(key=lambda t: case_ticket.ticket_key(t) or "")
        rng = random.Random(_seed_int(run_id))
        count = rng.randint(SEED_COUNT_MIN, SEED_COUNT_MAX)
        chosen = eligible if len(eligible) <= count else rng.sample(eligible, count)
        return [_to_seed(t) for t in chosen]
    except Exception as e:  # noqa: BLE001 — variance injection must never break the learn
        _log(f"seed sampling failed ({e!r}); empty pool")
        return []


def format_seeds(seeds: list[Seed]) -> str:
    return "\n".join(f"- {s.case_id}: {s.disposition} — {s.reason}" for s in seeds)
