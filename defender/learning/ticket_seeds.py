"""Benign actor seed sampler — the FP-direction analog of the MITRE menu (issue #317).

Samples the case-history store for prior **closed, benign-disposed,
adversarially-survived** cases on the alert's signature and offers them to the benign
actor as *seeds* — past handled cases it may propose as a covering operation. Seeds are
variance, not authority: the benign judge re-confirms any cited case against the
actuals, so a seed the evidence contradicts simply fails to survive. Cold-start (an
empty store) is the deployment model — the sampler returns no seeds and the actor
grounds off the systems-of-record as before.

Offline only, and non-fatal by construction: it shells out to the read-only
`ticket_cli.py` adapter (hook-clear off the runtime gate — no `agent_id`) and degrades
to an empty pool on any failure. All knowledge of ticket fields stays behind
`case_ticket`'s decoders/accessors — this module only applies the sampling policy
(filter → window → uniform draw).
"""
from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defender.learning._loop_config import REPO_ROOT
from defender.scripts.case_history import case_ticket

_TICKET_CLI = REPO_ROOT / "defender" / "scripts" / "tools" / "ticket_cli.py"
_LIST_TIMEOUT_SEC = 15

# The recency window: closed cases older than 24h (decorrelate from the current burst)
# and within ~3 months (current effective policy). Keyed on `created` ≈ alert time.
WINDOW_RECENT = timedelta(hours=24)
WINDOW_MAX = timedelta(days=90)

# Menu size: a small per-run count, uniform-sampled from the FULL eligible pool (no
# top-K cutoff). A thin pool returns whole; an empty pool returns nothing.
SEED_COUNT_MIN = 3
SEED_COUNT_MAX = 5

_REASON_EXCERPT_MAX = 220


@dataclass(frozen=True)
class Seed:
    """One past closed case offered to the benign actor as a covering-operation seed."""

    case_id: str
    disposition: str
    reason: str


def _log(msg: str) -> None:
    print(f"[ticket_seeds] {msg}", file=sys.stderr)


def _seed_int(run_id: str) -> int:
    """Stable per-run seed (mirrors `_loop_subagents._actor_seed`) so the menu is
    reproducible per case alongside the adversarial menu/archetype draw."""
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def _list_closed(label: str) -> list:
    """Closed tickets carrying `label`, via the read-only adapter. Non-fatal: any
    non-zero exit / unreachable store / unparseable body → empty list."""
    cmd = [
        sys.executable, str(_TICKET_CLI), "list-tickets",
        "--status", "closed", "--label", label, "--raw",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_LIST_TIMEOUT_SEC, cwd=str(REPO_ROOT),
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
    """Parse an ISO-8601 timestamp to an aware UTC datetime; None if absent/malformed
    (the caller drops that ticket only — a bad timestamp never empties the pool)."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_eligible(ticket, self_case_id: str, lo: datetime, hi: datetime) -> bool:
    """A closed ticket seeds iff it is a benign, seed-eligible, in-window case that is
    not the current one. Every field read goes through a `case_ticket` accessor."""
    key = case_ticket.ticket_key(ticket)
    if not key or key == self_case_id:
        return False
    if case_ticket.ticket_disposition(ticket) != "benign":
        return False
    if case_ticket.ticket_seed_eligible(ticket) is not True:
        return False
    created = _parse_iso(case_ticket.ticket_created(ticket))
    return created is not None and lo <= created <= hi


def _to_seed(ticket) -> Seed:
    reason = case_ticket.ticket_reason(ticket) or "(no reason recorded)"
    if len(reason) > _REASON_EXCERPT_MAX:
        reason = reason[: _REASON_EXCERPT_MAX - 1].rstrip() + "…"
    return Seed(case_id=case_ticket.ticket_key(ticket) or "?",
                disposition="benign", reason=reason)


def sample_seeds(
    alert: dict, self_case_id: str, run_id: str, *, now: datetime | None = None
) -> list[Seed]:
    """Sample 3–5 prior benign-and-survived closed cases for the alert's signature.

    Uniform draw from the full eligible pool, seeded by `run_id` (reproducible). Empty
    list on cold-start / any failure. `now` is injectable for tests."""
    label = case_ticket.signature_label(alert)
    if not label:
        return []
    now = now or datetime.now(timezone.utc)
    lo, hi = now - WINDOW_MAX, now - WINDOW_RECENT
    eligible = [t for t in _list_closed(label) if _is_eligible(t, self_case_id, lo, hi)]
    if not eligible:
        return []
    rng = random.Random(_seed_int(run_id))
    count = rng.randint(SEED_COUNT_MIN, SEED_COUNT_MAX)
    chosen = eligible if len(eligible) <= count else rng.sample(eligible, count)
    return [_to_seed(t) for t in chosen]


def format_seeds(seeds: list[Seed]) -> str:
    """Render the seed menu for prompt injection (one line per case)."""
    return "\n".join(f"- {s.case_id}: {s.disposition} — {s.reason}" for s in seeds)
