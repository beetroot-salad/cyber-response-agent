"""Change management stub — authorized-change context.

Seed is a list of ChangeRequest records in YAML, loaded at startup into an
in-memory mutable store (same lifecycle as ticket-server — restart wipes state
unless the seed file rewrites it). `/changes/active?host=<h>&at=<iso>` is the
primary shape the agent consumes: "was there an approved change covering this
host at this time?"

Not for production. Auth-less; loopback-exposed on the VPS.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

SEED_PATH = Path(os.environ.get("CHANGE_SEED_PATH", "/app/seed/changes.yaml"))
STANDING_PATH = Path(os.environ.get("CHANGE_STANDING_PATH", "/app/seed/standing.yaml"))
STANDING_REFRESH_SECONDS = int(os.environ.get("STANDING_REFRESH_SECONDS", "300"))
STANDING_LOOKBACK_DAYS = int(os.environ.get("STANDING_LOOKBACK_DAYS", "7"))
STANDING_LOOKAHEAD_DAYS = int(os.environ.get("STANDING_LOOKAHEAD_DAYS", "1"))

Status = Literal["planned", "approved", "in_progress", "implemented", "cancelled"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ChangeRequest(BaseModel):
    id: str
    summary: str
    description: str = ""
    status: Status = "planned"
    requester: Optional[str] = None
    approver: Optional[str] = None
    hosts: list[str] = Field(default_factory=list)
    window_start: str
    window_end: str
    created: str = Field(default_factory=_now)
    updated: str = Field(default_factory=_now)
    ticket_ref: Optional[str] = None


class ChangeCreate(BaseModel):
    id: str
    summary: str
    description: str = ""
    status: Status = "planned"
    requester: Optional[str] = None
    approver: Optional[str] = None
    hosts: list[str] = Field(default_factory=list)
    window_start: str
    window_end: str
    ticket_ref: Optional[str] = None


class Transition(BaseModel):
    status: Status


STORE: dict[str, ChangeRequest] = {}
STANDING: list[dict[str, Any]] = []


def _load_seed() -> int:
    STORE.clear()
    if not SEED_PATH.exists():
        return 0
    raw = yaml.safe_load(SEED_PATH.read_text()) or []
    for row in raw:
        cr = ChangeRequest(**row)
        STORE[cr.id] = cr
    return len(STORE)


def _load_standing() -> int:
    STANDING.clear()
    if not STANDING_PATH.exists():
        return 0
    raw = yaml.safe_load(STANDING_PATH.read_text()) or {}
    STANDING.extend(raw.get("standing_changes") or [])
    return len(STANDING)


def _occurrences(tmpl: dict[str, Any], now: datetime) -> list[datetime]:
    """Enumerate occurrence start-times for a standing template within the
    [now - lookback, now + lookahead] window. Supports daily and weekly kinds.

    Weekday convention: 1=Mon..7=Sun, matching ISO 8601 / Python's isoweekday().
    """
    rec = tmpl.get("recurrence") or {}
    kind = rec.get("kind")
    hour = int(rec.get("hour_utc", 0))
    minute = int(rec.get("minute_utc", 0))
    start_day = (now - timedelta(days=STANDING_LOOKBACK_DAYS)).date()
    end_day = (now + timedelta(days=STANDING_LOOKAHEAD_DAYS)).date()
    out: list[datetime] = []
    day = start_day
    while day <= end_day:
        include = False
        if kind == "daily":
            include = True
        elif kind == "weekly":
            include = day.isoweekday() == int(rec.get("weekday", 1))
        if include:
            out.append(datetime(day.year, day.month, day.day, hour, minute, tzinfo=timezone.utc))
        day += timedelta(days=1)
    return out


def _materialize_standing(now: Optional[datetime] = None) -> int:
    """Idempotently add a CR for each occurrence of each standing template
    inside the lookback/lookahead horizon. Existing ids (including from prior
    runs) are left untouched so they remain queryable by /changes/active?at=.
    """
    if not STANDING:
        return 0
    now = now or datetime.now(timezone.utc)
    added = 0
    for tmpl in STANDING:
        duration = timedelta(minutes=int(tmpl.get("duration_minutes", 60)))
        for occ_start in _occurrences(tmpl, now):
            cr_id = f"{tmpl['id_prefix']}{occ_start.strftime('%Y%m%dT%H%MZ')}"
            if cr_id in STORE:
                continue
            occ_end = occ_start + duration
            STORE[cr_id] = ChangeRequest(
                id=cr_id,
                summary=tmpl.get("summary", ""),
                description=tmpl.get("description", ""),
                status=tmpl.get("status", "approved"),
                requester=tmpl.get("requester"),
                approver=tmpl.get("approver"),
                hosts=list(tmpl.get("hosts") or []),
                window_start=occ_start.isoformat(),
                window_end=occ_end.isoformat(),
                ticket_ref=tmpl.get("ticket_ref"),
            )
            added += 1
    return added


def _parse(iso: str) -> datetime:
    # Accept trailing Z or explicit offset. datetime.fromisoformat handles both
    # on python 3.11+; normalize Z first for older tolerance.
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _covers(cr: ChangeRequest, at: datetime) -> bool:
    return _parse(cr.window_start) <= at <= _parse(cr.window_end)


async def _standing_refresh_loop() -> None:
    while True:
        try:
            _materialize_standing()
        except Exception as exc:  # pragma: no cover — defensive, log only
            print(f"[change-mgmt] standing refresh error: {exc}", flush=True)
        await asyncio.sleep(STANDING_REFRESH_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_seed()
    _load_standing()
    _materialize_standing()
    task = asyncio.create_task(_standing_refresh_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Playground change-mgmt stub", lifespan=lifespan)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "change_count": len(STORE),
        "standing_count": len(STANDING),
    }


@app.get("/changes")
def list_changes(
    status: Optional[Status] = None,
    host: Optional[str] = None,
    active_at: Optional[str] = None,
):
    out = list(STORE.values())
    if status:
        out = [c for c in out if c.status == status]
    if host:
        out = [c for c in out if host in c.hosts]
    if active_at:
        at = _parse(active_at)
        out = [c for c in out if _covers(c, at)]
    return {"total": len(out), "changes": out}


@app.get("/changes/active")
def active_changes(host: str, at: Optional[str] = None):
    when = _parse(at) if at else datetime.now(timezone.utc)
    out = [c for c in STORE.values() if host in c.hosts and _covers(c, when)]
    return out


@app.get("/changes/{id}")
def get_change(id: str):
    cr = STORE.get(id)
    if not cr:
        raise HTTPException(status_code=404, detail=f"change {id} not found")
    return cr


@app.post("/changes", status_code=201)
def create_change(body: ChangeCreate):
    if body.id in STORE:
        raise HTTPException(status_code=409, detail=f"change {body.id} already exists")
    cr = ChangeRequest(**body.model_dump())
    STORE[cr.id] = cr
    return cr


@app.post("/changes/{id}/transitions")
def transition(id: str, body: Transition):
    cr = STORE.get(id)
    if not cr:
        raise HTTPException(status_code=404, detail=f"change {id} not found")
    cr.status = body.status
    cr.updated = _now()
    return cr


@app.post("/admin/reset")
def reset():
    count = _load_seed()
    _load_standing()
    added = _materialize_standing()
    return {
        "status": "reset",
        "change_count": count + added,
        "standing_count": len(STANDING),
        "standing_materialized": added,
    }
