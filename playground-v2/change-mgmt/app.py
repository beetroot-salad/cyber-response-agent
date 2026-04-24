"""Change management stub — authorized-change context.

Seed is a list of ChangeRequest records in YAML, loaded at startup into an
in-memory mutable store (same lifecycle as ticket-server — restart wipes state
unless the seed file rewrites it). `/changes/active?host=<h>&at=<iso>` is the
primary shape the agent consumes: "was there an approved change covering this
host at this time?"

Not for production. Auth-less; loopback-exposed on the VPS.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

SEED_PATH = Path(os.environ.get("CHANGE_SEED_PATH", "/app/seed/changes.yaml"))

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


def _load_seed() -> int:
    STORE.clear()
    if not SEED_PATH.exists():
        return 0
    raw = yaml.safe_load(SEED_PATH.read_text()) or []
    for row in raw:
        cr = ChangeRequest(**row)
        STORE[cr.id] = cr
    return len(STORE)


def _parse(iso: str) -> datetime:
    # Accept trailing Z or explicit offset. datetime.fromisoformat handles both
    # on python 3.11+; normalize Z first for older tolerance.
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _covers(cr: ChangeRequest, at: datetime) -> bool:
    return _parse(cr.window_start) <= at <= _parse(cr.window_end)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_seed()
    yield


app = FastAPI(title="Playground change-mgmt stub", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "change_count": len(STORE)}


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
    return {"status": "reset", "change_count": count}
