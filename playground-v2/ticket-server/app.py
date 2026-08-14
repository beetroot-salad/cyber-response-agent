"""Playground ticket stub — minimal stateful ticketing API.

In-memory Jira-ish store used by the playground for end-to-end investigation
validation: the agent (or an ActionContract adapter) can create, read, and
close tickets against a real HTTP surface without a heavy Jira/ServiceNow
container. Not for production.

Seed tickets are loaded from TICKET_SEED_PATH on startup and on POST
/admin/reset. Storage is a process-local dict — restart wipes state unless a
seed file is mounted.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

SEED_PATH = Path(os.environ.get("TICKET_SEED_PATH", "/app/seed/tickets.json"))

Status = Literal["open", "in_progress", "closed"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Comment(BaseModel):
    author: str
    body: str
    created: str = Field(default_factory=_now)


class Ticket(BaseModel):
    key: str
    summary: str
    description: str = ""
    status: Status = "open"
    resolution: Optional[str] = None
    labels: list[str] = Field(default_factory=list)
    assignee: Optional[str] = None
    reporter: Optional[str] = None
    created: str = Field(default_factory=_now)
    updated: str = Field(default_factory=_now)
    comments: list[Comment] = Field(default_factory=list)


class TicketCreate(BaseModel):
    key: str
    summary: str
    description: str = ""
    labels: list[str] = Field(default_factory=list)
    assignee: Optional[str] = None
    reporter: Optional[str] = None
    status: Status = "open"


class CommentIn(BaseModel):
    author: str
    body: str


class Transition(BaseModel):
    status: Status
    resolution: Optional[str] = None
    author: Optional[str] = None
    comment: Optional[str] = None


STORE: dict[str, Ticket] = {}


def _load_seed() -> int:
    STORE.clear()
    if not SEED_PATH.exists():
        return 0
    raw = json.loads(SEED_PATH.read_text())
    for row in raw:
        t = Ticket(**row)
        STORE[t.key] = t
    return len(STORE)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_seed()
    yield


app = FastAPI(title="Playground ticket stub", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "ticket_count": len(STORE)}


@app.get("/tickets")
def list_tickets(
    status: Optional[Status] = None,
    label: Optional[str] = None,
    q: Optional[str] = None,
):
    out = list(STORE.values())
    if status:
        out = [t for t in out if t.status == status]
    if label:
        out = [t for t in out if label in t.labels]
    if q:
        ql = q.lower()
        out = [
            t for t in out
            if ql in t.summary.lower() or ql in t.description.lower()
        ]
    return {"total": len(out), "tickets": out}


@app.get("/tickets/{key}")
def get_ticket(key: str):
    t = STORE.get(key)
    if not t:
        raise HTTPException(status_code=404, detail=f"ticket {key} not found")
    return t


@app.post("/tickets", status_code=201)
def create_ticket(body: TicketCreate):
    if body.key in STORE:
        raise HTTPException(
            status_code=409, detail=f"ticket {body.key} already exists"
        )
    t = Ticket(**body.model_dump())
    STORE[t.key] = t
    return t


@app.post("/tickets/{key}/transitions")
def transition_ticket(key: str, body: Transition):
    t = STORE.get(key)
    if not t:
        raise HTTPException(status_code=404, detail=f"ticket {key} not found")
    t.status = body.status
    t.resolution = body.resolution if body.status == "closed" else None
    t.updated = _now()
    if body.comment:
        t.comments.append(
            Comment(author=body.author or "system", body=body.comment)
        )
    return t


@app.post("/tickets/{key}/comments", status_code=201)
def add_comment(key: str, body: CommentIn):
    t = STORE.get(key)
    if not t:
        raise HTTPException(status_code=404, detail=f"ticket {key} not found")
    c = Comment(author=body.author, body=body.body)
    t.comments.append(c)
    t.updated = _now()
    return c


@app.post("/admin/reset")
def reset():
    count = _load_seed()
    return {"status": "reset", "ticket_count": count}
