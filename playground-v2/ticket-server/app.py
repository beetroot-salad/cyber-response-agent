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

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel, Field

SEED_PATH = Path(os.environ.get("TICKET_SEED_PATH", "/app/seed/tickets.json"))
# A frozen copy pins the stub's clock (#1347 O3): every stamp is this instant.
STUB_AS_OF = os.environ.get("V2_STUB_AS_OF") or None

Status = Literal["open", "in_progress", "closed"]


def _now() -> str:
    if STUB_AS_OF:
        return datetime.fromisoformat(STUB_AS_OF.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
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


# --- Kibana alert hook (#1400) ---------------------------------------------
# Stands in for the customer's alert automation: the alert-ticket-watcher
# service posts each new security alert here and each one gets an OPEN ticket
# keyed by the alert's own id, so the ticket exists before any run comments on
# it. Alerts arrive as stored in the alerts index (flat dotted keys); nested
# objects are read too.
#
# Create-only: it never transitions or comments, so it gives nothing that can
# reach this stub a way to move a ticket along its lifecycle.

ALERT_HOOK_PATH = "/hooks/kibana-alerts"


def _alert_field(alert: dict, dotted: str):
    """Read a field from an alert in either shape Kibana hands to actions:
    flat dotted keys (as stored in the alert index) or nested objects."""
    if dotted in alert:
        return alert[dotted]
    node = alert
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _scalar(value) -> Optional[str]:
    if isinstance(value, list):  # a field Kibana expanded to a one-item list
        value = value[0] if len(value) == 1 else None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (str, int)):
        text = str(value)
        return text or None
    return None


def ticket_for_alert(alert: dict) -> Optional[TicketCreate]:
    """The ticket an alert opens, or None when the alert carries no id to key it by.

    The key is `kibana.alert.uuid`, the field the defender's alert.json records as
    `alert_id` (and the playground tenant maps to `case_key`). Summary and labels
    match what the defender's own open leg wrote before #1359: the rule description,
    `sig:<rule_id>` and `evt:<alert time>`.
    """
    key = _scalar(_alert_field(alert, "kibana.alert.uuid")) or _scalar(alert.get("_id"))
    if key is None:
        return None
    rule_id = _scalar(_alert_field(alert, "kibana.alert.rule.rule_id"))
    summary = (
        _scalar(_alert_field(alert, "kibana.alert.rule.description"))
        or _scalar(_alert_field(alert, "kibana.alert.rule.name"))
        or f"alert {key}"
    )
    event_time = _scalar(_alert_field(alert, "@timestamp")) or _scalar(
        _alert_field(alert, "kibana.alert.original_time")
    )
    labels = []
    if rule_id:
        labels.append(f"sig:{rule_id}")
    if event_time:
        labels.append(f"evt:{event_time}")
    return TicketCreate(
        key=key,
        summary=summary,
        description=f"Auto-created from alert {key} (rule {rule_id or 'unknown'}).",
        labels=labels,
        reporter="alerting",
        status="open",
    )


@app.post(ALERT_HOOK_PATH)
def kibana_alert_hook(payload: dict | list = Body(...)):
    # Body(...) explicitly: FastAPI reads a bare `dict | list` parameter as form data,
    # which fails at import without python-multipart (not in the image).
    """Body: `{"alerts": [...]}` (what the watcher sends) or a bare list."""
    alerts = payload.get("alerts") if isinstance(payload, dict) else payload
    if not isinstance(alerts, list):
        raise HTTPException(status_code=422, detail="expected a list of alerts")
    created, existing, skipped = [], [], 0
    for alert in alerts:
        body = ticket_for_alert(alert) if isinstance(alert, dict) else None
        if body is None:
            skipped += 1
            continue
        if body.key in STORE:  # a repeated delivery, or a re-fired alert
            existing.append(body.key)
            continue
        STORE[body.key] = Ticket(**body.model_dump())
        created.append(body.key)
    return {"created": created, "existing": existing, "skipped": skipped}


@app.post("/admin/reset")
def reset():
    count = _load_seed()
    return {"status": "reset", "ticket_count": count}
