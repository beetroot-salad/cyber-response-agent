"""CMDB stub — asset queries + in-memory mutation overlay.

Source of truth is hosts/inventory.yaml (baked into /opt/cmdb/inventory.yaml at
build time). Reads load into an immutable BASE dict; writes go to OVERLAY,
which is shallow-merged over BASE on read. The overlay exists to let the chaos
control plane (batch 11) stage stale-CMDB scenarios — phantom owners, renamed
hosts, reclassified criticality — without touching the file.

Not for production. Auth-less; loopback-exposed on the VPS.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

INVENTORY_PATH = Path(os.environ.get("CMDB_INVENTORY_PATH", "/opt/cmdb/inventory.yaml"))

BASE: dict[str, dict[str, Any]] = {}
ROLES: dict[str, Any] = {}
OVERLAY: dict[str, dict[str, Any]] = {}


def _load_inventory() -> None:
    BASE.clear()
    ROLES.clear()
    raw = yaml.safe_load(INVENTORY_PATH.read_text())
    for host in raw.get("hosts", []):
        BASE[host["name"]] = host
    ROLES.update(raw.get("roles", {}))


def _effective(name: str) -> Optional[dict[str, Any]]:
    base = BASE.get(name)
    if base is None and name not in OVERLAY:
        return None
    merged = dict(base or {"name": name})
    merged.update(OVERLAY.get(name, {}))
    return merged


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_inventory()
    yield


app = FastAPI(title="Playground CMDB stub", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "host_count": len(BASE), "overlay_count": len(OVERLAY)}


@app.get("/hosts")
def list_hosts(
    role: Optional[str] = None,
    criticality: Optional[str] = None,
    owner: Optional[str] = None,
):
    names = set(BASE) | set(OVERLAY)
    out = [_effective(n) for n in sorted(names)]
    out = [h for h in out if h is not None]
    if role:
        out = [h for h in out if h.get("role") == role]
    if criticality:
        out = [h for h in out if h.get("criticality") == criticality]
    if owner:
        out = [h for h in out if h.get("owner") == owner]
    return {"total": len(out), "hosts": out}


@app.get("/hosts/{name}")
def get_host(name: str):
    h = _effective(name)
    if h is None:
        raise HTTPException(status_code=404, detail=f"host {name} not found")
    return h


@app.get("/roles")
def get_roles():
    return ROLES


class OverlayBody(BaseModel):
    # Free-form partial record; fields shallow-merge over BASE on read.
    # Typed as dict to accept any inventory field (role, criticality, owner,
    # change_window, os, service, trust_edges_out, users, etc.).
    model_config = {"extra": "allow"}


@app.post("/admin/overlay/{name}")
def set_overlay(name: str, body: dict[str, Any]):
    OVERLAY[name] = {**OVERLAY.get(name, {}), **body}
    return {"name": name, "overlay": OVERLAY[name]}


@app.delete("/admin/overlay/{name}")
def clear_overlay(name: str):
    removed = OVERLAY.pop(name, None)
    return {"name": name, "cleared": removed is not None}


@app.post("/admin/reset")
def reset():
    OVERLAY.clear()
    _load_inventory()
    return {"status": "reset", "host_count": len(BASE), "overlay_count": 0}
