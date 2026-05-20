"""Identity stub — authoritative authz API over realm.yaml × inventory.yaml.

Exposes the same join `hosts/base/seed-users.py` does at container start, but
from the per-user perspective: "which hosts is user U authorized on, and with
what shell/sudo?" The soc-agent uses this to resolve legitimacy contracts
without having to reimplement the join or trust whatever `/etc/passwd` happens
to contain on a given host.

Source files baked into the image:
  /opt/identity/realm.yaml      ← keycloak/realm.yaml
  /opt/identity/inventory.yaml  ← hosts/inventory.yaml

Read-only. No write surface; no overlay/chaos endpoints yet (deferred until a
stale-IdP scenario needs one). Auth-less; loopback-exposed on the VPS.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import yaml
from fastapi import FastAPI, HTTPException

REALM_PATH = Path(os.environ.get("IDENTITY_REALM_PATH", "/opt/identity/realm.yaml"))
INVENTORY_PATH = Path(os.environ.get("IDENTITY_INVENTORY_PATH", "/opt/identity/inventory.yaml"))


USERS: dict[str, dict[str, Any]] = {}
ROLES: dict[str, dict[str, Any]] = {}
HOSTS: dict[str, dict[str, Any]] = {}
# Materialized per-user access: {username: {host: {via, sudo, shell}}}
ACCESS: dict[str, dict[str, dict[str, Any]]] = {}


def _load() -> None:
    USERS.clear()
    ROLES.clear()
    HOSTS.clear()
    ACCESS.clear()

    realm = yaml.safe_load(REALM_PATH.read_text()) or {}
    inv = yaml.safe_load(INVENTORY_PATH.read_text()) or {}

    for u in realm.get("users", []):
        roles = u.get("realmRoles") or []
        USERS[u["username"]] = {
            "username": u["username"],
            "email": u.get("email"),
            "first_name": u.get("firstName"),
            "last_name": u.get("lastName"),
            "enabled": u.get("enabled", True),
            "realm_role": roles[0] if roles else None,
        }

    for role_name, role_cfg in (inv.get("roles") or {}).items():
        ROLES[role_name] = {
            "name": role_name,
            "hosts": list(role_cfg.get("hosts") or []),
            "shell": role_cfg.get("shell", "/bin/bash"),
            "sudo": bool(role_cfg.get("sudo", False)),
            "sudo_hosts": list(role_cfg.get("sudo_hosts") or []) if role_cfg.get("sudo_hosts") is not None else None,
        }

    for h in inv.get("hosts") or []:
        HOSTS[h["name"]] = h

    _materialize_access()


def _materialize_access() -> None:
    """Build the per-user → per-host access map.

    Mirrors hosts/base/seed-users.py:resolve_users but inverted: that fn answers
    "which users on host H?", we answer "which hosts for user U?". Per-host
    `users:` overrides still win over role-wide rules.
    """
    for username, urec in USERS.items():
        role_name = urec["realm_role"]
        per_host: dict[str, dict[str, Any]] = {}

        if role_name and role_name in ROLES:
            role = ROLES[role_name]
            for host_name in role["hosts"]:
                if role["sudo_hosts"] is not None:
                    sudo = host_name in role["sudo_hosts"]
                else:
                    sudo = role["sudo"]
                per_host[host_name] = {
                    "via": "role",
                    "role": role_name,
                    "shell": role["shell"],
                    "sudo": sudo,
                }

        for host_name, host in HOSTS.items():
            for entry in host.get("users") or []:
                if entry.get("username") != username:
                    continue
                per_host[host_name] = {
                    "via": "override",
                    "role": role_name,
                    "shell": entry.get("shell", "/bin/bash"),
                    "sudo": bool(entry.get("sudo", False)),
                }

        ACCESS[username] = per_host


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load()
    yield


app = FastAPI(title="Playground identity stub", lifespan=lifespan)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "user_count": len(USERS),
        "role_count": len(ROLES),
        "host_count": len(HOSTS),
    }


@app.get("/users")
def list_users(role: Optional[str] = None, enabled: Optional[bool] = None):
    out = []
    for username, urec in USERS.items():
        if role is not None and urec["realm_role"] != role:
            continue
        if enabled is not None and urec["enabled"] != enabled:
            continue
        out.append(urec)
    return {"total": len(out), "users": out}


def _user_record(username: str) -> dict[str, Any]:
    urec = USERS.get(username)
    if urec is None:
        raise HTTPException(status_code=404, detail=f"user {username} not found")
    access = ACCESS.get(username, {})
    authorized_hosts = sorted(access.keys())
    sudo_hosts = sorted(h for h, v in access.items() if v["sudo"])
    return {
        **urec,
        "authorized_hosts": authorized_hosts,
        "sudo_hosts": sudo_hosts,
    }


@app.get("/users/{username}")
def get_user(username: str):
    return _user_record(username)


@app.get("/users/{username}/authorized_hosts")
def authorized_hosts(username: str):
    if username not in USERS:
        raise HTTPException(status_code=404, detail=f"user {username} not found")
    return sorted(ACCESS.get(username, {}).keys())


@app.get("/users/{username}/can_access")
def can_access(username: str, host: str):
    if username not in USERS:
        raise HTTPException(status_code=404, detail=f"user {username} not found")
    entry = ACCESS.get(username, {}).get(host)
    if entry is None:
        return {"authorized": False, "via": None, "role": USERS[username]["realm_role"], "sudo": False, "shell": None}
    return {"authorized": True, **entry}


@app.get("/roles")
def get_roles():
    return ROLES


@app.post("/admin/reset")
def reset():
    _load()
    return {
        "status": "reset",
        "user_count": len(USERS),
        "role_count": len(ROLES),
        "host_count": len(HOSTS),
    }
