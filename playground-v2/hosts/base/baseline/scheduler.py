#!/usr/bin/env python3
"""Baseline activity scheduler — batch 8.

One process per host. Spawns a dispatch loop per (action, identity) binding
drawn from /opt/soc-playground/baseline/catalog.yaml. Each loop samples
exponential inter-arrival times modulated by a time-of-day shape function
and executes actions as the bound realm identity via `runuser`.

Design intent (docs/playground-environment-v2.md §Baseline activity generators):

  - Jittered (Poisson, not cron) — draw intervals from random.expovariate.
  - Time-of-day shape — workhours peak, non-zero off-peak floor.
  - Weekday/weekend variation — service accounts flat, humans quieter on weekends.
  - Seeded reproducibility — same BASELINE_SEED → same arrival sequence.

The scheduler is state-free across restarts: on container recreate it starts
a fresh sequence (seeded from env), not resumed. Good enough for playground
baselines.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import random
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

CATALOG = Path("/opt/soc-playground/baseline/catalog.yaml")
INVENTORY = Path("/opt/soc-playground/inventory.yaml")
REALM = Path("/opt/soc-playground/realm.yaml")
LOG_PATH = Path("/var/log/baseline.log")


# ── Shape functions ──────────────────────────────────────────────────────────
# Every shape returns a multiplier in (0, 1]. effective_mean = mean_s /
# multiplier — smaller multiplier → longer gaps between dispatches.

def _weekday(now: datetime) -> bool:
    return now.weekday() < 5  # Mon–Fri


def shape_flat(now: datetime) -> float:
    return 1.0


def shape_workhours_utc(now: datetime) -> float:
    if not _weekday(now):
        return 0.05
    if 9 <= now.hour < 17:
        return 1.0
    return 0.15


def shape_workhours_us(now: datetime) -> float:
    # Approximate US Eastern working hours (13:00–21:00 UTC) — gives overlap
    # with workhours-utc but not full synchronization, per spec.
    if not _weekday(now):
        return 0.05
    if 13 <= now.hour < 21:
        return 1.0
    return 0.15


def shape_overnight_peak(now: datetime) -> float:
    # 22:00–06:00 UTC is the automation window (backup jobs etc.).
    if 22 <= now.hour or now.hour < 6:
        return 1.0
    return 0.2


SHAPES = {
    "flat": shape_flat,
    "workhours-utc": shape_workhours_utc,
    "workhours-us": shape_workhours_us,
    "overnight-peak": shape_overnight_peak,
}


# ── Inventory / identity resolution ──────────────────────────────────────────

def load_host(host_name: str) -> dict:
    inv = yaml.safe_load(INVENTORY.read_text())
    for h in inv["hosts"]:
        if h["name"] == host_name:
            return h
    sys.exit(f"FATAL: host {host_name!r} not in inventory.yaml")


def users_on_host(host_name: str) -> list[str]:
    """All realm usernames that seed-users.py would create on this host.

    Mirrors seed-users.py's resolve_users expansion. We don't import it
    directly (filename has a dash, not a valid module name) — duplicating
    the ~20-line resolve keeps scheduler.py standalone.
    """
    inv = yaml.safe_load(INVENTORY.read_text())
    host = next((h for h in inv["hosts"] if h["name"] == host_name), None)
    if host is None:
        sys.exit(f"FATAL: host {host_name!r} not in inventory.yaml")

    realm_users: dict[str, str] = {}
    if REALM.exists():
        realm = yaml.safe_load(REALM.read_text())
        for u in realm.get("users", []):
            roles = u.get("realmRoles", [])
            if roles:
                realm_users[u["username"]] = roles[0]

    resolved: set[str] = set()
    for role_name, role_cfg in inv.get("roles", {}).items():
        if host_name not in role_cfg.get("hosts", []):
            continue
        for username, role in realm_users.items():
            if role == role_name:
                resolved.add(username)
    for entry in host.get("users") or []:
        resolved.add(entry["username"])
    return sorted(resolved)


def match_identities(patterns: list[str], users: list[str]) -> list[str]:
    """Expand fnmatch patterns (sre.*, dev.*) against the user list."""
    out: list[str] = []
    for p in patterns:
        matched = [u for u in users if fnmatch.fnmatch(u, p)]
        for u in matched:
            if u not in out:
                out.append(u)
    return out


# ── Dispatch ─────────────────────────────────────────────────────────────────

def substitute(template: str, **kwargs) -> str:
    out = template
    for k, v in kwargs.items():
        out = out.replace("${" + k + "}", str(v))
    return out


def dispatch(action_id: str, user: str, cmd: str, log: logging.Logger) -> None:
    """Execute `cmd` as `user` via runuser. Captures exit code + elapsed time."""
    start = time.monotonic()
    try:
        # runuser on util-linux treats -u and -s as mutually exclusive, so we
        # skip -s and pass `bash -c` as the explicit argv instead — this
        # overrides the identity's login shell (e.g., /usr/sbin/nologin for
        # service accounts) in exactly the same way systemd timers dispatch
        # jobs as nologin service users.
        proc = subprocess.run(
            ["runuser", "-u", user, "--", "bash", "-c", cmd],
            capture_output=True, text=True, timeout=60,
        )
        rc = proc.returncode
        err_tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
    except subprocess.TimeoutExpired:
        rc = -1
        err_tail = "timeout"
    elapsed_ms = int((time.monotonic() - start) * 1000)
    log.info("action=%s user=%s rc=%s elapsed_ms=%s err=%s",
             action_id, user, rc, elapsed_ms, err_tail[:200])


# ── Per-binding loop ─────────────────────────────────────────────────────────

def run_binding(action: dict, user: str, host: dict, seed: str,
                log: logging.Logger, stop: threading.Event) -> None:
    shape_name = action["schedule"].get("shape", "flat")
    shape_fn = SHAPES[shape_name]
    mean_s = float(action["schedule"]["mean_s"])

    prng = random.Random(f"{seed}:{host['name']}:{action['id']}:{user}")

    # Stagger the first dispatch across a full mean interval so all bindings
    # don't pile up at startup.
    initial = prng.expovariate(1.0 / max(1.0, mean_s))
    if stop.wait(timeout=initial):
        return

    while not stop.is_set():
        now = datetime.now(timezone.utc)
        multiplier = shape_fn(now)
        effective_mean = mean_s / max(multiplier, 0.01)
        interval = prng.expovariate(1.0 / effective_mean)

        # Resolve ${target} / ${wrong} just-in-time — same-seeded prng so the
        # sequence of targets is deterministic per binding.
        cmd = action["cmd"]
        if "${target}" in cmd:
            targets = _resolve_targets(action, host)
            if not targets:
                log.info("action=%s user=%s skipped reason=no-targets",
                         action["id"], user)
                if stop.wait(timeout=interval):
                    return
                continue
            cmd = substitute(cmd, target=prng.choice(targets))
        if "${wrong}" in cmd:
            bads = action.get("bad_targets") or []
            if not bads:
                log.info("action=%s user=%s skipped reason=no-bad-targets",
                         action["id"], user)
                if stop.wait(timeout=interval):
                    return
                continue
            cmd = substitute(cmd, wrong=prng.choice(bads))
        cmd = substitute(cmd, host=host["name"], user=user)

        if stop.wait(timeout=interval):
            return

        try:
            dispatch(action["id"], user, cmd, log)
        except Exception as exc:  # noqa: BLE001 — never let one action kill the loop
            log.warning("action=%s user=%s dispatch_error=%s",
                        action["id"], user, exc)


def _resolve_targets(action: dict, host: dict) -> list[str]:
    source = action.get("targets_from")
    if source == "trust_edges_out":
        return list(host.get("trust_edges_out") or [])
    if isinstance(source, list):
        return list(source)
    return []


# ── Entrypoint ───────────────────────────────────────────────────────────────

def main() -> None:
    host_name = os.environ.get("HOST_NAME", "").strip()
    if not host_name:
        sys.exit("FATAL: HOST_NAME env var required")

    seed = os.environ.get("BASELINE_SEED", "42")

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_PATH),
        level=logging.INFO,
        format="%(asctime)sZ host=" + host_name + " %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    log = logging.getLogger("baseline")
    log.info("scheduler_start seed=%s", seed)

    host = load_host(host_name)
    users = users_on_host(host_name)

    catalog = yaml.safe_load(CATALOG.read_text())
    stop = threading.Event()
    threads: list[threading.Thread] = []

    for action in catalog.get("actions", []):
        if host["role"] not in action.get("host_roles", []):
            continue
        bound = match_identities(action.get("identities", []), users)
        if not bound:
            log.info("action=%s skipped reason=no-identity", action["id"])
            continue
        for user in bound:
            t = threading.Thread(
                target=run_binding,
                args=(action, user, host, seed, log, stop),
                name=f"{action['id']}:{user}",
                daemon=True,
            )
            t.start()
            threads.append(t)
            log.info("bound action=%s user=%s mean_s=%s shape=%s",
                     action["id"], user, action["schedule"]["mean_s"],
                     action["schedule"].get("shape", "flat"))

    log.info("scheduler_ready bindings=%s", len(threads))

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop.set()
        log.info("scheduler_stop")


if __name__ == "__main__":
    main()
