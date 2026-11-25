"""#1546: a worker's `drain()` under an explicit bound, for the e2e flows (`e2e/test_1344_learning_replay.py`). A drain that
does not end within its bound is a failure naming what never ended, with what was in flight at that moment: the tenant's
job rows, its claims and their staged facts and uploads, the database sessions not idle (what each waits on), and this
process's live descendants. The drain is then cancelled (the worker ends its children) and given a bounded time to
unwind. A hang is a failure, never the CI job's time cap. It bounds an idle event loop only: a loop blocked in a
synchronous call is not woken by it."""
from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable
from pathlib import Path
from typing import Any

#: How long a cancelled drain is given to end its children and unwind before the failure is raised anyway.
UNWIND = 60.0


def _descendants(root: int) -> list[str]:
    """`pid ppid state cmdline` of every live process under `root`, from `/proc` (no psutil in the test venv)."""
    parents: dict[int, int] = {}
    lines: dict[int, str] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            continue
        fields = stat[stat.rindex(")") + 2:].split()
        pid = int(entry.name)
        parents[pid] = int(fields[1])
        lines[pid] = f"{pid} {fields[1]} {fields[0]} {cmd[:300]}"
    under, frontier = [], [root]
    while frontier:
        parent = frontier.pop()
        for pid, ppid in parents.items():
            if ppid == parent:
                under.append(pid)
                frontier.append(pid)
    return [lines[p] for p in sorted(under)]


def _in_flight(dsn: str, tenant: str) -> dict[str, Any]:
    from defender.tests.support.shared._postgres1339 import execute

    def rows(sql: str, args: tuple = ()) -> list[Any]:
        try:
            return [r[0] for r in execute(dsn, sql, args)]
        except Exception as fault:  # noqa: BLE001 — a diagnostic: a read that fails is reported, never raised
            return [f"unreadable: {fault!r}"]

    return {
        "investigations": rows("SELECT row_to_json(i) FROM jobs.investigations i WHERE tenant_id = %s", (tenant,)),
        "learning_jobs": rows("SELECT row_to_json(j) FROM jobs.learning_jobs j WHERE tenant_id = %s", (tenant,)),
        "claims": rows("SELECT json_build_object('token', token, 'kind', kind, 'investigation', investigation_id, "
                       "'learning_job', learning_job_id, 'inputs', inputs) FROM jobs.claims WHERE tenant_id = %s",
                       (tenant,)),
        "staged_facts": rows("SELECT json_build_object('token', f.token, 'name', f.name) FROM jobs.staged_facts f "
                             "JOIN jobs.claims c USING (token) WHERE c.tenant_id = %s", (tenant,)),
        "uploads": rows("SELECT json_build_object('token', u.token, 'object', u.object, 'status', u.status, 'size', "
                        "u.size) FROM jobs.uploads u JOIN jobs.claims c USING (token) WHERE c.tenant_id = %s",
                        (tenant,)),
        "sessions": rows("SELECT json_build_object('pid', pid, 'state', state, 'wait', wait_event_type || ':' || "
                         "wait_event, 'xact_start', xact_start, 'query', left(query, 200)) FROM pg_stat_activity "
                         "WHERE datname = current_database() AND pid <> pg_backend_pid() AND state <> 'idle'"),
    }


async def drained_within(drain: Awaitable[Any], seconds: float, *, what: str, dsn: str, tenant: str) -> None:
    """Await `drain` (a worker's `drain()`), failing when it has not ended within `seconds`: the failure names `what`
    never ended and carries what was in flight then (module doc)."""
    task = asyncio.ensure_future(drain)
    done, _ = await asyncio.wait({task}, timeout=seconds)
    if task in done:
        task.result()
        return
    seen = {"in_flight": await asyncio.to_thread(_in_flight, dsn, tenant), "processes": _descendants(os.getpid())}
    task.cancel()
    unwound, _ = await asyncio.wait({task}, timeout=UNWIND)
    raise AssertionError(f"{what} did not end within {seconds:.0f}s (the cancelled drain "
                         f"{'unwound' if unwound else f'had not unwound {UNWIND:.0f}s later'}); in flight then: {seen}")
