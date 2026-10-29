"""#1342 a worker in its own process: `python _worker_proc1342.py <config.json>`.

The config names the DSN, the data root, the child (`scripted`: `ScriptedChild` with a spec; or
`entry`: `_blocking_entry1342.py`), the stand-in container folder and the stop grace. The worker
runs `serve()` until SIGTERM/SIGINT (its deliberate stop)."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from defender.tests.support.jobs._jobs1342 import ScriptedChild, StandInContainers, fixed_clock


def _child(config: dict):
    if config["child"] == "scripted":
        return ScriptedChild(Path(config["where"]), Path(config["runs"]), files=config["files"],
                             wait_for=Path(config["wait_for"]) if config.get("wait_for") else None)
    entry, marks = config["entry"], config["marks"]
    return lambda launch: [sys.executable, entry, marks, config["commit"], "--job",
                           launch.investigation_id, "--tenant", launch.tenant_id,
                           "--parent-pid", str(launch.parent_pid)]


async def _main(config: dict) -> None:
    from defender.jobs import JobStore
    from defender.worker import Worker

    store = JobStore(config["dsn"], clock=fixed_clock)
    try:
        worker = Worker(store, data_root=Path(config["data_root"]), child_argv=_child(config),
                        containers=StandInContainers(Path(config["containers"])), slots=3,
                        clock=fixed_clock, stop_grace=config.get("stop_grace", 30.0))
        Path(config["ready"]).touch()
        await worker.serve()
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(_main(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))))
