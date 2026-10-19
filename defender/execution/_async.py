"""Running a coroutine from synchronous code: the one helper every sync caller shares."""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
from typing import Any


def run_sync(coro: Any) -> Any:
    """Run a coroutine from a synchronous caller, whether or not a loop is already running
    on this thread (if one is, it runs on a fresh thread with its own loop).

    The thread runs in a copy of the caller's context so log lines keep the run id and
    tenant (`_log.log_context`)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(contextvars.copy_context().run, asyncio.run, coro).result()
