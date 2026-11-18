"""A learning job's post-step (#1344 O8, O14), in its job container (#1170): `python -m
defender.learning.branch.post_step [--job <id>] --tenant <T>`, started by the per-job host helper once a job that started
a family step has ended, whatever its status. Without `--job` it is a family-less post-step (#1344
amendment 1): the worker's check of a tenant whose last post-step left work waiting (amendment 3), so
a reviewer's verdict, a retained delivery or findings at threshold are not left waiting for the tenant's next alert.

It runs the author drain's tick once and returns its exit status (#1487). It publishes nothing (a learning job's findings
are stored by the worker with its ending), writes no record and hands nothing over: whether work is still waiting is the
worker's own question of the store once the container has exited (Flow 3). The tick's store is the job container's port
(`JobContainer.tick_store()`, Amendment 1): each store step is a request the helper answers with the trusted values bound
on its side, so nothing here holds a database address or opens a database.

Inside the container it takes no host lock, runs no admission and opens no database: the helper holds the tenant's
lock and admitted it before the container started (P-C). The tenant is accepted by the folder rules alone; the drain's
publish and draft (`batch.start`), its forge tokens (`forge.token`), its publish outcomes (`record.*`) and its store
(`store.*`) are the helper's, asked over the job socket (`container.JobContainer`). With no job socket (a host shell) it
does nothing and exits non-zero (A6). The first SIGTERM is a `KeyboardInterrupt`, so the tick unwinds and anything it
started is terminated; the end of its stdin (the helper's end of the container, A5) is that SIGTERM.
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from collections.abc import Callable, Mapping
from typing import Any

from defender import tenancy
from defender._paths import process_defender_dir
from defender.learning.branch.container import JobContainer, NotInContainer, sigterm_on_stdin_eof
from defender.records.formats import TenantRefused

_logger = logging.getLogger(__name__)

__all__ = ["main", "parse_post_step_args"]


def parse_post_step_args(argv: list[str]) -> argparse.Namespace:
    """`[--job <id>] --tenant <T>`; no `--job` is a family-less post-step (`job` None). A `--parent-pid` (the host
    entry's, retired) is accepted and not read: inside the container the death tie is the stdin's end (A5)."""
    p = argparse.ArgumentParser(prog="python -m defender.learning.branch.post_step",
                                description="A learning job's post-step, run in its job container.")
    p.add_argument("--job", default=None,
                   help="the job whose post-step this is; left out, the worker's family-less check of the tenant")
    p.add_argument("--tenant", required=True, help="the jobs' tenant")
    p.add_argument("--parent-pid", default=None, type=int, help=argparse.SUPPRESS)
    return p.parse_args(argv)


def _interrupt(_signum: int, _frame: Any) -> None:
    """The first SIGTERM is a `KeyboardInterrupt`; every later one is ignored, so the unwind it
    starts is not itself interrupted."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


def _default_tick(paths: Any, *, store: Any) -> int:
    """The lessons drain's tick over `store`, the job container's port; inside the job container the drain finds the
    helper for its records and forge by the job socket itself (`JobContainer.in_environ`)."""
    from defender.learning.core import drains

    return drains.author_drain(paths, store=store)


def main(argv: list[str], *, author_tick: Callable[..., int] | None = None,
         directory: Any = None, environ: Mapping[str, str] | None = None, watch_stdin: bool = False) -> int:
    """Run the drain's tick once, its store the job container's port; returns the tick's exit. In the job container
    (`environ`, default this process's) the tenant is accepted by the folder rules alone: the helper holds its lock for
    the whole step. With no job socket in `environ` it exits non-zero having done nothing (A6). `directory` is accepted
    for callers that still pass it and is not read. `watch_stdin` (the process's own entry point): the end of stdin is a
    SIGTERM (A5)."""
    del directory
    ns = parse_post_step_args(argv)
    which = f"job {ns.job}" if ns.job is not None else f"tenant {ns.tenant} (no family)"
    try:
        ask = JobContainer.client(environ)
    except NotInContainer as outside:
        sys.exit(f"[post-step] {which}: {outside}; nothing was done")
    on_main = threading.current_thread() is threading.main_thread()
    previous = signal.signal(signal.SIGTERM, _interrupt) if on_main else None
    try:
        if watch_stdin:
            sigterm_on_stdin_eof()
        paths, store = _opened(ns, which, ask)
        tick = author_tick if author_tick is not None else _default_tick
        exit_code = tick(paths, store=store)
        _logger.info(f"post-step of {which}: the tick ended with status {exit_code}")
        return exit_code
    finally:
        if on_main:
            signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


def _opened(ns: argparse.Namespace, which: str, ask: Callable[..., Any]) -> tuple[Any, Any]:
    """The tenant's learning paths (accepted by the folder rules) and the tick's store (the job container's port), or the
    step's refusal."""
    from defender.learning.core.config import LoopPaths
    from defender.learning_store.tick import StoreUnavailable

    try:
        container = JobContainer.connect(ask, tenant=ns.tenant)  # the helper's launch facts name this tenant
        data_root = tenancy.resolve_data_root()
        tenant = tenancy.accept_tenant(data_root, ns.tenant, defender_dir=process_defender_dir())
    except (TenantRefused, OSError, ValueError) as unusable:
        sys.exit(f"[post-step] {which}: the tenant cannot be used: {unusable}")
    try:
        store = container.tick_store()
    except (StoreUnavailable, ValueError) as unreachable:
        sys.exit(f"[post-step] {which}: the learning store cannot be reached through the helper: {unreachable}")
    return LoopPaths.for_tenant(tenant), store


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:], watch_stdin=True))
