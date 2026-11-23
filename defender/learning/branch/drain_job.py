"""A drain request's container entry (#1546 D7): `python -m defender.learning.branch.drain_job --job <request id> --tenant <T>`,
started by the per-job host helper of kind `drain`.

It runs the lead-author lane's tick once (`drains.lead_author_drain`) over the tenant's folder (bound read-write, as the
post-step's), its store the job container's port, and resolves a curation request's run only from the runs its helper
unpacked into the drain's own root (`launch.job_root`, `<root>/<T>/runs/<run id>`). Its result is the tick's exit status,
sent as the `result` record (an int); it writes no file the worker reads. Inside the container it takes no host lock,
runs no admission and opens no database. With no job socket (a host shell) it does nothing and exits non-zero."""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from defender import job_socket, tenancy
from defender._paths import process_defender_dir
from defender.learning.branch.container import JobContainer, NotInContainer, interrupt_on_sigterm, sigterm_on_stdin_eof
from defender.records.formats import TenantRefused

_logger = logging.getLogger(__name__)

__all__ = ["main"]


def _parse_drain_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m defender.learning.branch.drain_job",
                                description="A drain request's lead-author tick, run in its job container.")
    p.add_argument("--job", required=True, help="the drain request's id")
    p.add_argument("--tenant", required=True, help="the request's tenant")
    return p.parse_args(argv)


def _lead_tick(paths: Any, *, store: Any, runs: Any, unusable: Callable[[str, str], bool]) -> int:
    from defender.learning.core import drains

    return drains.lead_author_drain(paths, store=store, runs=runs, unusable=unusable)


def _asked_unusable(ask: Callable[..., dict[str, Any]], tenant_id: str) -> Callable[[str, str], bool]:
    """How the tick judges an absent run's owner (#1546 PR6): the helper's `owner.unusable`, for the drain's own tenant only
    (the container opens no database). A refusal raises, and the tick leaves that request waiting."""
    def unusable(tenant: str, run_id: str) -> bool:
        if tenant != tenant_id:
            raise ValueError(f"run {run_id} names tenant {tenant}, not the drain's")
        return bool(ask("owner.unusable", run_id=run_id)["unusable"])

    return unusable


def main(argv: list[str], *, tick: Callable[..., int] | None = None, environ: Mapping[str, str] | None = None,
         watch_stdin: bool = False) -> int:
    """Run the tick once and send its exit status as the drain's `result` (module doc); returns that status."""
    from defender.learning.core.config import LoopPaths

    ns = _parse_drain_args(argv)
    try:
        ask = JobContainer.client(environ)
    except NotInContainer as outside:
        sys.exit(f"[drain] request {ns.job}: {outside}; nothing was done")
    on_main = threading.current_thread() is threading.main_thread()
    previous = signal.signal(signal.SIGTERM, interrupt_on_sigterm) if on_main else None
    try:
        if watch_stdin:
            sigterm_on_stdin_eof()
        try:
            container = JobContainer.connect(ask, tenant=ns.tenant)
            tenant = tenancy.accept_tenant(tenancy.resolve_data_root(), ns.tenant, defender_dir=process_defender_dir())
            launch = container.launch
            job_root = launch.get("job_root")
            if not isinstance(job_root, str) or not job_root:
                raise TenantRefused("the launch facts name no drain root (`job_root`)")
            runs = tenancy.job_tenant_from_launch(tenancy.data_root_from_path(Path(job_root)), ns.tenant,
                                                  launch).runs_repository()
            store = container.tick_store()
        except (TenantRefused, OSError, ValueError) as unusable:
            sys.exit(f"[drain] request {ns.job}: the tenant cannot be used: {unusable}")
        status = (tick or _lead_tick)(LoopPaths.for_tenant(tenant), store=store, runs=runs,
                                      unusable=_asked_unusable(ask, ns.tenant))
        try:
            ask("result", record=int(status))
        except job_socket.Refused as refused:
            _logger.error("drain %s: the helper refused its result (%s): %s", ns.job, refused.code, refused)
        return int(status)
    finally:
        if on_main:
            signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:], watch_stdin=True))
