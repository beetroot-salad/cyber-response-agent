"""The run launcher's half of the launch-time publish (#1108 P4 U7, O-BUDGET, U11, O8).

Before a run starts, its launcher spawns the publish child (a separate short-lived process: the
run process never imports tenant delivery, P-3) and waits for its one-line report. It hands the
child identifiers and a number only — the tenant id, the data root and the child's own budget,
as argv — and the host children's scrubbed environment (`provider_scrubbed_environ`): the child
reads its login material from the config file its tenant row names (O8, P-4).

The child holds its own deadline over its network phase, a little inside the launcher's
`budget`, and reports (and records) running out of it itself. The launcher's wait is the
backstop: a child still in its network phase when `budget` runs out is stopped; a child that
has taken the tenant lock (its local phase) is never stopped, so a kill never leaves
`index.lock` or a half-swapped `current` behind. Whatever the child does, the launcher returns
one report line of the child's vocabulary:

- the child's own line, when it exited 0 having printed a valid one (OD20);
- `stale:transient ...` when the backstop stopped it in the network phase;
- `stale:operator publish child failed: <summary>` for a child that could not be started,
  crashed, exited non-zero, or printed nothing valid (U11) — never fresh.

Those last two the child never got to record, so the launcher records them (O-SEE).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from defender.run_common import provider_scrubbed_environ
from defender.runtime import run_knowledge
from defender.tenancy._exports import knowledge_lock_holder
from defender.tenancy._publish_status import STALE_TRANSIENT, record_report
from defender.tenancy._tenant import (
    Tenant,
    TenantRefused,
    data_root_from_path,
    requested_tenant,
)

#: The real child's process entry, named (never imported: P-3).
CHILD_MODULE = "defender.learning.author.version_control.publish_child"
#: Where the child's `-m` resolves `defender` from: this checkout's root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
#: How far inside the launcher's budget the child's own deadline falls (at most a quarter of
#: it), so the child reports running out itself before the backstop fires.
_REPORT_MARGIN = 5.0
#: Who records an outcome only the launcher sees (`tenant.py check` names the trigger).
_TRIGGER = "launch-time publish"
#: How long a child asked to stop (SIGTERM) may take to unwind before it is killed.
_STOP_GRACE = 5.0

Spawn = Callable[..., Any]


def _tenant(tenant_id: str, data_root: Path) -> Tenant | None:
    try:
        return requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
    except (TenantRefused, OSError):
        return None


def _recorded(tenant_id: str, data_root: Path, line: str) -> str:
    """`line`, an outcome the child never recorded, recorded for `tenant.py check` by the
    child's own recorder (`record_report`), so it reads as the child's would."""
    tenant = _tenant(tenant_id, data_root)
    if tenant is not None:
        record_report(tenant, line, by=_TRIGGER)
    return line


def child_budget(budget: float) -> float:
    """The child's own deadline over its network phase, inside the launcher's `budget`."""
    return budget - min(_REPORT_MARGIN, budget / 4)


def launch_publish(
    tenant_id: str,
    *,
    data_root: Path,
    budget: float = 60.0,
    command: Sequence[str] | None = None,
    spawn: Spawn | None = None,
) -> str:
    """Run the publish child for `tenant_id` under `data_root` and return its report line (module
    doc). `command` replaces the child's argv prefix (the launcher appends `<tenant id>
    --data-root <root> --budget <seconds>`); `spawn` is `subprocess.Popen`'s stand-in. A
    `budget` that is not positive is a caller's error (`ValueError`): there is no wait to give."""
    if not budget > 0:
        raise ValueError(f"the launch-time publish budget must be positive, not {budget!r}")
    prefix = list(command) if command is not None else [sys.executable, "-m", CHILD_MODULE]
    argv = [*prefix, str(tenant_id), "--data-root", str(data_root),
            "--budget", f"{child_budget(budget):g}"]
    start = spawn if spawn is not None else subprocess.Popen
    try:
        proc = start(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=provider_scrubbed_environ(), cwd=str(_REPO_ROOT), start_new_session=True)
    except (OSError, ValueError) as unstarted:
        return _recorded(tenant_id, data_root, run_knowledge.failed_line(
            f"it could not be started: {type(unstarted).__name__}: "
            f"{getattr(unstarted, 'strerror', None) or unstarted}"))
    try:
        out, err = proc.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        if not _holds_lock(proc, tenant_id, data_root):
            _stop(proc, tenant_id, data_root)
            return _recorded(
                tenant_id, data_root,
                f"{STALE_TRANSIENT} the launch-time publish did not finish its network phase "
                f"within the {budget:g}s budget")
        out, err = proc.communicate()
    line, failed = _read_report(proc.returncode, out, err)
    return _recorded(tenant_id, data_root, line) if failed else line


def _holds_lock(proc: Any, tenant_id: str, data_root: Path) -> bool:
    """Has the child taken the tenant's knowledge lock (its holder writes its pid there)? Then
    it is past its network phase, doing local work that must not be cut off."""
    tenant = _tenant(tenant_id, data_root)
    try:
        return tenant is not None and knowledge_lock_holder(tenant) == proc.pid
    except OSError:
        return False
def _stop(proc: Any, tenant_id: str, data_root: Path) -> None:
    """Ask the child to end (it unwinds its network calls, killing their process groups),
    then kill it — unless it took the lock meanwhile, in which case it is let finish."""
    try:
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=_STOP_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    except ProcessLookupError:
        return
    if _holds_lock(proc, tenant_id, data_root):
        proc.communicate()
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
    proc.communicate()


def _read_report(
    returncode: int | None, out: bytes | str | None, err: bytes | str | None,
) -> tuple[str, bool]:
    """The child's report line, or U11's failed line when there is no valid one; and whether
    it is the failed line (the child recorded nothing)."""
    def text(raw: bytes | str | None) -> str:
        if raw is None:
            return ""
        return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw

    said = [line.strip() for line in text(out).splitlines() if line.strip()]
    if returncode != 0:
        why = text(err).strip().splitlines()
        return run_knowledge.failed_line(
            f"it exited with status {returncode}" + (f": {why[-1]}" if why else "")), True
    if not said:
        return run_knowledge.failed_line("it printed no report line"), True
    # The report is the child's last line: a stray line printed before it (a library's
    # warning on stdout) does not turn a reported outcome into a failure. Its grammar is run
    # start's own (`run_knowledge.read_publish_report`), judged once there.
    line = said[-1]
    if run_knowledge.read_publish_report(line).unreadable:
        return run_knowledge.failed_line(
            f"its report is not one of the publish outcomes: {line!r}"), True
    return line, False
