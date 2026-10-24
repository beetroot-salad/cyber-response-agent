"""The run launcher's half of the launch-time publish (#1108 P4 U7, O-BUDGET, U11, O8).

Before a run starts, its launcher spawns the publish child (a separate short-lived process: the
run process never imports tenant delivery, P-3) and waits for its one-line report. It hands the
child identifiers only — the tenant id and the data root, as argv — and an environment with
every issuer-named variable removed: the child reads its login material from its own config
file (O8, P-4). It waits at most `budget` seconds while the child is in its network phase; a
child that has taken the tenant lock (its local phase) is never stopped, so a kill never leaves
`index.lock` or a half-swapped `current` behind. Whatever the child does, the launcher returns
one report line of the child's vocabulary:

- the child's own line, when it exited 0 having printed a valid one (OD20);
- `stale:transient ...` when the budget ran out in the network phase;
- `stale:operator publish child failed: <summary>` for a child that could not be started,
  crashed, exited non-zero, or printed nothing valid (U11) — never fresh.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from defender._text import one_line
from defender.tenancy._exports import OID, knowledge_lock_holder
from defender.tenancy._tenant import TenantRefused, data_root_from_path, requested_tenant

#: The real child's process entry, named (never imported: P-3).
CHILD_MODULE = "defender.learning.author.version_control.publish_child"
#: Where the child's `-m` resolves `defender` from: this checkout's root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
#: The report line's first words (the child's vocabulary).
_CLASSES = ("fresh", "stale:transient", "stale:operator", "misconfigured")
#: Environment names that could carry issuer or forge login material: never handed to the child.
_ISSUER_ENV = re.compile(
    r"BAO|VAULT|OPENBAO|ISSUER|APPROLE|ROLE_ID|SECRET_ID|FORGEJO_TOKEN", re.IGNORECASE)
#: How long a child asked to stop (SIGTERM) may take to unwind before it is killed.
_STOP_GRACE = 5.0
#: The most of a failed child's own words a summary carries.
_SUMMARY_LIMIT = 200

Spawn = Callable[..., Any]


def _failed(summary: str) -> str:
    return f"stale:operator publish child failed: {one_line(summary)[:_SUMMARY_LIMIT]}"


def child_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    """The child's environment: the launcher's, minus every issuer-named variable and every
    registered model provider's API key (the child only talks to the forge)."""
    from defender.runtime import providers

    source = os.environ if environ is None else environ
    keys = set(providers.api_key_vars())
    return {key: value for key, value in source.items()
            if not _ISSUER_ENV.search(key) and key not in keys}


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
    --data-root <root>`); `spawn` is `subprocess.Popen`'s stand-in."""
    prefix = list(command) if command is not None else [sys.executable, "-m", CHILD_MODULE]
    argv = [*prefix, str(tenant_id), "--data-root", str(data_root)]
    start = spawn if spawn is not None else subprocess.Popen
    try:
        proc = start(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=child_environment(), cwd=str(_REPO_ROOT), start_new_session=True)
    except (OSError, ValueError) as unstarted:
        return _failed(f"it could not be started: {type(unstarted).__name__}: "
                       f"{getattr(unstarted, 'strerror', None) or unstarted}")
    try:
        out, err = proc.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        if not _holds_lock(proc, tenant_id, data_root):
            _stop(proc, tenant_id, data_root)
            return (f"stale:transient the launch-time publish did not finish its network phase "
                    f"within the {budget:g}s budget")
        out, err = proc.communicate()
    return _read_report(proc.returncode, out, err)


def _holds_lock(proc: Any, tenant_id: str, data_root: Path) -> bool:
    """Has the child taken the tenant's knowledge lock (its holder writes its pid there)? Then
    it is past its network phase, doing local work that must not be cut off."""
    try:
        tenant = requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
        return knowledge_lock_holder(tenant) == proc.pid
    except (TenantRefused, OSError):
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


def _read_report(returncode: int | None, out: bytes | str | None, err: bytes | str | None) -> str:
    """The child's report line, or U11's failed line when there is no valid one."""
    def text(raw: bytes | str | None) -> str:
        if raw is None:
            return ""
        return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw

    said = [line.strip() for line in text(out).splitlines() if line.strip()]
    if returncode != 0:
        why = text(err).strip().splitlines()
        return _failed(f"it exited with status {returncode}" + (f": {why[-1]}" if why else ""))
    if not said:
        return _failed("it printed no report line")
    # The report is the child's last line: a stray line printed before it (a library's
    # warning on stdout) does not turn a reported outcome into a failure.
    line = said[-1]
    head, _, detail = line.partition(" ")
    if head not in _CLASSES or not detail.strip():
        return _failed(f"its report is not one of the publish outcomes: {line!r}")
    if head == "fresh" and not OID.fullmatch(detail.strip()):
        return _failed(f"its fresh report names no commit: {line!r}")
    return line
