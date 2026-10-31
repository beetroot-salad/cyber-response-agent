"""#1214 r10.1: the names the design leaves to the implementer, spelled once (A1, A2, A3, C3, C6, C8). Test support only.

The host acceptance step (A1, C3): `host_tenant(data_root, raw_id, *, directory=None, defender_dir=..., box_mounted=(),
clone_tree=True)` checks eagerly (raising `TenantRefused` at the call) and returns the admitted value, which carries
`.tenant` (the `Tenant`), `.directory` (the `TenantDirectory` it was admitted through) and `.wiring` (the forge
wiring); `with admitted:` releases the hold. It lives above `tenancy` and `migrations`, next to
`systems/run_tenant.entry_directory` (design: "The host acceptance step"); the module and the name are this
contract's choice. Where the implementer spells them otherwise, only this module changes.
"""
from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

#: The module the host acceptance step lives in, and its name (A1). Chosen here; the design names neither.
HOST_MODULE = "defender.systems.run_tenant"
HOST_MODULE_PATH = "systems/run_tenant.py"
HOST_ACCEPTANCE = "host_tenant"

#: The fields of the scope's value (design: "`admitted` carries the `Tenant`, the `TenantDirectory` ..., and the
#: forge wiring"). Chosen here.
ADMITTED_TENANT, ADMITTED_DIRECTORY, ADMITTED_WIRING = "tenant", "directory", "wiring"

#: The words the one waiting line carries while acceptance waits on the tenant's host lock (owner ruling: one line
#: naming that it is waiting for tenant T's host lock). The tenant id is asserted beside these.
WAITING_WORDS = ("waiting for tenant", "host lock")

#: The run-end curation request's keyword for the run's accepted tenant (O-A5: "the `enqueue` seam `run.main`
#: injects takes it"). Chosen here.
ENQUEUE_TENANT = "tenant"

#: C6: the environment variable the lifecycle process sets on itself (its `__main__` entry); the host acceptance
#: refuses in a process that carries it. Chosen here; the design says only that the process "marks itself".
LIFECYCLE_MARK = "DEFENDER_LIFECYCLE_PROCESS"

#: C8: the one tenant every box test names (never a wrapper that supplies a tenant, which would hide B1).
TEST_TENANT = "3d6f0b8e-2a41-4c97-9e15-7b2c8a4d6f01"

#: C2: the functions of an entry module that may open a host acceptance (the command, not a helper).
COMMAND_FUNCTIONS = frozenset({"main", "_launch"})

#: The raw folder acceptance's own module (it defines `accept_tenant`). The census derives every wrapper that reaches
#: it by reachability; no list of wrapper names is kept.
RAW_LAYER = "tenancy/_tenant.py"

#: A3: the processes covered by their starter, which load the folder with the folder rules only. Exactly these.
A3_SET = frozenset({
    "learning/author/version_control/publish.py",
    "investigation/publish_launch.py",
    "skills/connect/validate_scaffold.py",
})

#: The entry points that move to the host acceptance step (design: "Callers that move to it").
ENTRY_POINT_MODULES = (
    "run.py",
    "learning/branch/cli.py",
    "cli/policy_cli.py",
    "cli/tenant.py",
    "learning/core/cli.py",
    "cli/learning/revert_lesson.py",
    "cli/learning/lessons_page.py",
    "learning/leads/lead_author/__init__.py",
    "presentation/visualize_run.py",
    "cli/workspace_map.py",
    "presentation/visualize_episode.py",
    "learning/frontend/serialize.py",
    "cli/learning/trace_lesson.py",
    "cli/retire_legacy_runs.py",
)


# --- the read-only and one-shot commands that take `directory=` (design: "Callers that move to it") -------------------

#: A canonical lowercase uuid4, the only text `RunId` admits, so a command that passes acceptance can parse it.
RUN_ID = "9c2e4a17-3b58-4d06-b1f2-7e0a5c8d3f94"
EPISODE_ID = "5b1d9c3e-7a42-4f68-8e0b-2c6a9d4f1e73"

#: name -> (module, argv for tenant `t`). Each command's `main(argv, *, directory=None)` is the in-process seam
#: (design "Test fallout": the launcher, revert, policy view, lessons page and read-only commands gain it). The argv
#: convention (with or without the program name) follows each command's present `main`; the lessons page is new.
COMMANDS: dict[str, tuple[str, Callable[[str], list[str]]]] = {
    "workspace_map": ("defender.cli.workspace_map", lambda t: ["workspace_map.py", "--tenant", t, RUN_ID]),
    "run_page": ("defender.presentation.visualize_run", lambda t: ["visualize_run.py", "--tenant", t, RUN_ID]),
    "episode_page": ("defender.presentation.visualize_episode", lambda t: ["--tenant", t, EPISODE_ID]),
    "posture_contract": ("defender.learning.frontend.serialize", lambda t: ["serialize.py", "--tenant", t]),
    "lesson_tracer": ("defender.cli.learning.trace_lesson", lambda t: ["--tenant", t, "--all"]),
    "retirement": ("defender.cli.retire_legacy_runs", lambda t: ["--tenant", t]),
    "lead_author_opener": ("defender.learning.leads.lead_author", lambda t: ["--tenant", t, RUN_ID]),
    "lessons_page": ("defender.cli.learning.lessons_page", lambda t: ["--tenant", t]),
    "revert": ("defender.cli.learning.revert_lesson", lambda t: ["--tenant", t, "some-lesson"]),
    "policy_view": ("defender.cli.policy_cli",
                    lambda t: ["show", "gather", "--run-dir", os.devnull, "--tenant", t]),
}


def command_main(name: str) -> Callable[..., Any]:
    return importlib.import_module(COMMANDS[name][0]).main


# --- the hold, observed (shared by the host-entry and host-lock cases) -----------------------------------------------

def recorded(data_root: Path, tenant: str) -> list[tuple[int, Any]]:
    """`(pid, start)` of each process recorded under `tenant`'s host lock."""
    from defender.tenancy import host_lock

    return [(h.pid, h.start) for h in host_lock.holders(data_root, tenant)]


def this_process() -> list[tuple[int, Any]]:
    from defender.tenancy._owner import process_start

    return [(os.getpid(), process_start(os.getpid()))]


def exclusive_free(data_root: Path, tenant: str) -> bool:
    """True when nothing holds `tenant`'s host lock (an exclusive try, at once, is granted and given back)."""
    from defender.tenancy import host_lock

    fd = host_lock.acquire(data_root, tenant, exclusive=True, timeout=0)
    host_lock.release_lock(fd)
    return fd is not None


def host_tenant(*args: Any, **kwargs: Any) -> Any:
    """The real host acceptance step, imported at call time (a missing target is a red at the case, not at
    collection)."""
    return getattr(importlib.import_module(HOST_MODULE), HOST_ACCEPTANCE)(*args, **kwargs)


# --- the tenant's folder, observed at the operating system's boundary (O-A1 order, O-A2) -----------------------------

#: The audit events that touch a path; an audit hook cannot be removed, so one hook serves every test and a case turns it
#: on for the length of a `with watch_folder(...)` block.
_PATH_EVENTS = frozenset({"open", "os.listdir", "os.scandir"})
_WATCH: dict[str, Any] = {"installed": False, "prefixes": None, "events": None, "sample": None, "busy": False}


def _on_audit(event: str, args: tuple[Any, ...]) -> None:
    if _WATCH["prefixes"] is None or _WATCH["busy"] or event not in _PATH_EVENTS or not args:
        return
    try:
        path = os.fsdecode(args[0]) if not isinstance(args[0], int) else None
    except (TypeError, ValueError):
        return
    if path is None or not path.startswith(_WATCH["prefixes"]):
        return
    _WATCH["busy"] = True
    try:
        sample = _WATCH["sample"]
        _WATCH["events"].append((event, path, sample() if sample is not None else None))
    finally:
        _WATCH["busy"] = False


class watch_folder:
    """`with watch_folder(data_root, tenant) as touches:` -> every open or listing of a path under `<data root>/<tenant>`
    while the block runs, as `(event, path, held)`. `held` is `(recorded as this process, lock not free)` as the touch
    happened: what a command's own reads of the tenant's folder saw of its hold (r10 O-A1: none before the state is
    judged; O-A2: held for as long as the command works)."""

    def __init__(self, data_root: Path, tenant: str) -> None:
        folder = Path(data_root) / tenant
        self.prefixes = tuple({str(folder), str(folder.resolve())})
        self.data_root, self.tenant = Path(data_root), tenant
        self.touches: list[tuple[str, str, Any]] = []

    def __enter__(self) -> list[tuple[str, str, Any]]:
        import sys

        if not _WATCH["installed"]:
            sys.addaudithook(_on_audit)
            _WATCH["installed"] = True
        _WATCH.update(prefixes=self.prefixes, events=self.touches, sample=self._sample)
        return self.touches

    def _sample(self) -> tuple[bool, bool]:
        return (recorded(self.data_root, self.tenant) == this_process(),
                not exclusive_free(self.data_root, self.tenant))

    def __exit__(self, *exc: object) -> None:
        _WATCH.update(prefixes=None, events=None, sample=None)
