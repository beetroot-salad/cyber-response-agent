"""#1214 r10.1: the names the design leaves to the implementer, spelled once (A1, A2, A3, C3, C6, C8). Test support only.

The host acceptance step (A1, C3): `host_tenant(data_root, raw_id, *, directory=None, defender_dir=..., box_mounted=(),
clone_tree=True)` checks eagerly (raising `TenantRefused` at the call) and returns the admitted value, which carries
`.tenant` (the `Tenant`), `.directory` (the `TenantDirectory` it was admitted through) and `.wiring` (the forge
wiring); `with admitted:` releases the hold. It lives above `tenancy` and `migrations`, next to
`systems/run_tenant.entry_directory` (design: "The host acceptance step"); the module and the name are this
contract's choice. Where the implementer spells them otherwise, only this module changes.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import inspect
import os
import sys
import threading
from collections.abc import Callable, Iterator
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
COMMAND_FUNCTIONS = frozenset({"main", "_launch", "job_main"})  # #1342 r6 R6-3: the job entry admits its own tenant

#: The raw folder acceptance's own module (it defines `accept_tenant`). The census derives every wrapper that reaches
#: it by reachability; no list of wrapper names is kept.
RAW_LAYER = "tenancy/_tenant.py"

#: A3: the processes covered by their starter, which load the folder with the folder rules only. Exactly these.
#: (#1366 O11/O1: `skills/connect/validate_scaffold.py` left this set; it is a no-tenant surface judging a handoff.)
A3_SET = frozenset({
    "learning/author/version_control/publish.py",
    "investigation/publish_launch.py",
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
    # retired: "learning/leads/lead_author/__init__.py" — the by-hand lead-author entry is deleted (#1278 A3)
    "presentation/visualize_run.py",
    "cli/workspace_map.py",
    "presentation/visualize_episode.py",
    "learning/frontend/serialize.py",
    "cli/learning/trace_lesson.py",
    "cli/retire_legacy_runs.py",
    # #1170 (H7, P-C, A6): the per-job host helper admits each job's tenant; the post-step (#1344) runs in its job
    # container under the helper's hold and opens no acceptance of its own.
    "job_host/_investigation.py",
    "job_host/_learning.py",
)

#: #1170 (H7, P-C): the per-job host helper's host half, which enters the acceptance on the hold its run owns until the
#: job ends (its return closes nothing): the command scope of the helper's modules, beside `COMMAND_FUNCTIONS`.
HELPER_HOST_HALVES: dict[str, frozenset[str]] = {
    "job_host/_investigation.py": frozenset({"prepare"}),
    "job_host/_learning.py": frozenset({"_admit_tenant"}),
}

#: #1170 (P-C, "In-box entries", C19): the entries that run inside a job container, covered by the helper's hold as the
#: publish child (A3) is by its starter's: each takes its tenant by the folder rules only (no host lock, no admission).
#: Unit by unit, `(module, function)`, since their modules also hold host-side commands; a unit here may reach the raw
#: acceptance and does not pass the reach on to its callers.
IN_BOX_ENTRIES = frozenset({
    ("run.py", "_container_tenant"),             # the investigation job's entry (`run.py --job`)
    ("run.py", "_sibling_set_up"),               # learning's `run.py --episode` sibling
    ("learning/branch/cli.py", "_admitted"),     # the learning job's launch, its in-container branch
    ("learning/branch/post_step.py", "main"),    # the post-step
})


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
    # retired: "lead_author_opener" — the by-hand lead-author entry (`lead_author.main`) is deleted (#1278 A3)
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


def _lock_inode(data_root: Path, tenant: str) -> str | None:
    """The `/proc/locks` spelling (`major:minor:inode`) of `tenant`'s lock file, or None when the file does not exist."""
    from defender.tenancy import host_lock

    try:
        st = os.stat(host_lock.lock_dir(data_root, tenant) / "lock")
    except FileNotFoundError:
        return None
    return f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"


#: The kinds of lock `/proc/locks` lists: `flock(2)` locks, POSIX record locks and open-file-description locks.
_LOCK_KINDS = frozenset({"FLOCK", "POSIX", "OFDLCK"})


def lock_held(data_root: Path, tenant: str) -> bool:
    """True when any process holds `tenant`'s host lock, read from the kernel's lock table. Nothing is locked or created, so
    the answer does not depend on which open file a lock belongs to (a sample taken inside a hold cannot disturb it)."""
    inode = _lock_inode(data_root, tenant)
    if inode is None:
        return False
    with open("/proc/locks", encoding="utf-8") as table:
        return any(len(parts) > 5 and parts[1] in _LOCK_KINDS and parts[5] == inode for parts in map(str.split, table))


def exclusive_free(data_root: Path, tenant: str) -> bool:
    """True when nothing holds `tenant`'s host lock."""
    return not lock_held(data_root, tenant)


def host_tenant(*args: Any, **kwargs: Any) -> Any:
    """The real host acceptance step, imported at call time (a missing target is a red at the case, not at
    collection)."""
    return getattr(importlib.import_module(HOST_MODULE), HOST_ACCEPTANCE)(*args, **kwargs)


# --- the tenant's folder, observed at the operating system's boundary (O-A1 order, O-A2) -----------------------------

#: The audit events that touch a path: reads, listings and every change of a name or mode. An audit hook cannot be
#: removed, so one hook serves every test and a case turns it on for the length of a `with watch_folder(...)` block.
_PATH_EVENTS = frozenset({
    "open", "os.listdir", "os.scandir", "os.mkdir", "os.rename", "os.remove", "os.rmdir", "os.chmod", "os.chown",
    "os.utime", "os.truncate", "os.symlink", "os.link", "shutil.rmtree",
})
#: The events whose first two arguments are both paths (a rename or a link names a source and a target).
_TWO_PATHS = frozenset({"os.rename", "os.symlink", "os.link"})
_WATCH: dict[str, Any] = {"installed": False, "folders": None, "events": None, "sample": None, "busy": False,
                          "errors": None}


def _spelling(arg: object) -> str | None:
    """`arg` as a path string, or None when it is not one (a descriptor, None, an object with no path)."""
    if isinstance(arg, int) or arg is None:
        return None
    try:
        return os.fsdecode(arg)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None


def _is_under(path: str, folders: tuple[str, ...]) -> bool:
    """Exact match: the folder itself or a path below it (`folder + os.sep`), so a sibling that shares the prefix is no touch."""
    return any(path == folder or path.startswith(folder + os.sep) for folder in folders)


def _on_audit(event: str, args: tuple[Any, ...]) -> None:
    if _WATCH["folders"] is None or _WATCH["busy"] or event not in _PATH_EVENTS:
        return
    _WATCH["busy"] = True
    try:
        paths = [_spelling(a) for a in args[:2 if event in _TWO_PATHS else 1]]
        for path in paths:
            if path is None:
                continue
            # A relative path is a touch of unknown place (a descriptor-relative open names only its leaf), so it counts
            # as one wherever it happens; an absolute path counts when it lies in the tenant's folder.
            if os.path.isabs(path) and not _is_under(path, _WATCH["folders"]):
                continue
            sample = _WATCH["sample"]
            _WATCH["events"].append((event, path, sample() if sample is not None else None))
            break
    except Exception as failed:  # noqa: BLE001 — an audit hook must not raise into the code it watches: the block's exit reports it
        _WATCH["errors"].append(f"{event}: {type(failed).__name__}: {failed}")
    finally:
        _WATCH["busy"] = False


class watch_folder:
    """`with watch_folder(data_root, tenant) as touches:` -> every touch of the tenant's folder while the block runs, as
    `(event, path, held)`: an open or listing, a make, rename, removal, mode or time change, of a path in `<data root>/
    <tenant>` (exact match on the folder or `folder + os.sep`) or of any RELATIVE path (a descriptor-relative open names only
    its leaf, so it cannot be told from a read of the folder). `held` is `(recorded as this process, lock held)` as the
    touch happened, sampled without taking the lock: what a command's own reads saw of its hold (r10 O-A1: none before the
    state is judged; O-A2: held for as long as the command works). A fault inside the hook is reported when the block ends.

    What it cannot see: a `stat` (no audit event), so the behavioural matrix of `test_entry_boundaries` is the other
    observation of the order."""

    def __init__(self, data_root: Path, tenant: str) -> None:
        folder = Path(data_root) / tenant
        self.folders = tuple({str(folder), str(folder.resolve())})
        self.data_root, self.tenant = Path(data_root), tenant
        self.touches: list[tuple[str, str, Any]] = []
        self.errors: list[str] = []

    def __enter__(self) -> list[tuple[str, str, Any]]:
        import sys

        if not _WATCH["installed"]:
            sys.addaudithook(_on_audit)
            _WATCH["installed"] = True
        _WATCH.update(folders=self.folders, events=self.touches, sample=self._sample, errors=self.errors)
        return self.touches

    def _sample(self) -> tuple[bool, bool]:
        return (recorded(self.data_root, self.tenant) == this_process(), lock_held(self.data_root, self.tenant))

    def __exit__(self, *exc: object) -> None:
        _WATCH.update(folders=None, events=None, sample=None, errors=None)
        if self.errors and not any(exc):
            raise AssertionError(f"the folder watch faulted: {self.errors[:3]}")


# --- code objects watched, not names (the acceptance and the Tenant it builds) -------------------------------------------

class Calls:
    """How many times each watched function was called inside a `counting_calls` block, by the label given, and the arguments
    of each call by name (`locals[label][n]`: the values themselves, so a test can ask whether a callee was handed the very
    object another call built), and whether each ran on a thread with a running event loop (`on_loop[label][n]`)."""

    def __init__(self, labels: list[str]) -> None:
        self.counts = dict.fromkeys(labels, 0)
        self.locals: dict[str, list[dict[str, Any]]] = {label: [] for label in labels}
        self.on_loop: dict[str, list[bool]] = {label: [] for label in labels}

    def __getitem__(self, label: str) -> int:
        return self.counts[label]


@contextlib.contextmanager
def counting_calls(**functions: Callable[..., Any]) -> Iterator[Calls]:
    """Count the calls of each function by its code object (`sys.setprofile`, and `threading.setprofile` for threads started
    inside the block; a decorated function is watched by the code it wraps), whatever name or route reaches it: a runtime-built name, a `getattr`, an alias or a wrapper still
    runs that code. Nothing is replaced. The previous profile hooks (the process's and the one new threads get) come back at exit."""
    labels = {inspect.unwrap(fn).__code__: label for label, fn in functions.items()}
    calls = Calls(list(functions))
    active = True

    def hook(frame: Any, event: str, _arg: object) -> None:
        if active and event == "call" and frame.f_code in labels:
            label = labels[frame.f_code]
            calls.counts[label] += 1
            calls.locals[label].append(dict(frame.f_locals))
            calls.on_loop[label].append(asyncio.events._get_running_loop() is not None)

    previous, previous_threads = sys.getprofile(), threading.getprofile()
    threading.setprofile(hook)
    sys.setprofile(hook)
    try:
        yield calls
    finally:
        active = False
        sys.setprofile(previous)
        threading.setprofile(previous_threads)


def acceptance_calls(**more: Callable[..., Any]) -> contextlib.AbstractContextManager[Calls]:
    """`counting_calls` over the raw folder acceptance (`accepted`), the construction of a `Tenant` (`built`: the only
    constructor runs `__post_init__`; `locals["built"][n]["self"]` is the tenant it built) and the admission read of the
    records (`admission`), plus any `more` the case watches."""
    from defender.tenancy import TenantDirectory
    from defender.tenancy import _tenant

    return counting_calls(accepted=_tenant.accept_tenant, built=_tenant.Tenant.__post_init__,
                          admission=TenantDirectory.admission, **more)
