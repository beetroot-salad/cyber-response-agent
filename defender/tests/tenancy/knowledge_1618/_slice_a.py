"""Slice A helpers for #1618: the run-start seam over the production launcher, real caller processes, planted owners, and a
static census scanner. Policy under test (owner records, renames, sweeps) is never implemented here.

The seam list lives in `_support` (one place). Slice-A specifics (the launcher):
- the run launcher stays `defender.investigation.publish_launch.launch_publish` and is handed `dest=` (the caller's owned
  temporary) and `commit=` (a pin) beside today's `data_root=`, `budget=`, `command=`; the `command=` prefix is followed by
  the child's argv `<tenant> --data-root <root> --dest <folder> [--commit <id>]` and nothing else;
- `run.main(..., fetch=)` is the one fetch seam shape `(tenant_id, dest, *, data_root, commit=None) -> report line`; here
  it is the production launcher over the real child (`Fetching`).
"""
from __future__ import annotations

import ast
import functools
import importlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._support import IMPORT_ROOT

LAUNCHER_MODULE = "defender.investigation.publish_launch"
LAUNCHER_NAME = "launch_publish"

def __getattr__(name: str) -> Any:
    """`NAMED_OWNER`: `tenancy._owner`'s own pattern for an `owned_temporary` name (exists today), never a copy of its grammar."""
    if name == "NAMED_OWNER":
        return importlib.import_module("defender.tenancy._owner")._NAMED_OWNER
    raise AttributeError(name)

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def launcher() -> Callable[..., str]:
    """The production launcher of the fetch child (FORCED: module doc)."""
    return getattr(importlib.import_module(LAUNCHER_MODULE), LAUNCHER_NAME)


def child_command(t: Any, tmp_path: Path, *, tag: str = "child") -> list[str]:
    """The `command=` prefix that makes the production launcher spawn the real fetch child over the scene's fakes."""
    folder = tmp_path / f"fetch-{tag}"
    folder.mkdir(parents=True, exist_ok=True)
    wrapper = folder / "wrapper.py"
    wrapper.write_text(K._CHILD_WRAPPER, encoding="utf-8")
    spec = folder / "spec.json"
    spec.write_text(json.dumps({"module": K.CHILD_MODULE, "tenant_id": t.tenant_id, "origin": t.origin,
                                "data_root": str(location_path(t.data_root))}), encoding="utf-8")
    return [sys.executable, str(wrapper), str(spec)]


#: A stand-in child that half-fills `--dest` and is killed by SIGKILL (a child killed mid-fill) before it reports.
KILLED_MID_FILL = '''
import os, signal, sys
from pathlib import Path

argv = sys.argv[1:]
dest = Path(argv[argv.index("--dest") + 1])
(dest / "agent" / "lessons").mkdir(parents=True)
(dest / "agent" / "lessons" / "half.md").write_text("half\\n", encoding="utf-8")
os.kill(os.getpid(), signal.SIGKILL)
'''


def stand_in_command(tmp_path: Path, source: str, *, name: str = "stand-in") -> list[str]:
    """A `command=` prefix that runs `source` (a script reading the child's argv) in place of the fetch child."""
    script = tmp_path / f"{name}.py"
    script.write_text(source, encoding="utf-8")
    return [sys.executable, str(script)]


class Fetching:
    """`run.main`'s `fetch=` over the production launcher (module doc): records what it was handed and each line."""

    def __init__(self, t: Any, command: list[str], *, observe: Callable[[Path], Any] | None = None,
                 after: Callable[[Path, str], Any] | None = None, budget: float = 120.0) -> None:
        self.t, self.command, self.observe, self.after, self.budget = t, command, observe, after, budget
        self.calls: list[dict[str, Any]] = []
        self.lines: list[str] = []

    def __call__(self, tenant_id: Any, dest: Any, *, data_root: Any, commit: str | None = None, **named: Any) -> str:
        assert str(tenant_id) == self.t.tenant_id, (tenant_id, self.t.tenant_id)
        self.calls.append({"dest": Path(dest), "commit": commit, "named": dict(named)})
        if self.observe is not None:
            self.observe(Path(dest))
        line = launcher()(tenant_id, data_root=data_root, dest=dest, commit=commit, budget=self.budget,
                          command=self.command)
        self.lines.append(line)
        if self.after is not None:
            self.after(Path(dest), line)
        return line


def fetching(t: Any, tmp_path: Path, *, command: list[str] | None = None, **hooks: Any) -> Fetching:
    return Fetching(t, command if command is not None else child_command(t, tmp_path), **hooks)


def run_copies(t: Any) -> Path:
    """`<T>/run-knowledge/`."""
    return K.tenant_root(t) / "run-knowledge"


def listing(folder: Path) -> list[str]:
    return sorted(p.name for p in Path(folder).iterdir()) if Path(folder).is_dir() else []


def settings_mark(seen: Any) -> str | None:
    """The revision mark file the run's settings half holds (layout-agnostic: the run tenant's own `settings`)."""
    raw = seen.settings_files.get(K.MARK_FILE.removeprefix("settings/"))
    return None if raw is None else raw.decode()


def lesson_in(seen: Any) -> str | None:
    raw = seen.agent_files.get(K.LESSON.removeprefix("agent/"))
    return None if raw is None else raw.decode()


# --- planted owners ---------------------------------------------------------------------------------------------------

def dead_mark() -> tuple[int, str]:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import _dead_process

    return _dead_process()


def live_child() -> subprocess.Popen:
    """A live process other than this one (a stand-in for another host owner)."""
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])  # noqa: S603


def owner_file(folder: Path, pid: int, start: str) -> None:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import write_owner

    write_owner(folder, pid, start)


def named(prefix: str, pid: int, start: str) -> str:
    """A folder name `owned_temporary(prefix)` would give, but naming the process `pid`/`start` as owner: a real name from the
    helper with the pid and start fields replaced where the helper's own pattern finds them (no grammar spelled here)."""
    from defender.tenancy._owner import _NAMED_OWNER, owned_temporary

    name = owned_temporary(prefix)
    found = _NAMED_OWNER.search(name)
    assert found is not None, name
    return f"{name[:found.start(1)]}{pid}{name[found.end(1):found.start(2)]}{start}{name[found.end(2):]}"


def plant(folder: Path, *, pid: int | None = None, start: str | None = None, by_name: bool = False) -> Path:
    """A non-empty folder (a half-filled copy) at `folder`; with `pid`/`start` an `owner` record names that process
    (`by_name`: the owner is in the folder's own name, which the caller built with `named`, and no record exists)."""
    (folder / "stage" / "agent").mkdir(parents=True)
    (folder / "stage" / "agent" / "half.md").write_text("half\n", encoding="utf-8")
    if pid is not None and not by_name:
        assert start is not None
        owner_file(folder, pid, start)
    return folder


def process_start(pid: int) -> str:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import process_start as start

    return start(pid)


def scan_run_copies(folder: Path) -> tuple[list[str], list[str]]:
    """Watch `folder` (`<T>/run-knowledge/`) from outside: `(owned, unowned)` names of the renamed run copies in it (a name
    `tenancy._owner` does not read as an `owned_temporary` one) that do / do not hold an owner record. A copy that vanishes
    while it is read (swept after its owner died) is neither."""
    from defender.tenancy._owner import _NAMED_OWNER, OWNER_FILE

    owned, unowned = [], []
    for entry in (sorted(Path(folder).iterdir()) if Path(folder).is_dir() else []):
        if _NAMED_OWNER.search(entry.name):
            continue
        if (entry / OWNER_FILE).is_file():
            owned.append(entry.name)
        elif entry.exists():
            unowned.append(entry.name)
    return owned, unowned


def repos_under(root: Path) -> list[str]:
    """Every folder under `root` that is a git repository (a `HEAD` file beside `objects/`), relative to `root`."""
    found = []
    for head in Path(root).rglob("HEAD"):
        if (head.parent / "objects").is_dir():
            found.append(head.parent.relative_to(root).as_posix())
    return sorted(found)


# --- a real run process (the production caller) -----------------------------------------------------------------------

RUN_PROCESS = '''
import importlib, json, sys, time
from pathlib import Path

spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
from defender import run as run_py
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory

directory = tenant_directory(Path(spec["data_root"]), spec["tenant_id"], origin=spec["origin"])
launch = getattr(importlib.import_module(spec["launcher_module"]), spec["launcher_name"])


def fetch(tenant_id, dest, *, data_root, commit=None):
    return launch(tenant_id, data_root=data_root, dest=dest, commit=commit, budget=120.0, command=spec["command"])


def lifecycle(**kw):
    Path(spec["ready"]).write_text(str(kw["run"].run_dir), encoding="utf-8")
    time.sleep(600)


sys.exit(run_py.main([spec["alert"], "--tenant", spec["tenant_id"], "--no-learn"], directory=directory,
                     lifecycle=lifecycle, fetch=fetch,
                     preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None, enqueue=lambda *a, **k: False))
'''


def start_run_process(t: Any, tmp_path: Path, command: list[str]) -> tuple[subprocess.Popen, Path]:
    """`run.main` in a real process whose lifecycle is held; return it and the run folder it reported once reached."""
    import time

    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    spec = tmp_path / "run-process.json"
    ready = tmp_path / "run-ready"
    spec.write_text(json.dumps({
        "data_root": str(location_path(t.data_root)), "tenant_id": t.tenant_id, "origin": t.origin,
        "launcher_module": LAUNCHER_MODULE, "launcher_name": LAUNCHER_NAME, "command": command,
        "ready": str(ready), "alert": str(B.plant_alert(tmp_path / "alert"))}), encoding="utf-8")
    script = tmp_path / "run-process.py"
    script.write_text(RUN_PROCESS, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(IMPORT_ROOT)}
    proc = subprocess.Popen([sys.executable, str(script), str(spec)], cwd=IMPORT_ROOT, env=env,  # noqa: S603
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 120
    while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if not ready.exists():
        proc.kill()
        proc.wait(timeout=30)
        raise AssertionError(f"the run process never reached its lifecycle (rc={proc.returncode}): "
                             f"{proc.stderr.read().decode(errors='replace')[-2000:]}")
    return proc, Path(ready.read_text(encoding="utf-8"))


# --- the static census --------------------------------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[4]


def _excluded_prefixes() -> tuple[str, ...]:
    import importlib.util

    lint = REPO / "tooling" / "lint"
    spec = importlib.util.spec_from_file_location("_shippable_1618", lint / "lint_shippable_surface.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(lint))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(lint))
    return tuple(module.EXCLUDED_PREFIXES)


@functools.cache
def product_python() -> tuple[str, ...]:
    """The tracked product `.py` files: `lint_shippable_surface.EXCLUDED_PREFIXES` and flat `test_*` modules excluded."""
    # lint-raw-git: test-only census listing of the working tree.
    listed = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"], cwd=REPO,
                            check=True, capture_output=True, text=True).stdout.split()
    excluded = _excluded_prefixes()
    return tuple(rel for rel in listed if not rel.startswith(excluded) and not rel.rsplit("/", 1)[-1].startswith("test_")
                 and (REPO / rel).is_file())


def _docstrings(tree: ast.AST) -> set[int]:
    return {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and n.body
            and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}


def uses(name: str, *, literal: str | None = None, under: str = "") -> list[str]:
    """`file:line` of every product use of the identifier `name` (a name, attribute, definition, parameter, import or
    keyword), and of every non-docstring string literal containing `literal`, in the product `.py` files (those whose
    path starts with `under`, when given)."""
    hits = []
    for rel in (p for p in product_python() if p.startswith(under)):
        try:
            tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        docs = _docstrings(tree)
        for node in ast.walk(tree):
            spelled = (getattr(node, "id", None) if isinstance(node, ast.Name) else
                       node.attr if isinstance(node, ast.Attribute) else
                       node.name if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.alias) else
                       node.arg if isinstance(node, ast.arg | ast.keyword) else None)
            named = spelled == name or (name and isinstance(spelled, str) and spelled.endswith(f".{name}"))
            quoted = (literal is not None and isinstance(node, ast.Constant) and isinstance(node.value, str)
                      and id(node) not in docs and literal in node.value)
            if named or quoted:
                hits.append(f"{rel}:{node.lineno}")
    return hits


def _attr_sweep() -> Callable[..., Any]:
    """The sweep function itself (FORCED name, `K.SWEEP_MODULE`), for a call counter."""
    return importlib.import_module(K.SWEEP_MODULE).sweep_dead_owners
