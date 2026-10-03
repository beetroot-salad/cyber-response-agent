"""The drain's verbs and the child-process open watch for `test_1134_drain_trees.py`. It defines
no tests.

At import it needs only the standard library and `_tree_listing_1134` (itself stdlib-only), so
a child interpreter installs its audit hook BEFORE any `defender` module is imported, and the
pytest worker never installs one (`sys.addaudithook` cannot be removed; #1134 step 1's rule).

* `do_verb(held, name, verb, below=)`: one verb on the pair `DrainTrees.tree_for` hands back,
  spelled the way the drain will spell it. Writes and deletes go through the `Held`, reads
  through its view, as #1133 shipped them: `read(name)`; `entries`, the listing of the folder
  holding `name` (`view().under(<its folder>).entries()`, `view().entries()` at the top), where
  the entry at `name` is that listing's row; and `listing`, the folder `name` (`view()` itself
  for the mount, `name == "."`) and each folder `below` it in the tree's known shape, each by
  its own `under(...).entries()`.
* `child()`: a child interpreter's entry point. It reads one JSON request on stdin, a list of
  scenarios, and writes one JSON answer on stdout. Each scenario opens `DrainTrees` over its
  mounts, then, with the watch armed, maps its path with `tree_for`, asks `mount` and `tree_for`
  of every mount point again (as the drain does mid-batch), and runs its verb. The watch
  records every open BY NAME with its flags (the spelling as the caller gave it) and, for every
  open or listing BY DESCRIPTOR (`fdopen`, `scandir`), what that descriptor names. A spawned
  process is recorded too. Non-vacuity: before the call, the watch must see an `O_PATH` open of
  the scenario's plant by its absolute spelling.
* `watch_in_child(scenarios, deadline=)`: run `child` over this tree's `defender` and answer its
  rows.
"""
from __future__ import annotations

import contextlib
import dataclasses
import importlib
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from defender.tests._tree_listing_1134 import fd_path

#: What every write control lands: a NUL, CRLF and bytes that are not UTF-8, so no text path
#: can reproduce them. A byte-exact control reads the file itself (the test's own read, by
#: path); a read through a view reads it with `errors="replace"` (`PAYLOAD_TEXT`).
PAYLOAD = b"\xff\xfe\x00raw drain bytes\r\n"
#: What `Bound.read(name, errors="replace")` answers for a file holding `PAYLOAD`: each
#: undecodable byte one U+FFFD, the CRLF read as one newline.
PAYLOAD_TEXT = "\ufffd\ufffd\x00raw drain bytes\n"

#: The verbs on a file the drain makes through a held mount: the two write modes it uses, the
#: delete, the view's read of a name, and the listing of the folder that holds it (`entries`).
FILE_VERBS = ("replace", "create", "unlink", "read", "entries")

#: The audit events a spawned process raises. No verb has cause for one.
_SPAWNS = frozenset({"subprocess.Popen", "os.system", "os.posix_spawn", "os.exec", "os.spawn",
                     "os.fork", "os.forkpty"})


def do_verb(held: Any, name: str, verb: str, *, below: tuple[str, ...] = ()) -> Any:
    """`verb` on `(held, name)`: `replace` / `create` write `PAYLOAD` in that mode, `mkdir` and
    `unlink` are the `Held`'s, `read` its view's, `entries` lists the folder holding `name` off
    its view, and `listing` answers `{folder: EntriesRead}` for the folder `name` (`""`) and
    each folder in `below`, named relative to it."""
    if verb in ("replace", "create"):
        return held.write(name, PAYLOAD, mode=verb)
    if verb == "mkdir":
        return held.mkdir(name)
    if verb == "unlink":
        return held.unlink(name)
    view = held.view()
    if verb == "listing":
        top = view if name == "." else view.under(name)
        return {folder: (top.under(folder) if folder else top).entries()
                for folder in ("", *below)}
    if verb == "read":
        return view.read(name)
    if verb == "entries":
        folder = name.rpartition("/")[0]
        return (view.under(folder) if folder else view).entries()
    raise AssertionError(verb)


class _OpenWatch:
    """While armed: each open by name as `[spelling, flags]` (`flags` None where the event
    carries none: a spawn, recorded as `<event>`), and the target of each open or listing by
    descriptor."""

    def __init__(self) -> None:
        self.armed = False
        self._busy = False
        self.by_name: list[list[Any]] = []
        self.by_fd: list[str | None] = []

    def hook(self, event: str, args: tuple[Any, ...]) -> None:
        if not self.armed or self._busy:
            return
        self._busy = True
        try:
            with contextlib.suppress(Exception):  # an audit hook must never break the call
                self._note(event, args)
        finally:
            self._busy = False

    def _note(self, event: str, args: tuple[Any, ...]) -> None:
        if event in _SPAWNS:
            self.by_name.append([f"<{event}>", None])
            return
        if event not in ("open", "os.scandir", "os.listdir") or not args:
            return
        what = args[0]
        if isinstance(what, int) and not isinstance(what, bool):
            self.by_fd.append(fd_path(what))
        elif isinstance(what, (str, bytes, os.PathLike)):
            flags = args[2] if event == "open" and len(args) > 2 else None
            self.by_name.append([os.fsdecode(what), flags if isinstance(flags, int) else None])

    @contextlib.contextmanager
    def watching(self) -> Iterator[dict[str, list[Any]]]:
        seen: dict[str, list[Any]] = {"by_name": [], "by_fd": []}
        self.by_name, self.by_fd = seen["by_name"], seen["by_fd"]
        self.armed = True
        try:
            yield seen
        finally:
            self.armed = False


def _as_json(value: Any) -> Any:
    """A verb's answer as JSON: a record as its fields (a listing's entries as `[name, kind]`
    pairs, sorted: `entries()` keeps the directory's own order), a mapping of records as a
    mapping of their fields, anything else as itself."""
    if isinstance(value, dict):
        return {key: _as_json(record) for key, record in value.items()}
    if not dataclasses.is_dataclass(value) or isinstance(value, type):
        return value
    fields = dataclasses.asdict(value)
    if isinstance(fields.get("entries"), dict):
        fields["entries"] = sorted(list(row) for row in fields["entries"].items())
    return fields


def _run_scenario(scenario: dict[str, Any], watch: _OpenWatch, lane_trees: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        with watch.watching() as control:
            os.close(os.open(scenario["control"], os.O_PATH | os.O_NOFOLLOW))
        out["control"] = control
        mounts = tuple(Path(m) for m in scenario["mounts"])
        with lane_trees.DrainTrees.open(mounts) as trees, watch.watching() as seen:
            try:
                held, name = trees.tree_for(scenario["path"])
                # The drain asks for its mounts again mid-batch (`mount`, and `tree_for` of a
                # mount point): each answer is the held root, and nothing is opened by path.
                out["remapped"] = [trees.mount(m) is trees.tree_for(m)[0] for m in mounts]
                out["result"] = _as_json(do_verb(held, name, scenario["verb"],
                                                 below=tuple(scenario.get("below", ()))))
            except Exception as e:  # noqa: BLE001 — reported in the row, for the test to judge
                out["raised"] = [type(e).__name__, getattr(e, "errno", None)]
        out.update(seen)
    except Exception as e:  # noqa: BLE001 — the scenario's own failure, reported in its row
        out["failed"] = f"{type(e).__name__}: {e}"
    return out


def child() -> None:
    """The child's entry point: the hook first, then `lane_trees` (and `_io` with it), so no
    module is loaded while the watch is armed, then each scenario."""
    request = json.loads(sys.stdin.read())
    watch = _OpenWatch()
    sys.addaudithook(watch.hook)  # before ANY `defender` module is imported
    try:
        lane_trees = importlib.import_module("defender.learning.core.lane_trees")
        answer: dict[str, Any] = {
            "rows": {s["id"]: _run_scenario(s, watch, lane_trees) for s in request["scenarios"]}}
    except Exception as e:  # noqa: BLE001 — the parent reports it
        answer = {"child_failed": f"{type(e).__name__}: {e}"}
    sys.stdout.write(json.dumps(answer))


def watch_in_child(scenarios: list[dict[str, Any]], *, deadline: float) -> dict[str, Any]:
    """`child` over `scenarios` in a fresh interpreter whose `defender` is the one beside this
    file (its own tree first on `PYTHONPATH`), bounded by `deadline` seconds."""
    tree = Path(__file__).resolve().parents[2]
    inherited = os.environ.get("PYTHONPATH")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=os.pathsep.join([str(tree), *([inherited] if inherited else [])]))
    entry = "from defender.tests._drain_trees_1134 import child; child()"
    try:
        done = subprocess.run([sys.executable, "-c", entry], input=json.dumps(
            {"scenarios": scenarios}), capture_output=True, text=True, env=env, cwd=tree,
            timeout=deadline, check=False)
    except subprocess.TimeoutExpired as e:
        raise AssertionError(f"the watching child ran past its {deadline}s deadline") from e
    if done.returncode:
        raise AssertionError(f"the watching child exited {done.returncode}: {done.stderr[-4000:]}")
    answer = json.loads(done.stdout)
    if "child_failed" in answer:
        raise AssertionError(f"the watching child failed: {answer['child_failed']}")
    return answer["rows"]
