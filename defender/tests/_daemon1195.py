"""A docker daemon faked over one folder, for the #1195 rows. NOT a test module.

Standard library only, so the same code answers two callers over the same state:

- in process, as an injected `docker=` seam (`_box1195.FakeDaemon.__call__` calls `handle`);
- as a `docker` program first on `PATH` (`FakeDaemon.install`), which runs this file as a
  script, so the box code's DEFAULT seam (`runtime.box._docker`, a real subprocess) reaches it
  too: a box `start_box` created with no `docker=` carries that default, and every lifecycle
  call on it (the post-create stop, each run, the batch-end removal) reaches the program.

The folder holds `state.json` (the containers by name, each `{"status", "token"}`, the faults
still to inject, the per-verb call counts, and the host writes a box makes as it starts or
stops) and `calls.jsonl` (every argv, one JSON list per line, plus the marks a test writes
between them). The daemon decides nothing about what an answer means: it keeps container state
the way a daemon does and answers each verb the box code asks.

- `inspect -f <fmt> <name>`: the status or the start-token label, or rc 1 for no such
  container. `inspect <id> --format ...` (the own-mount-table probe) is rc 1: no such object.
- `version`: rc 0, unless the daemon is `down` (then every verb answers rc 1, as an
  unreachable daemon does).
- `image inspect`: rc 0 (the image is held).
- `run --name <n> --label defender.start-token=<t> ...`: creates `<n>` running, or rc 125 when
  the name is taken (docker's own conflict) or a create fault is set.
- `exec [flags] <name> cat <path>`: the host file at `<path>` (the drain's mounts sit at their
  own paths), or other bytes under a `sentinel` fault; `exec ... python3 -c <probe>`: the alias
  probe's healthy verdict, or one shape allowed when `alias_allowed`. A container that is not
  running answers rc 1.
- `start <name>`: `exited` (or `created`) -> `running`. On a container already running it
  answers rc 0 and changes nothing, as docker does (#1195 C3). A paused or dead one is refused.
- `stop [-t N] <name>`: `running` (or `paused`) -> `exited` (or `dead`, under a `dead` fault, or
  whatever status a `leave` fault names); rc 0 and no change on one that is not running.
- `rm -f <name>`: removes it (rc 0 whether or not it existed, as docker 29 does), unless an
  `rm` fault is pending: then rc 1 and the container stays as it was.

Faults on `start` and `stop`, by the call's ordinal (from 1, counted per verb) or `"*"` for
every call: `refuse` (rc 1, nothing changes) or `noop` (rc 0, nothing changes: a verb that
did not take). `inspect -f` calls can be refused the same way (rc 1, as for no such object: a
daemon that flaked on the question). `on_start`/`on_stop` are the box's own writes (or removals) through its mounts: on its
first act once up, or its last act while still up.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

STATE = "state.json"
CALLS = "calls.jsonl"

#: The probe's reply when every banned shape was refused (`runtime.box._alias`).
ALIAS_OK = "alias-probe: all banned shapes denied; ordinary create ok\n"
ALIAS_ALLOWED = "alias-probe: symlink was ALLOWED\n"

#: What a mount answers under a `sentinel` fault: never the token the host planted.
NOT_THE_SENTINEL = "a different tree\n"

#: Flags of `docker exec` that take a value: skipped, with it, to find the container name.
_EXEC_VALUED = frozenset({"-w", "--workdir", "-u", "--user", "-e", "--env"})


def fresh_state() -> dict:
    return {
        "containers": {},
        "faults": {"rm": 0, "alias_allowed": False, "down": False, "create": False,
                   "sentinel": False,
                   "start": {"refuse": [], "noop": []},
                   "stop": {"refuse": [], "noop": [], "dead": [], "leave": {}},
                   "inspect": {"refuse": []}},
        "counts": {"start": 0, "stop": 0, "inspect": 0, "boot": 0},
        "on": {"start": [], "stop": []},
    }


def load(here: Path) -> dict:
    return json.loads((here / STATE).read_text(encoding="utf-8"))


def save(here: Path, state: dict) -> None:
    (here / STATE).write_text(json.dumps(state), encoding="utf-8")


def log(here: Path, entry: list[str]) -> None:
    with open(here / CALLS, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _exec_target(argv: list[str]) -> tuple[str, list[str]]:
    """`docker exec [flags] <name> <command...>` -> `(name, command)`."""
    i = 2
    while i < len(argv) and argv[i].startswith("-"):
        i += 2 if argv[i] in _EXEC_VALUED else 1
    return (argv[i] if i < len(argv) else ""), argv[i + 1:]


def _label(argv: list[str], key: str) -> str | None:
    for i, tok in enumerate(argv[:-1]):
        if tok == "--label":
            k, _, v = argv[i + 1].partition("=")
            if k == key:
                return v
    return None


def _field(box: dict, fmt: str) -> str:
    """What `docker inspect -f <fmt>` prints for a container: its status, its start-token
    label (docker's `<no value>` when it carries none), or an empty map for any other field."""
    if "State.Status" in fmt:
        return f"{box['status']}\n"
    if "Config.Labels" in fmt:
        return f"{box.get('token') or '<no value>'}\n"
    return "map[]\n"


def _due(spec: list, n: int) -> bool:
    return "*" in spec or n in spec


def _box_writes(actions: list[dict], n: int) -> None:
    """The box's own writes through its mounts: each action due at this call (`at`: its
    ordinal, or every call when absent) puts `text` at `path`, or a symlink to `link`, or
    (`remove`) takes away whatever stands at `path`."""
    for action in actions:
        if action.get("at") not in (None, n):
            continue
        path = Path(action["path"])
        if action.get("remove"):
            if os.path.lexists(path):
                path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(path):
            path.unlink()
        if "link" in action:
            path.symlink_to(action["link"])
        else:
            path.write_text(action["text"], encoding="utf-8")


def _run_verb(state: dict, verb: str, name: str) -> tuple[int, str, str]:
    """`start` or `stop` one container, as the faults and its state allow."""
    state["counts"][verb] += 1
    n = state["counts"][verb]
    box = state["containers"].get(name)
    if box is None:
        return 1, "", f"Error response from daemon: No such container: {name}\n"
    faults = state["faults"][verb]
    if _due(faults["refuse"], n):
        return 1, "", f"Error response from daemon: cannot {verb} {name}: refused by the fake\n"
    if _due(faults["noop"], n):
        return 0, f"{name}\n", ""
    if verb == "start":
        if box["status"] in ("paused", "dead"):
            return 1, "", f"Error response from daemon: cannot start a {box['status']} container\n"
        if box["status"] != "running":
            box["status"] = "running"
            state["counts"]["boot"] += 1
            _box_writes(state["on"]["start"], n)
        return 0, f"{name}\n", ""
    if box["status"] in ("running", "paused"):
        _box_writes(state["on"]["stop"], n)
        left = faults.get("leave", {}).get(str(n))
        box["status"] = left or ("dead" if _due(faults.get("dead", []), n) else "exited")
    return 0, f"{name}\n", ""


def _exec(state: dict, argv: list[str]) -> tuple[int, str, str]:
    name, command = _exec_target(argv)
    box = state["containers"].get(name)
    if box is None or box["status"] != "running":
        return 1, "", f"Error response from daemon: container {name} is not running\n"
    if "python3" in command and "-c" in command:
        if state["faults"]["alias_allowed"]:
            return 1, "", ALIAS_ALLOWED
        return 0, ALIAS_OK, ""
    if command[:1] == ["cat"] and len(command) > 1:
        if state["faults"]["sentinel"]:
            return 0, NOT_THE_SENTINEL, ""
        try:
            return 0, Path(command[1]).read_text(encoding="utf-8"), ""
        except OSError:
            return 1, "", f"cat: {command[1]}: No such file or directory\n"
    return 0, "", ""


def _rm(here: Path, state: dict, name: str) -> tuple[int, str, str]:
    faults = state["faults"]
    pending = faults["rm"]
    if pending:
        # Negative: refuse every time; positive: refuse that many more times.
        faults["rm"] = pending - 1 if pending > 0 else pending
        save(here, state)
        return 1, "", ("Error response from daemon: could not kill container "
                       f"{name}: refused by the fake\n")
    state["containers"].pop(name, None)
    save(here, state)
    return 0, f"{name}\n", ""


def _inspect(here: Path, state: dict, argv: list[str]) -> tuple[int, str, str]:
    if "-f" not in argv:
        return 1, "", "Error: No such object\n"
    state["counts"]["inspect"] += 1
    save(here, state)
    box = state["containers"].get(argv[-1])
    if box is None or _due(state["faults"]["inspect"]["refuse"], state["counts"]["inspect"]):
        return 1, "", f"Error: No such object: {argv[-1]}\n"
    return 0, _field(box, argv[argv.index("-f") + 1]), ""


def _create(here: Path, state: dict, argv: list[str]) -> tuple[int, str, str]:
    containers = state["containers"]
    name = argv[argv.index("--name") + 1]
    if state["faults"]["create"]:
        return 125, "", "docker: Error response from daemon: refused by the fake\n"
    if name in containers:
        return 125, "", (f'docker: Error response from daemon: Conflict. The container '
                         f'name "/{name}" is already in use\n')
    containers[name] = {"status": "running", "token": _label(argv, "defender.start-token") or ""}
    save(here, state)
    return 0, "f" * 64 + "\n", ""


def handle(here: Path, argv: list[str]) -> tuple[int, str, str]:  # noqa: PLR0911 — one daemon, one arm per verb
    """Answer one docker argv (`["docker", verb, ...]`): `(rc, stdout, stderr)`."""
    log(here, argv)
    state = load(here)
    verb = argv[1] if len(argv) > 1 else ""
    if state["faults"]["down"]:
        return 1, "", "Cannot connect to the Docker daemon (the fake is down)\n"
    if verb == "version":
        return 0, "29.0.0-fake\n", ""
    if verb == "image":
        return 0, "sha256:fake1195\n", ""
    if verb == "inspect":
        return _inspect(here, state, argv)
    if verb == "run":
        return _create(here, state, argv)
    if verb == "exec":
        return _exec(state, argv)
    if verb in ("start", "stop"):
        answer = _run_verb(state, verb, argv[-1])
        save(here, state)
        return answer
    if verb == "rm":
        return _rm(here, state, argv[-1])
    return 1, "", f"the fake daemon does not answer `docker {verb}`\n"


def main() -> None:
    here = Path(sys.argv[1])
    rc, out, err = handle(here, ["docker", *sys.argv[2:]])
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(rc)


if __name__ == "__main__":
    main()
