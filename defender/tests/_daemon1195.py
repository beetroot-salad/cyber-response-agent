"""A docker daemon faked over one folder, for the #1195 box-per-run rows. NOT a test module.

Standard library only, so the same code answers two callers over the same state:

- in process, as an injected `docker=` seam (`_box1195.FakeDaemon.__call__` calls `handle`);
- as a `docker` program first on `PATH` (`FakeDaemon.install`), which runs this file as a
  script, so the box code's DEFAULT seam (`runtime.box._docker`, a real subprocess) reaches it
  too. The drain builds its `BoxSource` with that default, so a batch-end teardown asks this
  daemon what the per-run starts and stops told it.

The folder holds `state.json` (the containers by name, each `{"status", "token"}`, and the
faults still to inject) and `calls.jsonl` (every argv, one JSON list per line, plus the marks a
test writes between them). The daemon decides nothing about what an answer means: it keeps
container state the way a daemon does and answers each verb the box code asks.

- `inspect -f <fmt> <name>`: the status or the start-token label, or rc 1 for no such
  container. `inspect <id> --format ...` (the own-mount-table probe) is rc 1: no such object.
- `version`: rc 0, unless the daemon is `down` (then every verb answers rc 1, as an
  unreachable daemon does).
- `image inspect`: rc 0 (the image is held).
- `run --name <n> --label defender.start-token=<t> ...`: creates `<n>` running, or rc 125 when
  the name is taken (docker's own conflict).
- `exec [flags] <name> cat <path>`: the host file at `<path>` (the drain's mounts sit at their
  own paths); `exec ... python3 -c <probe>`: the alias probe's healthy verdict, or one shape
  allowed when `alias_allowed`. A container that is not running answers rc 1.
- `rm -f <name>`: removes it (rc 0 whether or not it existed, as docker 29 does), unless an
  `rm` fault is pending: then rc 1 and the container stays as it was.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STATE = "state.json"
CALLS = "calls.jsonl"

#: The probe's reply when every banned shape was refused (`runtime.box._alias`).
ALIAS_OK = "alias-probe: all banned shapes denied; ordinary create ok\n"
ALIAS_ALLOWED = "alias-probe: symlink was ALLOWED\n"

#: Flags of `docker exec` that take a value: skipped, with it, to find the container name.
_EXEC_VALUED = frozenset({"-w", "--workdir", "-u", "--user", "-e", "--env"})


def fresh_state() -> dict:
    return {
        "containers": {},
        "faults": {"rm": 0, "alias_allowed": False, "down": False, "create": False},
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


def handle(here: Path, argv: list[str]) -> tuple[int, str, str]:  # noqa: C901, PLR0911, PLR0912 — one daemon, one arm per verb
    """Answer one docker argv (`["docker", verb, ...]`): `(rc, stdout, stderr)`."""
    log(here, argv)
    state = load(here)
    faults = state["faults"]
    containers = state["containers"]
    verb = argv[1] if len(argv) > 1 else ""
    if faults["down"]:
        return 1, "", "Cannot connect to the Docker daemon (the fake is down)\n"
    if verb == "version":
        return 0, "29.0.0-fake\n", ""
    if verb == "image":
        return 0, "sha256:fake1195\n", ""
    if verb == "inspect":
        if "-f" not in argv:
            return 1, "", "Error: No such object\n"
        box = containers.get(argv[-1])
        if box is None:
            return 1, "", f"Error: No such object: {argv[-1]}\n"
        return 0, _field(box, argv[argv.index("-f") + 1]), ""
    if verb == "run":
        name = argv[argv.index("--name") + 1]
        if faults["create"]:
            return 125, "", "docker: Error response from daemon: refused by the fake\n"
        if name in containers:
            return 125, "", (f'docker: Error response from daemon: Conflict. The container '
                             f'name "/{name}" is already in use\n')
        containers[name] = {"status": "running",
                            "token": _label(argv, "defender.start-token") or ""}
        save(here, state)
        return 0, "f" * 64 + "\n", ""
    if verb == "exec":
        name, command = _exec_target(argv)
        box = containers.get(name)
        if box is None or box["status"] != "running":
            return 1, "", f"Error response from daemon: container {name} is not running\n"
        if "python3" in command and "-c" in command:
            if faults["alias_allowed"]:
                return 1, "", ALIAS_ALLOWED
            return 0, ALIAS_OK, ""
        if command[:1] == ["cat"] and len(command) > 1:
            try:
                return 0, Path(command[1]).read_text(encoding="utf-8"), ""
            except OSError:
                return 1, "", f"cat: {command[1]}: No such file or directory\n"
        return 0, "", ""
    if verb == "rm":
        name = argv[-1]
        pending = faults["rm"]
        if pending:
            # Negative: refuse every time; positive: refuse that many more times.
            faults["rm"] = pending - 1 if pending > 0 else pending
            save(here, state)
            return 1, "", ("Error response from daemon: could not kill container "
                           f"{name}: refused by the fake\n")
        containers.pop(name, None)
        save(here, state)
        return 0, f"{name}\n", ""
    return 1, "", f"the fake daemon does not answer `docker {verb}`\n"


def main() -> None:
    here = Path(sys.argv[1])
    rc, out, err = handle(here, ["docker", *sys.argv[2:]])
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(rc)


if __name__ == "__main__":
    main()
