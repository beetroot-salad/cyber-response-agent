"""#1487 (O8) e2e-only machinery: a real worker over real job containers (the helper's real docker), each running a
test program in place of its kind's entry (`job_host.main(command=)`). NOT RUN WITHOUT A NATIVE DOCKER DAEMON: CI's `test`
job runs it (the job image is built there, `defender-job:latest`).

- `LEARNING`: a learning job's container. It records what it can reach, then sends the job's `outcome` over its socket
  with product code (`job_socket.from_environ`, #1546 PR2: the helper screens and stages it; no end record is left for
  the worker), `completed` with the findings the host planted for it (`obs1487/rows.json`). The real
  entry's own read of the episode's held rows is not run here (it is `tests/learning/branch/test_1487_hand_in.py`'s).
- `POST_STEP`: a post-step container. It records what it can reach, then runs the real `post_step.main` with only its
  tick replaced (no curator is woken: the tick claims and stops): the tick records the store it was handed (it must be the
  job container's port), lists its work and claims through it.
- `REACH`: a post-step container that tries each store request a hostile post-step could make on a batch it was never
  given (another tenant's, another lane's lapsed and working ones, `end_review` on the lapsed lead batch included)
  beside the controls.

Every program leaves one JSON file in its container's tenant folder, `$DEFENDER_DATA_ROOT/<T>/obs1487/<name>.json`, read
here from the host's `<data root>/<T>/obs1487/`. A post-step's container binds the host's tenant folder itself; a
learning container binds only its claim's own root (#1546 A-O9), so the helper's docker (`ObservingDocker`, in
`_real_container_child1487.py`) carries the host's folder into that root before the start and the program's file back
out once the container has exited, before the helper removes the root (A-O1). Container processes are
observed through `/proc` (every process's command line and environment, the connection table); the host judges them
(`database_held`). The database's address is given to each program in a file of its own (`db-target-<name>.json`),
which it reads and deletes at once (a connect needs it): the containers of one flow (the learning job's, then the
post-step's) each find theirs. The scan covers processes and the connection table, not files, and a program that kept
the file would be no evidence, so nothing here counts the file."""
from __future__ import annotations

import json
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CHILD = Path(__file__).resolve().with_name("_real_container_child1487.py")
OBS = "obs1487"
#: The programs, by the name each leaves its observations under (`leave`) and reads its database address for.
PROGRAMS = ("learning", "post-step", "reach")

#: Shared by every program: what the container can reach, as plain data. Python 3.11 (the job image), product code only.
OBSERVE = r'''
import json, os, socket, sys, traceback
from pathlib import Path

def _read(path):
    try:
        return Path(path).read_bytes().replace(b"\0", b"\n").decode("utf-8", "replace")
    except OSError:
        return None

def observe(tenant, name):
    from defender import job_socket
    folder = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant
    seen = {"env": dict(os.environ), "socket_env": job_socket.SOCKET_ENV, "folder": str(folder)}
    seen["procs"] = [{"pid": int(d.name), "cmdline": _read(d / "cmdline"), "environ": _read(d / "environ")}
                     for d in Path("/proc").iterdir() if d.name.isdigit()]
    seen["tcp"] = [_read("/proc/net/tcp"), _read("/proc/net/tcp6")]
    target = folder / "obs1487" / ("db-target-" + name + ".json")
    try:
        found = json.loads(target.read_text(encoding="utf-8"))
        target.unlink()
        seen["target_read"] = True
        try:
            socket.create_connection((found["host"], found["port"]), timeout=5).close()
            seen["connect"] = "connected"
        except OSError as refused:
            seen["connect"] = "<" + type(refused).__name__ + ">"
    except Exception as unread:
        seen["target_read"] = False
        seen["target_error"] = type(unread).__name__
    try:
        import psycopg
        psycopg.connect("", connect_timeout=5).close()
        seen["driver_connect"] = "connected"
    except BaseException as e:
        seen["driver_connect"] = "<" + type(e).__name__ + ">"
    return folder, seen

def leave(folder, name, seen):
    (folder / "obs1487" / (name + ".json")).write_text(json.dumps(seen, default=str), encoding="utf-8")
'''

LEARNING = OBSERVE + r'''
tenant, job = sys.argv[1], sys.argv[2]
folder, seen = observe(tenant, "learning")
try:
    rows = json.loads((folder / "obs1487" / "rows.json").read_text(encoding="utf-8"))
    import os
    from defender import job_socket
    ask = job_socket.from_environ(os.environ)
    ask("outcome", record={"status": "completed", "reason": None,
                           "message": "the judge graded the family: 1 finding(s) wait in the episode",
                           "fork_message_id": None, "stage": None, "sibling_cost_usd": 0.0,
                           "findings": {"state": "ok", "text": json.dumps({"finding": rows, "questioner_finding": []})}})
except BaseException:
    seen["error"] = traceback.format_exc()
leave(folder, "learning", seen)
'''

POST_STEP = OBSERVE + r'''
tenant = sys.argv[1]
folder, seen = observe(tenant, "post-step")
try:
    from defender.learning.branch import post_step
    from defender.learning.branch.container import JobContainer

    def tick(paths, **kwargs):
        # The real post-step's tick seam (Amendment 1): what it is handed is the job container's port. The curator needs
        # no stub: the program claims and stops, so no curator is woken.
        store = kwargs.get("store")
        seen["tick_kwargs"] = sorted(kwargs)
        seen["tick_store"] = type(store).__module__ + "." + type(store).__qualname__
        seen["port"] = (lambda p: type(p).__module__ + "." + type(p).__qualname__)(JobContainer.in_environ().tick_store())
        seen["work_before"] = [[i.kind, i.key, i.status, i.source_run] for i in store.work()]
        held = store.claim()
        seen["claimed"] = None if held is None else {"batch": str(held.batch_id), "lane": held.lane,
                                                     "keys": [[kind, key] for kind, key, _payload in held.items]}
        return 0

    seen["exit"] = post_step.main(["--tenant", tenant], author_tick=tick)
except BaseException:
    seen["error"] = traceback.format_exc()
leave(folder, "post-step", seen)
'''

REACH = OBSERVE + r'''
tenant = sys.argv[1]
folder, seen = observe(tenant, "reach")
try:
    ids = json.loads((folder / "obs1487" / "ids.json").read_text(encoding="utf-8"))
    from defender.learning.branch.container import JobContainer
    from defender.records.learning_causes import Why
    store = JobContainer.in_environ().tick_store()
    seen["own_work"] = [[i.kind, i.key] for i in store.work()]
    seen["listed"] = [str(b.id) for b in store.batches()]
    calls = seen["calls"] = {}

    def attempt(name, request):
        try:
            calls[name] = {"returned": type(request()).__name__}
        except BaseException as refused:
            calls[name] = {"raised": type(refused).__name__}

    ended = dict(expect_phase="working", outcome="closed", published=[], held=[])
    attempt("other_tenant_take_over", lambda: store.take_over(ids["other_working"]))
    attempt("other_tenant_abandon", lambda: store.abandon(ids["other_working"]))
    attempt("other_tenant_end_review", lambda: store.end_review(ids["other_working"], **ended))
    attempt("lead_lapsed_take_over", lambda: store.take_over(ids["lead_lapsed"]))
    attempt("lead_lapsed_abandon", lambda: store.abandon(ids["lead_lapsed"]))
    attempt("lead_lapsed_end_review", lambda: store.end_review(ids["lead_lapsed"], **ended))
    attempt("feedback_working_abandon", lambda: store.abandon(ids["feedback_working"]))
    attempt("feedback_working_park", lambda: store.needs_person(ids["feedback_working"], Why.batch("foreign_pr", "parked from a job container")))
    attempt("feedback_working_end", lambda: store.end_review(ids["feedback_working"], **ended))
    attempt("own_lapsed_take_over", lambda: store.take_over(ids["author_lapsed"]))
except BaseException:
    seen["error"] = traceback.format_exc()
leave(folder, "reach", seen)
'''


def compiled() -> None:
    """The programs are Python 3.11 source; a syntax slip here would read as a container fault in CI."""
    for name, source in (("LEARNING", LEARNING), ("POST_STEP", POST_STEP), ("REACH", REACH)):
        compile(source, name, "exec")


def prepare(root: Path, tenant: str, dsn: str, *, rows: list[dict[str, Any]] | None = None,
            ids: dict[str, str] | None = None) -> Path:
    """The host tenant's `obs1487` folder (written by the container's user: a post-step's container binds the tenant's
    folder, a learning container is handed a copy in its own root, `ObservingDocker`), holding the database address each
    program dials (`db-target-<program>.json`, one per program), the learning job's rows and the
    batch ids a reach program names."""
    folder = root / tenant / OBS
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o777)
    parts = urlsplit(dsn)
    for program in PROGRAMS:  # one each: a program deletes its own once read, so the flow's next container finds its own
        (folder / f"db-target-{program}.json").write_text(json.dumps({"host": parts.hostname, "port": parts.port or 5432}),
                                                          encoding="utf-8")
    if rows is not None:
        (folder / "rows.json").write_text(json.dumps(rows), encoding="utf-8")
    if ids is not None:
        (folder / "ids.json").write_text(json.dumps(ids), encoding="utf-8")
    for name in folder.iterdir():
        name.chmod(0o666)
    return folder


def _container_data_root(argv: list[str]) -> Path | None:
    """The `DEFENDER_DATA_ROOT` a job container's `docker run` hands it (`--env NAME=value`), None for any other command."""
    if argv[:2] != ["docker", "run"]:
        return None
    for flag, value in zip(argv, argv[1:], strict=False):
        if flag == "--env" and value.startswith("DEFENDER_DATA_ROOT="):
            return Path(value.partition("=")[2])
    return None


class _Carried:
    """The started container's process, as the helper holds it: the first time it reads as exited, the program's
    observation is carried from the container's root back to the host's `obs1487` folder, before the helper removes
    that root (A-O1). Everything else is the real process's."""

    def __init__(self, proc: Any, inside: Path, host: Path, name: str) -> None:
        self._proc, self._inside, self._host, self._name, self._carried = proc, inside, host, name, False

    def poll(self) -> int | None:
        rc = self._proc.poll()
        if rc is not None and not self._carried:
            self._carried = True
            left = self._inside / f"{self._name}.json"
            if left.is_file():
                (self._host / left.name).write_bytes(left.read_bytes())
        return rc

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._proc, attr)


class ObservingDocker:
    """The helper's REAL docker (`run_docker`, every command passed through unchanged) with one addition at its edge,
    for a kind whose container is handed its own root, not the tenant's folder (#1546 A-O9: a learning job's container
    binds `.job-roots/<claim>/` and never the host's tenant folder): just before the job container's attached start, the
    host's `obs1487` folder (`prepare`) is copied into `<its root>/<T>/obs1487/` (made fresh, writable by the container's
    user), the program's own database target moved there (the host keeps no copy: the program reads and deletes it, as
    for a tenant-bound kind); once the container has exited, the program's `<name>.json` is carried back to the host's
    folder (`_Carried`), where `observed` reads it. A container whose root is the data root itself (the post-step: it
    binds the tenant's folder) is started as is. The program, the helper and the container see nothing of this."""

    def __init__(self, docker: Any, *, host_root: Path, tenant: str, name: str) -> None:
        self._docker, self._host, self._tenant, self._name = docker, host_root / tenant / OBS, tenant, name

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        return self._docker(argv, **kwargs)

    def popen(self, argv: list[str], **kwargs: Any) -> Any:
        root = _container_data_root(argv)
        if root is None or root.resolve() == self._host.parent.parent.resolve():
            return self._docker.popen(argv, **kwargs)
        inside = root / self._tenant / OBS
        inside.mkdir(parents=True, exist_ok=True)
        inside.chmod(0o777)
        target = f"db-target-{self._name}.json"
        for path in sorted(self._host.iterdir()) if self._host.is_dir() else []:
            if path.is_file() and (path.name == target or not path.name.startswith("db-target-")):
                (inside / path.name).write_bytes(path.read_bytes())
                (inside / path.name).chmod(0o666)
        (self._host / target).unlink(missing_ok=True)
        return _Carried(self._docker.popen(argv, **kwargs), inside, self._host, self._name)


def observed(root: Path, tenant: str, name: str) -> dict[str, Any]:
    """What program `name` left; a program that died before leaving anything is a failure of the harness."""
    path = root / tenant / OBS / f"{name}.json"
    assert path.is_file(), f"the {name} program left no record: its container never ran it"
    seen = json.loads(path.read_text(encoding="utf-8"))
    assert "error" not in seen, f"the {name} program crashed inside its container:\n{seen['error']}"
    return seen


_DATABASE_VARIABLE = re.compile(r"(DSN|DATABASE|^PG[A-Z]*$|POSTGRES)", re.IGNORECASE)


def database_held(seen: dict[str, Any], dsn: str) -> list[str]:  # noqa: C901 — one list of named problems
    """Everything the container held of the database: an address, login or route, named. Empty: nothing. The controls
    (the job socket's variable is set, some process's environment was readable, the target was read and the dial made)
    are part of the answer, so an empty observation is a problem and never a pass."""
    parts = urlsplit(dsn)
    port = parts.port or 5432
    needles = [dsn, "postgresql://", f"{parts.hostname}:{port}"]
    problems: list[str] = []
    if seen["socket_env"] not in seen["env"]:
        problems.append("control: the job socket's variable is not in the container's environment")
    if not any(p["environ"] for p in seen["procs"]):
        problems.append("control: no process's environment was readable, so none could be judged")
    if not seen.get("target_read"):
        problems.append(f"control: the database's address never reached the dial ({seen.get('target_error')})")
    elif seen.get("connect") == "connected":
        problems.append("a connect to the database's own address succeeded")
    if seen.get("driver_connect") == "connected":
        problems.append("the driver connected with no address given (a login by environment or default)")
    for proc in seen["procs"]:
        for field in ("cmdline", "environ"):
            text = proc[field] or ""
            problems += [f"process {proc['pid']} {field} holds {needle!r}" for needle in needles if needle in text]
            names = {line.partition("=")[0] for line in text.splitlines()} if field == "environ" else set()
            problems += [f"process {proc['pid']} has a variable named {n}" for n in sorted(names) if _DATABASE_VARIABLE.search(n)]
    for table in seen["tcp"]:
        for line in (table or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) > 3 and fields[3] == "01" and fields[2].rpartition(":")[2] == f"{port:04X}":
                problems.append(f"an open connection to port {port}: {line.strip()}")
    return problems


def host_can_dial(dsn: str) -> bool:
    """The control for the container's refused dial: the address the programs dial is live from here."""
    parts = urlsplit(dsn)
    try:
        socket.create_connection((parts.hostname, parts.port or 5432), timeout=5).close()
    except OSError:
        return False
    return True


@dataclass
class Seeded:
    """The reach scene's batches, by name, as the host made them with the store's own verbs."""

    ids: dict[str, str]
    own_finding: str


def seed_reach(dsn: str, tenant: str, other: str) -> Seeded:
    """Own tenant: an author batch that lapsed (the control: it may be taken over) and a waiting finding after it; a
    lead batch that lapsed; a feedback registry batch still live. The other tenant: a live author batch. One working
    batch per lane and tenant, so each lane's is one of these."""
    from defender.tests.support.learning.core._set_aside1485 import pitfall
    from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, LEAD_LANE, ONE, call, finding, lapse_lease

    def claimed(who: str, lane: str, *ids: str) -> str:
        for fid in ids:
            call(dsn, "publish_findings", who, f"run-{fid}", [finding(fid)], kind="finding")
        return str(call(dsn, "claim", who, lane, owner="host-a", thresholds=ONE).batch_id)

    author = claimed(tenant, AUTHOR_LANE, "own-a/w/0/0")
    lapse_lease(dsn, author)
    call(dsn, "publish_findings", tenant, "run-own-b", [finding("own-b/w/0/0")], kind="finding")
    call(dsn, "add_pitfall", tenant, pitfall("p-lead"))
    lead = str(call(dsn, "claim", tenant, LEAD_LANE, owner="host-a", thresholds=ONE).batch_id)
    lapse_lease(dsn, lead)
    tick = call(dsn, "begin_feedback_tick", tenant, owner="host-a")
    assert tick is not None, "premise: the feedback lane's tick began"
    feedback = str(call(dsn, "claim_registry", tick).batch_id)
    other_batch = claimed(other, AUTHOR_LANE, "other-a/w/0/0")
    ids = {"author_lapsed": author, "lead_lapsed": lead, "feedback_working": feedback, "other_working": other_batch}
    return Seeded(ids, "own-b/w/0/0")


def real_child(commit: str, kind: str, *, remote: Path):
    """A worker's `learning_argv` or `post_step_argv`: the real helper over the real docker, running `kind`'s program; its
    knowledge fetch reads the tenant's bare `remote` (#1618)."""
    def argv(launch: Any) -> list[str]:
        job = ["--kind", kind, "--job", launch.job_id, "--tenant", launch.tenant_id]
        source = ["--source", launch.source_investigation_id] if kind == "learning" else []
        return [sys.executable, str(CHILD), commit, str(remote), *job, *source, "--parent-pid", str(launch.parent_pid)]
    return argv
