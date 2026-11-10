"""#1170 (r4): machinery for driving the per-job host helper, `defender.job_host`, over a published, registered tenant.

Other slices import: `helper_scene(tmp_path, monkeypatch, dsn, *, proxied, files, alert_mapping)`/`HelperScene`,
`ContainerStandIn`/`Container`, `drive_helper`/`HelperRan`, `ForgeCredentialRecorder`, `SignalingSigner`, `ProcessHelper`,
`helper_child`/`NO_PROXY_FILES` (a worker `child_argv` that runs the helper in front of the replay entry), the shared test pieces
`make_signer` (the marked signer), `claims_of` (a pass token's claims), `after_the_signal`, `listing`, the fixtures
`process_state` (autouse where imported) and `scene` (the default `helper_scene`), and the pure parsers `parse_mounts`,
`parse_env`, `parse_labels`, `flag_values`, `host_path`, `until`. Picked names of the not-yet-built target (sketch choices, not settled
by the design): `job_host.main(argv, *, docker, signer, publish, forge, command)`, the client `job_host.ask(socket, request,
**fields) -> dict` raising `job_host.Refused`, the in-container variable `job_host.SOCKET_ENV` naming the job socket, the label
`job_host.JOB_LABEL` carried by every job container, and the settings `job_host.IMAGE_ENV` (the image). Requests name an id as `id=`.

Docker double. The helper starts its job container as an attached `docker run` asked of the docker seam's `.popen`, and makes
every other docker call through the seam. `ContainerStandIn` runs the job as a function on a thread (`job(container) -> rc`)
that sees the container's environment and mounts and talks to the socket through `Container.request`/`refused`; `docker stop`,
`kill` and `rm -f` of the container set `Container.stopping`. `docker inspect -f {{.State.Pid}}` of the job container answers
this process's pid (`init=True`: the pid of a real init process, whose descendants alone are the container's processes, for the
peer check; `Container.client` runs code in the container, `Container.foreign` outside it). `ProcessHelper` is the helper as a
real process over a `docker` executable on PATH (a real SIGKILL, a real EOF on stdin)."""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, TITLE, register_tenant
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING

HELPER_MODULE = "defender.job_host"
OTHER_TENANT = str(uuid.UUID(int=0x1170))
CANARY = "OTHER-TENANT-CANARY-1170"
#: The fixture's systems other than `identity` lose their `http-proxy` declaration, so the grant is known.
_UNDECLARED = ("ticket", "host-state", "threat-intel", "change-mgmt", "elastic", "cmdb")


#: `helper_scene`'s `files=` for a tenant none of whose systems is `http-proxy`: an empty grant, so nothing is signed.
NO_PROXY_FILES: dict[str, Any] = {f"settings/systems/{s}/access.yaml": None for s in (*_UNDECLARED, "identity")}

_HELPER_CHILD = Path(__file__).resolve().with_name("_helper_child1170.py")


def helper_child(mode: str, commit: str, marks: Path, launch: Any, *, stderr_to: Path | None = None) -> list[str]:
    """A worker's `child_argv` answer for an investigation: the real helper in front of the replay job entry
    (`_helper_child1170.py`; `mode`, `commit` and `marks` are `_job_entry1342.py`'s), in place of `python -m
    defender.job_host` (which would need a real vault, publish and docker). `stderr_to`: the child's stderr appended to it."""
    child = [sys.executable, str(_HELPER_CHILD), mode, commit, str(marks), "--job", launch.investigation_id,
             "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]
    return ["/bin/sh", "-c", 'exec "$@" 2>>"$0"', str(stderr_to), *child] if stderr_to is not None else child


def until(predicate: Callable[[], Any], what: str, timeout: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = predicate()
        if got:
            return got
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def flag_values(argv: list[str], *flags: str) -> list[str]:
    return [argv[i + 1] for i, tok in enumerate(argv[:-1]) if tok in flags]


def parse_mounts(argv: list[str]) -> list[dict[str, Any]]:
    """Every `--mount` on a `docker run` argv as {source, target, readonly} (`RecordingDocker.mounts`' shape)."""
    out = []
    for spec in flag_values(argv, "--mount"):
        parts = dict(p.split("=", 1) for p in spec.split(",") if "=" in p)
        out.append({"source": parts.get("source", parts.get("src", "")),
                    "target": parts.get("target", parts.get("dst", parts.get("destination", ""))),
                    "readonly": "readonly" in spec.split(",") or "ro" in spec.split(",")})
    return out


def parse_env(argv: list[str]) -> dict[str, str | None]:
    """`--env`/`-e` pairs; a bare key (inherited from the docker CLI's own environment) maps to None."""
    out: dict[str, str | None] = {}
    for item in flag_values(argv, "--env", "-e"):
        k, eq, v = item.partition("=")
        out[k] = v if eq else None
    return out


def parse_labels(argv: list[str]) -> dict[str, str]:
    return dict(item.partition("=")[::2] for item in flag_values(argv, "--label", "-l"))


#: A client program: asks `launch` of the socket in argv[1] and prints the outcome as one JSON object.
ASK_LAUNCH = textwrap.dedent("""
    import json, sys
    from pathlib import Path
    from defender import job_host
    try:
        print(json.dumps({"ok": job_host.ask(Path(sys.argv[1]), "launch")}))
    except job_host.Refused as refused:
        print(json.dumps({"refused": str(refused)}))
    except Exception as fault:
        print(json.dumps({"error": type(fault).__name__}))
""")

#: The init process of a container with `init=True`: runs each command file dropped in its folder, in turn.
_INIT = textwrap.dedent("""
    import json, pathlib, subprocess, sys, time
    queue = pathlib.Path(sys.argv[1])
    while True:
        for cmd in sorted(queue.glob("*.cmd")):
            run = cmd.with_suffix(".run")
            cmd.rename(run)
            with open(cmd.with_suffix(".out"), "w") as out:
                subprocess.run(json.loads(run.read_text()), stdout=out, stderr=subprocess.STDOUT)
            run.rename(cmd.with_suffix(".done"))
        time.sleep(0.02)
""")


def descendants(pid: int) -> set[int]:
    """`pid` and everything below it, from /proc."""
    found, todo = set(), [pid]
    while todo:
        cur = todo.pop()
        if cur in found:
            continue
        found.add(cur)
        for children in Path(f"/proc/{cur}/task").glob("*/children"):
            with contextlib.suppress(OSError):
                todo += [int(c) for c in children.read_text().split()]
    return found


def host_path(mounts: list[dict[str, Any]], inside: str) -> Path:
    """Where an in-container path lives on the host, through the bind table (nested mounts win)."""
    p = Path(inside)
    covering = [m for m in mounts if m["target"] and p.is_relative_to(m["target"])]
    assert covering, f"no mount of the job container covers {inside}"
    m = max(covering, key=lambda m: len(Path(m["target"]).parts))
    return Path(m["source"]) / p.relative_to(m["target"])


@dataclass
class Container:
    """The job container as its contents would see it: its environment, its mounts, and the job socket."""

    argv: list[str]
    name: str
    env: dict[str, str | None]
    mounts: list[dict[str, Any]]
    labels: dict[str, str]
    stopping: threading.Event = field(default_factory=threading.Event)
    queue: Path | None = None  # the init process' command folder (`init=True` only)

    def client(self, code: str, *args: str, timeout: float = 20.0) -> str:
        """`python -c code args` run by the container's own init process: a process inside the container."""
        assert self.queue is not None, "client() needs ContainerStandIn(init=True)"
        n = len(list(self.queue.iterdir()))
        cmd = self.queue / f"{n:04d}.cmd"
        cmd.write_text(json.dumps([sys.executable, "-c", code, *args]), encoding="utf-8")
        until(lambda: cmd.with_suffix(".done").exists(), "the container's init to run the client", timeout)
        return cmd.with_suffix(".out").read_text(encoding="utf-8")

    @staticmethod
    def foreign(code: str, *args: str, timeout: float = 20.0) -> str:
        """`python -c code args` run by the test, outside the container: the same uid, not the container's process."""
        done = subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, timeout=timeout,
                              check=False)
        return done.stdout + done.stderr

    def socket(self) -> Path:
        from defender import job_host

        inside = self.env.get(job_host.SOCKET_ENV)
        assert inside, f"the job container was handed no {job_host.SOCKET_ENV}"
        return host_path(self.mounts, inside)

    def request(self, name: str, **fields: Any) -> dict[str, Any]:
        from defender import job_host

        return job_host.ask(self.socket(), name, **fields)

    def refused(self, name: str, **fields: Any) -> Any:
        """The typed refusal `name` gets, or AssertionError when it is answered."""
        from defender import job_host

        try:
            answer = job_host.ask(self.socket(), name, **fields)
        except job_host.Refused as refusal:
            return refusal
        raise AssertionError(f"{name} was answered, not refused: {answer!r}")


class _ContainerProc:
    """The attached `docker run` as the helper holds it: it ends when the job function returns."""

    def __init__(self, thread: threading.Thread | None, box: Container | None, rc: int | None = None,
                 stderr: bytes = b"") -> None:
        self._thread, self._box, self.returncode = thread, box, rc
        self.stdin = self.stdout = None
        self.stderr = None
        self.err = stderr
        self.args = box.argv if box is not None else []

    def poll(self) -> int | None:
        if self.returncode is None and self._thread is not None and not self._thread.is_alive():
            self.returncode = getattr(self._thread, "rc", 99)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(self.args, timeout or 0)
            time.sleep(0.02)  # a short sleep, so a signal handler on this thread runs
        return int(self.returncode)  # type: ignore[arg-type]

    def communicate(self, input: Any = None, timeout: float | None = None) -> tuple[bytes, bytes]:  # noqa: A002
        self.wait(timeout)
        return b"", self.err

    def send_signal(self, _sig: int) -> None:
        if self._box is not None:
            self._box.stopping.set()

    terminate = kill = lambda self: self.send_signal(15)  # noqa: E731


class ContainerStandIn(RecordingDocker):
    """`RecordingDocker` (box starts keep its healthy-daemon model) whose attached `docker run` is the job
    container: `job(container) -> rc` runs on a thread. `docker stop`/`kill` of it set `container.stopping`;
    `ps -aq --filter label=K=V` and `rm -f` answer from the containers it has seen created. `run_fault`
    (rc, stderr) makes the `docker run` end at once, nothing run (an image missing: docker's rc 125).
    `exec_writer`, when set, is the host command a `docker exec` runs instead (a real writer)."""

    def __init__(self, job: Callable[[Container], int] | None = None, *,
                 run_fault: tuple[int, str] | None = None, exec_writer: list[str] | None = None,
                 init: bool = False, queue: Path | None = None) -> None:
        super().__init__()
        self.job = job
        self.init = init
        self._queue = queue  # where an `init=True` container's init finds its commands
        self.init_proc: subprocess.Popen | None = None
        self.run_fault = run_fault
        self.exec_writer = exec_writer
        self.boxes: list[Container] = []  # every job container `docker run` asked for
        self.job_error: BaseException | None = None
        self.job_ran = False
        self.live: dict[str, dict[str, str]] = {}  # container name -> labels, until removed
        self.log: list[list[str]] = []  # every call, `popen` ones included, in order

    @property
    def box(self) -> Container:
        assert len(self.boxes) == 1, f"expected one job container, got {len(self.boxes)}"
        return self.boxes[0]

    def creates(self) -> list[list[str]]:
        """Every box start the helper made (`docker create`/`run` through the call seam)."""
        return [c for c in self.calls if len(c) > 1 and c[1] in ("create", "run")]

    def popen(self, argv, **kw):  # noqa: ANN001 — Popen's own signature
        argv = list(argv)
        self.log.append(argv)
        if len(argv) > 1 and argv[1] == "run":
            return self._run(argv)
        if len(argv) > 1 and argv[1] == "exec" and self.exec_writer is not None:
            self.calls.append(argv)
            return subprocess.Popen(self.exec_writer, **kw)
        return super().popen(argv, **kw)

    def _run(self, argv: list[str]) -> _ContainerProc:
        name = (flag_values(argv, "--name") or [f"job-{len(self.boxes)}"])[0]
        box = Container(argv, name, parse_env(argv), parse_mounts(argv), parse_labels(argv))
        self.boxes.append(box)
        if self.run_fault is not None:
            return _ContainerProc(None, box, rc=self.run_fault[0], stderr=self.run_fault[1].encode())
        self.live[name] = box.labels
        if self.init:
            assert self._queue is not None, "init=True needs a queue folder"
            self._queue.mkdir(parents=True, exist_ok=True)
            box.queue = self._queue
            self.init_proc = subprocess.Popen([sys.executable, "-c", _INIT, str(self._queue)])

        def body() -> None:
            self.job_ran = True
            try:
                thread.rc = int(self.job(box)) if self.job is not None else 0  # type: ignore[attr-defined]
            except BaseException as e:  # noqa: BLE001 — kept for the case to show
                self.job_error = e
                thread.rc = 99  # type: ignore[attr-defined]
            finally:
                if self.init_proc is not None:
                    self.init_proc.kill()

        thread = threading.Thread(target=body, daemon=True, name=f"container-{name}")
        thread.start()
        return _ContainerProc(thread, box)

    def __call__(self, argv, **kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        self.log.append(argv)
        sub = argv[1] if len(argv) > 1 else ""
        pids = self._process_question(argv, sub)
        if pids is not None:
            return pids
        if sub in ("stop", "kill", "ps"):
            self.calls.append(argv)
            return self._stop(argv) if sub != "ps" else self._ps(argv)
        got = super().__call__(argv, **kw)
        if sub in ("create", "run") and got.returncode == 0:
            self.live[(flag_values(argv, "--name") or [f"box-{len(self.live)}"])[0]] = parse_labels(argv)
        if sub == "rm":
            for n in argv[2:]:
                self.live.pop(n, None)
                for box in self.boxes:
                    if box.name == n:
                        box.stopping.set()  # `rm -f` kills a running container, as docker does
        return got

    def _stop(self, argv: list[str]) -> subprocess.CompletedProcess:
        for box in self.boxes:
            if box.name in argv:
                box.stopping.set()
        return subprocess.CompletedProcess(argv, 0, "", "")

    def _ps(self, argv: list[str]) -> subprocess.CompletedProcess:
        wanted = [f.partition("=")[2] for f in flag_values(argv, "--filter") if f.startswith("label=")]
        names = [n for n, labels in self.live.items()
                 if all(labels.get(w.partition("=")[0]) == w.partition("=")[2] if "=" in w else w in labels
                        for w in wanted)]
        return subprocess.CompletedProcess(argv, 0, "".join(f"{n}\n" for n in names), "")

    def _process_question(self, argv: list[str], sub: str) -> subprocess.CompletedProcess | None:
        """The container's processes, asked as `inspect -f {{.State.Pid}}` (its init) or `top` (all of them)."""
        if not any(b.name in argv for b in self.boxes):
            return None
        init = self.init_proc.pid if self.init_proc is not None else os.getpid()
        if sub == "inspect" and any("State.Pid" in a for a in argv):
            out = f"{init}\n"
        elif sub == "top":
            out = "PID\n" + "".join(f"{p}\n" for p in sorted(descendants(init) if self.init_proc else {init}))
        else:
            return None
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, out, "")

    def left(self, label: str, value: str) -> list[str]:
        return [n for n, labels in self.live.items() if labels.get(label) == value]


@dataclass
class HelperScene:
    root: Path
    t: Any
    runs: Path
    dsn: str
    claim: str
    secrets: tuple[Path, ...] = ()

    @property
    def tenant(self) -> str:
        return self.t.tenant_id

    def plant(self, inv: str) -> None:
        """The worker's two files for an investigation (launch record and alert), as the worker writes them."""
        doc = {"investigation_id": inv, "tenant_id": self.tenant, "alert_id": str(uuid.uuid4()),
               "digest": hashlib.sha256(ALERT_BYTES).hexdigest(), "label": TITLE, "box_token": uuid.uuid4().hex}
        (self.runs / f"{inv}.launch.json").write_text(json.dumps(doc), encoding="utf-8")
        (self.runs / f"{inv}.alert.json").write_bytes(ALERT_BYTES)

    def end(self, inv: str) -> Any:
        """The job-end record `<runs>/<inv>.job-end.json` as `JobEnd`, or None when there is none."""
        from defender.records.job_lane import JobEnd

        path = self.runs / f"{inv}.job-end.json"
        if not path.exists():
            return None
        parsed = JobEnd.parse(path.read_text(encoding="utf-8"))
        assert parsed is not None, f"not a job-end record: {path.read_text(encoding='utf-8')!r}"
        return parsed

    def unmap(self) -> None:
        """The tenant's alert mapping taken away (a premise for the alert-mapping refusal)."""
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.dsn, "DELETE FROM tenancy.alert_mappings WHERE tenant_id = %s", (self.tenant,))

    def argv(self, kind: str, job: str | None, *, source: str | None = None, parent: int | None = None) -> list[str]:
        """The helper's command line (a sketch choice): the job's kind, its id, its tenant, the worker's pid."""
        out = ["--kind", kind]
        if job is not None:
            out += ["--job", job]
        out += ["--tenant", self.tenant]
        if source is not None:
            out += ["--source", source]
        return [*out, "--parent-pid", str(os.getppid() if parent is None else parent)]


@contextlib.contextmanager
def helper_scene(tmp_path: Path, monkeypatch: Any, dsn: str, *, proxied: tuple[str, ...] = ("identity",),
                 files: dict[str, Any] | None = None, alert_mapping: Any = FIXTURE_ALERT_MAPPING
                 ) -> Iterator[HelperScene]:
    """The fixture tenant published with `proxied` (default `identity`) its only `http-proxy` systems (none: an empty
    grant) and `files` written over it (a `None` value deletes the file), registered active in `dsn` with `alert_mapping`
    saved (`None`: none, for a test of absence) and a live generation whose sign login and forge secret files exist under
    `tmp_path/secrets`, the worker's claim in the environment, and a second tenant's folder beside it holding a canary."""
    from defender.box import CLAIM_ENV
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.support.tenancy._active1214 import insert_generation
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    # A short data root: the job socket lives under it and a unix socket's path holds about 100 bytes, which pytest's
    # nested temporary folders overrun.
    root = Path(tempfile.mkdtemp(prefix="j", dir="/tmp"))
    claim = uuid.uuid4().hex
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)  # the helper holds the database login (N7)
    monkeypatch.setenv(CLAIM_ENV, claim)  # the worker hands each child its claim (`_worker._spawn`)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    over: dict[str, Any] = {f"settings/systems/{s}/access.yaml": None
                            for s in (*_UNDECLARED, "identity") if s not in proxied}
    over.update(files or {})
    with contextlib.ExitStack() as cleanup:
        cleanup.callback(shutil.rmtree, root, ignore_errors=True)
        t = cleanup.enter_context(B.run_tenant(tmp_path, root, files=over))
        register_tenant(dsn, t.tenant_id, data_root=root, generations=(), alert_mapping=alert_mapping)
        fields = A.generation(t.tenant_id, tmp_path / "secrets", sign_role_id="role-1170-sign",
                              sign_secret="secret-1170-sign")
        insert_generation(dsn, t.tenant_id, fields)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        other = root / OTHER_TENANT
        (other / "runs").mkdir(parents=True)
        (other / "canary").write_text(CANARY, encoding="utf-8")
        yield HelperScene(root, t, root / t.tenant_id / "runs", dsn, claim,
                          secrets=(Path(fields["host_secret_file"]), Path(fields["sign_secret_file"])))


# --- pieces every helper test file shares --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def process_state():
    """The helper ties itself to its parent and takes SIGTERM on the test's thread, so give both back afterwards. Until it
    installs its own handler, a SIGTERM is recorded here rather than ending the test process. Autouse in a module that
    imports it."""
    libc = ctypes.CDLL(None, use_errno=True)
    prior_signal = ctypes.c_int(0)
    libc.prctl(2, ctypes.byref(prior_signal))  # PR_GET_PDEATHSIG
    prior = signal.signal(signal.SIGTERM, lambda *_: None)
    yield
    libc.prctl(1, prior_signal.value)  # PR_SET_PDEATHSIG
    signal.signal(signal.SIGTERM, prior)


@pytest.fixture
def scene(tmp_path, monkeypatch, migrated_database):
    """The default `helper_scene`: the fixture tenant with `identity` proxied."""
    with helper_scene(tmp_path, monkeypatch, migrated_database) as s:
        yield s


def make_signer() -> Any:
    """A fresh signer whose tokens carry a recognisable mark and whose signed payloads it keeps (`claims_of` reads them)."""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    return A.MarkedSigner()


def claims_of(signer: Any, token: str) -> dict:
    """The claims the `signer` signed into `token` (a pass the helper handed a job)."""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    (n,) = [i for i in range(1, len(signer.payloads) + 1) if token.endswith(f"{A.SIGNATURE_CANARY}-{i}")
            or f"{A.SIGNATURE_CANARY}-{i}." in token or f".{A.SIGNATURE_CANARY}-{i}" in token]
    return A.claims_of_payload(signer.payloads[n - 1])


def listing(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def after_the_signal(scene: HelperScene, kind: str, request: str, fields: dict) -> dict:
    """A `kind` helper whose job asks `request` (answered: the control), signals its helper, waits for the container to be
    stopped, asks again. Returns the answers and the state (passes signed, boxes created, copies, drafts) either side."""
    job_id = str(uuid.uuid4())
    if kind == "investigation":
        scene.plant(job_id)
    source = str(uuid.uuid4()) if kind == "learning" else None
    argv = scene.argv(kind, None if kind == "post-step" else job_id, source=source)
    signer, got = make_signer(), {}
    tenant_folder = scene.root / scene.tenant

    def state():
        return (len(signer.payloads), len(docker.creates()), listing(tenant_folder / "run-knowledge"),
                listing(tenant_folder / "drafts"))

    def job(c) -> int:
        asked = {k: (job_id if v == "<job>" else v) for k, v in fields.items()}
        got["control"] = c.request(request, **asked)
        got["before"] = state()
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        got["refusal"] = c.refused(request, **asked)
        got["after"] = state()
        return 143

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=signer, forge=ForgeCredentialRecorder())
    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    return got


@dataclass
class HelperRan:
    rc: int | None = None
    raised: BaseException | None = None
    publishes: int = 0


def drive_helper(scene: HelperScene, argv: list[str], *, docker: ContainerStandIn, signer: Any,
                 **seams: Any) -> HelperRan:
    """`job_host.main` on this thread (it takes SIGTERM here), its launch-time publish answered `fresh` at the
    published commit (as `test_job_entry.run_job` answers the job's today)."""
    from defender import job_host
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    ran = HelperRan()

    def publish(*_a: Any, **_k: Any) -> str:
        ran.publishes += 1
        return B.fresh(scene.t.commit)

    seams.setdefault("publish", publish)
    try:
        ran.rc = job_host.main(argv, docker=docker, signer=signer, **seams)
    except SystemExit as e:
        ran.rc = e.code if isinstance(e.code, int) else 1
    except BaseException as e:  # noqa: BLE001 — kept for the case to name
        ran.raised = e
    return ran


class ForgeCredentialRecorder:
    """The helper's forge seam (`forge(tenant_id, purpose)`): records who it was built for and every
    `token(min_validity)` asked; answers a token naming its tenant."""

    def __init__(self) -> None:
        self.built: list[str] = []
        self.asked: list[float] = []

    def __call__(self, tenant_id: str, *_a: Any, **_k: Any) -> Any:
        self.built.append(tenant_id)
        recorder = self

        class _Credential:
            def token(self, min_validity: float = 0) -> str:
                recorder.asked.append(min_validity)
                return f"forge-token-{tenant_id}-{len(recorder.asked)}"
        return _Credential()


class SignalingSigner:
    """A signer that sends this process SIGTERM when first asked to sign, then signs: the helper signalled after it has
    begun and before its container starts (the signal lands inside the helper's first pass)."""

    def __init__(self, inner: Any) -> None:
        self.inner, self.sent = inner, False

    @property
    def payloads(self) -> list[bytes]:
        return self.inner.payloads

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def sign(self, payload: bytes) -> str:
        if not self.sent:
            self.sent = True
            os.kill(os.getpid(), signal.SIGTERM)
        return self.inner.sign(payload)


_SHIM = textwrap.dedent("""\
    #!PYTHON
    import json, os, signal, sys, time
    from pathlib import Path
    state = Path("STATE")
    argv = sys.argv[1:]
    with open(state / "calls.log", "a") as log:
        log.write(json.dumps(argv) + "\\n")
    sub = argv[0] if argv else ""

    def flag(*names):
        return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a in names]

    def alive(pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    records = state / "containers"
    records.mkdir(exist_ok=True)
    if sub == "run":
        name = (flag("--name") or ["job"])[0]
        labels = dict(item.partition("=")[::2] for item in flag("--label", "-l"))
        (records / name).write_text(json.dumps({"labels": labels, "pid": os.getpid(), "argv": argv}))
        def terminated(*_):
            (state / "terminated").write_text("1")
            os._exit(143)
        signal.signal(signal.SIGTERM, terminated)
        (state / "started").write_text(str(os.getpid()))
        while os.read(0, 4096):
            pass
        (state / "eof").write_text(str(time.time()))
        sys.exit(0)
    if sub == "ps":
        wanted = [f.partition("=")[2] for f in flag("--filter") if f.startswith("label=")]
        for rec in sorted(records.iterdir()):
            labels = json.loads(rec.read_text())["labels"]
            if all(labels.get(w.partition("=")[0]) == w.partition("=")[2] for w in wanted):
                print(rec.name)
        sys.exit(0)
    if sub in ("rm", "stop", "kill"):
        for name in [a for a in argv[1:] if not a.startswith("-") and not a.isdigit()]:
            rec = records / name
            if rec.exists():
                pid = json.loads(rec.read_text())["pid"]
                if alive(pid):
                    os.kill(pid, signal.SIGTERM)
                if sub == "rm":
                    rec.unlink()
        sys.exit(0)
    if sub in ("inspect", "wait"):
        sys.exit(1)
    sys.exit(0)
""")

_DRIVER = textwrap.dedent("""\
    import json, sys
    from defender import job_host
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
    cfg = json.loads(sys.argv[1])
    sys.exit(job_host.main(cfg["argv"], signer=A.MarkedSigner(), publish=lambda *a, **k: B.fresh(cfg["commit"])))
""")


class ProcessHelper:
    """`job_host.main` as a real process (`python -c driver`, its signer and publish answered as `drive_helper`'s) over a
    `docker` executable first on PATH, whose `run` is a stand-in container: it records itself (labels, argv) under
    `state/containers/<name>`, reads its stdin until EOF and then writes `state/eof` and exits; `ps --filter label=`, `rm`,
    `stop` and `kill` act on those records. `state/started` holds the stand-in container's pid once it runs."""

    def __init__(self, scene: HelperScene, root: Path, argv: list[str]) -> None:
        self.state = root / "shim-state"
        bin_dir = root / "shim-bin"
        self.state.mkdir(parents=True)
        bin_dir.mkdir()
        shim = bin_dir / "docker"
        shim.write_text(_SHIM.replace("PYTHON", sys.executable).replace("STATE", str(self.state)), encoding="utf-8")
        shim.chmod(0o755)
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
        self.proc = subprocess.Popen([sys.executable, "-c", _DRIVER, json.dumps({"argv": argv, "commit": scene.t.commit})],
                                     env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def container_pid(self, timeout: float = 30.0) -> int:
        return int(until(lambda: (self.state / "started").exists() and (self.state / "started").read_text(),
                         "the stand-in container to start", timeout))

    def records(self) -> dict[str, dict[str, Any]]:
        return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in (self.state / "containers").glob("*")}

    def calls(self) -> list[list[str]]:
        log = self.state / "calls.log"
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []

    def close(self) -> None:
        for pid in [self.proc.pid, *(r["pid"] for r in self.records().values())]:
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)
        self.proc.wait(timeout=10)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                stream.close()


def pid_alive(pid: int) -> bool:
    """Whether `pid` is a live (not zombie) process."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return False
    return stat[stat.rindex(")") + 2] != "Z"
