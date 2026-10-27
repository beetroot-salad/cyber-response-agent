"""#540 — the box isolation boundary against a real Docker daemon: host paths absent, defender_dir read-only, no network, env allowlist, tmpfs noexec, boundary holds for commands the gate denies and under both runc and runsc."""
from __future__ import annotations

import contextlib
import dataclasses
import errno as errno_mod
import json
import os
import shutil
import socket
import subprocess
import threading
import uuid
from pathlib import Path

import pytest
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood

pytest.importorskip("pydantic_ai")

from defender.box import run_env  # noqa: E402
from defender import providers  # noqa: E402
from defender.investigation.agent_definition import compile_policy_for  # noqa: E402
from defender.execution.bash_exec import parse  # noqa: E402
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.investigation.permission.bash import decide_bash  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER  # noqa: E402

from defender import box as box_mod  # noqa: E402
from defender.box import (  # noqa: E402
    BOX_ENV_ALLOWLIST,
    BoxResult,
    BoxSpec,
    start_box,
    stop_box,
)

pytestmark = pytest.mark.e2e

EXEC_TIMEOUT = 60.0


_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
# What `_box` will actually ask for: `start_box` resolves the F1 lever when no spec is passed.
_LEVERED_RUNTIME = BoxSpec.from_env(os.environ).runtime


_DOOD_ANCHOR = dood_anchor() if _DOOD else None
_RUNTIME_ABSENT = (not _NO_DAEMON) and _LEVERED_RUNTIME not in docker_runtimes()

requires_box = pytest.mark.skipif(
    _NO_DAEMON or (_DOOD and _DOOD_ANCHOR is None) or _RUNTIME_ABSENT,
    reason=(
        "no reachable Docker daemon" if _NO_DAEMON else
        f"the {_LEVERED_RUNTIME!r} runtime is not registered with this daemon (`docker info` "
        "Runtimes), so no box here can start at all" if _RUNTIME_ABSENT else
        "docker-outside-of-Docker AND no path this container shares with the daemon covers "
        "the repo tree, so no bind source can be resolved (C46) and a bind assertion here "
        "would be asserting against a filesystem it cannot see. Run on a native daemon."
    ),
)


@pytest.fixture
def runs_base(tmp_path: Path):
    """The runs base every run dir in this file hangs off."""
    if _DOOD_ANCHOR is None:
        yield tmp_path / "defender-runs"
        return
    base = _DOOD_ANCHOR / uuid.uuid4().hex / "defender-runs"
    base.mkdir(parents=True)
    try:
        yield base
    finally:
        shutil.rmtree(base.parent, ignore_errors=True)


@pytest.fixture
def run_dir(runs_base: Path) -> Path:
    """A real run dir under a real runs base, with a real sibling run beside it
    (the sibling is what `test_another_runs_run_dir_is_absent` and the `..`
    escape test try to reach — a live neighbour, not an imagined one)."""
    d = runs_base / "20260718T101500Z-boxspec"
    (d / "gather_raw").mkdir(parents=True)
    from defender.tests.support.storage._alert_plant import plant_alert
    plant_alert(d, {"id": "boxspec"})
    return d


@pytest.fixture
def sibling_run(run_dir: Path) -> Path:
    """A SECOND real run dir beside the first, carrying a real secret-shaped
    artifact. O6's write set is 'exactly one directory' — this is the other one."""
    other = run_dir.parent / "20260718T101501Z-otherrun"
    (other / "gather_raw").mkdir(parents=True)
    (other / "gather_raw" / "l-001.lead.json").write_text(
        "SIBLING-RUN-SECRET-42", encoding="utf-8")
    return other


@contextlib.contextmanager
def _box(run_dir: Path, *, spec: BoxSpec | None = None):
    box = start_box(run_dir, DEFENDER) if spec is None else start_box(
        run_dir, DEFENDER, spec=spec)
    try:
        yield box
    finally:
        stop_box(box)


@pytest.fixture
def box(run_dir: Path):
    with _box(run_dir) as b:
        yield b


def _run(box, command: str, *, cwd: Path) -> BoxResult:
    """Drive the REAL entry point: the real `bash_exec.parse` decomposition —
    the same object the gate validates — handed to the box executor (M8)."""
    return box.run_parsed(parse(command), command=command, cwd=cwd, timeout=EXEC_TIMEOUT)


def _write_probe(run_dir: Path, name: str, source: str) -> Path:
    """Plant a probe script on the rw bind and return its model-visible path.

    The bytes are written HERE, by the
    test, through the real filesystem — the fault (or the capability) is real."""
    script = run_dir / f"_probe_{name}.py"
    script.write_text(source, encoding="utf-8")
    return Path("/runs/current") / script.name


def _probe(box, run_dir: Path, name: str, source: str, *args: str) -> dict:
    """Run a probe in the box and decode its one JSON line. The probe CATCHES its
    own OSError and reports `type(e).__name__` + `e.errno`, so the assertion is on
    the errno and the exact class — never on an exception subclass (C56)."""
    script = _write_probe(run_dir, name, source)
    argv = " ".join([f"python3 {script}", *args])
    res = _run(box, argv, cwd=Path("/runs/current"))
    assert res.rc == 0, f"probe {name} did not complete: rc={res.rc} err={res.err!r}"
    return json.loads(res.out.decode("utf-8"))


_TCP_CONNECT = '''
import json, socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect((host, port))
    s.sendall(b"ping")
    echo = s.recv(16).decode()
    print(json.dumps({"connected": True, "echo": echo, "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"connected": False, "echo": None,
                      "exc": type(e).__name__, "errno": e.errno}))
'''

_TCP6_CONNECT = '''
import json, socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    print(json.dumps({"connected": True, "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"connected": False, "exc": type(e).__name__, "errno": e.errno}))
'''

_UDP_SENDTO = '''
import json, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    n = s.sendto(b"udp-escape-payload", (sys.argv[1], int(sys.argv[2])))
    print(json.dumps({"sent": n, "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"sent": None, "exc": type(e).__name__, "errno": e.errno}))
'''

_DNS = '''
import json, socket, sys
try:
    infos = socket.getaddrinfo(sys.argv[1], 80)
    print(json.dumps({"resolved": [i[4][0] for i in infos], "exc": None, "errno": None}))
except socket.gaierror as e:
    # e.errno here is an EAI_* value; it is NOT looked up in errno.errorcode by
    # anyone (C56d: -2 and -3 are absent from that table).
    print(json.dumps({"resolved": None, "exc": type(e).__name__, "errno": e.errno}))
except OSError as e:
    print(json.dumps({"resolved": None, "exc": type(e).__name__, "errno": e.errno}))
'''

_LOOPBACK = '''
import json, socket, subprocess, sys

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
srv.settimeout(15)
port = srv.getsockname()[1]

client_src = (
    "import socket,sys\\n"
    "c=socket.create_connection(('127.0.0.1',int(sys.argv[1])),5)\\n"
    "c.sendall(b'loopback-ok')\\n"
)
child = subprocess.Popen([sys.executable, "-c", client_src, str(port)])
try:
    conn, _ = srv.accept()
    payload = conn.recv(32).decode()
    print(json.dumps({"payload": payload, "child_rc": child.wait(10), "exc": None}))
except OSError as e:
    child.kill()
    print(json.dumps({"payload": None, "child_rc": None, "exc": type(e).__name__}))
'''

_READ_PATH = '''
import json, sys
p = sys.argv[1]
try:
    data = open(p, "rb").read()
    print(json.dumps({"read": data.decode("utf-8", "replace"), "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"read": None, "exc": type(e).__name__, "errno": e.errno}))
'''

_WRITE_PATH = '''
import json, sys
try:
    with open(sys.argv[1], "wb") as fh:
        fh.write(b"box-was-here")
    print(json.dumps({"wrote": True, "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"wrote": False, "exc": type(e).__name__, "errno": e.errno}))
'''

_ENV_DUMP = '''
import json, os
print(json.dumps(dict(os.environ)))
'''

_IMPORT_DEFENDER = '''
import json
import defender.hooks._cmd_segments as seg
import defender.execution.bash_exec as be
print(json.dumps({"seg": seg.__file__, "bash_exec": be.__file__}))
'''

_SOCKET_SWEEP = '''
import json, os, stat
found = []
skip = {"/proc", "/sys", "/dev"}
for root, dirs, files in os.walk("/", followlinks=False, onerror=lambda e: None):
    dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip]
    for name in (*dirs, *files):
        p = os.path.join(root, name)
        try:
            if stat.S_ISSOCK(os.lstat(p).st_mode):
                found.append(p)
        except OSError:
            pass
print(json.dumps({"sockets": found}))
'''

_WHICH = '''
import json, shutil, sys
print(json.dumps({p: shutil.which(p) for p in sys.argv[1:]}))
'''

_FILL_TMPFS = '''
import json
chunk = b"x" * (1024 * 1024)
written = 0
try:
    with open("/tmp/fill.bin", "wb") as fh:
        for _ in range(64):
            fh.write(chunk)
            fh.flush()
            written += len(chunk)
    print(json.dumps({"written": written, "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"written": written, "exc": type(e).__name__, "errno": e.errno}))
'''


def _host_ipv4() -> str:
    """This host's routable address, discovered without sending a packet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    finally:
        s.close()


@contextlib.contextmanager
def _echo_listener():
    """A REAL TCP destination, on this host, echoing what it receives. The
    negatives and the positive control aim at THIS address — same address,
    complementary condition."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 0))
    srv.listen(4)
    srv.settimeout(20)
    accepted: list[bytes] = []

    def serve():
        with contextlib.suppress(OSError):
            conn, _ = srv.accept()
            with conn:
                data = conn.recv(64)
                accepted.append(data)
                conn.sendall(data)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield _host_ipv4(), srv.getsockname()[1], accepted
    finally:
        srv.close()
        t.join(timeout=5)


@requires_box
def test_host_path_outside_the_binds_is_absent(box, run_dir, tmp_path):
    outside = tmp_path / "outside" / "host-only-secret.txt"
    outside.parent.mkdir()
    outside.write_text("HOST-ONLY-SECRET-99", encoding="utf-8")

    res = _probe(box, run_dir, "outside", _READ_PATH, str(outside))

    assert res["read"] is None, f"the box read a host path outside the binds: {res}"
    assert res["errno"] == errno_mod.ENOENT, (
        f"expected ABSENT (ENOENT), got errno={res['errno']} ({res['exc']}) — a DENIED "
        "path means something mounted it and a matcher refused, which is not the boundary"
    )
    assert "HOST-ONLY-SECRET-99" not in _run(
        box, f"cat {outside}", cwd=Path("/runs/current")).out.decode("utf-8", "replace")


@pytest.mark.skipif(not _DOOD, reason="not docker-outside-of-Docker — there is no "
                                      "namespace split here, so the translation is the "
                                      "identity and this asserts nothing")
@requires_box
def test_the_bind_source_is_translated_for_the_daemons_namespace(box, run_dir):
    mounts = box_mod._shared_mounts(box_mod._docker)
    argv = box_mod._create_argv(box.name, run_dir, DEFENDER, box.spec, mounts, lane=box_mod._run_lane_mounts(run_dir, DEFENDER, None)).argv
    binds = [
        dict(part.split("=", 1) for part in spec.split(",") if "=" in part)
        for spec in argv if spec.startswith("type=bind,")
    ]
    by_target = {b["target"]: b["source"] for b in binds}
    for target, host in ((Path("/runs/current"), run_dir), (Path("/defender"), DEFENDER)):
        assert str(target) in by_target, f"{target} is not bound at all: {by_target}"
        assert by_target[str(target)] != str(host), (
            f"the bind source for {target} was not translated: {by_target} — under DooD an "
            "untranslated source names nothing on the daemon and is silently created as an "
            "EMPTY dir (C46)"
        )

    host_bytes = b"C46-ROUND-TRIP-\xe2\x9c\x93\n"
    (run_dir / "c46.txt").write_bytes(host_bytes)
    got = _probe(box, run_dir, "c46", _READ_PATH, "/runs/current/c46.txt")
    assert got["read"] == host_bytes.decode("utf-8"), (
        f"the translated bind did not map the host tree: {got}")


@requires_box
def test_run_dir_and_defender_dir_are_readable_in_box(box, run_dir):
    """Both binds ARE readable from inside the box: bytes the host wrote into `run_dir` and a
    real file under `defender_dir` both read back byte-exact."""
    host_bytes = b"RUN-DIR-SENTINEL-\xe2\x9c\x93\n"
    (run_dir / "sentinel.txt").write_bytes(host_bytes)
    skill = DEFENDER / "SKILL.md"

    got_run = _probe(box, run_dir, "readrun", _READ_PATH, "/runs/current/sentinel.txt")
    got_defender = _probe(box, run_dir, "readdef", _READ_PATH, "/defender/SKILL.md")

    assert got_run["read"] == host_bytes.decode("utf-8")
    assert got_defender["read"] == skill.read_text(encoding="utf-8")


@requires_box
def test_write_under_defender_dir_fails_erofs_by_errno(box, run_dir):
    """A write to any path under `defender_dir` fails EROFS: the ro bind is the enforcement, so a
    hijacked agent cannot poison its own corpus, skills, or lessons."""
    # #1108 P4 (O1): the product tree's `lessons/` is gone, and a write under a folder that does
    # not exist fails ENOENT before the ro bind is ever met — so the poisoned file goes into a
    # skills folder the product tree still ships, where only the ro bind can refuse it.
    poisoned = DEFENDER / "skills" / "gather" / "poisoned.md"
    assert poisoned.parent.is_dir(), f"{poisoned.parent} is gone; the EROFS probe would meet ENOENT"
    targets = [
        poisoned,
        DEFENDER / "SKILL.md",
        DEFENDER / "investigation" / "permission" / "bash.py",
    ]
    for i, target in enumerate(targets):
        res = _probe(box, run_dir, f"erofs{i}", _WRITE_PATH, str(Path("/defender") / target.relative_to(DEFENDER)))
        assert res["wrote"] is False, f"the box wrote into the ro bind at {target}"
        assert res["errno"] == errno_mod.EROFS, f"{target}: errno={res['errno']}"
        assert res["exc"] == "OSError", (
            f"{target}: EROFS must surface as a bare OSError, got {res['exc']} (C56a)")
    assert not poisoned.exists()
    assert b"box-was-here" not in (DEFENDER / "SKILL.md").read_bytes()


@requires_box
def test_defender_dir_imports_from_the_ro_bind(box, run_dir):
    res = _probe(box, run_dir, "roimport", _IMPORT_DEFENDER)

    for key in ("seg", "bash_exec"):
        assert res[key].startswith("/defender/"), (
            f"{key} imported from {res[key]!r}, not from the ro bind at {DEFENDER}")


@requires_box
def test_another_runs_run_dir_is_absent(box, run_dir, sibling_run):
    victim = sibling_run / "gather_raw" / "l-001.lead.json"
    assert victim.read_text(encoding="utf-8") == "SIBLING-RUN-SECRET-42"

    read = _probe(box, run_dir, "sibread", _READ_PATH, str(victim))
    assert read["read"] is None, read
    assert read["errno"] == errno_mod.ENOENT, read

    wrote = _probe(box, run_dir, "sibwrite", _WRITE_PATH, str(victim))
    assert wrote["wrote"] is False, "the box wrote into another run's run_dir"
    assert victim.read_text(encoding="utf-8") == "SIBLING-RUN-SECRET-42"

    parent = _probe(box, run_dir, "sibparent", _READ_PATH, str(run_dir.parent))
    assert parent["read"] is None, "the runs base itself is not mounted"


@requires_box
def test_bytes_written_in_box_appear_on_the_host(box, run_dir):
    written = _probe(box, run_dir, "hostwrite", _WRITE_PATH, "/runs/current/artifact.bin")
    assert written["wrote"] is True, written
    assert (run_dir / "artifact.bin").read_bytes() == b"box-was-here"

    raw = (
        "import json, os\n"
        "d = '/runs/current/gather_raw/l-042'\n"
        "os.makedirs(d, exist_ok=True)\n"
        "fd = os.open(os.path.join(d, '1.json'), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644)\n"
        "n = os.write(fd, b'{\"seq\": 1}')\n"
        "os.close(fd)\n"
        "print(json.dumps({'n': n}))\n"
    )
    assert _probe(box, run_dir, "rawwrite", raw)["n"] == 10
    assert (run_dir / "gather_raw" / "l-042" / "1.json").read_bytes() == b'{"seq": 1}'


@requires_box
def test_dotdot_operand_cannot_name_a_sibling_run(box, run_dir, sibling_run):
    escape = f"../{sibling_run.name}/gather_raw/l-001.lead.json"

    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    decision = decide_bash(f"cat {escape}", policy=policy, run_dir=run_dir,
                           defender_dir=DEFENDER)
    assert decision.allow is False, "the host-side gate should refuse the .. escape"

    res = _run(box, f"cat {escape}", cwd=Path("/runs/current"))
    combined = (res.out + res.err).decode("utf-8", "replace")
    assert "SIBLING-RUN-SECRET-42" not in combined, combined
    assert res.rc != 0, "the .. escape resolved to something readable"


@requires_box
def test_no_outbound_tcp_connect_succeeds(box, run_dir):
    with _echo_listener() as (host, port, accepted):
        res = _probe(box, run_dir, "tcp", _TCP_CONNECT, host, str(port))

    assert res["connected"] is False, f"a TCP connection escaped the box: {res}"
    assert res["errno"] in (errno_mod.ENETUNREACH, errno_mod.EHOSTUNREACH,
                            errno_mod.ENETDOWN), res
    assert accepted == [], f"the listener accepted a connection from the box: {accepted}"


@requires_box
def test_no_outbound_ipv6_connect_succeeds(box, run_dir):
    res = _probe(box, run_dir, "tcp6", _TCP6_CONNECT, "fc00::1", "80")

    assert res["connected"] is False, res
    assert res["errno"] in (errno_mod.ENETUNREACH, errno_mod.EHOSTUNREACH,
                            errno_mod.EADDRNOTAVAIL), res


@requires_box
def test_no_udp_sendto_reaches_a_destination(box, run_dir):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("0.0.0.0", 0))
    rx.settimeout(3)
    try:
        res = _probe(box, run_dir, "udp", _UDP_SENDTO, _host_ipv4(),
                     str(rx.getsockname()[1]))
        assert res["sent"] is None, f"a datagram left the box: {res}"
        assert res["errno"] in (errno_mod.ENETUNREACH, errno_mod.EHOSTUNREACH,
                                errno_mod.ENETDOWN, errno_mod.EPERM), res
        with pytest.raises((socket.timeout, TimeoutError, BlockingIOError)):
            rx.recvfrom(64)
    finally:
        rx.close()


@requires_box
def test_dns_resolution_fails_from_inside_the_box(box, run_dir):
    hostname = "example.com"
    try:
        socket.getaddrinfo(hostname, 80)
    except socket.gaierror:
        pytest.skip(f"this host cannot resolve {hostname} either — the control for "
                    "the DNS negative is unavailable, so the negative would be vacuous")

    res = _probe(box, run_dir, "dns", _DNS, hostname)

    assert res["resolved"] is None, f"DNS resolved inside the box: {res}"
    assert res["exc"] == "gaierror", res
    assert res["errno"] is not None, res


@requires_box
def test_the_same_egress_attempt_succeeds_outside_the_box(tmp_path):
    """THE control for the whole network family: the exact same probe source, aimed at the exact
    same address, connects and round-trips its bytes when run OUTSIDE the box."""
    script = tmp_path / "tcp_probe.py"
    script.write_text(_TCP_CONNECT, encoding="utf-8")

    with _echo_listener() as (host, port, accepted):
        proc = subprocess.run(
            ["python3", str(script), host, str(port)],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
    assert proc.returncode == 0, proc.stderr
    res = json.loads(proc.stdout)

    assert res["connected"] is True, f"the control could not reach {host}:{port}: {res}"
    assert res["echo"] == "ping"
    assert accepted == [b"ping"]


@requires_box
def test_egress_failure_is_a_bare_oserror_asserted_by_errno(box, run_dir):
    with _echo_listener() as (host, port, _accepted):
        res = _probe(box, run_dir, "bareerr", _TCP_CONNECT, host, str(port))

    assert res["connected"] is False
    assert res["exc"] == "OSError", (
        f"expected a bare OSError, got {res['exc']} — assert by errno, not by subclass")
    assert isinstance(res["errno"], int)
    assert res["errno"] > 0


@requires_box
def test_no_unix_socket_is_mounted_into_the_box(box, run_dir):
    """No socket is mounted inward: a full walk of the box's filesystem finds no unix socket
    anywhere outside the kernel pseudo-filesystems."""
    res = _probe(box, run_dir, "socksweep", _SOCKET_SWEEP)

    assert res["sockets"] == [], f"a unix socket is reachable inside the box: {res}"


@requires_box
def test_loopback_between_two_boxed_processes_is_permitted(box, run_dir):
    res = _probe(box, run_dir, "loopback", _LOOPBACK)

    assert res["exc"] is None, res
    assert res["payload"] == "loopback-ok", res
    assert res["child_rc"] == 0, res


@requires_box
def test_no_host_secret_is_present_in_the_box_env(run_dir, monkeypatch):
    """No host secret crosses into the box."""
    planted = {
        "ANTHROPIC_API_KEY": "sk-ant-boxspec-must-not-cross",
        "FIREWORKS_API_KEY": "fw-boxspec-must-not-cross",
        "GITHUB_TOKEN": "ghp-boxspec-must-not-cross",
        "SSH_AUTH_SOCK": "/tmp/boxspec-agent-must-not-cross.sock",
        "SIEM_PASSWORD": "boxspec-siem-must-not-cross",
    }
    for k, v in planted.items():
        monkeypatch.setenv(k, v)

    with _box(run_dir) as b:
        box_env = _probe(b, run_dir, "envsecret", _ENV_DUMP)

    blob = json.dumps(box_env)
    for name, value in planted.items():
        assert name not in box_env, f"{name} crossed into the box"
        assert value not in blob, f"the VALUE of {name} crossed into the box"


@requires_box
def test_box_env_contains_exactly_the_allowlist(box, run_dir):
    daemon_injected = {"HOSTNAME", "HOME", "PWD", "SHLVL", "_", "OLDPWD", "TERM"}

    box_env = _probe(box, run_dir, "envexact", _ENV_DUMP)

    expected = set(BOX_ENV_ALLOWLIST) - {"DEFENDER_AGENT_DIR"}
    assert set(box_env) - daemon_injected == expected, (
        f"box env is {sorted(box_env)}; expected is {sorted(expected)}")
    assert "DEFENDER_AGENT_DIR" not in box_env
    assert box_env["DEFENDER_RUN_DIR"] == "/runs/current"
    assert box_env["DEFENDER_RUNS_BASE"] == "/runs"

    siblings = _probe(box, run_dir, "runsbase",
                      'import json, os; print(json.dumps({"entries": os.listdir("/runs")}))')
    assert siblings["entries"] == ["current"], "the model runs parent exposes sibling runs"


def test_run_env_provider_key_strip_still_governs_host_subprocesses(
    tmp_path, monkeypatch,
):
    keys = sorted(providers.api_key_vars())
    assert keys, "api_key_vars() is empty — nothing to strip, so this survival test is vacuous"
    for var in keys:
        monkeypatch.setenv(var, f"live-{var}")
    monkeypatch.setenv("UNRELATED_HOST_VAR", "kept")

    env = run_env(DEFENDER, tmp_path / "run")

    for var in keys:
        assert var not in env, f"{var} survived run_env's strip"
        assert os.environ[var] == f"live-{var}", "run_env must not mutate os.environ"
    assert env["UNRELATED_HOST_VAR"] == "kept"
    assert env["DEFENDER_RUN_DIR"] == str(tmp_path / "run")


@requires_box
def test_boundary_holds_with_decide_bash_approving_everything(box, run_dir, sibling_run,
                                                              tmp_path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("O4-HOST-SECRET", encoding="utf-8")
    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)

    hostile = [
        f"cat {outside}",
        f"cat {sibling_run / 'gather_raw' / 'l-001.lead.json'}",
        f"cat {DEFENDER / 'investigation' / 'permission' / 'bash.py'} | head -1",
        "cat /etc/shadow",
        "defender-policy show",
    ]
    for command in hostile:
        decision = decide_bash(command, policy=policy, run_dir=run_dir,
                               defender_dir=DEFENDER)
        assert decision.allow is False, f"expected the gate to deny: {command!r}"
        res = _run(box, command, cwd=Path("/runs/current"))
        text = (res.out + res.err).decode("utf-8", "replace")
        assert "O4-HOST-SECRET" not in text, command
        assert "SIBLING-RUN-SECRET-42" not in text, command

    with _echo_listener() as (host, port, accepted):
        egress = _probe(box, run_dir, "o4net", _TCP_CONNECT, host, str(port))
    assert egress["connected"] is False
    assert accepted == []

    # #1108 P4 (O1): the product tree holds no `lessons/` — the read-only probe targets the
    # checkout's own root, which every box mounts and P4 keeps.
    poison = _probe(box, run_dir, "o4erofs", _WRITE_PATH,
                    "/defender/o4.md")
    assert poison["errno"] == errno_mod.EROFS, poison
    assert not (DEFENDER / "o4.md").exists()


def test_boxspec_carries_runtime_rootfs_and_lifecycle():
    fields = {f.name for f in dataclasses.fields(BoxSpec)}
    assert {"runtime", "rootfs", "lifecycle"} <= fields, fields

    default = BoxSpec.from_env({})
    assert default.runtime == "runsc"
    assert default == BoxSpec(), "the default must be anchored in the dataclass"

    levered = BoxSpec.from_env({BoxSpec.ENV_VAR: "runc"})
    assert levered.runtime == "runc"
    assert levered.rootfs == default.rootfs
    assert levered.lifecycle == default.lifecycle

    noise = BoxSpec.from_env({
        "DEFENDER_BOX_ROOTFS": "evil:latest",
        "DEFENDER_BOX_LIFECYCLE": "per_call",
        "DEFENDER_SANDBOX": "off",
    })
    assert noise == default, f"{BoxSpec.ENV_VAR} is not the sole lever: {noise}"


@requires_box
@pytest.mark.parametrize("runtime", ["runc", "runsc"])
def test_boundary_holds_under_both_runc_and_runsc(run_dir, sibling_run, tmp_path, runtime):
    if runtime not in docker_runtimes():
        pytest.skip(f"the {runtime!r} runtime is not registered with this daemon "
                    "(`docker info` Runtimes) — the parity claim is untestable here")

    outside = tmp_path / "floor-secret.txt"
    outside.write_text("FLOOR-HOST-SECRET", encoding="utf-8")

    with _box(run_dir, spec=BoxSpec.from_env({BoxSpec.ENV_VAR: runtime})) as b:
        absent = _probe(b, run_dir, f"floor-abs-{runtime}", _READ_PATH, str(outside))
        erofs = _probe(b, run_dir, f"floor-ro-{runtime}", _WRITE_PATH,
                       "/defender/floor.md")  # #1108 P4 (O1): no `lessons/` in the product
        sibling = _probe(b, run_dir, f"floor-sib-{runtime}", _READ_PATH,
                         str(sibling_run / "gather_raw" / "l-001.lead.json"))
        with _echo_listener() as (host, port, accepted):
            egress = _probe(b, run_dir, f"floor-net-{runtime}", _TCP_CONNECT, host, str(port))
        (run_dir / "alive.txt").write_text("alive", encoding="utf-8")
        alive = _probe(b, run_dir, f"floor-alive-{runtime}", _READ_PATH,
                       "/runs/current/alive.txt")

    assert alive["read"] == "alive", f"{runtime}: the box could not read its own rw bind"
    assert absent["read"] is None, absent
    assert absent["errno"] == errno_mod.ENOENT, absent
    assert erofs["errno"] == errno_mod.EROFS, erofs
    assert sibling["read"] is None, sibling
    assert egress["connected"] is False
    assert accepted == []


@requires_box
def test_a_script_on_the_tmpfs_cannot_execute(box, run_dir):
    stage = (
        "import json, os, stat\n"
        "p = '/tmp/staged.sh'\n"
        "open(p, 'w').write('#!/bin/sh\\necho staged-ran\\n')\n"
        "os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)\n"
        "print(json.dumps({'mode': oct(os.stat(p).st_mode), 'exists': os.path.exists(p)}))\n"
    )
    staged = _probe(box, run_dir, "tmpfsstage", stage)
    assert staged["exists"] is True, "the tmpfs is not even writable — wrong failure"

    res = _run(box, "/tmp/staged.sh", cwd=Path("/runs/current"))

    text = (res.out + res.err).decode("utf-8", "replace")
    assert "staged-ran" not in text, "a script on the tmpfs executed"
    assert res.rc == 126, f"expected rc=126 (exec denied), got rc={res.rc}: {text}"


@requires_box
def test_a_script_on_the_rw_bind_executes(box, run_dir):
    script = run_dir / "staged.sh"
    script.write_text("#!/bin/sh\necho staged-ran\n", encoding="utf-8")
    script.chmod(0o755)

    res = _run(box, "/runs/current/staged.sh", cwd=Path("/runs/current"))

    assert res.rc == 0, (res.rc, res.err)
    assert res.out.decode() == "staged-ran\n"


@requires_box
def test_tmpfs_exhaustion_fails_the_run_loudly(run_dir):
    small = dataclasses.replace(BoxSpec.from_env(os.environ), tmpfs_size="4m")

    unguarded = (
        "chunk = b'x' * (1024 * 1024)\n"
        "with open('/tmp/unguarded.bin', 'wb') as fh:\n"
        "    for _ in range(64):\n"
        "        fh.write(chunk)\n"
        "        fh.flush()\n"
    )
    with _box(run_dir, spec=small) as b:
        res = _probe(b, run_dir, "fill", _FILL_TMPFS)
        script = _write_probe(run_dir, "unguarded", unguarded)
        loud = _run(b, f"python3 {script}", cwd=Path("/runs/current"))

    assert res["exc"] == "OSError", f"ENOSPC must be a bare OSError (C56b): {res}"
    assert res["errno"] == errno_mod.ENOSPC, res
    assert res["written"] < 64 * 1024 * 1024, "the cap did not bind"
    assert loud.rc != 0, "exhaustion was silent — the run must fail loudly"
    assert b"OSError" in loud.err, loud.err


@requires_box
def test_defender_namespace_package_imports_in_the_box(box, run_dir):
    res = _probe(box, run_dir, "nspkg", _IMPORT_DEFENDER)
    assert res["seg"].startswith("/defender/")
    assert res["bash_exec"].startswith("/defender/")

    findspec = (
        "import importlib.util, json\n"
        "spec = importlib.util.find_spec('defender.execution.bash_exec')\n"
        "print(json.dumps({'origin': None if spec is None else spec.origin}))\n"
    )
    entrypoint = _probe(box, run_dir, "entrypoint", findspec)
    assert entrypoint["origin"] is not None, "the box entrypoint module is not importable"
    assert entrypoint["origin"].startswith("/defender/")


@requires_box
def test_the_granted_bash_repertoire_runs_inside_the_box(box, run_dir):
    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    programs = sorted({g.program for g in policy.bash_allow})
    assert programs, "the compiled policy grants no program — nothing to check"

    which = _probe(box, run_dir, "which", _WHICH, *programs)
    missing = [p for p, path in which.items() if path is None]
    assert missing == [], f"granted but absent from the rootfs: {missing}"

    (run_dir / "corpus.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    res = _run(box, "cat /runs/current/corpus.txt | grep -n beta", cwd=Path("/runs/current"))
    assert res.rc == 0, res.err
    assert res.out.decode() == "2:beta\n"
