"""#540 — the isolation boundary, as an executable spec.

The demands this file discharges (see `defender/tests/spec_graph_540.yaml`):

* **O1 / O5 / O6 — filesystem.** Every host path that is not `run_dir` or
  `defender_dir` is *absent* from inside the box, not denied; `defender_dir` is
  readable and importable but EROFS on write; `run_dir` is the one writable
  directory and its bytes reach the host with no copy step.
* **O2 — network.** No outbound connection of any family reaches any
  destination, DNS does not resolve, and the failure is a *bare* `OSError`
  asserted by errno. Loopback between two boxed processes stays permitted.
* **O3 — secrets.** The box environment is a positive allowlist; no host secret
  crosses. `run_common.run_env`'s provider-key strip still governs HOST-side
  subprocesses — the two are different mechanisms and must not be conflated.
* **O4 — structural, not the matcher.** The boundary holds for commands the
  real `decide_bash` DENIES: the mount list and the network mode are the
  enforcement, so a gate that approved everything would change nothing.
* **O14 / F3 — the knob and the tmpfs.** `BoxSpec` carries runtime + rootfs +
  lifecycle behind one env var; the boundary holds at the `runc` FLOOR as well
  as under `runsc`; `/tmp` is noexec and size-capped; the rw bind stays
  exec-able; the granted repertoire and the `defender` namespace package both
  work inside the box.

**This file is RED BY CONSTRUCTION.** `defender.runtime.box` does not exist —
there is zero sandbox code in the tree at base. The failing import IS the
expected red; do not add a skeleton module to make it resolve.

**Seams this spec requires of the target** (fakes never enter by monkeypatch —
`scripts/lint/lint_monkeypatch.py` is a blocking gate):

* `start_box(run_dir, defender_dir, *, spec=BoxSpec()) -> BoxExecutor`
* `BoxExecutor.run_parsed(pipelines, *, command, cwd, timeout) -> BoxResult`
  — the same `Pipeline` list `bash_exec.parse` produces (M8: no second parse),
  returning the `BoxResult(rc, out: bytes, err: bytes)` dataclass, never a tuple.
* `stop_box(box)`
* `BoxSpec.from_env(mapping)` — the ONE external lever (F1).
* `BOX_ENV_ALLOWLIST` — the positive env allowlist (F7), owned by the target so
  this file asserts against the shipped value rather than a copy of it.

**Environment honesty.** Every test here drives a real Docker daemon, and every
one of them starts a real box, which under docker-outside-of-Docker cannot pass
F8's startup sentinel (bind SOURCES resolve on the real daemon host and are
invisible from this process — ledger E2 / claim `C_dood`, corroborated by C46:
an absent bind source is silently created EMPTY, no error at any stage). Rather
than let a test pass green while unable to observe the thing it asserts, the
whole file skips under DooD with that reason. On a native daemon (CI's
`ubuntu-latest` included) it runs for real.

Not asserted here, deliberately:

* **C41** (artifacts land root-owned on the host) — architecturally unprobeable
  from a DooD sandbox and recorded `deferred`, not `holds`.
* **The DNS errno value** — `C56_dns_eai_again` is `deferred`: this sandbox has
  live egress and observed `-2`, not `-3`. Only the *shape* (`socket.gaierror`)
  is asserted, and no errno name is ever looked up in `errno.errorcode`, which
  contains neither `-2` nor `-3` (C56d).
* **A positive control for `test_no_unix_socket_is_mounted_into_the_box`** —
  waived in the graph (`w_no_socket_positive_control`): building one would mean
  mounting a socket into the box, the exact thing the negative forbids.
"""
from __future__ import annotations

import contextlib
import errno as errno_mod
import json
import os
import socket
import subprocess
import threading
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # MAIN_DEF lives in the driver

from defender.run_common import run_env  # noqa: E402
from defender.runtime import providers  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.bash_exec import parse  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.permission.bash import decide_bash  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER  # noqa: E402

# THE RED. Nothing below this line can run until #540's box module exists.
from defender.runtime.box import (  # noqa: E402
    BOX_ENV_ALLOWLIST,
    BoxResult,
    BoxSpec,
    start_box,
    stop_box,
)

pytestmark = pytest.mark.e2e

EXEC_TIMEOUT = 60.0


# --- environment gates -----------------------------------------------------
# Both are PROBES, not assumptions: a boundary test that cannot observe the
# boundary must say so out loud rather than pass.

def _daemon_reachable() -> bool:
    try:
        return subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=30,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _is_dood() -> bool:
    """docker-outside-of-Docker: the daemon's root dir is not on OUR filesystem,
    so bind SOURCES resolve somewhere this process cannot see (ledger E2)."""
    if not Path("/.dockerenv").exists():
        return False
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    root = probe.stdout.strip()
    return probe.returncode == 0 and bool(root) and not Path(root).exists()


_NO_DAEMON = not _daemon_reachable()
_DOOD = (not _NO_DAEMON) and _is_dood()

requires_box = pytest.mark.skipif(
    _NO_DAEMON or _DOOD,
    reason=(
        "no reachable Docker daemon" if _NO_DAEMON else
        "docker-outside-of-Docker: bind sources resolve on the real daemon host and are "
        "invisible from this process (ledger E2 / C_dood), so F8's startup sentinel cannot "
        "pass and a bind assertion here would be asserting against a filesystem it cannot "
        "see. Run on a native daemon."
    ),
)


def _docker_runtimes() -> frozenset[str]:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    return frozenset(probe.stdout.split()) if probe.returncode == 0 else frozenset()


# --- the box under test ----------------------------------------------------

@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """A real run dir under a real runs base, with a real sibling run beside it
    (the sibling is what `test_another_runs_run_dir_is_absent` and the `..`
    escape test try to reach — a live neighbour, not an imagined one)."""
    base = tmp_path / "defender-runs"
    d = base / "20260718T101500Z-boxspec"
    (d / "gather_raw").mkdir(parents=True)
    (d / "alert.json").write_text('{"id": "boxspec"}', encoding="utf-8")
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
    """Plant a probe script on the rw bind. The bytes are written HERE, by the
    test, through the real filesystem — the fault (or the capability) is real."""
    script = run_dir / f"_probe_{name}.py"
    script.write_text(source, encoding="utf-8")
    return script


def _probe(box, run_dir: Path, name: str, source: str, *args: str) -> dict:
    """Run a probe in the box and decode its one JSON line. The probe CATCHES its
    own OSError and reports `type(e).__name__` + `e.errno`, so the assertion is on
    the errno and the exact class — never on an exception subclass (C56)."""
    script = _write_probe(run_dir, name, source)
    argv = " ".join([f"python3 {script}", *args])
    res = _run(box, argv, cwd=run_dir)
    assert res.rc == 0, f"probe {name} did not complete: rc={res.rc} err={res.err!r}"
    return json.loads(res.out.decode("utf-8"))


# --- probe sources ---------------------------------------------------------
# Each is real code exercising a real primitive. The TCP source is shared
# verbatim between the in-box negative and its outside-the-box positive control,
# so the two differ in exactly one thing: whether they run inside the box.

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
import defender.runtime.bash_exec as be
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


# --- host-side helpers for the network family ------------------------------

def _host_ipv4() -> str:
    """This host's routable address, discovered without sending a packet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1; connect on UDP sends nothing
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


# ===========================================================================
# O1 / O5 / O6 — the filesystem boundary
# ===========================================================================

@requires_box
def test_host_path_outside_the_binds_is_absent(box, run_dir, tmp_path):
    """A host path that is neither `run_dir` nor `defender_dir` is ABSENT from
    inside the box, not denied: opening it fails ENOENT — the errno of a path
    that does not exist — rather than EACCES/EPERM, because nothing mounted it.
    The write set and the read set are the mount list, so a path outside both
    has no name inside the box at all."""
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
        box, f"cat {outside}", cwd=run_dir).out.decode("utf-8", "replace")


@requires_box
def test_run_dir_and_defender_dir_are_readable_in_box(box, run_dir):
    """Both binds ARE readable from inside the box: bytes the host wrote into
    `run_dir` and a real file under `defender_dir` both read back byte-exact.
    This is the positive control for the absence assertions — without it, every
    'the box cannot see it' result is equally green on a box that can see
    nothing at all, including its own mounts."""
    host_bytes = b"RUN-DIR-SENTINEL-\xe2\x9c\x93\n"
    (run_dir / "sentinel.txt").write_bytes(host_bytes)
    skill = DEFENDER / "SKILL.md"

    got_run = _probe(box, run_dir, "readrun", _READ_PATH, str(run_dir / "sentinel.txt"))
    got_defender = _probe(box, run_dir, "readdef", _READ_PATH, str(skill))

    assert got_run["read"] == host_bytes.decode("utf-8")
    assert got_defender["read"] == skill.read_text(encoding="utf-8")


@requires_box
def test_write_under_defender_dir_fails_erofs_by_errno(box, run_dir):
    """A write to any path under `defender_dir` fails EROFS: the ro bind is the
    enforcement, so a hijacked agent cannot poison its own corpus, skills, or
    lessons. The fault is a BARE `OSError` — asserted by `errno`, and by
    `type(e) is OSError` exactly, because EROFS has no `PermissionError`
    subclass (C56a)."""
    targets = [
        DEFENDER / "lessons" / "poisoned.md",
        DEFENDER / "SKILL.md",
        DEFENDER / "runtime" / "permission" / "bash.py",
    ]
    for i, target in enumerate(targets):
        res = _probe(box, run_dir, f"erofs{i}", _WRITE_PATH, str(target))
        assert res["wrote"] is False, f"the box wrote into the ro bind at {target}"
        assert res["errno"] == errno_mod.EROFS, f"{target}: errno={res['errno']}"
        assert res["exc"] == "OSError", (
            f"{target}: EROFS must surface as a bare OSError, got {res['exc']} (C56a)")
    assert not (DEFENDER / "lessons" / "poisoned.md").exists()
    assert b"box-was-here" not in (DEFENDER / "SKILL.md").read_bytes()


@requires_box
def test_defender_dir_imports_from_the_ro_bind(box, run_dir):
    """The ro bind is not merely present but USABLE: real defender modules import
    from it inside the box and resolve to files under the mount. This is the
    positive control for the EROFS assertion — read-only means read-ONLY, not
    unreachable."""
    res = _probe(box, run_dir, "roimport", _IMPORT_DEFENDER)

    for key in ("seg", "bash_exec"):
        assert res[key].startswith(str(DEFENDER)), (
            f"{key} imported from {res[key]!r}, not from the ro bind at {DEFENDER}")


@requires_box
def test_another_runs_run_dir_is_absent(box, run_dir, sibling_run):
    """The write set is exactly one directory: a SECOND, live run dir sitting
    beside this one on the host has no name inside the box. Reading it fails
    ENOENT and writing into it fails, so one alert's box structurally cannot
    see — or corrupt — another's scratch."""
    victim = sibling_run / "gather_raw" / "l-001.lead.json"
    assert victim.read_text(encoding="utf-8") == "SIBLING-RUN-SECRET-42"

    read = _probe(box, run_dir, "sibread", _READ_PATH, str(victim))
    assert read["read"] is None and read["errno"] == errno_mod.ENOENT, read

    wrote = _probe(box, run_dir, "sibwrite", _WRITE_PATH, str(victim))
    assert wrote["wrote"] is False, "the box wrote into another run's run_dir"
    assert victim.read_text(encoding="utf-8") == "SIBLING-RUN-SECRET-42"

    parent = _probe(box, run_dir, "sibparent", _READ_PATH, str(run_dir.parent))
    assert parent["read"] is None, "the runs base itself is not mounted"


@requires_box
def test_bytes_written_in_box_appear_on_the_host(box, run_dir):
    """`run_dir` is the one writable directory and the writable mount IS the
    exit: bytes a boxed process writes appear on the host as written, with no
    copy step. Positive control for every filesystem negative above."""
    written = _probe(box, run_dir, "hostwrite", _WRITE_PATH, str(run_dir / "artifact.bin"))
    assert written["wrote"] is True, written
    assert (run_dir / "artifact.bin").read_bytes() == b"box-was-here"

    # Again through a different write primitive, so the claim does not rest on
    # one code path: a raw os.open/os.write into a nested directory the box also
    # creates itself.
    raw = (
        "import json, os\n"
        f"d = {str(run_dir / 'gather_raw' / 'l-042')!r}\n"
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
    """A `..` operand from the box's cwd cannot name a sibling run: `run_dir` is
    the mount point, so its parent is not mounted and the escape resolves to a
    path that is absent rather than to another run's artifacts. The same operand
    is DENIED host-side by the real gate — the box makes the escape absent, the
    gate makes it refused, and neither alone is the claim."""
    escape = f"../{sibling_run.name}/gather_raw/l-001.lead.json"

    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    decision = decide_bash(f"cat {escape}", policy=policy, run_dir=run_dir,
                           defender_dir=DEFENDER)
    assert decision.allow is False, "the host-side gate should refuse the .. escape"

    res = _run(box, f"cat {escape}", cwd=run_dir)
    combined = (res.out + res.err).decode("utf-8", "replace")
    assert "SIBLING-RUN-SECRET-42" not in combined, combined
    assert res.rc != 0, "the .. escape resolved to something readable"


# ===========================================================================
# O2 — the network boundary
# ===========================================================================

@requires_box
def test_no_outbound_tcp_connect_succeeds(box, run_dir):
    """No outbound TCP connection reaches any destination: a connect to a REAL
    listener that is up and accepting on this host fails from inside the box,
    and the listener records no connection. There is no permitted peer, not a
    restricted one."""
    with _echo_listener() as (host, port, accepted):
        res = _probe(box, run_dir, "tcp", _TCP_CONNECT, host, str(port))

    assert res["connected"] is False, f"a TCP connection escaped the box: {res}"
    assert res["errno"] in (errno_mod.ENETUNREACH, errno_mod.EHOSTUNREACH,
                            errno_mod.ENETDOWN), res
    assert accepted == [], f"the listener accepted a connection from the box: {accepted}"


@requires_box
def test_no_outbound_ipv6_connect_succeeds(box, run_dir):
    """The absent network is family-agnostic: an IPv6 connect fails from inside
    the box exactly as the IPv4 one does — closing the other half of the address
    space rather than only the one the tests happened to use first."""
    res = _probe(box, run_dir, "tcp6", _TCP6_CONNECT, "fc00::1", "80")

    assert res["connected"] is False, res
    assert res["errno"] in (errno_mod.ENETUNREACH, errno_mod.EHOSTUNREACH,
                            errno_mod.EADDRNOTAVAIL), res


@requires_box
def test_no_udp_sendto_reaches_a_destination(box, run_dir):
    """No datagram leaves the box either: a `sendto` at a REAL bound UDP socket
    on this host does not arrive. The boundary is the absence of a route, not a
    connection-oriented check that a connectionless protocol would slip past."""
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
    """Name resolution does not work inside the box: a hostname that resolves on
    this host raises `socket.gaierror` in the box. Only the shape is asserted —
    the EAI_* value is `deferred` in the ledger, and no errno name is looked up,
    because `errno.errorcode` contains neither -2 nor -3 (C56d)."""
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
    # No errno NAME is asserted: `errno.errorcode` holds neither -2 nor -3 (C56d),
    # and which EAI_* value a network-less namespace produces is `deferred` in the
    # ledger — this sandbox observed -2 because it has live egress.


@requires_box
def test_the_same_egress_attempt_succeeds_outside_the_box(tmp_path):
    """THE control for the whole network family: the exact same probe source,
    aimed at the exact same address, connects and round-trips its bytes when run
    OUTSIDE the box. Without it every 'no connection' assertion above is equally
    green on a broken observation channel — a probe that never ran, a listener
    that never listened, an errno nobody produced."""
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
    """The egress fault is a BARE `OSError` — `type(e) is OSError` exactly, with
    no `ConnectionRefusedError`/`PermissionError` subclass to catch — so the only
    honest assertion is on `e.errno` (C56c: ENETUNREACH surfaced as errno 101 on
    a plain OSError). A suite that caught a subclass here would be pinning an
    exception hierarchy the kernel never promised."""
    with _echo_listener() as (host, port, _accepted):
        res = _probe(box, run_dir, "bareerr", _TCP_CONNECT, host, str(port))

    assert res["connected"] is False
    assert res["exc"] == "OSError", (
        f"expected a bare OSError, got {res['exc']} — assert by errno, not by subclass")
    assert isinstance(res["errno"], int) and res["errno"] > 0


@requires_box
def test_no_unix_socket_is_mounted_into_the_box(box, run_dir):
    """No socket is mounted inward: a full walk of the box's filesystem finds no
    unix socket anywhere outside the kernel pseudo-filesystems. The broker UDS
    the older design mandated is dead — there is no off-box path at all, not a
    single narrow one. (Waived without a positive control: building one would
    mean mounting a socket in, the exact thing this forbids.)"""
    res = _probe(box, run_dir, "socksweep", _SOCKET_SWEEP)

    assert res["sockets"] == [], f"a unix socket is reachable inside the box: {res}"


@requires_box
def test_loopback_between_two_boxed_processes_is_permitted(box, run_dir):
    """Loopback stays IN CONTRACT: two processes inside the box exchange bytes
    over 127.0.0.1. `lo` is up under `--network=none` and there is no peer
    outside the box for it to reach, so intra-box IPC survives without widening
    the egress boundary by anything."""
    res = _probe(box, run_dir, "loopback", _LOOPBACK)

    assert res["exc"] is None, res
    assert res["payload"] == "loopback-ok", res
    assert res["child_rc"] == 0, res


# ===========================================================================
# O3 — secrets and the environment
# ===========================================================================

@requires_box
def test_no_host_secret_is_present_in_the_box_env(run_dir, monkeypatch):
    """No host secret crosses into the box. Real secret-shaped variables are set
    in the host environment before the box is built — the provider keys the
    driver really holds, plus the credentials the old strip-list inherited
    (`GITHUB_TOKEN`, `SSH_AUTH_SOCK`, a SIEM password) — and none of their names
    or VALUES appears anywhere in the box's environment. The env is built
    positively, so a variable nobody enumerated is absent by construction."""
    # setenv is the REAL input channel for the process environment (and is
    # explicitly not what lint_monkeypatch flags — it gates `setattr`).
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
    """The box environment is a positive allowlist, not a strip-list: the
    variables present are exactly `BOX_ENV_ALLOWLIST` plus what the container
    runtime itself injects. `DEFENDER_RUNS_BASE` is in the allowlist and names
    `run_dir.parent`, which is NOT mounted — so the box is told where runs live
    and still cannot reach them."""
    # What any OCI runtime puts in a container's env regardless of what we ask
    # for; named so the exact-set assertion below stays exact.
    daemon_injected = {"HOSTNAME", "HOME", "PWD", "SHLVL", "_", "OLDPWD", "TERM"}

    box_env = _probe(box, run_dir, "envexact", _ENV_DUMP)

    assert set(box_env) - daemon_injected == set(BOX_ENV_ALLOWLIST), (
        f"box env is {sorted(box_env)}; allowlist is {sorted(BOX_ENV_ALLOWLIST)}")
    assert box_env["DEFENDER_RUN_DIR"] == str(run_dir)
    assert box_env["DEFENDER_RUNS_BASE"] == str(run_dir.parent)

    unreachable = _probe(box, run_dir, "runsbase", _READ_PATH, box_env["DEFENDER_RUNS_BASE"])
    assert unreachable["read"] is None, "DEFENDER_RUNS_BASE names a mounted path"


def test_run_env_provider_key_strip_still_governs_host_subprocesses(
    tmp_path, monkeypatch,
):
    """`run_env`'s provider-key strip is untouched by the box and still governs
    HOST-side subprocesses: every billable key is removed from the environment a
    host subprocess inherits, while unrelated variables still pass through. The
    box's positive allowlist and this strip are two different mechanisms on two
    different surfaces — this test fails if the box work collapses them."""
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


# ===========================================================================
# O4 — the boundary is structural, not the matcher
# ===========================================================================

@requires_box
def test_boundary_holds_with_decide_bash_approving_everything(box, run_dir, sibling_run,
                                                              tmp_path):
    """O1-O3 hold regardless of what the model emits and regardless of what the
    in-process gate decides: every command below is DENIED by the real
    `decide_bash`, and is then executed through the box anyway — a gate that
    approved all of them would change nothing, because the enforcement is the
    mount list and the network mode, not a matcher. The host path stays absent,
    the ro bind stays EROFS, the sibling run stays unreadable, and no connection
    leaves."""
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("O4-HOST-SECRET", encoding="utf-8")
    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)

    hostile = [
        f"cat {outside}",
        f"cat {sibling_run / 'gather_raw' / 'l-001.lead.json'}",
        f"cat {DEFENDER / 'runtime' / 'permission' / 'bash.py'} | head -1",
        "cat /etc/shadow",
        # C_bin_shims: the operator-only audit CLI is kept off every lane by a
        # GATE control, and the mount list makes its binary PRESENT. Running it
        # anyway must not reach anything outside the binds.
        "defender-policy show",
    ]
    for command in hostile:
        decision = decide_bash(command, policy=policy, run_dir=run_dir,
                               defender_dir=DEFENDER)
        assert decision.allow is False, f"expected the gate to deny: {command!r}"
        res = _run(box, command, cwd=run_dir)
        text = (res.out + res.err).decode("utf-8", "replace")
        assert "O4-HOST-SECRET" not in text, command
        assert "SIBLING-RUN-SECRET-42" not in text, command

    # The two non-filesystem halves, with the gate equally out of the picture.
    with _echo_listener() as (host, port, accepted):
        egress = _probe(box, run_dir, "o4net", _TCP_CONNECT, host, str(port))
    assert egress["connected"] is False and accepted == []

    poison = _probe(box, run_dir, "o4erofs", _WRITE_PATH,
                    str(DEFENDER / "lessons" / "o4.md"))
    assert poison["errno"] == errno_mod.EROFS, poison
    assert not (DEFENDER / "lessons" / "o4.md").exists()


# ===========================================================================
# O14 / F1 / F3 — the knob, the tmpfs, the repertoire
# ===========================================================================

def test_boxspec_carries_runtime_rootfs_and_lifecycle():
    """`BoxSpec` carries all three replaceables — runtime, rootfs and lifecycle
    — as one dataclass whose default runtime is `runsc`, and ONE env var is the
    sole external lever: it moves the runtime axis and nothing else, and no other
    variable moves anything. The lifecycle sits behind the interface rather than
    being hardcoded to a runtime's cost model."""
    import dataclasses

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
    """The boundary holds at the `runc` FLOOR as well as under the `runsc`
    default: outside host paths stay absent, the ro bind stays EROFS, and no
    connection leaves, under either runtime. v1 is not gated on gVisor — the
    mount list and `--network=none` are delivered by any Docker host — so
    nothing here may depend on a runsc-only hardening (M15)."""
    if runtime not in _docker_runtimes():
        pytest.skip(f"the {runtime!r} runtime is not registered with this daemon "
                    "(`docker info` Runtimes) — the parity claim is untestable here")

    outside = tmp_path / "floor-secret.txt"
    outside.write_text("FLOOR-HOST-SECRET", encoding="utf-8")

    with _box(run_dir, spec=BoxSpec.from_env({BoxSpec.ENV_VAR: runtime})) as b:
        absent = _probe(b, run_dir, f"floor-abs-{runtime}", _READ_PATH, str(outside))
        erofs = _probe(b, run_dir, f"floor-ro-{runtime}", _WRITE_PATH,
                       str(DEFENDER / "lessons" / "floor.md"))
        sibling = _probe(b, run_dir, f"floor-sib-{runtime}", _READ_PATH,
                         str(sibling_run / "gather_raw" / "l-001.lead.json"))
        with _echo_listener() as (host, port, accepted):
            egress = _probe(b, run_dir, f"floor-net-{runtime}", _TCP_CONNECT, host, str(port))
        # Positive control INSIDE the parametrization: the box is alive and can
        # read its own binds, so the three negatives are not a dead container.
        (run_dir / "alive.txt").write_text("alive", encoding="utf-8")
        alive = _probe(b, run_dir, f"floor-alive-{runtime}", _READ_PATH,
                       str(run_dir / "alive.txt"))

    assert alive["read"] == "alive", f"{runtime}: the box could not read its own rw bind"
    assert absent["read"] is None and absent["errno"] == errno_mod.ENOENT, absent
    assert erofs["errno"] == errno_mod.EROFS, erofs
    assert sibling["read"] is None, sibling
    assert egress["connected"] is False and accepted == []


@requires_box
def test_a_script_on_the_tmpfs_cannot_execute(box, run_dir):
    """`/tmp` is noexec: a real executable script written to the tmpfs inside the
    box, with the execute bit really set, fails to run — model-written code
    cannot stage an executable there. The failure is the exec permission one
    (rc=126), not 'command not found'."""
    stage = (
        "import json, os, stat\n"
        "p = '/tmp/staged.sh'\n"
        "open(p, 'w').write('#!/bin/sh\\necho staged-ran\\n')\n"
        "os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)\n"
        "print(json.dumps({'mode': oct(os.stat(p).st_mode), 'exists': os.path.exists(p)}))\n"
    )
    staged = _probe(box, run_dir, "tmpfsstage", stage)
    assert staged["exists"] is True, "the tmpfs is not even writable — wrong failure"

    res = _run(box, "/tmp/staged.sh", cwd=run_dir)

    text = (res.out + res.err).decode("utf-8", "replace")
    assert "staged-ran" not in text, "a script on the tmpfs executed"
    assert res.rc == 126, f"expected rc=126 (exec denied), got rc={res.rc}: {text}"


@requires_box
def test_a_script_on_the_rw_bind_executes(box, run_dir):
    """The rw bind stays exec-able — the positive control for the noexec tmpfs.
    The identical script, with the identical mode bits, runs from `run_dir`,
    which cannot be made noexec without breaking artifacts. So rc=126 above is
    the tmpfs's mount option, not a broken script or a broken box."""
    script = run_dir / "staged.sh"
    script.write_text("#!/bin/sh\necho staged-ran\n", encoding="utf-8")
    script.chmod(0o755)

    res = _run(box, str(script), cwd=run_dir)

    assert res.rc == 0, (res.rc, res.err)
    assert res.out.decode() == "staged-ran\n"


@requires_box
def test_tmpfs_exhaustion_fails_the_run_loudly(run_dir):
    """The tmpfs is size-capped and exhausting it fails LOUDLY: a boxed process
    writing past the cap gets ENOSPC as a bare `OSError` (C56b) and a non-zero
    result, never a silent short write. This is accounting, not a security
    boundary (TM class 7) — the obligation is that it is loud."""
    small = BoxSpec(tmpfs_size="4m")

    # The same overrun WITHOUT the probe's try/except, so the fault reaches the
    # BoxResult rather than being swallowed by the probe that observes it.
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
        loud = _run(b, f"python3 {script}", cwd=run_dir)

    assert res["exc"] == "OSError", f"ENOSPC must be a bare OSError (C56b): {res}"
    assert res["errno"] == errno_mod.ENOSPC, res
    assert res["written"] < 64 * 1024 * 1024, "the cap did not bind"
    assert loud.rc != 0, "exhaustion was silent — the run must fail loudly"
    assert b"OSError" in loud.err, loud.err


@requires_box
def test_defender_namespace_package_imports_in_the_box(box, run_dir):
    """`defender` is a PEP-420 namespace package, so the PARENT of the mount
    point is on `sys.path` inside the box: sibling submodules from different
    top-level dirs (`defender.runtime.*` and `defender.hooks.*`) both import, and
    the in-box entrypoint `python3 -m defender.runtime.bash_exec` is reachable as
    a module. A mount destination that broke this would make the entrypoint
    unimportable rather than merely awkward."""
    res = _probe(box, run_dir, "nspkg", _IMPORT_DEFENDER)
    assert res["seg"].startswith(str(DEFENDER)) and res["bash_exec"].startswith(str(DEFENDER))

    # The in-box entrypoint itself (M8) is reachable as a MODULE, which is the
    # half a plain `import` does not cover.
    findspec = (
        "import importlib.util, json\n"
        "spec = importlib.util.find_spec('defender.runtime.bash_exec')\n"
        "print(json.dumps({'origin': None if spec is None else spec.origin}))\n"
    )
    entrypoint = _probe(box, run_dir, "entrypoint", findspec)
    assert entrypoint["origin"] is not None, "the box entrypoint module is not importable"
    assert entrypoint["origin"].startswith(str(DEFENDER))


@requires_box
def test_the_granted_bash_repertoire_runs_inside_the_box(box, run_dir):
    """Every program the REAL grant table lets an agent run is present and runs
    inside the box, producing the same result it would outside: the repertoire
    is a property of the rootfs, and a program the policy grants but the image
    lacks is a silent capability loss, not a boundary. Read off the compiled
    policy's own grants, so a new grant cannot ship without an image that
    carries its program."""
    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    programs = sorted({g.program for g in policy.bash_allow})
    assert programs, "the compiled policy grants no program — nothing to check"

    which = _probe(box, run_dir, "which", _WHICH, *programs)
    missing = [p for p, path in which.items() if path is None]
    assert missing == [], f"granted but absent from the rootfs: {missing}"

    # And the repertoire actually runs, end to end, over real bytes on the rw bind.
    (run_dir / "corpus.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    res = _run(box, f"cat {run_dir / 'corpus.txt'} | grep -n beta", cwd=run_dir)
    assert res.rc == 0, res.err
    assert res.out.decode() == "2:beta\n"
