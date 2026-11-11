"""#1391 O5, r6 O8 and L4: the lab's endpoint-query service, over a fake Docker.

The service's route table, status table and validation; its two inputs (hosts answered,
containers inspectable); the process list run by name with the surface's argv; and the product's
host-state adapter driven against it over HTTP for every verb, so the answer shapes the adapter
reads are the ones the service writes.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

HERE = Path(__file__).resolve()
REPO = HERE.parents[3]
SERVICE = HERE.parents[1] / "service.py"
SURFACE = HERE.parents[2] / "lab-surface.json"
_spec = importlib.util.spec_from_file_location("endpoint_query_1391", SERVICE)
eq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(eq)

PS_ARGV = json.loads(SURFACE.read_text())["ps_argv"]
PASSWD = "root:x:0:0:root:/root:/bin/bash\n# comment\nsre.alice:x:1001:1001::/home/sre.alice:/bin/bash\n"
KEYS = "ssh-ed25519 AAAA alice@laptop\n# old key\n\nssh-rsa BBBB backup\n"
HOSTS_FILE = b"127.0.0.1 localhost\n"
SHA = __import__("hashlib").sha256(HOSTS_FILE).hexdigest()
DPKG_STATUS = """Package: bash
Status: install ok installed
Version: 5.1
Description: the shell
 continued line: not a field

Package: gone
Status: purge ok not-installed

Package: openssh-server
Status: install ok installed
Version: 8.9
"""
WEB_ID = "3f2a9c" + "0" * 58


class FakeDocker:
    """Containers by name and id; each has a filesystem (path -> bytes, or ("link", target)).
    Records every command run in a container."""

    def __init__(self):
        self.containers = {
            "web-1": {"id": WEB_ID, "running": True, "image": "soc-playground/host:local", "files": {
                "/etc/passwd": PASSWD.encode(),
                "/home/sre.alice/.ssh/authorized_keys": ("link", "../keys/alice.pub"),
                "/home/sre.alice/keys/alice.pub": KEYS.encode(),
                "/etc/hosts": HOSTS_FILE,
                "/etc": ("dir",),
                "/var/lib/dpkg/status": DPKG_STATUS.encode(),
                "/loop/a": ("link", "b"), "/loop/b": ("link", "a"),
            }},
            "db-1": {"id": "9" * 64, "running": False, "image": "soc-playground/host:local", "files": {}},
            "kibana": {"id": "k" * 64, "running": True, "image": "kibana:9", "files": {}},
        }
        self.calls, self.reads = [], []
        self.ps = (0, "  PID  PPID USER\n    1     0 root  init\n", "")

    def _named(self, ref):
        for name, c in self.containers.items():
            if ref == name or (len(ref) >= 4 and c["id"].startswith(ref)):
                return name, c
        return None, None

    def container(self, ref):
        name, c = self._named(ref)
        if c is None:
            return None
        return {"Id": c["id"], "Name": f"/{name}", "State": {"Running": c["running"]}, "Config": {"Image": c["image"]}}

    def read(self, name, path):
        self.reads.append((name, path))
        found = self.containers[name]["files"].get(path)
        if found is None:
            return None
        if isinstance(found, bytes):
            return "file", found
        return ("link", found[1]) if found[0] == "link" else ("other", "")

    def exec(self, name, argv):
        self.calls.append((name, list(argv)))
        code, out, err = self.ps if list(argv) == PS_ARGV else (127, "", f"{argv[0]}: not found")
        return code, out.encode(), err.encode()


def make(docker=None, *, hosts=("web-1", "db-1"), inspectable=("web-1", "db-1")):
    docker = docker or FakeDocker()
    return eq.Service(docker, hosts=list(hosts), inspectable=list(inspectable), argv=eq.ps_argv(SURFACE)), docker


@pytest.mark.parametrize(("target", "status", "body"), [
    ("/hosts", 200, {"hosts": [{"name": "web-1", "running": True}, {"name": "db-1", "running": False}]}),
    ("/hosts/web-1/processes", 200, {"ps_output": "  PID  PPID USER\n    1     0 root  init\n"}),
    ("/hosts/web-1/accounts", 200, {"entries": ["root:x:0:0:root:/root:/bin/bash",
                                                "sre.alice:x:1001:1001::/home/sre.alice:/bin/bash"]}),
    ("/hosts/web-1/accounts/sre.alice/authorized-keys", 200,
     {"path": "/home/sre.alice/.ssh/authorized_keys", "keys": ["ssh-ed25519 AAAA alice@laptop", "ssh-rsa BBBB backup"]}),
    ("/hosts/web-1/accounts/root/authorized-keys", 200, {"path": "/root/.ssh/authorized_keys", "keys": []}),
    ("/hosts/web-1/files/sha256?path=%2Fetc%2Fhosts", 200, {"sha256": SHA}),
    ("/hosts/web-1/packages", 200, {"packages": ["bash 5.1", "openssh-server 8.9"]}),
    ("/containers/web-1", 200, {"name": "web-1", "image": "soc-playground/host:local"}),
    (f"/containers/{WEB_ID}", 200, {"name": "web-1", "image": "soc-playground/host:local"}),
    (f"/containers/{WEB_ID[:12]}", 200, {"name": "web-1", "image": "soc-playground/host:local"}),
    (f"/hosts/{WEB_ID[:12]}/accounts", 200, {"entries": ["root:x:0:0:root:/root:/bin/bash",
                                                         "sre.alice:x:1001:1001::/home/sre.alice:/bin/bash"]}),
])
def test_each_route_answers(target, status, body):
    service, _ = make()
    assert service.answer("GET", target) == (status, body)


@pytest.mark.parametrize(("target", "status"), [
    ("/hosts/elasticsearch/processes", 404),          # not enrolled
    ("/hosts/soc-playground/processes", 404),         # case-007's golden lead: not a host
    ("/hosts/db-1/processes", 503),                   # enrolled, not running
    ("/hosts/web-1/accounts/nobody/authorized-keys", 404),   # no such user
    ("/hosts/web-1/accounts/bad%20user/authorized-keys", 400),
    ("/hosts/web-1/accounts/-x/authorized-keys", 400),
    ("/hosts/web-1/files/sha256?path=etc%2Fhosts", 400),     # not absolute
    ("/hosts/web-1/files/sha256?path=%2Fetc%2F..%2Fshadow", 400),
    ("/hosts/web-1/files/sha256?path=%2Fetc%2Fhosts%3Bid", 400),
    ("/hosts/web-1/files/sha256", 400),
    ("/hosts/web-1/files/sha256?path=%2Fetc%2Fmissing", 404),
    ("/hosts/web-1/shell", 404),                      # no such route
    ("/hosts/web-1/processes/extra", 404),
    ("/containers/kibana", 404),                      # not inspectable
    (f"/containers/{'k' * 12}", 404),                 # not inspectable, named by id
    ("/hosts/kkkkkkkkkkkk/processes", 404),           # an id that is not an enrolled host
    ("/hosts/web-1/files/sha256?path=%2Fetc", 503),   # not a regular file
    ("/hosts/web-1/files/sha256?path=%2Floop%2Fa", 503),     # a symlink loop
    ("/containers/ghost", 404),
    ("/", 404),
])
def test_the_status_table(target, status):
    service, _ = make()
    assert service.answer("GET", target)[0] == status


def test_a_command_that_fails_is_unavailable_never_an_empty_answer():
    """A replica's `ps` shim without its captured tree exits non-zero: 503, not 200 with nothing."""
    docker = FakeDocker()
    docker.ps = (1, "", "ps-shim: no captured process tree")
    service, _ = make(docker)
    status, body = service.answer("GET", "/hosts/web-1/processes")
    assert status == 503 and "ps-shim" in body["detail"]


def test_ps_runs_by_name_with_the_surfaces_argv_which_the_replica_shim_answers():
    service, docker = make()
    service.answer("GET", "/hosts/web-1/processes")
    assert docker.calls == [("web-1", PS_ARGV)]
    assert PS_ARGV[0] == "ps", "by name, so a replica's shim on PATH answers"
    shim = (HERE.parents[2] / "hosts" / "base" / "ps-shim").read_text()
    assert f'if [ "$*" = "{" ".join(PS_ARGV[1:])}" ]' in shim, "the shim matches another argv"


@pytest.mark.parametrize("target", [
    "/hosts", "/hosts/web-1/accounts", "/hosts/web-1/accounts/sre.alice/authorized-keys",
    "/hosts/web-1/accounts/root/authorized-keys", "/hosts/web-1/files/sha256?path=%2Fetc%2Fhosts",
    "/hosts/web-1/files/sha256?path=%2Fetc%2Fmissing", "/hosts/web-1/packages", "/containers/web-1"])
def test_only_the_process_list_runs_anything_in_a_host(target):
    """Every other verb reads files through the daemon: the defender's queries leave no process
    or file-access trace in the telemetry it investigates."""
    service, docker = make()
    service.answer("GET", target)
    assert docker.calls == []


def test_the_package_list_reads_dpkgs_status_as_dpkg_query_shows_it():
    assert eq.dpkg_packages(DPKG_STATUS) == ["bash 5.1", "openssh-server 8.9"]


def test_nothing_inspectable_means_container_inspect_is_not_served_for_an_enrolled_host():
    """The frozen deployment: hosts answered, nothing inspectable (#1347's named gap)."""
    service, _ = make(inspectable=())
    assert service.answer("GET", "/containers/web-1")[0] == 404
    assert service.answer("GET", "/hosts/web-1/processes")[0] == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_get_only(method):
    service, docker = make()
    assert service.answer(method, "/hosts/web-1/processes")[0] == 405
    assert not docker.calls


def test_a_daemon_that_cannot_answer_is_unavailable():
    class Down(FakeDocker):
        def container(self, ref):
            raise eq.Unavailable("docker daemon: ConnectionRefusedError")

    service, _ = make(Down())
    assert service.answer("GET", "/hosts/web-1/processes")[0] == 503


def _frame(kind, data):
    return bytes([kind, 0, 0, 0]) + len(data).to_bytes(4, "big") + data


def test_the_docker_stream_is_demultiplexed():
    assert eq.demux(_frame(1, b"out-a") + _frame(2, b"err") + _frame(1, b"out-b")) == (b"out-aout-b", b"err")


@pytest.fixture
def daemon(tmp_path):
    """A Docker Engine API on a unix socket: inspect answered chunked, exec start as a raw stream
    read to close (the daemon's shapes), anything unknown 404."""
    import socketserver

    path = str(tmp_path / "docker.sock")
    seen = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def address_string(self):
            return "unix"

        def _send(self, status, body, *, chunked=False, raw=False):
            self.send_response(status)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            elif not raw:
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if chunked:
                for piece in (body[:5], body[5:]):
                    self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            seen.append(("GET", self.path))
            if self.path == "/containers/web-1/json":
                self._send(200, json.dumps({"Name": "/web-1", "State": {"Running": True}}).encode(), chunked=True)
            elif self.path == "/exec/E1/json":
                polls = sum(1 for x in seen if x == ("GET", "/exec/E1/json"))
                done = polls >= 3   # the daemon records the exit a moment after the stream ends
                self._send(200, json.dumps({"Running": not done, "ExitCode": 3 if done else None}).encode())
            elif self.path == "/containers/web-1/archive?path=%2Fetc%2Fpasswd":
                self._send(200, _tar_of("passwd", b"root:x:0:0::/root:/bin/bash\n"))
            elif self.path == "/containers/web-1/archive?path=%2Fetc%2Fmtab":
                self._send(200, _tar_of("mtab", link="../proc/self/mounts"))
            else:
                self._send(404, b'{"message": "no such container"}')

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(("POST", self.path, body))
            if self.path == "/containers/web-1/exec":
                self._send(201, b'{"Id": "E1"}')
            elif self.path == "/exec/E1/start":
                self._send(200, _frame(1, b"line-1\n") + _frame(2, b"warn") + _frame(1, b"line-2\n"), raw=True)
            else:
                self._send(404, b"{}")

    class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    server = S(path, H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield path, seen
    server.shutdown()


def _tar_of(name, data=b"", *, link=None):
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo(name)
        if link is not None:
            info.type, info.linkname = tarfile.SYMTYPE, link
            t.addfile(info)
        else:
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_the_socket_client_speaks_the_daemons_shapes(daemon):
    path, seen = daemon
    docker = eq.SocketDocker(path)
    assert docker.container("web-1")["State"]["Running"] is True
    assert docker.container("nope") is None
    assert docker.read("web-1", "/etc/passwd") == ("file", b"root:x:0:0::/root:/bin/bash\n")
    assert docker.read("web-1", "/etc/mtab") == ("link", "../proc/self/mounts")
    assert docker.read("web-1", "/etc/missing") is None
    assert docker.exec("web-1", ["ps", "-ef"]) == (3, b"line-1\nline-2\n", b"warn")
    assert ("POST", "/containers/web-1/exec",
            {"AttachStdout": True, "AttachStderr": True, "Tty": False, "Cmd": ["ps", "-ef"]}) in seen


def test_a_daemon_that_is_not_there_is_unavailable(tmp_path):
    with pytest.raises(eq.Unavailable):
        eq.SocketDocker(str(tmp_path / "absent.sock")).container("web-1")


# -- the product adapter against the service -------------------------------------------------------


@pytest.fixture
def served():
    service, docker = make()
    server = ThreadingHTTPServer(("127.0.0.1", 0), eq.make_handler(service))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_the_product_adapter_reads_every_verb_from_the_service(served, monkeypatch):
    """Every verb the product's host-state adapter has, over HTTP, through the transport's own
    URL building; only the credential proxy is stood in for (a GET with the proxy's status
    classes)."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from defender.integrations import host_state_adapter as adapter
    from defender.kit import transport
    from defender.kit.faults import TransportFault, UpstreamFault

    def proxy(ctx, url, *, system, method, body=None, timeout_sec, error_detail=None, write=False):
        assert method == "GET" and body is None
        try:
            with urlopen(url, timeout=5) as reply:
                return json.loads(reply.read())
        except HTTPError as exc:
            raise (TransportFault if exc.code >= 500 else UpstreamFault)(f"{exc.code}") from exc

    monkeypatch.setattr(transport, "record_access", lambda tenant, system: SimpleNamespace(base=served))
    monkeypatch.setattr(transport, "_proxy_request", proxy)
    monkeypatch.setattr(transport, "record_config", lambda tenant, system, prefix, required, **kw: {})
    ctx = SimpleNamespace(tenant=None)
    calls = {
        "health-check": {},
        "container-inspect": {"container_id": "web-1"},
        "proc-tree": {"host": "web-1"},
        "passwd": {"host": "web-1"},
        "authorized-keys": {"host": "web-1", "user": "sre.alice"},
        "fim-checksum": {"host": "web-1", "path": "/etc/hosts"},
        "package-list": {"host": "web-1"},
    }
    assert set(calls) == set(adapter.VERBS), "a verb the service is not driven for"
    got = {verb: adapter.VERBS[verb](ctx, **params) for verb, params in calls.items()}
    assert got["health-check"]["hosts_present"] == ["web-1"] and got["health-check"]["hosts_missing"] == ["db-1"]
    assert got["container-inspect"] == {"container_id": "web-1", "name": "web-1", "image": "soc-playground/host:local"}
    assert got["proc-tree"]["ps_output"].startswith("  PID")
    assert got["passwd"]["entries"][0].startswith("root:")
    assert got["authorized-keys"]["keys"] == ["ssh-ed25519 AAAA alice@laptop", "ssh-rsa BBBB backup"]
    assert got["authorized-keys"]["path"] == "/home/sre.alice/.ssh/authorized_keys"
    assert got["fim-checksum"]["sha256"] == SHA
    assert got["package-list"]["packages"] == ["bash 5.1", "openssh-server 8.9"]
    with pytest.raises(UpstreamFault):
        adapter.VERBS["proc-tree"](ctx, host="soc-playground")
    with pytest.raises(TransportFault):
        adapter.VERBS["proc-tree"](ctx, host="db-1")
