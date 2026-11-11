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
from http.server import ThreadingHTTPServer
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
SHA = "a" * 64


class FakeDocker:
    """Containers by name: `running`, and per-argv answers (exit, stdout, stderr)."""

    def __init__(self):
        self.containers = {
            "web-1": {"running": True, "image": "soc-playground/host:local"},
            "db-1": {"running": False, "image": "soc-playground/host:local"},
            "kibana": {"running": True, "image": "kibana:9"},
        }
        self.calls = []
        self.answers = {
            tuple(PS_ARGV): (0, "  PID  PPID USER\n    1     0 root  init\n", ""),
            ("cat", "/etc/passwd"): (0, PASSWD, ""),
            ("getent", "passwd", "sre.alice"): (0, "sre.alice:x:1001:1001::/home/sre.alice:/bin/bash\n", ""),
            ("getent", "passwd", "root"): (0, "root:x:0:0:root:/root:/bin/bash\n", ""),
            ("cat", "/home/sre.alice/.ssh/authorized_keys"): (0, KEYS, ""),
            ("cat", "/root/.ssh/authorized_keys"): (1, "", "cat: /root/.ssh/authorized_keys: No such file or directory"),
            ("sha256sum", "--", "/etc/hosts"): (0, f"{SHA}  /etc/hosts\n", ""),
            ("sha256sum", "--", "/etc/missing"): (1, "", "sha256sum: /etc/missing: No such file or directory"),
            ("dpkg-query", "-W", "-f=${Package} ${Version}\\n"): (0, "bash 5.1\nopenssh-server 8.9\n\n", ""),
        }

    def running(self, name):
        c = self.containers.get(name)
        return None if c is None else c["running"]

    def inspect(self, name):
        c = self.containers.get(name)
        return None if c is None else {"Name": f"/{name}", "Config": {"Image": c["image"]}}

    def exec(self, name, argv):
        self.calls.append((name, list(argv)))
        code, out, err = self.answers.get(tuple(argv), (127, "", f"{argv[0]}: not found"))
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
])
def test_each_route_answers_from_its_one_fixed_command(target, status, body):
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
    ("/containers/ghost", 404),
    ("/", 404),
])
def test_the_status_table(target, status):
    service, _ = make()
    assert service.answer("GET", target)[0] == status


def test_a_command_that_fails_is_unavailable_never_an_empty_answer():
    """A replica's `ps` shim without its captured tree exits non-zero: 503, not 200 with nothing."""
    docker = FakeDocker()
    docker.answers[tuple(PS_ARGV)] = (1, "", "ps-shim: no captured process tree")
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
        def running(self, name):
            raise eq.Unavailable("docker daemon: ConnectionRefusedError")

    service, _ = make(Down())
    assert service.answer("GET", "/hosts/web-1/processes")[0] == 503


def test_the_docker_stream_is_demultiplexed_and_a_chunked_answer_dechunked():
    frame = lambda kind, data: bytes([kind, 0, 0, 0]) + len(data).to_bytes(4, "big") + data  # noqa: E731
    assert eq.demux(frame(1, b"out-a") + frame(2, b"err") + frame(1, b"out-b")) == (b"out-aout-b", b"err")
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: x\r\n\r\n"
           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    assert eq.parse_response(raw) == (200, {"transfer-encoding": "chunked", "content-type": "x"}, b"hello world")


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
