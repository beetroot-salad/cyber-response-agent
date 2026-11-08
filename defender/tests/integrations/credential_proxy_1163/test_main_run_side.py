"""#1163 run side, the shipped program: `python -m defender.credential_proxy` run as a process
against an operator config file takes its OpenBao token from files alone and never prints it."""
from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from defender._git import REPO_ROOT
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _target as P
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.shared._fixture_uuid import fixture_uuid

ENV_TOKEN = "bao-token-from-env-1163-z4x8c1"
FILE_TOKEN = "bao-token-from-file-1163-q7w2e9"
START_SEC, EXIT_SEC, REFUSE_SEC = 30, 30, 15


def _config(tmp_path: Path, **extra: object) -> Path:
    """The operator config of A13/A26 (data root, no tenant list, no OpenBao address)."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    config = {"kv_mount": "kv", "data_root": str(data),
              "audit_path": str(tmp_path / "audit.jsonl"), **extra}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def _start(config: Path, port: int, *, decoy_addr: str = "http://decoy.invalid", before: str | None = None,
           extra_env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    """The shipped program as a process; `before` is code to run first in that process."""
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO_ROOT),
           P.PROXY_ENV_CONFIG: str(config),
           P.PROXY_ENV_PORT: str(port), "DEFENDER_LOG_LEVEL": "DEBUG",
           "VAULT_TOKEN": ENV_TOKEN, "BAO_TOKEN": ENV_TOKEN, "VAULT_ADDR": decoy_addr, **(extra_env or {})}
    argv = ["-m", P.PROXY_PROGRAM_MODULE] if before is None else ["-c", (
        f"{before}\nimport runpy\n"
        f"runpy.run_module({P.PROXY_PROGRAM_MODULE!r}, run_name='__main__', alter_sys=True)")]
    return subprocess.Popen([sys.executable, *argv], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _stop(proc: subprocess.Popen[str]) -> str:
    if proc.poll() is None:
        proc.terminate()
    try:
        out, _ = proc.communicate(timeout=EXIT_SEC)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out


def _await_listening(proc: subprocess.Popen[str], port: int) -> bool:
    deadline = time.monotonic() + START_SEC
    while not _listening(port) and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    return _listening(port)


def test_m1_the_served_proxy_started_from_a_token_file_prints_no_token(tmp_path):
    """Served from a config naming a token file, with token variables in its environment: the
    program serves, answers a request with a fault (OpenBao is the deployment's, not served here) and no token
    is in its output. O5, A26."""
    token_file = tmp_path / "bao-token"
    token_file.write_text(FILE_TOKEN + "\n", encoding="utf-8")
    port = H.free_port()
    proc = _start(_config(tmp_path, **{P.PROXY_CONFIG_TOKEN_FILE_KEY: str(token_file)}), port)
    try:
        assert _await_listening(proc, port), "the program did not start serving"
        tok = T.token(fixture_uuid("tenant:1163-main"), {("identity", "r")})
        reply = httpx.post(f"http://127.0.0.1:{port}/v1/request", json={
            "system": "identity", "method": "GET", "url": "http://x.invalid/a",
            "headers": {}, "body": None}, headers={"Authorization": f"Bearer {tok}"}, timeout=40)
        answer = T.answer_of(reply.content)
    finally:
        out = _stop(proc)

    assert answer["fault"] is not None, "positive control: the request was served and classified"
    assert f"http://127.0.0.1:{port}" in out, "positive control: the program's log is read"
    for secret in (FILE_TOKEN, ENV_TOKEN):
        assert secret not in out, "an OpenBao token reached the program's output"


def test_m1_openbao_calls_carry_the_token_file_content_not_the_environments(
        tmp_path, data_root, monkeypatch):
    """Built in-process from a config naming a token file, with `VAULT_TOKEN` and OpenBao-address variables as decoys:
    every OpenBao request carries the file's token (trailing newline stripped) and goes to the deployment's address,
    not an address from the environment. O5, A13, A26 (r8.3: the proxy uses the deployment's address)."""
    from fastapi.testclient import TestClient

    from defender.configuration.issuer import DEPLOYMENT_ISSUER

    for name in ("DEFENDER_OPENBAO_ADDR", "VAULT_ADDR", "BAO_ADDR"):
        monkeypatch.setenv(name, "https://decoy-bao.invalid:8200")
    monkeypatch.setenv("VAULT_TOKEN", ENV_TOKEN)
    monkeypatch.setenv("BAO_TOKEN", ENV_TOKEN)
    token_file = tmp_path / "bao-token"
    token_file.write_text(FILE_TOKEN + "\n", encoding="utf-8")
    tid, calls = fixture_uuid("tenant:1163-main-file"), []

    def openbao(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"data": {"valid": True}})

    config = {"kv_mount": "kv", "data_root": str(data_root),
              "audit_path": str(tmp_path / "audit.jsonl"),
              P.PROXY_CONFIG_TOKEN_FILE_KEY: str(token_file)}
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH), tenant_id=tid):
        client = TestClient(P.app_from_config(config, transport=httpx.MockTransport(openbao)))
        T.ask(client, T.token(tid, {("identity", "r")}, signer=H.FakeSigner()), "identity",
              "GET", f"{up.url}{T.BASE_PATH}/users/x")

    assert calls, "positive control: the proxy called OpenBao"
    assert {c.headers.get("X-Vault-Token") for c in calls} == {FILE_TOKEN}
    deployment = httpx.URL(DEPLOYMENT_ISSUER.openbao_url)
    assert {(c.url.scheme, c.url.host, c.url.port) for c in calls} == {(deployment.scheme, deployment.host, deployment.port)}


def test_m2_a_config_naming_no_token_does_not_fall_back_to_the_environment(tmp_path):
    """No `openbao_token` or token file, a token in `VAULT_TOKEN` and a server in `VAULT_ADDR`:
    the program refuses to start (exit 2), calls that server never and prints no token. O5."""
    port = H.free_port()
    with H.upstream() as bao:
        proc = _start(_config(tmp_path), port, decoy_addr=bao.url)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=REFUSE_SEC)
        served = _listening(port)
        out = _stop(proc)

    assert not served, "the program is serving with a token from the environment"
    assert proc.returncode == P.PROXY_REFUSAL_EXIT, (proc.returncode, out)
    assert bao.seen == []
    assert P.PROXY_REFUSAL_LOG in out, "positive control: the refusal is logged"
    assert ENV_TOKEN not in out


@pytest.mark.parametrize("key", P.REMOVED_CONFIG_KEYS)
def test_m3_a_config_still_naming_a_removed_key_refuses_to_start(tmp_path, key):
    """An old config (`tenant_keys`, `tenant_exports`, `transit_mount` or `openbao_addr`) makes
    the program refuse to start: exit 2, logged, not serving. A26, upgrade note."""
    token_file = tmp_path / "bao-token"
    token_file.write_text(FILE_TOKEN + "\n", encoding="utf-8")
    old = {key: {} if key.startswith("tenant_") else "x",
           P.PROXY_CONFIG_TOKEN_FILE_KEY: str(token_file)}
    port = H.free_port()
    proc = _start(_config(tmp_path, **old), port)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=REFUSE_SEC)
    served = _listening(port)
    out = _stop(proc)

    assert not served
    assert proc.returncode == P.PROXY_REFUSAL_EXIT, (proc.returncode, out)
    assert P.PROXY_REFUSAL_LOG in out
    assert FILE_TOKEN not in out


# --- #1428 O1: bytes a run never takes do not hold the connection ---------------------------

DELIVERY_MS = 60_000
#: Makes the HTTP protocol underneath the shipped program write the delivery limit of each
#: connection it is handed to the file named by OBSERVED: the option is read off the connection
#: the program really serves.
_OBSERVE_THE_LIMIT = """
import os, socket
from uvicorn.protocols.http.h11_impl import H11Protocol
_made = H11Protocol.connection_made
def connection_made(self, transport):
    limit = transport.get_extra_info("socket").getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT)
    with open(os.environ["OBSERVED"], "a") as out:
        out.write(str(limit) + "\\n")
    return _made(self, transport)
H11Protocol.connection_made = connection_made
"""


def test_o1_the_served_proxy_gives_a_connection_the_delivery_limit(tmp_path):
    """A connection to the shipped program carries the 60 s limit. O1, O5."""
    port = H.free_port()
    observed = tmp_path / "observed"
    proc = _start(_config(tmp_path, openbao_token="t-1428"), port, before=_OBSERVE_THE_LIMIT,
                  extra_env={"OBSERVED": str(observed)})
    try:
        assert _await_listening(proc, port), _stop(proc)
        with socket.create_connection(("127.0.0.1", port)):
            deadline = time.monotonic() + START_SEC
            while not observed.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
    finally:
        _stop(proc)

    assert set(observed.read_text().split()) == {str(DELIVERY_MS)}


def _read_on(conn: socket.socket, got: list[int]) -> None:
    """Read `conn` to its end, noting each piece's size in `got`."""
    while piece := conn.recv(1 << 20):
        got.append(len(piece))


def test_o1_a_reader_that_takes_nothing_past_the_limit_loses_the_connection():
    """A reply far past the socket buffers to a reader that takes nothing: once the limit has
    passed the connection is dropped, so reading on gets a reset where, without the limit, the
    whole reply is still there. Run on the protocol the program serves with."""
    from defender.credential_proxy._connections import DeliveryLimited

    class TwoSeconds(DeliveryLimited):
        limit_sec = 2

    async def endless(_scope, _receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        for _ in range(96):
            await send({"type": "http.response.body", "body": b"x" * 65536, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    with H.serve_asgi(endless, http=TwoSeconds) as url:
        host, port = url.removeprefix("http://").split(":")
        with socket.create_connection((host, int(port))) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            time.sleep(5)
            conn.settimeout(10)
            got: list[int] = []
            with pytest.raises(ConnectionResetError):
                _read_on(conn, got)

    assert sum(got) < 6 * 2**20


# --- #1428: the limit leaves the program's start and stop as uvicorn gives them ----------------


def test_o5_an_interrupt_ends_the_program_cleanly(tmp_path):
    """Ctrl-C ends the served program with exit code 0 and no traceback."""
    port = H.free_port()
    # A test runner may have SIGINT ignored, which its children inherit and which hides the interrupt.
    proc = _start(_config(tmp_path, openbao_token="t-1428"), port,
                  before="import signal\nsignal.signal(signal.SIGINT, signal.default_int_handler)")
    try:
        assert _await_listening(proc, port), _stop(proc)
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=EXIT_SEC)
    finally:
        _stop(proc)

    assert (proc.returncode, "Traceback" in out) == (0, False), out


def test_o5_a_host_name_is_served_on_every_address_it_resolves_to(tmp_path):
    """Set to `localhost`, the program accepts on each of the name's addresses, IPv6 included."""
    port = H.free_port()
    addresses = {info[4][0]: info[0] for info in socket.getaddrinfo("localhost", port, type=socket.SOCK_STREAM)}
    if len(addresses) < 2:
        pytest.skip(f"localhost resolves only to {list(addresses)} here: one address proves nothing")
    proc = _start(_config(tmp_path, openbao_token="t-1428"), port,
                  extra_env={"DEFENDER_CREDENTIAL_PROXY_HOST": "localhost"})
    try:
        assert _await_listening(proc, port), _stop(proc)
        refused = []
        for address, family in addresses.items():
            with socket.socket(family) as s:
                s.settimeout(1)
                if s.connect_ex((address, port)) != 0:
                    refused.append(address)
    finally:
        _stop(proc)

    assert refused == []


def test_o5_a_platform_without_the_delivery_limit_refuses_to_start(tmp_path):
    """Where the kernel option does not exist the program says so and stops, rather than announce
    itself and leave each caller hanging on a connection it cannot serve."""
    port = H.free_port()
    proc = _start(_config(tmp_path, openbao_token="t-1428"), port,
                  before="import socket\ndel socket.TCP_USER_TIMEOUT")
    try:
        code = proc.wait(timeout=REFUSE_SEC)
    finally:
        out = _stop(proc)

    assert code == P.PROXY_REFUSAL_EXIT, out
    assert P.PROXY_REFUSAL_LOG in out
