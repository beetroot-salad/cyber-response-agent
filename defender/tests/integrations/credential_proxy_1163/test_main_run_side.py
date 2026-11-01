"""#1163 run side, the shipped program: `python -m defender.credential_proxy` run as a process
against an operator config file takes its OpenBao token from files alone and never prints it."""
from __future__ import annotations

import contextlib
import json
import os
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


def _start(config: Path, port: int, *, decoy_addr: str = "http://decoy.invalid") -> subprocess.Popen[str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO_ROOT),
           P.PROXY_ENV_CONFIG: str(config),
           P.PROXY_ENV_PORT: str(port), "DEFENDER_LOG_LEVEL": "DEBUG",
           "VAULT_TOKEN": ENV_TOKEN, "BAO_TOKEN": ENV_TOKEN, "VAULT_ADDR": decoy_addr}
    return subprocess.Popen([sys.executable, "-m", P.PROXY_PROGRAM_MODULE], cwd=REPO_ROOT,
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
        answer = httpx.post(f"http://127.0.0.1:{port}/v1/request", json={
            "system": "identity", "method": "GET", "url": "http://x.invalid/a",
            "headers": {}, "body": None}, headers={"Authorization": f"Bearer {tok}"},
            timeout=40).json()
    finally:
        out = _stop(proc)

    assert answer["fault"] is not None, "positive control: the request was served and classified"
    assert f"http://127.0.0.1:{port}" in out, "positive control: the program's log is read"
    for secret in (FILE_TOKEN, ENV_TOKEN):
        assert secret not in out, "an OpenBao token reached the program's output"


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
