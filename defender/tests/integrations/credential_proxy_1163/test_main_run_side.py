"""#1163 run side, the shipped program: `python -m defender.credential_proxy` run as a process
against an operator config file takes its OpenBao token from files alone and never prints it."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

from defender._git import REPO_ROOT
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.shared._fixture_uuid import fixture_uuid

TENANT = fixture_uuid("tenant:1163-main")
KEY = "transit-key-1163"
FILE_TOKEN = "bao-token-from-file-1163-q7w2e9"
ENV_TOKEN = "bao-token-from-env-1163-z4x8c1"
START_SEC, EXIT_SEC, REFUSE_SEC = 30, 30, 15


def _config(tmp_path: Path, bao_url: str, **token: str) -> Path:
    exports = tmp_path / "exports"
    exports.mkdir()
    config = {"openbao_addr": bao_url, "kv_mount": "kv", "transit_mount": "transit",
              "tenant_keys": {TENANT: KEY}, "tenant_exports": {TENANT: str(exports)},
              "audit_path": str(tmp_path / "audit.jsonl"), **token}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def _start(config: Path, port: int) -> subprocess.Popen[str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO_ROOT),
           "DEFENDER_CREDENTIAL_PROXY_CONFIG": str(config),
           "DEFENDER_CREDENTIAL_PROXY_PORT": str(port), "DEFENDER_LOG_LEVEL": "DEBUG",
           "VAULT_TOKEN": ENV_TOKEN, "BAO_TOKEN": ENV_TOKEN, "VAULT_ADDR": "http://decoy.invalid"}
    return subprocess.Popen([sys.executable, "-m", "defender.credential_proxy"], cwd=REPO_ROOT,
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


def test_m1_the_served_proxy_uses_the_token_file_and_prints_no_token(tmp_path):
    """Served from a config naming a token file, with token variables in its environment: the
    OpenBao calls carry the file's token alone, and no token is in the program's output. O5."""
    token_file = tmp_path / "bao-token"
    token_file.write_text(FILE_TOKEN + "\n", encoding="utf-8")
    port = H.free_port()
    with H.upstream() as bao:
        bao.replies[f"/v1/transit/verify/{KEY}"] = (
            200, {"Content-Type": "application/json"}, b'{"data": {"valid": true}}')
        proc = _start(_config(tmp_path, bao.url, openbao_token_file=str(token_file)), port)
        try:
            deadline = time.monotonic() + START_SEC
            while not _listening(port) and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            assert _listening(port), "the program did not start serving"
            tok = T.token(TENANT, {("identity", "r")})
            httpx.post(f"http://127.0.0.1:{port}/v1/request", json={
                "system": "identity", "method": "GET", "url": "http://x.invalid/a",
                "headers": {}, "body": None}, headers={"Authorization": f"Bearer {tok}"},
                timeout=20)
        finally:
            out = _stop(proc)

    sent = [s.header("X-Vault-Token") for s in bao.seen]
    assert sent, "positive control: the proxy called OpenBao"
    assert set(sent) == {FILE_TOKEN}, sent
    assert f"http://127.0.0.1:{port}" in out, "positive control: the program's log is read"
    for secret in (FILE_TOKEN, ENV_TOKEN):
        assert secret not in out, "an OpenBao token reached the program's output"


def test_m2_a_config_naming_no_token_does_not_fall_back_to_the_environment(tmp_path):
    """No `openbao_token` or token file, a token in `VAULT_TOKEN`: the program refuses to start
    (exit 2), calls no OpenBao and prints no token. O5."""
    port = H.free_port()
    with H.upstream() as bao:
        proc = _start(_config(tmp_path, bao.url), port)
        try:
            proc.wait(timeout=REFUSE_SEC)
        except subprocess.TimeoutExpired:
            pass
        served = _listening(port)
        out = _stop(proc)

    assert not served, "the program is serving with a token from the environment"
    assert proc.returncode == 2, (proc.returncode, out)
    assert bao.seen == []
    assert "credential proxy cannot start" in out, "positive control: the refusal is logged"
    assert ENV_TOKEN not in out
