"""The transport's credential never appears on a command line: every process monitor on the
target (Falco, host process metrics) reads argv and ships it into the very telemetry the agent
queries. Driven through the real transport, with a `docker` that runs the container half locally
against a local HTTP server."""
from __future__ import annotations

import base64
import http.server
import json
import os
import shutil
import threading

import pytest

from defender.systems.verbs import VerbContext
from defender.integrations import _stub_transport as transport
from defender.tests.support.tenancy import _tenants1106

SECRET = "S3cretValue42"

# `docker --context C exec -i CONTAINER <cmd…>`: log the argv it was handed, then run <cmd…> here.
FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$ARGV_LOG"
shift 5
exec "$@"
"""
# The in-container shell expands the credential, so curl's own argv is the one a monitor sees.
FAKE_CURL = """#!/bin/sh
printf '%s\\n' "$*" >> "$ARGV_LOG"
exec "$REAL_CURL" "$@"
"""


@pytest.fixture
def server():
    seen: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 — http.server's dispatch name
            seen["path"] = self.path
            seen["body"] = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            scheme, _, token = (self.headers.get("Authorization") or "").partition(" ")
            seen["user"] = base64.b64decode(token).decode() if scheme == "Basic" else ""
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *_):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def test_the_credential_reaches_the_server_but_no_argv(tmp_path, monkeypatch, server):
    url, seen = server
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_curl = shutil.which("curl")
    assert real_curl, "curl is needed on PATH"
    for name, script in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
        (bin_dir / name).write_text(script)
        (bin_dir / name).chmod(0o755)
    argv_log = tmp_path / "argv.log"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "ARGV_LOG": str(argv_log),
           "REAL_CURL": real_curl, "ELASTIC_PASSWORD": SECRET}
    ctx = VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env=env,
                      tenant=_tenants1106.fixture_run_tenant())
    monkeypatch.setattr(transport, "docker_context", lambda ctx, system: "fake")  # lint-monkeypatch: ok — the docker-exec-curl transport has no in-process DI seam (tests/integrations/test_ticket_adapter.py's established pattern)

    rc, out, err = transport.docker_exec_curl(
        ctx, "elasticsearch", f"{url}/_query", method="POST",
        body={"query": "FROM x | LIMIT 1"}, auth="elastic:${ELASTIC_PASSWORD}", system="elastic")

    assert (rc, transport.split_status(out)[1]) == (0, "200"), err
    assert seen["user"] == f"elastic:{SECRET}"
    assert seen["body"] == '{"query": "FROM x | LIMIT 1"}'
    logged = argv_log.read_text()
    assert logged.count("-X POST") == 2, logged  # both docker's and curl's argv were seen
    assert SECRET not in logged


def test_the_host_write_rides_the_same_transport_and_leaks_no_secret_to_argv(
        tmp_path, monkeypatch, server):
    """The comment action (the host write entry, #1359 D-6) reaches a real HTTP server through the
    same docker-exec-curl chain: one POST on the key's comments path carrying the body, while a
    secret in the run env appears on no command line. O3."""
    from defender.integrations import ticket_adapter

    url, seen = server
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_curl = shutil.which("curl")
    assert real_curl, "curl is needed on PATH"
    for name, script in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
        (bin_dir / name).write_text(script)
        (bin_dir / name).chmod(0o755)
    argv_log = tmp_path / "argv.log"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "ARGV_LOG": str(argv_log),
           "REAL_CURL": real_curl, "ELASTIC_PASSWORD": SECRET, "TICKET_PASSWORD": SECRET}
    ctx = VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env=env,
                      tenant=_tenants1106.fixture_run_tenant())
    monkeypatch.setattr(transport, "docker_context", lambda ctx, system: "fake")  # lint-monkeypatch: ok — the docker-exec-curl transport has no in-process DI seam (tests/integrations/test_ticket_adapter.py's established pattern)
    shaped = {"URL_BASE": url, "BASTION_HOST": "web-1", "TIMEOUT_SEC": "10"}
    monkeypatch.setattr(  # lint-monkeypatch: ok — same: the config is the only thing replaced
        transport, "load_config",
        lambda ctx, system, prefix, required=transport.REQUIRED_CONFIG_KEYS_TEMPLATE: {
            k: shaped.get(k, f"stub-{k}") for k in required})

    link = ticket_adapter.add_case_comment(ctx, key="SOC-7", body="the findings")

    assert link == f"{url}/tickets/SOC-7"
    assert json.loads(seen["body"])["body"] == "the findings"
    assert seen["path"] == "/tickets/SOC-7/comments"
    logged = argv_log.read_text()
    assert "-X POST" in logged, logged
    assert SECRET not in logged
