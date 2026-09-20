"""M1/O7 — the real exec seam never leaves the container.

Every other test in this suite drives `ctl.activate`/`revert`/`status`
through `FakeExecSeam` and never touches `chaos.ctl.DockerExecSeam` at all —
by design, so the unit suite needs no live stack. That leaves the one line
that actually decides O7 (no agent-attributable host-side network call)
unexercised. A host-side `urllib`/`requests` hit against `127.0.0.1:8001`
would still pass every other test in this file, and the design's own live
check proved exactly that call leaves a `gateway -> cmdb:8080` flow in the
agent's Zeek telemetry.

`DockerExecSeam(run=...)` injects `subprocess.run` so this can be checked
without actually shelling out.
"""
from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from chaos import ctl


def _fake_run(calls):
    def run(args, **kwargs):
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="{}", stderr="")

    return run


def test_every_real_seam_call_shells_docker_context_exec():
    calls: list[list[str]] = []
    seam = ctl.DockerExecSeam(run=_fake_run(calls))

    seam.cmdb_request("GET", "/health")
    seam.es_request("GET", "/_ingest/pipeline/*@custom")
    seam.read_container_file("cmdb", "/opt/cmdb/inventory.yaml")

    assert len(calls) == 3, calls
    for args in calls:
        assert args[:4] == ["docker", "--context", "soc-playground", "exec"], args


def test_cmdb_request_execs_inside_the_cmdb_container_not_the_host():
    calls: list[list[str]] = []
    seam = ctl.DockerExecSeam(run=_fake_run(calls))
    seam.cmdb_request("POST", "/admin/overlay/web-1", {"owner": "team.x"})

    args = calls[0]
    assert "cmdb" in args, args
    # The request itself must live inside the exec'd script, not as argv the
    # devcontainer host would resolve — nothing here may name 127.0.0.1:8001
    # (the host-published port a direct host-side call would hit).
    blob = " ".join(args)
    assert "127.0.0.1:8001" not in blob


def test_es_request_execs_inside_the_elasticsearch_container():
    calls: list[list[str]] = []
    seam = ctl.DockerExecSeam(run=_fake_run(calls))
    seam.es_request("GET", "/_ingest/pipeline/*@custom")

    args = calls[0]
    assert "elasticsearch" in args, args


def test_ctl_module_imports_no_host_side_http_client():
    """A `urllib.request`/`requests` import at module level would be a
    standing host-side transport, independent of what DockerExecSeam's
    methods happen to do at call time."""
    tree = ast.parse(Path(ctl.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"requests", "httpx", "http", "urllib"}, imported
