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

import pytest

from chaos import ctl
from chaos.seam import SeamError, SeamNotFound


def _fake_run(calls):
    def run(args, **kwargs):
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="{}\n200", stderr="")

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


def _run_returning(stdout: str, rc: int = 0, stderr: str = ""):
    def run(args, **kwargs):
        return subprocess.CompletedProcess(args, rc, stdout=stdout, stderr=stderr)

    return run


def test_an_http_error_from_elasticsearch_is_raised_not_returned():
    """curl exits 0 on a 4xx/5xx. Under the old `(rc, body)` contract a
    wrong password came back as rc 0 with `{"error":..., "status":401}`,
    and the controller recorded a fault that never landed. The seam's only
    outcomes are a payload or an exception."""
    seam = ctl.DockerExecSeam(run=_run_returning('{"error": {"type": "security_exception"}, "status": 401}\n401'))
    with pytest.raises(SeamError) as info:
        seam.es_request("PUT", "/_ingest/pipeline/logs-system.auth@custom", {"processors": []})
    assert info.value.status == 401
    assert not isinstance(info.value, SeamNotFound)


def test_a_404_is_the_distinguishable_not_found_error():
    seam = ctl.DockerExecSeam(run=_run_returning("{}\n404"))
    with pytest.raises(SeamNotFound):
        seam.es_request("GET", "/_ingest/pipeline/logs-system.syslog@custom")
    cmdb = ctl.DockerExecSeam(run=_run_returning('{"detail": "host x not found"}\n404'))
    with pytest.raises(SeamNotFound):
        cmdb.cmdb_request("GET", "/hosts/x")


def test_a_transport_failure_is_raised_not_returned_as_empty():
    """`docker exec` failing (container down, curl rc 7) must not read as
    'nothing there' — that is how an unreachable backend became a page of
    synthesized drift."""
    seam = ctl.DockerExecSeam(run=_run_returning("", rc=7, stderr="curl: (7) Failed to connect"))
    with pytest.raises(SeamError, match="transport"):
        seam.es_request("GET", "/_ingest/pipeline/*@custom")
    with pytest.raises(SeamError):
        ctl.DockerExecSeam(run=_run_returning("", rc=1, stderr="no such container")).read_container_file(
            "cmdb", "/opt/cmdb/inventory.yaml"
        )


def test_a_2xx_returns_the_parsed_body():
    seam = ctl.DockerExecSeam(run=_run_returning('{"acknowledged": true}\n200'))
    assert seam.es_request("PUT", "/_ingest/pipeline/x", {"processors": []}) == {"acknowledged": True}
    assert ctl.DockerExecSeam(run=_run_returning("\n200")).cmdb_request("DELETE", "/admin/overlay/x") == {}


def test_es_request_asks_curl_for_the_http_status():
    """The status line is what the whole contract rests on; curl only emits
    it when asked."""
    calls: list[list[str]] = []
    ctl.DockerExecSeam(run=_fake_run(calls)).es_request("GET", "/_ingest/pipeline/*@custom")
    assert "%{http_code}" in " ".join(calls[0])


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
