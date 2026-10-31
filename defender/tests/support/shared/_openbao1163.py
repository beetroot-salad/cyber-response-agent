"""#1163 OpenBao test server: one isolated set of mounts and policies per test.

Mirrors `_postgres1339`: skipped where `DEFENDER_TEST_OPENBAO_ADDR` is unset locally, failed where
it is unset in CI (the test job runs `openbao/openbao:2.4.1 server -dev` for it). Each test gets
a KV v2 mount and a transit mount named by a fresh uuid, and every policy and token it makes is
named under that uuid; all are removed when the test ends. This module applies policy text it is
handed and never writes a policy of its own.
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

ADDR_ENV = "DEFENDER_TEST_OPENBAO_ADDR"
TOKEN_ENV = "DEFENDER_TEST_OPENBAO_TOKEN"
#: Optional: the server's docker container name, for the audit-device case (it reads the audit
#: file with `docker exec`). Unset: that case skips locally and fails in CI.
CONTAINER_ENV = "DEFENDER_TEST_OPENBAO_CONTAINER"


#: The two values, taken out of `os.environ` at configure time: the run process under test must
#: hold no issuer-named variable (#1108 P4 O8), and CI sets these job-wide. `None` before configure.
_CACHED: tuple[str | None, str | None, str | None] | None = None


def pytest_configure(config: pytest.Config) -> None:
    """Read both variables once and remove them from this process's environment. An xdist worker
    gets them from its controller (`pytest_configure_node`), which has already removed them."""
    global _CACHED
    handed = getattr(config, "workerinput", {}).get("openbao1163")
    if handed is not None:
        _CACHED = (handed[0], handed[1], handed[2])
    else:
        _CACHED = (os.environ.pop(ADDR_ENV, None), os.environ.pop(TOKEN_ENV, None),
                   os.environ.pop(CONTAINER_ENV, None))


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    node.workerinput["openbao1163"] = list(_CACHED or (None, None, None))


def server() -> tuple[str, str]:
    """The test server's address and root token; skipped where none is set, but never in CI."""
    addr, token = _CACHED[:2] if _CACHED is not None else (
        os.environ.get(ADDR_ENV), os.environ.get(TOKEN_ENV))
    if not addr or not token:
        if os.environ.get("CI"):
            pytest.fail(f"{ADDR_ENV}/{TOKEN_ENV} are not set in CI; the test job's OpenBao "
                        "service provides them")
        pytest.skip(f"{ADDR_ENV}/{TOKEN_ENV} are not set")
    return addr.rstrip("/"), token


@dataclass
class Bao:
    """One test's slice of the server: its own mounts, and the policies it has applied."""

    addr: str
    root_token: str
    tag: str
    policies: list[str] = field(default_factory=list)

    @property
    def kv_mount(self) -> str:
        return f"kv-{self.tag}"

    @property
    def transit_mount(self) -> str:
        return f"transit-{self.tag}"

    def call(self, method: str, path: str, *, token: str | None = None,
             json: Any = None) -> Any:
        """One raw API call (`/v1/<path>`) as `token` (default root); the `httpx.Response`."""
        import httpx

        return httpx.request(method, f"{self.addr}/v1/{path}", json=json, timeout=10,
                             headers={"X-Vault-Token": token or self.root_token})

    def ok(self, method: str, path: str, **kw: Any) -> Any:
        response = self.call(method, path, **kw)
        assert response.status_code < 300, (method, path, response.status_code, response.text)
        return response.json() if response.content else None

    def apply_policy(self, role: str, hcl: str) -> str:
        """Write `hcl` as this test's policy `<role>-<tag>`; returns its name."""
        name = f"{role}-{self.tag}"
        self.ok("PUT", f"sys/policies/acl/{name}", json={"policy": hcl})
        self.policies.append(name)
        return name

    def token_for(self, *policies: str) -> str:
        """A child token holding only `policies` (no default policy), an hour long."""
        body = self.ok("POST", "auth/token/create", json={
            "policies": list(policies), "no_default_policy": True, "ttl": "1h",
            "display_name": f"t1163-{self.tag}"})
        return body["auth"]["client_token"]


def isolated(addr: str, root_token: str) -> Iterator[Bao]:
    bao = Bao(addr, root_token, uuid.uuid4().hex[:12])
    bao.ok("POST", f"sys/mounts/{bao.kv_mount}", json={"type": "kv", "options": {"version": "2"}})
    try:
        bao.ok("POST", f"sys/mounts/{bao.transit_mount}", json={"type": "transit"})
        try:
            yield bao
        finally:
            bao.call("DELETE", f"sys/mounts/{bao.transit_mount}")
    finally:
        bao.call("DELETE", f"sys/mounts/{bao.kv_mount}")
        for name in bao.policies:
            bao.call("DELETE", f"sys/policies/acl/{name}")


class AuditLog:
    """A file audit device enabled on the test server for one test. `text()` is the file's whole
    content, read with `docker exec` into the server's container."""

    def __init__(self, bao: Bao, container: str) -> None:
        self.bao, self.container = bao, container
        self.device = f"audit-{bao.tag}"
        self.path = f"/tmp/audit-{bao.tag}.log"

    def text(self) -> str:
        import subprocess

        done = subprocess.run(["docker", "exec", self.container, "cat", self.path],
                              capture_output=True, text=True, timeout=30, check=True)
        return done.stdout

    def hash_of(self, value: str) -> str:
        """The audit device's own HMAC of `value` (what the log holds in its place)."""
        body = self.bao.ok("POST", f"sys/audit-hash/{self.device}", json={"input": value})
        return body["hash"]


def audit_log(bao: Bao) -> Iterator[AuditLog]:
    container = _CACHED[2] if _CACHED is not None else os.environ.get(CONTAINER_ENV)
    if not container:
        if os.environ.get("CI"):
            pytest.fail(f"{CONTAINER_ENV} is not set in CI; the audit case reads the server's "
                        "audit file through docker exec")
        pytest.skip(f"{CONTAINER_ENV} is not set")
    log = AuditLog(bao, container)
    bao.ok("PUT", f"sys/audit/{log.device}", json={
        "type": "file", "options": {"file_path": log.path}})
    try:
        yield log
    finally:
        bao.call("DELETE", f"sys/audit/{log.device}")
        import subprocess

        subprocess.run(["docker", "exec", container, "rm", "-f", log.path],
                       capture_output=True, timeout=30, check=False)


@pytest.fixture
def openbao_audit(openbao: Bao) -> Iterator[AuditLog]:
    """A file audit device on the test server, this test's own (marker `openbao`)."""
    yield from audit_log(openbao)


@pytest.fixture
def openbao() -> Iterator[Bao]:
    """This test's isolated slice of the OpenBao test server (marker `openbao`)."""
    yield from isolated(*server())
