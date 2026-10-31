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


def server() -> tuple[str, str]:
    """The test server's address and root token; skipped where none is set, but never in CI."""
    addr, token = os.environ.get(ADDR_ENV), os.environ.get(TOKEN_ENV)
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


@pytest.fixture
def openbao() -> Iterator[Bao]:
    """This test's isolated slice of the OpenBao test server (marker `openbao`)."""
    yield from isolated(*server())
