"""#1108 P4 / #1214: the credential provider's wire behaviour, each case a wrong-but-green production variant.
The TLS case is a real local TLS server whose certificate the configured CA did not sign."""
from __future__ import annotations

import json
import base64
import logging
import time

import httpx
import pytest

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender.tests.support.shared._tls_server import self_signed, tls_server
from defender.tests.support.tenancy._active1214 import generation_fields

SECRET_ID = "p4-secret-id-9e7f3b"


def _credential(t: Any, tmp_path: Path, *, openbao_url: str, transport: Any = None, ca_cert: str | None = None,
                fields: dict | None = None) -> Any:
    """`forge_credential` (GAP-C-2) for `t` over a live generation whose host secret file holds `SECRET_ID`
    (or `fields`), against `openbao_url`; `config` carries `issuer_url`, `openbao_url` and `ca_cert`."""
    from defender.learning.author.version_control import forge_credential

    if fields is None:
        fields = generation_fields(t.tenant_id, tmp_path / "secrets")
        fields["host_secret_file"].parent.mkdir(parents=True, exist_ok=True)
        fields["host_secret_file"].write_text(SECRET_ID + "\n", encoding="utf-8")
    config = SimpleNamespace(issuer_url=f"{openbao_url}/v1/identity/oidc", openbao_url=openbao_url, ca_cert=ca_cert)
    return forge_credential(t.tenant_id, "drain", directory=t.directory_with(generations=[fields]), config=config,
                            transport=transport)


@pytest.fixture
def tls_issuer(tmp_path):
    """A local HTTPS server with a self-signed certificate; the CA the config names is another."""
    trusted_pem, _ = self_signed("the configured CA", san=False)
    (tmp_path / "trusted.pem").write_bytes(trusted_pem)
    token = json.dumps({"auth": {"client_token": "tok"}}).encode()
    with tls_server(tmp_path, lambda *_: (200, token)) as server:
        yield server.port, server.got, tmp_path


def test_r6_a_tls_server_the_configured_ca_did_not_sign_is_refused_and_gets_no_secret(
        p4_tenant, tls_issuer):
    from defender.learning.author.version_control import ForgejoAuthError

    port, got, folder = tls_issuer
    credential = _credential(p4_tenant, folder, openbao_url=f"https://localhost:{port}",
                             ca_cert=str(folder / "trusted.pem"))
    with pytest.raises(Exception) as refused:  # noqa: PT011 — the class is the code's choice
        credential.token()
    assert isinstance(refused.value, ForgejoAuthError), repr(refused.value)
    assert got == [], f"the secret reached a server the configured CA did not sign: {got}"
    assert SECRET_ID not in str(refused.value)


def test_r6_the_login_never_follows_a_redirect(p4_tenant, tmp_path):
    from defender.learning.author.version_control import ForgejoAuthError

    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.content.decode()))
        if request.url.host == "openbao.test":
            return httpx.Response(307, headers={"Location": "https://evil.invalid/steal"})
        return httpx.Response(200, json={"auth": {"client_token": "tok"}})

    credential = _credential(p4_tenant, tmp_path, openbao_url="https://openbao.test",
                             transport=httpx.MockTransport(handler))
    with pytest.raises(ForgejoAuthError):
        credential.token()
    assert [h for h, _ in seen if h == "evil.invalid"] == [], "the login body was re-POSTed"
    assert len(seen) == 1


def test_r6_an_http_issuer_is_refused_before_any_request(p4_tenant, tmp_path):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        return httpx.Response(200, json={"auth": {"client_token": "tok"}})

    credential = _credential(p4_tenant, tmp_path, openbao_url="http://openbao:8200",
                             transport=httpx.MockTransport(handler))
    with pytest.raises(Exception):  # noqa: B017, PT011
        credential.token()
    assert seen == [], f"the AppRole secret was POSTed to a cleartext issuer: {seen}"


def test_r6_no_secret_reaches_a_log_record_or_an_error_text(p4_tenant, tmp_path, caplog):
    from defender.learning.author.version_control import ForgejoAuthError
    from defender.tests.support.tenancy._active1214 import provision_generation
    from defender.tests.tenancy.lifecycle_1214._fakes import FakeOpenBao

    bao = FakeOpenBao()
    management = httpx.Client(transport=httpx.MockTransport(bao.handle), base_url="https://openbao.test",
                              headers={"X-Vault-Token": bao.management_token})
    fields = provision_generation(management, p4_tenant.tenant_id, tmp_path / "secrets")
    secret = fields["host_secret_file"].read_text(encoding="utf-8").strip()

    def signed(request: httpx.Request) -> httpx.Response:
        # The fake mints opaque strings; the credential decodes claims, so give the token a JWT's shape.
        answer = bao.handle(request)
        if request.method != "GET" or "/identity/oidc/token/" not in request.url.path or answer.status_code != 200:
            return answer
        part = lambda doc: base64.urlsafe_b64encode(json.dumps(doc).encode()).decode().rstrip("=")  # noqa: E731
        claims = {"iss": "https://openbao.test/v1/identity/oidc", "tenant_id": p4_tenant.tenant_id, "aud": fields["audience"], "iat": int(time.time()), "exp": int(time.time()) + 600}
        return httpx.Response(200, json={"data": {"token": f"{part({'alg': 'none'})}.{part(claims)}.sig"}})

    def echo(request: httpx.Request) -> httpx.Response:
        # A refusing issuer (or a proxy in front of it) that echoes the request back.
        return httpx.Response(403, text=f"denied {request.url} {request.content.decode()}")

    with caplog.at_level(logging.DEBUG):
        _credential(p4_tenant, tmp_path, openbao_url="https://openbao.test", fields=fields,
                    transport=httpx.MockTransport(signed)).token()
        with pytest.raises(ForgejoAuthError) as refused:
            _credential(p4_tenant, tmp_path, openbao_url="https://openbao.test", fields=fields,
                        transport=httpx.MockTransport(echo)).token()
    assert "denied" not in str(refused.value), "the issuer's echoed body reached the error text"
    texts = [r.getMessage() for r in caplog.records]
    texts.append(str(refused.value))
    cause = refused.value
    while cause is not None:
        texts.append(str(cause))
        cause = cause.__cause__
    blob = "\n".join(texts)
    for leaked in (secret, fields["role_id"]):
        assert leaked not in blob, f"{leaked!r} reached a log record or an error text"
