"""#1108 P4 / #1214: the credential provider's wire behaviour, each case a wrong-but-green production variant.
The TLS case is a real local TLS server whose certificate the configured CA did not sign."""
from __future__ import annotations

import datetime
import http.server
import json
import logging
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pathlib import Path
from types import SimpleNamespace
from typing import Any

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


def _cert(cn: str, *, san: bool):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1)))
    if san:
        import ipaddress
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


@pytest.fixture
def tls_issuer(tmp_path):
    """A local HTTPS server with a self-signed certificate; the CA the config names is another."""
    trusted_pem, _ = _cert("the configured CA", san=False)
    server_pem, server_key = _cert("localhost", san=True)
    (tmp_path / "trusted.pem").write_bytes(trusted_pem)
    (tmp_path / "server.pem").write_bytes(server_pem)
    (tmp_path / "server.key").write_bytes(server_key)
    got: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            got.append(self.rfile.read(int(self.headers.get("content-length", 0))).decode())
            out = json.dumps({"auth": {"client_token": "tok"}}).encode()
            self.send_response(200)
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "server.pem", tmp_path / "server.key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, got, tmp_path
    finally:
        server.shutdown()
        server.server_close()


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

    def echo(request: httpx.Request) -> httpx.Response:
        # A refusing issuer (or a proxy in front of it) that echoes the request back.
        return httpx.Response(403, text=f"denied {request.url} {request.content.decode()}")

    with caplog.at_level(logging.DEBUG):
        _credential(p4_tenant, tmp_path, openbao_url="https://openbao.test", fields=fields,
                    transport=httpx.MockTransport(bao.handle)).token()
        with pytest.raises(ForgejoAuthError) as refused:
            _credential(p4_tenant, tmp_path, openbao_url="https://openbao.test", fields=fields,
                        transport=httpx.MockTransport(echo)).token()
    texts = [r.getMessage() for r in caplog.records]
    texts.append(str(refused.value))
    cause = refused.value
    while cause is not None:
        texts.append(str(cause))
        cause = cause.__cause__
    blob = "\n".join(texts)
    for leaked in (secret, fields["role_id"]):
        assert leaked not in blob, f"{leaked!r} reached a log record or an error text"
