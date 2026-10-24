"""#1108 P4 round 6 — the issuer login's wire behaviour (each case was a wrong-but-green
production variant): the login trusts only the config's CA, never follows a redirect, never
sends the secret over cleartext, and leaks no secret into logs or error text.

The TLS case is a REAL local TLS server whose certificate the configured CA did not sign."""
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

from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    ROLE_ID,
    SECRET_ID,
    AppRoleVault,
    write_issuer_config,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge


def vc():
    from defender.learning.author.version_control import issuer
    return issuer


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
    port, got, folder = tls_issuer
    bind_forge(p4_tenant)
    config = write_issuer_config(folder / "cfg", issuer=f"https://localhost:{port}",
                                 ca_cert=str(folder / "trusted.pem"))
    with pytest.raises(Exception) as refused:  # noqa: PT011 — the class is the code's choice
        vc().issuer_login(p4_tenant.tenant, issuer_config=config)
    from defender.learning.author.version_control import ForgejoAuthError
    assert isinstance(refused.value, ForgejoAuthError), repr(refused.value)
    assert got == [], f"the secret reached a server the configured CA did not sign: {got}"
    assert SECRET_ID not in str(refused.value)


def test_r6_the_login_never_follows_a_redirect(p4_tenant, tmp_path):
    from defender.learning.author.version_control import ForgejoAuthError

    bind_forge(p4_tenant)
    config = write_issuer_config(tmp_path / "cfg")
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.content.decode()))
        if request.url.host == httpx.URL(json.loads(config.read_text())["issuer"]).host:
            return httpx.Response(307, headers={"Location": "https://evil.invalid/steal"})
        return httpx.Response(200, json={"auth": {"client_token": "tok"}})

    with pytest.raises(ForgejoAuthError):
        vc().issuer_login(p4_tenant.tenant, issuer_config=config,
                          transport=httpx.MockTransport(handler))
    assert [h for h, _ in seen if h == "evil.invalid"] == [], "the login body was re-POSTed"
    assert len(seen) == 1


def test_r6_an_http_issuer_is_refused_before_any_request(p4_tenant, tmp_path):
    """EXPECTED RED until production refuses a cleartext issuer address before the login POST
    (today `read_issuer_config` accepts `http://` and the secret is POSTed first)."""
    bind_forge(p4_tenant)
    config = write_issuer_config(tmp_path / "cfg", issuer="http://openbao:8200")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        return httpx.Response(200, json={"auth": {"client_token": "tok"}})

    with pytest.raises(Exception):  # noqa: B017, PT011
        vc().issuer_login(p4_tenant.tenant, issuer_config=config,
                          transport=httpx.MockTransport(handler))
    assert seen == [], f"the AppRole secret was POSTed to a cleartext issuer: {seen}"


def test_r6_no_secret_reaches_a_log_record_or_an_error_text(p4_tenant, tmp_path, caplog):
    from defender.learning.author.version_control import ForgejoAuthError

    bind_forge(p4_tenant)
    config = write_issuer_config(tmp_path / "cfg")
    vault = AppRoleVault(p4_tenant.tenant_id)

    def echo(request: httpx.Request) -> httpx.Response:
        # A refusing issuer (or a proxy in front of it) that echoes the request back.
        return httpx.Response(403, text=f"denied {request.url} {request.content.decode()}")

    with caplog.at_level(logging.DEBUG):
        vc().issuer_login(p4_tenant.tenant, issuer_config=config, transport=vault.transport)
        with pytest.raises(ForgejoAuthError) as refused:
            vc().issuer_login(p4_tenant.tenant, issuer_config=config,
                              transport=httpx.MockTransport(echo))
    texts = [r.getMessage() for r in caplog.records]
    texts.append(str(refused.value))
    cause = refused.value
    while cause is not None:
        texts.append(str(cause))
        cause = cause.__cause__
    blob = "\n".join(texts)
    for secret in (SECRET_ID, ROLE_ID):
        assert secret not in blob, f"{secret!r} reached a log record or an error text"
    assert "denied" not in str(refused.value), "the issuer's response body reached the error text"
