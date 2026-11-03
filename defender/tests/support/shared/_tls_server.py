"""A loopback HTTPS server with a self-signed certificate, for tests of who a client trusts."""
from __future__ import annotations

import contextlib
import datetime
import http.server
import ipaddress
import ssl
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

#: A reply: (status, body) for the request's method, path and body.
Answer = Callable[[str, str, bytes], tuple[int, bytes]]


def self_signed(cn: str, *, san: bool) -> tuple[bytes, bytes]:
    """A self-signed CA certificate (PEM) and its key (PEM) for `cn`; with `san`, valid for
    `localhost` and 127.0.0.1, so it can serve a loopback server and be its own CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


@dataclass
class TlsServer:
    """A running server: its port, the CA file that signed it, and each request body it got."""

    port: int
    ca: Path
    got: list[bytes] = field(default_factory=list)


@contextlib.contextmanager
def tls_server(folder: Path, answer: Answer) -> Iterator[TlsServer]:
    """A loopback HTTPS server answering every GET and POST by `answer`, its certificate
    self-signed for localhost/127.0.0.1 and written to `folder / "server.pem"` (its own CA)."""
    pem, key = self_signed("localhost", san=True)
    (folder / "server.pem").write_bytes(pem)
    (folder / "server.key").write_bytes(key)
    got: list[bytes] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length") or 0))
            got.append(body)
            status, out = answer(self.command, self.path, body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_POST = _answer  # noqa: N815

        def log_message(self, *_: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(folder / "server.pem", folder / "server.key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield TlsServer(server.server_port, folder / "server.pem", got)
    finally:
        server.shutdown()
        server.server_close()
