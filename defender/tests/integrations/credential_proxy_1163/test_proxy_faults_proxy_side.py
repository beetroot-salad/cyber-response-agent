"""#1163 repair (proxy side): the response cap holds for bodies with no honest Content-Length,
and a request the proxy cannot process is still classified and audited (O7, A9)."""
from __future__ import annotations

import contextlib
import gzip
import http.server
import json
import threading

import pytest

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH

BASE = T.BASE_PATH
PATH = f"{BASE}/users/x"
CAP = 1024


@contextlib.contextmanager
def _chunked_upstream(chunks: list[bytes]):
    """A loopback HTTP/1.1 server answering every GET with `chunks` as a chunked body and no
    Content-Length. Yields its base URL."""
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 — http.server's dispatch name
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, *_) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(("chunks", "fault"), [
    pytest.param([b"a" * 512, b"a" * 512], None, id="chunked-at-the-cap"),
    pytest.param([b"a" * 512, b"a" * 512, b"a"], "UpstreamFault", id="chunked-over-the-cap"),
    pytest.param([b"a" * 400] * 20, "UpstreamFault", id="chunked-many-small-over-the-cap"),
])
def test_f1_a_chunked_response_is_capped_like_any_other(tmp_path, data_root, chunks, fault):
    """A chunked reply (no Content-Length) up to the cap passes; one byte over is an
    `UpstreamFault` with no body. O7."""
    with _chunked_upstream(chunks) as base, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(base + BASE),
            max_response_bytes=CAP) as r:
        answer = r.ask(url=f"{base}{PATH}")

    assert answer["fault"] == fault, answer["fault"]
    if fault is None:
        assert len(answer["body"]) == CAP
    else:
        assert answer["body"] == ""


@pytest.mark.parametrize(("size", "fault"), [(CAP, None), (CAP + 1, "UpstreamFault"),
                                              (50_000, "UpstreamFault")])
def test_f1_a_compressed_response_is_capped_after_it_is_expanded(
        tmp_path, data_root, size, fault):
    """A gzip reply whose wire size is tiny is capped on its expanded size: 1024 bytes pass, more
    are an `UpstreamFault`. O7."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                              gzip.compress(b"a" * size))
        answer = r.ask()

    assert answer["fault"] == fault, answer["fault"]
    if fault is None:
        assert answer["body"] == "a" * CAP
    else:
        assert answer["body"] == ""


# --- A9 a request that cannot be processed is classified and audited --------------------------

def _raw(r, doc: dict, *, text: str | None = None):
    """POST `text` (default: `doc` as JSON with ASCII escapes, so a lone surrogate travels as
    `\\udXXX`) to the proxy as raw bytes, with a valid token."""
    content = (text if text is not None else json.dumps(doc)).encode("ascii")
    return r.client.post(PROXY_PATH, headers={"Authorization": f"Bearer {r.tok()}"},
                         content=content)


def _doc(r, **over):
    return {"system": "identity", "method": "GET", "url": f"{r.up.url}{PATH}",
            "headers": {}, "body": None} | over


@pytest.mark.parametrize("where", ["header", "url", "body", "system", "method"])
def test_f4_a_lone_surrogate_in_a_request_is_classified_and_audited(
        tmp_path, data_root, where):
    """A request holding a lone surrogate (in a header value, the URL, the body, the system or
    the method) gets a 200 answer with a fault class and one audit record; nothing is sent. O7, A9, A13."""
    lone = "\ud800"
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + BASE, writes=(("POST", "/tickets"),))) as r:
        doc = _doc(r)
        if where == "header":
            doc["headers"] = {"X-A": f"v{lone}"}
        elif where == "url":
            doc["url"] = f"{r.up.url}{BASE}/users/{lone}"
        elif where == "body":
            doc.update(method="POST", url=f"{r.up.url}{BASE}/tickets", body=f"{{\"x\": \"{lone}\"}}")
        elif where == "system":
            doc["system"] = lone
        else:
            doc["method"] = f"G{lone}T"
        grant = {("identity", "rw")}
        response = r.client.post(PROXY_PATH, headers={"Authorization": f"Bearer {r.tok(grant)}"},
                                 content=json.dumps(doc).encode("ascii"))
        control = r.ask()

    assert response.status_code == 200, response.text
    answer = response.json()
    assert answer["fault"] in ("ConfigFault", "ConfinementFault"), answer
    assert r.up.paths() == [PATH], "only the control request was sent"
    assert control["fault"] is None
    refused = [rec for rec in r.audit.records if not rec["outcome"].startswith("sent ")]
    assert [rec["outcome"] for rec in refused] == [answer["fault"]], "the refusal was audited once"
    sent = [rec for rec in r.audit.records if rec["outcome"].startswith("sent ")]
    assert len(sent) == 1, "the control request was audited as sent"


@pytest.mark.parametrize("shape", ["whole-request", "in-headers"])
def test_f4_deeply_nested_json_is_classified_and_audited(tmp_path, data_root, shape):
    """A request body nested far beyond any parser's depth gets a 200 answer with a fault class
    and one audit record; the proxy still serves the next request. O7, A9, A13."""
    depth = 200_000
    nested = "[" * depth + "]" * depth
    with T.rig(tmp_path / "forge", data_root) as r:
        text = nested if shape == "whole-request" else (
            f'{{"system": "identity", "method": "GET", "url": "{r.up.url}{PATH}", '
            f'"headers": {{"X-A": {nested}}}}}')
        response = _raw(r, {}, text=text)
        control = r.ask()

    assert response.status_code == 200, response.status_code
    answer = response.json()
    assert answer["fault"] in ("ConfigFault", "ConfinementFault"), answer
    assert (control["fault"], r.up.paths()) == (None, [PATH])
    records = r.audit.records
    assert len(records) == 2, records
    assert records[0]["outcome"] == answer["fault"], records
    assert records[1]["outcome"].startswith("sent "), records
