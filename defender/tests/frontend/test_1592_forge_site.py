# ruff: noqa: PT018 — each compound assert states one fact about one response
"""#1592 OD-1, OD-3, PP-3 "Edge": the ingress's Forgejo site, through the real launcher and Caddy, with an echo upstream
standing for Forgejo. Rows S3-11 (the allowlist), S3-12 (the Cookie drop on the sign-in start), S3-13 (host match).

Needs `caddy` on PATH (B11: a failure, never a skip). The paths are the design's "Allowed paths" and "Off the list, by
name"; a request is sent as written (no client normalisation), with `Host` set by hand."""
from __future__ import annotations

import http.client
import http.server
import itertools
import random
import shutil
import threading
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from defender.tests.support.frontend import _allowlist1592 as allowlist
from defender.tests.support.frontend._ingress1161 import FORGE_DOMAIN, ingress

UPSTREAM_BODY = b"the echo upstream"
R = "/t-4f1c7a52-3b9d-4c3e-8a21-5d0e9b7c1a66/knowledge"


@dataclass
class Seen:
    method: str
    target: str
    headers: dict[str, str]


@dataclass
class Echo:
    seen: list[Seen] = field(default_factory=list)


def _handler(echo: Echo) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self) -> None:
            echo.seen.append(Seen(self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
            length = int(self.headers.get("content-length") or 0)
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Length", str(len(UPSTREAM_BODY)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(UPSTREAM_BODY)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _answer  # noqa: N815

        def __getattr__(self, name: str) -> object:
            """Any other method (OPTIONS, TRACE, a made-up token) is answered and seen too: the upstream refuses none."""
            if name.startswith("do_"):
                return self._answer
            raise AttributeError(name)

        def log_message(self, *_args: object) -> None:
            return

    return Handler


@dataclass
class Site:
    port: int
    echo: Echo

    def send(self, method: str, target: str, *, host: str = FORGE_DOMAIN, headers: dict[str, str] | None = None,
             body: bytes | None = None) -> tuple[int, bytes]:
        """One request exactly as written (no normalisation of `target`), with the given `Host`."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host)
            for name, value in (headers or {}).items():
                conn.putheader(name, value)
            conn.putheader("Content-Length", str(len(body or b"")))
            conn.endheaders(body or b"")
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def forwarded(self, method: str, target: str, **kw: object) -> list[Seen]:
        """What the upstream saw because of this one request."""
        before = len(self.echo.seen)
        self.send(method, target, **kw)  # type: ignore[arg-type]
        return self.echo.seen[before:]


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> Iterator[Site]:
    assert shutil.which("caddy") is not None, "the Forgejo site tests need caddy on PATH (B11: a failure, never a skip)"
    tmp = tmp_path_factory.mktemp("forge-site")
    dist = tmp / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>the app</body></html>")
    echo = Echo()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(echo))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with ingress("127.0.0.1:1", dist, tmp / "work", forge_upstream=f"127.0.0.1:{server.server_port}") as origin:
            yield Site(int(urllib.parse.urlsplit(origin).port or 0), echo)
    finally:
        server.shutdown()
        server.server_close()


# --- S3-11: the allowlist ---------------------------------------------------------------------------------------------

ALLOWED = allowlist.allowed(R) + [("GET", f"{allowlist.OTHER_R}/pulls/3")]  # `{R}` is a shape: Forgejo's rules decide who reads
OFF_LIST = allowlist.off_list(R)
WRONG_METHOD = allowlist.wrong_method(R)  # "a path listed without a method allows GET only", from the one module


@pytest.mark.parametrize(("method", "target"), ALLOWED, ids=[f"{m} {t}" for m, t in ALLOWED])
def test_1592_every_allowed_pattern_is_forwarded_to_the_upstream(site, method, target):
    """S3-11: each path of the design's allowlist, with its method, reaches Forgejo and its answer comes back."""
    before = len(site.echo.seen)
    status, body = site.send(method, target)
    assert status == 200 and body == UPSTREAM_BODY, (status, body)
    [seen] = site.echo.seen[before:]
    assert (seen.method, seen.target) == (method, target), "the upstream was not given the path as sent"


_OFF = [(why, m, t) for why, cases in OFF_LIST.items() for m, t in cases]


@pytest.mark.parametrize(("why", "method", "target"), _OFF, ids=[f"{w}: {m} {t}" for w, m, t in _OFF])
def test_1592_every_class_off_the_list_is_404_and_never_reaches_the_upstream(site, why, method, target):
    """S3-11: the paths the design names off the list, and the classes refused before matching, answer 404 with the
    upstream untouched."""
    before = len(site.echo.seen)
    status, body = site.send(method, target)
    assert status == 404, (why, status)
    assert body != UPSTREAM_BODY
    assert site.echo.seen[before:] == [], f"{why}: the upstream saw {site.echo.seen[before:]}"


@pytest.mark.parametrize(("method", "target"), WRONG_METHOD, ids=[f"{m} {t}" for m, t in WRONG_METHOD])
def test_1592_an_allowed_path_with_a_method_the_list_does_not_give_it_is_404(site, method, target):
    """S3-11: the list names methods, none meaning GET only; every other method on every entry is refused at the edge."""
    before = len(site.echo.seen)
    assert site.send(method, target)[0] == 404
    assert site.echo.seen[before:] == []


def test_1592_the_allowlist_is_a_list_not_a_denylist(site):
    """S3-11: a path no pattern names (generated from segments no pattern holds) is 404, whatever it is shaped like."""
    segments = ["alpha", "x", "settings", "raw", "src", "git", "u", "t-1", "knowledge", "pulls", "3"]
    before = len(site.echo.seen)
    for depth in (1, 2, 3):
        for parts in itertools.islice(itertools.product(segments, repeat=depth), 0, None, 7):
            target = "/zz-" + "/".join(parts)
            assert site.send("GET", target)[0] == 404, target
    assert site.echo.seen[before:] == []


def _generated_requests(seed: int) -> list[tuple[str, str]]:
    """Every instance with every method, and each mutation of the list (`allowlist.mutations`) with GET, POST, one
    method drawn from `MUTATION_METHODS` and one made-up token."""
    rng = random.Random(seed)  # noqa: S311 — generated cases, not secrets
    requests = [(m, t) for _m, t in allowlist.allowed(R) for m in (*allowlist.MUTATION_METHODS, allowlist.random_method(rng))]
    for _why, target in allowlist.mutations(R, rng):
        requests += [(m, target) for m in ("GET", "POST", rng.choice(allowlist.MUTATION_METHODS), allowlist.random_method(rng))]
    return list(dict.fromkeys(requests))


def _is_signin_start(target: str) -> bool:
    """Whether Forgejo could read the path as the sign-in start: decoded, in any case, with or without a final slash."""
    return urllib.parse.unquote(target.split("?", 1)[0]).lower().rstrip("/") == allowlist.SIGNIN_START


def test_1592_a_generated_request_reaches_the_upstream_iff_the_list_allows_it_and_never_the_start_with_a_cookie(site):
    """S3-11 / S3-12 (PP-3, OD-3): over requests generated from every entry (values outside a placeholder's group, case
    flips, suffixes, dot-segments in every spelling; every method, a made-up one included), the upstream sees a request
    exactly when the list's `matches` allows it and the path is in no class refused before matching; whatever reaches the sign-in start, by
    any method, arrives without a Cookie."""
    wrong: list[str] = []
    for method, target in _generated_requests(1592):
        before = len(site.echo.seen)
        site.send(method, target, headers=COOKIE)
        seen = site.echo.seen[before:]
        expected = allowlist.matches(method, target) and not allowlist.refused_first(target)
        if bool(seen) != expected:
            wrong.append(f"{method} {target}: {'forwarded' if seen else 'refused'}, the list says {'allow' if expected else 'refuse'}")
        wrong += [f"{method} {target}: reached the sign-in start ({s.method} {s.target}) with its Cookie"
                  for s in seen if _is_signin_start(s.target) and "cookie" in s.headers]
    assert wrong == [], f"{len(wrong)} wrong, e.g. " + "; ".join(wrong[:25])


# --- S3-12: the Cookie drop on the sign-in start ------------------------------------------------------------------------

START = allowlist.SIGNIN_START
COOKIE = {"Cookie": "i_like_gitea=a-signed-in-session; _csrf=x"}


def test_1592_the_sign_in_start_reaches_forgejo_without_the_cookie(site):
    """S3-12 / P26: GET `/user/oauth2/product` is forwarded with no Cookie header, so a signed-in cookie cannot link."""
    [seen] = site.forwarded("GET", START, headers=COOKIE)
    assert "cookie" not in seen.headers, seen.headers
    [seen] = site.forwarded("GET", f"{START}?redirect_to=%2F", headers=COOKIE)
    assert "cookie" not in seen.headers, seen.headers


@pytest.mark.parametrize("target", [
    "/user/oauth2/%70roduct", "/user/oauth2/%50roduct", "/user/oauth2/product/", "//user/oauth2/product",
    "/user/oauth2/product?x=1", "/USER/OAUTH2/PRODUCT", "/user/./oauth2/product", "/user/oauth2/product%2f",
    "/user/oauth2/product/callback/..", "/user%2foauth2/product"])
def test_1592_no_variant_of_the_sign_in_start_reaches_forgejo_with_the_cookie(site, target):
    """S3-12 / P26: whichever variant (percent-encoded letter, trailing or leading slash, case) the edge forwards, the
    upstream receives it without the Cookie; the others are refused."""
    seen = site.forwarded("GET", target, headers=COOKIE)
    assert all("cookie" not in s.headers for s in seen), (target, seen)


@pytest.mark.parametrize(("method", "target"), [
    ("GET", "/user/oauth2/product/callback"), ("GET", "/user/login"), ("GET", "/"), ("POST", "/user/logout"),
    ("GET", f"{R}/pulls/3"), ("POST", f"{R}/pulls/3/merge"), ("GET", "/assets/js/index.js")])
def test_1592_every_other_path_keeps_the_cookie(site, method, target):
    """S3-12: the Cookie is dropped on the start alone: the callback, the sign-out and the pages keep it."""
    [seen] = site.forwarded(method, target, headers=COOKIE)
    assert seen.headers.get("cookie") == COOKIE["Cookie"], (target, seen.headers)


# --- S3-13: host match --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["/user/login", f"{R}/pulls/3", "/repo/search", "/user/oauth2/product", "/assets/js/index.js"])
def test_1592_a_forgejo_path_on_the_app_host_never_reaches_the_forgejo_upstream(site, target):
    """S3-13: on any other `Host` the Forgejo allowlist does not apply: the app answers, the upstream is untouched."""
    before = len(site.echo.seen)
    status, body = site.send("GET", target, host="localhost")
    assert body != UPSTREAM_BODY, (target, status)
    assert site.echo.seen[before:] == []


@pytest.mark.parametrize("target", ["/me", "/index.html", "/t/3/investigations/x", "/sign-in-failed", "/api/me", "/api"])
def test_1592_an_app_path_on_the_forgejo_host_is_404_and_reaches_neither_upstream(site, target):
    """S3-13: the Forgejo host serves the allowlist alone: the app's pages and `/api` are 404 there."""
    before = len(site.echo.seen)
    status, body = site.send("GET", target)
    assert status == 404, (target, status)
    assert b"the app" not in body
    assert site.echo.seen[before:] == []


def test_1592_the_forgejo_domain_is_matched_by_host_alone(site):
    """S3-13: a Host that merely contains or extends the domain is the app's, not Forgejo's."""
    for host in (f"x.{FORGE_DOMAIN}", f"{FORGE_DOMAIN}.evil.test", "evil.test"):
        before = len(site.echo.seen)
        site.send("GET", "/user/login", host=host)
        assert site.echo.seen[before:] == [], host
