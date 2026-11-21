# ruff: noqa: PT018 — each compound assert states one fact about one response
"""#1592 OD-1, OD-3, PP-3 "Edge": the ingress's Forgejo site, through the real launcher and Caddy, with an echo upstream
standing for Forgejo. Rows S3-11 (the allowlist), S3-12 (the Cookie drop on the sign-in start), S3-13 (host match).

Needs `caddy` on PATH (B11: a failure, never a skip). The paths are the design's "Allowed paths" and "Off the list, by
name"; a request is sent as written (no client normalisation), with `Host` set by hand."""
from __future__ import annotations

import http.client
import http.server
import itertools
import shutil
import threading
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from defender.tests.support.frontend._ingress1161 import FORGE_DOMAIN, ingress

UPSTREAM_BODY = b"the echo upstream"
R = "/t-4f1c7a52-3b9d-4c3e-8a21-5d0e9b7c1a66/knowledge"
OTHER_R = "/t-0a0a0a0a-1b1b-4c1c-8d1d-2e2e2e2e2e2e/knowledge"
SHA = "0123456789abcdef0123456789abcdef01234567"


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
            self.wfile.write(UPSTREAM_BODY)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _answer  # noqa: N815

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

ALLOWED: list[tuple[str, str]] = [
    ("GET", "/"), ("GET", "/user/login"), ("GET", "/user/oauth2/product"), ("GET", "/user/oauth2/product/callback"),
    ("POST", "/user/logout"), ("GET", "/repo/search"),
    ("GET", "/assets/js/index.js"), ("GET", "/assets/css/index.css"), ("GET", "/favicon.ico"),
    ("GET", "/avatars/0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
    ("GET", R), ("GET", f"{R}/src/branch/main"), ("GET", f"{R}/src/branch/main/agent/skills/a.md"),
    ("GET", f"{R}/raw/branch/main/agent/skills/a.md"), ("GET", f"{R}/blame/branch/main/a.md"),
    ("GET", f"{R}/commits/branch/main"), ("GET", f"{R}/commit/{SHA}"), ("GET", f"{R}/branches/list"),
    ("GET", f"{R}/media/branch/main/a.png"), ("GET", f"{R}/blob_excerpt/{SHA}"),
    ("GET", f"{R}/pulls"), ("GET", f"{R}/pulls/3"), ("GET", f"{R}/pulls/3/commits"), ("GET", f"{R}/pulls/3/files"),
    ("GET", f"{R}/pulls/3/files/reviews/new_comment"),
    ("POST", f"{R}/pulls/3/files/reviews/comments"), ("POST", f"{R}/pulls/3/files/reviews/submit"),
    ("POST", f"{R}/pulls/3/merge"), ("GET", f"{R}/issues/3/content-history/overview"), ("POST", "/-/fetch-redirect"),
    ("GET", f"{R}/_edit/main/a.md"), ("POST", f"{R}/_edit/main/a.md"), ("GET", f"{R}/_new/main/"),
    ("POST", f"{R}/_new/main/"), ("GET", f"{R}/_delete/main/a.md"), ("POST", f"{R}/_delete/main/a.md"),
    ("POST", f"{R}/_preview/main/a.md"), ("POST", f"{R}/markup"),
    ("GET", f"{R}/compare/main...feature"), ("POST", f"{R}/compare/main...feature"),
    ("GET", f"{R}/issues"), ("GET", f"{R}/issues/3"), ("GET", f"{R}/issues/suggestions"),
    ("POST", f"{R}/issues/3/comments"),
    ("GET", f"{OTHER_R}/pulls/3"),  # `{R}` is the shape `/t-<uuid>/knowledge`: any tenant's, Forgejo's own rules decide
]

OFF_LIST: dict[str, list[tuple[str, str]]] = {
    "git transport without a suffix": [
        ("GET", f"{R}/info/refs?service=git-upload-pack"), ("POST", f"{R}/git-upload-pack"),
        ("POST", f"{R}/git-receive-pack"), ("GET", f"{R}/HEAD"), ("GET", f"{R}/objects/info/packs")],
    "git transport with .git": [
        ("GET", f"{R}.git"), ("GET", f"{R}.git/info/refs?service=git-upload-pack"), ("POST", f"{R}.git/git-upload-pack"),
        ("POST", f"{R}.git/git-receive-pack")],
    "dot segments": [
        ("GET", f"{R}/src/../../../user/settings"), ("GET", "/assets/../user/settings"), ("GET", "/./user/login"),
        ("GET", f"{R}/src/branch/main/.."), ("GET", "/assets/%2e%2e/user/settings"), ("GET", "/assets/.%2e/user/settings"),
        ("GET", "/assets/%2E%2E/user/settings")],
    "encoded slashes": [
        ("GET", "/user%2flogin"), ("GET", "/user%2Flogin"), ("GET", f"{R}/src/branch/main/a%2fb"),
        ("GET", f"{R}%2fsettings"), ("GET", "/assets/js%2f..%2f..%2fuser/settings")],
    "doubled slashes": [
        ("GET", "//user/login"), ("GET", f"{R}//src"), ("GET", "/assets//x.js"), ("GET", "//"), ("GET", "///")],
    "case variants of a fixed segment": [
        ("GET", "/User/Login"), ("GET", "/USER/LOGIN"), ("GET", "/API/v1/version"), ("GET", "/Api/V1/Version"),
        ("GET", "/user/Settings"), ("GET", "/Explore/repos")],
    "a reserved first segment where a repository is expected": [
        ("GET", "/user/knowledge"), ("GET", "/api/knowledge/src/branch/main"), ("GET", "/explore/knowledge"),
        ("GET", "/-/knowledge"), ("GET", "/admin/knowledge"), ("GET", "/t-not-a-uuid/knowledge"),
        ("GET", f"{R[:-len('knowledge')]}other"), ("GET", f"{R}x"), ("GET", f"{R}-other/src/branch/main")],
    "the API": [
        ("GET", "/api/v1/version"), ("GET", "/api/v1/user"), ("POST", "/api/v1/repos/migrate"), ("GET", "/api/healthz"),
        ("GET", "/api/swagger"), ("GET", f"/api/v1/repos{R}"), ("DELETE", "/api/v1/user")],
    "the user's settings": [
        ("GET", "/user/settings"), ("GET", "/user/settings/applications"), ("GET", "/user/settings/security"),
        ("POST", "/user/settings/applications")],
    "account linking": [
        ("GET", "/user/link_account"), ("POST", "/user/link_account_signin"), ("GET", "/user/link_account_signup"),
        ("GET", "/user/link_account/x")],
    "administration": [("GET", "/-/admin"), ("GET", "/-/admin/users"), ("POST", "/-/admin/users/new")],
    "explore": [("GET", "/explore"), ("GET", "/explore/repos"), ("GET", "/explore/users")],
    "the repository's settings": [
        ("GET", f"{R}/settings"), ("GET", f"{R}/settings/hooks"), ("POST", f"{R}/settings/collaboration"),
        ("POST", f"{R}/settings/delete")],
    "other pages off the list": [
        ("GET", "/user/events"), ("GET", "/notifications"), ("GET", "/notifications/new"), ("GET", "/login/oauth/authorize"),
        ("POST", "/login/oauth/access_token"), ("GET", "/org/create"), ("GET", "/repo/create"), ("GET", "/repo/migrate")],
}

WRONG_METHOD = [("POST", "/user/login"), ("GET", "/user/logout"), ("POST", "/user/oauth2/product"),
                ("GET", f"{R}/pulls/3/merge"), ("DELETE", "/"), ("PUT", f"{R}/_edit/main/a.md"),
                ("GET", "/-/fetch-redirect"), ("PATCH", f"{R}/issues/3/comments")]


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
    """S3-11: the list names methods; any other method on the same path is refused at the edge."""
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


# --- S3-12: the Cookie drop on the sign-in start ------------------------------------------------------------------------

START = "/user/oauth2/product"
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
