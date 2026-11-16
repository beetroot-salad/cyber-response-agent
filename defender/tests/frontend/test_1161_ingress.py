# ruff: noqa: PT018 — each compound assert states one fact about one response
"""#1161 B9, B3: the repo's ingress in front of the built frontend and the real API child. Plain HTTP, except the one
browser page (#1540 F1: the built landing page works under the ingress's CSP); no async test lives here."""
from __future__ import annotations

import json
import subprocess
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.support.api._server1083 import A
from defender.tests.support.frontend._ingress1161 import ARTIFACT_DOMAIN, REPO, ingress, launcher_env

UUID = "3400a0c8-beda-4fe6-86fb-3c6da1ea4a11"
CSP = {"default-src": ["'self'"], "base-uri": ["'none'"], "frame-ancestors": ["'none'"],
       "form-action": ["'self'", f"https://*.{ARTIFACT_DOMAIN}"]}
GUARDED = ("content-security-policy", "referrer-policy", "x-content-type-options")
APP_PATHS = ["/", f"/t/{A}/investigations/{UUID}", "/sign-in-failed", "/sign-in-failed?reason=error", "/no/such/screen",
             "/apix", "/me", "/auth/login", "/index.html"]


def _csp(value: str) -> dict[str, list[str]]:
    parsed = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            assert tokens[0] not in parsed, f"directive repeated: {tokens[0]}"
            parsed[tokens[0]] = sorted(tokens[1:])
    return parsed


def _assert_guarded(r: httpx.Response, what: str) -> None:
    for name in GUARDED:
        assert len(r.headers.get_list(name)) == 1, (what, name, r.headers)
    assert {k: sorted(v) for k, v in CSP.items()} == _csp(r.headers["content-security-policy"]), what
    assert r.headers["referrer-policy"] == "strict-origin-when-cross-origin", what
    assert r.headers["x-content-type-options"] == "nosniff", what
    assert r.headers.get_list("cache-control") == ["no-cache"], (what, r.headers)  # revalidated on every load


@pytest.mark.parametrize("path", APP_PATHS)
def test_1161_b9_every_path_outside_api_is_the_app_with_exactly_the_three_headers(world, path):
    """CSP (with `form-action` for the artifact domain), Referrer-Policy and nosniff; unknown paths get the app. (B9)"""
    root = world.get("/")
    assert root.status_code == 200 and root.headers["content-type"].startswith("text/html"), root.headers
    r = world.get(path)
    _assert_guarded(r, path)
    assert r.text == root.text, f"{path}: not the app's document"
    if path in ("/", "/sign-in-failed", f"/t/{A}/investigations/{UUID}"):
        assert r.status_code == 200


class _Assets(HTMLParser):
    """The same-origin paths `index.html` loads: scripts, and links (stylesheets, preloads, icons)."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.styles: list[str] = []
        self.others: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        url = values.get("src") if tag == "script" else values.get("href") if tag == "link" else None
        if not url or urllib.parse.urlsplit(url).netloc or urllib.parse.urlsplit(url).scheme:
            return
        path = urllib.parse.urljoin("/", url)
        if tag == "script":
            self.scripts.append(path)
        elif "stylesheet" in (values.get("rel") or "").split():
            self.styles.append(path)
        else:
            self.others.append(path)


# Caddy's own error answers (a 400 to a malformed escape) are outside B9's header promise (owner ruling): untested.
def test_1161_b9_the_built_files_carry_the_headers_and_are_revalidated_on_every_load(world):
    """Every script, stylesheet and other file `index.html` references answers 200 with the three headers and
    `no-cache`, whatever the build named them: a browser never runs a cached app against a newer API. (B9, F2)"""
    parsed = _Assets()
    parsed.feed(world.get("/").text)
    assert parsed.scripts, "positive control: the app references a script"
    assert parsed.styles, "positive control: the app references a stylesheet"
    for asset in sorted({*parsed.scripts, *parsed.styles, *parsed.others}):
        r = world.get(asset)
        assert r.status_code == 200, asset
        _assert_guarded(r, asset)


def test_1540_f1_the_built_landing_page_loads_from_the_apps_own_origin_with_nothing_inlined(world, context, requests):
    """Signed out, `/` shows its illustration through requests all to the app's origin, no `data:` URL, and no CSP
    violation (the fixture guards it): images and fonts come from the app's origin, asset inlining is off. (F1)"""
    page = context.new_page()
    page.goto(f"{world.origin}/")
    page.locator('[data-screen="root"]').first.wait_for()
    page.wait_for_load_state("networkidle")
    images = page.evaluate("[...document.images].map(i => [i.currentSrc, i.naturalWidth])")
    foreign = [r.url for r in requests if not r.url.startswith(world.origin + "/")]
    assert foreign == [], f"requests outside the app's origin (data: URLs included): {foreign}"
    assert [src for src, _ in images if not src.startswith(world.origin + "/")] == [], images
    assert [src for src, width in images if width == 0] == [], f"images that did not load: {images}"
    loaded = [r.url for r in requests if r.resource_type == "image" and urllib.parse.urlsplit(r.url).path != "/favicon.ico"]
    assert loaded, "positive control: the illustration is an image request to the app's origin"


def _header_set(r: httpx.Response) -> list[tuple[str, str]]:
    """Every response header, name and value, but `Date` (a clock) and `Via` (the reverse proxy's own hop marker,
    `1.1 Caddy`, which carries no policy): the set a client of the API sees."""
    return sorted((name.lower(), value) for name, value in r.headers.multi_items() if name.lower() not in ("date", "via"))


@pytest.mark.parametrize("path", ["/api/me", "/api/openapi.json", "/api/nope", "/API/me", "/Api/openapi.json", "/api",
                                  "/aPI/me", "/apI", "/aPi/", "/APi/auth/login", "/ApI/nope"])
def test_1161_b9_b3_api_responses_carry_none_of_the_three_headers_and_are_the_apis_answer(world, path):
    """`/api` in any letter case goes to the API, unchanged; the ingress adds no header. (B9, B3)"""
    r = world.get(path)
    assert not r.headers["content-type"].startswith("text/html"), (path, r.status_code, r.headers)
    for name in GUARDED:
        assert name not in r.headers, (path, name, r.headers)
    direct = httpx.get(f"{world.api.base_url}{path}")
    assert (r.status_code, r.headers["content-type"]) == (direct.status_code, direct.headers["content-type"]), path
    assert _header_set(r) == _header_set(direct), path  # B3: nothing added, nothing removed, no CORS grant
    assert not [name for name in r.headers if name.lower().startswith("access-control-")], (path, r.headers)


FOREIGN = "https://evil.example"


@pytest.mark.parametrize("origin", [FOREIGN, None], ids=["foreign-origin", "no-origin"])
def test_1161_b3_a_state_changing_request_through_the_ingress_reaches_the_api_as_it_was_sent(world, origin):
    """A non-GET without the frontend's `Origin` is refused by the API (its 403), and a preflight is not granted:
    the ingress rewrites no request header and grants no CORS. Control: the frontend's own origin passes. (B3, B5)"""
    headers = {} if origin is None else {"origin": origin}
    for url in (f"{world.origin}/api/nope", f"{world.api.base_url}/api/nope"):
        r = httpx.post(url, headers=headers)
        assert (r.status_code, r.headers["content-type"]) == (403, "application/problem+json"), (url, r.status_code, r.text)
    through, direct = (httpx.post(f"{base}/api/nope", headers=headers) for base in (world.origin, world.api.base_url))
    assert through.json() == direct.json() and _header_set(through) == _header_set(direct)
    preflight = {"origin": FOREIGN, "access-control-request-method": "POST"}
    options = httpx.options(f"{world.origin}/api/nope", headers=preflight)
    assert not [n for n in options.headers if n.lower().startswith("access-control-")], options.headers
    assert _header_set(options) == _header_set(httpx.options(f"{world.api.base_url}/api/nope", headers=preflight))
    own = httpx.post(f"{world.origin}/api/nope", headers={"origin": world.origin})  # control
    assert "does not come from the frontend" not in own.text, (own.status_code, own.text)


def test_1161_b9_the_sign_in_start_through_the_ingress_is_the_apis_redirect_without_the_headers(world):
    """`/api/auth/login` answers the API's 302 to the provider; the ingress adds nothing. (B3, B9)"""
    r = world.get("/api/auth/login", follow_redirects=False)
    assert r.status_code == 302, r.headers
    assert urllib.parse.urlsplit(r.headers["location"]).netloc == urllib.parse.urlsplit(world.front.origin).netloc
    for name in GUARDED:
        assert name not in r.headers


def test_1161_b9_two_ingress_instances_serve_at_once(browser_tools, tmp_path: Path):
    """Caddy's admin endpoint is off, so a second ingress on the same host starts and serves beside the first. (B9)"""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>app</body></html>")
    with ingress("127.0.0.1:1", dist, tmp_path / "one") as first, ingress("127.0.0.1:1", dist, tmp_path / "two") as second:
        assert first != second
        for origin in (first, second):
            r = httpx.get(f"{origin}/")
            assert r.status_code == 200 and "app" in r.text, (origin, r.status_code)


def _adapted(listen: str, tmp_path: Path) -> Any:
    from defender.api_server.ingress import caddy_environment

    env = caddy_environment(launcher_env(listen, "127.0.0.1:1", tmp_path, work=tmp_path))
    done = subprocess.run(["caddy", "adapt", "--config", "defender/frontend/Caddyfile", "--adapter", "caddyfile"],
                          cwd=REPO, env=env, capture_output=True, text=True, check=False, timeout=60)
    assert done.returncode == 0, done.stderr[-1500:]
    return json.loads(done.stdout)


def test_1161_b9_the_caddyfile_turns_off_the_admin_endpoint(browser_tools, tmp_path: Path):
    """`caddy adapt` of the repo's Caddyfile gives `admin.disabled == true`. (B9)"""
    assert _adapted("127.0.0.1:8080", tmp_path)["admin"]["disabled"] is True


def test_1161_b9_the_ingress_serves_plain_http_on_its_listen_address_for_any_host(browser_tools, tmp_path: Path):
    """One plain-HTTP server on the listen port, bound to its host, with automatic HTTPS off and no host matcher: what
    a TLS terminator in front forwards (any `Host`) is served, and Caddy never binds 443 or asks for a certificate.
    (B9, amended: TLS ends in front of the ingress)"""
    [server] = _adapted("127.0.0.1:8080", tmp_path)["apps"]["http"]["servers"].values()
    assert server["listen"] == ["127.0.0.1:8080"], server["listen"]
    assert server.get("automatic_https", {}).get("disable") is True, server.get("automatic_https")
    assert all("host" not in matcher for route in server["routes"] for matcher in route.get("match", [])), server["routes"]
    assert "tls" not in _adapted("127.0.0.1:8080", tmp_path)["apps"]
