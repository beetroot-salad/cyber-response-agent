# ruff: noqa: PT018 — each compound assert states one fact about one response
"""#1161 B9, B3: the repo's ingress in front of the built frontend and the real API child. Plain HTTP, no browser."""
from __future__ import annotations

import re
import urllib.parse
from pathlib import Path

import httpx
import pytest

from defender.tests.support.api._server1083 import A
from defender.tests.support.frontend._ingress1161 import ARTIFACT_DOMAIN, ingress

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


# Caddy's own error answers (a 400 to a malformed escape) are outside B9's header promise (owner ruling): untested.
def test_1161_b9_the_built_files_carry_the_headers_too(world):
    """The scripts and styles `index.html` references are non-/api responses. (B9)"""
    html = world.get("/").text
    assets = sorted(set(re.findall(r'(?:src|href)="(/[^"/][^"]*)"', html)))
    assert assets, "positive control: the app references at least one built file"
    for asset in assets:
        r = world.get(asset)
        assert r.status_code == 200, asset
        _assert_guarded(r, asset)


@pytest.mark.parametrize("path", ["/api/me", "/api/openapi.json", "/api/nope", "/API/me", "/Api/openapi.json", "/api"])
def test_1161_b9_b3_api_responses_carry_none_of_the_three_headers_and_are_the_apis_answer(world, path):
    """`/api` in any letter case goes to the API, unchanged; the ingress adds no header. (B9, B3)"""
    r = world.get(path)
    assert not r.headers["content-type"].startswith("text/html"), (path, r.status_code, r.headers)
    for name in GUARDED:
        assert name not in r.headers, (path, name, r.headers)
    direct = httpx.get(f"{world.api.base_url}{path}")
    assert (r.status_code, r.headers["content-type"]) == (direct.status_code, direct.headers["content-type"]), path


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
