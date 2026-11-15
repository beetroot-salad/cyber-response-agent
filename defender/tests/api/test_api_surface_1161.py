"""#1161 piece 1: the API's address space (B3) and the shared setting parsers and ingress launcher (S5)."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import ANN, T1, World  # noqa: E402
from defender.tests.support.frontend._ingress1161 import ARTIFACT_DOMAIN, launcher_env, run_launcher  # noqa: E402

ORIGIN = "http://localhost:8000"


def _routes(routes: Any) -> Any:
    """Every route as served (FastAPI includes routers lazily, so walk their effective routes)."""
    for route in routes:
        if hasattr(route, "effective_candidates"):
            yield from _routes(route.effective_candidates())
        elif hasattr(route, "path"):
            yield route


def test_every_route_and_the_openapi_document_live_under_api() -> None:
    """Each route path starts `/api/`; the document is `/api/openapi.json` and declares only `/api/` paths; the old addresses answer 404. (B3)"""
    world = World(tenants={T1: [ANN]})
    paths = [r.path for r in _routes(world.app.routes)]
    assert len(paths) > 20, paths
    outside = [p for p in paths if not p.startswith("/api/") and p not in ("/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect")]
    assert outside == []
    browser = world.client()
    document = browser.get("/api/openapi.json")
    assert document.status_code == 200
    assert all(p.startswith("/api/") for p in document.json()["paths"])
    for old in ("/openapi.json", "/me", "/auth/login", "/docs", "/redoc"):
        assert browser.get(old).status_code == 404, old
    assert browser.get("/api/me").status_code == 401  # control: the moved route is there


def test_the_docs_pages_are_not_served_by_default() -> None:
    """Without `DEFENDER_API_DOCS=true` neither interactive page exists, under `/api` or at the root; the document does. (B10)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    assert [browser.get(p).status_code for p in ("/api/docs", "/api/redoc", "/docs", "/redoc")] == [404] * 4
    assert browser.get("/api/openapi.json").status_code == 200


# --- S5: the public parsers ----------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [ORIGIN, "https://app.defender.test", "https://app.defender.test:8443", "http://localhost"])
def test_origin_accepts_an_origin_as_a_browser_writes_it(text: str) -> None:
    """`origin()` returns an origin written as `Origin` is. (S5)"""
    from defender.api_server._settings import origin

    assert origin(text) == text


@pytest.mark.parametrize("text", [
    "", " " + ORIGIN, ORIGIN + " ", ORIGIN + "/", ORIGIN + "/app", "localhost:8000", "ftp://localhost", ORIGIN + "?a=1", ORIGIN + "#f",
    "http://LocalHost:8000", "HTTP://localhost:8000", "http://localhost:80", "http://bücher.example", "http://u@localhost:8000",
])
def test_origin_refuses_what_a_browser_would_not_send(text: str) -> None:
    """Misshapen origins raise `ValueError`. (S5)"""
    from defender.api_server._settings import origin

    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract; the message names the fix
        origin(text)


@pytest.mark.parametrize("text", ["artifacts.defender.test", "localhost", "a.b.c.example", "xn--bcher-kva.example", "a-b.example"])
def test_artifact_domain_accepts_a_bare_lowercase_hostname(text: str) -> None:
    """`artifact_domain()` returns the hostname. (S5)"""
    from defender.api_server._settings import artifact_domain

    assert artifact_domain(text) == text


@pytest.mark.parametrize("text", [
    "", " ", "Artifacts.Defender.Test", "https://artifacts.defender.test", "artifacts.defender.test:8443", "*.defender.test",
    "artifacts.defender.test/", "artifacts.defender.test/x", " artifacts.defender.test", "artifacts.defender.test\n",
    ".defender.test", "a..test", "-a.test", "a_b.test", "bücher.example", "a b.test",
])
def test_artifact_domain_refuses_anything_but_a_bare_lowercase_hostname(text: str) -> None:
    """Scheme, port, wildcard, path, case, spaces, non-ASCII: `ValueError`. (S5)"""
    from defender.api_server._settings import artifact_domain

    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract
        artifact_domain(text)


# --- S5: the launcher's four inputs --------------------------------------------------------------------------

@pytest.fixture
def fake_caddy(tmp_path: Path) -> Path:
    """A `caddy` on PATH that only records that it ran (a test-only stand-in: the launcher's refusals must come first)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "caddy-ran"
    script = bin_dir / "caddy"
    script.write_text(f"#!/bin/sh\necho \"$@\" > {marker}\nexit 0\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def _env(tmp_path: Path, bin_dir: Path, **over: str | None) -> dict[str, str]:
    dist = tmp_path / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("<html></html>")
    env = launcher_env(ORIGIN, "127.0.0.1:8001", dist, artifact_domain=ARTIFACT_DOMAIN, work=tmp_path / "work")
    env["PATH"] = f"{bin_dir}{os.pathsep}{os.path.dirname(sys.executable)}"
    for name, value in over.items():
        if value is None:
            env.pop(name)
        else:
            env[name] = value
    return env


INPUTS = {
    "DEFENDER_API_FRONTEND_ORIGIN": ["http://localhost:8000/app", "localhost:8000", "HTTP://localhost:8000"],
    "DEFENDER_ARTIFACT_DOMAIN": ["https://artifacts.defender.test", "*.defender.test", "Artifacts.Test", "a.test:8443"],
    "DEFENDER_INGRESS_API_UPSTREAM": ["localhost", "localhost:abc", "localhost:99999", ":8001", "http://localhost:8001"],
    "DEFENDER_INGRESS_FRONTEND_DIR": ["{tmp}/no-such-dir", "{tmp}/a-file"],
}


def test_the_launcher_starts_caddy_when_every_input_is_right(tmp_path: Path, fake_caddy: Path) -> None:
    """Positive control for the refusals: valid inputs reach Caddy. (S5, B9)"""
    done = run_launcher(_env(tmp_path, fake_caddy))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert (tmp_path / "caddy-ran").exists(), (done.stdout, done.stderr)


@pytest.mark.parametrize("name", sorted(INPUTS))
def test_the_launcher_refuses_an_unset_input_naming_it_before_caddy(name: str, tmp_path: Path, fake_caddy: Path) -> None:
    """Unset: non-zero exit, a message naming the setting, Caddy never started. (S5)"""
    done = run_launcher(_env(tmp_path, fake_caddy, **{name: None}))
    assert done.returncode > 0, (done.returncode, done.stderr)
    assert name in done.stdout + done.stderr
    assert not (tmp_path / "caddy-ran").exists()


@pytest.mark.parametrize(("name", "bad"), [(n, b) for n, values in sorted(INPUTS.items()) for b in values])
def test_the_launcher_refuses_a_misshapen_input_naming_it_before_caddy(name: str, bad: str, tmp_path: Path, fake_caddy: Path) -> None:
    """Misshapen: non-zero exit, a message naming the setting, Caddy never started. (S5)"""
    (tmp_path / "a-file").write_text("x")
    done = run_launcher(_env(tmp_path, fake_caddy, **{name: bad.format(tmp=tmp_path)}))
    assert done.returncode > 0, (done.returncode, done.stderr)
    assert name in done.stdout + done.stderr
    assert not (tmp_path / "caddy-ran").exists()
