"""#1161 piece 1: the API's address space (B3) and the shared setting parsers and ingress launcher (S5)."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import ANN, T1, World  # noqa: E402
from defender.tests.support.frontend._ingress1161 import (  # noqa: E402
    ARTIFACT_DOMAIN,
    FORGE_UPSTREAM_ENV,
    REPO,
    launcher_env,
    run_launcher,
    run_launcher_pid,
)

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
    outside = [p for p in paths if not p.startswith("/api/")]
    assert outside == []
    browser = world.client()
    document = browser.get("/api/openapi.json")
    assert document.status_code == 200
    assert all(p.startswith("/api/") for p in document.json()["paths"])
    for old in ("/openapi.json", "/me", "/auth/login", "/docs", "/redoc"):
        assert browser.get(old).status_code == 404, old
    assert browser.get("/api/me").status_code == 401  # control: the moved route is there


def test_no_route_answers_at_its_old_address() -> None:
    """Every real route's un-prefixed path, with each of its methods, answers 404: nothing keeps serving where it used to,
    whatever the route. Derived from the route table, not a list. (B3)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    old = sorted({(method, re.sub(r"\{[^}]*\}", "x", r.path).removeprefix("/api"))
                  for r in _routes(world.app.routes) for method in (getattr(r, "methods", None) or {"GET"})
                  if method not in ("HEAD", "OPTIONS")})
    assert len(old) > 20, old
    assert all(path.startswith("/") for _, path in old), old
    still_served = [(method, path, browser.request(method, path).status_code) for method, path in old]
    assert [row for row in still_served if row[2] != 404] == []
    assert browser.get("/api/me").status_code == 401  # control: the moved route is there


def test_the_docs_pages_are_not_served_by_default() -> None:
    """No interactive page exists, under `/api` or at the root; the document does. (B10)"""
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


@pytest.mark.parametrize("text", [
    "http://a_b.test", "http://-a.test", "http://a-.test", "http://a..test", "http://x.test.", "http://a%20b.test",
    "http://127.0.0.1:8000", "http://10.0.0.1", "http://999.1.1.1", "http://1.2.3", "http://0x7f", "http://a.0x1f",
    "http://app.0xyz", "http://a.1b", "http://[::1]:8000", "https://[2001:db8::1]", "http://[::ffff:102:304]",
])
def test_origin_refuses_a_host_that_is_not_a_domain_name(text: str) -> None:
    """The host is a domain name: the hostname rule, its last label starting with a letter. No IP address, and nothing
    a browser could read as one (a last label starting with a digit), so the browser's `Origin` is the host as
    written and a setting no `Origin` could equal fails at start. (#1566)"""
    from defender.api_server._settings import origin

    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract; the message names the fix
        origin(text)


@pytest.mark.parametrize("text", [
    "https://a-b.c9.example", "https://xn--bcher-kva.example", "http://localhost:8000", "https://9a.example",
    "https://app.x0", "https://0x.example",
])
def test_origin_accepts_a_domain_name_whose_last_label_starts_with_a_letter(text: str) -> None:
    """Control for the refusals above: digits anywhere but at the start of the last label. (#1566)"""
    from defender.api_server._settings import origin

    assert origin(text) == text


@pytest.mark.parametrize("text", ["artifacts.defender.test", "localhost", "a.b.c.example", "xn--bcher-kva.example", "a-b.example"])
def test_artifact_domain_accepts_a_bare_lowercase_hostname(text: str) -> None:
    """`artifact_domain()` returns the hostname. (S5)"""
    from defender.api_server._settings import artifact_domain

    assert artifact_domain(text) == text


@pytest.mark.parametrize("text", [
    "", " ", "Artifacts.Defender.Test", "https://artifacts.defender.test", "artifacts.defender.test:8443", "*.defender.test",
    "artifacts.defender.test/", "artifacts.defender.test/x", " artifacts.defender.test", "artifacts.defender.test\n",
    ".defender.test", "a..test", "-a.test", "a_b.test", "bücher.example", "a b.test", "10.0.0.1", "a.0x1f",
])
def test_artifact_domain_refuses_anything_but_a_bare_lowercase_hostname(text: str) -> None:
    """Scheme, port, wildcard, path, case, spaces, non-ASCII: `ValueError`. (S5)"""
    from defender.api_server._settings import artifact_domain

    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract
        artifact_domain(text)


# --- S5: the launcher's four inputs --------------------------------------------------------------------------

@pytest.fixture
def fake_caddy(tmp_path: Path) -> Path:
    """A `caddy` on PATH that only records that it ran, its own process id and its arguments, one per line (a test-only
    stand-in: the launcher's refusals must come first)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "caddy-ran"
    script = bin_dir / "caddy"
    script.write_text(f"#!/bin/sh\necho \"$@\" > {marker}\necho $$ > {marker}.pid\nprintf '%s\\n' \"$@\" > {marker}.argv\nexit 0\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def _env(tmp_path: Path, bin_dir: Path, **over: str | None) -> dict[str, str]:
    dist = tmp_path / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("<html></html>")
    env = launcher_env("127.0.0.1:8000", "127.0.0.1:8001", dist, artifact_domain=ARTIFACT_DOMAIN, work=tmp_path / "work")
    env["PATH"] = f"{bin_dir}{os.pathsep}{os.path.dirname(sys.executable)}"
    for name, value in over.items():
        if value is None:
            env.pop(name)
        else:
            env[name] = value
    return env


INPUTS = {
    "DEFENDER_INGRESS_LISTEN": ["localhost", "localhost:abc", "localhost:99999", ":8000", "http://localhost:8000"],
    "DEFENDER_ARTIFACT_DOMAIN": ["https://artifacts.defender.test", "*.defender.test", "Artifacts.Test", "a.test:8443"],
    "DEFENDER_INGRESS_API_UPSTREAM": ["localhost", "localhost:abc", "localhost:99999", ":8001", "http://localhost:8001"],
    "DEFENDER_FORGE_DOMAIN": ["https://forge.defender.test", "*.defender.test", "Forge.Test", "f.test:8443", "f.test/x"],
    FORGE_UPSTREAM_ENV: ["localhost", "localhost:abc", "localhost:99999", ":3000", "http://localhost:3000"],
    "DEFENDER_INGRESS_FRONTEND_DIR": ["{tmp}/no-such-dir", "{tmp}/a-file", "{tmp}/my dist", "{tmp}/a}}b", "{tmp}/a{{b",
                                      "{tmp}/a\nb", "{tmp}/a#b", '{tmp}/a"b', "{tmp}/a\tb"],
}


def test_the_launcher_starts_caddy_when_every_input_is_right(tmp_path: Path, fake_caddy: Path) -> None:
    """Positive control for the refusals: valid inputs reach Caddy. (S5, B9)"""
    done = run_launcher(_env(tmp_path, fake_caddy))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert (tmp_path / "caddy-ran").exists(), (done.stdout, done.stderr)


def test_the_launcher_execs_caddy_so_signals_reach_it(tmp_path: Path, fake_caddy: Path) -> None:
    """Caddy runs as the launcher's own process (`exec`): its `$$` is the launcher's pid. (S5, B9)"""
    done, pid = run_launcher_pid(_env(tmp_path, fake_caddy))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert (tmp_path / "caddy-ran.pid").read_text().strip() == str(pid)


def test_the_launcher_hands_caddy_the_repos_own_caddyfile_from_any_directory(tmp_path: Path, fake_caddy: Path) -> None:
    """From a directory that is not the repo root, Caddy is given the absolute path of `defender/frontend/Caddyfile`,
    and Caddy adapts that very file with its admin endpoint off (the file the Caddyfile tests read). (S5, B9)"""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env = _env(tmp_path, fake_caddy)
    done = run_launcher(env, cwd=elsewhere)
    assert done.returncode == 0, (done.stdout, done.stderr)
    argv = (tmp_path / "caddy-ran.argv").read_text().splitlines()
    given = [a.removeprefix("--config=") if a.startswith("--config=") else argv[i + 1]
             for i, a in enumerate(argv) if a == "--config" or a.startswith("--config=")]
    assert len(given) == 1, argv
    repos = (REPO / "defender" / "frontend" / "Caddyfile").resolve()
    assert os.path.isabs(given[0]), (given[0], argv)
    assert Path(given[0]).resolve() == repos, (given[0], argv)
    caddy = shutil.which("caddy")
    assert caddy is not None, "the Caddyfile check needs caddy on PATH (B11: a failure, never a skip)"
    adapted = subprocess.run([caddy, "adapt", "--config", given[0], "--adapter", "caddyfile"], env=env | {"PATH": os.environ["PATH"]},
                             cwd=elsewhere, capture_output=True, text=True, check=False, timeout=60)
    assert adapted.returncode == 0, adapted.stderr[-1500:]
    assert json.loads(adapted.stdout)["admin"]["disabled"] is True


@pytest.mark.parametrize("given", [None, ""], ids=["absent", "empty"])
@pytest.mark.parametrize("name", sorted(INPUTS))
def test_the_launcher_refuses_an_unset_input_naming_it_before_caddy(
        name: str, given: str | None, tmp_path: Path, fake_caddy: Path) -> None:
    """Not given, absent or empty (Caddy's `{env.X}` of an unset name): non-zero exit, a message naming the setting, Caddy never started. (S5)"""
    done = run_launcher(_env(tmp_path, fake_caddy, **{name: given}))
    assert done.returncode > 0, (done.returncode, done.stderr)
    assert name in done.stdout + done.stderr
    assert not (tmp_path / "caddy-ran").exists()


@pytest.mark.parametrize(("name", "bad"), [(n, b) for n, values in sorted(INPUTS.items()) for b in values])
def test_the_launcher_refuses_a_misshapen_input_naming_it_before_caddy(name: str, bad: str, tmp_path: Path, fake_caddy: Path) -> None:
    """Misshapen: non-zero exit, a message naming the setting, Caddy never started. (S5)"""
    (tmp_path / "a-file").write_text("x")
    for folder in ("my dist", "a}b", "a{b", "a\nb", "a#b", 'a"b', "a\tb"):  # each exists: only its shape is wrong
        (tmp_path / folder).mkdir()
    done = run_launcher(_env(tmp_path, fake_caddy, **{name: bad.format(tmp=tmp_path)}))
    assert done.returncode > 0, (done.returncode, done.stderr)
    assert name in done.stdout + done.stderr
    assert not (tmp_path / "caddy-ran").exists()


def test_the_redirect_uri_the_provider_is_sent_names_the_callback_route() -> None:
    """The path the program puts in the provider's redirect URI is the callback route's own, under `/api`. (B3, S1)"""
    from defender.api.app import SIGNIN_CALLBACK

    world = World(tenants={T1: [ANN]})
    assert SIGNIN_CALLBACK == "/api/auth/callback"
    assert SIGNIN_CALLBACK in {getattr(r, "path", None) for r in _routes(world.app.routes)}
