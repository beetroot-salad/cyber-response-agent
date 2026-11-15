"""#1161 piece 1, test-only: the built frontend behind the repo's ingress, started through its launcher (B9, S5, B11).

The launcher is `python -m defender.api_server.ingress` (the record's chosen name), which finds `caddy` on PATH. Its
four inputs are `DEFENDER_API_FRONTEND_ORIGIN`, `DEFENDER_ARTIFACT_DOMAIN`, `DEFENDER_INGRESS_API_UPSTREAM`
(`host:port`) and `DEFENDER_INGRESS_FRONTEND_DIR`; nothing else is passed. Missing tools and a missing frontend or
launcher fail loudly (B11), never skip.

- `require_tools()`: fails naming every missing tool (node, npm, caddy, playwright and its Chromium).
- `build_frontend()`: `npm ci && npm run build` in `defender/frontend/` once per pytest run (a file lock and a stamp
  keyed by `PYTEST_XDIST_TESTRUNUID` keep xdist workers from building at once); returns `dist/`.
- `ingress(upstream, frontend_dir, ...)`: the launcher running; yields the origin `http://localhost:<port>`.
- `launcher_env(...)` and `run_launcher(env)`: for the launcher's refusals."""
from __future__ import annotations

import contextlib
import fcntl
import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping
from pathlib import Path

import httpx

from defender.tests.support.api._server1083 import REPO, free_port

FRONTEND = REPO / "defender" / "frontend"
ARTIFACT_DOMAIN = "artifacts.defender.test"
LAUNCHER = [sys.executable, "-m", "defender.api_server.ingress"]
START_TIMEOUT = 30.0


def require_tools() -> None:
    """Fail (AssertionError, never a skip) naming every tool the browser tests need that is missing."""
    missing = [f"{tool} (on PATH)" for tool in ("node", "npm", "caddy") if shutil.which(tool) is None]
    if importlib.util.find_spec("playwright") is None:
        missing.append("the playwright Python package")
    elif not _chromium_present():
        missing.append("Playwright's Chromium (playwright install chromium)")
    assert not missing, f"the browser tests need tools that are missing (B11: a failure, never a skip): {missing}"


def _chromium_present() -> bool:
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as pw:
            pw.chromium.launch().close()  # the headless one tests use (the full build may not be installed)
    except Exception:  # noqa: BLE001 — any launch failure is a missing or broken browser
        return False
    return True


def build_frontend(frontend: Path = FRONTEND) -> Path:
    """The frontend built to static files, once per run; its `dist/`."""
    assert (frontend / "package.json").is_file(), f"no frontend at {frontend} (#1161 B8)"
    run_id = os.environ.get("PYTEST_XDIST_TESTRUNUID", f"pid{os.getpid()}")
    stamp = Path(tempfile.gettempdir()) / f"defender-frontend-built-{run_id}"
    with open(Path(tempfile.gettempdir()) / "defender-frontend-build.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not stamp.exists():
            for argv in (["npm", "ci", "--no-audit", "--no-fund"], ["npm", "run", "build"]):
                done = subprocess.run(argv, cwd=frontend, capture_output=True, text=True, check=False)
                assert done.returncode == 0, f"`{' '.join(argv)}` failed:\n{done.stdout[-2000:]}\n{done.stderr[-2000:]}"
            stamp.write_text("built")
    dist = frontend / "dist"
    assert (dist / "index.html").is_file(), f"the build made no {dist / 'index.html'}"
    return dist


def launcher_env(origin: str, upstream: str, frontend_dir: Path, *, artifact_domain: str = ARTIFACT_DOMAIN,
                 work: Path | None = None) -> dict[str, str]:
    """The launcher's environment: its four inputs, the process's PATH and HOME-like basics (so Caddy runs), and
    `XDG_*` under `work` so instances keep no shared state."""
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/root"),
           "PYTHONPATH": os.pathsep.join(p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p),
           "DEFENDER_API_FRONTEND_ORIGIN": origin, "DEFENDER_ARTIFACT_DOMAIN": artifact_domain,
           "DEFENDER_INGRESS_API_UPSTREAM": upstream, "DEFENDER_INGRESS_FRONTEND_DIR": str(frontend_dir)}
    if work is not None:
        env |= {"XDG_DATA_HOME": str(work / "xdg-data"), "XDG_CONFIG_HOME": str(work / "xdg-config")}
    return env


def run_launcher(env: Mapping[str, str], timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
    """The launcher once, to its end or `timeout` (then killed, returncode -9). For refusals: it must exit non-zero,
    naming the setting, before Caddy starts."""
    process = subprocess.Popen(LAUNCHER, env=dict(env), cwd=REPO, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate()
        return subprocess.CompletedProcess(LAUNCHER, -9, out, err + "\n[killed: still running]")
    return subprocess.CompletedProcess(LAUNCHER, process.returncode, out, err)


@contextlib.contextmanager
def ingress(upstream: str, frontend_dir: Path, work: Path, *, port: int | None = None,
            artifact_domain: str = ARTIFACT_DOMAIN) -> Iterator[str]:
    """The launcher running, serving `frontend_dir` and sending `/api` to `upstream` (`host:port`); yields its origin,
    `http://localhost:<port>` (Chromium treats localhost as secure, so `__Host-` cookies work over http). The
    launcher runs in its own session, so teardown kills whatever it started."""
    origin = f"http://localhost:{port or free_port()}"
    work.mkdir(parents=True, exist_ok=True)
    log = (work / "ingress.log").open("w+")
    process = subprocess.Popen(LAUNCHER, cwd=REPO, text=True, stdout=log, stderr=subprocess.STDOUT,
                               env=launcher_env(origin, upstream, frontend_dir, artifact_domain=artifact_domain,
                                                work=work), start_new_session=True)
    try:
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            log.seek(0)
            assert process.poll() is None, f"the launcher exited {process.returncode}:\n{log.read()}"
            with contextlib.suppress(httpx.TransportError):
                httpx.get(f"{origin}/", timeout=2)
                break
            assert time.monotonic() < deadline, f"the ingress never answered at {origin}:\n{log.read()}"
            time.sleep(0.2)
        yield origin
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        log.close()
