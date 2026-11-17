"""#1161 piece 1, test-only: the built frontend behind the repo's ingress, started through its launcher (B9, S5, B11).

The launcher is `python -m defender.api_server.ingress` (the record's chosen name), which finds `caddy` on PATH. Its
four inputs are `DEFENDER_INGRESS_LISTEN`, `DEFENDER_ARTIFACT_DOMAIN`, `DEFENDER_INGRESS_API_UPSTREAM`
(`host:port`) and `DEFENDER_INGRESS_FRONTEND_DIR`; nothing else is passed. Missing tools and a missing frontend or
launcher fail loudly (B11), never skip.

- `require_tools()`: fails naming every missing tool (node, npm, caddy, playwright and its Chromium).
- `build_frontend()`: `npm ci && npm run build` in a copy of `defender/frontend/` outside the checkout, kept by the hash
  of its sources (a file lock per hash keeps runs and xdist workers from building it twice); returns that copy's `dist/`,
  beside its `node_modules/`.
- `ingress(upstream, frontend_dir, ...)`: the launcher running; yields the origin `http://localhost:<port>`.
- `launcher_env(...)` and `run_launcher(env)`: for the launcher's refusals."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
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


#: What a build writes or installs in the frontend folder; never part of what a build is made from.
_BUILD_OUTPUTS = ("node_modules", "dist", "generated")
#: A build (with its `node_modules`, about 35 MB) unused this long is deleted by the next build; a staging folder left
#: by a killed build, after a day. Only by age, never "not the current one": a build another run serves stays.
_KEEP_BUILD = 7 * 24 * 3600
_KEEP_STAGING = 24 * 3600


def _prune(builds: Path, keep: Path) -> None:
    now = time.time()
    for entry in builds.iterdir():
        if entry == keep or not entry.is_dir():
            continue
        age = now - entry.stat().st_mtime
        if "-" in entry.name and age > _KEEP_STAGING:
            shutil.rmtree(entry, ignore_errors=True)
        elif "-" not in entry.name and age > _KEEP_BUILD:
            with open(builds / f"{entry.name}.lock", "w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                shutil.rmtree(entry, ignore_errors=True)


def _build_key(frontend: Path, shape_list: Path) -> str:
    """A hash of everything a build reads: the frontend's files as they are on disk (not only committed ones), the shape
    list and the Node version."""
    digest = hashlib.sha256()
    node = subprocess.run(["node", "--version"], capture_output=True, text=True, check=False).stdout.strip()
    digest.update(node.encode() + b"\0")
    files = sorted(p for p in frontend.rglob("*")
                   if p.is_file() and not set(p.relative_to(frontend).parts) & set(_BUILD_OUTPUTS))
    for path in [*files, shape_list]:
        digest.update(str(path.relative_to(frontend.parent)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()[:24]


def build_frontend(frontend: Path = FRONTEND) -> Path:
    """The frontend built to static files; its `dist/`. The build runs in a copy of the frontend and the shape list
    (`npm ci && npm run build` there), in a folder outside the checkout named by the hash of what it was made from, and
    is moved into place whole: the checkout is never written, a finished build is never changed, and another run
    serving one is never disturbed. A run whose sources match a finished build reuses it."""
    assert (frontend / "package.json").is_file(), f"no frontend at {frontend} (#1161 B8)"
    shape_list = frontend.parent / "api" / "addresses.json"
    builds = Path(tempfile.gettempdir()) / "defender-frontend-builds"
    builds.mkdir(exist_ok=True)
    done = builds / _build_key(frontend, shape_list)
    dist = done / "defender" / "frontend" / "dist"
    with open(builds / f"{done.name}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not done.exists():
            staging = Path(tempfile.mkdtemp(prefix=f"{done.name}-", dir=builds))
            try:
                copy = staging / "defender" / "frontend"
                shutil.copytree(frontend, copy, ignore=shutil.ignore_patterns(*_BUILD_OUTPUTS))
                (staging / "defender" / "api").mkdir()
                shutil.copy2(shape_list, staging / "defender" / "api" / "addresses.json")
                for argv in (["npm", "ci", "--no-audit", "--no-fund"], ["npm", "run", "build"]):
                    ran = subprocess.run(argv, cwd=copy, capture_output=True, text=True, check=False)
                    assert ran.returncode == 0, f"`{' '.join(argv)}` failed:\n{ran.stdout[-2000:]}\n{ran.stderr[-2000:]}"
                staging.rename(done)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
        os.utime(done)  # in use: the prune keeps it
    _prune(builds, done)
    assert (dist / "index.html").is_file(), f"the build made no {dist / 'index.html'}"
    return dist


def launcher_env(listen: str, upstream: str, frontend_dir: Path, *, artifact_domain: str = ARTIFACT_DOMAIN,
                 work: Path | None = None) -> dict[str, str]:
    """The launcher's environment: its four inputs, the process's PATH and HOME-like basics (so Caddy runs), and
    `XDG_*` under `work` so instances keep no shared state."""
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/root"),
           "PYTHONPATH": os.pathsep.join(p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p),
           "DEFENDER_INGRESS_LISTEN": listen, "DEFENDER_ARTIFACT_DOMAIN": artifact_domain,
           "DEFENDER_INGRESS_API_UPSTREAM": upstream, "DEFENDER_INGRESS_FRONTEND_DIR": str(frontend_dir)}
    if work is not None:
        env |= {"XDG_DATA_HOME": str(work / "xdg-data"), "XDG_CONFIG_HOME": str(work / "xdg-config")}
    return env


def run_launcher(env: Mapping[str, str], timeout: float = 20.0, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """The launcher once, to its end or `timeout` (then killed, returncode -9), from `cwd` (the repo root by default).
    For refusals: it must exit non-zero, naming the setting, before Caddy starts."""
    return run_launcher_pid(env, timeout, cwd=cwd)[0]


def run_launcher_pid(env: Mapping[str, str], timeout: float = 20.0, *,
                     cwd: Path | None = None) -> tuple[subprocess.CompletedProcess[str], int]:
    """`run_launcher`, and the launcher's process id (what a Caddy it `exec`s keeps)."""
    process = subprocess.Popen(LAUNCHER, env=dict(env), cwd=cwd or REPO, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate()
        return subprocess.CompletedProcess(LAUNCHER, -9, out, err + "\n[killed: still running]"), process.pid
    return subprocess.CompletedProcess(LAUNCHER, process.returncode, out, err), process.pid


@contextlib.contextmanager
def ingress(upstream: str, frontend_dir: Path, work: Path, *, port: int | None = None,
            artifact_domain: str = ARTIFACT_DOMAIN) -> Iterator[str]:
    """The launcher running, serving `frontend_dir` and sending `/api` to `upstream` (`host:port`); yields its origin,
    `http://localhost:<port>` (Chromium treats localhost as secure, so `__Host-` cookies work over http). The
    launcher runs in its own session, so teardown kills whatever it started."""
    port = port or free_port()
    origin = f"http://localhost:{port}"
    work.mkdir(parents=True, exist_ok=True)
    log = (work / "ingress.log").open("w+")
    process = subprocess.Popen(LAUNCHER, cwd=REPO, text=True, stdout=log, stderr=subprocess.STDOUT,
                               env=launcher_env(f"127.0.0.1:{port}", upstream, frontend_dir, artifact_domain=artifact_domain,
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
