"""#1161 piece 1 (as amended by #1540 r3.1), test-only: the built frontend behind the repo's ingress, started through its
launcher (B9, S5, B11).

The launcher is `python -m defender.api_server.ingress` (the record's chosen name), which finds `caddy` on PATH. Its
four inputs are `DEFENDER_INGRESS_LISTEN`, `DEFENDER_ARTIFACT_DOMAIN`, `DEFENDER_INGRESS_API_UPSTREAM`
(`host:port`) and `DEFENDER_INGRESS_FRONTEND_DIR`; nothing else is passed. Missing tools and a missing frontend or
launcher fail loudly (B11), never skip.

- `require_tools()`: fails naming every missing tool (bun, caddy, playwright and its Chromium).
- `frontend_inputs(frontend=FRONTEND)`: PR6's list as absolute paths: the files outside `defender/frontend/` the build
  reads, from `package.json`'s `defender.inputs` (paths relative to the frontend folder, e.g. `../api/addresses.json`).
  Fails when the key is missing or names a file that is not there.
- `copy_frontend(dest_root, *, inputs_override=None, node_modules_from=None)`: THE copy helper, used by every test that
  copies the frontend. Copies `defender/frontend/` (without `node_modules`, `dist`, `generated`) to
  `dest_root/defender/frontend` and each declared input to the same place relative to the repo root (so
  `../api/addresses.json` lands at `dest_root/defender/api/addresses.json`); returns the copy's frontend folder.
  `inputs_override` maps a declared input path (the string as `package.json` writes it) to replacement bytes, or to
  None to leave that input out; a key that is not a declared input fails. `node_modules_from` is a `node_modules`
  folder (see `node_modules_of`) to symlink into the copy. A test edits the copy's `src/` (or any file) after the call.
- `run_bun(frontend_copy, *args, timeout=600)`: `bun <args>` in the copy, output captured, never raising on a non-zero
  exit (`returncode`, `stdout`, `stderr` are the observation).
- `build_frontend()`: `bun install --frozen-lockfile` then `bun run build` in a `copy_frontend` copy outside the
  checkout, kept by the hash of the frontend files, every declared input and `bun --version` (a file lock per hash
  keeps runs and xdist workers from building it twice); returns that copy's `dist/`, beside its `node_modules/`
  (`node_modules_of(dist)`).
- `ingress(upstream, frontend_dir, ...)`: the launcher running; yields the origin `http://localhost:<port>`.
- `launcher_env(...)` and `run_launcher(env)`: for the launcher's refusals."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.util
import json
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
    missing = [f"{tool} (on PATH)" for tool in ("bun", "caddy") if shutil.which(tool) is None]
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
_BUILD_OUTPUTS = ("node_modules", "dist", "dist-staging", "dist-previous", "generated")
#: A build (with its `node_modules`) unused this long is deleted by the next build; a staging folder left
#: by a killed build, after a day. Only by age, never "not the current one": a build another run serves stays.
_KEEP_BUILD = 7 * 24 * 3600
_KEEP_STAGING = 24 * 3600


def frontend_inputs(frontend: Path = FRONTEND) -> list[Path]:
    """PR6: the files outside `frontend` that the build reads, from `package.json`'s `defender.inputs` (paths relative
    to `frontend`), as absolute paths in declared order. Fails loudly when the key is missing or a file is absent."""
    package = json.loads((frontend / "package.json").read_text())
    declared = (package.get("defender") or {}).get("inputs")
    well_formed = isinstance(declared, list) and bool(declared) and all(isinstance(d, str) for d in declared)
    assert well_formed, (
        f"PR6: {frontend / 'package.json'} must name the build's inputs in `defender.inputs` (a list of paths "
        f"relative to the frontend folder); found {declared!r}")
    assert isinstance(declared, list)  # narrows for the type checker; `well_formed` said why
    paths = [Path(os.path.normpath(frontend / d)) for d in declared]
    missing = [str(p) for p in paths if not p.is_file()]
    assert not missing, f"PR6: declared build inputs that are not files: {missing}"
    return paths


def _declared(frontend: Path) -> dict[str, Path]:
    declared = json.loads((frontend / "package.json").read_text())["defender"]["inputs"]
    return dict(zip(declared, frontend_inputs(frontend), strict=True))


def copy_frontend(dest_root: Path, *, inputs_override: Mapping[str, bytes | None] | None = None,
                  node_modules_from: Path | None = None, frontend: Path = FRONTEND) -> Path:
    """The one copy of the frontend a test makes: see the module docstring. Returns `dest_root/defender/frontend`."""
    declared = _declared(frontend)
    override = dict(inputs_override or {})
    unknown = sorted(set(override) - set(declared))
    assert not unknown, f"not declared build inputs: {unknown} (declared: {sorted(declared)})"
    root = frontend.parent.parent  # the folder the declared paths are relative to, from the repo root
    copy = dest_root / frontend.relative_to(root)
    shutil.copytree(frontend, copy, ignore=shutil.ignore_patterns(*_BUILD_OUTPUTS))
    for name, source in declared.items():
        target = dest_root / source.relative_to(root)
        if name in override and override[name] is None:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if name in override:
            target.write_bytes(override[name])  # type: ignore[arg-type]
        else:
            shutil.copy2(source, target)
    if node_modules_from is not None:
        (copy / "node_modules").symlink_to(node_modules_from)
    return copy


def node_modules_of(dist: Path) -> Path:
    """The `node_modules` folder beside a `build_frontend()` result's frontend copy, for `node_modules_from`."""
    return dist.parent / "node_modules"


def run_bun(frontend_copy: Path, *args: str, timeout: float = 600) -> subprocess.CompletedProcess[str]:
    """`bun <args>` in `frontend_copy`, output captured; a non-zero exit is returned, not raised."""
    return subprocess.run(["bun", *args], cwd=frontend_copy, capture_output=True, text=True, check=False,
                          timeout=timeout)


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


def _build_key(frontend: Path) -> str:
    """A hash of everything a build reads: the frontend's files as they are on disk (not only committed ones), every
    declared input and Bun's version."""
    digest = hashlib.sha256()
    bun = subprocess.run(["bun", "--version"], capture_output=True, text=True, check=False).stdout.strip()
    digest.update(bun.encode() + b"\0")
    files = sorted(p for p in frontend.rglob("*")
                   if p.is_file() and not set(p.relative_to(frontend).parts) & set(_BUILD_OUTPUTS))
    for path in [*files, *frontend_inputs(frontend)]:
        digest.update(str(path.relative_to(frontend.parent.parent)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()[:24]


def build_frontend(frontend: Path = FRONTEND) -> Path:
    """The frontend built to static files; its `dist/`. The build runs in a `copy_frontend` copy
    (`bun install --frozen-lockfile && bun run build` there), in a folder outside the checkout named by the hash of what
    it was made from, and is moved into place whole: the checkout is never written, a finished build is never changed,
    and another run serving one is never disturbed. A run whose sources match a finished build reuses it."""
    assert (frontend / "package.json").is_file(), f"no frontend at {frontend} (#1161 B8)"
    builds = Path(tempfile.gettempdir()) / "defender-frontend-builds"
    builds.mkdir(exist_ok=True)
    done = builds / _build_key(frontend)
    dist = done / "defender" / "frontend" / "dist"
    with open(builds / f"{done.name}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not done.exists():
            staging = Path(tempfile.mkdtemp(prefix=f"{done.name}-", dir=builds))
            try:
                copy = copy_frontend(staging, frontend=frontend)
                for args in (["install", "--frozen-lockfile"], ["run", "build"]):
                    ran = run_bun(copy, *args)
                    assert ran.returncode == 0, f"`bun {' '.join(args)}` failed:\n{ran.stdout[-2000:]}\n{ran.stderr[-2000:]}"
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
