"""Shared machinery for #1092's executable spec — NOT a test module (the leading underscore
keeps pytest from collecting it). Imported by the `test_1092_*.py` files, which live directly
under `defender/tests/` because `spec-graph binds` scans that directory non-recursively.

Every demand of `spec-flow/specs/spec_graph_1092.yaml` is exactly one test in those files,
named by the demand's `discharged_by`; the test's docstring carries the demand's prose.

THE FAULT-INJECTION HIERARCHY, applied (phases/author.md):

  tier 1 — REAL input through the REAL primitive, in the test itself. A tree that cannot
  name an image is built by deleting a file or putting a DIRECTORY in its place (root runs
  this suite, so a permission bit cannot make a file unreadable — `IsADirectoryError` can);
  the shims are the real `bin/defender-*` scripts exec'd by the real shell over stub
  interpreters; `reexec_into_venv` really `os.execv`s; the build script's `docker` is a
  real executable on PATH that records its argv; the drain's worktree is a real git repo
  whose HEAD is the commit the fault must name.

  tier 2 — a declarative fake whose fault CONTENT cites the ledger claim that observed it on
  the real daemon. `RecordingDocker` (from `_box665`) is reused; `NoSuchImageDocker` below
  answers the preflight `docker image inspect` with the daemon's `No such image: <ref>` rc 1
  (`NO_SUCH_IMAGE_CITE`), echoing the image token OFF THE ASKED ARGV so a fixture can never
  name an image the builder did not resolve — and leaves the create healthy, so a preflight
  that did not fire is caught by the create it lets through.

  tier 3 — an author-imagined fault is banned; none is used here.

RED AGAINST HEAD is the expected state of a spec. `runtime/box/_image.py`,
`defender/scripts/box_image.py`, `defender/box.Dockerfile`, `_BOX_MARK_ENV`, the `box` extra,
the missing-image preflight and the CI build step do not exist at b016749c. Every reference to a
future symbol is LAZY — reached inside a call site a test invokes (`box_mod.image_tag`, a path
that is stat'd in the body) — so every module still COLLECTS at HEAD and each test fails on
its own missing piece rather than taking the suite's collection down with it.

No `monkeypatch.setattr` anywhere: fakes enter through `docker=`, `start_box=`, `branch=`,
`shared_mounts` and the `run=` seam this spec demands of `_spec771.run_probe_under_profile`;
`monkeypatch.setenv`/`delenv` are used for env knobs and are outside the ratcheted gate.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

from defender._git import git_head_sha
from defender.runtime import box as box_mod
from defender.runtime.bash_exec import parse
from defender.runtime.box_codec import BoxFault, BoxResult
from defender.tests._by_path import DEFENDER, WORKTREE as REPO_ROOT
from defender.tests._repo import seed_repo
from defender.tests.e2e._box665 import (  # noqa: F401 — re-exported for the test files
    BoxLifecycleRecorder,
    DockerFault,
    RecordingBranch,
    RecordingDocker,
    _cp,
    drive_worktree_batch,
    requires_live_box,
)
from defender.tests.e2e._spec771 import requires_daemon, requires_real_box  # noqa: F401

#: The two files the image name is a function of, IN THE ORDER the resolver reads them —
#: the order decides which file a "cannot read" fault names first (MF1 part 1). #1097 M3: the
#: recipe and the exported package list, never the manifests the list is exported FROM.
HASH_INPUTS: tuple[str, ...] = ("box.Dockerfile", "box-requirements.txt")

#: Files a real tree still carries beside the inputs that must NOT name the image (#1097 O1):
#: an edit to either that leaves the exported list unchanged cannot change what the image
#: installs, so it must not rename it.
BYSTANDERS: tuple[str, ...] = ("uv.lock", "pyproject.toml")

#: The two new code files and the Dockerfile, where the amendment sites them (N10, F26).
IMAGE_PY = DEFENDER / "runtime" / "box" / "_image.py"
BOX_IMAGE_PY = DEFENDER / "scripts" / "box_image.py"
DOCKERFILE = DEFENDER / "box.Dockerfile"
#: The committed export the image installs and is named from (#1097 M1).
BOX_REQUIREMENTS = DEFENDER / "box-requirements.txt"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
README_RUNTIME = REPO_ROOT / ".devcontainer" / "README.runtime.md"

#: The stock image a FAKE-DOCKER test pins when it needs "an image" (the amendment's "tests
#: that need a stock image pin one"; real-daemon tests pin `image_tag(DEFENDER)` — #94).
STOCK_ROOTFS = "python:3.11-slim"

#: The name shape MF3 settled: `defender-box:<RECIPE_VERSION>-<12 hex>`.
TAG_RE = re.compile(r"^defender-box:(?P<version>[A-Za-z0-9._]+)-(?P<digest>[0-9a-f]{12})$")

#: The remedy's tail, relative to the tree — what the README documents and the fault names
#: absolutely (d42/d45).
BUILD_COMMAND_TAIL = "defender/scripts/box_image.py build"

#: The regenerate command the drift check names when the committed list is stale (#1097 M4).
EXPORT_COMMAND = "python3 defender/scripts/box_image.py export"

EXEC_TIMEOUT = 60.0

#: Synthetic bytes for a planted tree's inputs. Deterministic, so two plantings name the same
#: image (d4) and a one-byte edit names another (d3).
PLANTED_INPUT_BYTES: dict[str, bytes] = {
    "box.Dockerfile": b"FROM python:3.11-slim@sha256:" + b"0" * 64 + b"\nRUN true\n",
    "box-requirements.txt": b"planted==0.0.0 \\\n    --hash=sha256:" + b"0" * 64 + b"\n",
}

#: Synthetic bytes for the bystanders a planted tree also carries — a real tree has them, and
#: an image name that still read them would move when they do (d3's negative half).
PLANTED_BYSTANDER_BYTES: dict[str, bytes] = {
    "uv.lock": b"version = 1\nrevision = 3\n",
    "pyproject.toml": b"[project]\nname = \"planted\"\nversion = \"0.0.0\"\n",
}


# ---- the resolver, reached lazily -------------------------------------------------------------
def image_tag(tree: Path) -> str:
    """`runtime/box/_image.py::image_tag(tree)` through the package door. AttributeError at
    HEAD — the module does not exist — which is the red every naming test fails on."""
    return box_mod.image_tag(tree)  # type: ignore[attr-defined]


def recipe_version() -> str:
    """`_image.RECIPE_VERSION` — the constant that prefixes the name (MF3)."""
    from defender.runtime.box import _image  # type: ignore[attr-defined]

    return str(_image.RECIPE_VERSION)


# ---- trees ------------------------------------------------------------------------------------
def plant_tree(root: Path, *, missing: tuple[str, ...] = (), copy_code: bool = True) -> Path:
    """`root/defender` holding the hash inputs and the bystanders (synthetic bytes) — the
    DEFENDER DIR a box would mount — minus `missing`. With `copy_code`, the real `_image.py`
    and `box_image.py` are copied in where they exist, so the build script can be run FROM the
    planted tree and hash the planted tree's own inputs (F-B). Returns the defender dir.

    The bystanders (`uv.lock`, `pyproject.toml`) are planted too, because a real tree carries
    them: a tree that "lacks the inputs" still holds both, so a resolver that could name an
    image from them alone is caught (#1097 O1)."""
    defender_dir = root / "defender"
    defender_dir.mkdir(parents=True, exist_ok=True)
    for name, data in (*PLANTED_INPUT_BYTES.items(), *PLANTED_BYSTANDER_BYTES.items()):
        if name in missing:
            continue
        (defender_dir / name).write_bytes(data)
    if copy_code:
        for src, rel in ((IMAGE_PY, Path("runtime") / "box"), (BOX_IMAGE_PY, Path("scripts"))):
            if src.is_file():
                dest = defender_dir / rel
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, dest / src.name)
    return defender_dir


def plant_real_manifests(defender_dir: Path) -> Path:
    """Copy THIS checkout's `pyproject.toml` and `uv.lock` over a planted tree's synthetic
    bystanders, so `uv export` run there resolves the real closure (#1097). The real tree is
    only ever READ. Returns the defender dir."""
    for name in BYSTANDERS:
        shutil.copyfile(DEFENDER / name, defender_dir / name)
    return defender_dir


def load_box_image_script() -> ModuleType:
    """`defender/scripts/box_image.py`, loaded BY FILE PATH — the same door the script itself
    uses for `_image.py` (it is stdlib-only and never an importable `defender.*` module).
    Its #1097 attribute `export_requirements` is reached by the caller, lazily."""
    spec = importlib.util.spec_from_file_location("_box_image_script_1097", BOX_IMAGE_PY)
    assert spec is not None, BOX_IMAGE_PY
    assert spec.loader is not None, BOX_IMAGE_PY
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---- the exported package list, parsed (#1097 M4) ---------------------------------------------
@dataclass(frozen=True)
class Pinned:
    """One entry of a hash-pinned requirements list, normalised so that a formatting change in
    a newer `uv export` (wrapping, spacing, quote style, hash order) compares equal and a change
    to what would be INSTALLED does not."""

    version: str
    marker: str | None
    hashes: frozenset[str]


def parse_pinned(text: str) -> dict[str, Pinned]:
    """`canonical name -> Pinned` for a `uv export --no-header --no-annotate` list: `\\`
    continuations joined, whole-line comments dropped, each logical line `name==version
    [; marker]` followed by one or more `--hash=<algo>:<hex>`. STRICT — anything else on a
    line (an unpinned spec, an entry with no hash, an option line, a duplicate name) fails
    the caller's assertion rather than being skipped, and an empty list fails too: the parser
    is the comparison's own positive control."""
    from packaging.markers import Marker
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        logical.append((pending + line).strip())
        pending = ""
    if pending.strip():
        logical.append(pending.strip())

    out: dict[str, Pinned] = {}
    for entry in logical:
        head, *hash_parts = entry.split("--hash=")
        hashes = frozenset(h.strip() for h in hash_parts)
        assert hashes, f"no hash: {entry!r}"
        assert all(re.fullmatch(r"sha(256|384|512):[0-9a-f]{64,128}", h) for h in hashes), entry
        req = Requirement(head.strip())
        specs = list(req.specifier)
        assert len(specs) == 1, f"not an exact pin: {entry!r}"
        assert specs[0].operator == "==", f"not an exact pin: {entry!r}"
        assert not req.extras, entry
        assert req.url is None, entry
        name = str(canonicalize_name(req.name))
        assert name not in out, f"{name} listed twice"
        out[name] = Pinned(
            version=specs[0].version,
            marker=str(Marker(str(req.marker))) if req.marker is not None else None,
            hashes=hashes,
        )
    assert out, "the list parsed to no entries"
    return out


def lock_closure(env: dict | None = None) -> dict[str, str]:
    """`uv.lock`'s resolution of the project's core dependencies plus the `box` extra, closed
    over the lock's own dependency graph — canonical name -> version. With `env` (an image's
    `packaging.markers.default_environment()`), each edge's marker is evaluated for it (d21);
    without, every edge is followed — the universal closure an export lists (#1097). Reads
    the lock with `tomllib`, never uv: an oracle independent of the exporter it checks."""
    from packaging.markers import Marker
    from packaging.utils import canonicalize_name

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    by_name = {canonicalize_name(p["name"]): p for p in lock["package"]}
    environment = None if env is None else {**env, "extra": ""}

    def wanted(dep: dict) -> bool:
        marker = dep.get("marker")
        if not marker or environment is None:
            return True
        return Marker(marker).evaluate(environment, context="lock_file")

    root = by_name[canonicalize_name("defender")]
    stack = [
        (canonicalize_name(d["name"]), tuple(d.get("extra", ())))
        for d in [*root.get("dependencies", []), *root.get("optional-dependencies", {}).get("box", [])]
        if wanted(d)
    ]
    out: dict[str, str] = {}
    seen: set[tuple[str, tuple[str, ...]]] = set()
    while stack:
        name, extras = stack.pop()
        if (name, extras) in seen:
            continue
        seen.add((name, extras))
        pkg = by_name[name]
        out[str(name)] = pkg["version"]
        deps = list(pkg.get("dependencies", []))
        for extra in extras:
            deps += pkg.get("optional-dependencies", {}).get(extra, [])
        stack.extend(
            (canonicalize_name(d["name"]), tuple(d.get("extra", ()))) for d in deps if wanted(d)
        )
    return out


def make_run_dir(tmp_path: Path, name: str = "run-1092") -> Path:
    """A live run dir with the artifacts a host-side writer needs beside it."""
    run = tmp_path / "runs" / name
    (run / "gather_raw").mkdir(parents=True)
    (run / "alert.json").write_text('{"id": "a-1092"}\n', encoding="utf-8")
    return run


# ---- the fake daemon: a missing image, in the daemon's own words --------------------------------
#: `docker image inspect --format {{.Id}} <absent>` answers rc 1 with the daemon's one line
#: `Error response from daemon: No such image: <ref>` (CLI 29.6.1 / daemon 29.5.3, the
#: #1095 review-fix probe). The TEXT is never read by production — the preflight decides by
#: exit code, which is the whole point (#1095: the create's text differed across CLIs).
NO_SUCH_IMAGE_CITE = "#1095 image-inspect probe"


def no_such_image_stderr(ref: str) -> str:
    return f"Error response from daemon: No such image: {ref}\n"


#: What the CLI says when the daemon is not there — `docker image inspect` and `docker
#: version` both exit 1 with it (DOCKER_HOST pointed at an absent socket, CLI 29.6.1, the
#: #1095 round-2 probe). Same rc as a missing image; only the liveness probe tells them apart.
DAEMON_DOWN_STDERR = (
    "failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is "
    "correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such "
    "file or directory\n"
)


class NoSuchImageDocker(RecordingDocker):
    """`RecordingDocker` whose preflight `docker image inspect` answers rc 1 with the daemon's
    missing-image line for THE IMAGE THE START ASKED ABOUT (the last token of the inspect
    argv — `NO_SUCH_IMAGE_CITE`), recorded in `inspected_images`. The create is left HEALTHY:
    a start that reaches it did not preflight, and the test's `"run" not in subcommands`
    catches that. With `daemon_down`, the inspect AND the liveness probe (`docker version`)
    both fail with `DAEMON_DOWN_STDERR` — the other reading of the same rc."""

    def __init__(self, *, daemon_down: bool = False, **kw):
        super().__init__(**kw)
        self.cite = NO_SUCH_IMAGE_CITE
        self.daemon_down = daemon_down
        self.inspected_images: list[str] = []

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        if argv[1:3] == ["image", "inspect"]:
            self.calls.append(argv)
            self.inspected_images.append(argv[-1])
            if self.daemon_down:
                return _cp(1, "", DAEMON_DOWN_STDERR)
            return _cp(1, "", no_such_image_stderr(argv[-1]))
        if self.daemon_down and argv[1:2] == ["version"]:
            self.calls.append(argv)
            return _cp(1, "", DAEMON_DOWN_STDERR)
        return super().__call__(argv, **_kw)


def image_token(argv: list[str]) -> str:
    """The image a create argv names: the token before `sleep infinity` on both builders."""
    assert argv[-2:] == ["sleep", "infinity"], argv[-3:]
    return argv[-3]


def inspected_image(calls: list[list[str]]) -> str | None:
    """The image the ONE preflight `docker image inspect` asked the daemon about, or None
    when no preflight ran; more than one is a failure."""
    asked = [c[-1] for c in calls if c[1:3] == ["image", "inspect"]]
    assert len(asked) <= 1, asked
    return asked[0] if asked else None


def subcommands(calls: list[list[str]]) -> list[str]:
    """`docker <sub>` for every recorded call, in order."""
    return [c[1] for c in calls if len(c) > 1]


def env_pairs(argv: list[str]) -> list[tuple[str, str]]:
    """Every `--env K=V` pair on a create argv, in argv order (duplicates kept — d48 asserts
    each key lands once)."""
    out: list[tuple[str, str]] = []
    for i, tok in enumerate(argv):
        if tok == "--env" and i + 1 < len(argv):
            k, _, v = argv[i + 1].partition("=")
            out.append((k, v))
    return out


def without_the_additions(argv: list[str]) -> list[str]:
    """The create argv minus JF5's `--pull=never` token and M6's `--env DEFENDER_BOX=1` pair
    — what must be byte-for-byte today's argv (d48)."""
    out: list[str] = []
    skip = False
    for i, tok in enumerate(argv):
        if skip:
            skip = False
            continue
        if tok == "--pull=never":
            continue
        if tok == "--env" and i + 1 < len(argv) and argv[i + 1] == "DEFENDER_BOX=1":
            skip = True
            continue
        out.append(tok)
    return out


# ---- the build remedy, as the operator would read it --------------------------------------------
def remedy_command(message: str) -> list[str] | None:
    """The `python3 <tree>/defender/scripts/box_image.py build` command a fault message names,
    split as a shell would (the tree path is `shlex.quote`d — M5-TEXT #42), or None when the
    message names no build command. House style may wrap a command in backticks and end the
    sentence with `.` or `)`; neither is part of what an operator pastes."""
    import shlex

    script = BUILD_COMMAND_TAIL.split(" ", 1)[0]
    for line in reversed(message.strip().splitlines()):
        if script not in line:
            continue
        try:
            words = shlex.split(line.replace("`", " "))
        except ValueError:
            continue
        words = [w.rstrip(".,;)") if w.rstrip(".,;)") in ("build", "python3") else w for w in words]
        for i, w in enumerate(words):
            if w == "python3" and i + 2 < len(words) and words[i + 1].endswith("/" + script):
                return words[i:i + 3]
    return None


# ---- a real box (the CI `test` job's lanes) ---------------------------------------------------
def box_run(box, command: str, *, cwd: Path) -> BoxResult:
    """The REAL entry point: `bash_exec.parse` → `run_parsed` (M8)."""
    return box.run_parsed(parse(command), command=command, cwd=cwd, timeout=EXEC_TIMEOUT)


def box_probe(box, run_dir: Path, name: str, source: str, *args: str) -> dict:
    """Run a Python probe INSIDE the box under the image's own `python3` (the box PATH puts
    `defender/bin` first and `/usr/local/bin` next — no venv on it) and decode its one JSON
    line. The script is written to the rw bind by the test, through the real filesystem."""
    script = run_dir / f"_probe1092_{name}.py"
    script.write_text(source, encoding="utf-8")
    res = box_run(box, " ".join([f"python3 {script}", *args]), cwd=run_dir)
    assert res.rc == 0, f"probe {name} did not complete: rc={res.rc} err={res.err!r}"
    return json.loads(res.out.decode("utf-8"))


@contextlib.contextmanager
def real_box(run_dir: Path):
    """A box over THIS checkout's defender dir through the real `start_box` — the resolver
    names `image_tag(DEFENDER)`, the daemon must hold it (O3: a missing image faults, never
    skips — #84)."""
    box = box_mod.start_box(run_dir, DEFENDER)
    try:
        yield box
    finally:
        box_mod.stop_box(box)


def image_shell(script: str) -> dict:
    """Run a Python script in the OWNED IMAGE with no mount (the `_spec771` runner's shape,
    reached through that runner so it takes the same resolver and the same `--pull=never`)."""
    from defender.tests.e2e._spec771 import run_probe_under_profile

    return run_probe_under_profile(script, None)


#: A JSON-printing walk of the image filesystem, skipping kernel and daemon mounts.
IMAGE_WALK_PROBE = r"""
import json, os
skip = {"/proc", "/sys", "/dev", "/tmp", "/run", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
names = set()
dirs = set()
for root, ds, fs in os.walk("/"):
    if root in skip or any(root.startswith(s + "/") for s in skip):
        ds[:] = []
        continue
    for d in ds:
        dirs.add(os.path.join(root, d))
    for f in fs:
        names.add(os.path.join(root, f))
print(json.dumps({"files": sorted(names), "dirs": sorted(dirs)}))
"""


# ---- the build script's docker, on PATH (d9) --------------------------------------------------
def fake_docker_on_path(tmp_path: Path, *, rc: int = 0) -> tuple[dict[str, str], Path]:
    """A real `docker` executable first on PATH that appends its argv (NUL-separated) to a log
    and exits `rc` — the seam a stdlib script that spawns `docker` has. Returns (env, log).
    The builder it was asked for is logged beside the argv (`builder_log(log)`): the value
    of `DOCKER_BUILDKIT` in the environment the script gave it."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "docker-argv.log"
    exe = bin_dir / "docker"
    exe.write_text(
        "#!/bin/sh\n"
        f"for a in \"$@\"; do printf '%s\\0' \"$a\" >> {log}; done\n"
        f"printf '\\1' >> {log}\n"
        f"printf '%s\\n' \"${{DOCKER_BUILDKIT-unset}}\" >> {log}.builder\n"
        f"exit {rc}\n",
        encoding="utf-8",
    )
    exe.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    return env, log


def builder_log(log: Path) -> list[str]:
    """`DOCKER_BUILDKIT` as each recorded `docker` invocation saw it (`unset` when absent)."""
    side = Path(f"{log}.builder")
    return side.read_text(encoding="utf-8").splitlines() if side.exists() else []


def recorded_docker_calls(log: Path) -> list[list[str]]:
    """Every `docker` invocation the fake recorded, as argv lists (without `docker` itself)."""
    if not log.exists():
        return []
    calls = []
    for chunk in log.read_bytes().split(b"\1"):
        if chunk:
            calls.append([a.decode("utf-8") for a in chunk.split(b"\0") if a != b""])
    return calls


# ---- stub interpreters for the shims (d33) -----------------------------------------------------
@dataclass(frozen=True)
class ShimWorld:
    defender_dir: Path
    venv_python: Path
    bare_python: Path
    env: dict[str, str]


def shim_world(tmp_path: Path) -> ShimWorld:
    """A fake `DEFENDER_DIR` holding an EXECUTABLE `.venv/bin/python3` stub, and a PATH whose
    bare `python3` is another stub. Each stub prints `STUB:<its own path>` and exits 0, so the
    shim's exec target is observable on stdout — the real shims print nothing about their
    interpreter (G8), so the stubs are the observer."""
    defender_dir = tmp_path / "fake-tree" / "defender"
    venv_bin = defender_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    bare_bin = tmp_path / "bare-bin"
    bare_bin.mkdir()
    stub = "#!/bin/sh\necho \"STUB:$0\"\n"
    venv_python = venv_bin / "python3"
    bare_python = bare_bin / "python3"
    for p in (venv_python, bare_python):
        p.write_text(stub, encoding="utf-8")
        p.chmod(0o755)
    env = {
        "PATH": f"{bare_bin}{os.pathsep}/usr/bin{os.pathsep}/bin",
        "DEFENDER_DIR": str(defender_dir),
        "DEFENDER_RUNS_BASE": str(tmp_path / "runs"),
        "HOME": str(tmp_path),
    }
    return ShimWorld(defender_dir, venv_python, bare_python, env)


def run_shim(shim: str, world: ShimWorld, *, marked: bool) -> str:
    """Exec the REAL `bin/<shim>` under `world`'s env (+ `DEFENDER_BOX=1` when marked) and
    return the stub interpreter's `STUB:<path>` line."""
    env = dict(world.env)
    if marked:
        env["DEFENDER_BOX"] = "1"
    proc = subprocess.run(
        [str(DEFENDER / "bin" / shim)], env=env, capture_output=True, text=True,
        encoding="utf-8", timeout=30, cwd=str(world.defender_dir),
    )
    assert proc.returncode == 0, (shim, proc.returncode, proc.stderr)
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("STUB:")]
    assert len(lines) == 1, (shim, proc.stdout, proc.stderr)
    return lines[0][len("STUB:"):]


# ---- the drain lane's worktree, as a real git checkout (MF2) -----------------------------------
class GitWorktreeBranch(RecordingBranch):
    """`RecordingBranch` whose `start_batch` mints a REAL git repo at the worktree path — one
    commit, holding the hash inputs under `<wt>/defender` — so `HEAD` there is the
    commit the drain's fault must name, whatever channel the implementation reads it through
    (the real `AuthorBranch` cuts the worktree from `origin/main`, so its HEAD is that commit).
    `cleanup` destroys the tree, as the real one does (drains.py:776-780)."""

    def __init__(self, worktree_base: Path, **kw):
        super().__init__(worktree_base, destroy_on_cleanup=True, **kw)
        self.cut_commit: str | None = None

    def start_batch(self, batch_id: str) -> Path:
        wt = super().start_batch(batch_id)
        plant_tree(wt, copy_code=False)
        seed_repo(wt)
        self.cut_commit = git_head_sha(wt)
        return wt


class FaultingStartBox:
    """An injectable `start_box=` for `_run_worktree_batch` that drives the REAL `start_box`
    over the drain's own request with a scripted daemon, so the fault the drain handles is the
    one production's remedy helper raises — never a hand-written BoxFault whose type or text
    the drain might key on."""

    def __init__(self, docker: RecordingDocker):
        self.docker = docker
        self.requests: list = []

    def __call__(self, request, *a, **kw):
        self.requests.append(request)
        return box_mod.start_box(request, docker=self.docker)


def raise_boxfault_message(fn, *args, **kwargs) -> str:
    with pytest.raises(BoxFault) as e:
        fn(*args, **kwargs)
    return str(e.value)
