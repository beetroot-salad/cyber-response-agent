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
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

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

#: The three files the image name is a function of, IN THE ORDER the resolver reads them —
#: the order decides which file a "cannot read" fault names first (MF1 part 1).
HASH_INPUTS: tuple[str, ...] = ("box.Dockerfile", "uv.lock", "pyproject.toml")

#: The two new code files and the Dockerfile, where the amendment sites them (N10, F26).
IMAGE_PY = DEFENDER / "runtime" / "box" / "_image.py"
BOX_IMAGE_PY = DEFENDER / "scripts" / "box_image.py"
DOCKERFILE = DEFENDER / "box.Dockerfile"
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

EXEC_TIMEOUT = 60.0

#: The planted project's lock — WELL-FORMED, uv-shaped TOML (#1097: the name is computed from
#: the lock's parsed core + `box` closure, so a planted tree must carry a lock the resolver can
#: walk). Its closure from the root `planted` is alpha, beta, eta, winonly, gamma, delta and
#: BOTH `split` entries; every shape the walk has to handle is in it once:
#:   - `split` is resolved to two versions, as uv writes a fork (claim a1): two same-named
#:     `[[package]]` entries with `resolution-markers`, root edges carrying `version`+`marker`;
#:   - `alpha -> winonly` carries a marker no Linux build satisfies (markers are ignored);
#:   - `alpha -> beta[speed]` and the root's `box -> gamma[fast]` are edges with `extra`, whose
#:     targets' `speed`/`fast` optional-dependencies are in the closure — and whose `docs`/`slow`
#:     ones (both -> epsilon) are not;
#:   - `eta -> alpha` closes a cycle;
#:   - devtool (+ devdep) and rtlib are the `dev` and `runtime` extras' — outside the closure.
PLANTED_LOCK = """\
version = 1
revision = 3
requires-python = ">=3.11"
resolution-markers = [
    "python_full_version >= '3.12'",
    "python_full_version < '3.12'",
]

[[package]]
name = "alpha"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "beta", extra = ["speed"] },
    { name = "winonly", marker = "sys_platform == 'win32'" },
]
sdist = { url = "https://files.example/alpha-1.0.0.tar.gz", hash = "sha256:3e0f6b95dcc985c9178e23d1abd337eb1b1ade27666a85669dc5e8dd4e17f714", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/alpha-1.0.0-py3-none-any.whl", hash = "sha256:b58ed7ac069404adcbc36415eac21b3701710044f9baf21ae950d335f0c0cdd0", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "beta"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/beta-2.0.0.tar.gz", hash = "sha256:e62105c24b79440afa2deb8a938892a237166f9147968a11a21500d7de9b4018", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/beta-2.0.0-py3-none-any.whl", hash = "sha256:63f3336284f5226cb525fba3055726c9e9c63fd4a5fba8a4b08b0fe884eef39b", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[package.optional-dependencies]
speed = [
    { name = "eta" },
]
docs = [
    { name = "epsilon" },
]

[[package]]
name = "delta"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/delta-4.0.0.tar.gz", hash = "sha256:9c9b03d0391b2f7eab3308aa96f88114670afe16acd848d6446fc7e74a87e192", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/delta-4.0.0-py3-none-any.whl", hash = "sha256:39ab2f1f5f431bdc56335772bad22489ca56fc1787ebe2f993f34ef8ae35c10d", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "devdep"
version = "0.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/devdep-0.1.0.tar.gz", hash = "sha256:06fa0af22431cf8cc8a5bccb05131a9ccc5670443b4bbbe6d96f3fac1ff6063a", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/devdep-0.1.0-py3-none-any.whl", hash = "sha256:60d191690d44b9d5b29d52bf71a9ca03f9ebbe95367de0dffbe6de64a0a1503a", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "devtool"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "devdep" },
]
sdist = { url = "https://files.example/devtool-7.0.0.tar.gz", hash = "sha256:baad88892bdaca265b3de612a47852c8c2cfc57fe1e214139a442d82369abd65", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/devtool-7.0.0-py3-none-any.whl", hash = "sha256:55ae0eaf2aae50cbe28d73930e7567ab24f6ff33fd0db7e0e37da07bdfeef2aa", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "epsilon"
version = "5.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/epsilon-5.0.0.tar.gz", hash = "sha256:87c5ff861c9f08d8cc824489056d7371cf648417ee956ada90d0b406a3db0bf3", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/epsilon-5.0.0-py3-none-any.whl", hash = "sha256:718b050d40e620adce081a0da779d4c148ca03005e249f49ef28dfc699210229", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "eta"
version = "6.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "alpha" },
]
sdist = { url = "https://files.example/eta-6.0.0.tar.gz", hash = "sha256:67699a935c2a83b28810a6d5670c1db590b673b552de97210230b0a2a259e9b2", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/eta-6.0.0-py3-none-any.whl", hash = "sha256:44a565a41029132120b8adb3344286e43b0ca9f94980d0cddb57e8064ee7b71f", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "gamma"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/gamma-3.0.0.tar.gz", hash = "sha256:5aaf849456bdaff8df781140fa3eb5913d6a099b77a40c62011f08b884db2577", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/gamma-3.0.0-py3-none-any.whl", hash = "sha256:9d5f9a39ddf237a07d3c8681ee8e3204bd549e0c56ca19f1f47eb3e4fcfc2eaa", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[package.optional-dependencies]
fast = [
    { name = "delta" },
]
slow = [
    { name = "epsilon" },
]

[[package]]
name = "planted"
version = "0.0.0"
source = { virtual = "." }
dependencies = [
    { name = "alpha" },
    { name = "split", version = "1.0.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version < '3.12'" },
    { name = "split", version = "2.0.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version >= '3.12'" },
]

[package.optional-dependencies]
box = [
    { name = "gamma", extra = ["fast"] },
]
dev = [
    { name = "devtool" },
]
runtime = [
    { name = "rtlib" },
]

[package.metadata]
requires-dist = [
    { name = "alpha", specifier = ">=1" },
    { name = "devtool", marker = "extra == 'dev'" },
    { name = "gamma", extras = ["fast"], marker = "extra == 'box'" },
    { name = "rtlib", marker = "extra == 'runtime'" },
    { name = "split" },
]
provides-extras = ["box", "dev", "runtime"]

[[package]]
name = "rtlib"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/rtlib-8.0.0.tar.gz", hash = "sha256:781489f3dfa32b2258c258f0087cd79a2ad3bf5d3aa0e9cf40e8d1380af414a3", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/rtlib-8.0.0-py3-none-any.whl", hash = "sha256:9a1cb8c5fff277e2c2b2aaeb5a60de8dec7b5d950672c8cc638b14ddc8b28ee7", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "split"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version < '3.12'",
]
sdist = { url = "https://files.example/split-1.0.0.tar.gz", hash = "sha256:b6f8b51240e744ff0bdd46f645bca882a57cedba2ff8bc5f2e9725b5253a9e5b", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/split-1.0.0-py3-none-any.whl", hash = "sha256:9832de94b05abeedd86a74cb157bf4583916168e40df9221216c200408007503", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "split"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version >= '3.12'",
]
sdist = { url = "https://files.example/split-2.0.0.tar.gz", hash = "sha256:9aaf029ed0363b4c9793d3e3e3d4937681fd7e7ce9ef4d5cdab3d15f4b83630d", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/split-2.0.0-py3-none-any.whl", hash = "sha256:10d462f19a190ece5327f5f9227887da422fef8bd669d12ad6996d0804938c1c", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]

[[package]]
name = "winonly"
version = "9.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/winonly-9.0.0.tar.gz", hash = "sha256:1666617b6f7c4d0ab439f63aba366153843b120f1ee9f8b8f38c3053cd82405f", size = 1000, upload-time = "2026-01-01T00:00:00Z" }
wheels = [
    { url = "https://files.example/winonly-9.0.0-py3-none-any.whl", hash = "sha256:61c011ee9e3e7d42b275a49d5acde2d20415561e0db870cdadab63f6469b8091", size = 900, upload-time = "2026-01-01T00:00:00Z" },
]
"""

#: The planted project's manifest: `[project].name` names the lock's root, the `box` extra is
#: `gamma[fast]`, `[tool.uv]` is present, and `[tool.ruff]`/`[tool.mypy]` sit beside it.
PLANTED_PYPROJECT = """\
[project]
name = "planted"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = [
    "alpha>=1",
    "split",
]

[project.optional-dependencies]
box = ["gamma[fast]"]
dev = ["devtool"]
runtime = ["rtlib"]

[tool.uv]
package = false

[tool.ruff]
line-length = 100

[tool.mypy]
strict = true
"""

#: Synthetic bytes for a planted tree's three inputs. Deterministic, so two plantings name
#: the same image (d4) and an edit to the recipe or the closure names another (d3).
PLANTED_INPUT_BYTES: dict[str, bytes] = {
    "box.Dockerfile": b"FROM python:3.11-slim@sha256:" + b"0" * 64 + b"\nRUN true\n",
    "uv.lock": PLANTED_LOCK.encode("utf-8"),
    "pyproject.toml": PLANTED_PYPROJECT.encode("utf-8"),
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


def image_module():
    """`runtime/box/_image.py` through the package door — for the constants (`HASH_INPUTS`,
    `RECIPE_VERSION`) and `ImageInputError` a test pins exactly."""
    from defender.runtime.box import _image  # type: ignore[attr-defined]

    return _image


def box_closure(lock: dict, root_name: str) -> list[dict]:
    """`_image.box_closure(lock, root_name)` (#1097 M1'): the lock entries reachable from the
    root's core + `box` edges. Reached lazily, so a module that names it still collects while
    the function does not exist and each test fails on the missing attribute."""
    return image_module().box_closure(lock, root_name)  # type: ignore[no-any-return]


# ---- trees ------------------------------------------------------------------------------------
def plant_tree(root: Path, *, missing: tuple[str, ...] = (), copy_code: bool = True) -> Path:
    """`root/defender` holding the three hash inputs (synthetic bytes) — the DEFENDER DIR a box
    would mount — minus `missing`. With `copy_code`, the real `_image.py` and `box_image.py`
    are copied in where they exist, so the build script can be run FROM the planted tree and
    hash the planted tree's own inputs (F-B). Returns the defender dir."""
    defender_dir = root / "defender"
    defender_dir.mkdir(parents=True, exist_ok=True)
    for name in HASH_INPUTS:
        if name in missing:
            continue
        (defender_dir / name).write_bytes(PLANTED_INPUT_BYTES[name])
    if copy_code:
        for src, rel in ((IMAGE_PY, Path("runtime") / "box"), (BOX_IMAGE_PY, Path("scripts"))):
            if src.is_file():
                dest = defender_dir / rel
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, dest / src.name)
    return defender_dir


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
    commit, holding the three hash inputs under `<wt>/defender` — so `HEAD` there is the
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
