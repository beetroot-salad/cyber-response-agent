"""#1092 — what the built image IS, observed from inside a box (O1, O2, O5, O7, O8).

Every test here drives a REAL daemon. The `test`-job lanes carry `@requires_real_box` (the
`_spec771` guard: a reachable daemon, bind sources that resolve, the levered runtime
registered) — never `pytest.mark.live`, which no CI job selects (771's correction). The three
image-content walks that need no mount run the owned image through `_spec771`'s rootfs runner
under `@requires_daemon`, so a developer box without runsc still catches a bad image early.
The one `live`-marked test is the live suite's own duckdb row, re-sited here so its demand's
pointer is scannable (`spec-graph binds` reads `defender/tests/` non-recursively).

O3 is what makes these honest: on a daemon that has not built this tree's image every box
start FAULTS (`No such image`), none skips — `_real_box_skip_reason` never inspects the image
(#84). Red until CI builds before it boxes (M4 amended).
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

from defender.runtime import box as box_mod
from defender.runtime.box import BOX_ENV_ALLOWLIST
from defender.tests._spec1092 import (
    DEFENDER,
    IMAGE_WALK_PROBE,
    box_probe,
    box_run,
    image_shell,
    make_run_dir,
    real_box,
    requires_daemon,
    requires_live_box,
    requires_real_box,
)

SITE = "/usr/local/lib/python3.11/site-packages"
SHIMS = ("defender-sql", "defender-invlang", "defender-lessons")

_IMPORT_MODEL = """
import json, pydantic
from defender._model import model
import defender.runtime.box as box
print(json.dumps({"pydantic": pydantic.__file__, "model": model.__module__, "box": box.__file__}))
"""

_IMPORTS = """
import importlib, json, sys
out = {}
for name in sys.argv[1:]:
    try:
        mod = importlib.import_module(name)
        out[name] = getattr(mod, "__file__", "") or ""
    except ModuleNotFoundError:
        out[name] = None
print(json.dumps(out))
"""

_ENV_DUMP = "import json, os; print(json.dumps(dict(os.environ)))"

_NO_INSTALLER = """
import importlib, json, os, shutil, subprocess, sys
out = {"uv_on_path": shutil.which("uv"), "bin_uv": os.path.exists("/bin/uv")}
for name in ("setuptools", "wheel", "pydantic"):
    try:
        importlib.import_module(name)
        out[name] = "imports"
    except ModuleNotFoundError:
        out[name] = None
out["pip_rc"] = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True).returncode
ep = subprocess.run([sys.executable, "-m", "ensurepip", "--root", "/tmp/spec1092-ensurepip"], capture_output=True)
out["ensurepip_rc"] = ep.returncode
out["ensurepip_pip"] = os.path.exists("/tmp/spec1092-ensurepip/usr/local/lib/python3.11/site-packages/pip")
print(json.dumps(out))
"""

_DISTRIBUTIONS = """
import importlib.metadata, json
from packaging.markers import default_environment
dists = {}
for d in importlib.metadata.distributions():
    dists[d.metadata["Name"]] = d.version
print(json.dumps({"dists": dists, "env": default_environment()}))
"""

_BYTECODE = """
import importlib.util, json, os
site = "/usr/local/lib/python3.11/site-packages"
missing, total = [], 0
for root, _dirs, files in os.walk(site):
    for f in files:
        if f.endswith(".py"):
            total += 1
            src = os.path.join(root, f)
            if not os.path.exists(importlib.util.cache_from_source(src)):
                missing.append(src)
print(json.dumps({"total": total, "missing": missing, "pydantic": os.path.isdir(os.path.join(site, "pydantic"))}))
"""

_WHICH = """
import json, shutil, sys
print(json.dumps({p: shutil.which(p) for p in sys.argv[1:]}))
"""

_WHERE = """
import json, duckdb, pydantic, sys
print(json.dumps({"pydantic": pydantic.__file__, "duckdb": duckdb.__file__, "prefix": sys.prefix}))
"""


def _locked_core_and_box(env: dict) -> dict[str, str]:
    """`uv.lock`'s resolution of the project's core dependencies plus the `box` extra, closed
    over the lock's own dependency graph with each edge's marker evaluated for `env` (the
    image's own `packaging.markers.default_environment()`) — canonical name → version."""
    from packaging.markers import Marker
    from packaging.utils import canonicalize_name

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    by_name = {canonicalize_name(p["name"]): p for p in lock["package"]}
    environment = {**env, "extra": ""}

    def wanted(dep: dict) -> bool:
        marker = dep.get("marker")
        return True if not marker else Marker(marker).evaluate(environment, context="lock_file")

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


# ---- d17 -------------------------------------------------------------------------------------
@requires_real_box
def test_defender_model_imports_inside_the_box_from_the_image_site_packages(tmp_path):
    """Inside a started box, through the mounted tree and the entrypoint, `from defender._model
    import model` succeeds (and with it `defender.runtime.box`, the closure the rule used to
    guard) and `pydantic.__file__` is under `/usr/local/lib/python3.11/site-packages`.

    # rejected: NOT through `_spec771`'s rootfs runner — it runs `docker run <rootfs> python3 -`
    # with no mount and no PYTHONPATH (C18), so it can prove `import pydantic` but never
    # `defender._model`. O6 (#1077's constants module may import `_model`) is discharged by
    # this same observer on any closure module; no #1077 code is touched here. The new closure
    # under runsc + the alias-deny profile is unexecuted until the first CI run (N12)."""
    run_dir = make_run_dir(tmp_path)
    with real_box(run_dir) as box:
        seen = box_probe(box, run_dir, "model", _IMPORT_MODEL)
    assert seen["pydantic"].startswith(SITE + "/"), seen
    assert seen["model"] == "defender._model", seen
    assert seen["box"].startswith(str(DEFENDER)), seen


# ---- d18 -------------------------------------------------------------------------------------
@requires_real_box
def test_duckdb_imports_inside_the_box(tmp_path):
    """Inside a started box, bare `python3 -c 'import duckdb'` succeeds, from the image's own
    site-packages.

    # rejected: duckdb's default spill target is the cwd-relative `.tmp`, so a spilling query
    # on the drain lane's read-only worktree cwd fails with EROFS — pre-existing (the host-venv
    # duckdb behaves the same), unchanged here, recorded as a follow-up, not mechanised (rg3).
    # Thread sizing under runsc is out of scope (#66); the wheel's cost is C15's (#10)."""
    run_dir = make_run_dir(tmp_path)
    with real_box(run_dir) as box:
        res = box_run(box, "python3 -c 'import duckdb'", cwd=run_dir)
        seen = box_probe(box, run_dir, "duckdb", _IMPORTS, "duckdb")
    assert res.rc == 0, res.err
    assert seen["duckdb"], seen
    assert seen["duckdb"].startswith(SITE + "/"), seen


# ---- d19 (negative; positive control: pydantic and duckdb DO import, d17/d18) --------------------
@requires_real_box
def test_the_runtime_extra_never_enters_the_box(tmp_path):
    """Inside a started box, `anthropic`, `pydantic_ai`, `openai` and `mcp` are not
    importable, while `pydantic` and `duckdb` are.

    # rejected: the latent exposure that `duckdb` becomes importable by a `python3` the gate
    # COULD grant (`permission/grant.py:71` registers it as an extractor; not in
    # `reader_grants` today) is recorded, not mechanised."""
    run_dir = make_run_dir(tmp_path)
    with real_box(run_dir) as box:
        seen = box_probe(box, run_dir, "llm", _IMPORTS, "anthropic", "pydantic_ai", "openai", "mcp",
                         "pydantic", "duckdb")
    assert {k: v for k, v in seen.items() if k in ("anthropic", "pydantic_ai", "openai", "mcp")} == {
        "anthropic": None, "pydantic_ai": None, "openai": None, "mcp": None,
    }, seen
    assert seen["pydantic"], seen
    assert seen["duckdb"], seen


# ---- d20 -------------------------------------------------------------------------------------
@requires_real_box
def test_the_base_images_own_packages_survive_the_inexact_sync(tmp_path):
    """Inside a started box, `import packaging` succeeds from the image's own site-packages —
    the `--inexact` sync did not prune the base image's own site-packages.

    # rejected: the base's known substitutions (mawk, dash, no `jq`/gawk — #540 M13) are NOT
    # corrected by this image."""
    run_dir = make_run_dir(tmp_path)
    with real_box(run_dir) as box:
        seen = box_probe(box, run_dir, "packaging", _IMPORTS, "packaging")
    assert seen["packaging"], seen
    assert seen["packaging"].startswith(SITE + "/"), seen


# ---- d21 -------------------------------------------------------------------------------------
@requires_daemon
def test_every_distribution_in_the_image_is_the_locked_version_or_a_kept_base_package():
    """Every distribution installed in the image is either a package the lock resolves for
    core + `box` at exactly the locked version or a base package the Dockerfile keeps
    (`packaging`), and every lock-resolved core + `box` package is present."""
    from packaging.utils import canonicalize_name

    seen = image_shell(_DISTRIBUTIONS)
    installed: dict[str, str] = {str(canonicalize_name(n)): v for n, v in seen["dists"].items()}
    locked = _locked_core_and_box(seen["env"])
    assert "duckdb" in locked, locked
    assert "pydantic" in locked, locked
    kept = {"packaging"}
    assert set(installed) - kept == set(locked), {
        "unexpected": sorted(set(installed) - kept - set(locked)),
        "missing": sorted(set(locked) - set(installed)),
    }
    assert {n: installed[n] for n in locked} == locked


# ---- d22 (negative; positive controls: python3 and pydantic work in the same probe) ------------------
@requires_real_box
def test_no_uv_binary_and_no_pip_installable_path_remains_in_the_image(tmp_path):
    """Inside a started box there is no `uv` on `PATH` and no `/bin/uv`, `python3 -m pip
    --version` exits non-zero, `setuptools` and `wheel` do not import, and `python3 -m
    ensurepip --root /tmp/x` FAILS and installs no `pip` into the tmpfs (MF4: the bundled
    wheels are gone too) — no `uv` and no pip-installable path — while `pydantic` imports.

    # rejected: O7 is NARROWED to "no `uv`, no pip-installable path"; `apt-get`/`dpkg` ship
    # in the base and stay — the literal "no package installer" cannot hold on any Debian base
    # (F1 settled)."""
    run_dir = make_run_dir(tmp_path)
    with real_box(run_dir) as box:
        seen = box_probe(box, run_dir, "installers", _NO_INSTALLER)
    assert seen["uv_on_path"] is None, seen
    assert seen["bin_uv"] is False, seen
    assert seen["pip_rc"] != 0, seen
    assert seen["setuptools"] is None, seen
    assert seen["wheel"] is None, seen
    assert seen["ensurepip_rc"] != 0, seen
    assert seen["ensurepip_pip"] is False, seen
    assert seen["pydantic"] == "imports", seen


# ---- d23 (negative; positive control: the two copied files ARE in the image) ----------------------
@requires_daemon
def test_the_image_holds_no_checkout_no_env_file_and_no_ssh_material():
    """The image filesystem holds no checkout, no `.env`, no `.ssh` material and no
    `defender/` code — only the two copied manifest files (`pyproject.toml` beside `uv.lock`,
    exactly one of each) beside the installed packages.

    # rejected: a nested secret-shaped file in the build context: O7's image guarantee is
    # the COPY list (two files); `.dockerignore` only bounds the transfer (PJ-r2-1 executed
    # the legacy builder: one added layer, the two files)."""
    seen = image_shell(IMAGE_WALK_PROBE)
    files, dirs = seen["files"], seen["dirs"]
    assert [f for f in files if f.endswith("/.env") or f.endswith(".env.bak")] == []
    assert [d for d in dirs if d.endswith("/.ssh")] == []
    assert [f for f in files if re.search(r"/id_(rsa|ed25519|ecdsa|dsa)$", f)] == []
    assert [f for f in files if f.endswith("/box.Dockerfile") or f.endswith("/defender/run.py")] == []
    assert [d for d in dirs if d.endswith("/defender/runtime")] == []
    locks = [f for f in files if f.endswith("/uv.lock")]
    assert len(locks) == 1, locks
    assert str(Path(locks[0]).with_name("pyproject.toml")) in files, locks


# ---- d24 -------------------------------------------------------------------------------------
@requires_daemon
def test_every_module_under_the_images_site_packages_has_compiled_bytecode():
    """Every `.py` under the image's `/usr/local` site-packages — pydantic's included — has a
    `__pycache__` `.pyc` beside it, so the read-only rootfs never re-parses `pydantic` on a
    `docker exec`.

    # rejected: the entrypoint's import cost inside the exec timeout is covered by `timeout=`
    # (P47) — an accepted cost; compile-at-build is the mitigation this pins (#100)."""
    seen = image_shell(_BYTECODE)
    assert seen["pydantic"] is True, "pydantic is not in the image's site-packages"
    assert seen["total"] > 0
    assert seen["missing"] == [], seen["missing"][:10]


# ---- d31 -------------------------------------------------------------------------------------
@requires_real_box
def test_a_command_inside_the_box_sees_defender_box_1_and_the_env_is_still_exactly_the_allowlist(tmp_path):
    """A command run inside the box sees `DEFENDER_BOX=1` in its environment (the entrypoint's
    re-filter passes the allowlisted key through to the command), and the box environment is
    still exactly `BOX_ENV_ALLOWLIST` plus what the container runtime injects; a second exec
    in the same box sees the same mark (#51/#52: the container env is fixed at `docker run`)."""
    daemon_injected = {"HOSTNAME", "HOME", "PWD", "SHLVL", "_", "OLDPWD", "TERM"}
    run_dir = make_run_dir(tmp_path)
    with real_box(run_dir) as box:
        first = box_probe(box, run_dir, "env1", _ENV_DUMP)
        second = box_probe(box, run_dir, "env2", _ENV_DUMP)
    assert first.get("DEFENDER_BOX") == "1", sorted(first)
    assert second.get("DEFENDER_BOX") == "1", sorted(second)
    assert "DEFENDER_BOX" in BOX_ENV_ALLOWLIST
    assert set(first) - daemon_injected == set(BOX_ENV_ALLOWLIST), sorted(first)


# ---- d35 (M6's observer, re-sited beside test_540's repertoire test) ---------------------------------
@requires_real_box
def test_each_granted_shim_run_inside_the_box_takes_an_interpreter_whose_packages_are_the_images(tmp_path):
    """Every program the real grant table lets an agent run is present in the box, and each
    granted shim, executed there, runs an interpreter whose `pydantic.__file__` and
    `duckdb.__file__` are under `/usr/local/lib/python3.11/site-packages` — never under
    `${DEFENDER_DIR}/.venv`, whose `include-system-site-packages=false` makes the two sets
    disjoint. Observed by running the real shim under `bash -x`: its traced `exec` names the
    interpreter it hands off to (bare `python3`, never the mounted venv's), and that
    interpreter is then asked where its packages come from."""
    pytest.importorskip("pydantic_ai")
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.driver import MAIN_DEF

    run_dir = make_run_dir(tmp_path)
    policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    programs = sorted({g.program for g in policy.bash_allow})
    assert set(SHIMS) <= set(programs), programs
    with real_box(run_dir) as box:
        which = box_probe(box, run_dir, "which", _WHICH, *programs)
        assert [p for p, path in which.items() if path is None] == [], which
        where = run_dir / "_probe1092_where.py"
        where.write_text(_WHERE, encoding="utf-8")
        for shim in SHIMS:
            res = box_run(box, f"bash -x {DEFENDER / 'bin' / shim} --help", cwd=run_dir)
            execs = [ln for ln in res.err.decode("utf-8", "replace").splitlines() if ln.startswith("+ exec ")]
            assert execs, (shim, res.err)
            interpreter = execs[-1].split()[2]
            assert ".venv" not in interpreter, (shim, execs[-1])
            asked = box_run(box, f"{interpreter} {where}", cwd=run_dir)
            assert asked.rc == 0, (shim, asked.err)
            seen = json.loads(asked.out.decode("utf-8"))
            assert seen["pydantic"].startswith(SITE + "/"), (shim, seen)
            assert seen["duckdb"].startswith(SITE + "/"), (shim, seen)
            assert "/.venv" not in seen["prefix"], (shim, seen)


# ---- phase F (91-blind #9): "a missing image faults, never skips" is the guard's contract --------------
def test_the_real_box_guard_skips_on_daemon_topology_and_runtime_only_and_never_on_the_image():
    """`_spec771._real_box_skip_reason` — the guard every real-box lane here runs under — decides
    to skip on exactly three predicates (no reachable daemon; DooD with no shared mount covering
    the repo tree; the levered runtime not registered) and never inspects the image: its source
    names no image, tag or rootfs, and the reason it computed on this host (if any) mentions
    none — so a daemon that has not built this tree's image FAULTS at `start_box` (d44) rather
    than skipping (#84, O3 'loudly')."""
    import inspect

    from defender.tests.e2e import _spec771

    source = inspect.getsource(_spec771._real_box_skip_reason)
    for word in ("image", "rootfs", "defender-box", "tag"):
        assert word not in source, (word, source)
    for predicate in ("daemon_reachable", "is_dood", "_covered", "_runtime_registered"):
        assert predicate in source, (predicate, source)
    reason = _spec771._real_box_skip_reason()
    assert reason is None or not any(w in reason.lower() for w in ("image", "rootfs")), reason


# ---- d49 (the live suite's own row, re-sited) --------------------------------------------------
@pytest.mark.live
@requires_live_box
def test_the_live_suites_duckdb_startup_probe_exits_zero_in_a_box_from_the_owned_image(tmp_path):
    """The live suite's startup probe `python3 -c 'import duckdb'`
    (`test_665_box_live.py::test_box_start_probes_the_granted_repertoire_by_running_it`, red on
    every daemon at base) exits 0 in a box started the live suite's way — `start_box(run_dir,
    DEFENDER, docker=box_mod._docker)`, no explicit rootfs — from the owned image; the live
    suite's two tmp-workdir requests pin `rootfs=image_tag(DEFENDER)` (N4).

    # rejected: a real-box test on a daemon without the image FAULTS, never skips (O3, #84);
    # every live row faults with the remedy before the first build (#79)."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = box_run(box, "python3 -c 'import duckdb'", cwd=DEFENDER.parent)
    finally:
        box_mod.stop_box(box)
    assert res.rc == 0, res.err
