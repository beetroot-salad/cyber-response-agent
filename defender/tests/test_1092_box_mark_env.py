"""#1092 — nothing in a box reaches the mounted venv (M6, O5, JF3): the in-box mark
`DEFENDER_BOX=1` on both `docker run` builders, stripped by both host lanes, honoured by the
three granted shims and by `reexec_into_venv`; the O7 argv census (JF5); and M7's port of
`BoxSpec` to `@model` with the stdlib-only rule's text retired.

Tier 1 throughout: the real `bin/defender-*` scripts are exec'd by the real shell over stub
interpreters that print which one ran (no shim prints its interpreter — G8), `reexec_into_venv`
really `os.execv`s into a stub, `sql.py` really fails its `import duckdb` against a shadowing
module first on `PYTHONPATH`, and the argv builders are the real ones over planted trees.
"""
from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
import typing
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic.dataclasses import is_pydantic_dataclass

from defender.run_common import run_env
from defender.runtime import box as box_mod
from defender.runtime.box import BOX_ENV_ALLOWLIST, BoxRequest, BoxSpec, Mount
from defender.tests._defender_sql import EXIT_NO_RUNTIME, SQL_PY
from defender.tests._spec1092 import (
    DEFENDER,
    REPO_ROOT,
    STOCK_ROOTFS,
    env_pairs,
    image_tag,
    image_token,
    make_run_dir,
    plant_tree,
    run_shim,
    shim_world,
    without_the_additions,
)

SHIMS = ("defender-sql", "defender-invlang", "defender-lessons")
VENV_LINE = "uv pip install --python .venv/bin/python"


def _request(root: Path, run_dir: Path, env: dict[str, str] | None = None) -> BoxRequest:
    return BoxRequest(
        name="defender-drain-1092", workdir=root, env=dict(env or {}),
        mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
        spec=BoxSpec(rootfs=STOCK_ROOTFS),
    )


# ---- d29 -------------------------------------------------------------------------------------
def test_the_run_dir_lane_argv_carries_env_defender_box_1(tmp_path):
    """The run-dir lane's `docker run` argv carries `--env DEFENDER_BOX=1` beside the existing
    allowlisted keys — exactly one such pair, spread from `_BOX_MARK_ENV = {"DEFENDER_BOX":
    "1"}` into `env_pairs` so the allowlist loop finds it (C17) — and `DEFENDER_BOX` is a
    member of `BOX_ENV_ALLOWLIST`."""
    assert box_mod._BOX_MARK_ENV == {"DEFENDER_BOX": "1"}  # type: ignore[attr-defined]
    assert "DEFENDER_BOX" in BOX_ENV_ALLOWLIST
    run_dir = make_run_dir(tmp_path)
    argv = box_mod._create_argv(
        "defender-run-1092", run_dir, tmp_path / "srv" / "defender", BoxSpec(rootfs=STOCK_ROOTFS), (),
    ).argv
    pairs = env_pairs(argv)
    assert pairs.count(("DEFENDER_BOX", "1")) == 1, pairs
    assert {k for k, _ in pairs} == set(BOX_ENV_ALLOWLIST), pairs


# ---- d30 -------------------------------------------------------------------------------------
@pytest.mark.parametrize("request_env", [
    {},
    {"DEFENDER_BOX": ""},
    {"DEFENDER_BOX": "0"},
    {"defender_box": "1", " DEFENDER_BOX": "1", "DEFENDER_BOX ": "1"},
])
def test_the_request_lane_argv_carries_env_defender_box_1_whatever_the_request_env_says(tmp_path, request_env):
    """The request lane's `docker run` argv carries `--env DEFENDER_BOX=1` whether the request
    env omits the key, names it `""`, or names it with any other value — the mark is spread
    after the caller's keys in `_render_env`, so no request can switch venv-first back on
    inside a box; a padded or lower-cased spelling is not the allowlisted key and has no
    effect (#31: exact-key indexing).

    # rejected: a caller-overridable default (the value-blind rule for other allowlisted
    # keys): a request env carrying `DEFENDER_BOX=""` would silently restore the host-venv
    # path inside a box (JF3). An embedded NUL in a value raises `ValueError` before any
    # docker call and other bytes pass verbatim — pre-existing plumbing (ENV #32, PJ-r2-2)."""
    run_dir = make_run_dir(tmp_path)
    request = _request(tmp_path / "wt", run_dir, request_env)
    argv = box_mod._render_argv(request, ()).argv
    pairs = env_pairs(argv)
    assert pairs.count(("DEFENDER_BOX", "1")) == 1, pairs
    assert [k for k, _ in pairs if k.strip().upper() == "DEFENDER_BOX"] == ["DEFENDER_BOX"], pairs
    assert box_mod._render_env(request_env, Path(tmp_path / "wt"))["DEFENDER_BOX"] == "1"


# ---- d32 (negative; positive control: d30 — the same request env DOES carry the mark on the box lane) ----
def test_both_host_lanes_strip_defender_box_from_the_shell_and_request_env_and_the_locale_env_is_unchanged(tmp_path, monkeypatch):
    """With `DEFENDER_BOX=1` present in this process's environment and in `request.env`,
    neither `_host_fallback_env` nor `run_common.run_env` carries `DEFENDER_BOX` — both host
    lanes strip the key from what they copy, while another allowlisted request key (`TZ`) and
    an ordinary shell key still come through — and `_LOCALE_ENV` is still exactly `LANG` and
    `TZ`. Same request env through `_render_env`: the box lane carries the mark.

    # rejected: the marker rides in `_BOX_MARK_ENV`, NOT in `_LOCALE_ENV` (the encoding
    # contract). M6's "NOT via `request.env`, so `_host_fallback_env` never carries it" was
    # false as a mechanism (JF3): the host lanes now STRIP the key, which makes the sentence
    # true by construction. An operator's own shell carrying DEFENDER_BOX into a by-hand shim
    # is misuse outside every lane JF3 governs (silent #98); no sitecustomize exists (#58)."""
    monkeypatch.setenv("DEFENDER_BOX", "1")
    monkeypatch.setenv("SPEC1092_SHELL_KEY", "kept")
    request_env = {"DEFENDER_BOX": "1", "TZ": "Europe/Oslo"}
    run_dir = make_run_dir(tmp_path)
    request = _request(tmp_path / "wt", run_dir, request_env)

    host = box_mod._host_fallback_env(request)
    assert "DEFENDER_BOX" not in host, sorted(k for k in host if "BOX" in k)
    assert host["TZ"] == "Europe/Oslo"
    assert host["SPEC1092_SHELL_KEY"] == "kept"

    lane = run_env(tmp_path / "srv" / "defender", run_dir)
    assert "DEFENDER_BOX" not in lane, sorted(k for k in lane if "BOX" in k)
    assert lane["SPEC1092_SHELL_KEY"] == "kept"

    assert box_mod._LOCALE_ENV == {"LANG": "C.UTF-8", "TZ": "UTC"}
    assert box_mod._render_env(request_env, tmp_path / "wt")["DEFENDER_BOX"] == "1"


# ---- d33 -------------------------------------------------------------------------------------
@pytest.mark.parametrize("shim", SHIMS)
def test_each_granted_shim_execs_bare_python3_when_defender_box_is_set_and_the_venv_python_otherwise(tmp_path, shim):
    """Each of `bin/defender-sql`, `bin/defender-invlang`, `bin/defender-lessons`, run against
    a fake `DEFENDER_DIR` holding an executable `.venv/bin/python3` stub, execs bare
    `python3` (the one on PATH) when `DEFENDER_BOX` is set and the stub when it is unset.

    # rejected: `bin/defender-policy` (operator tool, ungranted, `OPERATOR_TOOLS`) keeps its
    # venv lookup and is deliberately outside this test."""
    world = shim_world(tmp_path)
    assert run_shim(shim, world, marked=False) == str(world.venv_python)
    assert run_shim(shim, world, marked=True) == str(world.bare_python)


# ---- d34 -------------------------------------------------------------------------------------
def test_reexec_into_venv_does_not_exec_when_defender_box_is_set_and_does_otherwise(tmp_path):
    """`reexec_into_venv`, with a venv interpreter present beside its own tree, does not exec
    when `DEFENDER_BOX` is set and does exec into it when the variable is unset."""
    tree = tmp_path / "defender"
    scripts = tree / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(DEFENDER / "scripts" / "_venv.py", scripts / "_venv.py")
    venv_bin = tree / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    stub = venv_bin / "python3"
    stub.write_text("#!/bin/sh\necho \"STUB-EXEC $*\"\n", encoding="utf-8")
    stub.chmod(0o755)
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(scripts)!r})\n"
        "import _venv\n"
        "_venv.reexec_into_venv('lessons_fm.py')\n"
        "print('NO-EXEC')\n"
    )

    def run(marked: bool) -> str:
        env = {"PATH": os.environ.get("PATH", "")}
        if marked:
            env["DEFENDER_BOX"] = "1"
        proc = subprocess.run(
            [sys.executable, "-c", code, "--tags"], env=env, capture_output=True, text=True,
            encoding="utf-8", timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout.strip()

    assert run(marked=False) == "STUB-EXEC lessons_fm.py --tags"
    assert run(marked=True) == "NO-EXEC"


# ---- d28 -------------------------------------------------------------------------------------
def test_defender_sqls_missing_duckdb_message_names_the_image_build_when_marked_and_the_venv_line_otherwise(tmp_path):
    """`defender-sql`'s missing-`duckdb` branch (`scripts/gather_tools/sql.py`) exits
    `EXIT_NO_RUNTIME` on both lanes; with `DEFENDER_BOX` set its message names the box image
    build (`box_image.py build`) and never `uv pip install --python .venv/bin/python` or the
    venv (the path O5 closes and a box cannot write), and with `DEFENDER_BOX` unset today's
    venv instruction stands.

    # rejected: the marked-lane wording is F-C (non-material); the unmarked lane keeps its
    # venv line because the host lane keeps venv-first (M6)."""
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "duckdb.py").write_text("raise ImportError('duckdb blocked by the spec')\n", encoding="utf-8")

    def run(marked: bool) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": f"{shadow}{os.pathsep}{REPO_ROOT}",
            "DEFENDER_DIR": str(DEFENDER),
        }
        if marked:
            env["DEFENDER_BOX"] = "1"
        return subprocess.run(
            [sys.executable, str(SQL_PY), "SELECT 1"], input="{}", env=env,
            capture_output=True, text=True, encoding="utf-8", timeout=120,
        )

    unmarked = run(marked=False)
    assert unmarked.returncode == EXIT_NO_RUNTIME, (unmarked.returncode, unmarked.stderr)
    assert VENV_LINE in unmarked.stderr, unmarked.stderr

    marked = run(marked=True)
    assert marked.returncode == EXIT_NO_RUNTIME, (marked.returncode, marked.stderr)
    assert VENV_LINE not in marked.stderr, marked.stderr
    assert ".venv" not in marked.stderr, marked.stderr
    assert "box_image.py build" in marked.stderr, marked.stderr
    assert "duckdb" in marked.stderr, marked.stderr


# ---- d48 (negative; positive controls: d29/d30/d44 — the three additions are present) ----------------
def test_both_docker_run_argv_builders_differ_from_today_only_by_the_marker_env_pull_never_and_the_image_token(tmp_path):
    """Both `docker run` argv builders produce today's argv plus exactly one
    `--env DEFENDER_BOX=1` pair, one `--pull=never` token, and the owned image token:
    `--network none`, `--read-only`, the seccomp profile, the mounts, the tmpfs, the workdir
    and every other `--env` pair are byte-for-byte unchanged and each env key lands once.

    # rejected: network for the box stays `none`; this issue changes what is installed in
    # the sandbox, not what it can reach."""
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    name, token, spec = "defender-run-1092", "tok1092", BoxSpec()
    head = [
        "docker", "run", "--detach", "--name", name,
        "--label", f"{box_mod.START_TOKEN_LABEL}={token}",
        "--runtime", spec.runtime, "--network", "none", "--read-only",
        "--security-opt", f"seccomp={box_mod.ALIAS_PROFILE_PATH}",
    ]
    infra = {**box_mod.infra_env(defender_dir, run_dir), **box_mod._LOCALE_ENV}
    today_run_dir = [
        *head,
        "--mount", f"type=bind,source={run_dir},target={run_dir}",
        "--mount", f"type=bind,source={defender_dir},target={defender_dir},readonly",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={spec.tmpfs_size}",
        "--workdir", str(run_dir),
    ]
    for key in ("DEFENDER_DIR", "DEFENDER_RUN_DIR", "DEFENDER_RUNS_BASE", "PATH", "PYTHONPATH", "LANG", "TZ"):
        today_run_dir += ["--env", f"{key}={infra[key]}"]
    today_run_dir += [image_tag(defender_dir), "sleep", "infinity"]

    argv = box_mod._create_argv(name, run_dir, defender_dir, spec, (), token).argv
    assert argv.count("--pull=never") == 1, argv
    assert "--pull" not in argv, argv
    assert env_pairs(argv).count(("DEFENDER_BOX", "1")) == 1, env_pairs(argv)
    assert len({k for k, _ in env_pairs(argv)}) == len(env_pairs(argv)), "a key landed twice"
    assert without_the_additions(argv) == today_run_dir

    request = BoxRequest(
        name="defender-drain-1092", workdir=root, env={"TZ": "Europe/Oslo"},
        mounts=(Mount(source=root, target=root), Mount(source=run_dir, target=run_dir, writable=True)),
        spec=spec,
    )
    today_request = [
        *head[:4], request.name, *head[5:],
        "--mount", f"type=bind,source={root},target={root},readonly",
        "--mount", f"type=bind,source={run_dir},target={run_dir}",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={spec.tmpfs_size}",
        "--workdir", str(root),
    ]
    derived = {**box_mod._LOCALE_ENV, "TZ": "Europe/Oslo", **box_mod._derived_infra_env(root)}
    for key in sorted(derived):
        today_request += ["--env", f"{key}={derived[key]}"]
    today_request += [image_tag(root / "defender"), "sleep", "infinity"]

    argv = box_mod._render_argv(request, (), token).argv
    assert argv.count("--pull=never") == 1, argv
    assert "--pull" not in argv, argv
    assert env_pairs(argv).count(("DEFENDER_BOX", "1")) == 1, env_pairs(argv)
    assert len({k for k, _ in env_pairs(argv)}) == len(env_pairs(argv)), "a key landed twice"
    assert without_the_additions(argv) == today_request
    assert image_token(argv) == image_tag(root / "defender")


# ---- d25 -------------------------------------------------------------------------------------
def test_boxspec_is_a_frozen_model_dataclass_with_an_optional_rootfs_that_still_serves_from_env_fields_and_equality():
    """`BoxSpec` is a frozen pydantic dataclass built with `defender._model.model` (strict —
    `runtime=123` is refused; `extra="forbid"` — an unknown keyword is refused, as stdlib
    `@dataclass` refuses it) whose `rootfs` is `str | None` defaulting to `None`, that still
    exposes `runtime`, `rootfs`, `lifecycle` through `dataclasses.fields`, still anchors its
    default in the class, still moves only `runtime` through `from_env`, still compares equal
    by value, and still takes `dataclasses.replace` (G12 corrected: test_540 replaces
    `tmpfs_size`).

    # rejected: `BoxExecutor`, `_DockerTransport`, `Mount`, `BoxRequest` need not be ported —
    # only what discharges O2 (the non-obligation list). The design comment's "`rootfs: str`
    # keeps its type" is superseded by the amendment's unset default. A dirty tree is JF6 plus
    # the provenance stamp's `dirty`/`dirty_paths`; the tag joins no stamp (#87)."""
    assert is_pydantic_dataclass(BoxSpec) is True, "BoxSpec is not a pydantic dataclass"
    names = [f.name for f in dataclasses.fields(BoxSpec)]
    assert {"runtime", "rootfs", "lifecycle"} <= set(names), names
    assert typing.get_type_hints(BoxSpec)["rootfs"] == (str | None)
    assert BoxSpec().rootfs is None
    assert BoxSpec.from_env({}) == BoxSpec()
    levered = BoxSpec.from_env({BoxSpec.ENV_VAR: "runc"})
    assert levered.runtime == "runc"
    assert levered.rootfs is None
    assert levered.lifecycle == BoxSpec().lifecycle
    assert levered.tmpfs_size == BoxSpec().tmpfs_size
    assert BoxSpec(rootfs="x") == BoxSpec(rootfs="x")
    assert BoxSpec(rootfs="x") != BoxSpec()
    assert dataclasses.replace(BoxSpec.from_env({}), tmpfs_size="4m").tmpfs_size == "4m"
    with pytest.raises(dataclasses.FrozenInstanceError):
        BoxSpec().runtime = "runc"
    with pytest.raises(ValidationError):
        BoxSpec(runtime=123)
    with pytest.raises(ValidationError):
        BoxSpec(bogus=1)


# ---- d26 -------------------------------------------------------------------------------------
def test_no_closure_module_points_at_the_stdlib_only_rule_and_the_closure_pin_is_gone():
    """The rule's TEXT is gone, not the symbol (`_run_box_entrypoint` stays — `bash_exec.py`
    defines and calls it): none of `box/_spec.py`, `box_codec.py`, `scrub.py`, `_io.py` carries
    the "see `bash_exec._run_box_entrypoint`" pointer comment, `_run_box_entrypoint`'s
    docstring no longer says the closure "stays on STDLIB `@dataclass`, never
    `defender._model.model`", and the static closure pin in `tests/test_1067_model_port.py`
    (the test that blocked pydantic via `sys.meta_path` and imported the box package) no
    longer exists.

    # rejected: #1077's ordering is reviewer discipline, not a mechanical guard (B2)."""
    from defender.runtime import bash_exec

    for rel in ("runtime/box/_spec.py", "runtime/box_codec.py", "runtime/scrub.py", "_io.py"):
        text = (DEFENDER / rel).read_text(encoding="utf-8")
        assert "_run_box_entrypoint" not in text, f"{rel} still points at the retired rule"
    doc = bash_exec._run_box_entrypoint.__doc__ or ""
    assert "STDLIB" not in doc, doc
    assert "never `defender._model.model`" not in doc, doc
    assert callable(bash_exec._run_box_entrypoint)
    pin = "test_box_entrypoint_closure_imports_without_pydantic"  # lint-stale-ref: ok — this test asserts the def is GONE; the name is the record of what was retired
    port_tests = (DEFENDER / "tests" / "test_1067_model_port.py").read_text(encoding="utf-8")
    assert f"def {pin}" not in port_tests, "the closure pin test still exists"
