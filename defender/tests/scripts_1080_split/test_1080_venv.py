"""#1080 group `lessons`, venv half: `reexec_into_venv` leaves `defender/scripts/_venv.py` for a
module in the flat tier (found by `S.moved` with the flat-tier home), and every program that
re-launches itself under `defender/.venv` reaches it there.

The hazard the move carries (K13): the helper anchors `defender/` on its own file's depth, so a
verbatim copy one level up resolves the REPOSITORY root, finds no `.venv/bin/python3` there and
silently skips the re-exec. Every behaviour below is therefore driven through a COPY of this
checkout's `defender/` code, where the venv interpreter is whatever the test plants: a recording
fake (a script that prints the argv it was exec'd with and exits — the observer, since the helper
prints nothing), a dangling link, a directory, a link to the venv running this suite (a linked
worktree's shape), or a real-directory venv. The exec is real: no attribute is patched.

"As today" expectations are `goldens/venv.json`, captured at the base 80888efb by
`<scratchpad>/lessons/capture_venv.py`, which imports THIS module and runs its `observe_*`
functions with `SPEC1080_AT_BASE` set to 1; `norm` is the one normaliser both sides use.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "venv"

_COPY_SKIP_TOP = frozenset({"tests", "evals", "docs", "fixtures-e2e", "lessons"})

#: The programs that call the helper (repo-relative). The lessons CLI is no longer one: since the
#: post-review change (human, 2026-10-04) `bin/defender-lessons` picks the interpreter itself and
#: runs the engine as a module, so it is observed through the shim (`LESSONS_SHIM`).
USERS_FIXED = {
    "api server": "defender/api/serve.py",
    "frontend build": "defender/learning/frontend/build.py",
    "frontend serializer": "defender/learning/frontend/serialize.py",
}

#: The `DEFENDER_BOX` spellings (s179). `None` is unset.
BOX_SPELLINGS: dict[str, str | None] = {
    "unset": None, "empty": "", "0": "0", "false": "false", "1": "1",
}

ONE_LESSON = (
    "---\nname: one\ndescription: one lesson\nsource_signature: [sig-one]\n"
    "telemetry_source: [sensor-one]\nattack_phase: [phase-one]\n---\n\nbody\n")


# ======================================================================================
# Trees, fakes, children
# ======================================================================================


def venv_home() -> Path:
    return Path(sys.executable).parents[1]


def base_interpreter() -> Path:
    """The interpreter behind this venv's `python` — what a real venv's `bin/python3` links to."""
    return Path(sys.executable).resolve()


def users() -> dict[str, str]:
    return dict(USERS_FIXED)


#: The lessons CLI's launcher, repo-relative.
LESSONS_SHIM = "defender/bin/defender-lessons"


def helper_home() -> str:
    """The venv helper's flat-tier home (the one module defining `reexec_into_venv` there)."""
    return S.home_of("reexec_into_venv", home=S.FLAT_TIER)


def code_tree(root: Path) -> Path:
    """`root/defender`: a copy of this checkout's `defender/` code, no venv, no lesson corpus
    (`ONE_LESSON` planted). Returns the copy's checkout root."""
    src = S.DEFENDER.resolve()

    def _ignore(d: str, names: list[str]) -> set[str]:
        skip = {n for n in names if n in S.JUNK_DIRS}
        if Path(d).resolve() == src:
            skip |= {n for n in names if n in _COPY_SKIP_TOP}
        return skip

    shutil.copytree(src, root / "defender", ignore=_ignore, symlinks=True)
    corpus = root / "defender" / "lessons"
    corpus.mkdir()
    (corpus / "one.md").write_text(ONE_LESSON, encoding="utf-8")
    return root


def recorder(path: Path, label: str, *, mode: int = 0o755) -> Path:
    """A fake interpreter at `path`: prints `EXEC<TAB><label><TAB><argv0><TAB><args...>` and
    exits 0. It records what it was exec'd with; it decides nothing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#!/bin/sh\n"
        f"printf 'EXEC\\t%s' '{label}'\n"
        'for a in "$0" "$@"; do printf \'\\t%s\' "$a"; done\n'
        "printf '\\n'\n", encoding="utf-8")
    path.chmod(mode)
    return path


def link_venv(defender_dir: Path) -> Path:
    """`<defender>/.venv` as a link to the venv running this suite (a linked worktree)."""
    venv = defender_dir / ".venv"
    venv.symlink_to(venv_home(), target_is_directory=True)
    return venv / "bin" / "python3"


def real_dir_venv(defender_dir: Path) -> Path:
    """`<defender>/.venv` as a real directory laid out like `python -m venv` makes one: its own
    `pyvenv.cfg`, `bin/python3` linking the base interpreter, and the suite venv's packages."""
    venv = defender_dir / ".venv"
    (venv / "bin").mkdir(parents=True)
    cfg = venv_home() / "pyvenv.cfg"
    (venv / "pyvenv.cfg").write_text(
        cfg.read_text(encoding="utf-8") if cfg.is_file()
        else f"home = {base_interpreter().parent}\ninclude-system-site-packages = false\n",
        encoding="utf-8")
    (venv / "lib").symlink_to(venv_home() / "lib", target_is_directory=True)
    (venv / "bin" / "python3").symlink_to(base_interpreter())
    return venv / "bin" / "python3"


def norm(text: str, tmp: Path) -> str:
    """THE normaliser (capture and test): the tmp dir, this checkout, this interpreter and its
    base interpreter become `<TMP>`, `<REPO>`, `<PY>` and `<BASE-PY>`, longest spelling first."""
    subs = {str(tmp.resolve()): "<TMP>", str(tmp): "<TMP>", str(S.REPO_ROOT): "<REPO>",
            sys.executable: "<PY>", str(base_interpreter()): "<BASE-PY>"}
    for real, token in sorted(subs.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(real, token)
    return text


def outcome(proc: subprocess.CompletedProcess[bytes], tmp: Path) -> dict[str, Any]:
    err: Any = norm(proc.stderr.decode("utf-8", "replace"), tmp)
    if "Traceback (most recent call last):" in err:
        err = {"traceback_last": err.rstrip("\n").splitlines()[-1]}
    return {"rc": proc.returncode, "out": norm(proc.stdout.decode("utf-8", "replace"), tmp),
            "err": err}


def exec_lines(proc: subprocess.CompletedProcess[bytes], tmp: Path) -> list[str]:
    return [norm(ln, tmp) for ln in proc.stdout.decode("utf-8", "replace").splitlines()
            if ln.startswith("EXEC\t")]


def bare_env(**extra: str | None) -> dict[str, str]:
    """No PYTHONPATH, no tree variable — the operator shell's shape; `None` drops a key."""
    env = S.child_env(pythonpath=False, LANG="C.UTF-8", COLUMNS="80")
    for k, v in extra.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    return env


def run_all(jobs: Mapping[str, Callable[[], Any]]) -> dict[str, Any]:
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {k: pool.submit(fn) for k, fn in jobs.items()}
        return {k: f.result() for k, f in futures.items()}


def golden(name: str) -> Any:
    return S.golden(GOLDEN)[name]


#: A caller that imports the helper from a tree and calls it the way every user does, with the
#: script name and its own arguments passed through. Prints a marker when the helper returned.
_CALLER = (
    "import importlib, sys\n"
    "root, module = sys.argv[1], sys.argv[2]\n"
    "sys.path.insert(0, root)\n"
    "helper = importlib.import_module(module)\n"
    "sys.argv = [sys.argv[0], *sys.argv[3:]]\n"
    "helper.reexec_into_venv('the-script.py')\n"
    "print('NO-EXEC under', sys.executable)\n"
)
CALLER_ARGS = ("--tags", "two words")


def call_helper(root: Path, tmp: Path, **env: str | None) -> dict[str, Any]:
    """The helper, imported from the copy at `root`'s flat-tier home, called once."""
    proc = S.run([sys.executable, "-c", _CALLER, root, S.dotted(helper_home()), *CALLER_ARGS],
                 cwd=tmp, env=bare_env(**env), timeout=60)
    return outcome(proc, tmp)


def tree(tmp: Path, name: str) -> Path:
    return code_tree(tmp / name)


# ======================================================================================
# Observations
# ======================================================================================


def observe_targets(tmp: Path) -> dict[str, Any]:
    """A copy holding a recording interpreter at `defender/.venv`, at the repository root's
    `.venv` and at its parent's: which one the helper execs, and that the box mark stops it."""
    root = tree(tmp, "tree")
    recorder(root / "defender" / ".venv" / "bin" / "python3", "defender-venv")
    recorder(root / ".venv" / "bin" / "python3", "repo-venv")
    recorder(tmp / ".venv" / "bin" / "python3", "repo-parent-venv")
    return run_all({
        "unmarked": lambda: call_helper(root, tmp),
        "marked": lambda: call_helper(root, tmp, DEFENDER_BOX="1"),
    })


def observe_s054(tmp: Path) -> dict[str, Any]:
    absent = tree(tmp, "absent")
    present = tree(tmp, "present")
    recorder(present / "defender" / ".venv" / "bin" / "python3", "defender-venv")
    repo_only = tree(tmp, "repo-only")
    recorder(repo_only / ".venv" / "bin" / "python3", "repo-venv")
    return run_all({
        "venv folder absent": lambda: call_helper(absent, tmp),
        "venv present": lambda: call_helper(present, tmp),
        "only the repository root has a venv": lambda: call_helper(repo_only, tmp),
    })


def _plant_interpreter(root: Path, tmp: Path, shape: str) -> None:
    py = root / "defender" / ".venv" / "bin" / "python3"
    py.parent.mkdir(parents=True)
    target = tmp / f"target-{shape}"
    if shape == "dangling link":
        py.symlink_to(tmp / "no-such-interpreter")
    elif shape == "file without the execute bit":
        recorder(py, "not-executable", mode=0o644)
    elif shape == "directory":
        py.mkdir()
    elif shape == "link to a file without the execute bit":
        py.symlink_to(recorder(target / "python3", "not-executable", mode=0o644))
    elif shape == "link to a directory":
        (target / "dir").mkdir(parents=True)
        py.symlink_to(target / "dir", target_is_directory=True)
    else:  # the control: a link to a working interpreter
        py.symlink_to(recorder(target / "python3", "linked-executable"))


INTERPRETER_SHAPES = ("dangling link", "file without the execute bit", "directory",
                      "link to a file without the execute bit", "link to a directory",
                      "link to an executable")


def observe_s055(tmp: Path) -> dict[str, Any]:
    roots = {}
    for i, shape in enumerate(INTERPRETER_SHAPES):
        roots[shape] = tree(tmp, f"tree-{i}")
        _plant_interpreter(roots[shape], tmp, shape)
    return run_all({shape: (lambda r=r: call_helper(r, tmp)) for shape, r in roots.items()})


USER_ARGS = ("--alpha", "two words")


def observe_s056(tmp: Path) -> dict[str, Any]:
    """Each user started by path, from an unrelated directory, under a bare interpreter (`-S`:
    no site-packages, so any third-party import before the re-exec fails) with a bare
    environment; the copy's `defender/.venv/bin/python3` is a recorder."""
    root = tree(tmp, "tree")
    recorder(root / "defender" / ".venv" / "bin" / "python3", "defender-venv")
    away = tmp / "elsewhere"
    away.mkdir()
    return run_all({
        name: (lambda rel=rel: outcome(S.run([sys.executable, "-S", root / rel, *USER_ARGS],
                                             cwd=away, env=bare_env(), timeout=60), tmp))
        for name, rel in users().items()})


def observe_s058(tmp: Path) -> dict[str, Any]:
    """A working interpreter at `defender/.venv` with the box mark set: the helper, and the
    lessons shim on the box lane, against the same tree unmarked."""
    from defender.runtime import box as box_mod

    root = tree(tmp, "tree")
    recorder(root / "defender" / ".venv" / "bin" / "python3", "mounted-venv")
    image_bin = tmp / "image-bin"
    image_bin.mkdir()
    (image_bin / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n',
                                       encoding="utf-8")
    (image_bin / "python3").chmod(0o755)
    box_env = dict(box_mod._render_env({}, root))
    head, _, tail = box_env["PATH"].partition(os.pathsep)
    box_env["PATH"] = os.pathsep.join((head, str(image_bin), tail))
    host_env = {k: v for k, v in box_env.items() if k != "DEFENDER_BOX"}
    run_dir = tmp / "runs" / "r1"
    run_dir.mkdir(parents=True)

    def shim(env: Mapping[str, str]) -> dict[str, Any]:
        return outcome(S.run(["defender-lessons", "--tags"], cwd=run_dir, env=env), tmp)

    return run_all({
        "helper, marked": lambda: call_helper(root, tmp, DEFENDER_BOX="1"),
        "helper, unmarked": lambda: call_helper(root, tmp),
        "shim on the box lane, marked": lambda: shim(box_env),
        "shim, the same tree unmarked": lambda: shim(host_env),
    })


_SITECUSTOMIZE = (
    "import os, sys\n"
    "with open(os.environ['SPEC1080_START_LOG'], 'a', encoding='utf-8') as f:\n"
    "    f.write(sys.executable + '\\n')\n"
)

#: What each user is started with once it settles: something short and side-effect free where
#: the program offers it (the frontend build takes no arguments and writes its pages into the copy).
SETTLE_ARGS = {"api server": ("--help",), "frontend build": (),
               "frontend serializer": ("--stdout",), "lessons shim": ("--tags",)}


def make_start_hook(tmp: Path) -> None:
    """A `sitecustomize` that appends each starting interpreter's `sys.executable` to a log —
    one line per process start, so a re-exec is one more line and a loop a runaway list. Written
    once, before any child starts."""
    hook = tmp / "start-hook"
    hook.mkdir(exist_ok=True)
    (hook / "sitecustomize.py").write_text(_SITECUSTOMIZE, encoding="utf-8")


def start_log(tmp: Path, name: str) -> tuple[Path, dict[str, str]]:
    hook = tmp / "start-hook"
    assert (hook / "sitecustomize.py").is_file(), "make_start_hook first"
    log = tmp / f"starts-{name}.txt"
    return log, bare_env(PYTHONPATH=str(hook), SPEC1080_START_LOG=str(log))


def started(interp: Path | str | None, script: Path, args: Sequence[str], tmp: Path, name: str,
            ) -> dict[str, Any]:
    """`script` started by `interp` (`None`: run directly, as a shim is) with the start hook."""
    log, env = start_log(tmp, name)
    proc = S.run([*([interp] if interp is not None else []), script, *args], cwd=tmp, env=env,
                 timeout=90)
    starts = log.read_text(encoding="utf-8").splitlines() if log.is_file() else []
    # What a settled program then does depends on the host's packages (the API server needs the
    # `api` extra), so only the lessons shim's answer is part of the record.
    mine = name.startswith("lessons shim")
    return {"starts": [norm(s, tmp) for s in starts], "exec lines": exec_lines(proc, tmp),
            "rc": proc.returncode if mine else None,
            "out": norm(proc.stdout.decode(), tmp) if mine else None}


def observe_s124(tmp: Path) -> dict[str, Any]:
    """Every user under each venv shape, started by the base interpreter, and the lessons shim
    under each shape; then the frontend serializer started under other spellings of an
    interpreter."""
    make_start_hook(tmp)
    shapes = {"linked venv": link_venv, "real-directory venv": real_dir_venv}
    jobs: dict[str, Callable[[], Any]] = {}
    for s, (shape, make) in enumerate(shapes.items()):
        for u, (name, rel) in enumerate(users().items()):
            root = tree(tmp, f"tree-{s}-{u}")
            make(root / "defender")
            jobs[f"{name}, {shape}, base interpreter"] = (
                lambda root=root, rel=rel, name=name, label=f"{name} {s}": started(
                    base_interpreter(), root / rel, SETTLE_ARGS[name], tmp, label))
        root = tree(tmp, f"tree-{s}-shim")
        make(root / "defender")
        jobs[f"lessons shim, {shape}"] = (
            lambda root=root, label=f"lessons shim {s}": started(
                None, root / LESSONS_SHIM, SETTLE_ARGS["lessons shim"], tmp, label))
    root = tree(tmp, "tree-spellings")
    venv_py = link_venv(root / "defender")
    (tmp / "tree-spellings-link").symlink_to(root, target_is_directory=True)
    program = root / users()["frontend serializer"]
    spellings = {
        "this suite's venv interpreter": Path(sys.executable),
        "the copy's venv interpreter": venv_py,
        "the copy's venv interpreter, dot-dot spelled": venv_py.parent / ".." / "bin" / "python3",
        "the copy's venv interpreter, through a linked checkout path":
            tmp / "tree-spellings-link" / "defender" / ".venv" / "bin" / "python3",
    }
    for label, interp in spellings.items():
        jobs[f"frontend serializer, linked venv, {label}"] = (
            lambda interp=interp, label=label: started(
                interp, program, SETTLE_ARGS["frontend serializer"], tmp,
                f"frontend serializer {label}"))
    return run_all(jobs)


def observe_s179(tmp: Path) -> dict[str, Any]:
    """Every `DEFENDER_BOX` spelling: the helper, each user started by path (only whether and
    how it re-exec'd — what an unmarked program then does depends on the host's packages), and
    the two shims' interpreter choice."""
    out: dict[str, Any] = {}
    jobs: dict[str, Callable[[], Any]] = {}
    bare = recorder(tmp / "bare-bin" / "python3", "bare-python3")
    for i, (spelling, value) in enumerate(BOX_SPELLINGS.items()):
        root = tree(tmp, f"tree-{i}")
        recorder(root / "defender" / ".venv" / "bin" / "python3", "defender-venv")
        jobs[f"helper, {spelling}"] = lambda root=root, value=value: call_helper(
            root, tmp, DEFENDER_BOX=value)
        for name, rel in users().items():
            jobs[f"{name}, {spelling}"] = lambda root=root, rel=rel, value=value: exec_lines(
                S.run([sys.executable, root / rel, *USER_ARGS], cwd=tmp,
                      env=bare_env(DEFENDER_BOX=value), timeout=90), tmp)
        for shim in ("defender-lessons", "defender-sql"):
            jobs[f"bin/{shim}, {spelling}"] = lambda root=root, shim=shim, value=value: (
                exec_lines(shim_with_stubs(root, tmp, bare, shim, value), tmp))
    out.update(run_all(jobs))
    out.update(sql_no_runtime(tmp))
    return out


def shim_with_stubs(root: Path, tmp: Path, bare: Path, shim: str, box: str | None,
                    ) -> subprocess.CompletedProcess[bytes]:
    """A shim run with its tree variable naming the copy, the copy's venv interpreter a recorder
    and the PATH's bare `python3` (`bare`) another (test_1092's shim world)."""
    env = bare_env(DEFENDER_DIR=str(root / "defender"), DEFENDER_BOX=box,
                   DEFENDER_RUNS_BASE=str(tmp / "runs"))
    env["PATH"] = f"{bare.parent}{os.pathsep}/usr/bin{os.pathsep}/bin"
    return S.run([root / "defender" / "bin" / shim, "SELECT 1"], cwd=tmp, env=env, timeout=60)


def sql_no_runtime(tmp: Path) -> dict[str, Any]:
    """The sql engine's own read of the mark: its missing-`duckdb` message under each spelling
    (a shadow `duckdb` that fails to import, as test_1092's d28 plants it)."""
    shadow = tmp / "shadow"
    shadow.mkdir()
    (shadow / "duckdb.py").write_text("raise ImportError('duckdb blocked by the spec')\n",
                                      encoding="utf-8")
    wrapper = S.shim_exec_target("defender-sql")
    jobs = {}
    for spelling, value in BOX_SPELLINGS.items():
        env = bare_env(DEFENDER_BOX=value, DEFENDER_DIR=str(S.DEFENDER),
                       PYTHONPATH=f"{shadow}{os.pathsep}{S.REPO_ROOT}")
        jobs[f"sql engine without duckdb, {spelling}"] = lambda env=env: outcome(
            S.run([sys.executable, wrapper, "SELECT 1"], cwd=tmp, env=env, stdin=b"{}"), tmp)
    return run_all(jobs)


def observe_s206(tmp: Path) -> dict[str, Any]:
    """A working product venv at `defender/.venv` (linked), and recording venvs one level up (the
    repository root) and two (its parent): the lessons shim, run directly, and the frontend
    serializer, started by the base interpreter."""
    make_start_hook(tmp)
    root = tree(tmp, "tree")
    link_venv(root / "defender")
    recorder(root / ".venv" / "bin" / "python3", "repo-venv")
    recorder(tmp / ".venv" / "bin" / "python3", "repo-parent-venv")
    u = users()
    return run_all({
        "lessons shim": lambda: started(None, root / LESSONS_SHIM, ("--tags",), tmp,
                                        "lessons shim"),
        "frontend serializer": lambda: started(base_interpreter(),
                                               root / u["frontend serializer"], ("--stdout",),
                                               tmp, "frontend serializer"),
    })


# ======================================================================================
# Static readers
# ======================================================================================


def _calls_reexec(stmt: ast.stmt) -> bool:
    return any(isinstance(n, ast.Call)
               and getattr(n.func, "id", getattr(n.func, "attr", None)) == "reexec_into_venv"  # lint-ast-resolve: ok — the importer census matches the helper's own name across the tree, statically
               for n in ast.walk(stmt))


def guarded_programs() -> list[str]:
    """Every non-test module under `defender/` that calls `reexec_into_venv` at module scope."""
    out = []
    for rel in S.py_files():
        src = (S.REPO_ROOT / rel).read_text(encoding="utf-8")
        if "reexec_into_venv" in src and any(_calls_reexec(s) for s in ast.parse(src).body):
            out.append(rel)
    return out


def imports_before_guard(rel: str) -> list[str]:
    seen: list[str] = []
    for stmt in ast.parse((S.REPO_ROOT / rel).read_text(encoding="utf-8")).body:
        if _calls_reexec(stmt):
            break
        seen += [i.module for i in S.import_statements(rel, ast.unparse(stmt))]
    return seen


def helper_importers(home: str) -> dict[str, set[str]]:
    """{module that uses the helper: where it imports it from} — `from M import
    reexec_into_venv` names M; importing the home module itself (`import M`, `from P import
    leaf`) names the home."""
    target = S.dotted(home)
    out: dict[str, set[str]] = {}
    for rel in S.py_files():
        src = (S.REPO_ROOT / rel).read_text(encoding="utf-8")
        if "reexec_into_venv" not in src or rel == home:
            continue
        for imp in S.import_statements(rel, src):
            if "reexec_into_venv" in imp.names:
                out.setdefault(rel, set()).add(imp.module)
            elif imp.module == target or f"{imp.module}.{'.'.join(imp.names)}" == target:
                out.setdefault(rel, set()).add(target)
    return out


# ======================================================================================
# Tests
# ======================================================================================


def test_1080_reexec_into_venv_from_the_flat_tier_still_targets_defenders_own_venv(tmp_path):
    """`reexec_into_venv`, imported from its flat-tier home, re-execs into
    `<defender>/.venv/bin/python3`, never `<repo>/.venv`. A verbatim depth-anchored copy at
    `defender/_venv.py` silently skips the re-exec (K13). Its `_DEFENDER_DIR` equals the tree's
    `defender/` directory. Under `DEFENDER_BOX` it still skips. `api/serve.py`,
    `learning/frontend/build.py`, `serialize.py` and the lessons engines import it from there.

    Observed in a copy holding a recording interpreter at `defender/.venv`, at the repository
    root and at its parent: the helper execs the first with the script and arguments passed
    through, and with the box mark set execs nothing. Every module that imports the helper names
    its flat-tier home, and the four programs are among them."""
    home = helper_home()
    mod = S.moved_module("reexec_into_venv", home=S.FLAT_TIER)
    assert Path(mod._DEFENDER_DIR).resolve() == S.DEFENDER.resolve(), (
        f"{home} anchors defender/ at {mod._DEFENDER_DIR} — the K13 depth slip")
    assert observe_targets(tmp_path) == golden("targets")

    importers = helper_importers(home)
    assert set(users().values()) <= set(importers), sorted(importers)
    stray = {r: m for r, m in importers.items() if m != {S.dotted(home)}}
    assert not stray, f"modules importing the helper from somewhere else: {stray}"


def test_venv_helper_runs_from_the_flat_tier_when_the_venv_folder_is_absent(tmp_path):
    """With the venv folder absent the helper returns without re-exec and the script runs under
    the current interpreter, as today. With it present, the re-exec happens: the helper anchored
    at the flat tier resolves the project's own defender/.venv (not the repo root), so
    `venv_py.is_file()` is true and the re-exec is not silently skipped. (M2 names `_venv.py:9`.)

    Three copies: no venv (the caller carries on under this interpreter), a recording venv at
    `defender/.venv` (it is exec'd), and one only at the repository root (it is not)."""
    helper_home()
    assert observe_s054(tmp_path) == golden("s054")


def test_venv_interpreter_is_a_dangling_link_or_not_executable(tmp_path):
    """A venv interpreter that is a dangling link, a file without the execute bit or a directory
    is handled exactly as today (the helper does not re-exec into something it cannot run, and
    the failure mode matches the pre-move behavior; probe PO10 pins the baseline). The move
    changes the anchor, not the checks.

    Each shape planted at the copy's `defender/.venv/bin/python3` (plus links to a non-executable
    file and to a directory, and the control: a link to a working interpreter, which is exec'd);
    the caller's exit status, output and last error line are the base's."""
    helper_home()
    assert observe_s055(tmp_path) == golden("s055")


def test_entry_script_is_started_by_path_from_an_unrelated_directory_before_the_package_is_importable(
        tmp_path):
    """Each of the API server, the frontend build and serializer and the lessons engine, started by
    path from an unrelated directory with no environment variable and a bare interpreter, reaches
    the venv helper at its new flat-tier home and re-execs before any third-party import, ending
    under the project interpreter as today; none fails with an ImportError at the helper import.
    Arguments are passed through unchanged.

    The bare interpreter is this one with site-packages off, so a third-party import before the
    re-exec fails; the project interpreter is a recorder, so the re-exec is its line. Then the
    same start with the flat-tier helper module removed from the copy fails: the programs reach
    it there and nowhere else."""
    home = helper_home()
    seen = observe_s056(tmp_path)
    assert seen == golden("s056")
    assert all(v["err"] == "" for v in seen.values()), seen

    root = tree(tmp_path, "no-helper")
    recorder(root / "defender" / ".venv" / "bin" / "python3", "defender-venv")
    (root / home).unlink()
    for name, rel in users().items():
        proc = S.run([sys.executable, "-S", root / rel], cwd=tmp_path, env=bare_env())
        assert b"EXEC\t" not in proc.stdout, (
            f"{name} still re-execs with {home} gone — it reaches the helper elsewhere")
        assert proc.returncode != 0, name


def test_venv_helper_is_imported_through_a_package_that_pulls_in_third_party_code(tmp_path):
    """The venv helper is importable with only the standard library: every package initialiser on
    the way to it (defender/ has none; the flat tier) imports no third-party package, so the
    re-launch decision precedes the entry script's first third-party import. test_c2c's ordering
    contract keeps holding. (Box closure rule's spirit; F11.)

    A child with site-packages off and every import outside the standard library and this tree
    refused imports the helper's module and lists what it loaded. Then the ordering contract over
    the real tree: the helper module imports only the standard library, and every program that
    calls the helper at module scope imports nothing from `defender.*` before that call but the
    helper's module."""
    from defender.tests._import_blocker import run_blocked

    home = helper_home()
    module = S.dotted(home)
    done = run_blocked(
        "import importlib, json, sys\n"
        f"importlib.import_module({module!r})\n"
        "print(json.dumps(sorted(m for m in sys.modules "
        "if m != '__main__' and m.split('.')[0] not in sys.stdlib_module_names)))\n",
        allow_only=("defender", "__main__"), no_site=True, cwd=tmp_path,
        env={"PYTHONPATH": str(S.REPO_ROOT), "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr.decode()
    loaded = json.loads(done.stdout)
    assert module in loaded, loaded
    assert all(m == "defender" or m.startswith("defender.") for m in loaded), loaded

    src = (S.REPO_ROOT / home).read_text(encoding="utf-8")
    third = [i.module for i in S.import_statements(home, src)
             if i.module.split(".")[0] not in sys.stdlib_module_names
             and i.module != "__future__"]
    assert not third, f"{home} imports outside the standard library: {third}"
    programs = guarded_programs()
    assert set(users().values()) <= set(programs), programs
    early = {p: [m for m in imports_before_guard(p) if m.startswith("defender") and m != module]
             for p in programs}
    assert not any(early.values()), {p: m for p, m in early.items() if m}


def test_box_variable_is_set_while_a_project_environment_is_present_on_the_mount(tmp_path):
    """With the box marker set, the helper does not re-exec into a mounted project venv even if
    one exists with a working interpreter; the engine runs under the box image's interpreter. The
    marker is a presence flag read by the helper and the sql engine, as today.

    A copy whose `defender/.venv/bin/python3` is a working recorder: with the mark set the helper
    returns and `defender-lessons` on the box lane answers from the image's interpreter (no
    recorder line); the same tree unmarked execs the recorder (the control)."""
    helper_home()
    assert observe_s058(tmp_path) == golden("s058")


def test_reexec_into_the_venv_when_the_venv_is_a_link_to_another_checkouts_venv(tmp_path):
    """Every user of the venv helper (API server, frontend build and serialize; the lessons
    CLI through its shim) re-execs exactly once into the venv interpreter and settles, both from a checkout
    with a real venv and from a linked worktree whose .venv is a link to the main checkout's venv,
    whatever spelling sys.executable has. No loop and no second exec. Preserved behavior.

    Each process start is logged by a `sitecustomize` on PYTHONPATH. Every user, under a linked
    venv and a real-directory venv, started by the base interpreter: two starts, the second the
    copy's venv interpreter. The lessons shim under each shape: it picks the copy's venv
    interpreter itself, so it starts once. The frontend serializer under other spellings of an
    interpreter: any spelling of the copy's venv (`python`, `..`, a linked checkout path, or the
    suite's venv the copy's links to) is the same environment and settles at once; only a
    different environment re-execs, once. (Post-review change, human: the helper compares
    environments, `sys.prefix`, not path spellings; at the base a respelled path re-exec'd once
    more.)"""
    helper_home()
    seen = observe_s124(tmp_path)
    assert seen == golden("s124")
    for label, v in seen.items():
        assert 1 <= len(v["starts"]) <= 2, (label, v["starts"])
        # `<PY>` is this suite's venv, which the linked copy's `.venv` points at: the same
        # environment, so it settles there.
        assert v["starts"][-1].endswith("/defender/.venv/bin/python3") \
            or v["starts"] == ["<PY>"] and "linked venv" in label, (label, v["starts"])


def test_box_marker_spelled_as_empty_zero_or_false(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster and
    rename; O5 where it applies). DEFENDER_BOX empty, `0`, `false`, `1` or unset is read as a
    presence flag exactly as today by the venv helper and the engines; the API server, the
    frontend builder and the lessons engine each behave as before under every spelling.

    Under each spelling: the helper's choice, each program's re-exec (a recording venv), the
    lessons and sql shims' interpreter choice (recorders for both interpreters), and the sql
    engine's missing-runtime message."""
    helper_home()
    assert observe_s179(tmp_path) == golden("s179")


def test_venv_bootstrap_with_a_second_environment_beside_the_product_one(tmp_path):
    """With a second virtualenv one directory level above the product's own, the bootstrap helper
    re- launches into the product's defender/.venv (the re-anchored root resolves the project, not
    the repo's parent), once, and the process settles without re-launching again.

    The product venv is linked; the one at the repository root and the one above it are
    recorders, which never print."""
    helper_home()
    seen = observe_s206(tmp_path)
    assert seen == golden("s206")
    assert all(v["exec lines"] == [] for v in seen.values()), seen


#: The LLM stack the providers package may not load at module scope.
LLM_STACK = ("pydantic_ai", "anthropic", "openai", "mcp", "fastmcp", "logfire")


def _child_modules(tmp: Path, body: str) -> dict[str, Any]:
    probe = (body + "import json, sys\n"
             "print(json.dumps(sorted(m for m in sys.modules if m.startswith('defender') "
             f"or m.split('.')[0] in {S.BOX_BLOCKED + LLM_STACK!r})))\n")
    done = S.python("-c", probe, cwd=tmp)
    assert done.returncode == 0, done.stderr.decode()
    return {"modules": json.loads(done.stdout)}


def _allowed_1096() -> tuple[str, ...]:
    path = S.DEFENDER / "tests" / "test_1096_entrypoint_closure.py"
    for n in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "_ALLOWED" for t in n.targets):
            return tuple(ast.literal_eval(n.value))
    raise AssertionError("test_1096 defines no _ALLOWED")


def test_guard_keyed_on_a_module_name_prefix_meets_code_whose_prefix_changed(tmp_path):
    """Each module-name-prefix guard keeps its protective meaning after code changes prefix: the API
    still loads neither the runtime nor the learning loop (its import of the venv helper from the
    flat tier loads neither), the providers package still has no LLM stack at module scope, and
    the box entrypoint closure's allowed set names the engines' new locations. No guard passes
    because the code it should police now sits under a prefix the guard does not look at. (O5
    lists the box entrypoint closure test.)

    Children list what they loaded: the helper's module alone loads nothing under
    `defender.runtime` or `defender.learning`; the providers package and the moved pricing module
    load none of the LLM stack (the listing sees them, the positive control); the moved lessons
    and sql engines sit under a top-level name test_1096's allowed set and the box closure admit.
    Last, the API server module itself, loaded as a module (it needs the `api` extra)."""
    helper = S.dotted(helper_home())
    seen = _child_modules(tmp_path, f"import {helper}\n")["modules"]
    assert helper in seen
    assert [m for m in seen if m.startswith(("defender.runtime", "defender.learning"))] == []

    pricing = S.dotted(S.home_of("usage_cost", home=S.PRICING))
    seen = _child_modules(tmp_path, f"import defender.runtime.providers\nimport {pricing}\n")
    assert {"defender.runtime.providers", pricing} <= set(seen["modules"]), seen
    assert [m for m in seen["modules"] if m.split(".")[0] in LLM_STACK] == [], seen

    allowed = _allowed_1096()
    for symbol in ("cmd_show", "_no_runtime"):
        top = S.dotted(S.home_of(symbol)).split(".")[0]
        assert top in allowed, (symbol, top, allowed)
        assert top in S.box_import_allowlist(), (symbol, top)

    pytest.importorskip("fastapi")
    serve = S.DEFENDER / "api" / "serve.py"
    seen = _child_modules(tmp_path, (
        "import runpy, sys\n"
        f"sys.argv = [{str(serve)!r}, '--help']\n"
        f"runpy.run_path({str(serve)!r}, run_name='spec1080')\n"))["modules"]
    assert {"defender.api.app", helper} <= set(seen), seen
    assert [m for m in seen if m.startswith(("defender.runtime", "defender.learning"))] == [], seen
