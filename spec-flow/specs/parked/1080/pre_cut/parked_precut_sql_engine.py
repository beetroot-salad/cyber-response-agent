# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT collected.
# This is defender/tests/scripts_1080_split/test_1080_sql_engine.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. It keeps
# the cells the cut removed from KEPT tests: the OUT halves of narrowed tests, and the tables and
# helpers the cut narrowed or deleted. Each such node carries a `# PRE-CUT …` marker naming the
# issue(s) that own its cut cells; an owner adopts those cells when its module moves. Nodes without
# a marker are unchanged in the live suite (no test of this file was parked whole). The file name does not match test_*.py, so pytest never
# collects it. It imports the LIVE helper modules; their pre-cut versions are
# parked_precut__spec1080.py and parked_precut__census1080.py beside this file (_pointers1080.py did
# not change). The goldens it reads are split between the suite's goldens/ and ../goldens/. Each
# narrowed kept demand's `parked_cells` block in spec-flow/specs/spec_graph_1080-scripts-split.yaml
# points at its pre-cut function here.
"""#1080, group `sql`: the engine behind `defender-sql` leaves `defender/scripts/gather_tools/sql.py`
for a dedicated subpackage under `defender/runtime/`, and the file the unchanged shim execs becomes
a thin wrapper carrying one import-root bootstrap (M-H (a)). One test per demand.

REACHING THE CODE. The moved sql engine is found by symbol (dF0): `_sql_engine()` is the one module
under `defender/runtime/` that defines `EXIT_NO_RUNTIME`, so every test here is red until the move
and names the missing home. The lessons engine (s014's bad regex, s061, s070, s071, s114-s118) is
the one module defining `cmd_tags`, outside `defender/lessons/`. The wrappers are what the shims
exec, read off the shims themselves (`S.shim_exec_target`).

WHICH ENGINE ANSWERED. A shim needs a `python3` on its PATH; inside a box that is the image's
interpreter (core plus the `box` extra). Here it is a two-line stub running THIS interpreter
through `_TRACER`, which starts the target file exactly as `python3 <file>` does (the same argv,
the file's folder first on `sys.path`, `__main__`) and records, through the `exec` audit event,
every code file the process executed. After the move the wrapper must have executed the moved
engine (`_assert_answered_by`); a wrapper still holding the engine's code fails that. A host lane
whose tree has a `defender/.venv` runs it, as the shim does, and leaves no record.

GOLDENS (`goldens/sql.json`). Every "as today" value is what the BASE (80888efb) printed and
returned for the fixed inputs below, captured by running the base shims, wrappers and engines
through THESE producers (`PRODUCERS`; the capture script imports this module) and normalised by
`_norm` alone: the checkout root, tree copies and tmp folders become tokens, duckdb's scratch
folder becomes `<SCRATCH>`, and a traceback collapses to its last line (its frames name the file
and line the move changes).

TREE COPIES. A test that plants a fault, or needs a fixed lesson corpus, runs a copy of
`defender/` (`_copy_tree`: everything but tests and caches, `lessons/` replaced by `_CORPUS`),
never the real tree. Every child runs with its working directory and import path pinned (s127).
"""
from __future__ import annotations

import ast
import contextlib
import functools
import importlib
import importlib.metadata
import itertools
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tomllib
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.tests._import_blocker import run_blocked
from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "sql"
SQL = "defender-sql"
LESSONS = "defender-lessons"

# ======================================================================================
# Locating the engines (dF0: by symbol; red until the move)
# ======================================================================================


def _sql_engine() -> str:
    """The moved sql engine, repo-relative: the one module under `defender/runtime/` defining the
    engine's exit-code vocabulary."""
    return S.home_of("EXIT_NO_RUNTIME", home=S.RUNTIME)


def _lessons_engine() -> str:
    """The moved lessons engine, repo-relative: the one module defining `cmd_tags`, which must not
    sit in the lesson content folder."""
    home = S.home_of("cmd_tags")
    assert not S.under(home, S.rel(S.LESSONS_CONTENT)), (
        f"the lessons engine {home} sits in the lesson content folder")
    return home


def _engine(shim: str) -> str:
    return _sql_engine() if shim == SQL else _lessons_engine()


def _wrapper_rel(shim: str) -> str:
    """The file the (unchanged) shim execs, repo-relative."""
    return S.rel(S.shim_exec_target(shim))


def _packages(relpath: str) -> list[str]:
    """Every package directory on a module's dotted path, outermost first:
    `defender/runtime/x/y.py` gives `defender`, `defender/runtime`, `defender/runtime/x`."""
    parts = relpath.split("/")[:-1]
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


# ======================================================================================
# Fixed inputs
# ======================================================================================

_PAYLOAD = (b'[{"user": "alice", "n": 3, "host": {"name": "h1"}}, '
            b'{"user": "bob", "n": 5, "host": {"name": "h2"}}, '
            b'{"user": "alice", "n": 1, "host": {"name": "h1"}}]\n')
_QUERY = 'SELECT "user", sum(n) AS total, count(*) AS c FROM data GROUP BY 1 ORDER BY 1'
_POSITIONAL = (b'{"columns": ["host.name", "count"], "values": [["a", 1], ["b", 2]], '
               b'"truncated": true}\n')
_DECLARED = ("--rows", "values", "--names", "columns",
             'SELECT "host.name", "count" FROM data ORDER BY 1')

#: The fixed lesson corpus every tree copy carries in place of the real one, so a lessons
#: engine's answer is the same on every machine and at every later commit.
_CORPUS = {
    "spec1080-alpha.md": (
        "---\nname: spec1080-alpha\ndescription: alpha lesson of the 1080 sql group\n"
        "source_signature: [rule-alpha]\ntelemetry_source: [auditd]\n"
        "attack_phase: [persistence]\n---\n\nalpha body\n"),
    "spec1080-beta.md": (
        "---\nname: spec1080-beta\ndescription: beta lesson of the 1080 sql group\n"
        "source_signature: [rule-beta]\ntelemetry_source: [auditd, falco]\n"
        "attack_phase: [execution]\n---\n\nbeta body\n"),
}
_ALPHA_REL = "defender/lessons/spec1080-alpha.md"
#: The lessons engine's real invocations ([72]: a pattern query, `--tags`, `--show`).
_LESSON_RUNS = {
    "grep": ("source_signature:.*rule-alpha",),
    "tags": ("--tags",),
    "show": ("--show", _ALPHA_REL),
}
#: Each engine's one real invocation for the closure and tree-derivation runs.
_REAL_RUN = {SQL: ((_QUERY,), _PAYLOAD), LESSONS: (("--tags",), b"")}

# ======================================================================================
# The one normaliser (capture and test both go through it)
# ======================================================================================

_SCRATCH = re.compile(r"[^\s\"']*defender-sql-[A-Za-z0-9_]{8}")
_TRACEBACK = "Traceback (most recent call last):"


def _norm(text: str, subs: Sequence[tuple[Path | str, str]] = ()) -> str:
    """Tokens for every machine- or run-specific spelling: each `(path, token)` in `subs` (both
    the spelling given and its resolved form) and the checkout root (`<ROOT>`), longest first;
    duckdb's scratch folder (`<SCRATCH>`); a traceback reduced to its final `Type: message`
    line, since its frames name the file and line that the move changes."""
    pairs: dict[str, str] = {str(S.REPO_ROOT): "<ROOT>"}
    for path, token in subs:
        pairs[str(path)] = token
    for path, token in subs:  # a resolved form never overrides a spelling named explicitly
        pairs.setdefault(str(Path(path).resolve()), token)
    for real in sorted(pairs, key=len, reverse=True):
        text = text.replace(real, pairs[real])
    text = _SCRATCH.sub("<SCRATCH>", text)
    if _TRACEBACK in text:
        head, _, tail = text.partition(_TRACEBACK)
        last = [ln for ln in tail.splitlines() if ln.strip()][-1]
        text = f"{head}{_TRACEBACK} <frames elided>\n{last}\n"
    return text


def _txt(data: bytes | None) -> str:
    return (data or b"").decode("utf-8", "backslashreplace")


def _rec(proc: subprocess.CompletedProcess[bytes],
         subs: Sequence[tuple[Path | str, str]] = ()) -> dict[str, Any]:
    """What a run did, as a golden record."""
    return {"rc": proc.returncode, "stdout": _norm(_txt(proc.stdout), subs),
            "stderr": _norm(_txt(proc.stderr), subs)}


def _check(key: str, actual: Any) -> None:
    golden = S.golden(GOLDEN)
    assert key in golden, f"goldens/sql.json carries no `{key}`: re-run the base capture"
    assert S.canon(actual) == golden[key], (
        f"`{key}` differs from the base\n  base: {golden[key]!r}\n  now:  {S.canon(actual)!r}")


def _check_all(records: dict[str, Any]) -> None:
    for key, value in records.items():
        _check(key, value)


# ======================================================================================
# Trees: copies, foreign checkouts
# ======================================================================================

_SKIP = S.JUNK_DIRS | {"tests"}


def _copy_tree(root: Path) -> Path:
    """`defender/` copied to `<root>/defender` (tests and caches left out, no `.venv`), its
    lesson corpus replaced by `_CORPUS`. Returns `root`, the copy's checkout root."""
    root.mkdir(parents=True, exist_ok=True)
    dst = root / "defender"
    shutil.copytree(S.DEFENDER, dst, symlinks=True,
                    ignore=lambda _d, names: [n for n in names if n in _SKIP])
    shutil.rmtree(dst / "lessons")
    (dst / "lessons").mkdir()
    for name, text in _CORPUS.items():
        (dst / "lessons" / name).write_text(text, encoding="utf-8")
    return root


def _foreign_tree(root: Path, marker: Path) -> Path:
    """Another checkout of defender, shaped like this one (a module at every path this tree has
    one, no `defender/__init__.py`), each of whose modules records its own name in `marker` and
    exits 97 when imported. Returns `root`."""
    src = ("import sys\n"
           f"with open({str(marker)!r}, 'a', encoding='utf-8') as _fh:\n"
           "    _fh.write(__name__ + '\\n')\n"
           "sys.stderr.write('a FOREIGN checkout answered: ' + __name__ + '\\n')\n"
           "raise SystemExit(97)\n")
    for relpath in S.py_files():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")
    return root


def _foreign_loaded(marker: Path) -> list[str]:
    return marker.read_text(encoding="utf-8").split() if marker.exists() else []


@contextlib.contextmanager
def _planted(path: Path, edit: Callable[[Path], None]) -> Iterator[None]:
    """`edit` applied to `path` (created if absent) for the body of the block, then undone."""
    before = path.read_bytes() if path.exists() else None
    try:
        edit(path)
        yield
    finally:
        if before is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(before)


def _at_module_scope(line: str) -> Callable[[Path], None]:
    """An edit inserting `line` at module scope, after the module's imports and bootstrap and
    before its first `def` or `class`."""
    def edit(path: Path) -> None:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        first = next((n for n in tree.body if isinstance(
            n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))), None)
        lines = src.splitlines(keepends=True)
        at = len(lines) if first is None else min(
            [first.lineno, *(d.lineno for d in first.decorator_list)]) - 1
        lines.insert(at, line + "\n")
        path.write_text("".join(lines), encoding="utf-8")
    return edit


def _appending(line: str) -> Callable[[Path], None]:
    def edit(path: Path) -> None:
        before = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(before + line + "\n", encoding="utf-8")
    return edit


def _writing(text: str) -> Callable[[Path], None]:
    def edit(path: Path) -> None:
        path.write_text(text, encoding="utf-8")
    return edit


# ======================================================================================
# Children: the shim's interpreter, environments, runners
# ======================================================================================

#: `python3 <file> <args>` as a shim runs it, recording every code file executed.
_TRACER = '''\
import atexit, json, os, runpy, sys
_record = os.environ.get("SPEC1080_TRACE")
_ran = set()
def _audit(event, args):
    name = getattr(args[0], "co_filename", "<>") if event == "exec" and args else "<>"
    if not name.startswith("<"):
        _ran.add(os.path.abspath(name))
def _dump():
    if _record:
        with open(_record, "w", encoding="utf-8") as fh:
            json.dump(sorted(_ran), fh)
sys.addaudithook(_audit)
atexit.register(_dump)
_target = sys.argv[1]
if not os.path.isfile(_target):
    # Not a runnable file: hand the argv to the interpreter itself, so its own refusal speaks.
    os.execv(sys.executable, ["python3", *sys.argv[1:]])
del sys.argv[0]
_real = _target
while os.path.islink(_real):
    _real = os.path.join(os.path.dirname(_real), os.readlink(_real))
sys.path[0] = os.path.dirname(os.path.abspath(_real))
runpy.run_path(_target, run_name="__main__")
'''

_RUNS = itertools.count()


def _interp(tmp: Path) -> Path:
    """A folder whose `python3` is this interpreter run through `_TRACER`: the box image's
    `python3` (core plus the `box` extra) for every shim run here."""
    folder = tmp / "interp"
    if not (folder / "python3").exists():
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "tracer.py").write_text(_TRACER, encoding="utf-8")
        stub = folder / "python3"
        stub.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{folder / "tracer.py"}" "$@"\n',
                        encoding="utf-8")
        stub.chmod(0o755)
    return folder


def _trace_file(tmp: Path) -> Path:
    return tmp / f"trace-{next(_RUNS)}.json"


def _read_trace(path: Path) -> list[str] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _env(tmp: Path, *, box: bool, defender_dir: Path | str | None, pythonpath: str | None,
         trace: Path | None = None, **extra: str) -> dict[str, str]:
    """A shim's or wrapper's environment: the minimal inherited keys, the C.UTF-8 locale and UTC
    (as a box has them), `_interp` first on PATH, the tree variable, the box mark when `box`, and
    the import path when given (the box and host lanes give the checkout root; the operator shell
    gives none)."""
    env = S.child_env(pythonpath=False)
    env.pop("LC_ALL", None)
    env.update(LANG="C.UTF-8", TZ="UTC", COLUMNS="80")  # COLUMNS: argparse wraps --help to it
    env["PATH"] = f"{_interp(tmp)}{os.pathsep}{env['PATH']}"
    if defender_dir is not None:
        env["DEFENDER_DIR"] = str(defender_dir)
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    if box:
        env["DEFENDER_BOX"] = "1"
    if trace is not None:
        env["SPEC1080_TRACE"] = str(trace)
    env.update(extra)
    return env


def _run_shim(tmp: Path, shim: str, args: Sequence[str], *, lane: str = "box",  # noqa: PLR0913
              tree: Path = S.REPO_ROOT, defender_dir: Path | str | None | bool = True,
              pythonpath: str | None | bool = True, stdin: bytes | None = b"",
              cwd: Path | str | None = None, closed_stdin: bool = False,
              subs: Sequence[tuple[Path | str, str]] = (), **extra: str,
              ) -> tuple[dict[str, Any], list[str] | None]:
    """`<tree>/defender/bin/<shim> <args>` on the box lane (the mark set) or the host lane (no
    mark), with `DEFENDER_DIR` naming the tree's `defender/` unless told otherwise and the
    checkout root on the import path unless told otherwise. Returns the golden record and the
    trace (None when the interpreter never started or was not the stub)."""
    trace = _trace_file(tmp)
    dfn = tree / "defender" if defender_dir is True else (defender_dir or None)
    path = str(tree) if pythonpath is True else (pythonpath or None)
    env = _env(tmp, box=lane == "box", defender_dir=dfn, pythonpath=path, trace=trace, **extra)
    argv = [str(tree / "defender" / "bin" / shim), *args]
    run_dir = Path(cwd) if cwd is not None else tmp / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    if closed_stdin:
        proc = subprocess.run(argv, cwd=run_dir, env=env, capture_output=True, check=False,  # noqa: S603
                              timeout=120, preexec_fn=lambda: os.close(0))
    else:
        proc = S.run(argv, cwd=run_dir, env=env, stdin=stdin)
    return _rec(proc, subs), _read_trace(trace)


def _run_wrapper(tmp: Path, shim: str, args: Sequence[str], *, tree: Path = S.REPO_ROOT,  # noqa: PLR0913
                 via: Path | None = None, box: bool = False, pythonpath: str | None = None,
                 stdin: bytes = b"", cwd: Path | str | None = None,
                 subs: Sequence[tuple[Path | str, str]] = (), **extra: str,
                 ) -> tuple[dict[str, Any], list[str] | None]:
    """The wrapper started by path (`python3 <tree>/<wrapper> <args>`, through `_TRACER`), from
    the operator shell's bare environment unless told otherwise. `via` spells the checkout root
    another way (a link to it)."""
    trace = _trace_file(tmp)
    env = _env(tmp, box=box, defender_dir=None, pythonpath=pythonpath, trace=trace, **extra)
    run_dir = Path(cwd) if cwd is not None else tmp / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    wrapper = (via or tree) / _wrapper_rel(shim)
    proc = S.run([sys.executable, _interp(tmp) / "tracer.py", wrapper, *args], cwd=run_dir,
                 env=env, stdin=stdin)
    return _rec(proc, subs), _read_trace(trace)


def _assert_answered_by(ran: list[str] | None, engine: Path, what: str) -> None:
    """The run executed the engine at `engine` (the file the locator found, in the tree run)."""
    assert ran is not None, f"{what}: the run left no record: its interpreter never started"
    seen = {os.path.realpath(f) for f in ran if f.startswith("/")}
    assert os.path.realpath(engine) in seen, (
        f"{what}: the engine at {engine} never ran; the files of that tree that did: "
        f"{sorted(f for f in seen if f.startswith(os.path.realpath(engine.parents[2])))}")


@functools.lru_cache(maxsize=1)
def _box_allowlist() -> tuple[str, ...]:
    """`S.box_import_allowlist()` plus the top-level EXTENSION modules of the same distributions,
    which `importlib.metadata.packages_distributions()` misnames (it strips only the last suffix
    of `_duckdb.cpython-311-x86_64-linux-gnu.so`), so the shared list lacks `_duckdb`, without
    which duckdb itself cannot be imported. Same walk: the lock's `box_closure` (core plus the
    `box` extra). Plus the interpreter's own sysconfig data module, which ships with the standard
    library (the image's Python has its own) but is missing from `sys.stdlib_module_names`."""
    from defender.runtime.box import _image

    lock = tomllib.loads((S.DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    dists = {_image.normalized_name(e["name"]) for e in _image.box_closure(lock, "defender")}
    extensions = set()
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        if not name or _image.normalized_name(name) not in dists:
            continue
        for f in dist.files or ():
            if len(f.parts) == 1 and f.name.endswith((".so", ".pyd")):
                top = f.name.split(".")[0]
                if top.isidentifier():
                    extensions.add(top)
    stdlib_data = {sysconfig._get_sysconfigdata_name()}  # noqa: SLF001 — the stdlib's own name for it
    return tuple(sorted(set(S.box_import_allowlist()) | extensions | stdlib_data))


# ======================================================================================
# The box closure check ([121]: the engine run as the shim runs it, by path, with the box mark,
# under the import blocker, a real query; [72]; s120: preloads evicted, never trusted). Its names
# avoid the blocker prelude's own (`_refused`, `_Blocker`), which share the `-c` namespace.
# ======================================================================================

_CLOSURE_BODY = '''
import importlib, importlib.machinery, json, os, runpy, sys, traceback
def _outside(name):
    top = name.split(".")[0]
    return top not in _ALLOWED and top not in sys.stdlib_module_names
_s_refused = []
class _SRecorder:
    # Records an import the blocker is about to refuse, when the package exists on this host
    # (a probe like `copy`'s `import org` for Jython finds nothing anywhere and is no finding).
    def find_spec(self, name, path=None, target=None):
        if _outside(name) and importlib.machinery.PathFinder.find_spec(name.split(".")[0]):
            _s_refused.append(name)
        return None
sys.meta_path.insert(0, _SRecorder())
_evicted = sorted(m for m in list(sys.modules) if _outside(m))
for _m in _evicted:
    del sys.modules[_m]
# A preloaded package may also have installed its own import machinery (pydantic_ai's stack adds
# a meta-path finder, and a path hook whose source loader is beartype's): each goes with the
# package, and so do the cached path finders.
def _s_hook_owners(hook):
    owners = {getattr(hook, "__module__", "") or ""}
    for cell in getattr(hook, "__closure__", None) or ():
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        for detail in value if isinstance(value, tuple) else (value,):
            for part in detail if isinstance(detail, tuple) else (detail,):
                owners.add(getattr(part, "__module__", "") or "")
    return {o for o in owners if o and _outside(o)}
_s_finders = sorted({type(f).__module__ for f in sys.meta_path if _outside(type(f).__module__)}
                    | {o for h in sys.path_hooks for o in _s_hook_owners(h)})
sys.meta_path[:] = [f for f in sys.meta_path if not _outside(type(f).__module__)]
sys.path_hooks[:] = [h for h in sys.path_hooks if not _s_hook_owners(h)]
sys.path_importer_cache.clear()
_ran = set()
def _audit(event, args):
    name = getattr(args[0], "co_filename", "<>") if event == "exec" and args else "<>"
    if not name.startswith("<"):
        _ran.add(os.path.abspath(name))
sys.addaudithook(_audit)
sys.argv = [_WRAPPER, *_ARGS]
sys.path[0] = os.path.dirname(_WRAPPER)
_status = 0
try:
    runpy.run_path(_WRAPPER, run_name="__main__")
except SystemExit as exc:
    _status = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
except BaseException:
    traceback.print_exc()
    _status = 1
sys.stdout.flush()
_host = None
try:
    importlib.import_module(_DOTTED)
except BaseException as exc:
    _host = type(exc).__name__ + ": " + str(exc)
with open(_REPORT, "w", encoding="utf-8") as fh:
    json.dump({"status": _status, "host_import": _host, "refused": sorted(set(_s_refused)),
               "blocked_loaded": sorted(m for m in sys.modules if m.split(".")[0] in _BLOCKED),
               "evicted": _evicted, "evicted_finders": _s_finders, "ran": sorted(_ran)}, fh)
sys.exit(_status)
'''


def _closure(tmp: Path, shim: str, *, root: Path = S.REPO_ROOT, args: Sequence[str] | None = None,
             stdin: bytes | None = None, hook: Path | None = None,
             subs: Sequence[tuple[Path | str, str]] = ()) -> dict[str, Any]:
    """Run `shim`'s wrapper in `root` as the box does, under an interpreter that refuses every
    import outside the standard library and the box image's packages
    (`_box_allowlist()`), then import the engine by its dotted name (the host's import,
    which executes every package initialiser down to it). Modules a start-up hook loaded before
    the blocker are evicted first (with any import finder they installed), so a later import of
    one is refused rather than served from the cache. Returns the report plus `run`, the golden
    record of the box run."""
    engine = _engine(shim)
    default_args, default_stdin = _REAL_RUN[shim]
    report = tmp / f"closure-{next(_RUNS)}.json"
    header = (f"_ALLOWED = frozenset({_box_allowlist()!r})\n"
              f"_BLOCKED = {S.BOX_BLOCKED!r}\n"
              f"_REPORT = {str(report)!r}\n"
              f"_DOTTED = {S.dotted(engine)!r}\n"
              f"_WRAPPER = {str(root / _wrapper_rel(shim))!r}\n"
              f"_ARGS = {list(default_args if args is None else args)!r}\n")
    pythonpath = os.pathsep.join(str(p) for p in (hook, root) if p is not None)
    env = _env(tmp, box=True, defender_dir=root / "defender", pythonpath=pythonpath,
               PYTHONDONTWRITEBYTECODE="1")
    run_dir = tmp / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    proc = run_blocked(header + _CLOSURE_BODY, allow_only=_box_allowlist(), cwd=run_dir,
                       env=env, stdin=default_stdin if stdin is None else stdin)
    assert report.exists(), (
        f"the closure child died before reporting (rc {proc.returncode}):\n{_txt(proc.stderr)}")
    rep: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    rep["run"] = _rec(proc, subs)
    return rep


def _findings(rep: dict[str, Any]) -> list[str]:
    """What the closure check reports: every import it refused (even one the engine caught),
    every agent-framework or provider module present after the run, a host import that failed."""
    out = []
    if rep["refused"]:
        out.append(f"refused imports {rep['refused']}")
    if rep["blocked_loaded"]:
        out.append(f"blocked modules loaded {rep['blocked_loaded']}")
    if rep["host_import"]:
        out.append(f"the host import of the engine failed: {rep['host_import']}")
    return out


def _assert_clean(rep: dict[str, Any], root: Path, shim: str, what: str) -> None:
    """The check passes: nothing refused or loaded, the run and the host import succeeded, and
    every package initialiser on the engine's path was executed inside the blocked child."""
    assert not _findings(rep), f"{what}: the box closure check fails: {_findings(rep)}"
    assert rep["run"]["rc"] == 0, f"{what}: the engine failed in the box closure: {rep['run']}"
    ran = {os.path.realpath(f) for f in rep["ran"] if f.startswith("/")}
    inits = [root / p / "__init__.py" for p in _packages(_engine(shim))]
    unrun = [str(p) for p in inits if p.exists() and os.path.realpath(p) not in ran]
    assert not unrun, f"{what}: package initialisers on the engine's path never ran: {unrun}"


def _assert_caught(rep: dict[str, Any], name: str | None, what: str) -> None:
    """The check fails, and (when `name` is given) its findings name `name`."""
    found = _findings(rep)
    assert found, f"{what}: the box closure check PASSED an engine that reaches outside the image"
    if name is not None:
        assert any(name in f for f in found), (
            f"{what}: the check failed but never named `{name}`: {found}")


# ======================================================================================
# Static readers
# ======================================================================================


def _path_mutations(source: str) -> list[int]:
    """Lines where a module changes `sys.path` (insert/append/extend/remove/assignment)."""
    def is_sys_path(node: ast.AST) -> bool:
        return (isinstance(node, ast.Attribute) and node.attr == "path"
                and isinstance(node.value, ast.Name) and node.value.id == "sys")
    hits = []
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"insert", "append", "extend", "remove"}  # lint-ast-resolve: ok — `sys.path` mutation read off a wrapper's/engine's own source
                and is_sys_path(node.func.value)):
            hits.append(node.lineno)
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if is_sys_path(t) or (isinstance(t, ast.Subscript) and is_sys_path(t.value)):
                    hits.append(node.lineno)
    return sorted(hits)


def _parent_steps(source: str) -> list[int]:
    """Every literal `N` in a `.parents[N]` subscript counted up from the module's own file
    (`Path(__file__)...parents[N]`): the paths derived by counting parent steps."""
    return [n.slice.value for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute)
            and n.value.attr == "parents" and isinstance(n.slice, ast.Constant)
            and isinstance(n.slice.value, int)
            and any(isinstance(x, ast.Name) and x.id == "__file__" for x in ast.walk(n.value))]


def _snapshot(root: Path) -> dict[str, tuple[int, int, int]]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in [*dirnames, *filenames]:
            p = Path(dirpath) / name
            st = p.lstat()
            out[p.relative_to(root).as_posix()] = (st.st_size, st.st_mtime_ns, st.st_mode)
    return out


def _set_writable(root: Path, writable: bool) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in [*dirnames, *filenames, "."]:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            mode = p.stat().st_mode
            p.chmod(mode | stat.S_IWUSR if writable
                    else mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


# ======================================================================================
# Golden producers (the capture script runs each one at the base, under SPEC1080_AT_BASE)
# ======================================================================================

PRODUCERS: dict[str, Callable[[Path, Path], dict[str, Any]]] = {}


def _producer(fn: Callable[[Path, Path], dict[str, Any]]) -> Callable[[Path, Path], dict[str, Any]]:
    PRODUCERS[fn.__name__] = fn
    return fn


def _co_subs(co: Path, tmp: Path) -> list[tuple[Path | str, str]]:
    return [(co, "<CO>"), (tmp, "<TMP>")]


@_producer
def _p_survival(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    engine = S.REPO_ROOT / _sql_engine()
    for lane in ("box", "host"):
        rec, ran = _run_shim(tmp, SQL, [_QUERY], lane=lane, stdin=_PAYLOAD)
        out[f"survival.query.{lane}"] = rec
        if lane == "box":
            _assert_answered_by(ran, engine, "defender-sql on the box lane")
        out[f"survival.help.{lane}"] = _run_shim(tmp, SQL, ["--help"], lane=lane)[0]
        out[f"survival.declared.{lane}"] = _run_shim(tmp, SQL, list(_DECLARED), lane=lane,
                                                     stdin=_POSITIONAL)[0]
    return out


#: sql_lanes_enforce_the_same_constraints: one argv table, both lanes. `{TMP}` is the test's tmp.
_LANE_TABLE: tuple[tuple[str, tuple[str, ...], bytes], ...] = (
    ("query", (_QUERY,), _PAYLOAD),
    ("declared", _DECLARED, _POSITIONAL),
    ("declared-equals-form", ("--rows=values", "--names=columns",
                              "SELECT count(*) AS n FROM data"), _POSITIONAL),
    ("declared-names-first", ("--names", "columns", "--rows", "values",
                              "SELECT count(*) AS n FROM data"), _POSITIONAL),
    ("declared-after-sql", ("SELECT count(*) AS n FROM data", "--rows", "values", "--names",
                            "columns"), _POSITIONAL),
    ("rows-alone", ("--rows", "values", "SELECT 1"), _POSITIONAL),
    ("names-alone", ("--names", "columns", "SELECT 1"), _POSITIONAL),
    ("unknown-flag", ("--bogus", "x", "SELECT 1"), _PAYLOAD),
    ("abbreviated-flag", ("--row", "values", "--names", "columns",
                          "SELECT count(*) AS n FROM data"), _POSITIONAL),
    ("help-flag", ("-h",), b""),
    ("read-csv-passwd", ("SELECT * FROM read_csv('/etc/passwd')",), _PAYLOAD),
    ("read-text-passwd", ("SELECT * FROM read_text('/etc/passwd')",), _PAYLOAD),
    ("copy-to", ("COPY (SELECT 1 AS x) TO '{TMP}/copied.csv'",), _PAYLOAD),
    ("attach", ("ATTACH '{TMP}/attached.duckdb' AS other",), _PAYLOAD),
    ("unlock-external-access", ("SET enable_external_access=true",), _PAYLOAD),
)


def _lane_env(tmp: Path, lane: str, trace: Path) -> dict[str, str]:
    """The lane's own environment from its own builder: the box's `_render_env` (what `docker
    run --env` carries), or the host's `run_common.run_env`. The `_interp` folder goes first on
    PATH: the box image's `python3` here, and the host python3 a tree without a venv falls back
    to."""
    if lane == "box":
        # By its dotted name: the package door binds `_docker` to a function of that name.
        docker = importlib.import_module("defender.runtime.box._docker")
        env = dict(docker._render_env({}, S.REPO_ROOT))
    else:
        from defender import run_common
        run_dir = tmp / "runs" / "r1"
        run_dir.mkdir(parents=True, exist_ok=True)
        env = dict(run_common.run_env(S.DEFENDER, run_dir))
    env["PATH"] = f"{_interp(tmp)}{os.pathsep}{env['PATH']}"
    env["SPEC1080_TRACE"] = str(trace)
    env["COLUMNS"] = "80"  # argparse wraps `-h` to the terminal width it is told
    return env


@_producer
def _p_lanes(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    engine = S.REPO_ROOT / _sql_engine()
    run_dir = tmp / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    for case, args, stdin in _LANE_TABLE:
        argv = [a.replace("{TMP}", str(tmp)) for a in args]
        verdicts = {}
        for lane in ("box", "host"):
            trace = _trace_file(tmp)
            proc = S.run([SQL, *argv], cwd=run_dir, env=_lane_env(tmp, lane, trace), stdin=stdin)
            verdicts[lane] = _rec(proc, [(tmp, "<TMP>")])
            if lane == "box":
                _assert_answered_by(_read_trace(trace), engine, f"{case} on the box lane")
        assert verdicts["box"] == verdicts["host"], (
            f"{case}: the lanes disagree\n  box:  {verdicts['box']}\n  host: {verdicts['host']}")
        out[f"lanes.{case}"] = verdicts["box"]
    for written in ("copied.csv", "attached.duckdb"):
        assert not (tmp / written).exists(), f"a query on a lane wrote {written} outside the run"
    return out


def _shadow(tmp: Path, module: str) -> Path:
    """A folder holding `<module>.py` that raises ImportError: the module is not installed."""
    folder = tmp / f"without-{module}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{module}.py").write_text(f"raise ImportError('{module} is not installed here')\n",
                                         encoding="utf-8")
    return folder


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1165 or #1172 (the flat-tier exit-code vocabulary).
def _host_reading(rc: int, rec: dict[str, Any]) -> dict[str, Any]:
    """How the host's bash tool reads a `defender-sql` result: the queries-table code, the stored
    error class, and the text the model is handed."""
    from defender.runtime import tools
    from defender.runtime.tools._deps import _format_bash_result

    error_class_for_exit = S.moved("error_class_for_exit", home=S.EXIT_CODES)
    code = tools._shim_exit_code(rc)
    return {"table_code": code, "error_class": error_class_for_exit(code),
            "model_reads": _format_bash_result(rc, rec["stdout"], rec["stderr"])}


@_producer
def _p_statuses(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    no_duckdb = f"{_shadow(tmp, 'duckdb')}{os.pathsep}{S.REPO_ROOT}"
    cases: tuple[tuple[str, str, Sequence[str], bytes, str | bool], ...] = (
        ("ok", SQL, [_QUERY], _PAYLOAD, True),
        ("bad-sql", SQL, ["SELECT nope FROM data"], _PAYLOAD, True),
        ("bad-flag", SQL, ["--bogus", "SELECT 1"], _PAYLOAD, True),
        ("no-input", SQL, [_QUERY], b"", True),
        ("no-runtime", SQL, [_QUERY], _PAYLOAD, no_duckdb),
        ("bad-regex", LESSONS, ["("], b"", True),
    )
    for case, shim, args, stdin, pythonpath in cases:
        rec, ran = _run_shim(tmp, shim, args, stdin=stdin, pythonpath=pythonpath,
                             subs=[(tmp, "<TMP>")])
        _assert_answered_by(ran, S.REPO_ROOT / _engine(shim), f"{case} through {shim}")
        out[f"statuses.{case}"] = rec
        if shim == SQL:
            out[f"statuses.{case}.host"] = _host_reading(rec["rc"], rec)
    return out


_EXIT_NAMES = ("EXIT_OK", "EXIT_QUERY_ERROR", "EXIT_INPUT_ERROR", "EXIT_NO_RUNTIME")


@_producer
def _p_closure_clean(tmp: Path, co: Path) -> dict[str, Any]:
    """Both engines in the box closure, over the real tree (sql) and the fixed-corpus copy
    (lessons), each with a real invocation."""
    out: dict[str, Any] = {}
    for shim, root in ((SQL, S.REPO_ROOT), (LESSONS, co)):
        rep = _closure(tmp, shim, root=root, subs=_co_subs(co, tmp))
        _assert_clean(rep, root, shim, f"{shim} in the box closure")
        out[f"closure.{shim}"] = rep["run"]
    return out


@_producer
def _p_host_import(tmp: Path, co: Path) -> dict[str, Any]:
    """The host's import of the engine by dotted name, inside the box's package set: the
    exit-code vocabulary it reads, and what the host tool maps each code to."""
    from defender.runtime import tools

    engine = _sql_engine()
    body = ("import importlib, json, sys\n"
            f"m = importlib.import_module({S.dotted(engine)!r})\n"
            f"print(json.dumps({{k: getattr(m, k) for k in {_EXIT_NAMES!r}}}))\n"
            f"print(json.dumps(sorted(x for x in sys.modules if x.split('.')[0] in "
            f"{S.BOX_BLOCKED!r})))\n")
    proc = run_blocked(body, allow_only=_box_allowlist(), cwd=S.REPO_ROOT,
                       env=S.child_env(DEFENDER_BOX="1"))
    assert proc.returncode == 0, f"the engine cannot be imported by name: {_txt(proc.stderr)}"
    consts_line, blocked_line = _txt(proc.stdout).splitlines()[-2:]
    assert json.loads(blocked_line) == [], f"importing the engine loaded {blocked_line}"
    consts = json.loads(consts_line)
    return {"host_import.constants": consts,
            "host_import.table_codes": {k: tools._shim_exit_code(v) for k, v in consts.items()}}


#: s074: one process holding the engine by its dotted name AND running it by path, per case.
_TWO_COPIES_BODY = '''
import importlib, io, json, os, runpy, sys
host = importlib.import_module(_DOTTED)
constants = {k: getattr(host, k) for k in _NAMES}
statuses = {}
for case, args, data, without_duckdb in _CASES:
    sys.argv = [_WRAPPER, *args]
    sys.path[0] = os.path.dirname(_WRAPPER)
    sys.stdin = io.TextIOWrapper(io.BytesIO(data.encode("utf-8")), encoding="utf-8")
    saved = sys.modules.get("duckdb")
    if without_duckdb:
        sys.modules["duckdb"] = None
    try:
        runpy.run_path(_WRAPPER, run_name="__main__")
        statuses[case] = 0
    except SystemExit as exc:
        statuses[case] = exc.code if isinstance(exc.code, int) else 1
    finally:
        if without_duckdb:
            if saved is None:
                del sys.modules["duckdb"]
            else:
                sys.modules["duckdb"] = saved
with open(_REPORT, "w", encoding="utf-8") as fh:
    json.dump({"constants": constants, "statuses": statuses,
               "host_still_same": sys.modules[_DOTTED] is host}, fh)
'''

_TWO_COPIES_CASES = (
    ("ok", [_QUERY], _PAYLOAD.decode(), False),
    ("bad-sql", ["SELECT nope FROM data"], _PAYLOAD.decode(), False),
    ("declaration-refused", ["--rows", "values", "--names", "nope", "SELECT 1"],
     _POSITIONAL.decode(), False),
    ("declared-not-json", list(_DECLARED), "not json", False),
    ("no-input", [_QUERY], "", False),
    ("no-runtime", [_QUERY], _PAYLOAD.decode(), True),
)


@_producer
def _p_two_copies(tmp: Path, co: Path) -> dict[str, Any]:
    report = tmp / "two-copies.json"
    engine = _sql_engine()
    header = (f"_DOTTED = {S.dotted(engine)!r}\n_NAMES = {_EXIT_NAMES!r}\n"
              f"_WRAPPER = {str(S.REPO_ROOT / _wrapper_rel(SQL))!r}\n"
              f"_CASES = {_TWO_COPIES_CASES!r}\n_REPORT = {str(report)!r}\n")
    proc = run_blocked(header + _TWO_COPIES_BODY, allow_only=_box_allowlist(),
                       cwd=tmp, env=_env(tmp, box=True, defender_dir=S.DEFENDER,
                                         pythonpath=str(S.REPO_ROOT)))
    assert report.exists(), f"the two-copies child died: {_txt(proc.stderr)}"
    rep = json.loads(report.read_text(encoding="utf-8"))
    assert rep["host_still_same"], "running the engine by path replaced the host's module object"
    return {"two_copies.constants": rep["constants"], "two_copies.statuses": rep["statuses"]}


@_producer
def _p_no_runtime(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    engine = S.REPO_ROOT / _sql_engine()
    zoned = "SELECT '2026-01-01T03:00:00Z'::TIMESTAMPTZ AS t FROM data"
    for lane in ("box", "host"):
        for case, module, query in (("no-duckdb", "duckdb", _QUERY), ("no-pytz", "pytz", zoned),
                                    ("plain-without-pytz", "pytz", _QUERY)):
            path = f"{_shadow(tmp, module)}{os.pathsep}{S.REPO_ROOT}"
            rec, ran = _run_shim(tmp, SQL, [query], lane=lane, stdin=_PAYLOAD, pythonpath=path,
                                 subs=[(tmp, "<TMP>")])
            if lane == "box":
                _assert_answered_by(ran, engine, f"{case} on the box lane")
            out[f"no_runtime.{case}.{lane}"] = {"run": rec, **_host_reading(rec["rc"], rec)}
        rec, _ = _run_shim(tmp, SQL, ["SELEKT 1"], lane=lane, stdin=_PAYLOAD)
        out[f"no_runtime.bad-query.{lane}"] = {"run": rec, **_host_reading(rec["rc"], rec)}
    return out


@_producer
def _p_image(tmp: Path, co: Path) -> dict[str, Any]:
    from defender.runtime.box import _image
    return {"image.recipe": {"hash_inputs": _image.HASH_INPUTS,
                             "recipe_version": _image.RECIPE_VERSION}}


@_producer
def _p_dir_unset(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for lane in ("box", "host"):
        rec, ran = _run_shim(tmp, SQL, [_QUERY], lane=lane, defender_dir=False, stdin=_PAYLOAD)
        assert ran is None, (
            f"with DEFENDER_DIR unset the {lane} lane still started an interpreter: {ran}")
        out[f"dir_unset.{lane}"] = rec
    return out


def _spellings(tmp: Path, co: Path) -> dict[str, tuple[str, Path]]:
    """DEFENDER_DIR spelled six ways: (value, working directory)."""
    link = tmp / "link-to-defender"
    if not link.exists():
        link.symlink_to(co / "defender", target_is_directory=True)
    spaced = tmp / "with space"
    spaced.mkdir(exist_ok=True)
    if not (spaced / "defender").exists():
        (spaced / "defender").symlink_to(co / "defender", target_is_directory=True)
    run = tmp / "run"
    run.mkdir(exist_ok=True)
    return {
        "plain": (str(co / "defender"), run),
        "relative": ("defender", co),
        "trailing-slash": (str(co / "defender") + "/", run),
        "symlink": (str(link), run),
        "space": (str(spaced / "defender"), run),
        "moved-away": (str(tmp / "moved-away" / "defender"), run),
    }


@_producer
def _p_spellings(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    subs = _co_subs(co, tmp)
    for shim, args, stdin in ((SQL, [_QUERY], _PAYLOAD),
                              (LESSONS, list(_LESSON_RUNS["grep"]), b"")):
        engine = co / _engine(shim)
        for spelling, (value, cwd) in _spellings(tmp, co).items():
            for lane in ("box", "host"):
                if lane == "host" and spelling not in ("relative", "moved-away", "symlink"):
                    continue
                rec, ran = _run_shim(tmp, shim, args, lane=lane, tree=co, defender_dir=value,
                                     pythonpath=str(co) if lane == "box" else False, stdin=stdin,
                                     cwd=cwd, subs=subs)
                if spelling != "moved-away":
                    _assert_answered_by(ran, engine, f"{shim} with a {spelling} DEFENDER_DIR")
                out[f"spellings.{shim}.{spelling}.{lane}"] = rec
    return out


_ARG_SHAPES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("empty", ("",)),
    ("whitespace", ("   ",)),
    ("dash-leading", ("-x",)),
    ("dash-number-after-separator", ("--", "-1")),
    ("bare-separator", ("--",)),
    ("separator-then-sql", ("--", "SELECT count(*) AS n FROM data")),
    ("non-ascii", ("SELECT 'é' AS e, '日本' AS j, \"user\" FROM data ORDER BY 3 LIMIT 1",)),
    ("extra-positional", ("SELECT 1 AS x", "extra")),
    ("two-sqls", ("SELECT 1 AS x", "SELECT 2 AS y")),
)


@_producer
def _p_arg_shapes(tmp: Path, co: Path) -> dict[str, Any]:
    return {f"arg_shapes.{case}": _run_shim(tmp, SQL, list(args), stdin=_PAYLOAD)[0]
            for case, args in _ARG_SHAPES}


def _huge() -> bytes:
    return ("[" + ",".join(f'{{"a":{i}}}' for i in range(300_000)) + "]").encode()


@_producer
def _p_stdin(tmp: Path, co: Path) -> dict[str, Any]:
    q = "SELECT count(*) AS n, max(a) AS top FROM data"
    return {
        "stdin.closed": _run_shim(tmp, SQL, [q], closed_stdin=True)[0],
        "stdin.empty": _run_shim(tmp, SQL, [q], stdin=b"")[0],
        "stdin.whitespace": _run_shim(tmp, SQL, [q], stdin=b" \n\t\n")[0],
        "stdin.huge-single-line": _run_shim(tmp, SQL, [q], stdin=_huge())[0],
        "stdin.non-text": _run_shim(tmp, SQL, [q], stdin=b"\xff\xfe\x00\x01garbage\x80")[0],
        "stdin.non-text-declared": _run_shim(tmp, SQL, list(_DECLARED),
                                             stdin=b"\xff\xfe\x00\x01garbage\x80")[0],
    }


@_producer
def _p_rows_names(tmp: Path, co: Path) -> dict[str, Any]:
    unreadable = tmp / "unreadable-file"
    unreadable.write_text('{"values": [[1]], "columns": ["a"]}', encoding="utf-8")
    unreadable.chmod(0)
    folder = tmp / "a-folder"
    folder.mkdir(exist_ok=True)
    cases = {
        "rows-alone": ("--rows", "values"),
        "names-alone": ("--names", "columns"),
        "missing-files": ("--rows", str(tmp / "no-such-rows"), "--names", str(tmp / "no-such-names")),
        "directories": ("--rows", str(folder), "--names", str(folder)),
        "unreadable-file": ("--rows", str(unreadable), "--names", str(unreadable)),
        "outside-the-run": ("--rows", "/etc/passwd", "--names", "/etc/hostname"),
        "control-both-paired": ("--rows", "values", "--names", "columns"),
    }
    return {f"rows_names.{case}": _run_shim(tmp, SQL, [*flags, "SELECT count(*) AS n FROM data"],
                                            stdin=_POSITIONAL, subs=[(tmp, "<TMP>")])[0]
            for case, flags in cases.items()}


_OPTIONAL_RESULTS = {
    "zoned-timestamp": "SELECT '2026-01-01T03:00:00+05:00'::TIMESTAMPTZ AS t, "
                       "TIMESTAMP '2026-01-01 03:00:00' AS p, "
                       "date_trunc('day', '2026-01-01T03:00:00Z'::TIMESTAMPTZ) AS d FROM data",
    "decimal": "SELECT 12345.6789::DECIMAL(18,4) AS d, 0.1::DECIMAL(3,2) AS e, "
               "sum(n)::DECIMAL(10,1) AS s FROM data",
    "nested-list": "SELECT [[1, 2], [3]] AS nl, {'k': [1, 2], 'z': 'x'} AS st, "
                   "list(\"user\") AS users FROM data",
    "wide-row": "SELECT " + ", ".join(f"{i} AS c{i}" for i in range(300)) + " FROM data LIMIT 1",
    "other-types": "SELECT INTERVAL 1 DAY AS iv, '\\x00\\x01'::BLOB AS b, DATE '2026-01-02' AS d, "
                   "TIME '03:04:05' AS t, 'NaN'::DOUBLE AS n, 'inf'::DOUBLE AS i "
                   "FROM data LIMIT 1",
}


@_producer
def _p_optional_results(tmp: Path, co: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for case, query in _OPTIONAL_RESULTS.items():
        rep = _closure(tmp, SQL, args=[query])
        _assert_clean(rep, S.REPO_ROOT, SQL, f"a {case} result")
        out[f"optional_results.{case}"] = rep["run"]
    return out


@_producer
def _p_bare_wrapper(tmp: Path, co: Path) -> dict[str, Any]:
    rec, ran = _run_wrapper(tmp, SQL, [_QUERY], stdin=_PAYLOAD)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "the wrapper from a bare environment")
    return {"bare_wrapper.query": rec,
            "bare_wrapper.help": _run_wrapper(tmp, SQL, ["--help"])[0]}


def _lesson_and_sql_runs(tmp: Path, root: Path, subs: Sequence[tuple[Path | str, str]], *,
                         label: str, via: Path | None = None, box: bool = False,
                         pythonpath: str | None = None, cwd: Path | str | None = None,
                         ) -> dict[str, Any]:
    """Both wrappers started by path in the tree at `root` (optionally spelled `via`): the sql
    query and every lessons invocation, each checked to have run the engine of THAT tree."""
    out: dict[str, Any] = {}
    runs = [(SQL, "query", (_QUERY,), _PAYLOAD),
            *((LESSONS, k, v, b"") for k, v in _LESSON_RUNS.items())]
    for shim, case, args, stdin in runs:
        rec, ran = _run_wrapper(tmp, shim, list(args), tree=root, via=via, box=box,
                                pythonpath=pythonpath, stdin=stdin, cwd=cwd, subs=subs)
        _assert_answered_by(ran, root / _engine(shim), f"{shim} {case} ({label})")
        out[f"{label}.{shim}.{case}"] = rec
    return out


@_producer
def _p_stale_above(tmp: Path, co: Path) -> dict[str, Any]:
    outer = tmp / "outer"
    marker = tmp / "stale-loaded.txt"
    _foreign_tree(outer, marker)
    (outer / "defender" / "lessons").mkdir(parents=True, exist_ok=True)
    (outer / "defender" / "lessons" / "spec1080-stale.md").write_text(
        _CORPUS["spec1080-alpha.md"].replace("alpha", "stale"), encoding="utf-8")
    checkout = _copy_tree(outer / "checkout")
    subs = [(checkout, "<CO>"), (outer, "<OUTER>"), (tmp, "<TMP>")]
    out = {
        **_lesson_and_sql_runs(tmp, checkout, subs, label="stale_above.bare", cwd=outer),
        **_lesson_and_sql_runs(tmp, checkout, subs, label="stale_above.box", box=True,
                               pythonpath=str(checkout), cwd=outer),
    }
    assert _foreign_loaded(marker) == [], (
        f"an engine imported the stale defender/ above its checkout: {_foreign_loaded(marker)}")
    # Positive control: the stale folder IS importable, and the marker sees it.
    probe = S.run([sys.executable, "-c", "import defender._io"], cwd=tmp,
                  env=S.child_env(pythonpath=False, PYTHONPATH=str(outer)))
    assert probe.returncode == 97, f"the stale folder never answered: {_txt(probe.stderr)}"
    assert _foreign_loaded(marker) == ["defender._io"], "the stale folder's marker never fired"
    return out


@_producer
def _p_other_cwd(tmp: Path, co: Path) -> dict[str, Any]:
    marker = tmp / "foreign-loaded.txt"
    foreign = _foreign_tree(tmp / "foreign", marker)
    subs = [*_co_subs(co, tmp)]
    out: dict[str, Any] = {}
    for label, cwd in (("run-folder", tmp / "run"), ("filesystem-root", Path("/")),
                       ("foreign-checkout", foreign), ("foreign-defender", foreign / "defender")):
        out.update(_lesson_and_sql_runs(tmp, co, subs, label=f"other_cwd.{label}", cwd=cwd))
    assert _foreign_loaded(marker) == [], (
        f"the working directory's checkout answered: {_foreign_loaded(marker)}")
    return out


def _mounted(tmp: Path) -> Path:
    """A copy whose checkout root holds nothing but `defender/`, as a box mount leaves it."""
    return _copy_tree(tmp / "mount")


@_producer
def _p_mount(tmp: Path, co: Path) -> dict[str, Any]:
    root = _mounted(tmp)
    subs = [(root, "<MOUNT>"), (tmp, "<TMP>")]
    out: dict[str, Any] = {}
    _set_writable(root, False)
    try:
        assert sorted(p.name for p in root.iterdir()) == ["defender"]
        for shim, case, args, stdin in ((SQL, "query", [_QUERY], _PAYLOAD),
                                        *((LESSONS, k, list(v), b"")
                                          for k, v in _LESSON_RUNS.items())):
            rec, ran = _run_shim(tmp, shim, args, tree=root, stdin=stdin, subs=subs)
            _assert_answered_by(ran, root / _engine(shim), f"{shim} {case} in the mount")
            out[f"mount.{shim}.{case}"] = rec
    finally:
        _set_writable(root, True)
    return out


@_producer
def _p_symlinked(tmp: Path, co: Path) -> dict[str, Any]:
    link = tmp / "linked-checkout"
    if not link.exists():
        link.symlink_to(co, target_is_directory=True)
    subs = [(co, "<CO>"), (link, "<LINK>"), (tmp, "<TMP>")]
    out = _lesson_and_sql_runs(tmp, co, subs, label="symlinked.wrapper", via=link)
    for shim, case, args, stdin in ((SQL, "query", [_QUERY], _PAYLOAD),
                                    *((LESSONS, k, list(v), b"")
                                      for k, v in _LESSON_RUNS.items())):
        rec, ran = _run_shim(tmp, shim, args, tree=link, stdin=stdin, subs=subs)
        _assert_answered_by(ran, co / _engine(shim), f"{shim} {case} through the link")
        out[f"symlinked.shim.{shim}.{case}"] = rec
    return out


def _no_cache_tree(tmp: Path) -> Path:
    """A copy where no bytecode can be cached beside any module: every package folder's
    `__pycache__` is a regular file."""
    root = _copy_tree(tmp / "ro")
    for dirpath, _dirs, files in os.walk(root / "defender"):
        if any(f.endswith(".py") for f in files):
            (Path(dirpath) / "__pycache__").write_text("not a folder\n", encoding="utf-8")
    return root


@_producer
def _p_read_only(tmp: Path, co: Path) -> dict[str, Any]:
    root = _no_cache_tree(tmp)
    small_tmp = tmp / "small-tmp"
    small_tmp.mkdir()
    subs = [(root, "<RO>"), (tmp, "<TMP>")]
    out: dict[str, Any] = {}
    _set_writable(root, False)
    try:
        before = _snapshot(root)
        for variant, extra in (("pycache-is-a-file", {}),
                               ("cache-prefix-uncreatable",
                                {"PYTHONPYCACHEPREFIX": "/proc/spec1080-no-pycache"})):
            for shim, args, stdin in ((SQL, [_QUERY], _PAYLOAD), (LESSONS, ["--tags"], b"")):
                rec, ran = _run_shim(tmp, shim, args, tree=root, stdin=stdin, subs=subs,
                                     TMPDIR=str(small_tmp), HOME="/proc/spec1080-no-home",
                                     **extra)
                _assert_answered_by(ran, root / _engine(shim), f"{shim} on the read-only tree")
                out[f"read_only.{variant}.{shim}"] = rec
        after = _snapshot(root)
    finally:
        _set_writable(root, True)
    changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
    assert not changed, f"running the engines wrote into the tree: {changed[:10]}"
    assert list(small_tmp.iterdir()) == [], f"the engine left {list(small_tmp.iterdir())} behind"
    return out


def _gate_forms(engine_rel: str, wrapper_rel: str, arg: str) -> dict[str, tuple[str, str]]:
    """Model-authored commands that run an engine file directly: (command, the operand that
    names it), keyed by form. Paths under the gate's synthetic `/dfn` checkout."""
    def under_dfn(rel: str) -> str:
        return "/dfn/" + rel.split("/", 1)[1]
    new, old = under_dfn(engine_rel), under_dfn(wrapper_rel)
    return {
        "python3-old-path": (f"python3 {old} {arg}", old),
        "python3-new-path": (f"python3 {new} {arg}", new),
        "python3-new-relative": (f"python3 {engine_rel.split('/', 1)[1]} {arg}",
                                 engine_rel.split("/", 1)[1]),
        "exec-old-path": (f"{old} {arg}", old),
        "exec-new-path": (f"{new} {arg}", new),
        "module-old": (f"python3 -m {S.dotted(wrapper_rel)} {arg}", S.dotted(wrapper_rel)),
        "module-new": (f"python3 -m {S.dotted(engine_rel)} {arg}", S.dotted(engine_rel)),
        "piped-new-path": (f"cat /run/gather_raw/l-001/0.json | python3 {new} {arg}", new),
    }


_ARBITRARY = {
    "python3-old-path": "/dfn/arbitrary/prog.py", "python3-new-path": "/dfn/arbitrary/prog.py",
    "python3-new-relative": "arbitrary/prog.py", "exec-old-path": "/dfn/arbitrary/prog.py",
    "exec-new-path": "/dfn/arbitrary/prog.py", "module-old": "defender.arbitrary.prog",
    "module-new": "defender.arbitrary.prog", "piped-new-path": "/dfn/arbitrary/prog.py",
}


def _verdict(decision: Any, operand: str) -> dict[str, Any]:
    reason = decision.reason or ""
    for spelling, token in ((operand, "<OPERAND>"), (operand.rsplit("/", 1)[-1], "<FILE>")):
        if spelling:
            reason = reason.replace(spelling, token)
    return {"allow": decision.allow, "reason": reason}


@_producer
def _p_gate(tmp: Path, co: Path) -> dict[str, Any]:
    pytest.importorskip("pydantic_ai")
    from defender.agents import MAIN_DEF
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.permission import files
    from defender.tests import _tenants1106 as T1106

    run, dfn = Path("/run"), Path("/dfn")
    lanes = {"main": compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn),
             "gather": compile_policy_for(T1106.fixture_gather_def(), run_dir=run,
                                          defender_dir=dfn)}
    out: dict[str, Any] = {}

    def bash(cmd: str, policy: Any) -> Any:
        return permission.decide_bash(cmd, policy=policy, run_dir=run, defender_dir=dfn)

    for lane, policy in lanes.items():
        for shim, arg in ((SQL, "'SELECT 1'"), (LESSONS, "--tags")):
            for form, (cmd, operand) in _gate_forms(_engine(shim), _wrapper_rel(shim),
                                                    arg).items():
                got = _verdict(bash(cmd, policy), operand)
                arbitrary_cmd = cmd.replace(operand, _ARBITRARY[form])
                like = _verdict(bash(arbitrary_cmd, policy), _ARBITRARY[form])
                assert got == like, (
                    f"{lane}: `{cmd}` is not refused as an arbitrary program path is: "
                    f"{got} vs {like}")
                assert not got["allow"], f"{lane}: the gate admits `{cmd}`"
                out[f"gate.{lane}.{shim}.{form}"] = got
            for which, rel in (("old", _wrapper_rel(shim)), ("new", _engine(shim))):
                path = "/dfn/" + rel.split("/", 1)[1]
                out[f"gate.{lane}.{shim}.read-{which}"] = {
                    "read_roots": files.read_allowed_path(path, run_dir=run, defender_dir=dfn,
                                                          policy=policy),
                    "decide_read": _verdict(permission.decide_read(
                        Path(path), run_dir=run, defender_dir=dfn, policy=policy), path),
                    "cat": _verdict(bash(f"cat {path}", policy), path),
                }
        out[f"gate.{lane}.control.sql-token"] = _verdict(
            bash("cat /run/gather_raw/l-001/0.json | defender-sql 'SELECT 1'", policy), "")
        out[f"gate.{lane}.control.lessons-token"] = _verdict(
            bash("defender-lessons --tags", policy), "")
    return out


# ======================================================================================
# Fixtures
# ======================================================================================


@pytest.fixture(scope="module")
def co(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One copy of the tree with the fixed lesson corpus, shared by the tests that only read it."""
    return _copy_tree(tmp_path_factory.mktemp("co"))


# ======================================================================================
# Tests
# ======================================================================================


def test_1080_defender_sql_answers_through_the_moved_engine_as_today(tmp_path, co):
    """`bin/defender-sql`, run with `DEFENDER_DIR` set to the worktree's `defender/`, execs a file
    that exists and answers a fixed SQL query over a fixed JSON input with the same stdout and
    exit code as the base engine. Its `--help` text is unchanged.

    Observed through the real shim on the box and host lanes: the query, a declared
    positional-rows query and `--help`, each against the base golden, and on the box lane the
    trace shows the moved engine (found by symbol) is what ran."""
    assert S.shim_exec_target(SQL).is_file(), f"bin/{SQL} execs a file that does not exist"
    _check_all(_p_survival(tmp_path, co))


def test_1080_the_defender_sql_engine_imports_nothing_outside_the_box_image_closure(tmp_path, co):
    """The engine `bin/defender-sql` execs runs under an interpreter that refuses every import
    outside the standard library, `defender`, and the core and `box` dependencies, with
    `DEFENDER_BOX=1`. It answers a fixed query, and no blocked module (`pydantic_ai`,
    `anthropic`, `openai`, `mcp` and their kin) appears in `sys.modules`, including through any
    package `__init__` on its path. The allowlist is derived from `pyproject.toml`'s core
    dependencies and `box` extra.

    The check (`_closure`) starts the wrapper the shim names, by path, as `__main__`, then
    imports the engine by name so every package initialiser on its path runs inside the blocked
    child; it reports every refused import, every blocked module present, and the initialisers
    executed. Positive control in the same test: the same check over a copy whose engine
    imports `pydantic_ai` fails and names it (box_closure_catches_heavy_import)."""
    allow = _box_allowlist()
    assert "pydantic_ai" not in allow, allow
    assert "duckdb" in allow, allow
    rep = _closure(tmp_path, SQL)
    _check("closure.defender-sql", rep["run"])
    _assert_clean(rep, S.REPO_ROOT, SQL, "the sql engine")
    root = _copy_tree(tmp_path / "planted")
    with _planted(root / _sql_engine(), _at_module_scope("import pydantic_ai")):
        _assert_caught(_closure(tmp_path, SQL, root=root), "pydantic_ai",
                       "an engine importing pydantic_ai")


def test_1080_the_box_closure_check_fails_an_engine_that_reaches_for_pydantic_ai(tmp_path):
    """The closure check, run over a copy of the sql engine with `import pydantic_ai` planted at
    module scope or in its package's `__init__`, fails and names the blocked module.

    Both plants are made in a copy of the tree (the engine's own module, and its package's
    `__init__.py`, created when the package has none), for the sql engine and the lessons
    engine; the unplanted copy passes the same check first, so the failure is the plant's."""
    root = _copy_tree(tmp_path / "copy")
    for shim in (SQL, LESSONS):
        engine = root / _engine(shim)
        _assert_clean(_closure(tmp_path, shim, root=root), root, shim, f"the unplanted {shim}")
        for where, path in (("module scope", engine), ("package __init__",
                                                       engine.parent / "__init__.py")):
            edit = _at_module_scope("import pydantic_ai") if path == engine \
                else _appending("import pydantic_ai")
            with _planted(path, edit):
                _assert_caught(_closure(tmp_path, shim, root=root), "pydantic_ai",
                               f"{shim} with pydantic_ai imported at {where}")


def test_wrapper_between_the_shim_and_an_engine_that_reports_by_exit_status(tmp_path, co):
    """The wrapper changes no status: bad SQL, bad input (flag), missing runtime and a bad regex
    each exit with the engine's status exactly as today, and the host tool still classifies and
    records the call the same way (EXIT_OK/INPUT_ERROR/QUERY_ERROR/NO_RUNTIME mapping and the
    stored error class). The model reads the same result. (O5: defender-sql and defender-lessons
    inside the box behave as today.)

    Each case runs through its real shim on the box lane (a missing duckdb is a folder on the
    import path whose `duckdb` raises ImportError, as test_1092 plants it), and the host's
    reading is the real chain: `tools._shim_exit_code`, the moved `error_class_for_exit`, and
    `_format_bash_result`, each against the base."""
    _check_all(_p_statuses(tmp_path, co))


def test_sql_engine_home_must_serve_a_host_import_and_a_box_run(tmp_path, co):
    """The sql engine lives in a dedicated subpackage under runtime/ (not under runtime/tools or
    runtime/branch, whose initialisers import pydantic_ai) whose own initialiser imports nothing
    heavy. The host imports it for the EXIT_* constants and the box runs it on the box image's
    Python with no agent framework; both work, and the box closure test pins the engine's whole
    import chain, every initialiser included. (Box closure rule; runtime/__init__.py is empty.)

    The host import is made inside the box's package set and must yield the base constants and
    the base queries-table codes; the box run is the closure check with a real query. The
    placement assertions come last."""
    _check_all(_p_host_import(tmp_path, co))
    rep = _closure(tmp_path, SQL)
    _check("closure.defender-sql", rep["run"])
    _assert_clean(rep, S.REPO_ROOT, SQL, "the sql engine")
    home = _sql_engine()
    parts = home.split("/")
    assert parts[:2] == ["defender", "runtime"], f"the sql engine {home} is not under runtime/"
    assert len(parts) >= 4, f"the sql engine {home} is not in a subpackage of defender/runtime/"
    assert parts[2] not in ("tools", "branch"), f"the sql engine {home} sits under runtime/{parts[2]}"
    assert (S.DEFENDER / "runtime" / "__init__.py").read_text(encoding="utf-8").strip() == "", (
        "defender/runtime/__init__.py is no longer empty")


def test_engine_package_initialiser_imports_a_package_the_box_image_lacks(tmp_path):
    """An engine whose package initialiser imports the agent framework (or any package outside
    core plus the box extra) is caught: the box closure test fails and names the offending
    import, because the rule covers the engine's whole import chain including every package
    __init__. The engine never lives under runtime/tools or runtime/branch.

    For each engine, `import pydantic_ai` is planted in each package initialiser on its dotted
    path in turn (created where the package has none), in a copy; each plant must fail the
    check naming pydantic_ai. The placement assertion comes last."""
    root = _copy_tree(tmp_path / "copy")
    for shim in (SQL, LESSONS):
        for package in _packages(_engine(shim)):
            with _planted(root / package / "__init__.py", _appending("import pydantic_ai")):
                _assert_caught(_closure(tmp_path, shim, root=root), "pydantic_ai",
                               f"{shim} with pydantic_ai in {package}/__init__.py")
    for shim in (SQL, LESSONS):
        assert not any(S.under(_engine(shim), f"defender/runtime/{d}") for d in ("tools", "branch")), (
            f"{_engine(shim)} sits under runtime/tools or runtime/branch")


#: What a sibling reaches for. At the base `defender.runtime.providers` and `defender.skills`
#: (invlang included) import cleanly inside the box's package set, so "the model providers" are
#: the provider SDKs and the host-only reader is the agent tool package, which pulls the
#: framework in through its initialiser.
_SIBLINGS = (
    ("the agent framework", "import pydantic_ai", "pydantic_ai"),
    ("a model provider SDK", "import anthropic", "anthropic"),
    ("another model provider SDK", "import openai", "openai"),
    ("a host-only reader of the agent framework", "import defender.runtime.tools", "pydantic_ai"),
)


def test_engine_imports_a_sibling_that_itself_reaches_the_agent_framework(tmp_path):
    """An engine whose import chain reaches a sibling that imports the agent framework, the model
    providers or the skills package at module level is caught by the closure test, because the
    engine would raise an ImportError in the box process that cannot import them. The frontier
    and other host-only readers therefore do not share the engine's import chain.

    In a copy, each engine is made to import a new sibling module in its own package, and the
    sibling imports one host-only target; every variant must fail the check (naming the target
    where the target is itself a blocked package)."""
    root = _copy_tree(tmp_path / "copy")
    for shim in (SQL, LESSONS):
        engine = _engine(shim)
        sibling = root / Path(engine).parent / "_spec1080_sibling.py"
        dotted = S.dotted(str(Path(engine).parent / "_spec1080_sibling.py"))
        with _planted(root / engine, _at_module_scope(f"import {dotted}")):
            for what, line, name in _SIBLINGS:
                with _planted(sibling, _writing(line + "\n")):
                    _assert_caught(_closure(tmp_path, shim, root=root), name,
                                   f"{shim} through a sibling reaching {what}")


def test_box_interpreter_is_older_than_the_host_interpreter(tmp_path, co):
    """A moved engine runs on the box image's Python: it uses no language feature or
    standard-library name the image's interpreter lacks, and a check (or the box CI jobs) runs it
    on the image's version. (Box closure rule: the engines run inside the box on the box image's
    Python.)

    The image's version is read off `box.Dockerfile`'s base image; the closure check (which runs
    each engine on this interpreter) must be running that version, both engines answer as the
    base did, and every defender module the run executed parses at that grammar version."""
    m = re.search(r"^FROM python:(\d+)\.(\d+)", (S.DEFENDER / "box.Dockerfile").read_text(
        encoding="utf-8"), re.M)
    assert m, "box.Dockerfile names no python:<major>.<minor> base image"
    image = (int(m.group(1)), int(m.group(2)))
    assert sys.version_info[:2] == image, (
        f"the closure check runs on {sys.version_info[:2]}, the box image on {image}")
    for shim, root in ((SQL, S.REPO_ROOT), (LESSONS, co)):
        rep = _closure(tmp_path, shim, root=root, subs=_co_subs(co, tmp_path))
        _check(f"closure.{shim}", rep["run"])
        _assert_clean(rep, root, shim, shim)
        mine = [f for f in rep["ran"] if os.path.realpath(f).startswith(
            os.path.realpath(root / "defender") + os.sep)]
        assert any(os.path.realpath(f) == os.path.realpath(root / _engine(shim)) for f in mine)
        for f in mine:
            ast.parse(Path(f).read_text(encoding="utf-8"), filename=f, feature_version=image)


def test_sql_engine_file_is_loaded_by_path_in_the_box_and_by_name_on_the_host(tmp_path, co):
    """The sql engine's exit constants are defined once and read the same by the in-box by-path
    run and the host's import by dotted name; the two copies of the module never disagree on a
    constant, and nothing relies on class or module identity shared across the two copies. A
    process holding both copies behaves the same.

    One blocked child imports the engine by name, then runs the wrapper by path as `__main__`
    once per case (an answer, a bad query, a refused declaration, a declared payload that is not
    JSON, no input, no duckdb): the constants it read and every status the by-path run returned
    are the base's, and the host's module object is untouched. The one-definition half: the
    vocabulary is defined in the engine and nowhere else."""
    _check_all(_p_two_copies(tmp_path, co))
    for name in _EXIT_NAMES:
        assert S.definitions(name) == (_sql_engine(),), (
            f"`{name}` is defined in {S.definitions(name)}, not once in the engine")


def test_sql_engine_runs_where_the_database_library_is_not_installed(tmp_path, co):
    """With the database library missing (no box extra), the engine reports the no-runtime status
    at start or first query, as today, distinct from a bad-query status, and the host classifies
    it through the same exit-code mapping.

    Through the real shim on both lanes: duckdb missing (a folder on the import path whose
    `duckdb` raises ImportError), pytz missing on a query returning a zoned value and on one that
    returns none, and a bad query; each run, queries-table code and error class against the
    base."""
    _check_all(_p_no_runtime(tmp_path, co))


def test_box_image_built_before_the_move_is_reused_with_the_moved_engines_mounted(tmp_path, co):
    """A box image built before the move is reused unchanged: the image tag hashes only
    box.Dockerfile, uv.lock and pyproject.toml, nothing forces a rebuild and none is needed,
    because the whole defender/ tree is bind-mounted and the engines' imports stay inside the
    image's package set (core plus box extra). The moved engines start and answer inside it.

    The tag's inputs and recipe version are the base's; the tag of the real tree equals the tag
    of a folder holding only those three files (so no moved file can rename the image); and
    both engines answer inside the image's package set as the base did."""
    from defender.runtime.box import _image

    _check_all(_p_image(tmp_path, co))
    only = tmp_path / "hash-inputs-only"
    only.mkdir()
    for name in _image.HASH_INPUTS:
        shutil.copy2(S.DEFENDER / name, only / name)
    assert _image.image_tag(S.DEFENDER) == _image.image_tag(only), (
        "the image tag reads something beyond its three inputs")
    _check_all(_p_closure_clean(tmp_path, co))


def test_engine_imports_a_package_the_host_venv_has_and_the_box_image_lacks(tmp_path):
    """An engine (or a module on its chain) that imports a package the host venv has but the box
    image lacks (core plus box extra only) is caught by the closure check, because the allowlist
    is the image's package set, not whatever the host venv carries. A pass in the host venv is
    not evidence the box can run it.

    The planted package is `pytest`: present in every venv that runs this suite, absent from the
    image's derived set. The planted copy answers in the host venv, and the closure check over
    the same copy fails naming pytest."""
    import importlib.util

    assert importlib.util.find_spec("pytest") is not None
    assert "pytest" not in _box_allowlist()
    root = _copy_tree(tmp_path / "copy")
    with _planted(root / _sql_engine(), _at_module_scope("import pytest")):
        rec, ran = _run_wrapper(tmp_path, SQL, [_QUERY], tree=root, box=True,
                                pythonpath=str(root), stdin=_PAYLOAD)
        _check("closure.defender-sql", rec)
        _assert_answered_by(ran, root / _sql_engine(), "the planted engine in the host venv")
        _assert_caught(_closure(tmp_path, SQL, root=root), "pytest", "an engine importing pytest")


def test_closure_check_where_a_blocked_package_is_already_loaded_before_the_blocker_is_installed(
        tmp_path):
    """The closure check can fail: with the blocker installed in a child whose start-up hooks may
    have already loaded modules (the venv's hook, a coverage hook), a planted import of a blocked
    or outside-allowed package is still refused, and the check has a positive control that proves
    this. A check that cannot fail because its violation was preloaded is a failure.

    The start-up hook is a real one: a `sitecustomize` on the child's import path that imports
    `pydantic_ai` before the blocker exists. The unplanted engine still passes (and the report
    shows the hook DID preload pydantic_ai); the planted engine fails naming it."""
    hook = tmp_path / "startup-hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text("import pydantic_ai\n", encoding="utf-8")
    root = _copy_tree(tmp_path / "copy")
    clean = _closure(tmp_path, SQL, root=root, hook=hook)
    assert "pydantic_ai" in clean["evicted"], (
        f"the start-up hook never preloaded pydantic_ai: {clean['evicted']}")
    _assert_clean(clean, root, SQL, "the unplanted engine under a preloading hook")
    _check("closure.defender-sql", clean["run"])
    with _planted(root / _sql_engine(), _at_module_scope("import pydantic_ai")):
        _assert_caught(_closure(tmp_path, SQL, root=root, hook=hook), "pydantic_ai",
                       "a planted pydantic_ai import already loaded by a start-up hook")


def test_subprocess_check_started_with_a_working_directory_or_path_naming_another_checkout(
        tmp_path, co, monkeypatch):
    """A test that starts a child interpreter (a shim, wrapper, closure launcher) pins the working
    directory and import path to the tree under test, so the child exercises that tree; the
    child's result does not depend on which other checkout a developer's shell happens to name. A
    child that imported another checkout makes the test fail rather than pass.

    The developer's shell names a foreign checkout (its import path and its working directory)
    whose every module records itself. The closure launcher and a wrapper run still answer from
    this tree (the base golden, the moved engine in the trace, the foreign marker silent).
    Positive control: a child launched from that shell as-is imports the foreign checkout and the
    marker sees it."""
    marker = tmp_path / "foreign-loaded.txt"
    foreign = _foreign_tree(tmp_path / "foreign", marker)
    monkeypatch.setenv("PYTHONPATH", str(foreign))
    monkeypatch.chdir(foreign)
    rep = _closure(tmp_path, SQL)
    _check("closure.defender-sql", rep["run"])
    _assert_clean(rep, S.REPO_ROOT, SQL, "the closure launcher")
    rec, ran = _run_wrapper(tmp_path, SQL, [_QUERY], stdin=_PAYLOAD)
    _check("bare_wrapper.query", rec)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "the wrapper")
    assert _foreign_loaded(marker) == [], f"a pinned child imported {_foreign_loaded(marker)}"
    naive = subprocess.run([sys.executable, "-c", f"import {S.dotted(_sql_engine())}"],  # noqa: S603
                           cwd=foreign, env=dict(os.environ), capture_output=True, check=False,
                           timeout=120)
    assert naive.returncode == 97, f"the unpinned control never answered: {_txt(naive.stderr)}"
    assert _foreign_loaded(marker), "the unpinned control never reached the foreign checkout"


def test_defender_sql_dir_env_absent_on_host_and_in_box(tmp_path, co):
    """With DEFENDER_DIR unset, `defender-sql` behaves as it does today on the host and in the
    box: the shim requires the variable and reports its missing-variable error rather than
    running the query; the move does not make the shim guess a tree. The query the model gave is
    not run.

    On both lanes the shim's error and status are the base's and no interpreter started (the
    stub records every start). Positive control: with the variable set, the same lane starts the
    moved engine and answers."""
    _check_all(_p_dir_unset(tmp_path, co))
    rec, ran = _run_shim(tmp_path, SQL, [_QUERY], stdin=_PAYLOAD)
    _check("survival.query.box", rec)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "defender-sql with DEFENDER_DIR set")


def test_defender_dir_spelled_unusually(tmp_path, co):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A DEFENDER_DIR that is relative, has a trailing slash, goes
    through a symlink, contains a space, or names a directory moved after the shim last ran gives
    the same outcome as today for each spelling; only the engine path appended to it is new.
    Probe via the shim's pre-move behavior.

    Both shims, over a copy of the tree with the fixed corpus, on the box lane for every spelling
    and the host lane for three; each run against the base and, where it answers, shown to have
    run the moved engine."""
    _check_all(_p_spellings(tmp_path, co))


def test_sql_argument_shapes_the_shim_must_forward(tmp_path, co):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). An empty, whitespace-only, dash-leading, bare `--`,
    non-ASCII SQL argument, or one followed by extra positionals reaches the engine unaltered and
    produces the same status and output as before.

    Through the real shim on the box lane; the base answers an empty or whitespace-only query with
    a traceback (pinned by its last line). Each shape also runs once with the trace checked."""
    _check_all(_p_arg_shapes(tmp_path, co))
    rec, ran = _run_shim(tmp_path, SQL, ["SELECT 'é' AS e, '日本' AS j, \"user\" FROM data "
                                         "ORDER BY 3 LIMIT 1"], stdin=_PAYLOAD)
    _check("arg_shapes.non-ascii", rec)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "a non-ASCII query")


def test_sql_stdin_closed_empty_or_huge(tmp_path, co):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A closed, empty, huge single-line or non-text stdin yields
    the same status and output as today.

    Through the real shim on the box lane: stdin closed (descriptor 0 closed in the child: the
    base answers a traceback, pinned by its last line), empty, whitespace, a 300 000-record
    single line, and undecodable bytes with and without a declaration."""
    _check_all(_p_stdin(tmp_path, co))
    _rec_, ran = _run_shim(tmp_path, SQL, ["SELECT count(*) AS n FROM data"], stdin=_huge())
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "a huge stdin")


def test_rows_and_names_flags_unpaired_or_unreadable(tmp_path, co):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). One of `--rows`/`--names` alone, or both naming a missing
    file, directory, unreadable file or a file outside the run, gives the same input-error status
    and message as today.

    At the base `--rows` and `--names` are paths INTO the payload, never files: a file path is a
    key that does not resolve. Pinned as the base answers it, through the real shim."""
    _check_all(_p_rows_names(tmp_path, co))
    _rec_, ran = _run_shim(tmp_path, SQL, ["--rows", "values", "SELECT 1"], stdin=_POSITIONAL)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "an unpaired flag")


def test_query_result_that_needs_an_optional_box_module(tmp_path, co):
    """A query returning a zoned timestamp, a decimal, a nested list or a very wide row renders as
    it does today inside an image carrying only the box extra: the moved engine needs nothing
    outside core plus the box extra for these results, and no heavy import is added on those
    paths.

    Each query runs in the box closure check (the image's package set, nothing else importable),
    answers as the base did, and the check finds nothing."""
    _check_all(_p_optional_results(tmp_path, co))


def test_1080_the_sql_engine_gives_one_verdict_per_argv_on_the_box_lane_and_the_host_lane(
        tmp_path, co):
    """For each lane that reaches `defender-sql` with model-authored argv (the box lane with
    `DEFENDER_BOX` set, and the host lane under `run_common.run_env`) the same fixed table of argv
    gets the same verdict from the moved engine: the `--rows` and `--names` flag allowlist admits
    and refuses identically; a query that reaches duckdb's external access
    (`read_csv('/etc/passwd')`, `COPY ... TO`) is refused on both lanes; and the engine starts
    under that lane's own environment, with the checkout root importable, and answers. The shim
    token gate is observed at the permission gate (s203) and is not re-asserted here.

    Each lane's environment comes from its own builder (the box's `_render_env`, the host's
    `run_env`) and the shim is reached by its token on that PATH. Every row's verdict is equal
    across the lanes and to the base; no refused write lands; the box lane ran the moved
    engine."""
    _check_all(_p_lanes(tmp_path, co))


def test_1080_the_sql_wrapper_starts_the_moved_engine_from_a_bare_environment_and_answers(
        tmp_path, co):
    """The `defender-sql` wrapper left under `defender/scripts/`, started by path from an
    environment with no PYTHONPATH (the operator shell's shape, and how
    `tests/_defender_sql.run_sql_py` and test_1126's `_without_pytz` start it), puts its own
    checkout root first on `sys.path`, starts the moved engine and answers a fixed SQL query over
    a fixed JSON input with the same stdout and exit code as the base engine. With PYTHONPATH
    naming a different checkout of defender, the engine that answers is the one beside the
    wrapper: a foreign checkout cannot shadow it ([144]). The wrapper carries exactly this one
    import-root bootstrap and the moved engine carries none.

    The foreign checkout is a tree shaped like this one whose every module records itself; it
    is named alone and ahead of this checkout. The bootstrap counts are read off the two files'
    syntax trees and come last."""
    _check_all(_p_bare_wrapper(tmp_path, co))
    engine = S.REPO_ROOT / _sql_engine()
    marker = tmp_path / "foreign-loaded.txt"
    foreign = _foreign_tree(tmp_path / "foreign", marker)
    for label, path in (("foreign alone", str(foreign)),
                        ("foreign ahead of this checkout", f"{foreign}{os.pathsep}{S.REPO_ROOT}")):
        rec, ran = _run_wrapper(tmp_path, SQL, [_QUERY], pythonpath=path, stdin=_PAYLOAD)
        assert _foreign_loaded(marker) == [], f"{label}: the foreign checkout answered"
        _check("bare_wrapper.query", rec)
        _assert_answered_by(ran, engine, f"the wrapper with {label} on PYTHONPATH")
    wrapper_src = S.shim_exec_target(SQL).read_text(encoding="utf-8")
    assert len(_path_mutations(wrapper_src)) == 1, (
        f"the wrapper changes sys.path at lines {_path_mutations(wrapper_src)}, not once")
    engine_src = engine.read_text(encoding="utf-8")
    assert _path_mutations(engine_src) == [], (
        f"the moved engine carries a bootstrap at lines {_path_mutations(engine_src)}")


def test_model_authored_command_naming_a_moved_engine_by_path(tmp_path, co):
    """A model-authored bash command running an engine by its old path, by the new path or by
    module form is refused or not admitted exactly as an arbitrary program path is today: the
    permission gate admits `defender-sql` and `defender-lessons` by shim token only and the model
    cannot pick the engine file. Passing an engine file as an operand of a read command is
    allowed by the read gate's whole-defender/ default as today.

    The real gate over the main and gather policies (the synthetic checkout test_permission
    uses): every form of naming either engine gets the verdict an arbitrary program path gets,
    and the base's; the read half is pinned as the base answers it (the read roots admit an
    engine file; the agents' declared read shapes and `cat` refuse it); the shim tokens are still
    admitted."""
    _check_all(_p_gate(tmp_path, co))


def test_engine_started_by_path_when_a_directory_above_the_checkout_holds_another_defender_folder(
        tmp_path, co):
    """An engine started by path from a checkout beneath a directory that holds an older,
    unrelated folder named defender imports that checkout's own flat-tier modules, never the
    stale folder's: the re-anchored path logic gives the same result at the engine's new depth
    and never overshoots or undershoots onto a neighboring defender/. A wrong depth must not
    silently pick another tree. (M2.)

    The stale folder is shaped like a checkout (every module records itself) and carries its own
    lesson. Both wrappers start by path from the bare environment and the box's, the working
    directory the stale folder's parent; each answers as the base did from its own checkout's
    corpus, ran its own engine, and the stale marker stays silent. Positive control: a plain
    import with the stale folder's parent on the path trips the marker."""
    _check_all(_p_stale_above(tmp_path, co))


def test_wrapper_launched_by_path_from_a_directory_other_than_the_tree(tmp_path, co):
    """A wrapper launched by path answers with the engine of its own checkout, whatever the
    working directory (a box's run folder, the filesystem root, another checkout's folder): the
    tree is derived from the wrapper's location or the shim's tree variable, never from the
    working directory. (M2.)

    Both wrappers, every lessons invocation (the relative `--show` path resolves against the
    engine's own checkout), from each working directory, against the base; the foreign
    checkout's marker stays silent."""
    _check_all(_p_other_cwd(tmp_path, co))


def test_wrapper_launched_by_path_in_a_box_whose_tree_mount_has_no_content_above_it(tmp_path, co):
    """Launched by path in a box where the tree is mounted read-only at its own host path with
    nothing above it, the wrapper and engine still find the package at their depth; no path
    derived by counting parent steps runs off the top of the path (the same holds at a one- or
    two-component absolute path such as /defender). The box mounts defender/ whole so moved
    engines resolve inside it.

    A copy whose checkout root holds only `defender/`, write bits removed, run through both shims
    on the box lane; then every `parents[N]` in the wrappers, the engines and each defender
    module the runs executed must stay at or below the checkout root at that module's depth
    (which is what keeps it on the path at /defender)."""
    _check_all(_p_mount(tmp_path, co))
    files = {S.shim_exec_target(SQL), S.shim_exec_target(LESSONS),
             S.REPO_ROOT / _sql_engine(), S.REPO_ROOT / _lessons_engine()}
    for shim in (SQL, LESSONS):
        _rec_, ran = _run_shim(tmp_path, shim, list(_REAL_RUN[shim][0]), tree=co,
                               stdin=_REAL_RUN[shim][1])
        files |= {S.REPO_ROOT / Path(f).relative_to(co) for f in ran or ()
                  if f.startswith(str(co / "defender") + os.sep)}
    for path in sorted(files):
        depth = len(path.relative_to(S.REPO_ROOT).parts)
        over = [n for n in _parent_steps(path.read_text(encoding="utf-8")) if n > depth - 1]
        assert not over, f"{S.rel(path)} counts {over} parent steps up from depth {depth}"


def test_wrapper_launched_by_path_through_a_symlinked_spelling_of_the_tree(tmp_path, co):
    """Launched through a symlinked spelling of the tree, the engines derive the same roots and
    print the same paths as today for that spelling, and answer from the same corpus. Preserved
    behavior (O5); the re-anchored constants do not change which tree is read.

    A link to the copy's checkout root; both wrappers started by path through it, and both shims
    with the tree variable spelled through it; every printed path against the base (which prints
    the resolved spelling), and each run executed the engine behind the link."""
    _check_all(_p_symlinked(tmp_path, co))


def test_engine_run_with_the_tree_read_only_and_no_place_to_cache_bytecode(tmp_path, co):
    """With the tree mounted read-only, the root filesystem read-only and a small no-exec
    temporary folder, both engines run at their new, deeper package paths exactly as today: they
    need no write to the tree and tolerate uncompilable bytecode. The move adds no write
    requirement.

    A copy with its write bits removed and a regular file where every `__pycache__` folder would
    go (and, separately, a bytecode cache prefix that cannot be created), HOME uncreatable, and a
    fresh temporary folder: both shims answer as the base did, the copy is byte-for-byte and
    stat-for-stat unchanged afterwards (the observation that holds even for root, whom mode bits
    do not stop), and the temporary folder is left empty."""
    _check_all(_p_read_only(tmp_path, co))
