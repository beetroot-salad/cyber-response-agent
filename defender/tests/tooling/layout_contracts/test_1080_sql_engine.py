"""Behavior of the `defender-sql` engine and its shim: output, argument shapes, stdin, and the
box-image import closure. Goldens: `goldens/sql.json`."""
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
import subprocess
import sys
import sysconfig
import tomllib
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared.contracts._import_blocker import run_blocked
from defender.tests.tooling.layout_contracts import _spec1080 as S

GOLDEN = "sql"
SQL = "defender-sql"
LESSONS = "defender-lessons"


def _sql_engine() -> str:
    """The moved sql engine, repo-relative: the one module under `defender/investigation/` defining the
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
    `defender/investigation/x/y.py` gives `defender`, `defender/investigation`, `defender/investigation/x`."""
    parts = relpath.split("/")[:-1]
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


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
#: Each engine's one real invocation for the closure and tree-derivation runs.
_REAL_RUN = {SQL: ((_QUERY,), _PAYLOAD), LESSONS: (("--tags",), b"")}


_SCRATCH = re.compile(r"[^\s\"']*defender-sql-[A-Za-z0-9_]{8}")
_TRACEBACK = "Traceback (most recent call last):"
_PREFIX_WARNING = re.compile(
    r"^(?:Could not find platform (?:in)?dependent libraries <(?:exec_)?prefix>"
    r"|Consider setting \$PYTHONHOME to <prefix>\[:<exec_prefix>\])\n", re.M)


def _norm(text: str, subs: Sequence[tuple[Path | str, str]] = ()) -> str:
    """Tokens for every machine- or run-specific spelling: each `(path, token)` in `subs` (both
    the spelling given and its resolved form) and the checkout root (`<ROOT>`), longest first;
    duckdb's scratch folder (`<SCRATCH>`); an untrusted frame's salt (`<SALT>`); a traceback reduced to its final `Type: message`
    line, since its frames name the file and line that the move changes; and the interpreter's
    prefix warnings (`_PREFIX_WARNING`) dropped."""
    text = _PREFIX_WARNING.sub("", text)
    pairs: dict[str, str] = {str(S.REPO_ROOT): "<ROOT>"}
    for path, token in subs:
        pairs[str(path)] = token
    for path, token in subs:  # a resolved form never overrides a spelling named explicitly
        pairs.setdefault(str(Path(path).resolve()), token)
    for real in sorted(pairs, key=len, reverse=True):
        text = text.replace(real, pairs[real])
    text = _SCRATCH.sub("<SCRATCH>", text)
    # `defender-lessons --show` frames each lesson with a fresh salt (#1206).
    text = re.sub(r"<(/?)run-[0-9a-f]{16}-untrusted>", r"<\1run-<SALT>-untrusted>", text)
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


_SKIP = S.JUNK_DIRS | {"tests"}


def _copy_tree(root: Path) -> Path:
    """`defender/` copied to `<root>/defender` (tests and caches left out, no `.venv`), and a
    run-copy-shaped agent root `<root>/agent` whose `lessons/` holds `_CORPUS`. Returns `root`,
    the copy's checkout root.

    #1108 P4 (O1, O2): the product tree carries no corpus, so the copy holds none either (a
    leftover `lessons*/` in this checkout is left out rather than removed after the fact); the
    lessons engine reads `$DEFENDER_AGENT_DIR/lessons` (`_agent_root`)."""
    root.mkdir(parents=True, exist_ok=True)
    dst = root / "defender"
    shutil.copytree(S.DEFENDER, dst, symlinks=True,
                    ignore=lambda d, names: [n for n in names if n in _SKIP or (
                        Path(d) == S.DEFENDER and n.startswith("lessons"))])
    corpus = _agent_root(root) / "lessons"
    corpus.mkdir(parents=True)
    for name, text in _CORPUS.items():
        (corpus / name).write_text(text, encoding="utf-8")
    return root


def _agent_root(root: Path) -> Path:
    """The agent root beside a tree copy: what `DEFENDER_AGENT_DIR` names for its lessons shim."""
    return root / "agent"


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
_args = sys.argv[1:]
if _args[:1] == ["-P"] and _args[1:2] == ["-m"] and len(_args) > 2:
    # `python3 -P -m <module> ...`, the shims' form: no working directory on sys.path (this
    # stub's own folder stands where `-P` leaves nothing), the module run as `__main__`.
    import importlib.util
    del sys.path[0]
    try:
        _found = importlib.util.find_spec(_args[2]) is not None
    except ImportError:
        _found = False
    if not _found:
        os.execv(sys.executable, ["python3", *_args])
    sys.argv = [_args[2], *_args[3:]]
    runpy.run_module(_args[2], run_name="__main__", alter_sys=True)
    sys.exit(0)
_target = _args[0]
if not os.path.isfile(_target):
    # Not a runnable file: hand the argv to the interpreter itself, so its own refusal speaks.
    os.execv(sys.executable, ["python3", *_args])
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
              cwd: Path | str | None = None,
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
    proc = S.run(argv, cwd=run_dir, env=env, stdin=stdin)
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
    from defender.box import _image

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


PRODUCERS: dict[str, Callable[[Path, Path], dict[str, Any]]] = {}


def _producer(fn: Callable[[Path, Path], dict[str, Any]]) -> Callable[[Path, Path], dict[str, Any]]:
    PRODUCERS[fn.__name__] = fn
    return fn


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
    run --env` carries), or the host's `box_mod.run_env`. The `_interp` folder goes first on
    PATH: the box image's `python3` here, and the host python3 a tree without a venv falls back
    to."""
    if lane == "box":
        # By its dotted name: the package door binds `_docker` to a function of that name.
        docker = importlib.import_module("defender.box._docker")
        env = dict(docker._render_env({}, S.REPO_ROOT))
    else:
        from defender import box as box_mod
        run_dir = tmp / "runs" / "r1"
        run_dir.mkdir(parents=True, exist_ok=True)
        env = dict(box_mod.run_env(S.DEFENDER, run_dir))
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


@pytest.fixture(scope="module")
def co(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One copy of the tree with the fixed lesson corpus, shared by the tests that only read it."""
    return _copy_tree(tmp_path_factory.mktemp("co"))


def test_1080_defender_sql_answers_through_the_moved_engine_as_today(tmp_path, co):
    assert S.shim_exec_target(SQL).is_file(), f"bin/{SQL} execs a file that does not exist"
    _check_all(_p_survival(tmp_path, co))


def test_1080_the_defender_sql_engine_imports_nothing_outside_the_box_image_closure(tmp_path, co):
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


def test_sql_argument_shapes_the_shim_must_forward(tmp_path, co):
    _check_all(_p_arg_shapes(tmp_path, co))
    rec, ran = _run_shim(tmp_path, SQL, ["SELECT 'é' AS e, '日本' AS j, \"user\" FROM data "
                                         "ORDER BY 3 LIMIT 1"], stdin=_PAYLOAD)
    _check("arg_shapes.non-ascii", rec)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "a non-ASCII query")


def test_rows_and_names_flags_unpaired_or_unreadable(tmp_path, co):
    _check_all(_p_rows_names(tmp_path, co))
    _rec_, ran = _run_shim(tmp_path, SQL, ["--rows", "values", "SELECT 1"], stdin=_POSITIONAL)
    _assert_answered_by(ran, S.REPO_ROOT / _sql_engine(), "an unpaired flag")


def test_1080_the_sql_engine_gives_one_verdict_per_argv_on_the_box_lane_and_the_host_lane(
        tmp_path, co):
    _check_all(_p_lanes(tmp_path, co))
