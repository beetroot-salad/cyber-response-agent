"""Shared machinery for #1080's spec — "split `defender/scripts/` into its homes". NO tests."""
from __future__ import annotations

import ast
import functools
import importlib
import importlib.metadata
import json
import math
import os
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

# ======================================================================================
# Paths
# ======================================================================================

SUITE = Path(__file__).resolve().parent
REPO_ROOT = SUITE.parents[3]
DEFENDER = REPO_ROOT / "defender"
IMAGE_CLI = DEFENDER / "box" / "image_cli.py"
BIN = DEFENDER / "bin"
GOLDENS = SUITE / "goldens"

# ======================================================================================
# Pinned homes (repo-relative). `under=` takes one of these, or any repo-relative dir/file.
# ======================================================================================

#: Pinned by demand text.
RUNTIME = "defender/investigation"
TENANCY = "defender/tenancy"
#: The price table and process bootstrap keep dependency-free package initializers; neither
#: needs to import provider objects or load the LLM stack merely to read configuration.
PRICING = "defender/configuration/_pricing.py"
VENV = "defender/execution/venv_guard.py"
QUERY_RULES = "defender/knowledge/_query_rules.py"

#: Query rule base name -> its spelling; the identity map while the public rename is parked
#: (#1165). Every file of this suite reads a rule's spelling from here, so a rename is made here.
QUERY_RULE_PUBLIC = {"json_safe_params": "json_safe_params", "query_request_key": "query_request_key"}

#: What the API program must never load: the learning loop and every former `defender.runtime`
#: module (#1308 placed them by layer). A package covers its submodules.
API_FORBIDDEN = (
    "defender.learning", "defender.investigation", "defender.systems", "defender.providers",
    "defender.records.session_store", "defender.records.selection", "defender.records._wire",
    "defender.records.run_end", "defender.tenancy.case_ticket", "defender.tenancy.run_knowledge",
    "defender.tenancy.tenant_settings", "defender.records._family", "defender._exception_groups",
    "defender.lifecycle",  # #1214: the management service and host actor (forge admin, OpenBao management)
)


def api_forbidden(modules: Iterable[str]) -> list[str]:
    """The `API_FORBIDDEN` modules among `modules`."""
    return [m for m in modules
            if m in API_FORBIDDEN or m.startswith(tuple(f + "." for f in API_FORBIDDEN))]

#: Directory names no census, locator or scan descends into: tool output, caches, virtualenvs,
#: VCS metadata. A directory holding its own `.git` (a nested checkout) is skipped too.
JUNK_DIRS = frozenset({
    ".venv", "venv", "__pycache__", "node_modules", "build", "dist", ".git", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", ".tox", ".hypothesis", ".eggs", "site-packages",
})


def rel(path: Path) -> str:
    """`path` relative to this checkout's root, POSIX-spelled."""
    return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix() if path.is_absolute() \
        else path.as_posix()


def is_test_path(relpath: str) -> bool:
    """The test exemption, by location: any file under a directory named `tests`, plus any
    `conftest.py`. A `test_*.py` beside production code and `tooling/testing/` are not exempt."""
    parts = relpath.split("/")
    return "tests" in parts[:-1] or parts[-1] == "conftest.py"


def under(relpath: str, home: str) -> bool:
    """Whether `relpath` sits in `home` — a directory (boundary-matched, never a string prefix:
    `defender/integrations_old/x.py` is not under `defender/integrations`) or a file."""
    home = home.rstrip("/")
    return relpath == home or relpath.startswith(home + "/")


def py_files(root: Path) -> list[str]:
    """Every non-test `.py` under `root/defender`, relative to `root` and sorted — walked from
    the filesystem (not `git ls-files`), skipping `JUNK_DIRS` and nested checkouts."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root / "defender"):
        d = Path(dirpath)
        keep = []
        for name in dirnames:
            if name in JUNK_DIRS:
                continue
            if (d / name / ".git").exists():  # a nested checkout: not this tree's source
                continue
            keep.append(name)
        dirnames[:] = sorted(keep)
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            r = (d / fn).relative_to(root).as_posix()
            if not is_test_path(r):
                out.append(r)
    return sorted(out)


def dotted(relpath: str) -> str:
    """`defender/a/b.py` → `defender.a.b`; `defender/a/__init__.py` → `defender.a`."""
    parts = relpath[:-3].split("/") if relpath.endswith(".py") else relpath.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


# ======================================================================================
# The symbol locator: homes are found by symbol
# ======================================================================================


def module_level_names(source: bytes | str, filename: str = "<src>") -> list[str]:
    """Every name a module binds at module level by a `def`, `class` or assignment — including
    one nested in a module-level `if` / `try` / `with`, never one inside a function or class.
    Imports are not definitions."""
    tree = ast.parse(source, filename=filename)
    out: list[str] = []

    def walk(body: Sequence[ast.stmt]) -> None:
        for n in body:
            out.extend(_bound_here(n))
            for block in _nested_blocks(n):
                walk(block)

    walk(tree.body)
    return list(dict.fromkeys(out))


def _bound_here(n: ast.stmt) -> list[str]:
    """The names one module-level statement binds by definition or assignment."""
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [n.name]
    if isinstance(n, ast.Assign):
        return [x.id for tg in n.targets for x in ast.walk(tg) if isinstance(x, ast.Name)]
    if isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name):
        return [n.target.id]
    return []


def _nested_blocks(n: ast.stmt) -> list[Sequence[ast.stmt]]:
    """The statement blocks a module-level `if` / `try` / `with` runs at module level."""
    if isinstance(n, ast.If):
        return [n.body, n.orelse]
    if isinstance(n, ast.Try):
        return [n.body, n.orelse, n.finalbody, *(h.body for h in n.handlers)]
    if isinstance(n, ast.With):
        return [n.body]
    return []


@functools.cache
def _definition_index() -> Mapping[str, tuple[str, ...]]:
    """name → every non-test module under `defender/` that defines it at module level. One AST
    pass per process; tests never write into the real tree."""
    index: dict[str, list[str]] = {}
    for r in py_files(REPO_ROOT):
        try:
            names = module_level_names((REPO_ROOT / r).read_bytes(), r)
        except (SyntaxError, ValueError) as e:  # a file the locator cannot read is a finding
            raise AssertionError(f"the locator cannot parse {r}: {e}") from e
        for n in names:
            index.setdefault(n, []).append(r)
    return {k: tuple(v) for k, v in index.items()}


def definitions(name: str) -> tuple[str, ...]:
    """Every module (repo-relative, tests excluded) that defines `name` at module level."""
    return _definition_index().get(name, ())


def home_of(name: str, *, home: str | None = None) -> str:
    """The ONE module that defines `name` (optionally inside `home`), repo-relative. Fails with
    an `AssertionError` naming the symbol when it has no such home or more than one (a
    duplicate definition: the one-home rule)."""
    defs = definitions(name)
    cands = [d for d in defs if home is None or under(d, home)]
    where = f" under {home}" if home else ""
    assert cands, f"`{name}` is defined nowhere{where} (definitions: {list(defs) or 'none'})"
    assert len(cands) == 1, f"`{name}` has {len(cands)} homes{where}: {cands}"
    return cands[0]


def moved_module(name: str, *, home: str | None = None) -> ModuleType:
    """The module object of `home_of(name, home=...)`, imported by its dotted name."""
    return importlib.import_module(dotted(home_of(name, home=home)))


def moved(name: str, *, home: str | None = None) -> Any:
    """The moved object itself: `getattr(moved_module(name), name)`."""
    return getattr(moved_module(name, home=home), name)


def query_rule(base_name: str) -> Any:
    """A flat-tier query rule by its base spelling (`json_safe_params`, ...), under the spelling
    `QUERY_RULE_PUBLIC` gives it."""
    return moved(QUERY_RULE_PUBLIC.get(base_name, base_name), home=QUERY_RULES)


def module_at(relpath: str) -> ModuleType:
    """A module at a fixed repo-relative path (a pinned home, or a module that does not move),
    imported by its dotted name. Fails with an `AssertionError` (not a collection error) when
    the file is absent."""
    assert (REPO_ROOT / relpath).is_file(), f"{relpath} does not exist"
    return importlib.import_module(dotted(relpath))


# ======================================================================================
# Goldens
# ======================================================================================


@functools.cache
def golden(name: str) -> Mapping[str, Any]:
    """`goldens/<name>.json`, parsed once. Its `_meta` says what was captured, where, and how."""
    path = GOLDENS / f"{name}.json"
    assert path.is_file(), f"golden {path.name} is missing from the suite"
    # Only the repair command's source address changes; all captured behavior stays pinned.
    text = path.read_text(encoding="utf-8")
    if name in {"runpage", "venv"}:
        text = text.replace("defender/scripts/box_image.py", "defender/box/image_cli.py")
    data: Mapping[str, Any] = json.loads(text)
    return data



def canon(value: Any) -> Any:
    """A JSON-shaped, TYPE-PRESERVING encoding of `value`, the one both sides of a golden
    comparison go through. `True` vs `1`, `1` vs `1.0`, `-0.0` vs `0.0`, NaN, a tuple vs a list,
    dict key order and key type, bytes and sets all survive; anything else is its type name
    plus `repr` (choose inputs whose repr carries no address)."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return {"int": str(value)} if abs(value) > 2**53 else value
    if isinstance(value, float):
        return {"float": "nan" if math.isnan(value) else repr(value)}
    if isinstance(value, tuple):
        return {"tuple": [canon(v) for v in value]}
    if isinstance(value, list):
        return [canon(v) for v in value]
    if isinstance(value, dict):
        return {"dict": [[canon(k), canon(v)] for k, v in value.items()]}
    if isinstance(value, (set, frozenset)):
        return {type(value).__name__: sorted((canon(v) for v in value), key=repr)}
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    if isinstance(value, Path):
        return {"path": value.as_posix()}
    return {"type": type(value).__name__, "repr": repr(value)}


def outcome(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """What calling `fn` does, as a golden-comparable record: `{"returns": canon(value)}`, or
    `{"raises": <class short name>, "message": str(exc)}`. Short class names, because a moved
    class keeps its name while its module path changes."""
    try:
        value = fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return {"raises": type(e).__name__, "message": str(e)}
    return {"returns": canon(value)}


# ======================================================================================
# Child processes (every child is pinned to this checkout)
# ======================================================================================


#: The only keys a child inherits from this process's environment.
_INHERITED = ("PATH", "HOME", "LANG", "LC_ALL", "TZ")


def child_env(*, pythonpath: bool = True, **extra: str) -> dict[str, str]:
    """A minimal environment for a child: the few `_INHERITED` keys, `PYTHONPATH` set to this
    checkout's root when `pythonpath` (never another checkout a developer's shell names), then
    `extra`. `pythonpath=False` is the bare-environment shape (the operator shell)."""
    env = {k: os.environ[k] for k in _INHERITED if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    if pythonpath:
        env["PYTHONPATH"] = str(REPO_ROOT)
    env.update(extra)
    return env


def run(argv: Sequence[str | os.PathLike[str]], *, cwd: Path | str = REPO_ROOT,
        env: Mapping[str, str] | None = None, stdin: bytes | None = None,
        timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
    """`argv` as a child, bytes in and out, never raising on a nonzero status. `cwd` defaults
    to this checkout's root; `env` defaults to `child_env()`."""
    return subprocess.run(  # noqa: S603 — fixed argv built by the test itself
        [os.fspath(a) for a in argv], cwd=os.fspath(cwd), input=stdin, capture_output=True,
        check=False, env=dict(child_env() if env is None else env), timeout=timeout)


def python(*args: str | os.PathLike[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
    """This interpreter as a child: `run([sys.executable, *args], **kw)`."""
    return run([sys.executable, *args], **kw)


def child_outcome(proc: subprocess.CompletedProcess[bytes],
                  norm: Callable[[str], str]) -> dict[str, Any]:
    """A child's verdict: exit status and stdout/stderr through `norm`, a traceback reduced to
    its last line, since its frames name the engine's file and line, which the move changes."""
    err: Any = norm(proc.stderr.decode("utf-8", "replace"))
    if "Traceback (most recent call last):" in err:
        err = {"traceback_last": err.rstrip("\n").splitlines()[-1]}
    return {"rc": proc.returncode, "out": norm(proc.stdout.decode("utf-8", "replace")),
            "err": err}


def run_all(jobs: Mapping[str, Callable[[], Any]]) -> dict[str, Any]:
    """Run independent children four at a time; results keyed as given."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {k: pool.submit(fn) for k, fn in jobs.items()}
        return {k: f.result() for k, f in futures.items()}


# ======================================================================================
# Code copies of this checkout
# ======================================================================================

#: Top-level `defender/` entries a code copy leaves out: the suite, the eval corpora, the docs
#: and the e2e fixtures (no engine imports them), and any lesson corpus.
_COPY_SKIP_TOP = frozenset({"tests", "evals", "docs", "fixtures-e2e", "lessons"})


def copy_defender(root: Path) -> Path:
    """`root/defender`: a copy of this checkout's `defender/` code without `JUNK_DIRS` and
    `_COPY_SKIP_TOP`, walked from the disk, so it holds whatever the tree holds now. Returns
    `root`, the copy's checkout root."""
    src = DEFENDER.resolve()

    def _ignore(d: str, names: list[str]) -> set[str]:
        skip = {n for n in names if n in JUNK_DIRS}
        if Path(d).resolve() == src:
            skip |= {n for n in names if n in _COPY_SKIP_TOP}
        return skip

    shutil.copytree(src, root / "defender", ignore=_ignore, symlinks=True)
    return root


def agent_root(root: Path) -> Path:
    """The agent root beside a code copy at `root` (`root/agent`, shaped like a run copy's
    `agent/`): what `DEFENDER_AGENT_DIR` names for that copy's lessons shim. The code tree holds
    no corpus; the engine reads `$DEFENDER_AGENT_DIR/lessons` (#1108)."""
    return root / "agent"


def venv_home() -> Path:
    """The venv running this suite — what a linked worktree's `.venv` points at."""
    return Path(sys.executable).parents[1]


# ======================================================================================
# The box image's import closure: core dependencies plus the `box` extra, read through the
# lock the way the image is built
# ======================================================================================


@functools.lru_cache(maxsize=1)
def box_import_allowlist() -> tuple[str, ...]:
    """The top-level import names a box process may load: the standard library (implicit in
    `_import_blocker`'s `allow_only`), `defender`, `__main__`, `_virtualenv` (this venv's
    start-up hook, which no box has), and every import name of the distributions the image
    installs (`box._image.box_closure(uv.lock, "defender")`, the image build's own walk), mapped
    through the installed distributions' metadata. Not whatever the host venv carries."""
    from defender.box import _image

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    dists = {_image.normalized_name(e["name"]) for e in _image.box_closure(lock, "defender")}
    tops = {top for top, ds in importlib.metadata.packages_distributions().items()
            if any(_image.normalized_name(d) in dists for d in ds)}
    # A top-level EXTENSION module (`_duckdb.cpython-311-x86_64-linux-gnu.so`) is misnamed by
    # `packages_distributions()` (it strips only the last suffix); without it duckdb cannot load.
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        if not name or _image.normalized_name(name) not in dists:
            continue
        for f in dist.files or ():
            if len(f.parts) == 1 and f.name.endswith((".so", ".pyd")) \
                    and f.name.split(".")[0].isidentifier():
                tops.add(f.name.split(".")[0])
    assert {"duckdb", "yaml", "pydantic"} <= tops, (
        f"the derived box closure lost a package the image installs: {sorted(tops)}")
    # The interpreter's own build-data module (`_sysconfigdata_*`, reached through
    # sysconfig) ships with every CPython but is absent from `sys.stdlib_module_names`.
    import sysconfig

    build_data = sysconfig._get_sysconfigdata_name()  # noqa: SLF001 — CPython's own name
    return tuple(sorted(tops | {"defender", "__main__", "_virtualenv", build_data}))


#: Packages a box process must never load: the agent framework, the model providers and the
#: MCP stack. Checked against `sys.modules` in the child as well as refused.
BOX_BLOCKED = ("pydantic_ai", "anthropic", "openai", "mcp", "fastmcp", "logfire", "httpx",
               "fastapi", "uvicorn", "toons")


# ======================================================================================
# Small AST readers shared across files
# ======================================================================================


@dataclass(frozen=True)
class ImportStmt:
    """One import statement, resolved: the file, the line, the module it names (relative
    forms resolved against the importer's package), the names it binds from it (empty for
    `import x`), and whether it sits at module level."""

    path: str
    line: int
    module: str
    names: tuple[str, ...]
    top_level: bool


def import_statements(relpath: str, source: bytes | str) -> Iterator[ImportStmt]:
    """Every `import` / `from … import` in a module, wherever it sits (module level, function
    body, `try`, `if TYPE_CHECKING:`), relative forms resolved against the importer's package.
    Raises `SyntaxError` / `ValueError` for a file that cannot be parsed — the caller decides
    (a census must name it, never skip it)."""
    tree = ast.parse(source, filename=relpath)
    pkg = dotted(relpath).split(".")
    if not relpath.endswith("__init__.py"):
        pkg = pkg[:-1]
    module_level = {id(n) for n in tree.body}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield ImportStmt(relpath, node.lineno, a.name, (), id(node) in module_level)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                mod = ".".join([*base, node.module] if node.module else base)
            else:
                mod = node.module or ""
            yield ImportStmt(relpath, node.lineno, mod, tuple(a.name for a in node.names),
                             id(node) in module_level)


def has_main_block(source: bytes | str) -> bool:
    """Whether a module carries an `if __name__ == "__main__":` block at module level."""
    for n in ast.parse(source).body:
        if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) \
                and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__" \
                and any(isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in n.test.comparators):
            return True
    return False


def shim_exec_module(shim: str) -> str:
    """The dotted module a `bin/` shim runs, read off its `exec "$PY" -P -m <module>` line (each
    shim puts its own checkout root first on `PYTHONPATH` and runs its engine as a module).
    Fails when the shim names no such line."""
    text = (BIN / shim).read_text(encoding="utf-8")
    for line in text.splitlines():
        toks = [t.strip('"') for t in line.split()]
        if "exec" in toks and "-m" in toks:
            return toks[toks.index("-m") + 1]
    raise AssertionError(f"bin/{shim} names no `exec ... -m <module>` line")


def shim_exec_target(shim: str) -> Path:
    """The engine's source file the module a `bin/` shim runs resolves to in this checkout."""
    return REPO_ROOT / (shim_exec_module(shim).replace(".", "/") + ".py")


