"""The production-code censuses #1107 pins, each as ONE scanner function over a ROOT.

A root is a repo-shaped tree (`<root>/defender/...`): the checkout (`REPO_ROOT`) for the
negative, or a tmp tree holding a planted module for the positive control. Sharing one function
between the two is what makes the control prove the observation channel — a scanner that saw
nothing would be green on the real tree and red on the plant. Every scanner returns
`(files_scanned, findings)`, the count being the negative's own precondition (a census over zero
files is green for any implementation).

  * `elastic_key_reads`  (d4, F12)     — a read of an `ELASTIC_*` / `ELASTICSEARCH_URL` key's VALUE
    out of a mapping (a `SystemConfig`, a parsed config file, an env) in runtime/, learning/ or
    run.py, outside the module that defines `ElasticSettings` (the view).
  * `settings_copies`    (S3)          — a copy / link / byte-transfer whose SOURCE derives from a
    tenant's `settings` folder (`RunTenant.settings`, a `settings_dir`, a `settings/` path).
  * `settings_dir_hits`  (F7)          — every `settings_dir` identifier outside F7's allow-list.
  * `helper_location_lookups` (N3)     — `process_defender_dir()` / `run_env()` calls and
    `DEFENDER_DIR` / `DEFENDER_RUN_DIR` lookups in the four swept trees, outside a module-level
    `def main`.
  * `soc_playground_reads` (D2)        — a lookup of a `SOC_PLAYGROUND_*` name in any mapping.
  * `doc_env_teaching`   (MF-14)       — model-facing doc lines that teach environment overrides of
    config, `SOC_PLAYGROUND_*` settings, environment-variable secrets or the `_ENV` suffix, or a
    hard-coded host-state context.

GREP FLOORS, recorded rather than hidden:
* Key resolution is NAME-LEVEL per file: a string constant, a name bound anywhere in the file to a
  constant or a literal collection of constants, an element of such a collection
  (`_KEYS[verb]`), or a loop / comprehension variable iterating one. A key reaching a lookup
  through another module, a function return or string building is below the floor.
* The copy census taints through assignments by name within one file and through `/`,
  `Path(...)` and method calls on a tainted value; a path handed in from another module is not
  traced.
* The doc census is line-oriented, reading on into the next line only where a sentence does; a
  sentence spread over three lines, or phrased without the trigger words, is below it. A line
  whose trigger is negated (`not`, `never`, `no longer`, `cannot` within four words before it) or
  that describes the new convention (`_SECRET_REF`, `secrets.env`) is not a finding — that is
  what keeps the rewritten docs, and the listed homonyms, out of it.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import ast
import functools
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

_SKIP_PARTS = {".venv", "__pycache__", "node_modules", "tests"}

#: O7's four swept trees (C5, the design's O7 sentence), repo-relative: adapters, estate with
#: staging.py, case-history, and `runtime/lead_zero*` (the package and lead_zero_config.py).
#: The case-history tree is two entries since #1190 moved the case-mapping module out of it to
#: `defender/runtime/case_ticket.py`; the write-back (`ticket_writer`) stays in the folder.
#: `lint_tenant_env_reads.SWEPT` lists the same entries (#1190's env-read test holds them equal).
SWEPT: tuple[str, ...] = (
    "defender/scripts/adapters/",
    "defender/learning/branch/estate/",
    "defender/learning/branch/staging.py",
    "defender/scripts/case_history/",
    "defender/runtime/case_ticket.py",
    "defender/runtime/lead_zero/",
    "defender/runtime/lead_zero_config.py",
)

#: F7 (auto)'s allow-list for `settings_dir`: the resolver and its components, and the folder
#: validator reading the folder it validates. `query_tool._model_visible` (the path-namer) is
#: allowed by function, below.
SETTINGS_DIR_ALLOWED_FILES: frozenset[str] = frozenset({
    "defender/runtime/run_tenant.py",
    "defender/_tenants.py",
    "defender/runtime/verb_dispositions.py",
    "defender/runtime/lead_zero_config.py",
    "defender/skills/connect/validate_scaffold.py",
})
SETTINGS_DIR_ALLOWED_FUNCS: frozenset[tuple[str, str]] = frozenset({
    ("defender/runtime/query_tool.py", "_model_visible"),
})

#: G34's eight model-facing files (MF-14, human), repo-relative.
MODEL_DOCS: tuple[str, ...] = (
    "defender/skills/cmdb/execution.md",
    "defender/skills/identity/execution.md",
    "defender/skills/host-state/execution.md",
    "defender/scripts/adapters/README.md",
    "defender/skills/connect/SKILL.md",
    "defender/skills/connect/decisions.md",
    "defender/skills/connect/checklist.md",
    "defender/skills/connect/adapter.md",
)

#: G34's domain homonyms of "override" — lines that stay (they are not about the environment).
HOMONYM_DOCS: tuple[str, ...] = (
    "defender/skills/identity/SKILL.md",
    "defender/skills/cmdb/SKILL.md",
    "defender/skills/elastic/execution.md",
    "defender/skills/gather/queries/identity/user-authorization.md",
    "defender/skills/connect/SKILL.md",
    "defender/skills/tacit-knowledge/execution.md",
)

_ELASTIC_KEY = re.compile(r"^(ELASTICSEARCH_URL|ELASTIC_[A-Z0-9_]+)$")
_LOCATION_KEYS = frozenset({"DEFENDER_DIR", "DEFENDER_RUN_DIR"})
_LOOKUP_METHODS = frozenset({"get", "pop", "setdefault", "__getitem__", "__contains__"})


# ======================================================================================
# The file sets.
# ======================================================================================

def _py_below(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix == ".py" else []
    if not path.is_dir():
        return []
    out = []
    for p in sorted(path.rglob("*.py")):
        rel = p.relative_to(path)
        if _SKIP_PARTS & set(rel.parts) or p.name.startswith("test_") or p.name == "conftest.py":
            continue
        out.append(p)
    return out


def production_py(root: Path, *, under: Iterable[str] = ("defender",)) -> list[Path]:
    """Non-test Python files below each of `under` (repo-relative) in `root`."""
    out: list[Path] = []
    for rel in under:
        out += _py_below(Path(root) / rel)
    return sorted(set(out))


def swept_py(root: Path) -> list[Path]:
    return production_py(root, under=SWEPT)


def platform_py(root: Path) -> list[Path]:
    """d4's scope: runtime/, learning/ and run.py (the platform), non-test."""
    return production_py(root, under=("defender/runtime", "defender/learning", "defender/run.py"))


def _rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(Path(root).resolve()).as_posix()


@functools.cache
def _parse_at(path: Path, stamp: tuple[int, int]) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))


def _parse(path: Path) -> ast.Module:
    """The parsed module, once per process and file state: the censuses all walk the same
    production files, and nothing here mutates a tree."""
    st = path.stat()
    return _parse_at(path, (st.st_mtime_ns, st.st_size))


# ======================================================================================
# Name-level constant resolution (the floor is in the module docstring).
# ======================================================================================

def _const_bindings(tree: ast.AST) -> dict[str, set[str]]:  # noqa: C901 — one flat dispatch over the binding shapes, read top to bottom
    """name -> the string constants it may hold: assignments of a constant or a literal
    collection of constants, and loop / comprehension targets iterating one."""
    binds: dict[str, set[str]] = {}

    def strings(node: ast.AST | None) -> set[str]:
        if node is None:
            return set()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return set().union(*(strings(e) for e in node.elts)) if node.elts else set()
        if isinstance(node, ast.Dict):
            return set().union(*(strings(v) for v in node.values)) if node.values else set()
        if isinstance(node, ast.Name):
            return set(binds.get(node.id, set()))
        return set()

    for _ in range(3):  # a short fixpoint: aliases of aliases
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                got = strings(node.value)
                if got:
                    for t in targets:
                        if isinstance(t, ast.Name):
                            binds.setdefault(t.id, set()).update(got)
            elif isinstance(node, (ast.For, ast.comprehension)):
                got = strings(node.iter)
                if got and isinstance(node.target, ast.Name):
                    binds.setdefault(node.target.id, set()).update(got)
    return binds


def _key_strings(node: ast.AST, binds: dict[str, set[str]]) -> set[str]:
    """The string keys `node`, used as a lookup key, may carry."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        return set(binds.get(node.id, set()))
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return set(binds.get(node.value.id, set()))
    return set()


def _lookups(tree: ast.AST, binds: dict[str, set[str]]) -> Iterator[tuple[ast.AST, set[str]]]:
    """Every lookup site and the keys it may read: `m[k]`, `m.get(k)` (and pop/setdefault),
    `os.getenv(k)` / `getenv(k)`, `k in m`."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            keys = _key_strings(node.slice, binds)
            if keys:
                yield node, keys
        elif isinstance(node, ast.Call) and node.args:
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if name in _LOOKUP_METHODS or name == "getenv":
                keys = _key_strings(node.args[0], binds)
                if keys:
                    yield node, keys
        elif isinstance(node, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn))
                                                   for o in node.ops):
            keys = _key_strings(node.left, binds)
            if keys:
                yield node, keys


def _outside_main(tree: ast.Module) -> Iterator[ast.AST]:
    """Every node of `tree` except those inside a MODULE-LEVEL `def main` (NF-7's exemption)."""
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == "main":
            continue
        yield from ast.walk(stmt)


# ======================================================================================
# d4 — Elastic keys interpreted only through the view (F12).
# ======================================================================================

def _defines(tree: ast.AST, cls: str) -> bool:
    return any(isinstance(n, ast.ClassDef) and n.name == cls for n in ast.walk(tree))


def elastic_key_reads(root: Path) -> tuple[int, list[str]]:
    files = platform_py(root)
    found: list[str] = []
    for path in files:
        tree = _parse(path)
        if _defines(tree, "ElasticSettings"):
            continue  # the view: the one place platform code interprets the keys (D4)
        binds = _const_bindings(tree)
        for node, keys in _lookups(tree, binds):
            hits = sorted(k for k in keys if _ELASTIC_KEY.match(k))
            if hits:
                found.append(f"{_rel(path, root)}:{node.lineno}: reads {', '.join(hits)}")
    return len(files), sorted(set(found))


# ======================================================================================
# S3 — nothing copies a file (or its bytes) out of a tenant's settings folder.
# ======================================================================================

_SETTINGS_ATTRS = frozenset({"settings", "settings_dir"})
_COPY_CALLS = frozenset({"copy", "copy2", "copyfile", "copytree", "copyfileobj", "move", "link"})
_LINK_METHODS = frozenset({"symlink_to", "hardlink_to"})


def _tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Attribute):
        return node.attr in _SETTINGS_ATTRS or _tainted(node.value, tainted)
    if isinstance(node, ast.Name):
        return node.id == "settings_dir" or node.id in tainted
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        v = node.value
        return "/settings/" in v or v.startswith("settings/") or v == "settings"
    if isinstance(node, ast.BinOp):
        return _tainted(node.left, tainted) or _tainted(node.right, tainted)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and _tainted(node.func.value, tainted):
            return True
        return any(_tainted(a, tainted) for a in node.args)
    if isinstance(node, ast.JoinedStr):
        return any(_tainted(v, tainted) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _tainted(node.value, tainted)
    return False


def _taint_names(tree: ast.AST) -> set[str]:
    tainted: set[str] = set()
    for _ in range(4):
        for node in ast.walk(tree):
            if (isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
                    and _tainted(node.value, tainted)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                tainted |= {t.id for t in targets if isinstance(t, ast.Name)}
    return tainted


def settings_copies(root: Path) -> tuple[int, list[str]]:
    files = production_py(root)
    found: list[str] = []
    for path in files:
        tree = _parse(path)
        tainted = _taint_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            src: ast.AST | None = None
            if (name in _COPY_CALLS or name in _LINK_METHODS) and node.args:
                src = node.args[0]
            elif name in ("write_bytes", "write_text") and node.args:
                arg = node.args[0]
                if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                        and arg.func.attr in ("read_bytes", "read_text")):  # lint-ast-resolve: ok — a Path METHOD on any receiver; no import origin to resolve
                    src = arg.func.value
            if src is not None and _tainted(src, tainted):
                found.append(f"{_rel(path, root)}:{node.lineno}: {name}() from a settings path")
    return len(files), sorted(set(found))


# ======================================================================================
# F7 — `settings_dir` survives only on the resolver, its components, and the path-namers.
# ======================================================================================

def _func_spans(tree: ast.Module) -> list[tuple[str, int, int]]:
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.name, node.lineno, node.end_lineno or node.lineno))
    return spans


def settings_dir_hits(root: Path) -> tuple[int, list[str]]:
    files = production_py(root)
    found: list[str] = []
    for path in files:
        rel = _rel(path, root)
        if rel in SETTINGS_DIR_ALLOWED_FILES:
            continue
        tree = _parse(path)
        allowed_spans = [(a, b) for (n, a, b) in _func_spans(tree)
                         if (rel, n) in SETTINGS_DIR_ALLOWED_FUNCS]
        for node in ast.walk(tree):
            hit = ((isinstance(node, ast.Name) and node.id == "settings_dir")
                   or (isinstance(node, ast.Attribute) and node.attr == "settings_dir")
                   or (isinstance(node, ast.arg) and node.arg == "settings_dir")
                   or (isinstance(node, ast.keyword) and node.arg == "settings_dir"))
            if not hit:
                continue
            line = getattr(node, "lineno", 0)
            if any(a <= line <= b for a, b in allowed_spans):
                continue
            found.append(f"{rel}:{line}: settings_dir")
    return len(files), sorted(set(found))


# ======================================================================================
# N3 — no helper location/env lookups in the swept trees, outside a module-level main.
# ======================================================================================

def helper_location_lookups(root: Path) -> tuple[int, list[str]]:
    files = swept_py(root)
    found: list[str] = []
    for path in files:
        tree = _parse(path)
        binds = _const_bindings(tree)
        kept = {id(n) for n in _outside_main(tree)}
        rel = _rel(path, root)
        for node in ast.walk(tree):
            if id(node) not in kept:
                continue
            if isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
                if name in ("process_defender_dir", "run_env"):
                    found.append(f"{rel}:{node.lineno}: calls {name}()")
        for node, keys in _lookups(tree, binds):
            if id(node) in kept and keys & _LOCATION_KEYS:
                found.append(f"{rel}:{node.lineno}: looks up {', '.join(sorted(keys & _LOCATION_KEYS))}")
    return len(files), sorted(set(found))


# ======================================================================================
# D2 — no SOC_PLAYGROUND_* name is read from any environment.
# ======================================================================================

def soc_playground_reads(root: Path) -> tuple[int, list[str]]:
    files = production_py(root)
    found: list[str] = []
    for path in files:
        tree = _parse(path)
        binds = _const_bindings(tree)
        for node, keys in _lookups(tree, binds):
            hits = sorted(k for k in keys if k.startswith("SOC_PLAYGROUND_"))
            if hits:
                found.append(f"{_rel(path, root)}:{node.lineno}: reads {', '.join(hits)}")
    return len(files), sorted(set(found))


# ======================================================================================
# MF-14 — model-facing docs teach no environment override, no env-var secret.
# ======================================================================================

#: A negation governing the trigger: `not`/`never`/`no`/`no longer`/`cannot` within four words
#: before an environment / override / export / hard-coded word ("no environment variable to
#: resolve", "can no longer be overridden"). A negation elsewhere on the line ("Names, not
#: values") does not exempt it.
_NEGATED = re.compile(
    r"\b(?:no|not|never|cannot|can't|nor)\b(?:\W+[\w'-]+){0,4}?\W+"
    r"(?:(?<![.\w])env\b|environment|overrid|export|hard-?coded|SOC_PLAYGROUND_|_ENV\b)", re.I)
_NEW_CONVENTION = re.compile(r"_SECRET_REF|secrets\.env")
_OVERRIDE = re.compile(r"overrid\w*|takes precedence|wins over", re.I)
#: `env` as a word, not the `.env` of a file name (`config.env`, `secrets.env`).
_ENV_WORD = re.compile(r"(?<![.\w])env(ironment)?\b|\bexport(ed|ing|s)?\b", re.I)
_ENV_VAR = re.compile(r"(?<![.\w])env(ironment)? var(iable)?s?\b|\bin (the |an )?environment\b",
                      re.I)
_SECRET_WORD = re.compile(
    r"\b(secrets?|credentials?|tokens?|passwords?|api[_ -]?keys?)\b|\bmust set\b|\bto set\b"
    r"|\bhold(s)? the\b", re.I)
_ENV_SUFFIX = re.compile(r"\b[A-Z][A-Z0-9_]*_ENV\b|`_ENV`|\b_ENV\b")
_HARDCODED = re.compile(r"hard-?coded", re.I)


def _doc_findings(rel: str, lines: list[str]) -> list[str]:
    found: list[str] = []
    for i, line in enumerate(lines):
        # The next line counts only when this one runs on into it (no sentence end here).
        runs_on = not line.rstrip().endswith((".", "!", "?", ":", ".**", "`."))
        nxt = lines[i + 1] if runs_on and i + 1 < len(lines) else ""
        window = f"{line} {nxt}"
        if _NEGATED.search(line) or _NEW_CONVENTION.search(line):
            continue
        why = None
        if "SOC_PLAYGROUND_" in line:
            why = "names a SOC_PLAYGROUND_* variable"
        elif _ENV_SUFFIX.search(line):
            why = "teaches the _ENV suffix"
        elif _OVERRIDE.search(line) and _ENV_WORD.search(window):
            why = "says a config key can be overridden by the environment"
        elif _ENV_VAR.search(line) and _SECRET_WORD.search(window) or _SECRET_WORD.search(line) and _ENV_VAR.search(nxt) and not _NEGATED.search(nxt):
            why = "teaches environment-variable secrets"
        elif _HARDCODED.search(line) and "context" in (lines[i - 1] if i else "") + line:
            why = "says the docker context is hard-coded"
        if why:
            found.append(f"{rel}:{i + 1}: {why}")
    return found


def doc_env_teaching(root: Path, docs: Iterable[str] = MODEL_DOCS) -> tuple[int, list[str]]:
    """`(files read, findings)` over `docs` (repo-relative) under `root`; a missing file is not
    counted as read."""
    read = 0
    found: list[str] = []
    for rel in docs:
        path = Path(root) / rel
        if not path.is_file():
            continue
        read += 1
        found += _doc_findings(rel, path.read_text(encoding="utf-8").splitlines())
    return read, sorted(set(found))
