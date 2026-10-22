"""O4 — one owner of the knowledge layout, by symbol (#1108 P4).

A symbol-resolved census, not a spelling grep (P4-C2 was lexical; the design owes this one).
Every reference in production source is resolved through `tooling/lint/_astlib.py`'s scope
tree (imports, `import ... as`, from-imports, attribute chains, function-local imports) and
then through `reexport_origin` (a re-export through a package door lands on its definition).
A reference that resolves to a banned layout symbol is a hit, wherever it sits, unless the
allowlist below names its module and the symbol, with a reason.

What the resolver cannot reach — an attribute on a value (`paths.lessons_dir` where `paths` is
a parameter) — is closed structurally instead: the accessor does not exist on `DefenderPaths`,
so no receiver can reach it (`test_defender_paths_carries_no_corpus_accessor`).
"""
from __future__ import annotations

import ast
import dataclasses
import importlib
from collections.abc import Iterator
from pathlib import Path

from defender.tests.support.shared.contracts._by_path import DEFENDER, WORKTREE, import_lint_lib

_astlib = import_lint_lib("_astlib")

_K = "defender.knowledge._knowledge"
_P = "defender._paths"

#: The corpus accessors `DefenderPaths` carried as pass-throughs to the knowledge layout
#: (`_paths.py:66-110` at base). Banned on `PATHS`, on the class, and (structurally) absent.
CORPUS_ACCESSORS = (
    "knowledge", "lessons_dir", "lessons_questioner_dir", "catalog_dir", "skills_dir",
    "catalog_rel", "skills_rel", "lessons_dir_rel", "lessons_questioner_dir_rel",
)

#: The banned symbols (O4's list). A reference resolving to one of these, or to an attribute
#: chain below one, is a hit.
BANNED: dict[str, str] = {
    f"{_K}.CHECKOUT_KNOWLEDGE": "the product tree's knowledge (CHECKOUT_KNOWLEDGE)",
    f"{_K}.KnowledgePaths.of_defender_dir": "knowledge rooted in a code tree (of_defender_dir)",
    **{f"{_P}.PATHS.{a}": f"PATHS.{a}" for a in CORPUS_ACCESSORS},
    **{f"{_P}.DefenderPaths.{a}": f"DefenderPaths.{a}" for a in CORPUS_ACCESSORS},
    # The import-time corpus constants O4 names, by their defining module (P4-C2's sites).
    "defender.runtime.lessons_engine.lessons_fm.LESSONS_DIR": "lessons_fm.LESSONS_DIR",
    "defender.runtime.lessons_engine.lessons_frontier.DEFAULT_CORPUS": "lessons_frontier.DEFAULT_CORPUS",
    "defender.hooks.inject_system_skill_description.SKILLS_DIR": "inject_system_skill_description.SKILLS_DIR",
    "defender.runtime.query_catalog._SKILLS_REL": "query_catalog._SKILLS_REL",
    "defender.learning.leads.path_validation.CATALOG_DIR": "path_validation.CATALOG_DIR",
    "defender.learning.leads.path_validation.CATALOG_REL": "path_validation.CATALOG_REL",
    "defender.learning.leads.path_validation.SKILLS_DIR": "path_validation.SKILLS_DIR",
    "defender.learning.leads.path_validation.SKILLS_REL": "path_validation.SKILLS_REL",
    "defender.learning.leads.declared_systems.SKILLS_REL": "declared_systems.SKILLS_REL",
    "defender.cli.learning.revert_lesson.LESSONS_REL": "revert_lesson.LESSONS_REL",
    "defender.cli.learning.trace_lesson.LESSONS_DIR": "trace_lesson.LESSONS_DIR",
    "defender.presentation.visualize_runtime._LESSONS_PATHSPEC": "visualize_runtime._LESSONS_PATHSPEC",
}

#: The layout's corpus names: joined onto a root at import time they make a constant the
#: design says becomes a function of an agent root.
LAYOUT_NAMES = frozenset({f"{_K}.{n}" for n in (
    "LESSONS", "LESSONS_QUESTIONER", "SKILLS", "CATALOG", "LESSONS_ACTOR", "LESSONS_ENVIRONMENT")})
#: The same names spelled as literals: a first path component that is a corpus, or the
#: catalog's path under the agent root. (`"skills"` alone is not one: `skills/invlang` is a
#: product skill and `orient.py` joins it legitimately.)
_CORPUS_HEADS = frozenset({"lessons", "lessons-questioner", "lessons-actor", "lessons-environment"})
KNOWLEDGE_PATHS = f"{_K}.KnowledgePaths"

ALL = frozenset(BANNED) | {KNOWLEDGE_PATHS, "<import-time join>"}

#: Modules allowed to reference banned symbols — `{module path under the repo: (symbols, kinds,
#: reason)}`. Nothing else: `_paths.py` is deliberately a red site (its accessors go).
ALLOWLIST: dict[str, tuple[frozenset[str], frozenset[str], str]] = {
    "defender/knowledge/_knowledge.py": (
        ALL, frozenset({"ref", "import", "join"}),
        "KnowledgePaths' own module: the one owner of the layout (O4)"),
    "defender/knowledge/__init__.py": (
        ALL, frozenset({"import"}),
        "the owner package's door may re-export; a re-export binding reads nothing, and every "
        "reader through the door resolves to the definition and is judged where it reads"),
}
#: The judge's pre-move branch (O6): a run whose code commit's tree has
#: `defender/lessons/<name>.md` is read from the product repo at that commit, through
#: `CHECKOUT_KNOWLEDGE` — the one place the design keeps it (`KnowledgePaths` data model).
JUDGE_PACKAGE = "defender/learning/judge/"
JUDGE_SYMBOLS = frozenset({f"{_K}.CHECKOUT_KNOWLEDGE"})


@dataclasses.dataclass(frozen=True)
class Hit:
    path: str
    line: int
    symbol: str
    kind: str  # "ref" | "import" | "join" | "construct"

    def __str__(self) -> str:
        return f"{self.path}:{self.line} {self.kind} {BANNED.get(self.symbol, self.symbol)}"


def _matches(origin: str) -> str | None:
    for symbol in BANNED:
        if origin == symbol or origin.startswith(symbol + "."):
            return symbol
    return None


def _module_level_nodes(tree: ast.Module) -> Iterator[ast.AST]:
    """Every node evaluated at import time: the module body and class bodies, decorators and
    default values, never a function's or lambda's body."""
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(node.decorator_list)
            stack.extend(d for d in (*node.args.defaults, *node.args.kw_defaults) if d is not None)
            continue
        if isinstance(node, ast.Lambda):
            stack.extend(d for d in (*node.args.defaults, *node.args.kw_defaults) if d is not None)
            continue
        stack.extend(ast.iter_child_nodes(node))


class Census:
    """Resolve references in one source tree. `roots` are the folders the `defender` package
    is found in, for re-export following (a planted tree first, the worktree's after)."""

    def __init__(self, roots: tuple[Path, ...] = (DEFENDER,)) -> None:
        self.roots = roots
        self.cache: dict[str, dict[str, str]] = {}

    def canonical(self, origin: str) -> str:
        return _astlib.reexport_origin(origin, self.roots, self.cache)

    def _layout_operand(self, node: ast.expr, env) -> bool:  # noqa: ANN001 — _astlib.ModuleEnv
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            head = node.value.strip("/").split("/")[0]
            return head in _CORPUS_HEADS or node.value.strip("/").startswith("skills/gather/queries")
        if isinstance(node, (ast.Name, ast.Attribute)):
            origin = _astlib.origin(node, env)
            return origin is not None and self.canonical(origin) in LAYOUT_NAMES
        return False

    def _references(self, rel: str, tree: ast.Module, env, package: str) -> Iterator[Hit]:  # noqa: ANN001 — _astlib.ModuleEnv
        """Import bindings and Name/Attribute chains resolving to a banned symbol."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                source = _astlib.import_source(node, package)
                for alias in node.names:
                    symbol = _matches(self.canonical(f"{source}.{alias.name}"))
                    if symbol:
                        yield Hit(rel, node.lineno, symbol, "import")
            elif isinstance(node, (ast.Name, ast.Attribute)):
                origin = _astlib.origin(node, env)
                symbol = _matches(self.canonical(origin)) if origin else None
                if symbol:
                    yield Hit(rel, node.lineno, symbol, "ref")

    def _import_time(self, rel: str, tree: ast.Module, env) -> Iterator[Hit]:  # noqa: ANN001 — _astlib.ModuleEnv
        """Corpus joins and `KnowledgePaths` constructions evaluated at import time."""
        for node in _module_level_nodes(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                if self._layout_operand(node.left, env) or self._layout_operand(node.right, env):
                    yield Hit(rel, node.lineno, "<import-time join>", "join")
            elif isinstance(node, ast.Call):
                callee = _astlib.callee(node, env)
                joined = callee in {"os.path.join", "posixpath.join"} or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "joinpath")  # lint-ast-resolve: ok — `Path.joinpath` on a value; the resolver answers None for a value receiver, so the verb is matched by name
                if joined and any(self._layout_operand(a, env) for a in node.args):
                    yield Hit(rel, node.lineno, "<import-time join>", "join")
                if callee is not None and self.canonical(callee) == KNOWLEDGE_PATHS:
                    yield Hit(rel, node.lineno, KNOWLEDGE_PATHS, "construct")

    def scan(self, rel: str, tree: ast.Module, module: str, package: str) -> list[Hit]:
        env = _astlib.module_env(tree, module=module, package=package)
        hits = {*self._references(rel, tree, env, package), *self._import_time(rel, tree, env)}
        # One line, one symbol: an attribute chain resolves at every prefix.
        seen: set[tuple[str, int, str]] = set()
        out = []
        for hit in sorted(hits, key=lambda h: (h.line, h.kind != "import", h.symbol, h.kind)):
            key = (hit.path, hit.line, hit.symbol)
            if key not in seen:
                seen.add(key)
                out.append(hit)
        return out


def _allowed(hit: Hit) -> bool:
    entry = ALLOWLIST.get(hit.path)
    if entry is not None and hit.symbol in entry[0] and hit.kind in entry[1]:
        return True
    return hit.path.startswith(JUDGE_PACKAGE) and hit.symbol in JUDGE_SYMBOLS


#: Production source: the whole `defender/` package (hooks and cli included — the design's
#: list names both) except tests, and the evals harness at the repo root.
_EXCLUDED = (".venv", "__pycache__", "node_modules", "tests", "docs")
_TREES = (("defender", DEFENDER), ("evaluations", WORKTREE / "evaluations"))


def production_hits() -> list[Hit]:
    census = Census()
    hits: list[Hit] = []
    for package_root, folder in _TREES:
        for rel in _astlib.source_files(folder, _EXCLUDED):
            _text, tree = _astlib.read_and_parse(folder / rel, rel)
            module, package = _astlib.module_and_package(rel, root=package_root)
            with _astlib.scan_guard(rel):
                hits.extend(census.scan(f"{package_root}/{rel}", tree, module, package))
    return hits


def test_no_production_module_outside_the_owner_reaches_the_product_layout():
    """O4: outside `KnowledgePaths`' module (and `CHECKOUT_KNOWLEDGE` in the judge's pre-move
    branch), no production module references `CHECKOUT_KNOWLEDGE`, `of_defender_dir`,
    `PATHS`/`DefenderPaths` corpus accessors or an import-time corpus constant, and no module
    joins a corpus name onto a root at import time or builds a `KnowledgePaths` at import
    time. Resolved by symbol: an aliased import or a door re-export is the same symbol."""
    hits = [str(h) for h in production_hits() if not _allowed(h)]
    assert hits == [], (
        f"{len(hits)} production reference(s) to the product-tree knowledge layout; each "
        "takes an agent root (`KnowledgePaths(agent_root)`) instead:\n  " + "\n  ".join(hits))


# --- positive controls over synthetic modules, through the same classifier -------------------

def _scan_synthetic(source: str, rel: str = "defender/runtime/planted.py",
                    roots: tuple[Path, ...] = (DEFENDER,)) -> list[Hit]:
    tree = _astlib.parse_source(source, rel)
    module, package = _astlib.module_and_package(rel.removeprefix("defender/"))
    return Census(roots).scan(rel, tree, module, package)


def _symbols(hits: list[Hit]) -> set[tuple[int, str, str]]:
    return {(h.line, h.symbol, h.kind) for h in hits}


def test_the_resolver_catches_aliased_imports_attribute_chains_and_door_reexports(tmp_path):
    """O4 positive control: the census flags an aliased class method, a module alias reaching
    `PATHS.<accessor>`, a function-local import, an attribute chain below a banned symbol, a
    from-import of an import-time constant, and a renamed re-export through a package door —
    each is the banned symbol under another spelling."""
    door = tmp_path / "defender" / "door"
    door.mkdir(parents=True)
    (door / "__init__.py").write_text(
        "from defender.knowledge._knowledge import CHECKOUT_KNOWLEDGE as CK\n", encoding="utf-8")
    hits = _scan_synthetic(roots=(tmp_path / "defender", DEFENDER), source=
        "from defender.knowledge._knowledge import KnowledgePaths as KP\n"     # 1 (class: not banned)
        "import defender._paths as pp\n"                                       # 2
        "from defender.runtime.lessons_engine import lessons_fm as fm\n"       # 3
        "def a(x):\n"                                                          # 4
        "    return KP.of_defender_dir(x).lessons_dir\n"                       # 5
        "def b():\n"                                                           # 6
        "    return pp.PATHS.catalog_dir / 'cmdb'\n"                           # 7
        "def c():\n"                                                           # 8
        "    from defender._paths import DefenderPaths as D\n"                 # 9
        "    return D.skills_rel\n"                                            # 10
        "def d():\n"                                                           # 11
        "    return fm.LESSONS_DIR.glob('*.md')\n"                             # 12
        "def e():\n"                                                           # 13
        "    from defender.door import CK as ck\n"                              # 14
        "    return ck.rel('lessons')\n"                                       # 15
    )
    got = _symbols(hits)
    assert (5, f"{_K}.KnowledgePaths.of_defender_dir", "ref") in got, hits
    assert (7, f"{_P}.PATHS.catalog_dir", "ref") in got, hits
    assert (10, f"{_P}.DefenderPaths.skills_rel", "ref") in got, hits
    assert (12, "defender.runtime.lessons_engine.lessons_fm.LESSONS_DIR", "ref") in got, hits
    assert (14, f"{_K}.CHECKOUT_KNOWLEDGE", "import") in got, hits
    assert (15, f"{_K}.CHECKOUT_KNOWLEDGE", "ref") in got, hits


def test_the_census_catches_import_time_corpus_joins_but_not_call_time_ones():
    """O4: a corpus name joined onto a root at import time (by the layout's own constant or as
    a literal, by `/`, `joinpath` or `os.path.join`, or in a default argument), and a
    `KnowledgePaths` built at import time, are hits; the same join inside a function body —
    a function of an agent root — is not."""
    hits = _scan_synthetic(
        "import os\n"                                                          # 1
        "from pathlib import Path\n"                                           # 2
        "from defender.knowledge._knowledge import LESSONS as L, KnowledgePaths\n"  # 3
        "ROOT = Path(os.environ.get('X', '/'))\n"                              # 4
        "A = ROOT / L\n"                                                       # 5
        "B = ROOT / 'lessons-questioner'\n"                                    # 6
        "C = os.path.join(str(ROOT), 'skills/gather/queries')\n"               # 7
        "D = ROOT.joinpath('lessons', 'x.md')\n"                               # 8
        "def f(corpus=ROOT / 'lessons'):\n"                                    # 9
        "    return corpus\n"                                                  # 10
        "K = KnowledgePaths(agent_root=ROOT, agent_rel='agent')\n"             # 11
        "def g(agent_root):\n"                                                 # 12
        "    return agent_root / L, agent_root / 'lessons', KnowledgePaths(agent_root=agent_root, agent_rel='a')\n"  # 13
        "S = ROOT / 'skills' / 'invlang'\n"                                    # 14
    )
    lines = {(h.line, h.kind) for h in hits}
    assert {(5, "join"), (6, "join"), (7, "join"), (8, "join"), (9, "join"),
            (11, "construct")} <= lines, hits
    assert not any(h.line in (13, 14) for h in hits), \
        f"a call-time join onto an agent root, or a product skill, is not a hit: {hits}"


def test_the_census_does_not_flag_a_shadowing_local_or_the_owner_type():
    """O4 negative control on the same channel: a local that shadows a banned name, an
    unrelated module's same-named attribute, and `KnowledgePaths(...)` built from a root at
    call time are not hits — the census resolves bindings, it does not match spellings."""
    hits = _scan_synthetic(
        "from defender.knowledge._knowledge import KnowledgePaths\n"           # 1
        "import other_pkg as PATHS\n"                                          # 2
        "def f(root):\n"                                                       # 3
        "    CHECKOUT_KNOWLEDGE = KnowledgePaths(agent_root=root, agent_rel='agent')\n"  # 4
        "    return CHECKOUT_KNOWLEDGE.lessons_dir, PATHS.lessons_dir\n"       # 5
        "def g(paths):\n"                                                      # 6
        "    return paths.knowledge.lessons_dir\n"                             # 7
    )
    assert hits == [], hits


def test_the_allowlist_admits_only_its_named_symbols_and_kinds():
    """O4: the allowlist is not a module-wide pass: the door may re-export but not read, and the
    judge package may name `CHECKOUT_KNOWLEDGE` but no other banned symbol."""
    door_read = Hit("defender/knowledge/__init__.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "ref")
    door_export = Hit("defender/knowledge/__init__.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "import")
    judge_ck = Hit("defender/learning/judge/render.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "ref")
    judge_paths = Hit("defender/learning/judge/render.py", 1, f"{_P}.PATHS.lessons_dir", "ref")
    assert _allowed(door_export)
    assert _allowed(judge_ck)
    assert not _allowed(door_read)
    assert not _allowed(judge_paths)


# --- what the resolver cannot reach, closed structurally ---------------------------------------

def test_defender_paths_carries_no_corpus_accessor():
    """O4: `DefenderPaths` (and so every subclass, `LoopPaths` included) has no corpus
    accessor. An attribute on a value (`paths.lessons_dir_rel`, `getattr(paths, "lessons_dir")`
    as `config.py:55` does) is beyond a symbol resolver; an accessor that does not exist is
    beyond every receiver."""
    from defender._paths import DefenderPaths
    present = [name for name in CORPUS_ACCESSORS if hasattr(DefenderPaths, name)]
    assert present == [], f"DefenderPaths still carries corpus accessors: {present}"


def test_the_author_config_carries_no_product_corpus_spelling():
    """O4 (author `corpus_dir_rel`): no author config dataclass carries a corpus spelling
    relative to the product repo — the author writes a draft's `agent/`, located by
    `KnowledgePaths`, not a `defender/lessons/` pathspec."""
    config = importlib.import_module("defender.learning.author._config")
    carriers = [name for name, value in vars(config).items()
                if dataclasses.is_dataclass(value) and isinstance(value, type)
                and "corpus_dir_rel" in {f.name for f in dataclasses.fields(value)}]
    assert carriers == [], f"author config still carries corpus_dir_rel: {carriers}"


# --- amendment 2's census: readers of the clone in the run process ------------------------------

#: The accepted tenant's clone accessors (`_TenantLayout.knowledge/settings/agent`: the clone and
#: its working-tree halves). The data model says the working tree is read by nothing in
#: production, and P-3 that the run process never touches the clone.
TENANT = "defender.tenancy._tenant.Tenant"
RUN_TENANT = "defender.runtime.run_tenant.RunTenant"
CLONE_ATTRS = frozenset({"knowledge", "settings", "agent"})
RUN_ENTRIES = ("defender.run", "defender.run_common")


def _module_file(module: str, root: Path = DEFENDER) -> Path | None:
    path = root.joinpath(*module.split(".")[1:])
    for candidate in (path.with_suffix(".py"), path / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


_DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "builtins.__import__"})


def static_import_closure(entries: tuple[str, ...], root: Path = DEFENDER) -> dict[str, str | None]:
    """Every `defender` module reachable from `entries` through an import statement — module
    level or function local, absolute or relative — mapped to the module that first imported
    it. Also follows a string naming a `defender` module when it is the argument of an
    `importlib.import_module` / `__import__` call — never a module merely NAMED (to spawn a
    child with `-m`, which is the separate process P-3 asks for, not an import)."""
    seen: dict[str, str | None] = {e: None for e in entries}
    queue = list(entries)
    while queue:
        module = queue.pop()
        path = _module_file(module, root)
        if path is None:
            continue
        _text, tree = _astlib.read_and_parse(path, module)
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        env = _astlib.module_env(tree, module=module, package=package)
        named: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                named.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                source = _astlib.import_source(node, package)
                named.add(source)
                named.update(f"{source}.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.Call) and _astlib.callee(node, env) in _DYNAMIC_IMPORTS:
                named.update(a.value for a in node.args[:1]
                             if isinstance(a, ast.Constant) and isinstance(a.value, str))
        for name in named:
            parts = name.split(".")
            for end in range(2, len(parts) + 1):
                candidate = ".".join(parts[:end])
                if candidate not in seen and _module_file(candidate, root) is not None:
                    seen[candidate] = module
                    queue.append(candidate)
    return seen


def _clone_attr_reads(rel: str, func: ast.AST, receivers: dict[str, str]) -> Iterator[str]:
    """In `func`, each clone attribute read on a receiver typed `Tenant`, or through the
    `tenant` field of one typed `RunTenant`."""
    for node in ast.walk(func):
        if not (isinstance(node, ast.Attribute) and node.attr in CLONE_ATTRS):  # lint-ast-resolve: ok — the attribute is read on a value whose class was resolved by `annotated_class`
            continue
        base = node.value
        if isinstance(base, ast.Name) and receivers.get(base.id) == TENANT:
            yield f"{rel}:{node.lineno} {base.id}.{node.attr}"
        elif (isinstance(base, ast.Attribute) and base.attr == "tenant"  # lint-ast-resolve: ok — `RunTenant.tenant` field on a resolved RunTenant value
              and isinstance(base.value, ast.Name)
              and receivers.get(base.value.id) == RUN_TENANT):
            yield f"{rel}:{node.lineno} {base.value.id}.tenant.{node.attr}"


def _clone_reads(rel: str, tree: ast.Module, module: str, package: str) -> list[str]:
    """`.knowledge`/`.settings`/`.agent` read on a value the resolver can type: a parameter
    annotated `Tenant`, `x.tenant.<attr>` on one annotated `RunTenant` (its `tenant` is the
    accepted `Tenant`), and `self.tenant.<attr>` inside `RunTenant` itself."""
    env = _astlib.module_env(tree, module=module, package=package)
    census = Census()
    out: set[str] = set()
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        if f"{module}.{cls.name}" == RUN_TENANT:
            for item in cls.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.update(_clone_attr_reads(rel, item, {"self": RUN_TENANT}))
    for func in ast.walk(tree):
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]
            receivers = {}
            for a in args:
                cls_origin = _astlib.annotated_class(a.annotation, env)
                typed = census.canonical(cls_origin) if cls_origin else None
                if typed in {TENANT, RUN_TENANT}:
                    receivers[a.arg] = typed
            if receivers:
                out.update(_clone_attr_reads(rel, func, receivers))
    return sorted(out)


def test_the_run_process_reads_nothing_from_the_tenant_clone():
    """O4 (amendment 2's census) / P-1 / P-3: in the run process's static import closure,
    outside `tenancy/`, no code reads the accepted tenant's clone — `Tenant.knowledge`,
    `.settings` or `.agent` — directly or through `RunTenant.tenant`. Settings, knowledge and
    the stamp come from the run copy of one export (O-B)."""
    closure = static_import_closure(RUN_ENTRIES)
    reads: list[str] = []
    for module in sorted(closure):
        path = _module_file(module)
        if path is None:
            continue
        rel = path.relative_to(DEFENDER).as_posix()
        if rel.startswith("tenancy/"):
            continue
        _text, tree = _astlib.read_and_parse(path, rel)
        _m, package = _astlib.module_and_package(rel)
        reads.extend(_clone_reads(rel, tree, module, package))
    assert reads == [], "the run process reads the tenant's clone:\n  " + "\n  ".join(reads)


def test_the_clone_reader_census_sees_typed_receivers():
    """Positive control for the clone-reader census: a `Tenant`-annotated parameter's
    `.settings`, a `RunTenant`-annotated one's `.tenant.agent`, and `self.tenant.knowledge`
    inside `RunTenant` are each seen; an untyped `tenant.exports` is not."""
    source = (
        "from defender.tenancy._tenant import Tenant\n"
        "from defender.runtime.run_tenant import RunTenant\n"
        "def a(t: Tenant):\n"
        "    return t.settings / 'x'\n"
        "def b(rt: 'RunTenant'):\n"
        "    return rt.tenant.agent\n"
        "def c(t: Tenant):\n"
        "    return t.exports\n"
    )
    tree = _astlib.parse_source(source, "runtime/planted.py")
    reads = _clone_reads("runtime/planted.py", tree, "defender.runtime.planted", "defender.runtime")
    assert reads == ["runtime/planted.py:4 t.settings", "runtime/planted.py:6 rt.tenant.agent"], reads
    planted = ast.parse("class RunTenant:\n    def k(self):\n        return self.tenant.knowledge\n")
    assert _clone_reads("runtime/run_tenant.py", planted, "defender.runtime.run_tenant",
                        "defender.runtime") == ["runtime/run_tenant.py:3 self.tenant.knowledge"]
