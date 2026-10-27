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
    "defender.investigation.lessons_engine.lessons_fm.LESSONS_DIR": "lessons_fm.LESSONS_DIR",
    "defender.investigation.lessons_engine.lessons_frontier.DEFAULT_CORPUS": "lessons_frontier.DEFAULT_CORPUS",
    "defender.hooks.inject_system_skill_description.SKILLS_DIR": "inject_system_skill_description.SKILLS_DIR",
    "defender.investigation.query_catalog._SKILLS_REL": "query_catalog._SKILLS_REL",
    "defender.learning.leads.path_validation.CATALOG_DIR": "path_validation.CATALOG_DIR",
    "defender.learning.leads.path_validation.CATALOG_REL": "path_validation.CATALOG_REL",
    "defender.learning.leads.path_validation.SKILLS_DIR": "path_validation.SKILLS_DIR",
    "defender.learning.leads.path_validation.SKILLS_REL": "path_validation.SKILLS_REL",
    "defender.learning.leads.declared_systems.SKILLS_REL": "declared_systems.SKILLS_REL",
    "defender.cli.learning.revert_lesson.LESSONS_REL": "revert_lesson.LESSONS_REL",
    "defender.cli.learning.trace_lesson.LESSONS_DIR": "trace_lesson.LESSONS_DIR",
    "defender.presentation.visualize_runtime._LESSONS_PATHSPEC": "visualize_runtime._LESSONS_PATHSPEC",
    # O-B: the stamp is the commit of the export actually copied, never the clone's HEAD, and
    # O4 names both captures (run start, the branch CLI's live capture). They read a clone's
    # checked-out commit; no production caller remains (their own module calls the one from the
    # other by bare name, which is not a reference to the import).
    "defender.records._provenance.capture_run": "capture_run (stamps the clone's HEAD)",
    "defender.records._provenance.capture_knowledge": "capture_knowledge (reads the clone's HEAD)",
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

PRODUCT_JOIN = "<call-time product-tree join>"
ALL = frozenset(BANNED) | {KNOWLEDGE_PATHS, "<import-time join>", PRODUCT_JOIN}

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
#: `CHECKOUT_KNOWLEDGE` — the one place the design keeps it (`KnowledgePaths` data model). The
#: branch is the judge's lesson-body reader, `learning/judge/render.py` (P4-C6: `render.py:368-
#: 393`; at base `_lesson_paths_for`, `render.py:440-445`, is its one `CHECKOUT_KNOWLEDGE`
#: reference). One module, not the package; a function-level pin would freeze a name the
#: design does not give.
JUDGE_MODULE = "defender/learning/judge/render.py"
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


def _div_parts(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return [*_div_parts(node.left), *_div_parts(node.right)]
    return [node]


#: The product tree's knowledge as a path spells it: O-TEXT's own patterns (the first three:
#: corpus, catalog, tenant system skill under a product-tree root).
def _product_patterns():  # noqa: ANN202
    from defender.tests.tenancy.tenant_1108_p4.test_model_text import OLD_SPELLINGS
    return [pattern for pattern, _why in OLD_SPELLINGS[:3]]


def _spells_product_knowledge(parts: list[ast.expr]) -> bool:
    words = []
    for i, part in enumerate(parts):
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            words.append(part.value.strip("/"))
        elif i == 0 and isinstance(part, ast.Name):
            words.append(part.id)
        elif i == 0 and isinstance(part, ast.Attribute):
            words.append(part.attr)
        else:
            words.append("\x00")
    text = "/".join(words)
    return any(p.search(text) for p in _product_patterns())


class _Aliases(dict):
    """`(scope id, name) -> origin`, plus every `(scope id, name)` a scope binds at all, so a
    function's own rebinding of a module-level alias is never read as the alias."""

    stores: set[tuple[int, str]] = set()  # noqa: RUF012 — replaced per instance


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

    def _call_origin(self, call: ast.Call, env, aliases) -> str | None:  # noqa: ANN001
        """`importlib.import_module("<m>")` is module `<m>`; `getattr(<x>, "<a>")` is `<x>.<a>`."""
        scope = env.scope_of.get(call, env)
        callee = _astlib.callee(call, scope)
        literal = [a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else None
                   for a in call.args]
        if callee == "importlib.import_module" and literal and literal[0]:
            return literal[0]
        if callee == "builtins.getattr" and len(literal) >= 2 and literal[1]:
            base = self.chain_origin(call.args[0], env, aliases)
            return f"{base}.{literal[1]}" if base else None
        return None

    def chain_origin(self, node: ast.expr, env, aliases) -> str | None:  # noqa: ANN001
        """`_astlib.origin`, plus what a symbol resolver owes beyond it: a chain rooted at a
        local or module-level alias of a resolvable chain (`k = _knowledge; k.X`), at
        `importlib.import_module(...)`, or at `getattr(<module>, "<literal>")`."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            base = _astlib.origin(cur, env)
            if base is None:
                scope = env.scope_of.get(cur, env)
                base = aliases.get((id(scope), cur.id))
                if base is None and (id(scope), cur.id) not in aliases.stores:
                    base = aliases.get((id(env), cur.id))  # not bound here: the module's alias
        elif isinstance(cur, ast.Call):
            base = self._call_origin(cur, env, aliases)
        else:
            base = None
        return ".".join([base, *reversed(parts)]) if base else None

    def _aliases(self, tree: ast.Module, env) -> _Aliases:  # noqa: ANN001
        """`name = <resolvable chain>` per scope: the name is that chain (two passes, so an
        alias of an alias resolves)."""
        aliases = _Aliases()
        aliases.stores = {(id(env.scope_of.get(n, env)), n.id) for n in ast.walk(tree)
                          if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        for _ in range(2):
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Name, ast.Attribute, ast.Call)):
                    found = self.chain_origin(node.value, env, aliases)
                    for target in node.targets:
                        if found and isinstance(target, ast.Name):
                            aliases[(id(env.scope_of.get(target, env)), target.id)] = found
        return aliases

    def _references(self, rel: str, tree: ast.Module, env, package: str) -> Iterator[Hit]:  # noqa: ANN001 — _astlib.ModuleEnv
        """Import bindings, and Name/Attribute chains or dynamic lookups resolving to a banned
        symbol."""
        aliases = self._aliases(tree, env)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                source = _astlib.import_source(node, package)
                for alias in node.names:
                    symbol = _matches(self.canonical(f"{source}.{alias.name}"))
                    if symbol:
                        yield Hit(rel, node.lineno, symbol, "import")
            elif isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
                origin = (self._call_origin(node, env, aliases) if isinstance(node, ast.Call)
                          else self.chain_origin(node, env, aliases))
                symbol = _matches(self.canonical(origin)) if origin else None
                if symbol:
                    yield Hit(rel, node.lineno, symbol, "ref")

    def _product_joins(self, rel: str, tree: ast.Module, env) -> Iterator[Hit]:  # noqa: ANN001
        """A path built at any time by `/`, `joinpath` or `os.path.join` that spells the
        product tree's knowledge (`REPO_ROOT / "defender" / "lessons"`, `DEFENDER_DIR /
        "lessons"`). The head component is spelled by its identifier (a root named for the
        product tree counts); later non-literal components never match."""
        for node in ast.walk(tree):
            parts: list[ast.expr] | None = None
            if not isinstance(node, (ast.BinOp, ast.Call)):
                continue
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                parts = _div_parts(node)
            elif isinstance(node, ast.Call) and node.args:
                callee = _astlib.callee(node, env.scope_of.get(node, env))
                if callee in {"os.path.join", "posixpath.join"}:
                    parts = list(node.args)
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":  # lint-ast-resolve: ok — `Path.joinpath` on a value receiver, which the resolver answers None for
                    parts = [node.func.value, *node.args]
            if parts and _spells_product_knowledge(parts):
                yield Hit(rel, node.lineno, PRODUCT_JOIN, "join")

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
        hits = {*self._references(rel, tree, env, package), *self._import_time(rel, tree, env),
                *self._product_joins(rel, tree, env)}
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
    return hit.path == JUDGE_MODULE and hit.symbol in JUDGE_SYMBOLS


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

def _scan_synthetic(source: str, rel: str = "defender/investigation/planted.py",
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
        "from defender.investigation.lessons_engine import lessons_fm as fm\n"       # 3
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
    assert (12, "defender.investigation.lessons_engine.lessons_fm.LESSONS_DIR", "ref") in got, hits
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
    judge's pre-move module may name `CHECKOUT_KNOWLEDGE` but no other banned symbol, and no
    other judge module may name it."""
    door_read = Hit("defender/knowledge/__init__.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "ref")
    door_export = Hit("defender/knowledge/__init__.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "import")
    judge_ck = Hit("defender/learning/judge/render.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "ref")
    judge_paths = Hit("defender/learning/judge/render.py", 1, f"{_P}.PATHS.lessons_dir", "ref")
    judge_elsewhere = Hit("defender/learning/judge/__init__.py", 1, f"{_K}.CHECKOUT_KNOWLEDGE", "ref")
    assert _allowed(door_export)
    assert _allowed(judge_ck)
    assert not _allowed(door_read)
    assert not _allowed(judge_paths)
    assert not _allowed(judge_elsewhere), "the judge allowance is its pre-move module, not the package"


def test_the_census_follows_dynamic_lookups_and_aliases():
    """O4 (review R-I7): `importlib.import_module("<m>").X`, `getattr(<module>, "X")`, a
    module bound to a module-level or local name, a local alias of `PATHS`, and a reference
    to the clone-HEAD captures (`capture_run`, `capture_knowledge`) are each the banned
    symbol; a `getattr` on an untyped value is not."""
    hits = _scan_synthetic(
        "import importlib\n"                                                            # 1
        "import defender.knowledge._knowledge as k\n"                                   # 2
        "from defender.knowledge import _knowledge as kk\n"                             # 3
        "from defender._paths import PATHS\n"                                           # 4
        "from defender.records import _provenance as prov\n"                           # 5
        "X = kk\n"                                                                      # 6
        "def a():\n"                                                                    # 7
        "    return importlib.import_module('defender.knowledge._knowledge').CHECKOUT_KNOWLEDGE\n"  # 8
        "def b():\n"                                                                    # 9
        "    return getattr(k, 'CHECKOUT_KNOWLEDGE')\n"                                # 10
        "def c():\n"                                                                    # 11
        "    return X.CHECKOUT_KNOWLEDGE\n"                                             # 12
        "def d():\n"                                                                    # 13
        "    p = PATHS\n"                                                               # 14
        "    q = p\n"                                                                   # 15
        "    return q.lessons_dir\n"                                                    # 16
        "def e(repo, clone):\n"                                                         # 17
        "    return prov.capture_run(repo, clone), prov.capture_knowledge(clone)\n"     # 18
        "def f(v):\n"                                                                   # 19
        "    return getattr(v, 'CHECKOUT_KNOWLEDGE')\n"                                # 20
    )
    got = {(h.line, h.symbol) for h in hits}
    ck = f"{_K}.CHECKOUT_KNOWLEDGE"
    assert {(8, ck), (10, ck), (12, ck), (16, f"{_P}.PATHS.lessons_dir"),
            (18, "defender.records._provenance.capture_run"),
            (18, "defender.records._provenance.capture_knowledge")} <= got, hits
    assert not any(h.line == 20 for h in hits), hits


def test_the_census_catches_a_call_time_product_tree_join():
    """O4 / O-TEXT (review R-I7): a path built at call time that spells the product tree's
    knowledge — `REPO_ROOT / "defender" / "lessons"`, `DEFENDER_DIR / "skills" / "cmdb"`,
    `os.path.join(root, "defender/skills/gather/queries")`, `.joinpath("defender", "lessons")`
    — is a hit; a join onto an agent root, a product skill, and a system name held in a
    variable are not (the O1 layout test is the backstop for those)."""
    hits = _scan_synthetic(
        "import os\n"                                                                   # 1
        "from defender._git import REPO_ROOT\n"                                         # 2
        "def a():\n    return REPO_ROOT / 'defender' / 'lessons' / 'x.md'\n"            # 3-4
        "def b(DEFENDER_DIR):\n    return DEFENDER_DIR / 'skills' / 'cmdb'\n"          # 5-6
        "def c(root):\n    return os.path.join(root, 'defender/skills/gather/queries')\n"  # 7-8
        "def d(root):\n    return root.joinpath('defender', 'lessons')\n"              # 9-10
        "def e(agent_root, defender_dir, system):\n"                                    # 11
        "    return (agent_root / 'lessons', defender_dir / 'skills' / 'invlang',\n"    # 12
        "            defender_dir / 'skills' / system)\n"                               # 13
    )
    lines = {h.line for h in hits if h.symbol == PRODUCT_JOIN}
    assert lines == {4, 6, 8, 10}, hits


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
RUN_TENANT = "defender.systems.run_tenant.RunTenant"
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


_TYPING_UNIONS = frozenset({"typing.Optional", "typing.Union"})


class _Typer:
    """Just enough typing to find who holds a `Tenant`: annotations (unions, `Optional`,
    strings), dataclass/class fields and properties, function and method return annotations,
    locals assigned from any of these, `self.<x> = ...` stores, and `getattr(v, "<literal>")`.
    Classes and functions are looked up in the module that defines them (`_module_file`), and
    the module under scan is registered first so a synthetic module types its own classes."""

    def __init__(self) -> None:
        self.census = Census()
        self.modules: dict[str, tuple[ast.Module, object] | None] = {}
        #: `(owner, name)` -> type, `None` while being computed (a cycle answers "untyped").
        self.members: dict[tuple[str, str], set[str] | None] = {}

    def register(self, module: str, tree: ast.Module, env: object) -> None:
        self.modules[module] = (tree, env)

    def _module(self, module: str):  # noqa: ANN202 — (tree, ModuleEnv) | None
        if module not in self.modules:
            path = _module_file(module)
            if path is None:
                self.modules[module] = None
            else:
                rel = path.relative_to(DEFENDER).as_posix()
                _t, tree = _astlib.read_and_parse(path, rel)
                mod, package = _astlib.module_and_package(rel)
                self.modules[module] = (tree, _astlib.module_env(tree, module=mod, package=package))
        return self.modules[module]

    def _split(self, origin: str):  # noqa: ANN202 — (tree, env, rest) | None
        parts = origin.split(".")
        for end in range(len(parts) - 1, 0, -1):
            loaded = self._module(".".join(parts[:end]))
            if loaded is not None:
                return (*loaded, parts[end:])
        return None

    def _class(self, origin: str):  # noqa: ANN202 — (ClassDef, env) | None
        found = self._split(origin)
        if found is None or len(found[2]) != 1:
            return None
        tree, env, (name,) = found
        cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name), None)
        return None if cls is None else (cls, env)

    def ann(self, node: ast.expr | None, env) -> set[str]:  # noqa: ANN001 — ModuleEnv
        if node is None:
            return set()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                parsed = ast.parse(node.value.strip(), mode="eval").body
            except SyntaxError:
                return set()
            return self._ann_parsed(parsed, env, node)
        return self._ann_parsed(node, env, node)

    def _ann_parsed(self, node: ast.expr, env, anchor: ast.AST) -> set[str]:  # noqa: ANN001
        scope = env.scope_of.get(anchor, env)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._ann_parsed(node.left, env, anchor) | self._ann_parsed(node.right, env, anchor)
        if isinstance(node, ast.Subscript):
            head = _astlib.origin(node.value, scope) if isinstance(node.value, (ast.Name, ast.Attribute)) else None
            if head in _TYPING_UNIONS:
                elts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
                return set().union(*(self._ann_parsed(e, env, anchor) for e in elts))
            return set()
        if isinstance(node, (ast.Name, ast.Attribute)):
            cls = _astlib.annotated_class(node, scope) if node is anchor else (
                _astlib.origin(node, scope) or (scope.own_defs.get(node.id) if isinstance(node, ast.Name) else None))
            return {self.census.canonical(cls)} if cls else set()
        return set()

    def member(self, owner: str, name: str) -> set[str]:
        """The type of `owner.<name>`: an annotated field, a `self.<name> = ...` store, a
        property's return annotation. Memoised; a member whose typing reaches itself is
        untyped on the inner visit."""
        key = (owner, name)
        if key in self.members:
            return self.members[key] or set()
        self.members[key] = None
        self.members[key] = typed = self._member(owner, name)
        return typed

    def _member(self, owner: str, name: str) -> set[str]:
        found = self._class(owner)
        if found is None:
            return set()
        cls, env = found
        out: set[str] = set()
        for item in cls.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.target.id == name:
                out |= self.ann(item.annotation, env)
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name == name:
                    out |= self.ann(item.returns, env)
                for node in ast.walk(item):
                    if isinstance(node, ast.Assign) and any(
                            isinstance(t, ast.Attribute) and t.attr == name  # lint-ast-resolve: ok — a `self.<field>` store on the class being typed
                            and isinstance(t.value, ast.Name) and t.value.id == "self" for t in node.targets):
                        out |= self.expr(node.value, env, self.locals_of(item, env, owner))
        return out

    def returns(self, origin: str) -> set[str]:
        if self._class(origin) is not None:
            return {origin}
        found = self._split(origin)
        if found is None:
            return set()
        tree, env, rest = found
        body: list[ast.stmt] = tree.body
        for name in rest[:-1]:
            cls = next((n for n in body if isinstance(n, ast.ClassDef) and n.name == name), None)
            if cls is None:
                return set()
            body = cls.body
        func = next((n for n in body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.name == rest[-1]), None)
        return self.ann(func.returns, env) if func is not None else set()

    def expr(self, node: ast.expr, env, local: dict[str, set[str]]) -> set[str]:  # noqa: ANN001, C901
        scope = env.scope_of.get(node, env)
        if isinstance(node, ast.Name):
            return local.get(node.id, set())
        if isinstance(node, ast.Attribute):
            return set().union(*(self.member(t, node.attr) for t in self.expr(node.value, env, local)))
        if isinstance(node, ast.Call):
            if _astlib.callee(node, scope) == "builtins.getattr" and len(node.args) >= 2 \
                    and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                return set().union(*(self.member(t, node.args[1].value)
                                     for t in self.expr(node.args[0], env, local)))
            callee = _astlib.callee(node, scope)
            if callee is None and isinstance(node.func, ast.Name):
                callee = scope.own_defs.get(node.func.id)
            if callee is not None:
                return self.returns(self.census.canonical(callee))
            if isinstance(node.func, ast.Attribute):
                return set().union(*(self.returns(f"{t}.{node.func.attr}")
                                     for t in self.expr(node.func.value, env, local)))
        if isinstance(node, ast.NamedExpr):
            return self.expr(node.value, env, local)
        return set()

    def _params(self, func: ast.AST, env, self_cls: str | None) -> dict[str, set[str]]:  # noqa: ANN001
        local: dict[str, set[str]] = {}
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return local
        args = func.args
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            local[a.arg] = self.ann(a.annotation, env)
        positional = (*args.posonlyargs, *args.args)
        if self_cls and positional and positional[0].arg in {"self", "cls"}:
            local[positional[0].arg] = {self_cls}
        return local

    def locals_of(self, func: ast.AST, env, self_cls: str | None) -> dict[str, set[str]]:  # noqa: ANN001
        local = self._params(func, env, self_cls)
        for _ in range(2):  # an alias of an alias
            for node in ast.walk(func):
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    local[node.target.id] = local.get(node.target.id, set()) | self.ann(node.annotation, env)
                elif isinstance(node, ast.Assign):
                    typed = self.expr(node.value, env, local)
                    for target in node.targets:
                        if isinstance(target, ast.Name) and typed:
                            local[target.id] = local.get(target.id, set()) | typed
                elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                    local[node.target.id] = local.get(node.target.id, set()) | self.expr(node.value, env, local)
        return local


def _clone_reads(rel: str, tree: ast.Module, module: str, package: str,
                 typer: _Typer | None = None) -> list[str]:
    """Each `.knowledge`/`.settings`/`.agent` (attribute or `getattr` literal) read on a value
    typed `Tenant` — the accepted tenant, whose three are the clone and its working tree."""
    typer = typer or _Typer()
    env = _astlib.module_env(tree, module=module, package=package)
    typer.register(module, tree, env)
    owners: dict[ast.AST, str | None] = {}
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        for item in cls.body:
            owners[item] = f"{module}.{cls.name}"
    out: set[str] = set()
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for func in funcs:
        local = typer.locals_of(func, env, owners.get(func))
        for node in ast.walk(func):
            if isinstance(node, ast.Attribute) and node.attr in CLONE_ATTRS:  # lint-ast-resolve: ok — the attribute is read on a value whose class the typer resolved
                receiver, attr = node.value, node.attr
            elif (isinstance(node, ast.Call) and _astlib.callee(node, env) == "builtins.getattr"
                  and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                  and node.args[1].value in CLONE_ATTRS):
                receiver, attr = node.args[0], str(node.args[1].value)
            else:
                continue
            if TENANT in typer.expr(receiver, env, local):
                out.add(f"{rel}:{node.lineno} {ast.unparse(receiver)}.{attr}")
    return sorted(out)


def test_the_run_process_reads_nothing_from_the_tenant_clone():
    """O4 (amendment 2's census) / P-1 / P-3: in the run process's static import closure,
    outside `tenancy/`, no code reads the accepted tenant's clone — `Tenant.knowledge`,
    `.settings` or `.agent` — directly or through `RunTenant.tenant`. Settings, knowledge and
    the stamp come from the run copy of one export (O-B)."""
    closure = static_import_closure(RUN_ENTRIES)
    typer = _Typer()
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
        reads.extend(_clone_reads(rel, tree, module, package, typer))
    assert reads == [], "the run process reads the tenant's clone:\n  " + "\n  ".join(reads)


def _planted_clone_reads(source: str) -> list[int]:
    tree = _astlib.parse_source(source, "runtime/planted.py")
    reads = _clone_reads("runtime/planted.py", tree, "defender.investigation.planted", "defender.investigation")
    return sorted({int(r.split(":")[1].split()[0]) for r in reads})


def test_the_clone_reader_census_sees_typed_receivers():
    """Positive control for the clone-reader census (review R-I5): a `Tenant` reached through
    a plain, `X | None`, `Optional[X]` or string annotation, a `RunTenant`'s `tenant` field,
    an unannotated local assigned from a producer (`accept_tenant`, a `RunTenant` method or
    field), an alias of an alias, a stored attribute (`self.rt.tenant`), a planted class's
    own field, and `getattr(t, "agent")` are each seen; `tenant.exports`, a `RunTenant`'s own
    `.agent`, and an untyped receiver are not."""
    lines = _planted_clone_reads(
        "from typing import Optional\n"                                                  # 1
        "from defender.tenancy._tenant import Tenant, accept_tenant\n"                   # 2
        "from defender.systems.run_tenant import RunTenant\n"                            # 3
        "def a(t: Tenant):\n    return t.settings / 'x'\n"                              # 4-5
        "def b(t: Tenant | None):\n    return t.agent\n"                                # 6-7
        "def c(t: Optional[Tenant]):\n    return t.knowledge\n"                         # 8-9
        "def d(rt: 'RunTenant'):\n    return rt.tenant.agent\n"                         # 10-11
        "def e(root, raw):\n    t = accept_tenant(root, raw, defender_dir=root)\n    return t.settings\n"  # 12-14
        "def f(rt: RunTenant):\n    u = rt.tenant\n    v = u\n    return v.agent\n"   # 15-18
        "class Holder:\n"                                                                # 19
        "    def __init__(self, rt: RunTenant):\n        self.rt = rt\n"                # 20-21
        "    def g(self):\n        return self.rt.tenant.agent\n"                       # 22-23
        "class Own:\n    tenant: 'Tenant'\n"                                             # 24-25
        "    def h(self):\n        return self.tenant.knowledge\n"                      # 26-27
        "def i(t: Tenant):\n    return getattr(t, 'agent')\n"                           # 28-29
        "def j(t: Tenant, rt: RunTenant, x):\n    return t.exports, rt.agent, x.agent\n"  # 30-31
    )
    assert lines == [5, 7, 9, 11, 14, 18, 23, 27, 29], lines
