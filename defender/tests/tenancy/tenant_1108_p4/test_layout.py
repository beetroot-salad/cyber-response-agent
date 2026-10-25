"""O1 / O-U5 / O-U6 (structural half) / O10 remnant — the product tree's layout (#1108 P4).

After P4 the product tree holds no tenant knowledge: the tenant repo's `agent/` is the only
home of lessons, system skills, queries, the tacit registry and the pitfalls add-on.
"""
from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path

from defender.tests.support.shared.contracts._by_path import DEFENDER, import_lint_lib

_astlib = import_lint_lib("_astlib")

SKILLS = DEFENDER / "skills"
#: O1's allowlist: the product's own skills. Everything else under `skills/` was a tenant's.
PRODUCT_SKILLS = frozenset({"gather", "invlang", "handbook", "advisory", "connect"})
RETIRED_CORPORA = ("lessons-actor", "lessons-environment")


def _entries(folder: Path) -> set[str]:
    """`folder`'s children a checkout carries: no caches, no hidden entries."""
    return {p.name for p in folder.iterdir()
            if p.name != "__pycache__" and not p.name.startswith(".")}


def test_product_skills_are_exactly_the_five_product_skills():
    """O1: `defender/skills/` holds exactly gather, invlang, handbook, advisory and connect —
    no system skill (`cmdb`, `elastic`, ...) and no `tacit-knowledge` folder."""
    assert _entries(SKILLS) == PRODUCT_SKILLS, sorted(_entries(SKILLS) ^ PRODUCT_SKILLS)


def test_no_lesson_corpus_in_the_product_tree():
    """O1 / O-U5: no `defender/lessons*` entry — the runtime corpus, the questioner's, and the
    retired `lessons-actor`/`lessons-environment` (deleted, not archived) are all gone."""
    left = sorted(p.name for p in DEFENDER.glob("lessons*"))
    assert left == [], left


def test_the_query_catalog_is_gone_and_its_schema_moved_beside_gather():
    """O1: `skills/gather/queries/` is absent; the catalog's format document, product
    content, lives at `skills/gather/query-schema.md`, and no `SCHEMA.md` remains."""
    assert not (SKILLS / "gather" / "queries").exists()
    schema = SKILLS / "gather" / "query-schema.md"
    assert schema.is_file(), schema
    assert schema.read_text(encoding="utf-8").strip(), "the moved schema is not empty"
    assert sorted(str(p.relative_to(DEFENDER)) for p in SKILLS.rglob("SCHEMA.md")) == []


def test_no_tacit_registry_or_pitfalls_add_on_in_the_product_tree():
    """O1: the tacit registry (`skills/tacit-knowledge/registry.yaml`) and the learned SQL
    pitfalls add-on (`skills/gather/defender-sql.pitfalls.md`) are tenant content; neither, nor
    a learned `## Common pitfalls` section in the product's own `defender-sql.md`, is here."""
    registries = sorted(str(p.relative_to(DEFENDER)) for p in SKILLS.rglob("registry.yaml"))
    assert registries == [], registries
    assert not (SKILLS / "gather" / "defender-sql.pitfalls.md").exists()
    sql = (SKILLS / "gather" / "defender-sql.md").read_text(encoding="utf-8")
    assert not re.search(r"(?m)^##\s+Common pitfalls\s*$", sql)


def test_no_verb_roster_file_anywhere_in_the_product_tree():
    """O10 remnant (retired in P2, held here): no committed `verb-roster.md` survives the move."""
    found = sorted(str(p.relative_to(DEFENDER)) for p in DEFENDER.rglob("verb-roster.md")
                   if "tests" not in p.relative_to(DEFENDER).parts
                   and ".venv" not in p.relative_to(DEFENDER).parts)
    assert found == [], found


# --- O-U5: the retired corpora are not named by the layout owner or the posture page ---------

def _source(rel: str) -> str:
    return (DEFENDER / rel).read_text(encoding="utf-8")


def test_the_layout_owner_names_no_retired_corpus():
    """O-U5: `KnowledgePaths`' module defines no retired-corpus name and none of its corpus
    sets holds one; its source spells neither corpus."""
    knowledge = importlib.import_module("defender.knowledge._knowledge")
    assert not hasattr(knowledge, "LESSONS_ACTOR")
    assert not hasattr(knowledge, "LESSONS_ENVIRONMENT")
    for name, value in vars(knowledge).items():
        if isinstance(value, (frozenset, set, tuple, list)):
            assert not set(RETIRED_CORPORA) & {str(v) for v in value}, name
    text = _source("knowledge/_knowledge.py")
    assert [c for c in RETIRED_CORPORA if c in text] == []


def test_the_posture_page_names_no_retired_corpus():
    """O-U5: the lessons posture page (`learning/frontend/serialize.py`) no longer shows the
    retired corpora — it neither imports their names nor spells them."""
    text = _source("learning/frontend/serialize.py")
    named = [w for w in (*RETIRED_CORPORA, "LESSONS_ACTOR", "LESSONS_ENVIRONMENT") if w in text]
    assert named == [], named


# --- O-U6 (structural): nothing in presentation/ runs git -------------------------------------

_GIT_FACADE = "defender._git"
_SPAWNERS = re.compile(
    r"^(subprocess\.\w+|os\.(system|popen|exec\w*|spawn\w*|posix_spawn\w*)"
    r"|asyncio(\.subprocess)?\.create_subprocess_\w+)$")


def _folded_head(node: ast.expr | None) -> str | None:
    """The program a spawn names, when its argv (or command string) is literal."""
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        node = node.elts[0]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.split()[0] if node.value.split() else ""
    return None


def _runs_git(origin: str) -> bool:
    """Is `origin` something of the `_git` facade that runs git? Its path constants
    (`REPO_ROOT`, upper-case) and exception classes (`GitError`) run nothing."""
    if not (origin == _GIT_FACADE or origin.startswith(_GIT_FACADE + ".")):
        return False
    leaf = origin.removeprefix(_GIT_FACADE).lstrip(".").split(".")[0]
    return not (leaf.isupper() or leaf.endswith(("Error", "Timeout", "Expired")))


def git_runs(rel: str, tree: ast.Module, module: str, package: str) -> list[str]:
    """Every place a module could run git: any reference resolving to a git-running member of
    the `defender._git` facade (called, or handed on as a value), and any spawn whose literal
    program is `git`. An import binding alone runs nothing; its uses are judged."""
    env = _astlib.module_env(tree, module=module, package=package)
    out: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) or (
                isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
            origin = _astlib.origin(node, env)
            if origin and origin != _GIT_FACADE and _runs_git(origin):
                out.setdefault(node.lineno, f"{rel}:{node.lineno} {origin}")
        if isinstance(node, ast.Call):
            callee = _astlib.callee(node, env) or ""
            head = _folded_head(node.args[0] if node.args else None)
            if _SPAWNERS.match(callee) and head is not None and Path(head).name == "git":
                out.setdefault(node.lineno, f"{rel}:{node.lineno} {callee}({head} ...)")
    return [out[line] for line in sorted(out)]


def test_nothing_in_presentation_runs_git():
    """O-U6: no module under `defender/presentation/` runs git — no use of the `_git` facade
    and no spawn of a `git` program (the run page's lesson-history panel read `git log`)."""
    folder = DEFENDER / "presentation"
    found: list[str] = []
    for rel in _astlib.source_files(folder, (".venv", "__pycache__")):
        full = f"presentation/{rel}"
        _text, tree = _astlib.read_and_parse(folder / rel, full)
        module, package = _astlib.module_and_package(full)
        found.extend(git_runs(full, tree, module, package))
    assert found == [], "presentation/ runs git:\n  " + "\n  ".join(found)


def test_the_git_census_sees_aliases_and_spawns_but_not_a_python_child():
    """O-U6 positive/negative control on the same channel: a call through an aliased facade
    module, through a function-local aliased import, and a `subprocess.run(["git", ...])` are
    each seen; spawning this interpreter, reading a `.git` pointer file, naming the facade's
    `REPO_ROOT` or catching its `GitError` are not running git."""
    source = (
        "import subprocess, sys\n"
        "from defender import _git as g\n"                                  # 2
        "def a(p):\n"
        "    return g.git(['log'], cwd=p)\n"                                # 4
        "def b(p):\n"
        "    from defender._git import git_show_file as show\n"             # 6
        "    return show(p, 'x')\n"                                         # 7
        "def c(p):\n"
        "    return subprocess.run(['/usr/bin/git', 'log'], cwd=p)\n"       # 9
        "def d(p):\n"
        "    subprocess.run([sys.executable, '-m', 'x'])\n"                 # 11
        "    return (p / '.git').read_text()\n"                             # 12
        "def e():\n"
        "    try:\n"
        "        return g.REPO_ROOT\n"                                      # 15
        "    except g.GitError:\n"                                          # 16
        "        return None\n"
    )
    rel = "presentation/planted.py"
    tree = _astlib.parse_source(source, rel)
    found = git_runs(rel, tree, "defender.presentation.planted", "defender.presentation")
    lines = {int(f.split(":")[1].split()[0]) for f in found}
    assert lines == {4, 7, 9}, found
