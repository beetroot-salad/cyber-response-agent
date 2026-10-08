"""#1108 P1 — one owner of the agent-knowledge layout.

`defender/_knowledge.py` is the only module that joins a corpus name onto a root: the lesson
corpora, the per-system skills' parent, and the query catalog. Every other reader goes through a
`KnowledgePaths`, so moving the knowledge into each tenant's own repo changes how one is built,
not forty call sites. This census keeps a new hand-spelled join from slipping back in.

It counts, per production module outside the owner (and outside `tests/`):
- a join onto `"skills"`, `"queries"` or a lesson-corpus name: `root / "x"`,
  `root.joinpath("x")` or `Path(root, "x")`;
- any other literal that IS a lesson-corpus name (a dict key, a folder list);
- a string spelling `defender/lessons`, `defender/skills/` or `gather/queries`.

`ALLOWED` names every such literal that is not a knowledge path, with how many times it may
occur and why; one more occurrence fails. A `"skills"` join is allowed only for a GENERAL skill
(product code that stays in the checkout) or for a walk #1108's later pieces split.

What it cannot see: a corpus name reached through a variable (`agent_definition.
_resolve_corpus_dir` joins a name it is handed), and a path built inside a regex; the read
gate holds both, and #1108 P2 moves it (its folder lists are counted below as bare names).
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

from defender._knowledge import (
    CATALOG, CHECKOUT_KNOWLEDGE, LESSONS, LESSONS_QUESTIONER, KnowledgePaths,
)
from defender._paths import PATHS, DefenderPaths

_DEFENDER = Path(__file__).resolve().parents[1]
_OWNER = "_knowledge.py"

_CORPUS_NAMES = frozenset({"lessons", "lessons-questioner", "lessons-actor", "lessons-environment"})
_JOIN_NAMES = _CORPUS_NAMES | {"skills", "queries"}
_SPELLINGS = ("defender/lessons", "defender/skills/", "gather/queries")
_PATH_TYPES = frozenset({"Path", "PurePath", "PosixPath"})

_P2_GATE = "the read gate's folder list, built under `defender_dir`; #1108 P2 moves the gate"
_P4_TEXT = "text naming the checkout's corpus; rewritten with the switch (#1108 P4)"
_KEY = "a dict key or list name, not a path"

#: (file, the literal) -> (how many times it occurs, why it is not a knowledge path).
ALLOWED: dict[tuple[str, str], tuple[int, str]] = {
    ("api/app.py", "lessons"): (1, _KEY),
    ("learning/frontend/build.py", "lessons"): (1, _KEY),
    ("learning/frontend/serialize.py", "lessons"): (2, _KEY),
    ("learning/judge/render.py", "lessons"): (1, _KEY),
    ("learning/judge/run.py", "lessons"): (1, _KEY),
    ("evals/harness.py", "lessons"):
        (2, "a scenario's own `lessons/` folder and the results folder, not a knowledge root"),
    ("learning/author/lessons/run.py", "lessons"):
        (2, "the `learning/author/lessons/` package's prompt files, code not knowledge"),
    ("runtime/driver/_build.py", "lessons"): (1, _P2_GATE),
    ("runtime/permission/policies/_common.py", "lessons"): (1, _P2_GATE),
    ("runtime/driver/_build.py", "skills"): (1, "gather's own SKILL.md: a general skill"),
    ("runtime/orient.py", "skills"): (1, "invlang's SKILL.md: a general skill"),
    ("runtime/verb_roster.py", "skills"):
        (3, "the roster file (gather, a general skill) and the model-read-surface walk, which "
            "spans general and per-system skills in one tree until #1108 P4 splits it"),
    ("learning/author/branch.py", "`). Touches `defender/lessons/` only — distinct from the "
     "lead-author PR."): (1, _P4_TEXT),
    ("learning/core/drains.py", "`). May also fold agent-fixable execution failures into "
     "per-system `execution.md` `## Comm"): (1, _P4_TEXT),
    ("learning/leads/lead_author_engine.py", "Blocked: the lead author curates the gather query "
     "catalog and the per-SYSTEM skill docs. I"): (1, "model-facing deny text; " + _P4_TEXT),
    ("learning/frontend/serialize.py", "Frozen archive. Both directions that fed it were "
     "deleted with the four-role pipeline (#922"): (1, "prose on the posture page"),
    ("learning/leads/pitfalls_curator.py", "defender/skills/gather/defender-sql.md"):
        (1, "the shared SQL guide: a general skill"),
    ("learning/ops/trace_lesson.py", "Corpus directory (default: defender/lessons)"):
        (1, "CLI help text"),
    ("skills/connect/validate_scaffold.py", "no seed query templates under skills/gather/queries/"):
        (1, "a report message"),
}

#: Long literals are keyed by their first 90 characters.
_KEY_LEN = 90


def _production_sources() -> list[Path]:
    return [p for p in sorted(_DEFENDER.rglob("*.py"))
            if "tests" not in p.relative_to(_DEFENDER).parts and ".venv" not in p.parts
            and p.relative_to(_DEFENDER).as_posix() != _OWNER]


def _docstrings(tree: ast.Module) -> set[int]:
    owners = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    return {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, owners) and n.body and isinstance(n.body[0], ast.Expr)
            and isinstance(n.body[0].value, ast.Constant)}


def _joined_operands(node: ast.AST) -> list[ast.expr]:
    """The operands a node joins onto a path: `a / x`, `a.joinpath(x, ...)`, `Path(a, x, ...)`."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return [node.right]
    if isinstance(node, ast.Call):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name == "joinpath":
            return list(node.args)
        if name in _PATH_TYPES:
            return list(node.args[1:])
    return []


def _hits(source: Path) -> Counter[tuple[str, str]]:
    rel = source.relative_to(_DEFENDER).as_posix()
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=rel)
    docs = _docstrings(tree)
    found: Counter[tuple[str, str]] = Counter()
    joined: set[int] = set()
    for node in ast.walk(tree):
        for operand in _joined_operands(node):
            if isinstance(operand, ast.Constant) and operand.value in _JOIN_NAMES:
                found[(rel, operand.value)] += 1
                joined.add(id(operand))
    for node in ast.walk(tree):
        if (not isinstance(node, ast.Constant) or not isinstance(node.value, str)
                or id(node) in docs or id(node) in joined):
            continue
        if node.value in _CORPUS_NAMES:
            found[(rel, node.value)] += 1
        elif any(s in node.value for s in _SPELLINGS):
            found[(rel, node.value[:_KEY_LEN])] += 1
    return found


def _all_hits() -> Counter[tuple[str, str]]:
    total: Counter[tuple[str, str]] = Counter()
    for src in _production_sources():
        total.update(_hits(src))
    return total


def test_no_production_module_spells_a_knowledge_path_outside_the_owner() -> None:
    hits = _all_hits()
    wrong = [f"{rel}: {value!r} occurs {n}x, allowed {ALLOWED.get((rel, value), (0, ''))[0]}"
             for (rel, value), n in sorted(hits.items())
             if n != ALLOWED.get((rel, value), (0, ""))[0]]
    assert wrong == [], (
        "build these through `defender._knowledge.KnowledgePaths`, or record the literal in "
        "ALLOWED with its count and why it is not a knowledge path:\n" + "\n".join(wrong))


def test_every_allowance_still_matches_a_hit() -> None:
    """An allowance whose literal is gone would excuse a future hit it was never about."""
    assert sorted(set(ALLOWED) - set(_all_hits())) == []


def test_the_census_sees_every_join_form(tmp_path: Path) -> None:
    """Positive control: each join form, and a bare corpus name, is counted."""
    probe = tmp_path / "probe.py"
    probe.write_text(
        "from pathlib import Path\n"
        "a = root / 'lessons'\n"
        "b = root.joinpath('skills', 'x')\n"
        "c = Path(root, 'queries')\n"
        "d = ('lessons-questioner', 'examples')\n"
        "e = 'see defender/skills/elastic'\n",
        encoding="utf-8",
    )
    tree = ast.parse(probe.read_text(encoding="utf-8"))
    joins = [op.value for node in ast.walk(tree) for op in _joined_operands(node)
             if isinstance(op, ast.Constant) and op.value in _JOIN_NAMES]
    assert sorted(joins) == ["lessons", "queries", "skills"]
    bare = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
            and isinstance(n.value, str) and n.value in _CORPUS_NAMES]
    assert "lessons-questioner" in bare


def test_the_checkout_paths_pass_through_to_the_owner() -> None:
    """`DefenderPaths` keeps its corpus names, and they are exactly the owner's."""
    knowledge = KnowledgePaths.of_defender_dir(PATHS.defender_dir)
    assert PATHS.knowledge == knowledge == CHECKOUT_KNOWLEDGE
    assert PATHS.lessons_dir == knowledge.lessons_dir == PATHS.defender_dir / LESSONS
    assert PATHS.lessons_questioner_dir == knowledge.corpus_dir(LESSONS_QUESTIONER)
    assert PATHS.catalog_dir == knowledge.catalog_dir == PATHS.defender_dir / CATALOG
    assert PATHS.skills_dir == knowledge.skills_dir
    assert DefenderPaths.lessons_dir_rel == knowledge.rel(LESSONS) == "defender/lessons/"
    assert DefenderPaths.lessons_questioner_dir_rel == knowledge.rel(LESSONS_QUESTIONER)
    assert DefenderPaths.catalog_rel == knowledge.catalog_rel == CHECKOUT_KNOWLEDGE.rel(CATALOG)
    assert DefenderPaths.skills_rel == knowledge.skills_rel


def test_a_re_rooted_checkout_carries_its_own_knowledge(tmp_path: Path) -> None:
    """A worktree's paths reach the worktree's knowledge, never the running checkout's."""
    wt = DefenderPaths(repo_root=tmp_path)
    assert wt.knowledge.agent_root == tmp_path / "defender"
    assert wt.lessons_dir == tmp_path / "defender" / "lessons"
    assert wt.knowledge.system_skill_dir("cmdb") == tmp_path / "defender" / "skills" / "cmdb"
