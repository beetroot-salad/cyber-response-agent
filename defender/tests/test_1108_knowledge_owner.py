"""#1108 P1 — one owner of the agent-knowledge layout.

`defender/_knowledge.py` is the only module that joins a corpus name onto a root: the lesson
corpora, the per-system skills' parent, and the query catalog. Every other reader goes through a
`KnowledgePaths`, so moving the knowledge into each tenant's own repo changes how one is built,
not forty call sites. This census keeps a new hand-spelled join from slipping back in.

It flags, outside the owner (and outside `tests/`):
- a `/` join whose right operand is a corpus name, `"skills"` or `"queries"`;
- a string spelling `defender/lessons`, `defender/skills/` or `gather/queries`.

`ALLOWED` holds every hit that is not a knowledge path, each with why. A `"skills"` join is
allowed only for a GENERAL skill (product code that stays in the checkout) or for a walk that
#1108's later pieces split; adding one there is a classification someone must state.
"""
from __future__ import annotations

import ast
from pathlib import Path

from defender._knowledge import (
    CATALOG, CHECKOUT_AGENT_REL, LESSONS, LESSONS_QUESTIONER, KnowledgePaths, checkout_rel,
)
from defender._paths import PATHS, DefenderPaths

_DEFENDER = Path(__file__).resolve().parents[1]
_OWNER = "_knowledge.py"

_JOIN_NAMES = frozenset({
    "lessons", "lessons-questioner", "lessons-actor", "lessons-environment", "skills", "queries",
})
_SPELLINGS = ("defender/lessons", "defender/skills/", "gather/queries")

#: (file, the flagged literal) -> why it is not a knowledge path built outside the owner.
ALLOWED: dict[tuple[str, str], str] = {
    ("evals/harness.py", "lessons"):
        "a scenario's own `lessons/` folder and the results folder, not a knowledge root",
    ("learning/author/lessons/run.py", "lessons"):
        "the `learning/author/lessons/` package's prompt files, code not knowledge",
    ("runtime/driver/_build.py", "skills"): "gather's own SKILL.md: a general skill",
    ("runtime/orient.py", "skills"): "invlang's SKILL.md: a general skill",
    ("runtime/verb_roster.py", "skills"):
        "the roster file (gather, a general skill) and the model-read-surface walk, which spans "
        "general and per-system skills in one tree until #1108 P4 splits it into two roots",
    ("learning/author/branch.py", "`). Touches `defender/lessons/` only — distinct from the "
     "lead-author PR."): "PR body text; rewritten with the switch (#1108 P4)",
    ("learning/core/drains.py", "`, off freshly-fetched `origin/main`). May also fold "
     "agent-fixable execution failures into"): "PR body text; rewritten with the switch (#1108 P4)",
    ("learning/frontend/serialize.py", "Frozen archive. Both directions that fed it were "
     "deleted with the four-role pipeline (#922"): "prose on the posture page",
    ("learning/leads/lead_author_engine.py", "Blocked: the lead author curates the gather query "
     "catalog and the per-SYSTEM skill docs. I"):
        "model-facing deny text; rewritten with the prompts (#1108 P4)",
    ("learning/leads/pitfalls_curator.py", "defender/skills/gather/defender-sql.md"):
        "the shared SQL guide: a general skill",
    ("learning/ops/trace_lesson.py", "Corpus directory (default: defender/lessons)"):
        "CLI help text",
    ("skills/connect/validate_scaffold.py", "no seed query templates under skills/gather/queries/"):
        "a report message",
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


def _hits(source: Path) -> list[tuple[str, str, int]]:
    rel = source.relative_to(_DEFENDER).as_posix()
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=rel)
    docs = _docstrings(tree)
    found: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant) and node.right.value in _JOIN_NAMES):
            found.append((rel, node.right.value, node.lineno))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docs and any(s in node.value for s in _SPELLINGS)):
            found.append((rel, node.value[:_KEY_LEN], node.lineno))
    return found


def test_no_production_module_spells_a_knowledge_path_outside_the_owner() -> None:
    hits = [h for src in _production_sources() for h in _hits(src)]
    unexplained = [f"{rel}:{line}: {value!r}" for rel, value, line in hits
                   if (rel, value) not in ALLOWED]
    assert unexplained == [], (
        "build these through `defender._knowledge.KnowledgePaths`, or add the literal to "
        "ALLOWED with why it is not a knowledge path:\n" + "\n".join(unexplained))


def test_every_allowance_still_matches_a_hit() -> None:
    """An allowance whose literal is gone would excuse a future hit it was never about."""
    seen = {(rel, value) for src in _production_sources() for rel, value, _ in _hits(src)}
    assert sorted(set(ALLOWED) - seen) == []


def test_the_checkout_paths_pass_through_to_the_owner() -> None:
    """`DefenderPaths` keeps its corpus names, and they are exactly the owner's."""
    knowledge = KnowledgePaths.of_defender_dir(PATHS.defender_dir)
    assert PATHS.knowledge == knowledge
    assert PATHS.lessons_dir == knowledge.lessons_dir == PATHS.defender_dir / LESSONS
    assert PATHS.lessons_questioner_dir == knowledge.corpus_dir(LESSONS_QUESTIONER)
    assert PATHS.catalog_dir == knowledge.catalog_dir == PATHS.defender_dir / CATALOG
    assert PATHS.skills_dir == knowledge.skills_dir
    assert DefenderPaths.lessons_dir_rel == knowledge.rel(LESSONS) == f"{CHECKOUT_AGENT_REL}/lessons/"
    assert DefenderPaths.lessons_questioner_dir_rel == knowledge.rel(LESSONS_QUESTIONER)
    assert DefenderPaths.catalog_rel == knowledge.catalog_rel == checkout_rel(CATALOG)
    assert DefenderPaths.skills_rel == knowledge.skills_rel


def test_a_re_rooted_checkout_carries_its_own_knowledge(tmp_path: Path) -> None:
    """A worktree's paths reach the worktree's knowledge, never the running checkout's."""
    wt = DefenderPaths(repo_root=tmp_path)
    assert wt.knowledge.agent_root == tmp_path / "defender"
    assert wt.lessons_dir == tmp_path / "defender" / "lessons"
    assert wt.knowledge.system_skill_dir("cmdb") == tmp_path / "defender" / "skills" / "cmdb"
