"""O-TEXT — every path the model is shown is rendered from `KnowledgePaths` or the model view
(#1108 P4).

After P4 the tenant's knowledge lives under an agent root (`$DEFENDER_AGENT_DIR`, a run copy or
a draft), still in its relative shape (`lessons/`, `skills/<system>/`, `skills/gather/queries/`).
So a bare relative spelling is not old; what is old is the PRODUCT TREE's spelling of tenant
knowledge — `defender/lessons`, `defender/skills/<system>`, `defender/skills/gather/queries` —
and the names of things P4 deletes or moves (`SCHEMA.md`, the retired corpora, the roster
file, P2's `/tenant/agent` mount).

This census has no suppression marker: a line that must name an old spelling does not exist in
model-facing text or production code after P4. Its only allowlist entry is the layout owner.
"""
from __future__ import annotations

import ast
import json
import re

from defender.tests.support.shared.contracts._by_path import WORKTREE
from defender.tests.tenancy.tenant_1108_delivery.test_architecture import (
    _agent_facing_text, _folded, non_docstring_nodes, production_trees,
)

PRODUCT_SKILLS = ("gather", "invlang", "handbook", "advisory", "connect")
#: A root that is the product tree: `defender/`, `DEFENDER_DIR/`, `$DEFENDER_DIR/`,
#: `{defender_dir}/`, `${DEFENDER_DIR}/`.
_PRODUCT = r"(?i:\bdefender(?:_dir)?\}?)/"

#: Each old spelling, with why it is old.
OLD_SPELLINGS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(_PRODUCT + r"lessons\b"),
     "a lesson corpus in the product tree (O1: the corpora live under the agent root)"),
    (re.compile(_PRODUCT + r"skills/gather/queries\b"),
     "the query catalog in the product tree (O1)"),
    (re.compile(_PRODUCT + r"skills/(?!(?:" + "|".join(PRODUCT_SKILLS) + r")\b)[\w<{$-]"),
     "a tenant system skill in the product tree (O1: skills/ holds only the five product skills)"),
    (re.compile(r"\bSCHEMA\.md\b"),
     "the catalog schema's old name (moved to skills/gather/query-schema.md)"),
    (re.compile(r"\blessons-(?:actor|environment)\b"),
     "a retired corpus (U5: deleted, not archived)"),
    (re.compile(r"\bverb-roster\.md\b"),
     "the committed verb roster (deleted; O10 retired in P2)"),
    (re.compile(r"/tenant/agent\b"),
     "P2's in-box tenant agent mount (retired: the box mounts the run copy's agent/)"),
)

#: `{path under the repo: reason}` — the one owner of the layout may spell its own names.
ALLOWLIST = {
    "defender/knowledge/_knowledge.py": "KnowledgePaths' module: the one owner of the layout (O4)",
}


def old_spellings(text: str) -> list[str]:
    return [f"{m.group(0)!r} ({why})" for pattern, why in OLD_SPELLINGS
            for m in pattern.finditer(text)]


def test_the_old_spellings_are_recognised_and_the_new_ones_are_not():
    """O-TEXT (oracle self-check): each old spelling is refused; the agent-root spellings that
    replace them, the product's own skills, and a code package that happens to be called
    `lessons` are not."""
    old = [
        "Read defender/lessons/x.md", "/workspace/defender/lessons-questioner/",
        "`{defender_dir}/skills/gather/queries/cmdb`", "$DEFENDER_DIR/skills/cmdb/SKILL.md",
        "defender/skills/<system>/execution.md", "defender/skills/{system}/SKILL.md",
        "see queries/SCHEMA.md", "lessons-actor/", "skills/gather/verb-roster.md",
        "mounted at /tenant/agent",
    ]
    new = [
        "$DEFENDER_AGENT_DIR/lessons/x.md", "/agent/skills/gather/queries/cmdb/t.md",
        "agent/skills/cmdb/SKILL.md", "defender/skills/gather/query-schema.md",
        "defender/skills/invlang/SKILL.md", "defender/skills/handbook/content/design.md",
        "defender/skills/connect/adapter.md", "defender/learning/author/lessons/prompt.md",
        "lessons_dir", "the verb roster",
    ]
    assert [s for s in old if not old_spellings(s)] == []
    assert [(s, old_spellings(s)) for s in new if old_spellings(s)] == []


def test_model_facing_text_names_no_product_tree_knowledge_path():
    """O-TEXT: no text a model may be handed — `SKILL.md`s, gather/handbook/connect pages,
    learning prompts, and the template and fixture tenants' `agent/` — spells an old path."""
    found: list[str] = []
    for path in _agent_facing_text():
        rel = path.relative_to(WORKTREE).as_posix()
        if rel in ALLOWLIST:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            found.extend(f"{rel}:{lineno} {hit}" for hit in old_spellings(line))
    assert found == [], f"{len(found)} old spelling(s) in model-facing text:\n  " + "\n  ".join(found)


def test_production_code_spells_no_product_tree_knowledge_path():
    """O-TEXT: no string a production module builds — a `list_verbs` or query error, a deny
    text, a prompt, a pathspec — spells an old path. Folded constants (`+`, f-strings of
    literals, `"/".join([...])`) count; docstrings and comments are not strings the model is
    shown."""
    found: set[str] = set()
    for rel, tree in production_trees():
        path = f"defender/{rel}"
        if path in ALLOWLIST:
            continue
        for node in non_docstring_nodes(tree):
            if isinstance(node, ast.expr_context):
                continue
            value = _folded(node)
            if value is not None:
                found.update(f"{path}:{node.lineno} {hit}" for hit in old_spellings(value))
    assert sorted(found) == [], f"{len(found)} old spelling(s) in production code:\n  " + \
        "\n  ".join(sorted(found))


def test_the_code_census_reads_folded_constants(tmp_path):
    """O-TEXT positive control on the code channel: a spelling assembled by `+`, by an
    f-string of literals, or by a literal `"/".join`, is folded and caught; a docstring is
    not a model-facing string."""
    tree = ast.parse(
        '"""Module docs may cite defender/lessons/ history."""\n'
        'A = "defender/" + "lessons/x.md"\n'
        'B = f"{\'defender\'}/skills/cmdb"\n'
        'C = "/".join(["defender", "skills", "gather", "queries"])\n'
        'D = "$DEFENDER_AGENT_DIR/lessons/x.md"\n'
    )
    caught = {node.lineno for node in non_docstring_nodes(tree)
              if not isinstance(node, ast.expr_context)
              and old_spellings(_folded(node) or "")}
    assert caught == {2, 3, 4}, caught


# --- the existing lints are updated, not suppressed -------------------------------------------

LINT = WORKTREE / "tooling" / "lint"
#: The lints that carve tenant-knowledge directories out of their scope (`EXCLUDED_PREFIXES`,
#: `EXCLUDED_GREP_DIRS`) and their baselines. Once the directories are gone, a carve-out naming
#: one is dead configuration that would quietly exempt anything re-created there.
UPDATED_LINTS = ("lint_stale_refs", "lint_shippable_surface", "lint_ci_hygiene")


def test_the_scope_lints_carve_out_no_product_tree_knowledge():
    """O-TEXT: the stale-ref, shippable-surface and ci-hygiene lints (sources and baselines)
    name no product-tree knowledge directory — their carve-outs are updated to the new layout
    rather than left to exempt paths that no longer exist."""
    found: list[str] = []
    for stem in UPDATED_LINTS:
        for path in (LINT / f"{stem}.py", LINT / f"{stem}_baseline.json"):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                json.loads(text)  # a baseline is data; an unreadable one is not "clean"
            for lineno, line in enumerate(text.splitlines(), 1):
                found.extend(f"{path.relative_to(WORKTREE)}:{lineno} {h}" for h in old_spellings(line))
    assert found == [], "\n  ".join(["lints still carve out product-tree knowledge:", *found])


# --- rendered paths come from the run's knowledge root and model view -------------------------

def test_the_workspace_map_names_knowledge_through_the_run_copy(tmp_path):
    """O-TEXT / O2 (orient's view mapping): with a run view whose agent tree is the run copy,
    the workspace map's system-skill and query-template sections name the agent tree's model
    paths and list the run copy's content — never the product tree's, which holds none."""
    from defender.presentation.workspace_map import workspace_map
    from defender.runtime.model_view import ModelView

    product = tmp_path / "product" / "defender"
    for skill in PRODUCT_SKILLS:
        (product / "skills" / skill).mkdir(parents=True)
        (product / "skills" / skill / "SKILL.md").write_text(f"# {skill}\n", encoding="utf-8")
    (product / "integrations").mkdir()
    agent = tmp_path / "run-knowledge" / "r1" / "agent"
    (agent / "lessons").mkdir(parents=True)
    (agent / "lessons" / "made-up-lesson.md").write_text("---\nname: x\n---\nbody\n", encoding="utf-8")
    (agent / "skills" / "zebra-ledger").mkdir(parents=True)
    (agent / "skills" / "zebra-ledger" / "SKILL.md").write_text("# zebra-ledger\n", encoding="utf-8")
    (agent / "skills" / "gather" / "queries" / "zebra-ledger").mkdir(parents=True)
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)

    view = ModelView.for_run(run_dir, product, tenant_agent=agent)
    text = workspace_map(run_dir, systems=["zebra-ledger"], view=view)

    skills = next(line for line in text.splitlines() if line.startswith("## System skills"))
    queries = next(line for line in text.splitlines() if line.startswith("## Gather query templates"))
    assert "`/agent/skills/`" in skills, skills
    assert "`/agent/skills/gather/queries/`" in queries, queries
    assert "- zebra-ledger (SKILL.md)" in text, "the run copy's system skill is listed"
    assert "/defender/" not in skills, skills
    assert "/defender/" not in queries, queries
    assert old_spellings(text) == [], old_spellings(text)
    assert str(tmp_path) not in text, "a host path reached the model"
