"""#869 M5/RF2/U1/U2 — the lead-author commit gate (site 2)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.learning.curation._claim1175 import claim_git
from defender.learning.leads import lead_author
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import (
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
)
from defender.tests.support.runtime.engine._declared869 import (
    CATALOG_REL,
    NESTED_MARKER_RELS,
    SKILLS_REL,
    commit_all,
    head_files,
    seed_tree,
    write,
    write_template,
)
from defender.tests.support.learning.curation._lead_author_1134 import lane_tree_for
from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

NON_SYSTEMS = ("advisory", "connect", "gather", "handbook", "invlang", "judge")

DECLARED = frozenset({"elastic", "cmdb"})


#: The fixture tenant's committed catalog (made-up content, `knowledge/tenant-fixture/agent/`).
#: #1108 P4 O1/O11: the product tree holds no catalog, so a catalog-wide control drives this
#: content instead of the checkout's.
FIXTURE_CATALOG = FIXTURE_AGENT / "skills" / "gather" / "queries"
#: The systems the fixture tenant declares (its one system skill and catalog folder).
FIXTURE_SYSTEMS = frozenset({"cmdb"})


def _fixture_catalog_lane(tmp_path: Path) -> tuple[Path, list[str]]:
    """A gate repo declaring the fixture's systems, holding the fixture's catalog committed at
    the lane's catalog spelling. Returns the repo and the catalog paths it committed."""
    lane = seed_tree(tmp_path, adapters=tuple(FIXTURE_SYSTEMS), markers=tuple(FIXTURE_SYSTEMS),
                     skills=tuple(FIXTURE_SYSTEMS), catalog=(), name="fixture-lane")
    paths = []
    for src in sorted(FIXTURE_CATALOG.rglob("*.md")):
        rel = CATALOG_REL + src.relative_to(FIXTURE_CATALOG).as_posix()
        write(lane / rel, src.read_text(encoding="utf-8"))
        paths.append(rel)
    commit_all(lane, "fixture catalog")
    return lane, paths


def _gate_repo(tmp_path: Path, name: str = "repo") -> Path:
    return seed_tree(
        tmp_path, adapters=("elastic", "cmdb"), markers=("elastic", "cmdb"),
        skills=("elastic", "cmdb"), catalog=("elastic",), non_systems=("gather",), name=name,
    )


def test_skills_path_rule_refuses_an_undeclared_system_skill(tmp_path):
    repo = _gate_repo(tmp_path)
    phantom = write(repo / SKILLS_REL / "fakesys2" / "SKILL.md",
                    "---\nname: defender-fakesys2\n---\n# fakesys2\n")
    assert _is_in_scope("defender/skills/fakesys2/SKILL.md")

    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/fakesys2/SKILL.md", systems=DECLARED,
            tree_for=lane_tree_for(repo))
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))

    assert phantom.is_file(), "the refusal is the gate's, not the filesystem's"
    assert "defender/skills/fakesys2/SKILL.md" not in head_files(repo)


def test_skills_path_rule_refuses_an_undeclared_catalog_system(tmp_path):
    repo = _gate_repo(tmp_path)
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/fakesys/hunt-creds.md",
            systems=DECLARED, tree_for=lane_tree_for(repo))
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/fakesys/_draft/hunt-creds.md",
            systems=DECLARED, tree_for=lane_tree_for(repo))


def test_skills_path_rule_still_admits_the_fixture_tenants_catalog(tmp_path):
    repo = _gate_repo(tmp_path)
    assert "gather" not in DECLARED
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/queries/elastic/auth-events.md",
        systems=DECLARED, tree_for=lane_tree_for(repo)) is None
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/queries/elastic/_draft/new-verb.md",
        systems=DECLARED, tree_for=lane_tree_for(repo)) is None

    lane, committed = _fixture_catalog_lane(tmp_path)
    catalog_paths = [
        p for p in committed if not _is_schema_md(p) and not _is_draft_readme(p)
    ]
    assert catalog_paths, "no committed catalog paths, so the control would be vacuous"
    for path in catalog_paths:
        assert path.split("/")[2] == "gather"
        assert lead_author._skills_path_rule(
            lane, "A ", path, systems=FIXTURE_SYSTEMS, tree_for=lane_tree_for(lane)) is None


def test_the_lane_cannot_commit_a_non_system_skill_md(tmp_path):
    repo = _gate_repo(tmp_path)
    for name in NON_SYSTEMS:
        path = f"defender/skills/{name}/SKILL.md"
        assert _is_in_scope(path), f"{path} is in scope today, which is why it needs refusing"
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(repo, "A ", path, systems=DECLARED,
                                          tree_for=lane_tree_for(repo))

    # Driven through the composed gate over the file G4 actually committed at this base.
    write(repo / SKILLS_REL / "gather" / "SKILL.md",
          "---\nname: defender-gather\n---\n# gather\nedited by the lane\n")
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))

    # The live edge FK-10 leaves open, stated: declare `gather` and the refusal lifts.
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/SKILL.md",
        systems=DECLARED | {"gather"}, tree_for=lane_tree_for(repo)) is None


def test_the_marker_is_the_one_file_the_lane_cannot_commit(tmp_path):
    repo = _gate_repo(tmp_path)
    for admitted in (
        "defender/skills/elastic/SKILL.md",
        "defender/skills/elastic/_draft/x.md",
        "defender/skills/gather/queries/elastic/x.md",
        "defender/skills/gather/queries/elastic/_draft/x.md",
    ):
        assert lead_author._skills_path_rule(repo, "A ", admitted, systems=DECLARED,
                                             tree_for=lane_tree_for(repo)) is None

    # The control for the depth half: the SAME nested directories, one basename over, for the
    # same declared system — still admitted, id-less so RF2's rule spares them.
    for sibling in (
        "defender/skills/elastic/_draft/mcpsys/notes.md",
        "defender/skills/gather/queries/elastic/mcpsys/notes.md",
    ):
        write(repo / sibling, "# a nested note, carrying no id\n")
        assert lead_author._skills_path_rule(repo, "A ", sibling, systems=DECLARED,
                                             tree_for=lane_tree_for(repo)) is None

    assert not _is_in_scope("defender/skills/elastic/execution.md")
    nested_forms = (*NESTED_MARKER_RELS, "defender/skills/gather/queries/elastic/execution.md")
    for nested in nested_forms:
        assert _is_in_scope(nested), f"{nested} left scope; this composition has moved"

    for refused in ("defender/skills/elastic/execution.md", *nested_forms):
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(repo, "A ", refused, systems=DECLARED,
                                          tree_for=lane_tree_for(repo))

    write(repo / SKILLS_REL / "elastic" / "execution.md", "# elastic\n## Common pitfalls\n- x\n")
    before = head_files(repo)
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert head_files(repo) == before

    # And through the composed gate on the NESTED form, which is the one an agent can write
    # today: the file lands in the worktree and the tick still commits nothing.
    (repo / SKILLS_REL / "elastic" / "execution.md").unlink()
    nested = write(repo / NESTED_MARKER_RELS[0], "# mcpsys\n")
    assert nested.is_file(), "the refusal is the gate's, not the filesystem's"
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert head_files(repo) == before


def test_the_commit_gate_refuses_an_id_that_disagrees_with_its_directory(tmp_path):
    repo = _gate_repo(tmp_path)
    write_template(repo, "elastic", "x", tid="fakesys.x")
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/elastic/x.md", systems=DECLARED,
            tree_for=lane_tree_for(repo))

    # The agreeing id, on the same address, is admitted.
    write_template(repo, "elastic", "y")
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/queries/elastic/y.md", systems=DECLARED,
        tree_for=lane_tree_for(repo)) is None

    # Ordering: the delete-prohibition still owns a `D` record on the disagreeing file …
    with pytest.raises(LeadAuthorError, match="deleted"):
        lead_author._skills_path_rule(
            repo, "D ", "defender/skills/gather/queries/elastic/x.md", systems=DECLARED,
            tree_for=lane_tree_for(repo))
    # … and the protected-surface branch still owns SCHEMA.md, whose frontmatter has no id.
    with pytest.raises(LeadAuthorError, match="protected"):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/SCHEMA.md", systems=DECLARED,
            tree_for=lane_tree_for(repo))


def _frontmatter(path: Path) -> dict:
    import yaml

    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end < 0:
        return {}
    try:
        data = yaml.safe_load(text[4:end])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _frontmatter_id(path: Path) -> str | None:
    value = _frontmatter(path).get("id")
    return value if isinstance(value, str) and value else None


def _frontmatter_name(path: Path) -> str | None:
    value = _frontmatter(path).get("name")
    return value if isinstance(value, str) and value else None


def _system_segment(path: str) -> str:
    """The segment the rule keys membership on, by form (F2's two-key reading).

    Catalog paths key on the segment after `queries/`, hopping over `_draft`; system-skill
    and system-draft paths key on the segment after `defender/skills/`. Derived here rather
    than read off the rule, so the two can disagree."""
    parts = path.split("/")
    if path.startswith("defender/skills/gather/queries/"):
        return parts[4]
    return parts[2]
