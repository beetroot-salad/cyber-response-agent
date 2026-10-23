"""#869 M5/RF2/U1/U2 — the lead-author commit gate (site 2).

#1108 P4 (O7, OD6): the lane writes a batch's git-free draft; the gate judges repo-relative
`agent/skills/...` paths and, composed, the batch's `ChangeSet`. The draft is built for real
(`_curator1134.draft_lane`, lane `skills`).
ASSUMED SEAMS (S-H): `_skills_path_rule(root, xy, path, *, systems, tree_for)` keeps its shape with
`root` the draft root and `xy` derived from the `ChangeSet` (deletion = `D `); the composed gate is
`_verify_skills_state(root, *, change_set, systems, tree_for)` (the `ChangeSet` replaces
`baseline_stray`/`git`).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core.lane_trees import DrainTrees
from defender.learning.leads import lead_author
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import (
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

NON_SYSTEMS = ("advisory", "connect", "gather", "handbook", "invlang", "judge")

DECLARED = frozenset({"elastic", "cmdb"})

#: The repo-relative spellings after P4 (OD6).
SKILLS_REL = "agent/skills/"
CATALOG_REL = "agent/skills/gather/queries/"
#: #869 F1's two nested `execution.md` addresses (`_declared869.NESTED_MARKER_RELS`), at the
#: draft's spelling.
NESTED_MARKER_RELS = (
    "agent/skills/elastic/_draft/mcpsys/execution.md",
    "agent/skills/gather/queries/elastic/mcpsys/execution.md",
)

#: The fixture tenant's committed catalog (made-up content, `knowledge/tenant-fixture/agent/`).
FIXTURE_CATALOG = FIXTURE_AGENT / "skills" / "gather" / "queries"
#: The systems the fixture tenant declares (its one system skill and catalog folder).
FIXTURE_SYSTEMS = frozenset({"cmdb"})


def _template(system: str, stem: str, *, tid: str | None = None) -> str:
    ident = f"{system}.{stem}" if tid is None else tid
    return f"---\nid: {ident}\nstatus: established\n---\n\n## Goal\n\nprobe\n\n## Query\n\nx\n"


def _skill(system: str) -> str:
    return f"---\nname: defender-{system}\n---\n# {system}\n"


def _gate_files(*, systems=("elastic", "cmdb"), catalog=("elastic",), non_systems=("gather",)):
    """The lead lane's tree (`_declared869.seed_tree`'s content) agent-relative: each system's
    `SKILL.md` and marker `execution.md`, each non-system `SKILL.md`, a catalog template."""
    files: dict[str, str] = {}
    for system in systems:
        files[f"skills/{system}/SKILL.md"] = _skill(system)
        files[f"skills/{system}/execution.md"] = "# execution\n"
    for name in non_systems:
        files[f"skills/{name}/SKILL.md"] = _skill(name)
    for system in catalog:
        files[f"skills/gather/queries/{system}/auth-events.md"] = _template(system, "auth-events")
    return files


def _gate_lane(tmp_path: Path, **kw) -> C.DraftLane:
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files=_gate_files(**kw))


def _tree_for(lane: C.DraftLane):
    """The lead lane's held `skills/` mount over the draft (open while referenced)."""
    return DrainTrees.open((lane.skills_dir,)).tree_for


def _root(lane: C.DraftLane) -> Path:
    return lane.root


def _write(lane: C.DraftLane, rel: str, text: str) -> Path:
    """`rel` (repo-relative, `agent/...`) written into the draft."""
    at = _root(lane) / rel
    C.put(at, text)
    return at


def _composed(lane: C.DraftLane, systems=DECLARED):
    """The composed gate over the claim the batch derives from its draft (real P3 `ChangeSet`)."""
    return lead_author._verify_skills_state(
        _root(lane), change_set=lane.batch.change_set(), systems=systems,
        tree_for=_tree_for(lane))


def test_skills_path_rule_refuses_an_undeclared_system_skill(tmp_path):
    """#869 M5: an undeclared system's SKILL.md is refused, by the rule and the composed gate."""
    lane = _gate_lane(tmp_path)
    phantom = _write(lane, "agent/skills/fakesys2/SKILL.md",
                     "---\nname: defender-fakesys2\n---\n# fakesys2\n")
    assert _is_in_scope("agent/skills/fakesys2/SKILL.md")

    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            _root(lane), "A ", "agent/skills/fakesys2/SKILL.md", systems=DECLARED,
            tree_for=_tree_for(lane))
    with pytest.raises(LeadAuthorError):
        _composed(lane)

    assert phantom.is_file(), "the refusal is the gate's, not the filesystem's"
    assert lane.landed() == []


def test_skills_path_rule_refuses_an_undeclared_catalog_system(tmp_path):
    """#869 M5: a catalog template (or draft) under an undeclared system is refused."""
    lane = _gate_lane(tmp_path)
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            _root(lane), "A ", "agent/skills/gather/queries/fakesys/hunt-creds.md",
            systems=DECLARED, tree_for=_tree_for(lane))
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            _root(lane), "A ", "agent/skills/gather/queries/fakesys/_draft/hunt-creds.md",
            systems=DECLARED, tree_for=_tree_for(lane))
    # Control on the same channel: the declared system's catalog template is admitted.
    assert lead_author._skills_path_rule(
        _root(lane), "A ", "agent/skills/gather/queries/elastic/auth-events.md",
        systems=DECLARED, tree_for=_tree_for(lane)) is None


def test_skills_path_rule_still_admits_the_fixture_tenants_catalog(tmp_path):
    """#869 M5 control: declared catalog paths are admitted, and so is every template of the
    fixture tenant's committed catalog (O11: fixture content, not the checkout's)."""
    lane = _gate_lane(tmp_path)
    assert "gather" not in DECLARED
    _write(lane, "agent/skills/gather/queries/elastic/_draft/new-verb.md",
           _template("elastic", "new-verb"))
    assert lead_author._skills_path_rule(
        _root(lane), "A ", "agent/skills/gather/queries/elastic/auth-events.md",
        systems=DECLARED, tree_for=_tree_for(lane)) is None
    assert lead_author._skills_path_rule(
        _root(lane), "A ", "agent/skills/gather/queries/elastic/_draft/new-verb.md",
        systems=DECLARED, tree_for=_tree_for(lane)) is None

    fixture = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, agent=FIXTURE_AGENT)
    committed = sorted(
        CATALOG_REL + src.relative_to(FIXTURE_CATALOG).as_posix()
        for src in FIXTURE_CATALOG.rglob("*.md"))
    catalog_paths = [
        p for p in committed if not _is_schema_md(p) and not _is_draft_readme(p)
    ]
    assert catalog_paths, "no committed catalog paths, so the control would be vacuous"
    for path in catalog_paths:
        assert (_root(fixture) / path).is_file(), path
        assert path.split("/")[2] == "gather"
        assert lead_author._skills_path_rule(
            _root(fixture), "A ", path, systems=FIXTURE_SYSTEMS,
            tree_for=_tree_for(fixture)) is None


def test_the_lane_cannot_commit_a_non_system_skill_md(tmp_path):
    """#869 U1: a non-system `SKILL.md` in the draft is refused unless that name is declared."""
    lane = _gate_lane(tmp_path)
    for name in NON_SYSTEMS:
        path = f"agent/skills/{name}/SKILL.md"
        assert _is_in_scope(path), f"{path} is in scope today, which is why it needs refusing"
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(_root(lane), "A ", path, systems=DECLARED,
                                          tree_for=_tree_for(lane))

    # Driven through the composed gate over the file the draft carries from its export.
    _write(lane, "agent/skills/gather/SKILL.md",
           "---\nname: defender-gather\n---\n# gather\nedited by the lane\n")
    with pytest.raises(LeadAuthorError):
        _composed(lane)

    # The live edge FK-10 leaves open, stated: declare `gather` and the refusal lifts.
    assert lead_author._skills_path_rule(
        _root(lane), "A ", "agent/skills/gather/SKILL.md",
        systems=DECLARED | {"gather"}, tree_for=_tree_for(lane)) is None


def test_the_marker_is_the_one_file_the_lane_cannot_commit(tmp_path):
    """#869 U2/F1: a system's marker `execution.md`, top-level or nested, never lands."""
    lane = _gate_lane(tmp_path)
    _write(lane, "agent/skills/elastic/_draft/x.md", "# a draft\n")
    _write(lane, "agent/skills/gather/queries/elastic/x.md", _template("elastic", "x"))
    _write(lane, "agent/skills/gather/queries/elastic/_draft/x.md", _template("elastic", "x"))
    for admitted in (
        "agent/skills/elastic/SKILL.md",
        "agent/skills/elastic/_draft/x.md",
        "agent/skills/gather/queries/elastic/x.md",
        "agent/skills/gather/queries/elastic/_draft/x.md",
    ):
        assert lead_author._skills_path_rule(_root(lane), "A ", admitted, systems=DECLARED,
                                             tree_for=_tree_for(lane)) is None

    # The control for the depth half: the SAME nested directories, one basename over, for the
    # same declared system — still admitted, id-less so RF2's rule spares them.
    for sibling in (
        "agent/skills/elastic/_draft/mcpsys/notes.md",
        "agent/skills/gather/queries/elastic/mcpsys/notes.md",
    ):
        _write(lane, sibling, "# a nested note, carrying no id\n")
        assert lead_author._skills_path_rule(_root(lane), "A ", sibling, systems=DECLARED,
                                             tree_for=_tree_for(lane)) is None

    assert not _is_in_scope("agent/skills/elastic/execution.md")
    nested_forms = (*NESTED_MARKER_RELS, "agent/skills/gather/queries/elastic/execution.md")
    for nested in nested_forms:
        assert _is_in_scope(nested), f"{nested} left scope; this composition has moved"

    for refused in ("agent/skills/elastic/execution.md", *nested_forms):
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(_root(lane), "A ", refused, systems=DECLARED,
                                          tree_for=_tree_for(lane))

    marker_lane = _gate_lane(tmp_path)
    _write(marker_lane, "agent/skills/elastic/execution.md", "# elastic\n## Common pitfalls\n- x\n")
    with pytest.raises(LeadAuthorError):
        _composed(marker_lane)
    assert marker_lane.landed() == []

    # And through the composed gate on the NESTED form: the file lands in the draft and the
    # claim still commits nothing.
    nested_lane = _gate_lane(tmp_path)
    nested = _write(nested_lane, NESTED_MARKER_RELS[0], "# mcpsys\n")
    assert nested.is_file(), "the refusal is the gate's, not the filesystem's"
    with pytest.raises(LeadAuthorError):
        _composed(nested_lane)
    assert nested_lane.landed() == []


def test_the_commit_gate_refuses_an_id_that_disagrees_with_its_directory(tmp_path):
    """#869 RF2: a template whose id disagrees with its directory is refused; the agreeing one
    is admitted; deletion and the protected surface keep their own refusals."""
    lane = _gate_lane(tmp_path)
    _write(lane, "agent/skills/gather/queries/elastic/x.md", _template("elastic", "x", tid="fakesys.x"))
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            _root(lane), "A ", "agent/skills/gather/queries/elastic/x.md", systems=DECLARED,
            tree_for=_tree_for(lane))

    # The agreeing id, on the same address, is admitted.
    _write(lane, "agent/skills/gather/queries/elastic/y.md", _template("elastic", "y"))
    assert lead_author._skills_path_rule(
        _root(lane), "A ", "agent/skills/gather/queries/elastic/y.md", systems=DECLARED,
        tree_for=_tree_for(lane)) is None

    # Ordering: the delete-prohibition still owns a `D` record on the disagreeing file …
    with pytest.raises(LeadAuthorError, match="deleted"):
        lead_author._skills_path_rule(
            _root(lane), "D ", "agent/skills/gather/queries/elastic/x.md", systems=DECLARED,
            tree_for=_tree_for(lane))
    # … and the protected-surface branch still owns a catalog-root SCHEMA.md, whose frontmatter
    # has no id (needs-implementation-check: O1 moves the product schema to
    # `defender/skills/gather/query-schema.md`; a tenant-catalog `SCHEMA.md` stays protected).
    _write(lane, "agent/skills/gather/queries/SCHEMA.md", "# template schema\n")
    with pytest.raises(LeadAuthorError, match="protected"):
        lead_author._skills_path_rule(
            _root(lane), "A ", "agent/skills/gather/queries/SCHEMA.md", systems=DECLARED,
            tree_for=_tree_for(lane))
