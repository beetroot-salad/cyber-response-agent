"""#869 M5/RF2/U1/U2 — the lead-author commit gate (site 2).

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared869.py`.

Site 2 is the gate that would have refused the phantom draft's commit even with M3 and M4
absent — and, executed at this base (G4), the gate that today ACCEPTS AND COMMITS a
host-minted phantom catalog directory, a brand-new phantom SYSTEM directory, and an edit to a
non-system's `SKILL.md`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _git
from defender.learning.leads import lead_author
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import (
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
)
from defender.runtime import verbs
from defender.runtime.driver import _gather_instructions
from defender.runtime.permission.files import build_write_allow
from defender.tests._declared869 import (
    ADAPTERS_REL,
    NESTED_MARKER_RELS,
    SKILLS_REL,
    git,
    head_files,
    seed_tree,
    write,
    write_template,
)

#: The six directories under `defender/skills/` that no source declares — the ones FK-1
#: refuses all writes to. `judge` carries no `SKILL.md` today; the rule is a path rule, so it
#: answers about the path either way.
NON_SYSTEMS = ("advisory", "connect", "gather", "handbook", "invlang", "judge")

DECLARED = frozenset({"elastic", "cmdb"})


def _real_adapter_systems() -> frozenset[str]:
    """The real tree's declared set, computed HERE from the adapter glob.

    On the committed tree the union equals the adapter set exactly, and that equality is
    itself a demand (`declared_systems_union_is_a_noop_here`) — so a corpus-wide parity drive
    can take the cheaper half without depending on the resolver, and its red stays about the
    rule under test rather than about a module that does not exist yet."""
    d = _git.REPO_ROOT / ADAPTERS_REL
    return frozenset(verbs._system_of(p) for p in d.glob("*" + verbs.ADAPTER_SUFFIX))


def _gate_repo(tmp_path: Path, name: str = "repo") -> Path:
    return seed_tree(
        tmp_path, adapters=("elastic", "cmdb"), markers=("elastic", "cmdb"),
        skills=("elastic", "cmdb"), catalog=("elastic",), non_systems=("gather",), name=name,
    )


def test_skills_path_rule_refuses_an_undeclared_system_skill(tmp_path):
    """The commit gate refuses a brand-new `defender/skills/<undeclared>/SKILL.md`, and the
    tick therefore commits nothing.

    G4, executed at this base: today this gate ACCEPTS AND COMMITS exactly that file. Site 2
    mints phantom SYSTEM directories, not only catalog ones — a second, independent route the
    design's U1/U2 sentences do not name. Driven through the whole composed gate, because the
    per-file rule refusing while the walk that calls it commits anyway would be a green test
    over a shipped hole.
    """
    repo = _gate_repo(tmp_path)
    phantom = write(repo / SKILLS_REL / "fakesys2" / "SKILL.md",
                    "---\nname: defender-fakesys2\n---\n# fakesys2\n")
    assert _is_in_scope("defender/skills/fakesys2/SKILL.md")

    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/fakesys2/SKILL.md", systems=DECLARED)
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)

    assert phantom.is_file(), "the refusal is the gate's, not the filesystem's"
    assert "defender/skills/fakesys2/SKILL.md" not in head_files(repo)


def test_skills_path_rule_refuses_an_undeclared_catalog_system(tmp_path):
    """The catalog form is keyed on the segment after `queries/`, and THAT segment must name
    a declared system: `gather/queries/fakesys/hunt-creds.md` is refused.

    This is the path the host mints from a model-supplied `query_id` (C12/G3), so it is the
    last gate in front of the finding this issue exists to close.
    """
    repo = _gate_repo(tmp_path)
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/fakesys/hunt-creds.md",
            systems=DECLARED)
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/fakesys/_draft/hunt-creds.md",
            systems=DECLARED)


def test_skills_path_rule_still_admits_the_real_catalog(tmp_path):
    """Every real catalog path is still admitted — the key is the segment after `queries/`,
    NOT the `skills/<x>` segment.

    `skills_path_rule_refuses_undeclared_catalog`'s positive control, and the reason this is a
    demand rather than an assumption: EVERY catalog path's `skills/<x>` segment is `gather`,
    which no source declares (G7/R4), so M5 read literally refuses the entire committed
    catalog. The consequence if that reading shipped is "the lead author commits nothing at
    all", and this is the test that catches it — driven over the real committed corpus, whose
    every catalog file has `gather` in that position.
    """
    repo = _gate_repo(tmp_path)
    assert "gather" not in DECLARED
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/queries/elastic/auth-events.md",
        systems=DECLARED) is None
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/queries/elastic/_draft/new-verb.md",
        systems=DECLARED) is None

    real = _real_adapter_systems()
    catalog_paths = [
        p for p in git(_git.REPO_ROOT, "ls-files", "defender/skills/gather/queries/").stdout.split()
        if p.endswith(".md") and not _is_schema_md(p) and not _is_draft_readme(p)
    ]
    assert catalog_paths, "no committed catalog paths, so the control would be vacuous"
    for path in catalog_paths:
        assert path.split("/")[2] == "gather"
        assert lead_author._skills_path_rule(
            _git.REPO_ROOT, "A ", path, systems=real) is None


def test_skills_path_rule_refuses_an_undeclared_system_draft(tmp_path):
    """The third in-scope form: `defender/skills/<undeclared>/_draft/x.md` is refused.

    A universal discharged at two of three forms is not discharged, and this form is the one
    `discover_system_drafts` would otherwise hand the agent as work. The declared system's own
    draft is admitted in the same call, so the refusal is about the name and not about the
    form.
    """
    repo = _gate_repo(tmp_path)
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/fakesys/_draft/hunt-creds.md", systems=DECLARED)
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/elastic/_draft/hunt-creds.md", systems=DECLARED) is None


def test_the_lane_cannot_commit_a_non_system_skill_md(tmp_path):
    """The lead-author lane loses write access to all SIX non-system `SKILL.md` files
    (FK-1, §7): M5 keys on membership with NO exception.

    THIS IS A BEHAVIOUR CHANGE ON A PATH THAT IS LEGAL TODAY, and it is the point: C23 shows
    `_is_system_skill_md` admits `defender/skills/gather/SKILL.md`, and G4 executed a real
    commit of exactly that edit. N3 protected those directories' EXISTENCE, never this lane's
    write access to them. Accepted cost, recorded rather than discovered: `gather/SKILL.md` is
    the gather subagent's ENTIRE system prompt and becomes maintainer-written, with no
    loop-side writer at all.

    REJECTED: carving the six out with a literal exception list — the shape N4/N5 exist to
    avoid, and the shape FK-10 separately declined. Which is why the refusal LIFTS the moment
    a source declares one of them, and that is asserted here too: it is a live edge the design
    states rather than discovers.
    """
    repo = _gate_repo(tmp_path)
    for name in NON_SYSTEMS:
        path = f"defender/skills/{name}/SKILL.md"
        assert _is_in_scope(path), f"{path} is in scope today, which is why it needs refusing"
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(repo, "A ", path, systems=DECLARED)

    # Driven through the composed gate over the file G4 actually committed at this base.
    write(repo / SKILLS_REL / "gather" / "SKILL.md",
          "---\nname: defender-gather\n---\n# gather\nedited by the lane\n")
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)

    # The live edge FK-10 leaves open, stated: declare `gather` and the refusal lifts.
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/SKILL.md",
        systems=DECLARED | {"gather"}) is None


def test_the_gather_subagent_still_loads_its_own_prompt():
    """The gather subagent still resolves and loads its entire system prompt, unchanged, from
    `defender/skills/gather/SKILL.md`.

    FK-1's READ SIDE, bound at THIS reader's own edge because that is what R7 asks — a demand
    at the boundary would read as discharged while this reader went stale. The refusal removes
    a WRITER, never a reader, and this is the demand that catches an implementation that
    "closes the lane" by moving or renaming the file: the write side is driven in the same
    test against the same path, and the reader must still answer from it.
    """
    prompt = _git.REPO_ROOT / SKILLS_REL / "gather" / "SKILL.md"
    assert prompt.is_file()

    loaded = _gather_instructions(_git.REPO_ROOT / "defender")
    assert loaded.strip(), "the gather subagent would dispatch with an empty system prompt"
    body = prompt.read_text(encoding="utf-8")
    assert loaded.strip() in body

    # The write lane onto that same path is closed, in the same drive.
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            _git.REPO_ROOT, "A ", "defender/skills/gather/SKILL.md",
            systems=_real_adapter_systems())


def test_the_marker_is_the_one_file_the_lane_cannot_commit(tmp_path):
    """`execution.md` is the ONE per-system file the lead-author lane cannot get committed —
    AT ANY DEPTH under `defender/skills` — while `SKILL.md`, `_draft/` and every catalog path
    for the same DECLARED system are admitted, at those same depths.

    C32, executed over all seven candidate markers. That refusal — not the filesystem, and not
    the write tool — is what stops an agent that mints a marker from minting a declared
    system, and NF1 makes it MORE central rather than less: with the marker read from the
    committed tree, the commit gate IS the marker's integrity, which is exactly why NF4 chose
    marker existence over a content signature. If a later change admits `execution.md` here,
    the union's whole marker half becomes forgeable by the lane whose gate reads it.

    THE DEPTH HALF (phase F, F1 — human-resolved, BOTH halves). `_is_system_execution_md` is
    an exact-two-segment test, and it is the only thing this rule ever asked about
    `execution.md` — while `_is_in_scope` admits `<declared>/_draft/<anything>/…` and every
    `gather/queries/…` path at any depth. So at this base the gate ADMITS
    `defender/skills/elastic/_draft/mcpsys/execution.md` and
    `defender/skills/gather/queries/elastic/mcpsys/execution.md`, whose parent directory names
    are entirely model-chosen, and a recursive marker read then declares `mcpsys`. The rule
    now keys on the BASENAME anywhere under the tree, so the refusal no longer depends on
    which of the three in-scope forms owns the path.
    `marker_source_is_exactly_depth_one` is the other end of the same composition — one closes
    the read, this closes the write, and neither is asked to carry it alone.

    THE CONTROL FOR THE DEPTH HALF, on the same addresses: a sibling `.md` in those same
    nested directories, for the same declared system, is still ADMITTED — so what fired is the
    basename rule and not a new blanket refusal of depth, which would be a different and
    unresolved behaviour change.

    Bound at every surface the write could reach: the rule refuses, the composed gate refuses,
    and no commit carries the path. `skills_path_rule_admits_declared_catalog` is the paired
    positive control; the sibling paths below are its shape on this address.
    """
    repo = _gate_repo(tmp_path)
    for admitted in (
        "defender/skills/elastic/SKILL.md",
        "defender/skills/elastic/_draft/x.md",
        "defender/skills/gather/queries/elastic/x.md",
        "defender/skills/gather/queries/elastic/_draft/x.md",
    ):
        assert lead_author._skills_path_rule(repo, "A ", admitted, systems=DECLARED) is None

    # The control for the depth half: the SAME nested directories, one basename over, for the
    # same declared system — still admitted, id-less so RF2's rule spares them.
    for sibling in (
        "defender/skills/elastic/_draft/mcpsys/notes.md",
        "defender/skills/gather/queries/elastic/mcpsys/notes.md",
    ):
        write(repo / sibling, "# a nested note, carrying no id\n")
        assert lead_author._skills_path_rule(repo, "A ", sibling, systems=DECLARED) is None

    # The base-state fact the depth half is about, re-measured rather than remembered: the
    # two-segment form is refused today only as OUT OF SCOPE, while every nested form is IN
    # scope — which is why nothing refuses those, and why the rule must key on the basename.
    assert not _is_in_scope("defender/skills/elastic/execution.md")
    nested_forms = (*NESTED_MARKER_RELS, "defender/skills/gather/queries/elastic/execution.md")
    for nested in nested_forms:
        assert _is_in_scope(nested), f"{nested} left scope; this composition has moved"

    for refused in ("defender/skills/elastic/execution.md", *nested_forms):
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(repo, "A ", refused, systems=DECLARED)

    write(repo / SKILLS_REL / "elastic" / "execution.md", "# elastic\n## Common pitfalls\n- x\n")
    before = head_files(repo)
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert head_files(repo) == before

    # And through the composed gate on the NESTED form, which is the one an agent can write
    # today: the file lands in the worktree and the tick still commits nothing.
    (repo / SKILLS_REL / "elastic" / "execution.md").unlink()
    nested = write(repo / NESTED_MARKER_RELS[0], "# mcpsys\n")
    assert nested.is_file(), "the refusal is the gate's, not the filesystem's"
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert head_files(repo) == before


def test_the_marker_write_is_admitted_and_still_never_lands(tmp_path):
    """The agent's write tool ADMITS `defender/skills/<x>/execution.md`; the tick still
    commits nothing.

    THE HONEST CAVEAT, PINNED. C33 refutes "the agent cannot write the marker":
    `build_write_allow(skills, suffix=".md")` compiles to `…/defender/skills/[^\\x00]*\\.md`,
    which MATCHES the marker path — so the file appears in the worktree and a test that only
    asserted the write is denied would pin a guard that does not exist. The boundary is the
    commit gate, never the write tool.

    UNDER NF1 THERE ARE NOW THREE REASONS THE PLANT NEVER COUNTS, and they are kept apart on
    purpose: the write is admitted (asserted here), the COMMIT is refused
    (`marker_is_not_agent_committable`), and even had it landed unrefused it would declare
    nothing until committed (`marker_read_is_from_the_committed_tree`). Folding them into one
    assertion would let a regression in any of the three read as green.
    """
    repo = _gate_repo(tmp_path)
    allow = build_write_allow(repo / SKILLS_REL, suffix=".md")
    marker = repo / SKILLS_REL / "mcpsys" / "execution.md"
    assert allow.fullmatch(str(marker.resolve())), (
        "the write tool does NOT admit the marker path, so this caveat has moved"
    )
    # The confinement it DOES enforce, so the claim is about a real boundary: the adapter
    # module and a non-.md sibling are refused by the same pattern.
    assert not allow.fullmatch(str((repo / ADAPTERS_REL / "mcpsys_adapter.py").resolve()))
    assert not allow.fullmatch(str((repo / SKILLS_REL / "mcpsys" / "config.env").resolve()))

    write(marker, "# mcpsys\n")
    assert marker.is_file()
    before = head_files(repo)
    with pytest.raises(LeadAuthorError):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert head_files(repo) == before


def test_the_commit_gate_refuses_an_id_that_disagrees_with_its_directory(tmp_path):
    """The commit gate refuses a template whose frontmatter `id:` prefix disagrees with the
    directory it sits in, so U1's DIRECTORY channel and its CONTENT channel close together
    (RF2, human-resolved, in scope).

    A file at `gather/queries/elastic/x.md` declaring `id: fakesys.x` is refused even though
    its directory names a declared system — otherwise the phantom simply moves from the path
    into the frontmatter, and `lead_neighbors._resolve_cli` reads it back out.

    ORDERING, from the probe: the id check runs AFTER the delete-prohibition and AFTER the
    protected-surface branch, both asserted here — a `D` record on an established template
    still reports the deletion, and a protected surface still reports the protected surface,
    rather than either being pre-empted by a content read of a file that may not be there.
    """
    repo = _gate_repo(tmp_path)
    write_template(repo, "elastic", "x", tid="fakesys.x")
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/elastic/x.md", systems=DECLARED)

    # The agreeing id, on the same address, is admitted.
    write_template(repo, "elastic", "y")
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/gather/queries/elastic/y.md", systems=DECLARED) is None

    # Ordering: the delete-prohibition still owns a `D` record on the disagreeing file …
    with pytest.raises(LeadAuthorError, match="deleted"):
        lead_author._skills_path_rule(
            repo, "D ", "defender/skills/gather/queries/elastic/x.md", systems=DECLARED)
    # … and the protected-surface branch still owns SCHEMA.md, whose frontmatter has no id.
    with pytest.raises(LeadAuthorError, match="protected"):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/gather/queries/SCHEMA.md", systems=DECLARED)


def test_the_id_rule_still_admits_every_committed_id():
    """Every committed in-scope file that carries a frontmatter `id:` still passes the rule —
    the id-prefix invariant holds over the whole in-scope corpus, not only the catalog.

    C35: 33 of the in-scope `.md` files carry an `id:` and 33 of 33 match, and the rule
    extends PAST the catalog to `skills/<system>/_draft/*.md`, whose ids are directory-
    matching today — a rule scoped to the catalog alone would leave that surface open.
    `catalog_id_prefix_equals_directory`'s positive control, and the parity floor below keeps
    it from passing over an empty census.

    The two `_draft/README` surface declarations carry an id and are counted in the census,
    but they are refused by the protected-surface branch for a reason that predates this
    change, so they are not driven through the rule.
    """
    root = _git.REPO_ROOT
    real = _real_adapter_systems()
    in_scope = [
        p for p in git(root, "ls-files", SKILLS_REL).stdout.split()
        if p.endswith(".md") and _is_in_scope(p)
    ]
    with_id = {p: _frontmatter_id(root / p) for p in in_scope}
    with_id = {p: i for p, i in with_id.items() if i}
    assert len(with_id) >= 33, f"the census floor moved: {len(with_id)} ids over {len(in_scope)}"

    mismatched = [
        p for p, ident in with_id.items() if ident.split(".", 1)[0] != _system_segment(p)
    ]
    assert mismatched == []

    for path in with_id:
        if _is_draft_readme(path) or _is_schema_md(path):
            continue
        assert lead_author._skills_path_rule(root, "A ", path, systems=real) is None


def test_the_id_rule_spares_the_idless_surfaces(tmp_path):
    """A file that carries no `id:` at all is NOT refused for lacking one.

    The domain member that keeps RF2's rule from closing the whole system-skill surface: the
    system `SKILL.md` files and `SCHEMA.md` carry no `id:` (C35), so a rule that refused an
    id-less in-scope file would refuse all of them.

    AND THIS IS WHERE NF3 IS PINNED (§7, auto-resolved): the id rule does NOT extend to
    `SKILL.md`'s `name:` field. Because the rule reads `id:` and only `id:`, a `SKILL.md`
    whose `name:` disagrees with its directory is still admitted — R4's "the advertised
    combination works" half, asserted rather than assumed. `catalog_id_prefix_equals_directory`
    is the paired control: on the same address, a file that DOES carry a disagreeing id is
    refused, so this is not a rule that admits everything.
    """
    root = _git.REPO_ROOT
    real = _real_adapter_systems()
    declared_skill_mds = [
        p for p in git(root, "ls-files", SKILLS_REL).stdout.split()
        if p.endswith("/SKILL.md") and p.split("/")[2] in real
    ]
    assert declared_skill_mds, "no declared system carries a SKILL.md, so this is vacuous"
    for path in declared_skill_mds:
        assert _frontmatter_id(root / path) is None
        assert lead_author._skills_path_rule(root, "A ", path, systems=real) is None

    # NF3's crossing, CONSTRUCTED rather than hunted for: the two committed `SKILL.md` files
    # whose `name:` does not follow `defender-<dir>` (`advisory`, `connect`) belong to
    # directories no source declares, so the real corpus cannot exhibit the combination at all
    # — a loop over it would be vacuously green and would certify nothing.
    repo = _gate_repo(tmp_path, name="nf3")
    write(repo / SKILLS_REL / "elastic" / "SKILL.md",
          "---\nname: defender-something-else\n---\n# elastic\n")
    assert _frontmatter_name(repo / SKILLS_REL / "elastic" / "SKILL.md") != "defender-elastic"
    assert _frontmatter_id(repo / SKILLS_REL / "elastic" / "SKILL.md") is None
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/elastic/SKILL.md", systems=DECLARED) is None


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
