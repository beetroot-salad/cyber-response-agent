"""#869 — the cross-site universal, the second empty-set boundary, and the two unmoved readers.

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared869.py`.

U1's discharge standard is a CENSUS with a test at each member, not a guard plus prose: a
universal discharged at three of four sites is not discharged.
"""
from __future__ import annotations

import dataclasses
import shutil
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, lead_neighbors, pitfalls_curator
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.runtime.query_tool import QueryCapture
from defender.runtime.verb_grant import DENY_ALL
from defender.runtime.verbs import ModuleVerbRegistry
from defender.tests._declared869 import (
    CATALOG_REL,
    SKILLS_REL,
    LeadAuthorSpawn,
    git,
    head_files,
    seed_tree,
    write,
)

#: The name driven at every composition site. It must be undeclared under BOTH membership
#: readings (NF2): a MARKER-ONLY name is declared at the three union sites and undeclared at
#: the pitfalls gate, so using one here would make this "parity" assert a divergence the
#: design requires.
PHANTOM = "fakesys"

DECLARED = frozenset({"elastic"})


def _lead(query_id: str, *, system: str) -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb="esql", params={"query": "FROM logs"},
        raw_command="", goal_text="probe the thing", what_to_summarize=(),
        raw_ref=Path("gather_raw/l-001/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None,
    )


class _RaisingRegistry:
    """A registry that cannot list its systems — the fault C16/G8 executed against the real
    one, injected here as its exception class and nothing else. It classifies nothing and
    decides nothing; the coarsening and the stderr line below are production code's."""

    def systems(self):
        raise PermissionError(13, "Permission denied")


def test_runtime_system_of_record_is_unchanged(tmp_path, capsys):
    """The runtime's own reader of the adapter source is untouched by the widening: it still
    coarsens an undeclared system to `''`, and it still says so on stderr when the registry
    cannot list at all.

    N1, bound at THIS READER'S OWN EDGE because that is what R7 asks. This change is the
    offline half plus the one writer; the runtime dispatch keeps answering the narrower
    adapter question, and §7 settled why the other two unmoved readers of the same source need
    no coverage rather than leaving it open — NF2 keeps the pitfalls lane adapter-only, so the
    only membership value that diverges from the runtime's is the path-composition lane's,
    which none of them consults.
    """
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    write(adapters / "elastic_adapter.py", "VERBS = {}\n")
    write(adapters / "cmdb_adapter.py", "VERBS = {}\n")
    registry = ModuleVerbRegistry(adapters, DENY_ALL)
    capture = QueryCapture(registry)

    assert registry.systems() == ("cmdb", "elastic")
    assert capture._system_of_record("elastic") == "elastic"
    assert capture._system_of_record("mcpsys") == ""
    assert capture._system_of_record("gather") == ""
    assert capture._system_of_record("") == ""

    capsys.readouterr()
    assert QueryCapture(_RaisingRegistry())._system_of_record("elastic") == ""
    err = capsys.readouterr().err
    assert "query_tool" in err
    assert "PermissionError" in err


def test_every_path_composition_site_refuses_an_undeclared_name(tmp_path, monkeypatch):
    """The SAME undeclared name, driven at each of the FOUR sites that spend a name as a path
    component, produces a write at NONE of them.

    U1's discharge standard as one test over the census, bound per access cell so the parity
    is per-surface and cannot be discharged facet-wide. FK-4 grew the census from three sites
    to four: `discover_system_drafts` joins it, and gets no access cell of its own because it
    composes a path and hands it ONWARD without writing — its surface is the handoff.

    THE FIXTURE TRAP NF2 ADDS, and this is where the two membership values bite first: the
    name driven here is undeclared under BOTH readings. A marker-only name is declared at the
    three union sites and undeclared at the pitfalls gate, so using one would make this
    "parity" assert a divergence the design requires.

    The declared name is driven through the same four sites in the same test, so a set of
    predicates that refused everything could not pass.
    """
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",), non_systems=("gather",))
    skills = repo / SKILLS_REL
    catalog = repo / CATALOG_REL
    write(skills / PHANTOM / "_draft" / "hunt-creds.md",
          f"---\nid: {PHANTOM}.hunt-creds\nstatus: draft\n---\n\n## Goal\n\nx\n")
    write(skills / "elastic" / "_draft" / "lift-me.md",
          "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a phantom draft dir and a real one")
    before = head_files(repo)

    # site 1 — the pitfalls gate
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", f"defender/skills/{PHANTOM}/execution.md", systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "defender/skills/elastic/execution.md", systems=DECLARED) is None

    # site 2 — the lead-author commit gate, over all three in-scope forms
    for form in (
        f"defender/skills/{PHANTOM}/SKILL.md",
        f"defender/skills/{PHANTOM}/_draft/hunt-creds.md",
        f"defender/skills/gather/queries/{PHANTOM}/hunt-creds.md",
    ):
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(repo, "A ", form, systems=DECLARED)
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/elastic/_draft/lift-me.md", systems=DECLARED) is None

    # site 3 — the host-side draft writer
    assert synthesize_drafts(
        [_lead(f"{PHANTOM}.hunt-creds", system=PHANTOM)],
        catalog_dir=catalog, catalog=[], systems=DECLARED,
    ) == []
    assert synthesize_drafts(
        [_lead("elastic.hunt-creds", system="elastic")],
        catalog_dir=catalog, catalog=[], systems=DECLARED,
    ) == [catalog / "elastic" / "_draft" / f"{_draft_basename('elastic.hunt-creds')}.md"]

    # site 4 — the draft discovery that hands the agent its work
    found = lead_author.discover_system_drafts(skills_dir=skills, systems=DECLARED)
    handed = lead_author.build_system_draft_handoffs(found, repo_root=repo)
    assert [h["system"] for h in handed] == ["elastic"]

    # and NOTHING anywhere under the tree was written for the phantom by any of the four.
    assert not (catalog / PHANTOM).exists()
    assert sorted(p for p in git(repo, "status", "--porcelain").stdout.split() if PHANTOM in p) == []
    assert head_files(repo) == before


def test_an_empty_declared_set_refuses_the_lead_author_lane(tmp_path, monkeypatch):
    """With `systems == frozenset()` the lead-author lane refuses LOUDLY and commits nothing —
    never a quiet per-path "no" that looks like ordinary membership enforcement.

    RF6 states the empty-set refusal as a per-boundary universal — "AT EACH BOUNDARY an empty
    declared set is a refusal to run the lane" — and `empty_declared_set_refuses_the_lane`
    pins it only at the pitfalls curator. This is the same unsafe state one boundary over: an
    empty set spent as an ordinary membership answer would have the commit gate refuse every
    catalog and system-skill path ONE FILE AT A TIME, which is the failure O4 names.

    The discriminator is that it refuses BEFORE the agent runs and regardless of what the
    agent does: the drive hands the lane an agent that edits nothing at all, where a per-path
    refusal would have nothing to refuse and the tick would report a clean no-op.
    """
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=(), markers=(), skills=(), catalog=(),
                     non_systems=("gather",))
    write(repo / SKILLS_REL / "gather" / "_draft" / "lift-me.md",
          "---\nid: gather.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a pending draft under a tree that declares nothing")
    before = head_files(repo)

    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    spawn = LeadAuthorSpawn()
    deps = dataclasses.replace(
        lead_author.build_lead_author_deps(paths),
        invoke_agent=spawn, extract=lambda _rd: ([], []),
        acquire_queue_lock=lambda: object(), release_queue_lock=lambda _fh: None,
    )
    assert deps.systems == frozenset()

    run_dir = tmp_path / "run-x"
    (run_dir / "gather_raw").mkdir(parents=True)
    with pytest.raises(LeadAuthorError):
        lead_author.run(run_dir, paths=paths, deps=deps)

    assert spawn.calls == [], "the agent must not be spawned against an empty declared set"
    assert head_files(repo) == before
    assert git(repo, "status", "--porcelain").stdout == ""


def test_directory_and_id_prefix_derivations_agree_on_the_gated_catalog(tmp_path):
    """The catalog's two readers agree: `iter_query_templates` derives a template's system
    from its DIRECTORY and `lead_neighbors._resolve_cli` derives it from the `id:` PREFIX, and
    over every gated entry the two report the SAME system.

    R7 at the readers' own edges. `catalog_dir` moves under this delta — RF2 now enforces
    id-prefix == directory AT THE COMMIT GATE — and `catalog_id_prefix_equals_directory` pins
    the WRITER; nothing pinned the READERS, and a boundary-altitude demand reads as discharged
    for "two of three moved", which is the altitude collapse this rule exists to catch.

    Driven over the committed corpus AND over an agent-authored draft the new gate now admits,
    in a copy of the corpus so the real tree is untouched. The deferred half is not this
    demand's: whether either join can go EMPTY at write time transfers to write-code-from-spec
    as an R8 census; this is the agreement half only.
    """
    real_catalog = _git.REPO_ROOT / CATALOG_REL
    committed = lead_neighbors.load_catalog(real_catalog)
    assert committed, "the committed catalog is empty, so the agreement claim is vacuous"
    for tpl in committed:
        assert tpl.system == tpl.cli, f"{tpl.path}: {tpl.system!r} vs {tpl.cli!r}"

    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    copied = repo / CATALOG_REL
    shutil.rmtree(copied, ignore_errors=True)
    shutil.copytree(real_catalog, copied)

    authored = copied / "elastic" / "_draft" / "agent-authored.md"
    write(authored, "---\nid: elastic.agent-authored\nstatus: draft\n---\n\n## Goal\n\nx\n")
    rel = str(authored.relative_to(repo))
    real = frozenset({tpl.system for tpl in committed})
    assert lead_author._skills_path_rule(repo, "A ", rel, systems=real) is None

    for tpl in lead_neighbors.load_catalog(copied):
        assert tpl.system == tpl.cli, f"{tpl.path}: {tpl.system!r} vs {tpl.cli!r}"
    assert any(
        tpl.id == "elastic.agent-authored" for tpl in lead_neighbors.load_catalog(copied)
    )
