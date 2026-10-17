"""#869 M1/O4 — `declared_systems`, the resolver as a VALUE."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import verbs
from defender.tests._declared869 import (
    ADAPTERS_REL,
    NESTED_MARKER_PARENT,
    NESTED_MARKER_RELS,
    SKILLS_REL,
    commit_all,
    declared_systems,
    init_git,
    loop_log,
    marker_file,
    pitfall_row,
    seed_tree,
    write,
    write_adapter,
    write_marker,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests import _state1135
from defender.learning.core.state import PITFALLS


def _adapter_half_of(repo: Path) -> set[str]:
    """The adapter source, computed HERE from the WORKING tree — an independent encoding of
    the same rule the resolver must apply, never a call back into it."""
    d = repo / ADAPTERS_REL
    return {
        verbs._system_of(p)
        for p in d.glob("*" + verbs.ADAPTER_SUFFIX)
    } if d.is_dir() else set()


def _committed_skills_paths(repo: Path) -> list[str]:
    """Every path under `defender/skills/` at HEAD — the committed tree, listed once.

    DELIBERATELY NOT the plumbing the resolver runs (#910's shared-oracle gate). `_marker_names`
    asks `ls-tree` for HEAD; an oracle that re-ran that same query could not disagree with the
    code about how the tree is read — it could only confirm the implementation does what the
    test's own copy does, and every input on which the shared primitive is wrong would be
    invisible BY CONSTRUCTION. That is not a hypothetical here: it is how #869 shipped a
    marker half that dropped every non-ASCII and every spaced name.

    `ls-files` answers from the INDEX rather than from HEAD — a different command, a different
    parse, and a different question. For these fixtures the two coincide exactly, because
    every one of them reaches this helper through `commit_all`, and a file merely WRITTEN is
    in neither (which is the NF1 asymmetry this suite turns on, so the substitution does not
    quietly relax it). `-z` and `--full-name` are for the oracle's own correctness: NUL
    delimiting so a spaced or non-ASCII path is neither torn nor C-quoted, and root-relative
    output so `count("/") == 3` means what it says.
    """
    listing = _git.git(
        ["ls-files", "-z", "--full-name", "--cached", "--", SKILLS_REL], cwd=repo,
    )
    return [rel for rel in listing.split("\0") if rel]


def _marker_half_of(repo: Path) -> set[str]:
    """The marker source, computed HERE from the COMMITTED tree (NF1) — `git ls-tree` at
    HEAD, never a `stat` of the working tree, because a working-tree read is exactly the
    reading §7 rejected and a control that made it would agree with the bug.

    `p.count("/") == 3` is the DEPTH RULE, not a convenience: the marker address is
    `defender/skills/<name>/execution.md` and nothing deeper. Dropping it turns this helper
    into `_recursive_marker_read_of` below, which is the bug — so the depth is encoded here
    as an independent ground truth and pinned as its own demand
    (`marker_source_is_exactly_depth_one`)."""
    return {
        Path(p).parent.name for p in _committed_skills_paths(repo)
        if p.endswith("/execution.md") and p.count("/") == 3
    }


def _recursive_marker_read_of(repo: Path) -> set[str]:
    """What the OBVIOUS implementation answers: `git ls-tree -r … -- defender/skills`
    filtered on the `execution.md` basename, with no depth bound.

    Not a control — the WRONG answer, computed so the depth demand can show its fixture
    really does separate the two readings rather than asserting a difference no tree
    exhibits."""
    return {
        Path(p).parent.name for p in _committed_skills_paths(repo)
        if p.endswith("/execution.md")
    }


def test_declared_systems_unions_the_adapter_glob_and_the_marker(tmp_path):
    """`declared_systems(<tree root>)` returns a `frozenset[str]` that is the UNION of the
    adapter glob and the committed `execution.md` marker, both rooted at the ONE tree-root
    parameter it was handed.

    Over a tree carrying an adapter-only system (`cmdb`), a marker-only system (`mcpsys`)
    and one both sources name (`elastic`), all three are declared: either half alone is a
    strict subset, so a resolver that read one source answers a strictly smaller set. The
    return is a `frozenset`, deliberately NOT `ModuleVerbRegistry.systems()`'s sorted tuple.
    And the tree root is a real coordinate, not plumbing: a second tree with different
    sources answers differently through the same call.
    """
    repo = seed_tree(
        tmp_path, adapters=("elastic", "cmdb"), markers=("elastic", "mcpsys"),
        skills=("elastic",), catalog=(),
    )
    got = declared_systems(repo)

    assert got == frozenset({"elastic", "cmdb", "mcpsys"})
    assert type(got) is frozenset
    # The answer is EXACTLY the two halves, and each half is a STRICT subset of it. The
    # strictness alone says neither source could have produced the answer by itself; the
    # EQUALITY is what says the resolver added nothing of its own — a strict-subset test is
    # still satisfied by a resolver that returns MORE than either source names, which is
    # precisely what a depth-unbounded marker read does (`marker_source_is_exactly_depth_one`).
    assert set(got) == _adapter_half_of(repo) | _marker_half_of(repo)
    assert _adapter_half_of(repo) < set(got)
    assert _marker_half_of(repo) < set(got)

    other = seed_tree(
        tmp_path, adapters=("ticket",), markers=("ticket",), skills=(), catalog=(),
        name="other-worktree",
    )
    assert declared_systems(other) == frozenset({"ticket"})


def test_the_marker_half_reads_the_committed_tree_and_the_adapter_half_does_not(tmp_path):
    """One tree, ONE drive, BOTH arms, because the asymmetry is the observable (NF1, §7).

    In a tree where `defender/skills/mcpsys/execution.md` exists on disk but is NOT
    committed, `mcpsys` is NOT declared — an uncommitted marker, however it got there,
    declares nothing. In the SAME tree an uncommitted `scripts/adapters/newsys_adapter.py`
    IS declared, because the adapter half reads the working tree. Commit the marker and
    `mcpsys` joins the set.

    A test that drove only the marker arm could not tell a committed-tree read from a
    resolver that ignores markers altogether; a test that drove only the negative arm passes
    against a resolver that returns `frozenset()`. This is what closes phase C's executed
    planted-marker break structurally rather than by ordering discipline.
    """
    repo = seed_tree(
        tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
        catalog=(),
    )
    write_marker(repo, "mcpsys")
    write_adapter(repo, "newsys")

    on_disk_only = declared_systems(repo)
    assert marker_file(repo, "mcpsys").is_file()
    assert "mcpsys" not in on_disk_only          # the marker half ignores the working tree
    assert "newsys" in on_disk_only              # the adapter half does not
    assert "elastic" in on_disk_only             # and the committed baseline still answers

    commit_all(repo, "land the marker")
    assert "mcpsys" in declared_systems(repo)


def test_the_marker_source_is_exactly_depth_one(tmp_path):
    """The marker address is `<root>/defender/skills/<name>/execution.md` and NOTHING
    deeper: a COMMITTED `execution.md` nested below that declares nothing, and in
    particular does not declare its own parent directory's name.

    THE COMPOSITION THIS CLOSES (phase F, F1). Two individually-pinned facts jointly admit a
    forged marker: `marker_is_not_agent_committable` refuses the two-segment form at the
    commit gate, while `_is_in_scope` admits `defender/skills/<declared>/_draft/<any>/…`
    and every `gather/queries/…` path at ANY depth — so an agent can get
    `defender/skills/elastic/_draft/mcpsys/execution.md` committed under a name it chose
    itself. If the marker half is written as the obvious `git ls-tree -r … -- defender/skills`
    filtered on the basename, `mcpsys` becomes declared on the next tick with every other
    control in this spec holding, because the file really is committed and really does
    predate the resolution. The spec must not depend on the implementer getting the recursion
    right; the depth is a demand.
    Its BELT is at the other end — `marker_is_not_agent_committable` now refuses
    `execution.md` at any depth, so neither the read nor the write side stands alone.

    Both nested paths are COMMITTED here, not merely written: an uncommitted one is refused
    by `marker_read_is_from_the_committed_tree` for a different reason, and a fixture that
    leaned on that would assert nothing about depth. The wrong answer is computed in-test
    from the same committed tree, so the fixture is shown to separate the two readings rather
    than the test asserting a difference no tree exhibits.

    The positive control is on the same address and in the same drive: `cmdb`, a marker-only
    system whose `execution.md` sits at depth 1, IS declared — so this is not a resolver that
    has simply stopped reading markers.
    """
    repo = seed_tree(
        tmp_path, adapters=("elastic",), markers=("elastic", "cmdb"), skills=("elastic",),
        catalog=("elastic",),
    )
    for rel in NESTED_MARKER_RELS:
        write(repo / rel, "# a marker whose parent directory name the model chose\n")
    commit_all(repo, "commit both nested execution.md files")

    committed = _committed_skills_paths(repo)
    for rel in NESTED_MARKER_RELS:
        assert rel in committed, f"{rel} is not committed, so the demand drives nothing"
    # The wrong answer, measured rather than remembered: the depth-unbounded read DOES pick
    # the model-chosen parent name up out of this very tree.
    assert NESTED_MARKER_PARENT in _recursive_marker_read_of(repo)
    assert NESTED_MARKER_PARENT not in _marker_half_of(repo)

    got = declared_systems(repo)
    assert NESTED_MARKER_PARENT not in got, (
        f"a nested execution.md declared {NESTED_MARKER_PARENT!r}: the marker read is "
        f"recursive, and every path in {list(NESTED_MARKER_RELS)} is agent-committable"
    )
    assert got == frozenset({"elastic", "cmdb"})
    assert "cmdb" in got, "the depth-1 marker-only control is not declared either"


def test_declared_systems_raises_when_either_source_is_unresolvable(tmp_path):
    """Either source unresolvable RAISES `LeadAuthorError` — the DISJUNCTIVE reading O4
    forces, over three states of the two sources.

    * the adapters directory absent while the skills tree is fine — a conjunctive resolver
      would hand back the marker half alone and silently retire every adapter-backed system,
      which is precisely the failure O4 names;
    * `defender/skills` absent at HEAD while the adapters directory is fine;
    * the committed-tree read itself failing — here, a tree that is not a repository at all.

    Rejected, and asserted as rejected: returning `frozenset()` and letting the caller not
    know the difference. The fault class is pinned too, because the drain routes on the class
    and not on the message.
    """
    whole = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), catalog=())
    assert declared_systems(whole) == frozenset({"elastic"})   # the control on the same address

    no_adapters = seed_tree(
        tmp_path, adapters=(), markers=("elastic",), skills=("elastic",), catalog=(),
        name="no-adapters",
    )
    (no_adapters / ADAPTERS_REL).rmdir()
    with pytest.raises(LeadAuthorError):
        declared_systems(no_adapters)
    # Not the conjunctive reading, and not a silent empty set: the marker half alone WOULD
    # have been an answer here, and it must not be the one.
    assert _marker_half_of(no_adapters) == {"elastic"}

    no_skills = tmp_path / "no-skills"
    init_git(no_skills)
    write_adapter(no_skills, "elastic")
    commit_all(no_skills, "adapters only")
    assert not (no_skills / SKILLS_REL).exists()
    with pytest.raises(LeadAuthorError):
        declared_systems(no_skills)

    not_a_repo = tmp_path / "not-a-repo"
    write_adapter(not_a_repo, "elastic")
    write_marker(not_a_repo, "elastic")
    assert not (not_a_repo / ".git").exists()
    with pytest.raises(LeadAuthorError):
        declared_systems(not_a_repo)


def test_a_resolver_failure_is_not_a_successful_tick(tmp_path, capsys, monkeypatch):
    """A resolver failure on the pitfalls leg is NOT a green tick with the queue rotated.

    `drains._run_curator_module` catches `(SubprocessError, OSError)`, logs "(continuing)"
    and returns `None`, which `_invoke_pitfalls` maps to rc 0 — so an `OSError` out of the
    resolver would be a successful tick that rotated the whole batch out, which is O4's own
    named failure. The resolver's fault must not present to that handler as one: driven
    through the real drain seam over a tree with no adapters directory, `_invoke_pitfalls`
    RAISES instead of returning 0, the queue is untouched, nothing is stamped consumed, and
    the swallow's own log line never appears.

    The queued rows name a system nothing declares so that this drive cannot reach the
    curator spawn on ANY tree — the resolver's refusal is what the demand is about, and a
    fixture that could reach a live agent would be measuring the environment.
    """
    assert not issubclass(LeadAuthorError, OSError), (
        "an OSError subclass is swallowed by _run_curator_module and becomes rc 0"
    )
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=(), markers=("elastic",), skills=("elastic",),
                     catalog=())
    (repo / ADAPTERS_REL).rmdir()
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "mcpsys"), pitfall_row("r:l-001:0", "mcpsys")],
        state=_state1135.state_for_paths(paths),
    )
    capsys.readouterr()

    with pytest.raises(LeadAuthorError):
        drains._invoke_pitfalls(
            paths, _state1135.state_for_paths(paths), on_curated=lambda _d: None, label=LEAD_AUTHOR_DRAIN_LABEL)

    assert len(persist.read_pitfalls(_state1135.state_for_paths(paths))) == 2
    assert not (paths.state_root / PITFALLS.consumed).exists()
    assert "(continuing)" not in loop_log(capsys)


