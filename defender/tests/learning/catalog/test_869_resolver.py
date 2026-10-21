"""#869 M1/O4 — `declared_systems`, the resolver as a VALUE."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import verbs
from defender.tests.support.runtime.engine._declared869 import (
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
from defender.tests.support.learning.core import _state1135
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
    """Every path under `defender/skills/` at HEAD — the committed tree, listed once."""
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
    repo = seed_tree(
        tmp_path, adapters=("elastic", "cmdb"), markers=("elastic", "mcpsys"),
        skills=("elastic",), catalog=(),
    )
    got = declared_systems(repo)

    assert got == frozenset({"elastic", "cmdb", "mcpsys"})
    assert type(got) is frozenset
    assert set(got) == _adapter_half_of(repo) | _marker_half_of(repo)
    assert _adapter_half_of(repo) < set(got)
    assert _marker_half_of(repo) < set(got)

    other = seed_tree(
        tmp_path, adapters=("ticket",), markers=("ticket",), skills=(), catalog=(),
        name="other-worktree",
    )
    assert declared_systems(other) == frozenset({"ticket"})


def test_the_marker_half_reads_the_committed_tree_and_the_adapter_half_does_not(tmp_path):
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
    assert not (location_path(paths.state_root) / PITFALLS.consumed).exists()
    assert "(continuing)" not in loop_log(capsys)
