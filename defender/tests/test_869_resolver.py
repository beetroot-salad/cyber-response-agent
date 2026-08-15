"""#869 M1/O4 — `declared_systems`, the resolver as a VALUE.

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its observable-outcome prose in its docstring.

THE CODE DOES NOT EXIST YET. `defender.learning.leads.declared_systems` is what this suite is
the contract for; `defender/tests/_declared869.py` states the whole seam contract and holds
the not-yet-written shim, so a missing target fails each test loudly rather than aborting
collection.

THE ONE THING TO READ BEFORE EDITING ANYTHING HERE — **the union is ASYMMETRIC, and the
asymmetry is the design** (NF1, the §7 human seam, which overrode the judge's
recommendation). The adapter half answers from the tree AS IT STANDS; the marker half
answers from the tree AS IT WAS LAST COMMITTED. A fixture that commits both halves, or
neither, cannot see the difference, and a test written against "one source for both" pins
the contract §7 rejected.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import verbs
from defender.tests._declared869 import (
    ADAPTERS_REL,
    NESTED_MARKER_PARENT,
    NESTED_MARKER_RELS,
    RAISING_ADAPTER_BODY,
    SKILLS_REL,
    Spawn,
    adapter_declared_systems,
    adapter_file,
    commit_all,
    declared_systems,
    init_git,
    log_lines_naming,
    loop_log,
    marker_file,
    pitfall_row,
    seed_tree,
    unreadable_dir_verdict,
    write,
    write_adapter,
    write_marker,
    write_skill_md,
)


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
    return subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", "--", SKILLS_REL],
        capture_output=True, text=True, check=True,
    ).stdout.split()


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


def test_a_marker_only_system_is_declared(tmp_path):
    """A tree whose `defender/skills/mcpsys/` holds a COMMITTED `execution.md` and whose
    adapters directory holds no `mcpsys_adapter.py` declares `mcpsys`.

    RF1: the MCP-routed system of record `connect/mcp.md` onboards WITHOUT an adapter, and
    it must not be silently retired. This is `marker_read_is_from_the_committed_tree`'s
    positive control — the same file, committed, IS the difference between declared and
    not — so the marker here is committed on purpose (NF1's accepted cost: a scaffolded MCP
    system stays undeclared until its branch merges).
    """
    repo = seed_tree(
        tmp_path, adapters=("elastic",), markers=("elastic", "mcpsys"), skills=("elastic",),
        catalog=(),
    )
    assert not adapter_file(repo, "mcpsys").exists()
    assert "mcpsys" in declared_systems(repo)


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


def test_the_union_equals_the_adapter_set_on_the_committed_tree():
    """On the real committed tree both sources yield the SAME names — zero marker-only, zero
    adapter-only — so the widening evicts nothing and admits nothing (RF1's positive control,
    N2's guarantee, C31 as a test rather than a reassurance).

    Any divergence a run reports is a regression, not a cleanup. Computed from the tree twice
    over, once per source, and compared to what the resolver answers.
    """
    root = _git.REPO_ROOT
    adapter_half = _adapter_half_of(root)
    marker_half = _marker_half_of(root)

    assert adapter_half, "the real tree declares no adapters — the comparison would be vacuous"
    assert marker_half - adapter_half == set()
    assert adapter_half - marker_half == set()
    assert declared_systems(root) == frozenset(adapter_half)


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


def test_the_resolver_tests_each_source_rather_than_trusting_the_glob(tmp_path):
    """The raise comes from an EXPLICIT per-source test, never inherited from `Path.glob`.

    All three of M1's "absent or unreadable" states are SILENT EMPTY SETS at the primitive —
    an absent path, a regular file, and (P2) an unreadable directory under a real non-root
    uid. The first two are re-probed here on every run, in the test itself, so the taxonomy
    is measured rather than remembered; the third is driven through the instrument the
    running uid makes real. In each state the glob says `[]` and the resolver must still
    refuse, which is the whole content of #0 part 5.

    Its positive control is `declared_systems_empty_dir_reports`: a genuinely empty pair of
    present sources is an honest `frozenset()`, so this is not a resolver that refuses
    everything. P1 closes the fourth state — a partially yielded set is unreachable on this
    interpreter — so no truncation arm is owed.
    """
    absent = seed_tree(tmp_path, adapters=(), markers=("elastic",), catalog=(), name="absent")
    (absent / ADAPTERS_REL).rmdir()
    assert list((absent / ADAPTERS_REL).glob("*" + verbs.ADAPTER_SUFFIX)) == []
    with pytest.raises(LeadAuthorError):
        declared_systems(absent)

    regular = seed_tree(tmp_path, adapters=(), markers=("elastic",), catalog=(), name="regular")
    (regular / ADAPTERS_REL).rmdir()
    write(regular / ADAPTERS_REL.rstrip("/"), "not a directory\n")
    assert (regular / ADAPTERS_REL.rstrip("/")).is_file()
    assert list((regular / ADAPTERS_REL).glob("*" + verbs.ADAPTER_SUFFIX)) == []
    with pytest.raises(LeadAuthorError):
        declared_systems(regular)

    unreadable = seed_tree(
        tmp_path, adapters=("elastic",), markers=("elastic",), catalog=(), name="unreadable",
    )
    assert unreadable_dir_verdict(unreadable, unreadable / ADAPTERS_REL), (
        "an unreadable adapters directory is a silent `[]` at the glob (P2), so a resolver "
        "that only globs cannot tell it from an empty one — it must test the source itself"
    )


def test_declared_systems_reports_an_empty_union(tmp_path, capsys):
    """Both sources present and the union empty is an honest `frozenset()` PLUS one log line
    naming BOTH directories — never a silent one.

    The falsy member is a valid answer AT THE RESOLVER; what the consumers may do with it is
    a different demand (`empty_declared_set_refuses_the_lane`). Both directories, because
    with two sources a line naming one of them leaves an operator guessing which half came
    back empty.
    """
    repo = seed_tree(tmp_path, adapters=(), markers=(), skills=(), catalog=(),
                     non_systems=("gather",))
    # Both sources PRESENT and both EMPTY of what they are read for — the state this demand
    # is about, and the one an absent source must not be confused with.
    assert (repo / ADAPTERS_REL).is_dir()
    assert subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", "--", SKILLS_REL],
        capture_output=True, text=True, check=True,
    ).stdout.split(), "defender/skills is absent at HEAD, which is a different demand"
    assert _adapter_half_of(repo) == set()
    assert _marker_half_of(repo) == set()

    capsys.readouterr()
    assert declared_systems(repo) == frozenset()

    named = log_lines_naming(loop_log(capsys), repo / ADAPTERS_REL, repo / SKILLS_REL)
    assert len(named) == 1, (
        f"expected exactly one line naming both source directories, got {named}"
    )


def test_declared_systems_imports_no_adapter_and_reads_no_marker_body(tmp_path, capsys):
    """The resolver is COLD on both halves: it never imports an adapter module and never
    reads an `execution.md` body.

    Real faults, not imagined ones. The adapters directory holds a module whose import
    raises, and the marker holds bytes that are not valid UTF-8 — so an implementation that
    imported or read either would announce itself by the exception it took, and both faults
    are proved live in the test before the resolver is driven. Every surface the evidence
    could reach is bound: the returned set still names both systems, `sys.modules` gains no
    module loaded out of the adapters directory, `verbs`' own adapter cache gains nothing,
    and neither log stream carries the marker's bytes.

    35 extends C2/G1's cold-glob finding to the marker half — a membership test, never a
    read — which is also why NF4's content-signature alternative was a real cost rather than
    a free upgrade.
    """
    repo = seed_tree(tmp_path, adapters=(), markers=(), skills=(), catalog=(),
                     non_systems=("gather",))
    write_adapter(repo, "boom", body=RAISING_ADAPTER_BODY)
    write_adapter(repo, "elastic")
    marker_file(repo, "elastic").parent.mkdir(parents=True, exist_ok=True)
    marker_file(repo, "elastic").write_bytes(b"# execution \xff\xfe not utf-8\n")
    write_skill_md(repo, "elastic")
    commit_all(repo, "seed the two faults")

    # The faults are real, and this is where that is established rather than assumed.
    with pytest.raises(RuntimeError):
        verbs._load_adapter_module(adapter_file(repo, "boom"))
    with pytest.raises(UnicodeDecodeError):
        marker_file(repo, "elastic").read_text(encoding="utf-8")

    before_modules = dict(sys.modules)
    before_cache = dict(verbs._MODULES)
    capsys.readouterr()

    assert declared_systems(repo) == frozenset({"boom", "elastic"})

    new_modules = [
        name for name, mod in sys.modules.items()
        if name not in before_modules
        and str(getattr(mod, "__file__", "") or "").startswith(str(repo / ADAPTERS_REL))
    ]
    assert new_modules == []
    assert set(verbs._MODULES) - set(before_cache) == set()
    assert "not utf-8" not in loop_log(capsys)


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
        paths=paths,
    )
    capsys.readouterr()

    with pytest.raises(LeadAuthorError):
        drains._invoke_pitfalls(paths)

    assert len(persist.read_pitfalls(paths)) == 2
    assert not paths.pitfalls.consumed.exists()
    assert "(continuing)" not in loop_log(capsys)


def test_the_resolver_never_emits_a_shape_anomalous_name(tmp_path, capsys):
    """The set can never CARRY a malformed name, from EITHER source, and every refusal is
    logged with the source it came from (FK-5, §7).

    J4 executed the four the adapter glob admits today — a DIRECTORY named `dir_adapter.py`,
    a `.hidden_adapter.py`, the suffix-only `_adapter.py` and `.._adapter.py`, from which
    `verbs._system_of` derives `'dir'`, `'.hidden'`, `''` and `'..'`. The marker half is
    screened by the same predicate, so a committed `defender/skills/.planted/execution.md`
    is refused too, not admitted because it came from the other source. Each refused name is
    named on a line that also names the directory it came from: two lines, one carrying the
    name and another carrying a directory, tell an operator nothing about which source
    produced which name.

    This is also the only thing closing R6's log sink — the dropped-names line renders a raw
    system name, and filtering at the SOURCE is its sanitizer. The positive control is in the
    same drive: `cmdb` (adapter-only) and `mcpsys` (marker-only) survive, so a predicate that
    refused everything would not pass this.
    """
    repo = seed_tree(tmp_path, adapters=("cmdb",), markers=("mcpsys",), skills=(), catalog=())
    adapters = repo / ADAPTERS_REL
    write(adapters / "dir_adapter.py" / ".keep", "")
    write(adapters / ".hidden_adapter.py", "VERBS = {}\n")
    write(adapters / "_adapter.py", "VERBS = {}\n")
    write(adapters / ".._adapter.py", "VERBS = {}\n")
    write_marker(repo, ".planted")
    commit_all(repo, "commit the marker-source anomaly")

    # The anomalies are what J4 says they are — measured here, not remembered.
    derived = {verbs._system_of(p) for p in adapters.glob("*" + verbs.ADAPTER_SUFFIX)}
    assert {"dir", ".hidden", "", ".."} <= derived

    capsys.readouterr()
    got = declared_systems(repo)

    assert got == frozenset({"cmdb", "mcpsys"})
    log = loop_log(capsys)
    for name in ("dir", ".hidden", "", ".."):
        assert log_lines_naming(log, repr(name), repo / ADAPTERS_REL), (
            f"the adapter-source refusal of {name!r} is not named with its source: {log}"
        )
    assert log_lines_naming(log, repr(".planted"), repo / SKILLS_REL), (
        f"the marker-source refusal of '.planted' is not named with its source: {log}"
    )


def test_the_adapter_half_resolution_point_is_its_own_call(tmp_path, monkeypatch, capsys):
    """NF2's SECOND resolution point is a NAMED call with a signature of its own —
    `adapter_declared_systems(repo_root) -> frozenset[str]`, the value the PITFALLS lane is
    handed — and THREE properties ride on it that it does not inherit from the union.

    WHY THIS DEMAND EXISTS (phase F, F4, human-resolved). §7 resolved NF2 so the pitfalls lane
    resolves a DIFFERENT value, and no input ever named the call that produces it: the
    artifact mints two production symbols and this was not one of them. Three properties were
    therefore pinned only on the union resolver, and an implementer could satisfy every one of
    them while the adapter-half path did the opposite:

    1. THE DISJUNCTIVE RAISE IS NOT INHERITED. `declared_systems_absent_dir_raises` binds the
       union; under NF2 this call never consults the marker source, so an unresolvable MARKER
       source is not its fault to raise. Driven on ONE tree with no `defender/skills` at all:
       the union raises and this call answers. Its OWN source stays mandatory — a missing
       adapters directory raises here too, which is the control that keeps property 1 from
       reading as "this call never raises".
    2. EMPTINESS IS MEASURED ON THE ADAPTER HALF, NOT THE UNION.
       `empty_declared_set_refuses_the_lane` seeds BOTH sources empty, so it cannot tell the
       two apart. A tree with committed markers and no adapters genuinely declares systems and
       must STILL refuse the whole pitfalls lane — a live consequence of NF2 that no input
       stated. The union is non-empty in the same drive, so the refusal is demonstrably
       measured on the half this lane resolves.
    3. FK-5's SHAPE FILTER AND ITS PER-REFUSAL LOG LINE APPLY HERE TOO.
       `resolver_refuses_shape_anomalous_names` drives the union only, and this path is THE
       ONLY thing closing R6's log sink for the pitfalls lane's own dropped-names line. The
       four names J4 executed are driven again at this call, each owed a line naming
       `repr(name)` and the source directory it came from; `cmdb` surviving in the same drive
       is the control against a predicate that refuses everything.
    """
    # ---- (1) the marker source is not this call's to raise about; its own source is ----
    no_skills = tmp_path / "no-skills"
    init_git(no_skills)
    write_adapter(no_skills, "elastic")
    commit_all(no_skills, "adapters only")
    assert not (no_skills / SKILLS_REL).exists()
    with pytest.raises(LeadAuthorError):
        declared_systems(no_skills)
    assert adapter_declared_systems(no_skills) == frozenset({"elastic"})

    no_adapters = seed_tree(
        tmp_path, adapters=(), markers=("elastic",), skills=("elastic",), catalog=(),
        name="no-adapters-half",
    )
    (no_adapters / ADAPTERS_REL).rmdir()
    with pytest.raises(LeadAuthorError):
        adapter_declared_systems(no_adapters)

    # ---- (2) emptiness is the ADAPTER half's, and it refuses the lane ----
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    markers_only = seed_tree(
        tmp_path, adapters=(), markers=("elastic",), skills=("elastic",), catalog=(),
        name="markers-only",
    )
    # Present and EMPTY of adapters, not absent: absent is the demand above.
    assert (markers_only / ADAPTERS_REL).is_dir()
    assert declared_systems(markers_only) == frozenset({"elastic"})
    assert adapter_declared_systems(markers_only) == frozenset()

    paths = LoopPaths(repo_root=markers_only, state_dir=tmp_path / "state-markers-only")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], paths=paths,
    )
    spawn = Spawn()
    with pytest.raises(LeadAuthorError):
        pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn)
    assert spawn.calls == [], "the curator ran against a tree whose adapter half is empty"
    assert len(persist.read_pitfalls(paths)) == 2
    assert not paths.pitfalls.consumed.exists()

    # ---- (3) FK-5's filter and its per-refusal line, on this path ----
    hostile = seed_tree(
        tmp_path, adapters=("cmdb",), markers=("mcpsys",), skills=(), catalog=(),
        name="hostile-half",
    )
    adapters = hostile / ADAPTERS_REL
    write(adapters / "dir_adapter.py" / ".keep", "")
    write(adapters / ".hidden_adapter.py", "VERBS = {}\n")
    write(adapters / "_adapter.py", "VERBS = {}\n")
    write(adapters / ".._adapter.py", "VERBS = {}\n")
    derived = {verbs._system_of(p) for p in adapters.glob("*" + verbs.ADAPTER_SUFFIX)}
    assert {"dir", ".hidden", "", ".."} <= derived

    capsys.readouterr()
    got = adapter_declared_systems(hostile)
    assert got == frozenset({"cmdb"}), (
        "the adapter half carries a shape-anomalous name, or the marker-only `mcpsys` reached "
        "the lane that must not see it"
    )
    log = loop_log(capsys)
    for name in ("dir", ".hidden", "", ".."):
        assert log_lines_naming(log, repr(name), adapters), (
            f"the adapter-half refusal of {name!r} is not named with its source: {log}"
        )
