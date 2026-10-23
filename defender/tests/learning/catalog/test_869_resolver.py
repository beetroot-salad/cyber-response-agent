"""#869 M1/O4 — `declared_systems`, the resolver as a VALUE."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import shutil
from pathlib import Path

import pytest

from defender.learning.author.version_control import DeliveryRefused
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import verbs
from defender.tests.support.runtime.engine._declared869 import (
    ADAPTERS_REL,
    AGENT_NESTED_MARKER_RELS,
    AGENT_SKILLS_REL,
    NESTED_MARKER_PARENT,
    agent_marker_file,
    declared_systems,
    loop_log,
    pitfall_row,
    seed_agent_files,
    seed_product,
    seed_tree,
    write_adapter,
    write_agent_marker,
    write_marker,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import draft_lead_deps
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


def _committed_agent_paths(lane: C.DraftLane) -> list[str]:
    """Every `agent/...` path of the batch's base commit, asked of git in the tenant clone — the
    committed tree, listed independently of `Batch.base` (which is what the resolver is handed)."""
    listing = lane.git("ls-tree", "-r", "-z", "--name-only", lane.tip(), "--", "agent").stdout
    return [rel for rel in listing.split("\0") if rel]


def _marker_half_of(paths: object) -> set[str]:
    """The marker source, computed HERE from a committed tree's repo-relative paths (NF1).

    `len(parts) == 2` is the DEPTH RULE, not a convenience: the marker address is
    `agent/skills/<name>/execution.md` and nothing deeper. Dropping it turns this helper into
    `_recursive_marker_read_of` below, which is the bug — so the depth is encoded here as an
    independent ground truth and pinned as its own demand (`marker_source_is_exactly_depth_one`)."""
    out = set()
    for rel in paths:
        if not rel.startswith(AGENT_SKILLS_REL):
            continue
        parts = rel[len(AGENT_SKILLS_REL):].split("/")
        if len(parts) == 2 and parts[1] == "execution.md":
            out.add(parts[0])
    return out


def _recursive_marker_read_of(paths: object) -> set[str]:
    """What the OBVIOUS implementation answers: every `execution.md` under `agent/skills/`,
    filtered on the basename with no depth bound.

    Not a control — the WRONG answer, computed so the depth demand can show its fixture really
    does separate the two readings rather than asserting a difference no tree exhibits."""
    return {
        Path(rel).parent.name for rel in paths
        if rel.startswith(AGENT_SKILLS_REL) and rel.endswith("/execution.md")
    }


def _lane(tmp_path: Path, *, adapters: tuple[str, ...], markers: tuple[str, ...],
          skills: tuple[str, ...] = (), catalog: tuple[str, ...] = (), name: str = "product",
          extra: dict[str, str] | None = None) -> tuple[Path, C.DraftLane]:
    """The resolver's two sources after P4 (O1, #1172): a product checkout holding the adapters
    (`seed_product`) and a real batch of the fixture tenant whose PUBLISHED agent half holds the
    markers (`markers`/`skills`/`catalog`, plus `extra`, agent-relative) — so `lane.batch.base()`
    is a committed tree read from git's objects, the value the lane hands the resolver."""
    product = seed_product(tmp_path, adapters=adapters, name=name)
    files = {**seed_agent_files(markers=markers, skills=skills, catalog=catalog), **(extra or {})}
    return product, C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files=files,
                                 state_dir=tmp_path / f"state-{name}")


# #1108 P4 (O1, OD12 class ii; owner ruling on repair r4 item 14): the markers are the tenant's
# (`agent/skills/<name>/execution.md`) and the resolver takes the committed tree they are read
# from as a value — `declared_systems(repo_root, *, agent=<a committed tree's repo-relative
# paths>)`, README §2 — where it used to read `repo`'s HEAD itself. The adapter half stays the
# product checkout's working tree (#1172). The committed-vs-working-tree rule is kept whole: at
# the resolver (the marker half answers only from `agent`, never from any working tree, the
# product's included) and at the lane (`test_the_lead_lane_hands_the_resolver_the_batch_base_never_the_draft`).


def test_declared_systems_unions_the_adapter_glob_and_the_marker(tmp_path):
    product, lane = _lane(tmp_path, adapters=("elastic", "cmdb"),
                          markers=("elastic", "mcpsys"), skills=("elastic",))
    base = lane.batch.base()
    assert set(base) == set(_committed_agent_paths(lane)), "base() is not the committed tree"
    got = declared_systems(product, agent=base)

    assert got == frozenset({"elastic", "cmdb", "mcpsys"})
    assert type(got) is frozenset
    assert set(got) == _adapter_half_of(product) | _marker_half_of(base)
    assert _adapter_half_of(product) < set(got)
    assert _marker_half_of(base) < set(got)

    other, lane2 = _lane(tmp_path, adapters=("ticket",), markers=("ticket",),
                         name="other-product")
    assert declared_systems(other, agent=lane2.batch.base()) == frozenset({"ticket"})


def test_the_marker_half_reads_the_committed_tree_and_the_adapter_half_does_not(tmp_path):
    product, lane = _lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                          skills=("elastic",))
    # A marker for `mcpsys` on disk in every working tree the resolver could stat — the draft
    # the box writes, the product checkout under both the pre-P4 and the tenant spelling — and
    # in none of them committed. Only an uncommitted adapter is meant to count.
    write_agent_marker(lane.root, "mcpsys")
    write_agent_marker(product, "mcpsys")
    write_marker(product, "mcpsys")
    write_adapter(product, "newsys")
    base = lane.batch.base()
    assert f"{AGENT_SKILLS_REL}mcpsys/execution.md" not in base

    on_disk_only = declared_systems(product, agent=base)
    assert agent_marker_file(lane.root, "mcpsys").is_file()
    assert "mcpsys" not in on_disk_only          # the marker half ignores every working tree
    assert "newsys" in on_disk_only              # the adapter half does not
    assert "elastic" in on_disk_only             # and the committed baseline still answers

    lane.batch.commit(lane.batch.change_set(), "land the marker")
    landed = lane.batch.base()
    assert f"{AGENT_SKILLS_REL}mcpsys/execution.md" in _committed_agent_paths(lane)
    assert "mcpsys" in declared_systems(product, agent=landed)


def test_the_marker_source_is_exactly_depth_one(tmp_path):
    product, lane = _lane(
        tmp_path, adapters=("elastic",), markers=("elastic", "cmdb"), skills=("elastic",),
        catalog=("elastic",),
        extra={rel.removeprefix("agent/"): "# a marker whose parent directory name the model chose\n"
               for rel in AGENT_NESTED_MARKER_RELS},
    )
    committed = _committed_agent_paths(lane)
    for rel in AGENT_NESTED_MARKER_RELS:
        assert rel in committed, f"{rel} is not committed, so the demand drives nothing"
    base = lane.batch.base()
    # The wrong answer, measured rather than remembered: the depth-unbounded read DOES pick the
    # model-chosen parent name up out of this very tree.
    assert NESTED_MARKER_PARENT in _recursive_marker_read_of(base)
    assert NESTED_MARKER_PARENT not in _marker_half_of(base)

    got = declared_systems(product, agent=base)
    assert NESTED_MARKER_PARENT not in got, (
        f"a nested execution.md declared {NESTED_MARKER_PARENT!r}: the marker read is "
        f"recursive, and every path in {list(AGENT_NESTED_MARKER_RELS)} is agent-committable"
    )
    assert got == frozenset({"elastic", "cmdb"})
    assert "cmdb" in got, "the depth-1 marker-only control is not declared either"


def test_declared_systems_raises_when_either_source_is_unresolvable(tmp_path):
    """The adapter half unreadable raises, whatever the markers say. The pre-P4 halves "no
    `defender/skills/` tree at HEAD" and "`repo` is no git repository" raised because the resolver
    read the committed tree itself; that read is now the caller's (OD12 class i: the mechanism
    moved behind the `agent=` value), so the unresolvable committed tree is pinned where it is read
    — `test_the_lead_lane_hands_the_resolver_the_batch_base_never_the_draft` (an unreadable batch
    base refuses the lane's deps, never an adapter-only answer)."""
    product, lane = _lane(tmp_path, adapters=("elastic",), markers=("elastic",))
    base = lane.batch.base()
    assert declared_systems(product, agent=base) == frozenset({"elastic"})   # the control

    no_adapters, lane2 = _lane(tmp_path, adapters=(), markers=("elastic",), skills=("elastic",),
                               name="no-adapters")
    (no_adapters / ADAPTERS_REL).rmdir()
    base2 = lane2.batch.base()
    with pytest.raises(LeadAuthorError):
        declared_systems(no_adapters, agent=base2)
    # Not the conjunctive reading, and not a silent empty set: the marker half alone WOULD
    # have been an answer here, and it must not be the one.
    assert _marker_half_of(base2) == {"elastic"}


def test_the_lead_lane_hands_the_resolver_the_batch_base_never_the_draft(tmp_path):
    """The lane-level half of the committed-vs-working-tree rule: the lead-author lane's systems
    are resolved over the batch's BASE (`Batch.base()`), never over the draft its box writes."""
    product, lane = _lane(tmp_path, adapters=("elastic",), markers=("elastic", "basesys"),
                          skills=("elastic",))
    write_agent_marker(lane.root, "draftsys")      # in the draft, never committed
    assert agent_marker_file(lane.root, "draftsys").is_file()
    assert f"{AGENT_SKILLS_REL}draftsys/execution.md" not in _committed_agent_paths(lane)

    deps = draft_lead_deps(lane)
    assert "basesys" in deps.systems, "the committed marker-only system is not declared"
    assert "draftsys" not in deps.systems, (
        "a marker the box wrote into the draft declared its system: the lane resolved over "
        "the draft, not the batch base")
    assert deps.systems == declared_systems(product, agent=lane.batch.base())

    # An unresolvable committed tree refuses the deps; it never degrades to the adapter half.
    _p2, broken = _lane(tmp_path, adapters=("elastic",), markers=("elastic", "basesys"),
                        name="broken")
    shutil.rmtree(broken.clone / ".git" / "objects")
    with pytest.raises((DeliveryRefused, LeadAuthorError)):
        draft_lead_deps(broken)


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
