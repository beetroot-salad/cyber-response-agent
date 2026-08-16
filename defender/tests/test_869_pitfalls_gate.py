"""#869 M6/U1 — the pitfalls predicate (site 1). The `SKILL.md` probe goes.

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared869.py`.

The subtraction is the headline: `_is_real_system` — "does `defender/skills/<system>/SKILL.md`
exist" — is deleted, along with the two in-code justifications C34 refuted (they argue the
census that chose `SKILL.md` over `execution.md`, and that census no longer holds: 7 of 7
systems have an `execution.md`). What replaces it is `is_system_name`'s shape half plus
membership in the threaded value.
"""
from __future__ import annotations

import pytest

from defender import _git
from defender.learning.core import persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import _is_in_scope
from defender.tests._declared869 import (
    SKILLS_REL,
    Spawn,
    is_system_name,
    git,
    head_files,
    loop_log,
    marker_file,
    pitfall_row,
    seed_tree,
    skill_md,
    write,
)

DECLARED = frozenset({"elastic"})


def test_pitfalls_handoff_drops_an_undeclared_system(tmp_path):
    """A queued row naming a system no source declares yields NO handoff, so no
    `defender/skills/<name>/execution.md` path is ever composed from it.

    The issue's headline, executed on base (G2): a row with `system: "gather"` yields
    `execution_md_path: defender/skills/gather/execution.md` today, purely because `gather`
    carries a `SKILL.md`. Under the union it is still dropped — no adapter AND no
    `execution.md` — and the drop is a MEMBERSHIP answer, not a shape accident: the same name
    passes the shape predicate, which is asserted here so the two reasons cannot be confused.
    """
    rows = [pitfall_row("r:0", "gather"), pitfall_row("r:1", "fakesys")]
    assert is_system_name("gather")
    assert is_system_name("fakesys")
    assert pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED) == []

    # And over the real tree's own names, where `gather` is the directory this issue is about.
    assert (_git.REPO_ROOT / SKILLS_REL / "gather" / "SKILL.md").is_file()
    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:2", "gather")], systems=frozenset({"elastic", "cmdb"})) == []


def test_pitfalls_handoff_keeps_a_declared_system(tmp_path):
    """A queued row naming a DECLARED system still becomes a handoff carrying that system's
    `execution.md` path and its failures.

    `pitfalls_handoff_drops_undeclared`'s positive control on the same address: a predicate
    that dropped everything would satisfy the negative and silently retire the whole pitfalls
    channel.
    """
    rows = [pitfall_row("r:0", "elastic"), pitfall_row("r:1", "gather")]
    handoffs = pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED)
    assert [h["system"] for h in handoffs] == ["elastic"]
    assert handoffs[0]["execution_md_path"] == "defender/skills/elastic/execution.md"
    assert [f["query_id"] for f in handoffs[0]["failures"]] == ["elastic.esql"]


def test_system_name_shape_still_refuses_a_traversal(tmp_path):
    """#868's shape check survives the split intact and is still checked BEFORE membership,
    so a traversal never becomes a set lookup.

    `..` is the one that matters: `skills_dir / ".." / "SKILL.md"` IS `defender/SKILL.md`,
    which exists, and `_is_in_scope('defender/skills/../SKILL.md')` is True — both measured
    here rather than remembered, because they are why the shape half is load-bearing beyond
    site 1. The four distinguished shapes are refused individually, and then the ORDER is
    driven: a row whose `system` is `..` yields no handoff EVEN WHEN the threaded set contains
    `..`, which it cannot under FK-5 but which is exactly the state a shape check running
    after membership would admit.

    `resolver_refuses_shape_anomalous_names` pins the SOURCE half; this demand keeps the
    site-1 half, because a queued row's `system` field is a separate untrusted channel that
    never passes through the resolver at all.
    """
    assert (_git.REPO_ROOT / "defender" / "SKILL.md").is_file()
    assert _is_in_scope("defender/skills/../SKILL.md")

    for bad in ("..", "", ".hidden", "a/b", "a\\b", "a\x00b"):
        assert is_system_name(bad) is False, bad
    for good in ("elastic", "change-mgmt", "host-state"):
        assert is_system_name(good) is True, good

    hostile = frozenset({"..", "", ".hidden", "elastic"})
    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:0", ".."), pitfall_row("r:1", ".hidden")], systems=hostile) == []
    assert [
        h["system"] for h in pitfalls_curator._build_pitfalls_handoffs(
            [pitfall_row("r:2", "elastic")], systems=hostile)
    ] == ["elastic"]


def test_pitfalls_path_rule_refuses_an_undeclared_directory(tmp_path):
    """The last gate asks the same membership question the handoff builder does, FROM THE
    SAME THREADED VALUE — and it stops re-deriving membership from the tree the agent just
    wrote into.

    NF2 settles WHICH value: the ADAPTER HALF ALONE, the same one `_build_pitfalls_handoffs`
    is handed. "The same question the handoff builder asks" is a statement about these two
    consumers sharing one argument, NOT about that argument matching the lead-author lane's —
    it does not, by design.

    Driven at the rule and through the composed gate, with the declared system's own
    `execution.md` admitted in the same drive so the refusal is about the name.
    """
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=())
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", "defender/skills/fakesys/execution.md", systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "defender/skills/elastic/execution.md", systems=DECLARED) is None

    write(repo / SKILLS_REL / "fakesys" / "execution.md", "# fakesys\n")
    before = head_files(repo)
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._verify_pitfalls_state(repo, baseline_stray=[], systems=DECLARED)
    assert head_files(repo) == before


def test_a_declared_system_with_no_skill_md_is_admitted(tmp_path, monkeypatch, capsys):
    """A tree that declares `ticket` through its ADAPTER ALONE — no `defender/skills/ticket/
    SKILL.md`, no `execution.md` — still admits a ticket handoff and commits the curator's
    edit.

    What the SUBTRACTION buys, and #870 R2's prerequisite: the removed `SKILL.md` probe was
    the only thing standing between a real system and its own pitfalls lane, and every
    consumer of that probe has to keep working without it.

    WHAT THE FIXTURE'S ABSENT `execution.md` BUYS, CORRECTED (phase F, F10.2). It was recorded
    as a trap against "passing through the marker half" — and under NF2 that reason does not
    hold: this lane resolves the ADAPTER HALF ALONE and never consults the marker source, so a
    seeded marker could not have declared `ticket` here in the first place. The fixture is
    still right, for the reason that does hold: with no `execution.md` committed, the path the
    tick commits is one the CURATOR created, so `execution.md in head_files` is an observation
    about this drive rather than about the fixture. The trap that carries the demand is the
    absent `SKILL.md` — the probe M6 deletes — and it is asserted directly below.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("ticket",), markers=(), skills=(), catalog=(),
                     non_systems=("gather",))
    assert not skill_md(repo, "ticket").exists()
    assert not marker_file(repo, "ticket").exists()

    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "ticket"), pitfall_row("r:l-001:0", "ticket")], paths=paths,
    )
    spawn = Spawn(lambda root: write(
        marker_file(root, "ticket"), "# ticket\n## Common pitfalls\n- use the key, not the id\n",
    ))
    capsys.readouterr()

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert spawn.systems_seen == ["ticket"]
    assert spawn.handoffs[0]["execution_md_path"] == "defender/skills/ticket/execution.md"
    assert "defender/skills/ticket/execution.md" in head_files(repo)
    assert persist.read_pitfalls(paths) == []
    assert not skill_md(repo, "ticket").exists()
    assert "execution.md pitfalls" in git(repo, "log", "--oneline", "-1").stdout
    assert loop_log(capsys)
