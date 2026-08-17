"""#870 M9 — three ways to leave the queue uncurated, told apart.

Every test here is one demand of `spec-flow/specs/spec_graph_870.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared870.py`.

At this base all three retirement classes share ONE reason string — G5/C9 reproduced a five-row
tick in which the systemless row, the undeclared-name row and the malformed `'../evil'` row all
carry `'system not in the declared adapter set'`, which names no system to be undeclared and is
simply false of two of the three. A human triaging that file cannot tell an onboarding miss from
an attacker-shaped row.

WHAT THIS SUITE DOES NOT SHOW, stated so it cannot be read out of the prose: nothing here
demonstrates that `pitfalls.deadletter.jsonl` is unread in production (O7 / #903). That is G22's
census, recorded as the clause demand `graveyard_is_still_unread` — a deliberate prose deferral,
which is why M9 converts a mis-labelled quiet loss into a correctly-labelled quiet one rather
than into a visible one. A guarantee a suite tells you but never exercises is how a claim
outlives its evidence.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.runtime.verbs import is_system_name
from defender.tests._declared870 import (
    Spawn,
    commit_all,
    consumed_by_id,
    curate_execution_md,
    curate_reducer_surface,
    edits,
    graveyard_by_id,
    pitfall_row,
    queue_ids,
    seed_tree,
    shim_row,
    write_reducer_surface,
)

#: M9's closed vocabulary, all four members (FK-11 adds the last). Two writers append to one
#: `pitfalls.deadletter.jsonl` and a reason outside this set is a fifth shape a human triaging
#: that file has to learn by reading rows.
REASONS = ("no-system", "malformed-system", "undeclared-system", "batch-error")


@pytest.fixture
def paths(tmp_path: Path) -> LoopPaths:
    """State only — `_graveyard_dropped_rows` writes beside the queue and reads no tree."""
    return LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")


def _reason(paths, row: dict) -> str:
    """Retire ONE row through the real classifier and read back the reason it filed under.

    The rows go into the real queue file through the real appender first, so the classifier is
    handed what a queue read would hand it rather than what this test would like it to see.

    Read with `.get`, like `by_surface` above: a build that never files the row at all fails on
    the caller's own comparison against its expected reason, not on a `KeyError` in this shared
    helper — which would read as a broken test rather than as an unmet demand.
    """
    persist.append_pitfalls([row], paths=paths)
    rows = persist.read_pitfalls(paths)
    pitfalls_curator._graveyard_dropped_rows(paths, rows, [row["pitfall_id"]])
    entry = graveyard_by_id(paths).get(row["pitfall_id"], {})
    return str(entry.get("deadletter_reason"))


def test_a_systemless_row_retires_as_no_system(paths):
    """A retired row carrying NO system at all files under `deadletter_reason: 'no-system'`.

    Today it is filed under "system not in the declared adapter set" (C9, executed), which
    names no system to be undeclared and is simply false of it. The reason is the only thing
    the graveyard record offers a human, so a false one is worse than a coarse one.
    """
    assert _reason(paths, pitfall_row("r:l-000:0", "")) == "no-system"


def test_a_malformed_name_retires_as_malformed_system(paths, tmp_path, monkeypatch):
    """A row whose `system` is `'../evil'` — or carries a NUL, a backslash or a leading dot —
    files under `'malformed-system'`, so an attacker-shaped row no longer reads identically to
    an ordinary onboarding miss in the one record a human will triage.

    FK-12's two open branches are pinned here as EXECUTED assertions rather than decided in
    prose, and the predicate is re-probed in this test so the expected reason follows from its
    real answer instead of from a remembered one. THE PREDICATE MOVED UNDER THIS ROUND: #914
    deletes `declared_systems._is_system_name` and re-homes it as
    `defender.runtime.verbs.is_system_name`, whose alphabet is strictly narrower — lowercase
    letters, digits and hyphens, bounded. FK-12 anticipated exactly this: it routed both
    branches to an executed assertion rather than deciding them, and the demand's own note
    enumerates the two outcomes. So this is the narrower branch being SELECTED, not the round's
    classification being wrong.

    * an ALL-WHITESPACE `system` files under `no-system`, and that reason is INDEPENDENT of the
      predicate: every reader on this path applies `str(r.get("system") or "").strip()` before
      classifying, so the value is already `""` when the shape check would see it. It is
      probed here anyway, to keep the row's reason traceable to a fact rather than to a habit
      — under #914 the predicate now refuses it too, and the reason does not move.
    * a NON-ASCII LOOKALIKE of a declared name — and, on the same footing, an UPPERCASE
      spelling of one — is now OUTSIDE the alphabet, so it files under `malformed-system`
      where it used to file under `undeclared-system:<lookalike>`.

    THAT RECLASSIFICATION IS A DECISION, AND IT IS THE RIGHT ONE, so it is written down rather
    than absorbed as drift: a homoglyph of a declared system name is attacker-shaped, and
    `malformed-system` says so, where `undeclared-system:еlastic` reads to the human triaging
    the file exactly like an ordinary onboarding miss — a name someone will get round to
    declaring. The one class M9 exists to separate from the other two is the one that was
    being spelled as its neighbour. What did NOT change: `../evil` and friends stay
    `malformed-system`, a well-formed undeclared name stays `undeclared-system:<name>`, and a
    systemless row stays `no-system`.
    """
    for i, malformed in enumerate(("../evil", "a\\b", ".hidden", "a\x00b")):
        assert is_system_name(malformed) is False, malformed
        assert _reason(paths, pitfall_row(f"m:l-00{i}:0", malformed)) == "malformed-system"

    # The strip runs upstream of the shape check, so this row's reason is the same under
    # either alphabet — the probe is here to keep that traceable, not to carry the reason.
    assert is_system_name("   ") is False, "#914's alphabet admits whitespace again"
    assert _reason(paths, pitfall_row("w:l-000:0", "   ")) == "no-system"

    # Outside the alphabet, both of them, and the one class that MOVED under #914.
    for i, outside in enumerate(("\u0435lastic", "\uff45lastic", "Elastic")):
        assert is_system_name(outside) is False, (
            f"#914's alphabet admits {outside!r} again, so it is a well-formed name nothing "
            f"declares and reads as an onboarding miss rather than as attacker-shaped"
        )
        assert _reason(paths, pitfall_row(f"u:l-00{i}:0", outside)) == "malformed-system"

    # FK-12's THIRD member, pinned as an executed assertion on the same terms as the two
    # above — a row carrying no `pitfall_id` at all. The resolution declined a DEMAND for it
    # (nothing here changes its fate) and required it to be EXECUTED rather than reasoned
    # about, because copy 1's settled reading is uncomfortable: `batch_ids` is built from rows
    # that HAVE the key, so such a row is in neither `committed_ids` nor `dropped_ids`, is
    # never rotated and never graveyarded — permanently inert — WHILE STILL COUNTING toward
    # `merge_pitfalls` and therefore toward the very gate FK-3 was resolved to de-inflate.
    # Driven through a real tick so the claim is the tick's, not this test's arithmetic.
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",), name="inert")
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    inert = LoopPaths(repo_root=repo, state_dir=tmp_path / "state-inert")
    idless = {k: v for k, v in pitfall_row("x:l-000:0", "elastic").items() if k != "pitfall_id"}
    persist.append_pitfalls([idless, pitfall_row("k:l-000:0", "elastic")], paths=inert)
    assert len(persist.merge_pitfalls(persist.read_pitfalls(inert))) == 2, (
        "an id-less row stopped counting toward the threshold arithmetic"
    )

    assert pitfalls_curator.run_pitfalls(
        paths=inert, invoke=Spawn(curate_execution_md("elastic")),
    ) == 0
    survivors = persist.read_pitfalls(inert)
    assert [r.get("pitfall_id") for r in survivors] == [None], (
        "RECORDED, NOT DEMANDED: the id-less row is inert — it survives the tick untouched "
        "while every row with an id leaves. If this ever changes it is a decision, not a fix"
    )
    assert "k:l-000:0" in consumed_by_id(inert)
    assert graveyard_by_id(inert) == {}


def test_an_undeclared_name_retires_naming_itself(paths):
    """A well-formed row naming `'newsys'`, which this tree's adapter set does not declare,
    files under `'undeclared-system:newsys'`.

    The reason CARRIES THE NAME, so the graveyard is triageable by reason rather than by
    opening each row — which is the whole of O2′'s "naming its class" for the one class where
    the class alone is not actionable: from inside a tick an adapter that will exist tomorrow
    and an invented name are indistinguishable (N5), and both go to human review.
    """
    assert _reason(paths, pitfall_row("r:l-001:0", "newsys")) == "undeclared-system:newsys"
    assert _reason(paths, pitfall_row("r:l-002:0", "alsomissing")) == (
        "undeclared-system:alsomissing"
    ), "the one false string all three classes shared survived"


def test_a_ceiling_retirement_names_its_exception_class(tmp_path, monkeypatch):
    """A row retired by the ATTEMPTS CEILING files under `'batch-error:<exception-class-name>'`
    — the CLASS is what M9's vocabulary is closed over, and it is the reason's PREFIX.

    Two writers append to one `pitfalls.deadletter.jsonl` with two incompatible reason shapes:
    `_graveyard_dropped_rows`' named classes, and `drain.retire`'s `deadletter_reason: str(e)`
    — a raw free-text exception message — from the ceiling path. That ceiling shape is the one
    a REDUCER row most plausibly gets, because its system is neither missing nor malformed nor
    undeclared: it is `""` by design after M5′. A human triaging one file sees named classes
    and a traceback string, and O2′'s "carries a reason naming its CLASS" stops being true at
    the writer that produces it most often.

    THE MESSAGE RIDES AFTER THE CLASS rather than replacing it (the round's review). Pinning
    the class as the WHOLE reason closed the vocabulary and lost the diagnosis: a curator that
    exited rc=124, one that tried to delete a section and one that wrote outside
    `defender/skills` all raise `LeadAuthorError` and all filed as the same four words, in the
    one durable record this lane leaves — unread until #903, so the operator log the message
    also reached is long gone by the time anyone looks. So the demand is on the PREFIX, which
    is what a reader groups on and what `REASONS` is closed over, exactly as the undeclared
    class carries its name after the same `:` separator.

    `ImportError` is the class FK-10's answerer traced through the guard: it is not in
    `SYSTEMIC_FAULTS`, so it reaches `_retire_pitfalls_batch` → `drain.retire` rather than
    crashing the tick.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls([shim_row("r:l-003:0")], paths=paths)

    def _explodes(p, box=None):
        raise ImportError("the curator module vanished mid-tick")

    drains._drain_pitfalls(paths, _explodes)

    entry = graveyard_by_id(paths).get("r:l-003:0", {})
    reason = str(entry.get("deadletter_reason", ""))
    assert reason.startswith("batch-error:ImportError"), (
        "the ceiling path files a raw exception message where every other writer names a class"
    )
    assert reason.split(":")[0] in REASONS
    assert "the curator module vanished mid-tick" in reason, (
        "the class survived and the diagnosis did not — the graveyard cannot tell this "
        "retirement from any other ImportError the lane ever raises"
    )
    assert queue_ids(paths) == []


def test_the_consumed_category_says_unattributable(tmp_path, monkeypatch):
    """Every uncurated row leaves stamped `consumed_unattributable`, and curated rows still
    leave stamped `consumed_committed` with their sha.

    The rename is honest — `'undeclared'` is false of a systemless row and of `'../evil'` — and
    cheap: C19 (searched) found nine writers stamping the field, one stripper, and EXACTLY ONE
    comparison (`== 'consumed_committed'`, which decides whether to attach `consumed_commit`),
    so nothing branches on the outgoing literal and the shipped default survives either
    spelling.

    BOTH producer sites are driven, because the literal is spelled twice (G16:
    `pitfalls_curator.py:247` and `:284`) and a rename that reached one of them would be green
    in a test that drove only the other: the `not handoffs` arm, where a batch nothing can
    teach is rotated wholesale, and the mixed arm beside a real commit.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")

    nothing_teachable = LoopPaths(repo_root=repo, state_dir=tmp_path / "state-a")
    persist.append_pitfalls(
        [pitfall_row("a:l-000:0", "newsys"), pitfall_row("a:l-001:0", "fakesys")],
        paths=nothing_teachable,
    )
    spawn = Spawn(None)
    assert pitfalls_curator.run_pitfalls(paths=nothing_teachable, invoke=spawn) == 0
    assert spawn.calls == [], "the batch had nothing to teach, so this is the wrong arm"
    for row in consumed_by_id(nothing_teachable).values():
        assert row["consumed_category"] == "consumed_unattributable"

    mixed = LoopPaths(repo_root=repo, state_dir=tmp_path / "state-b")
    persist.append_pitfalls(
        [pitfall_row("b:l-000:0", "elastic"), pitfall_row("b:l-001:0", "newsys"),
         shim_row("b:l-002:0")],
        paths=mixed,
    )
    assert pitfalls_curator.run_pitfalls(
        paths=mixed, invoke=Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface())),
    ) == 0
    consumed = consumed_by_id(mixed)
    assert consumed["b:l-001:0"]["consumed_category"] == "consumed_unattributable"
    assert consumed["b:l-000:0"]["consumed_category"] == "consumed_committed"
    assert consumed["b:l-002:0"]["consumed_category"] == "consumed_committed"
    assert consumed["b:l-000:0"]["consumed_commit"]
