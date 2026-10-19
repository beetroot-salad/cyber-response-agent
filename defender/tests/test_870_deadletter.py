"""#870 M9 — three ways to leave the queue uncurated, told apart."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core import persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.runtime.verbs import is_system_name
from defender.tests._declared870 import (
    Spawn,
    commit_all,
    consumed_by_id,
    curate_execution_md,
    graveyard_by_id,
    pitfall_row,
    seed_tree,
    write_reducer_surface,
)
from defender.tests import _state1135
from defender.tests._lead_author_1134 import lead_trees

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
    persist.append_pitfalls([row], state=_state1135.state_for_paths(paths))
    rows = persist.read_pitfalls(_state1135.state_for_paths(paths))
    pitfalls_curator._graveyard_dropped_rows(_state1135.state_for_paths(paths), rows, [row["pitfall_id"]])
    entry = graveyard_by_id(paths).get(row["pitfall_id"], {})
    return str(entry.get("deadletter_reason"))


def test_a_systemless_row_retires_as_no_system(paths):
    assert _reason(paths, pitfall_row("r:l-000:0", "")) == "no-system"


def test_a_malformed_name_retires_as_malformed_system(paths, tmp_path, monkeypatch):
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

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",), name="inert")
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    inert = LoopPaths(repo_root=repo, state_dir=tmp_path / "state-inert")
    idless = {k: v for k, v in pitfall_row("x:l-000:0", "elastic").items() if k != "pitfall_id"}
    persist.append_pitfalls([idless, pitfall_row("k:l-000:0", "elastic")], state=_state1135.state_for_paths(inert))
    assert len(persist.merge_pitfalls(persist.read_pitfalls(_state1135.state_for_paths(inert)))) == 2, (
        "an id-less row stopped counting toward the threshold arithmetic"
    )

    assert pitfalls_curator.run_pitfalls(
        paths=inert, invoke=Spawn(curate_execution_md("elastic")), trees=lead_trees(inert),
    ) == 0
    survivors = persist.read_pitfalls(_state1135.state_for_paths(inert))
    assert [r.get("pitfall_id") for r in survivors] == [None], (
        "RECORDED, NOT DEMANDED: the id-less row is inert — it survives the tick untouched "
        "while every row with an id leaves. If this ever changes it is a decision, not a fix"
    )
    assert "k:l-000:0" in consumed_by_id(inert)
    assert graveyard_by_id(inert) == {}


def test_an_undeclared_name_retires_naming_itself(paths):
    assert _reason(paths, pitfall_row("r:l-001:0", "newsys")) == "undeclared-system:newsys"
    assert _reason(paths, pitfall_row("r:l-002:0", "alsomissing")) == (
        "undeclared-system:alsomissing"
    ), "the one false string all three classes shared survived"
