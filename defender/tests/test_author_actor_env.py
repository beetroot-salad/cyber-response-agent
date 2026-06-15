"""Direction-config behavior of the shared environment-lessons curator
(``author_actor_benign``): the two sources that feed lessons-environment/ have
distinct outcome policy + commit trailer + generation counter, but share the
transaction envelope (issue #298)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

LEARNING_SRC = Path(__file__).resolve().parents[1] / "learning"
sys.path.insert(0, str(LEARNING_SRC))

import author_actor_benign as aenv  # type: ignore[import-not-found]
import author_actor_env  # type: ignore[import-not-found]


def _rows() -> list[dict]:
    return [
        {"observation_id": "t/0", "judge_outcome": "caught"},
        {"observation_id": "t/1", "judge_outcome": "incoherent"},
        {"observation_id": "t/2", "judge_outcome": "survived"},
        {"observation_id": "t/3", "judge_outcome": "undecidable"},
        {"observation_id": "t/4", "judge_outcome": "refuted"},
    ]


def _ids(rows: list[dict]) -> set[str]:
    return {r["observation_id"] for r in rows}


def test_adversarial_outcome_policy_authors_caught_incoherent() -> None:
    held, consumed_pre, to_author = aenv._partition_pre_author(
        _rows(), aenv.ADVERSARIAL_CONFIG
    )
    assert _ids(to_author) == {"t/0", "t/1"}              # caught + incoherent author
    # survived/undecidable are skip-by-policy for the adversarial direction.
    assert {"t/2", "t/3"} <= _ids(consumed_pre)


def test_benign_outcome_policy_authors_only_survived() -> None:
    held, consumed_pre, to_author = aenv._partition_pre_author(
        _rows(), aenv.BENIGN_CONFIG
    )
    assert _ids(to_author) == {"t/2"}                     # only survived authors
    assert {"t/4", "t/3", "t/1"} <= _ids(consumed_pre)    # refuted/undecidable/incoherent skip


def test_configs_are_distinct() -> None:
    b, a = aenv.BENIGN_CONFIG, aenv.ADVERSARIAL_CONFIG
    assert b.trailer_label == "Benign-Actor-Model"
    assert a.trailer_label == "Actor-Env-Model"
    assert b.pending_file != a.pending_file
    assert b.lock_file != a.lock_file
    assert b.outcome_author == frozenset({"survived"})
    assert a.outcome_author == frozenset({"caught", "incoherent"})
    # the adversarial entry point delegates with the adversarial config.
    assert author_actor_env.run_batch.__module__ == "author_actor_env"


def test_assert_head_trailers_matches_per_config(monkeypatch) -> None:
    msg = "defender/environment: batch\n\nGeneration: 3\nActor-Env-Model: claude-x\n"
    monkeypatch.setattr(aenv, "head_commit_message", lambda: msg)
    # the adversarial config's trailer regex accepts it
    aenv.assert_head_trailers(3, "claude-x", aenv.ADVERSARIAL_CONFIG)
    # the benign config looks for Benign-Actor-Model: → absent → raises
    with pytest.raises(aenv.AuthorError, match="Benign-Actor-Model"):
        aenv.assert_head_trailers(3, "claude-x", aenv.BENIGN_CONFIG)
    # wrong generation also raises under the right trailer
    with pytest.raises(aenv.AuthorError, match="Generation"):
        aenv.assert_head_trailers(4, "claude-x", aenv.ADVERSARIAL_CONFIG)
