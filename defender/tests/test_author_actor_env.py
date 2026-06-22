"""Direction-config behavior of the shared environment-lessons curator
(``author_actor_benign``): the two sources that feed lessons-environment/ have
distinct outcome policy + commit trailer + generation counter, but share the
transaction envelope (issue #298)."""
from __future__ import annotations

import subprocess

from defender.learning import _author_curator as curator
from defender.learning import author_actor_benign as aenv
from defender.learning import author_actor_env
from defender.learning._loop_config import LoopPaths


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
    held, consumed_pre, to_author = curator._partition_pre_author(
        _rows(), aenv.ADVERSARIAL_CONFIG
    )
    assert _ids(to_author) == {"t/0", "t/1"}              # caught + incoherent author
    # survived/undecidable are skip-by-policy for the adversarial direction.
    assert {"t/2", "t/3"} <= _ids(consumed_pre)


def test_benign_outcome_policy_authors_only_survived() -> None:
    held, consumed_pre, to_author = curator._partition_pre_author(
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
    assert author_actor_env.run_batch.__module__ == "defender.learning.author_actor_env"


def test_commit_corpus_uses_per_config_label(tmp_path, monkeypatch) -> None:
    """The loop commits the corpus using the per-direction ``trailer_label``, so each
    source records its own provenance key (Actor-Env-Model vs Benign-Actor-Model) onto
    the shared corpus's commits."""
    repo = tmp_path / "repo"
    corpus = repo / "defender" / "lessons-environment"
    corpus.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "README").write_text("seed\n")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "seed"], check=True)

    # Both directions share the corpus dir; the factories derive it (+ the git
    # cwd via cfg.repo_root) from the tmp tree, so no module-global patch is needed.
    paths = LoopPaths(repo_root=repo)
    adv = aenv.build_adversarial_config(paths)
    ben = aenv.build_benign_config(paths)

    def _head_msg() -> str:
        return subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--pretty=%B", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout

    (corpus / "a.md").write_text("x\n")  # agent edit, uncommitted
    curator.commit_corpus(3, "claude-x", "adversarial batch", adv)
    msg = _head_msg()
    assert "Generation: 3" in msg
    assert "Actor-Env-Model: claude-x" in msg
    assert "Benign-Actor-Model" not in msg

    (corpus / "b.md").write_text("y\n")
    curator.commit_corpus(2, "claude-y", "benign batch", ben)
    assert "Benign-Actor-Model: claude-y" in _head_msg()
