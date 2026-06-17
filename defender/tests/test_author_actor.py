"""Unit tests for the actor lessons curator.

Covers the deterministic pre/post-flight without spawning ``claude -p``. The
transaction envelope lives in ``_author_curator``; ``author_actor`` supplies the
actor ``CuratorConfig``. Tests drive the engine with a config pointed at a tmp repo
and an injected ``invoke_agent`` — no module-global monkeypatching beyond the single
repo-root seam shared with ``_author_shared`` (git/lock/generation operations).
"""
from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

LEARNING_SRC = Path(__file__).resolve().parents[1] / "learning"
sys.path.insert(0, str(LEARNING_SRC))

# The curator engine, the lock/generation helpers, and the actor config wrapper.
# Each resolves to one module instance (the path imports inside the modules use the
# same names), so patching ``curator.REPO_ROOT`` / ``shared.*`` reaches them.
import _author_curator as curator  # type: ignore[import-not-found]  # noqa: E402
import _author_shared as shared  # type: ignore[import-not-found]  # noqa: E402
import author_actor as aa  # type: ignore[import-not-found]  # noqa: E402

AuthorError = curator.AuthorError


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _isolate(monkeypatch, tmp_path: Path):
    """Point the curator's git/lock/generation operations at a fresh tmp repo.

    Returns a dict of pointers; build a config with ``_cfg(ctx, invoke)``."""
    repo = tmp_path / "repo"
    learning = repo / "defender" / "learning"
    pending = learning / "_pending"
    lessons = repo / "defender" / "lessons-actor"
    lessons.mkdir(parents=True)
    pending.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    # Seed an initial commit so HEAD exists and rev-list works.
    seed = repo / "README"
    seed.write_text("seed\n")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "seed"], check=True)

    # The engine runs all git operations at curator.REPO_ROOT; the repo lock +
    # generation counter live in _author_shared. Both point at the tmp repo.
    monkeypatch.setattr(curator, "REPO_ROOT", repo)
    monkeypatch.setattr(shared, "REPO_ROOT", repo)
    monkeypatch.setattr(shared, "LEARNING_DIR", learning)
    monkeypatch.setattr(shared, "REPO_LOCK_FILE", learning / "_author.lock")

    return {
        "repo": repo,
        "learning": learning,
        "pending": pending,
        "lessons": lessons,
    }


def _cfg(ctx: dict, invoke_agent) -> curator.CuratorConfig:
    """The production actor config, repointed at the tmp repo's queue + corpus and
    given an injected ``invoke_agent`` so no ``claude -p`` runs."""
    return dataclasses.replace(
        aa.ACTOR_CONFIG,
        corpus_dir=ctx["lessons"],
        pending_file=ctx["pending"] / "actor_observations.jsonl",
        consumed_file=ctx["pending"] / "actor_observations.consumed.jsonl",
        lock_file=ctx["pending"] / ".actor.lock",
        invoke_agent=invoke_agent,
    )


def _consume_all(observations, batch_id, generation, cfg):
    """A no-commit AUTHOR_RESULT that routes every to_author obs to consumed_skip."""
    return {
        "committed": [],
        "consumed_skip": [
            {"observation_id": o["observation_id"], "reason": "test"}
            for o in observations
        ],
        "commit_sha": None,
    }


def _row(observation_id: str, outcome: str, source_run_dir: str = "") -> dict:
    return {
        "observation_id": observation_id,
        "run_id": observation_id.split("/")[0],
        "observation_index": int(observation_id.split("/")[1]),
        "alert_rule_key": "rule-5710",
        "type": "misprediction",
        "subject_anchor": "anchor",
        "subject_topic": "topic",
        "observation": "obs body",
        "judge_outcome": outcome,
        "source_run_dir": source_run_dir
        or f"defender/learning/runs/{observation_id.split('/')[0]}/",
    }


def _write_queue(pending: Path, rows: list[dict]) -> None:
    pending.mkdir(parents=True, exist_ok=True)
    path = pending / "actor_observations.jsonl"
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _write_lesson(
    lessons: Path,
    slug: str,
    frontmatter: dict,
    body: str = "x\n",
) -> Path:
    """Write a flat-corpus v2 lesson file. Frontmatter dict is dumped as-is."""
    fm_text = yaml.safe_dump(frontmatter, sort_keys=False).strip()
    path = lessons / f"{slug}.md"
    path.write_text(f"---\n{fm_text}\n---\n\n{body}")
    return path


# ---------------------------------------------------------------------------
# Pre-flight filters
# ---------------------------------------------------------------------------


def test_outcome_policy_filter_drops_survived_and_undecidable(
    monkeypatch, tmp_path: Path
):
    ctx = _isolate(monkeypatch, tmp_path)
    _write_queue(
        ctx["pending"],
        [
            _row("a/0", "caught"),
            _row("b/0", "survived"),
            _row("c/0", "undecidable"),
            _row("d/0", "incoherent"),
        ],
    )
    # The to_author list handed to the agent must contain only caught + incoherent.
    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, generation, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, generation, cfg)

    rc = curator.run_batch(hold_committed=False, cfg=_cfg(ctx, fake_invoke))
    assert rc == 0
    assert len(captured) == 1
    sent_ids = {o["observation_id"] for o in captured[0]}
    assert sent_ids == {"a/0", "d/0"}

    consumed = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.consumed.jsonl")
        .read_text()
        .splitlines()
    ]
    by_id = {r["observation_id"]: r for r in consumed}
    assert by_id["b/0"]["consumed_category"] == "consumed_skip"
    assert by_id["b/0"]["skip_reason"] == "outcome_policy:survived"
    assert by_id["c/0"]["skip_reason"] == "outcome_policy:undecidable"


def test_idempotency_consumes_already_cited_observations(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    _write_lesson(
        ctx["lessons"],
        "existing",
        {
            "techniques": ["T1078"],
            "mutable": False,
            "relevance_criteria": "x",
            "recorded_at": "old",
            "source_observation_ids": ["a/0"],
        },
    )
    # Pre-flight requires lessons-actor/ to be git-clean.
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/existing.md"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "seed lesson"],
        check=True,
    )
    _write_queue(ctx["pending"], [_row("a/0", "caught"), _row("b/0", "caught")])

    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, generation, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, generation, cfg)

    rc = curator.run_batch(hold_committed=False, cfg=_cfg(ctx, fake_invoke))
    assert rc == 0
    sent_ids = {o["observation_id"] for o in captured[0]}
    assert sent_ids == {"b/0"}
    consumed = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.consumed.jsonl")
        .read_text()
        .splitlines()
    ]
    by_id = {r["observation_id"]: r for r in consumed}
    assert by_id["a/0"]["consumed_category"] == "consumed_idempotent"


def test_held_out_double_check_holds_observation(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    # Synthesize a held-out source run dir under the tmp repo root.
    src = ctx["repo"] / "defender" / "learning" / "runs" / "held/"
    src.mkdir(parents=True)
    (src / "ground_truth.yaml").write_text("held_out: true\n")
    row = _row("held/0", "caught", source_run_dir="defender/learning/runs/held/")
    _write_queue(ctx["pending"], [row, _row("ok/0", "caught")])

    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, generation, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, generation, cfg)

    rc = curator.run_batch(hold_committed=False, cfg=_cfg(ctx, fake_invoke))
    assert rc == 0
    sent_ids = {o["observation_id"] for o in captured[0]}
    assert sent_ids == {"ok/0"}

    # held/0 must remain in active queue with held_reason annotation.
    rows_left = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.jsonl")
        .read_text()
        .splitlines()
    ]
    assert len(rows_left) == 1
    assert rows_left[0]["observation_id"] == "held/0"
    assert rows_left[0]["held_reason"] == "held_out_double_check"


# ---------------------------------------------------------------------------
# Result partition + post-flight
# ---------------------------------------------------------------------------


def test_result_partition_rejects_unknown_observation():
    to_author = [_row("a/0", "caught")]
    result = {
        "committed": ["a/0", "bogus/9"],
        "consumed_skip": [],
        "commit_sha": "deadbeef",
    }
    with pytest.raises(AuthorError, match="unknown observations"):
        curator.validate_agent_result_partition(result, to_author)


def test_result_partition_rejects_duplicate_across_buckets():
    to_author = [_row("a/0", "caught")]
    result = {
        "committed": ["a/0"],
        "consumed_skip": [{"observation_id": "a/0", "reason": "x"}],
        "commit_sha": "deadbeef",
    }
    with pytest.raises(AuthorError, match="more than once"):
        curator.validate_agent_result_partition(result, to_author)


def test_result_partition_rejects_missing_observation():
    to_author = [_row("a/0", "caught"), _row("b/0", "caught")]
    result = {"committed": ["a/0"], "consumed_skip": [], "commit_sha": "x"}
    with pytest.raises(AuthorError, match="missing observations"):
        curator.validate_agent_result_partition(result, to_author)


def test_post_flight_rejects_missing_generation_trailer(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    # Land a commit inside lessons-actor with no trailers.
    (ctx["lessons"] / "x.md").write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/x.md"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "no trailers here"],
        check=True,
    )
    with pytest.raises(AuthorError, match="Generation:"):
        curator.assert_head_trailers(1, "claude-sonnet-4-6", aa.ACTOR_CONFIG)


def test_post_flight_accepts_correct_trailers(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    (ctx["lessons"] / "x.md").write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/x.md"],
        check=True,
    )
    msg = "lesson batch\n\nGeneration: 1\nActor-Model: claude-sonnet-4-6\n"
    subprocess.run(["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", msg], check=True)
    curator.assert_head_trailers(1, "claude-sonnet-4-6", aa.ACTOR_CONFIG)
    # And the head-only-corpus predicate accepts this commit.
    assert curator.head_changed_only(aa.ACTOR_CONFIG.corpus_dir_rel) is True


def test_post_flight_rejects_commit_outside_lessons_actor(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    other = ctx["repo"] / "defender" / "lessons"
    other.mkdir(parents=True)
    (other / "y.md").write_text("y\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons/y.md"], check=True
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "wrong dir"], check=True
    )
    assert curator.head_changed_only(aa.ACTOR_CONFIG.corpus_dir_rel) is False


def test_post_flight_rejects_no_commit_result_when_head_changed(
    monkeypatch, tmp_path: Path
):
    ctx = _isolate(monkeypatch, tmp_path)
    pre_agent_head = curator.git_head_sha()
    (ctx["lessons"] / "x.md").write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/x.md"],
        check=True,
    )
    msg = "lesson batch\n\nGeneration: 1\nActor-Model: claude-sonnet-4-6\n"
    subprocess.run(["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", msg], check=True)
    result = {"committed": [], "consumed_skip": [], "commit_sha": None}

    with pytest.raises(AuthorError, match="HEAD changed"):
        curator.verify_agent_state(
            result, 1, "claude-sonnet-4-6", pre_agent_head, _cfg(ctx, _consume_all)
        )


# ---------------------------------------------------------------------------
# Generation counter
# ---------------------------------------------------------------------------


def test_actor_generation_count_starts_at_1(monkeypatch, tmp_path: Path):
    _isolate(monkeypatch, tmp_path)
    assert shared.actor_generation_count() == 1


def test_actor_generation_count_ignores_pre_author_commits(monkeypatch, tmp_path: Path):
    """Pre-author commits that touch lessons-actor/ (corpus structure, templates)
    must NOT advance the counter — only commits carrying the Actor-Model: trailer do."""
    ctx = _isolate(monkeypatch, tmp_path)
    pre = ctx["lessons"] / "_TEMPLATE.md"
    pre.write_text("template\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", str(pre.relative_to(ctx["repo"]))],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "seed templates"],
        check=True,
    )
    assert shared.actor_generation_count() == 1


def test_actor_generation_count_increments_with_prior_author_commits(
    monkeypatch, tmp_path: Path
):
    ctx = _isolate(monkeypatch, tmp_path)
    for i in range(2):
        p = ctx["lessons"] / f"gen{i}.md"
        p.write_text("x\n")
        subprocess.run(
            ["git", "-C", str(ctx["repo"]), "add", str(p.relative_to(ctx["repo"]))],
            check=True,
        )
        msg = (
            f"author batch {i}\n\nGeneration: {i + 1}\n"
            f"Actor-Model: claude-sonnet-4-6\n"
        )
        subprocess.run(
            ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", msg], check=True
        )
    assert shared.actor_generation_count() == 3


# ---------------------------------------------------------------------------
# Repo lock
# ---------------------------------------------------------------------------


def test_repo_lock_blocks_second_acquire(monkeypatch, tmp_path: Path):
    _isolate(monkeypatch, tmp_path)
    fh = shared.acquire_repo_lock(timeout_seconds=2)
    try:
        with pytest.raises(TimeoutError, match="repo lock"):
            shared.acquire_repo_lock(timeout_seconds=1)
    finally:
        shared.release_repo_lock(fh)
    # After release a fresh acquire succeeds.
    fh2 = shared.acquire_repo_lock(timeout_seconds=1)
    shared.release_repo_lock(fh2)


# ---------------------------------------------------------------------------
# Queue rotation
# ---------------------------------------------------------------------------


def test_rotate_queue_preserves_held_and_appends_consumed(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    held = [{**_row("h/0", "caught"), "held_reason": "x"}]
    consumed = [
        {**_row("c/0", "caught"), "consumed_category": "consumed_committed"},
        {**_row("s/0", "caught"), "consumed_category": "consumed_skip", "skip_reason": "low"},
    ]
    curator.rotate_queue(
        held=held, consumed=consumed, commit_sha="abc123", cfg=_cfg(ctx, _consume_all)
    )

    left = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert [r["observation_id"] for r in left] == ["h/0"]

    consumed_rows = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.consumed.jsonl")
        .read_text()
        .splitlines()
    ]
    by_id = {r["observation_id"]: r for r in consumed_rows}
    assert by_id["c/0"]["consumed_commit"] == "abc123"
    assert "consumed_at" in by_id["c/0"]
    # Skip rows do not get consumed_commit even if a sha was passed.
    assert "consumed_commit" not in by_id["s/0"]


# ---------------------------------------------------------------------------
# Index CLI — stale env filter
# ---------------------------------------------------------------------------


def test_index_cli_hides_stale_lessons_by_default(monkeypatch, tmp_path: Path):
    """The runtime actor uses lessons_actor_index.py; stale lessons must not be
    surfaced unless --include-stale is passed. v2: stale-hiding applies to any
    mutable=true lesson, not just env-channel."""
    ctx = _isolate(monkeypatch, tmp_path)
    _write_lesson(
        ctx["lessons"],
        "live-claim",
        {
            "subject": "docker-auditing",
            "mutable": True,
            "status": "live",
            "relevance_criteria": "live one",
            "recorded_at": "r1",
            "source_observation_ids": ["r1/0"],
        },
    )
    _write_lesson(
        ctx["lessons"],
        "stale-claim",
        {
            "subject": "docker-auditing",
            "mutable": True,
            "status": "stale",
            "superseded_by": "live-claim",
            "relevance_criteria": "stale one",
            "recorded_at": "r0",
            "source_observation_ids": ["r0/0"],
        },
    )
    script = Path(__file__).resolve().parents[1] / "scripts" / "lessons_actor_index.py"
    fake_scripts = ctx["repo"] / "defender" / "scripts"
    fake_scripts.mkdir(parents=True, exist_ok=True)
    (fake_scripts / "lessons_actor_index.py").write_text(script.read_text())

    def _run(extra: list[str]) -> str:
        proc = subprocess.run(
            [sys.executable, str(fake_scripts / "lessons_actor_index.py"), *extra],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout

    out = _run([])
    assert "live-claim" in out
    assert "stale-claim" not in out

    out2 = _run(["--include-stale"])
    assert "live-claim" in out2
    assert "stale-claim" in out2
