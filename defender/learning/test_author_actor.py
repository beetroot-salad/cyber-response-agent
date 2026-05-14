"""Unit tests for author_actor.py — the actor lessons curator.

Covers the deterministic pre/post-flight without spawning ``claude -p``.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Pre-load _author_runner / _author_shared so the import inside
# author_actor.py resolves the same way it does at runtime.
_HERE = Path(__file__).resolve().parent
_load("_author_runner_t", _HERE / "_author_runner.py")
sys.modules["_author_runner"] = sys.modules["_author_runner_t"]
_load("_author_shared_t", _HERE / "_author_shared.py")
sys.modules["_author_shared"] = sys.modules["_author_shared_t"]

aa = _load("author_actor_t", _HERE / "author_actor.py")
shared = sys.modules["_author_shared"]

AuthorError = aa.AuthorError


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _isolate(monkeypatch, tmp_path: Path):
    """Run author_actor against a tmp repo. Returns dict of pointers."""
    repo = tmp_path / "repo"
    learning = repo / "defender" / "learning"
    pending = learning / "_pending"
    lessons = repo / "defender" / "lessons-actor"
    (lessons / "tradecraft").mkdir(parents=True)
    (lessons / "environment").mkdir(parents=True)
    pending.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "t@t"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "t"], check=True
    )
    # Seed an initial commit so HEAD exists and rev-list works.
    seed = repo / "README"
    seed.write_text("seed\n")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "seed"], check=True
    )

    monkeypatch.setattr(aa, "REPO_ROOT", repo)
    monkeypatch.setattr(aa, "LEARNING_DIR", learning)
    monkeypatch.setattr(aa, "LESSONS_ACTOR_DIR", lessons)
    monkeypatch.setattr(aa, "PENDING_DIR", pending)
    monkeypatch.setattr(aa, "PENDING_FILE", pending / "actor_observations.jsonl")
    monkeypatch.setattr(
        aa, "CONSUMED_FILE", pending / "actor_observations.consumed.jsonl"
    )
    monkeypatch.setattr(aa, "LOCK_FILE", pending / ".actor.lock")
    monkeypatch.setattr(aa, "AUTHOR_RUN_LOG", pending / "author_actor_run.jsonl")
    monkeypatch.setattr(shared, "REPO_ROOT", repo)
    monkeypatch.setattr(shared, "LEARNING_DIR", learning)
    monkeypatch.setattr(shared, "REPO_LOCK_FILE", learning / "_author.lock")

    return {
        "repo": repo,
        "learning": learning,
        "pending": pending,
        "lessons": lessons,
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
        "source_run_dir": source_run_dir or f"defender/learning/runs/{observation_id.split('/')[0]}/",
    }


def _write_queue(pending: Path, rows: list[dict]) -> None:
    pending.mkdir(parents=True, exist_ok=True)
    path = pending / "actor_observations.jsonl"
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _write_lesson(
    lessons: Path,
    channel: str,
    slug: str,
    frontmatter: dict,
    body: str = "x\n",
) -> Path:
    fm_text = yaml.safe_dump(frontmatter, sort_keys=False).strip()
    path = lessons / channel / f"{slug}.md"
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
    # Stub invoke_agent so the test never spawns claude; the to_author
    # list it sees must contain only caught + incoherent.
    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, generation, actor_model):
        captured.append(observations)
        # Return a no-commit result that consumes all to_author.
        return {
            "committed": [],
            "consumed_skip": [
                {"observation_id": o["observation_id"], "reason": "test"}
                for o in observations
            ],
            "commit_sha": None,
        }

    monkeypatch.setattr(aa, "invoke_agent", fake_invoke)
    rc = aa.run_batch()
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
        "tradecraft",
        "existing",
        {
            "techniques": ["T1078"],
            "actor_type": ["internal"],
            "relevance_criteria": "x",
            "recorded_at": "old",
            "source_observation_ids": ["a/0"],
        },
    )
    # Pre-flight requires lessons-actor/ to be git-clean.
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/tradecraft/existing.md"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "seed lesson"],
        check=True,
    )
    _write_queue(
        ctx["pending"], [_row("a/0", "caught"), _row("b/0", "caught")]
    )

    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, generation, actor_model):
        captured.append(observations)
        return {
            "committed": [],
            "consumed_skip": [
                {"observation_id": o["observation_id"], "reason": "test"}
                for o in observations
            ],
            "commit_sha": None,
        }

    monkeypatch.setattr(aa, "invoke_agent", fake_invoke)
    rc = aa.run_batch()
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

    def fake_invoke(observations, batch_id, generation, actor_model):
        captured.append(observations)
        return {
            "committed": [],
            "consumed_skip": [
                {"observation_id": o["observation_id"], "reason": "t"}
                for o in observations
            ],
            "commit_sha": None,
        }

    monkeypatch.setattr(aa, "invoke_agent", fake_invoke)
    rc = aa.run_batch()
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


def test_result_partition_rejects_unknown_observation(monkeypatch, tmp_path: Path):
    _isolate(monkeypatch, tmp_path)
    to_author = [_row("a/0", "caught")]
    result = {
        "committed": ["a/0", "bogus/9"],
        "consumed_skip": [],
        "commit_sha": "deadbeef",
    }
    with pytest.raises(AuthorError, match="unknown observations"):
        aa.validate_agent_result_partition(result, to_author)


def test_result_partition_rejects_duplicate_across_buckets(
    monkeypatch, tmp_path: Path
):
    _isolate(monkeypatch, tmp_path)
    to_author = [_row("a/0", "caught")]
    result = {
        "committed": ["a/0"],
        "consumed_skip": [{"observation_id": "a/0", "reason": "x"}],
        "commit_sha": "deadbeef",
    }
    with pytest.raises(AuthorError, match="more than once"):
        aa.validate_agent_result_partition(result, to_author)


def test_result_partition_rejects_missing_observation(monkeypatch, tmp_path: Path):
    _isolate(monkeypatch, tmp_path)
    to_author = [_row("a/0", "caught"), _row("b/0", "caught")]
    result = {"committed": ["a/0"], "consumed_skip": [], "commit_sha": "x"}
    with pytest.raises(AuthorError, match="missing observations"):
        aa.validate_agent_result_partition(result, to_author)


def test_post_flight_rejects_missing_generation_trailer(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    # Land a commit inside lessons-actor with no trailers.
    p = ctx["lessons"] / "tradecraft" / "x.md"
    p.write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/tradecraft/x.md"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "no trailers here"],
        check=True,
    )
    with pytest.raises(AuthorError, match="Generation:"):
        aa.assert_head_trailers(1, "claude-sonnet-4-6")


def test_post_flight_accepts_correct_trailers(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    p = ctx["lessons"] / "tradecraft" / "x.md"
    p.write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/tradecraft/x.md"],
        check=True,
    )
    msg = "lesson batch\n\nGeneration: 1\nActor-Model: claude-sonnet-4-6\n"
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", msg], check=True
    )
    aa.assert_head_trailers(1, "claude-sonnet-4-6")
    # And the head-only-lessons-actor predicate accepts this commit.
    assert aa.head_changed_only_lessons_actor() is True


def test_post_flight_rejects_commit_outside_lessons_actor(monkeypatch, tmp_path: Path):
    ctx = _isolate(monkeypatch, tmp_path)
    other = ctx["repo"] / "defender" / "lessons"
    other.mkdir(parents=True)
    (other / "y.md").write_text("y\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons/y.md"], check=True
    )
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", "wrong dir"],
        check=True,
    )
    assert aa.head_changed_only_lessons_actor() is False


def test_post_flight_rejects_no_commit_result_when_head_changed(
    monkeypatch, tmp_path: Path
):
    ctx = _isolate(monkeypatch, tmp_path)
    pre_agent_head = aa.git_head_sha()
    p = ctx["lessons"] / "tradecraft" / "x.md"
    p.write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "add", "defender/lessons-actor/tradecraft/x.md"],
        check=True,
    )
    msg = "lesson batch\n\nGeneration: 1\nActor-Model: claude-sonnet-4-6\n"
    subprocess.run(
        ["git", "-C", str(ctx["repo"]), "commit", "-q", "-m", msg],
        check=True,
    )
    result = {"committed": [], "consumed_skip": [], "commit_sha": None}

    with pytest.raises(AuthorError, match="HEAD changed"):
        aa.verify_agent_state(result, 1, "claude-sonnet-4-6", pre_agent_head)


# ---------------------------------------------------------------------------
# Generation counter
# ---------------------------------------------------------------------------


def test_actor_generation_count_starts_at_1(monkeypatch, tmp_path: Path):
    _isolate(monkeypatch, tmp_path)
    assert shared.actor_generation_count() == 1


def test_actor_generation_count_ignores_pre_author_commits(
    monkeypatch, tmp_path: Path
):
    """Pre-author commits that touch lessons-actor/ (corpus structure,
    templates) must NOT advance the counter — only commits carrying the
    Actor-Model: trailer do."""
    ctx = _isolate(monkeypatch, tmp_path)
    pre = ctx["lessons"] / "environment" / "_TEMPLATE.md"
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
        p = ctx["lessons"] / "tradecraft" / f"gen{i}.md"
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


def test_rotate_queue_preserves_held_and_appends_consumed(
    monkeypatch, tmp_path: Path
):
    ctx = _isolate(monkeypatch, tmp_path)
    held = [{**_row("h/0", "caught"), "held_reason": "x"}]
    consumed = [
        {**_row("c/0", "caught"), "consumed_category": "consumed_committed"},
        {**_row("s/0", "caught"), "consumed_category": "consumed_skip", "skip_reason": "low"},
    ]
    aa.rotate_queue(held=held, consumed=consumed, commit_sha="abc123")

    left = [
        json.loads(l)
        for l in (ctx["pending"] / "actor_observations.jsonl").read_text().splitlines()
        if l.strip()
    ]
    assert [r["observation_id"] for r in left] == ["h/0"]

    consumed_rows = [
        json.loads(l)
        for l in (ctx["pending"] / "actor_observations.consumed.jsonl")
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


def test_index_cli_hides_stale_env_by_default(monkeypatch, tmp_path: Path):
    """The runtime actor uses lessons_actor_index.py; stale lessons must
    not be surfaced unless --include-stale is passed."""
    ctx = _isolate(monkeypatch, tmp_path)
    _write_lesson(
        ctx["lessons"],
        "environment",
        "live-claim",
        {
            "actor_type": ["internal"],
            "subject": "docker-auditing",
            "relevance_criteria": "live one",
            "recorded_at": "r1",
            "status": "live",
            "source_observation_ids": ["r1/0"],
        },
    )
    _write_lesson(
        ctx["lessons"],
        "environment",
        "stale-claim",
        {
            "actor_type": ["internal"],
            "subject": "docker-auditing",
            "relevance_criteria": "stale one",
            "recorded_at": "r0",
            "status": "stale",
            "superseded_by": "live-claim",
            "source_observation_ids": ["r0/0"],
        },
    )
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "lessons_actor_index.py"
    )
    # Stage a fake repo layout so the script's LESSONS_ROOT
    # (= parents[2]/defender/lessons-actor) resolves under our tmp repo.
    # Easiest: symlink the script into ctx["repo"]/defender/scripts/, and
    # invoke via subprocess so the script's own .venv reexec doesn't fire.
    fake_scripts = ctx["repo"] / "defender" / "scripts"
    fake_scripts.mkdir(parents=True, exist_ok=True)
    (fake_scripts / "lessons_actor_index.py").write_text(script.read_text())

    def _run(extra: list[str]) -> str:
        proc = subprocess.run(
            [sys.executable, str(fake_scripts / "lessons_actor_index.py"),
             "--channel", "environment", *extra],
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
