"""Unit tests for the actor lessons curator.

Covers the deterministic pre/post-flight without a real model call. The
transaction envelope lives in ``_author_curator``; ``author_actor`` supplies the
actor ``CuratorConfig``. Tests drive the engine with a config pointed at a tmp repo
and an injected ``invoke_agent`` — no module-global monkeypatching: git, repo lock,
and the generation counters all take their root/lock-file by param via the config.
"""
from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# The curator engine, the lock/generation helpers, and the actor config wrapper.
# Each resolves to one module instance, and the engine's repo root, repo lock, and
# generation counters all flow through the injected ``CuratorConfig`` — no ``shared.*``
# module globals to patch (#389).
from defender import _git  # type: ignore[import-not-found]
from defender.learning.author import curator as curator  # type: ignore[import-not-found]
from defender.learning.author import shared as shared  # type: ignore[import-not-found]
from defender.learning.author.malicious_actor import run as aa  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]

# Reference ``shared.AuthorError`` live rather than a captured module-level alias:
# every author module binds ``AuthorError = _shared.AuthorError`` once at import, so the
# one shared class object is exactly what the curators raise — matching it directly stays
# correct without depending on any import-time aliasing (no conftest reload to rebind it).


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _isolate(tmp_path: Path):
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

    # The engine runs every git/lock/generation operation at the injected
    # ``cfg.repo_root`` / ``cfg.repo_lock_file`` (built from ``LoopPaths(repo_root=repo)``
    # in ``_cfg``); the generation counters take ``repo_root`` by param. Nothing on
    # ``_author_shared`` needs pointing at the tmp repo any more (#389).
    return {
        "repo": repo,
        "learning": learning,
        "pending": pending,
        "lessons": lessons,
    }


def _cfg(ctx: dict, invoke_agent) -> curator.CuratorConfig:
    """The production actor config, repointed at the tmp repo (the factory derives the
    queue + corpus paths from ``LoopPaths(repo_root=...)``, matching ctx exactly) and
    given an injected ``invoke_agent`` so no real agent runs."""
    return dataclasses.replace(
        aa.build_actor_config(LoopPaths(repo_root=ctx["repo"])),
        invoke_agent=invoke_agent,
    )


def _consume_all(observations, batch_id, cfg):
    """A no-commit AUTHOR_RESULT that routes every to_author obs to consumed_skip."""
    return {
        "committed": [],
        "consumed_skip": [
            {"observation_id": o["observation_id"], "reason": "test"}
            for o in observations
        ],
        "commit_message": None,
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
    # Model production: persist always creates the durable run-bundle dir under runs/ for
    # every persisted run (``_copy_shared_inputs`` mkdirs ``learning_run_dir``), so a
    # queued observation always has its bundle on disk. Create it here so the curator's
    # source-bundle-missing guard (#425) sees the realistic layout; a test that wants the
    # missing-bundle anomaly removes a specific bundle after writing the queue.
    runs = pending.parent / "runs"
    path = pending / "actor_observations.jsonl"
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
            src = (r.get("source_run_dir") or "").rstrip("/")
            if src:
                (runs / Path(src).name).mkdir(parents=True, exist_ok=True)


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
    tmp_path: Path
):
    ctx = _isolate(tmp_path)
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

    def fake_invoke(observations, batch_id, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, cfg)

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


def test_idempotency_consumes_already_cited_observations(tmp_path: Path):
    ctx = _isolate(tmp_path)
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

    def fake_invoke(observations, batch_id, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, cfg)

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


def test_held_out_double_check_holds_observation(tmp_path: Path):
    ctx = _isolate(tmp_path)
    # Synthesize a held-out source run dir under the tmp repo root.
    src = ctx["repo"] / "defender" / "learning" / "runs" / "held/"
    src.mkdir(parents=True)
    (src / "ground_truth.yaml").write_text("held_out: true\n")
    row = _row("held/0", "caught", source_run_dir="defender/learning/runs/held/")
    _write_queue(ctx["pending"], [row, _row("ok/0", "caught")])

    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, cfg)

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


def test_held_out_double_check_worktree_immune(tmp_path: Path):
    """#425: under a batch worktree the held-out double-check must resolve the bundle
    off the shared state root (cfg.runs_dir), not the worktree repo_root — else a
    held-out case silently leaks into the corpus."""
    orig = tmp_path / "checkout"
    (orig / "defender" / "learning").mkdir(parents=True)
    worktree = tmp_path / "worktree"  # fresh origin/main checkout: no runs/
    worktree.mkdir()
    # The held-out bundle lives under the ORIGINAL state root, never the worktree.
    src = orig / "defender" / "learning" / "runs" / "held"
    src.mkdir(parents=True)
    (src / "ground_truth.yaml").write_text("held_out: true\n")

    # The drain re-roots the layout at the worktree but keeps the shared state dir.
    cfg = aa.build_actor_config(LoopPaths(repo_root=orig).with_repo_root(worktree))
    assert cfg.repo_root == worktree
    assert cfg.runs_dir == orig / "defender" / "learning" / "runs"

    src_rel = "defender/learning/runs/held/"
    assert curator.is_held_out_source(cfg.runs_dir, src_rel) is True
    # The pre-#425 join (repo_root / source_run_dir) would miss it in the worktree.
    assert not (cfg.repo_root / src_rel / "ground_truth.yaml").is_file()


def test_missing_source_bundle_is_held_not_authored(tmp_path: Path):
    """#425 follow-up: a non-empty source_run_dir whose bundle dir is *absent* is an
    anomaly (a resolution regression / deleted bundle), so it is held loudly as
    ``source_bundle_missing`` instead of being silently read as not-held-out and authored.
    A *present* bundle with no ground_truth.yaml is a genuine not-held-out run and still
    authors — the guard must not fire on it."""
    ctx = _isolate(tmp_path)
    # _write_queue models production: it creates the durable bundle dir for both rows
    # (no ground_truth.yaml → genuinely not held out).
    _write_queue(ctx["pending"], [_row("present/0", "caught"), _row("gone/0", "caught")])
    # Simulate the anomaly: the durable bundle LEARN created is gone at author time.
    shutil.rmtree(ctx["learning"] / "runs" / "gone")

    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, cfg)

    rc = curator.run_batch(hold_committed=False, cfg=_cfg(ctx, fake_invoke))
    assert rc == 0
    # Only the present-bundle observation reaches the agent; the missing one is held.
    assert {o["observation_id"] for o in captured[0]} == {"present/0"}

    rows_left = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.jsonl").read_text().splitlines()
    ]
    assert len(rows_left) == 1
    assert rows_left[0]["observation_id"] == "gone/0"
    assert rows_left[0]["held_reason"] == "source_bundle_missing"


# ---------------------------------------------------------------------------
# Result partition + post-flight
# ---------------------------------------------------------------------------


def test_result_partition_rejects_unknown_observation():
    to_author = [_row("a/0", "caught")]
    result = {
        "committed": ["a/0", "bogus/9"],
        "consumed_skip": [],
        "commit_message": "m",
    }
    with pytest.raises(shared.AuthorError, match="unknown observations"):
        shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )


def test_result_partition_rejects_duplicate_across_buckets():
    to_author = [_row("a/0", "caught")]
    result = {
        "committed": ["a/0"],
        "consumed_skip": [{"observation_id": "a/0", "reason": "x"}],
        "commit_message": "m",
    }
    with pytest.raises(shared.AuthorError, match="more than once"):
        shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )


def test_result_partition_rejects_missing_observation():
    to_author = [_row("a/0", "caught"), _row("b/0", "caught")]
    result = {"committed": ["a/0"], "consumed_skip": [], "commit_message": "m"}
    with pytest.raises(shared.AuthorError, match="missing observations"):
        shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )


def _head_files(repo: Path) -> list[str]:
    return subprocess.run(
        ["git", "-C", str(repo), "show", "--name-only", "--pretty=format:", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.split()


def _head_message(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--pretty=%B", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout


def test_commit_corpus_appends_provenance(tmp_path: Path):
    """The loop — not the agent — commits the corpus with the Generation/model trailers,
    so the recorded provenance can't drift from the prompt. The agent runs no git: it
    leaves the lesson un-committed in the working tree and the loop commits it."""
    ctx = _isolate(tmp_path)
    cfg = _cfg(ctx, _consume_all)
    (ctx["lessons"] / "x.md").write_text("hello\n")  # agent edit, uncommitted

    new_sha = curator.commit_corpus(
        3, "claude-sonnet-4-6", "defender/actor: lesson batch abc", cfg
    )
    assert new_sha == curator.git_head_sha(ctx["repo"])
    msg = _head_message(ctx["repo"])
    assert "Generation: 3" in msg
    assert "Actor-Model: claude-sonnet-4-6" in msg
    # The committed trailer is exactly what the generation counter greps, so the next
    # generation advances — provenance round-trips through git history.
    assert shared.actor_generation_count(ctx["repo"]) == 2
    # The commit touched only the corpus, and the working tree is now clean.
    assert _head_files(ctx["repo"]) == ["defender/lessons-actor/x.md"]
    assert curator.changes_outside_corpus(ctx["repo"], cfg.corpus_dir_rel) == []


def test_committed_batch_gets_trailers_stamped_by_loop(tmp_path: Path):
    """End-to-end: the agent leaves a lesson in the working tree (no git); run_batch
    commits it with the provenance trailers and rotates the committed observation out
    against the loop's commit sha."""
    ctx = _isolate(tmp_path)
    _write_queue(ctx["pending"], [_row("a/0", "caught")])

    def committing_invoke(observations, batch_id, cfg):
        # Mimic the agent: write a lesson, run NO git, return the commit message as data.
        oid = observations[0]["observation_id"]
        (ctx["lessons"] / "lesson.md").write_text(
            f"---\nsource_observation_ids: [{oid}]\n---\nbody\n"
        )
        return {
            "committed": [oid],
            "consumed_skip": [],
            "commit_message": f"defender/actor: lesson batch {batch_id}",
        }

    cfg = _cfg(ctx, committing_invoke)
    rc = curator.run_batch(hold_committed=False, cfg=cfg)
    assert rc == 0
    # The loop committed the lesson with the trailers the agent never wrote — the actor model
    # comes from cfg (config's ACTOR_MODEL default), stamped by the LOOP, not the agent, so this
    # tracks the configured model rather than pinning a literal that a model flip would break.
    msg = _head_message(ctx["repo"])
    assert "Generation: 1" in msg
    assert f"Actor-Model: {cfg.actor_model}" in msg
    assert _head_files(ctx["repo"]) == ["defender/lessons-actor/lesson.md"]
    # a/0 rotated out to consumed, stamped with the loop's commit sha.
    consumed = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.consumed.jsonl")
        .read_text()
        .splitlines()
    ]
    by_id = {r["observation_id"]: r for r in consumed}
    assert by_id["a/0"]["consumed_category"] == "consumed_committed"
    assert by_id["a/0"]["consumed_commit"] == curator.git_head_sha(ctx["repo"])
    # Queue drained.
    assert (ctx["pending"] / "actor_observations.jsonl").read_text().strip() == ""


def test_commit_failure_is_atomic_queue_intact(tmp_path: Path):
    """#321 regression: if the loop's commit fails (here, a rejecting pre-commit hook —
    the issue's exact trigger), no commit lands, there is **no** un-stamped lesson commit
    on HEAD, and the queue is fully intact for retry."""
    ctx = _isolate(tmp_path)
    hooks = ctx["repo"] / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    _write_queue(ctx["pending"], [_row("a/0", "caught")])
    head_before = curator.git_head_sha(ctx["repo"])

    def committing_invoke(observations, batch_id, cfg):
        oid = observations[0]["observation_id"]
        (ctx["lessons"] / "lesson.md").write_text(
            f"---\nsource_observation_ids: [{oid}]\n---\nbody\n"
        )
        return {
            "committed": [oid],
            "consumed_skip": [],
            "commit_message": f"defender/actor: lesson batch {batch_id}",
        }

    # Post-migration the commit failure is a systemic ``GitError`` (a broken git op, not an
    # AuthorError), which propagates out of run_batch — the drain enrolls it as exit 2.
    with pytest.raises(_git.GitError):
        curator.run_batch(hold_committed=False, cfg=_cfg(ctx, committing_invoke))
    # No un-stamped (or any) lesson commit on HEAD — the failure is atomic.
    assert curator.git_head_sha(ctx["repo"]) == head_before
    # The observation stays in the active queue; nothing rotated out.
    left = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert {r["observation_id"] for r in left} == {"a/0"}
    consumed_path = ctx["pending"] / "actor_observations.consumed.jsonl"
    assert not consumed_path.exists() or consumed_path.read_text().strip() == ""


def test_verify_threads_observations_noun(tmp_path: Path):
    """The curator's ``_author_to_author`` calls ``shared.verify_agent_state`` with *its*
    corpus noun (``observations``) and ``cfg`` corpus, not the author side's
    ``findings``/``defender/lessons/``. ``committed`` non-empty but the corpus clean is the
    inconsistent state the post-flight gate must reject — and the one branch whose error
    string carries the noun, so a mis-threaded arg would surface here. The shared-layer
    branch logic itself is covered corpus-agnostically in test_author_shared."""
    ctx = _isolate(tmp_path)
    cfg = _cfg(ctx, _consume_all)
    result = {"committed": ["a/0"], "consumed_skip": [], "commit_message": "m"}
    with pytest.raises(shared.AuthorError, match="committed observations but left"):
        shared.verify_agent_state(
            cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel,
            "observations", [],
        )


# ---------------------------------------------------------------------------
# Generation counter
# ---------------------------------------------------------------------------


def test_actor_generation_count_starts_at_1(tmp_path: Path):
    ctx = _isolate(tmp_path)
    assert shared.actor_generation_count(ctx["repo"]) == 1


def test_actor_generation_count_ignores_pre_author_commits(tmp_path: Path):
    """Pre-author commits that touch lessons-actor/ (corpus structure, templates)
    must NOT advance the counter — only commits carrying the Actor-Model: trailer do."""
    ctx = _isolate(tmp_path)
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
    assert shared.actor_generation_count(ctx["repo"]) == 1


def test_actor_generation_count_increments_with_prior_author_commits(
    tmp_path: Path
):
    ctx = _isolate(tmp_path)
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
    assert shared.actor_generation_count(ctx["repo"]) == 3


# ---------------------------------------------------------------------------
# Repo lock
# ---------------------------------------------------------------------------


def test_repo_lock_blocks_second_acquire(tmp_path: Path):
    ctx = _isolate(tmp_path)
    lock = ctx["learning"] / "_author.lock"
    fh = shared.acquire_repo_lock(lock, timeout_seconds=2)
    try:
        with pytest.raises(TimeoutError, match="repo lock"):
            shared.acquire_repo_lock(lock, timeout_seconds=1)
    finally:
        shared.release_repo_lock(fh)
    # After release a fresh acquire succeeds.
    fh2 = shared.acquire_repo_lock(lock, timeout_seconds=1)
    shared.release_repo_lock(fh2)


# ---------------------------------------------------------------------------
# Queue rotation
# ---------------------------------------------------------------------------


def test_rotate_queue_preserves_held_and_appends_consumed(tmp_path: Path):
    ctx = _isolate(tmp_path)
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


def _index_cli_runner(ctx: dict):
    """Mirror lessons_actor_index.py + its import deps into ctx's tmp repo (at the real
    scripts/lessons/ depth, so the script's REPO_ROOT resolves to the fake repo) and return a
    ``_run(extra_argv) -> stdout`` closure that runs it against ctx's isolated corpus."""
    defender_src = Path(__file__).resolve().parents[1]
    script = defender_src / "scripts" / "lessons" / "lessons_actor_index.py"
    fake_scripts = ctx["repo"] / "defender" / "scripts" / "lessons"
    fake_scripts.mkdir(parents=True, exist_ok=True)
    (fake_scripts / "lessons_actor_index.py").write_text(script.read_text())
    # The script imports defender._frontmatter and the shared scripts.lessons._lessons_common
    # helper (both via its sys.path bootstrap), which re-exports scripts._venv — mirror all three.
    (ctx["repo"] / "defender" / "_frontmatter.py").write_text(
        (defender_src / "_frontmatter.py").read_text()
    )
    (fake_scripts / "_lessons_common.py").write_text(
        (defender_src / "scripts" / "lessons" / "_lessons_common.py").read_text()
    )
    (ctx["repo"] / "defender" / "scripts" / "_venv.py").write_text(
        (defender_src / "scripts" / "_venv.py").read_text()
    )

    def _run(extra: list[str]) -> str:
        proc = subprocess.run(
            [sys.executable, str(fake_scripts / "lessons_actor_index.py"), *extra],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout

    return _run


def test_index_cli_applies_to_filter(tmp_path: Path):
    """--applies-to selects pattern lessons whose applies_to frontmatter lists the queried env-fact
    subject (OR within the comma list) — the retrieval axis that previously needed grep (#517)."""
    ctx = _isolate(tmp_path)
    _write_lesson(ctx["lessons"], "cover-prereqs", {
        "techniques": ["T1036"], "mutable": False,
        "applies_to": ["svc-monitoring-cadence-baseline", "authorized-keys-host-cr-baseline"],
        "relevance_criteria": "cover on pre-existing infra",
    })
    _write_lesson(ctx["lessons"], "unrelated", {
        "techniques": ["T1078"], "mutable": False,
        "applies_to": ["some-other-subject"],
        "relevance_criteria": "different axis",
    })
    _write_lesson(ctx["lessons"], "no-applies", {
        "techniques": ["T1036"], "mutable": False,
        "relevance_criteria": "no applies_to key at all",
    })
    _run = _index_cli_runner(ctx)
    # names the subject -> only the lesson that lists it (excludes the mismatch AND the no-key lesson)
    out = _run(["--applies-to", "authorized-keys-host-cr-baseline"])
    assert "cover-prereqs" in out
    assert "unrelated" not in out
    assert "no-applies" not in out
    # OR within the comma list: either subject hits
    out2 = _run(["--applies-to", "some-other-subject,svc-monitoring-cadence-baseline"])
    assert "cover-prereqs" in out2
    assert "unrelated" in out2
    # no filter -> the field is opt-in; all live lessons surface
    out3 = _run([])
    assert "cover-prereqs" in out3
    assert "unrelated" in out3
    assert "no-applies" in out3


def test_index_cli_hides_stale_lessons_by_default(tmp_path: Path):
    """The runtime actor uses lessons_actor_index.py; stale lessons must not be
    surfaced unless --include-stale is passed. v2: stale-hiding applies to any
    mutable=true lesson, not just env-channel."""
    ctx = _isolate(tmp_path)
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
    _run = _index_cli_runner(ctx)

    out = _run([])
    assert "live-claim" in out
    assert "stale-claim" not in out

    out2 = _run(["--include-stale"])
    assert "live-claim" in out2
    assert "stale-claim" in out2


# ---------------------------------------------------------------------------
# read_batch — reads the pending queue tolerantly (#446)
# ---------------------------------------------------------------------------


def test_read_batch_skips_torn_line(tmp_path):
    """A torn last line from an interrupted append is skipped, not raised.

    Before #446 ``read_batch`` re-rolled ``json.loads`` with no try/except, so a
    half-written record raised ``JSONDecodeError`` — a type that escapes every
    drain guard and crashed the ``author_drain`` every tick. It now delegates to
    the shared tolerant reader, so the valid rows come through and the queue
    stays processable."""
    ctx = _isolate(tmp_path)
    cfg = _cfg(ctx, _consume_all)
    cfg.channel.file.parent.mkdir(parents=True, exist_ok=True)
    cfg.channel.file.write_text(
        json.dumps(_row("r1/0", "survived")) + "\n"
        + "\n"  # blank line
        + json.dumps(_row("r2/0", "survived")) + "\n"
        + '{"observation_id": "r3/0"'  # torn final append, no closing brace
    )
    batch = curator.read_batch(cfg)
    assert [r["observation_id"] for r in batch] == ["r1/0", "r2/0"]


def test_read_batch_missing_file_is_empty(tmp_path):
    ctx = _isolate(tmp_path)
    cfg = _cfg(ctx, _consume_all)
    if cfg.channel.file.exists():
        cfg.channel.file.unlink()
    assert curator.read_batch(cfg) == []
