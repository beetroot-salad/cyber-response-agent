"""Unit tests for the actor lessons curator.

Covers the deterministic pre/post-flight without a real model call. The
transaction envelope lives in ``_author_curator``; ``author_actor`` supplies the
actor ``CuratorConfig``. Tests drive the engine with a config pointed at a tmp repo
and an injected ``invoke_agent`` — no module-global monkeypatching: git, repo lock,
and the generation counters all take their root/lock-file by param via the config.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from defender import _git  # type: ignore[import-not-found]
from defender.learning.author import curator as curator  # type: ignore[import-not-found]
from defender.learning.author import shared as shared  # type: ignore[import-not-found]
from defender.learning.author.malicious_actor import run as aa  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]





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
    seed = repo / "README"
    seed.write_text("seed\n")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "seed"], check=True)

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


def test_existing_observation_ids_skips_an_undecodable_lesson(tmp_path: Path, capsys):
    """One corrupt byte must not abort the curator drain. ``read_text()`` raises
    ``UnicodeDecodeError`` — a ``ValueError``, not an ``OSError`` — so the un-guarded read this
    pre-flight used to do took the whole drain down, where the corpus manifest beside it warned and
    skipped the one file. The well-formed sibling's ids must still come back, because an id this
    scan fails to see is an observation the curator re-authors as a duplicate lesson."""
    corpus = tmp_path / "lessons-actor"
    corpus.mkdir()
    (corpus / "good.md").write_text(
        "---\nname: good\nsource_observation_ids:\n  - a/0\n---\nbody\n"
    )
    (corpus / "corrupt.md").write_bytes(b"---\nname: c\n---\n\xff\xfe\n")
    assert curator.existing_observation_ids(corpus) == {"a/0"}
    assert "corrupt.md" in capsys.readouterr().err


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




def test_missing_source_bundle_is_held_not_authored(tmp_path: Path):
    """#425 follow-up: a non-empty source_run_dir whose bundle dir is *absent* is an
    anomaly (a resolution regression / deleted bundle), so it is held loudly as
    ``source_bundle_missing`` instead of being silently read as not-held-out and authored.
    A *present* bundle with no ground_truth.yaml is a genuine not-held-out run and still
    authors — the guard must not fire on it."""
    ctx = _isolate(tmp_path)
    _write_queue(ctx["pending"], [_row("present/0", "caught"), _row("gone/0", "caught")])
    shutil.rmtree(ctx["learning"] / "runs" / "gone")

    captured: list[list[dict]] = []

    def fake_invoke(observations, batch_id, cfg):
        captured.append(observations)
        return _consume_all(observations, batch_id, cfg)

    rc = curator.run_batch(hold_committed=False, cfg=_cfg(ctx, fake_invoke))
    assert rc == 0
    assert {o["observation_id"] for o in captured[0]} == {"present/0"}

    rows_left = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.jsonl").read_text().splitlines()
    ]
    assert len(rows_left) == 1
    assert rows_left[0]["observation_id"] == "gone/0"
    assert rows_left[0]["held_reason"] == "source_bundle_missing"




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
    (ctx["lessons"] / "x.md").write_text("hello\n")

    new_sha = curator.commit_corpus(
        3, "claude-sonnet-4-6", "defender/actor: lesson batch abc", cfg
    )
    assert new_sha == curator.git_head_sha(ctx["repo"])
    msg = _head_message(ctx["repo"])
    assert "Generation: 3" in msg
    assert "Actor-Model: claude-sonnet-4-6" in msg
    assert shared.actor_generation_count(ctx["repo"]) == 2
    assert _head_files(ctx["repo"]) == ["defender/lessons-actor/x.md"]
    assert curator.changes_outside_corpus(ctx["repo"], cfg.corpus_dir_rel) == []


def test_committed_batch_gets_trailers_stamped_by_loop(tmp_path: Path):
    """End-to-end: the agent leaves a lesson in the working tree (no git); run_batch
    commits it with the provenance trailers and rotates the committed observation out
    against the loop's commit sha."""
    ctx = _isolate(tmp_path)
    _write_queue(ctx["pending"], [_row("a/0", "caught")])

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

    cfg = _cfg(ctx, committing_invoke)
    rc = curator.run_batch(hold_committed=False, cfg=cfg)
    assert rc == 0
    msg = _head_message(ctx["repo"])
    assert "Generation: 1" in msg
    assert f"Actor-Model: {cfg.actor_model}" in msg
    assert _head_files(ctx["repo"]) == ["defender/lessons-actor/lesson.md"]
    consumed = [
        json.loads(line)
        for line in (ctx["pending"] / "actor_observations.consumed.jsonl")
        .read_text()
        .splitlines()
    ]
    by_id = {r["observation_id"]: r for r in consumed}
    assert by_id["a/0"]["consumed_category"] == "consumed_committed"
    assert by_id["a/0"]["consumed_commit"] == curator.git_head_sha(ctx["repo"])
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

    with pytest.raises(_git.GitError):
        curator.run_batch(hold_committed=False, cfg=_cfg(ctx, committing_invoke))
    assert curator.git_head_sha(ctx["repo"]) == head_before
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




def test_repo_lock_blocks_second_acquire(tmp_path: Path):
    ctx = _isolate(tmp_path)
    lock = ctx["learning"] / "_author.lock"
    fh = shared.acquire_repo_lock(lock, timeout_seconds=2)
    try:
        with pytest.raises(TimeoutError, match="repo lock"):
            shared.acquire_repo_lock(lock, timeout_seconds=1)
    finally:
        shared.release_repo_lock(fh)
    fh2 = shared.acquire_repo_lock(lock, timeout_seconds=1)
    shared.release_repo_lock(fh2)




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
    assert "consumed_commit" not in by_id["s/0"]




def _defender_import_closure(script: Path, repo_src: Path) -> set[str]:
    """Every `defender.*` module reachable from `script`, through imports at ANY depth.

    `ast.walk`, not `tree.body`: `_corpus.iter_lessons` imports `defender._frontmatter` INSIDE
    the function (deliberately — the module must stay yaml-free at import time for the actor's
    system-interpreter bootstrap). A module-level-only closure misses it, and the subprocess dies
    with ModuleNotFoundError the moment nothing else puts the real tree on sys.path."""
    def direct(src: Path) -> set[str]:
        found: set[str] = set()
        for node in ast.walk(ast.parse(src.read_text())):
            if isinstance(node, ast.Import):
                found |= {a.name for a in node.names if a.name.startswith("defender.")}
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.level == 0
                and node.module.startswith("defender.")
            ):
                found.add(node.module)
        return found

    seen: set[str] = set()
    queue = direct(script)
    while queue:
        module = queue.pop()
        if module in seen:
            continue
        seen.add(module)
        real = repo_src / (module.replace(".", "/") + ".py")
        if real.exists():
            queue |= direct(real)
    return seen


def _index_cli_runner(ctx: dict):
    """Mirror lessons_actor_index.py + its import deps into ctx's tmp repo (at the real
    scripts/lessons/ depth, so the script's REPO_ROOT resolves to the fake repo) and return a
    ``_run(extra_argv) -> stdout`` closure that runs it against ctx's isolated corpus."""
    defender_src = Path(__file__).resolve().parents[1]
    repo_src = defender_src.parent
    script = defender_src / "scripts" / "lessons" / "lessons_actor_index.py"
    fake_scripts = ctx["repo"] / "defender" / "scripts" / "lessons"
    fake_scripts.mkdir(parents=True, exist_ok=True)
    (fake_scripts / "lessons_actor_index.py").write_text(script.read_text())
    for module in _defender_import_closure(script, repo_src):
        dst = ctx["repo"] / (module.replace(".", "/") + ".py")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text((repo_src / (module.replace(".", "/") + ".py")).read_text())

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
    out = _run(["--applies-to", "authorized-keys-host-cr-baseline"])
    assert "cover-prereqs" in out
    assert "unrelated" not in out
    assert "no-applies" not in out
    out2 = _run(["--applies-to", "some-other-subject,svc-monitoring-cadence-baseline"])
    assert "cover-prereqs" in out2
    assert "unrelated" in out2
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
        + "\n"
        + json.dumps(_row("r2/0", "survived")) + "\n"
        + '{"observation_id": "r3/0"'
    )
    batch = curator.read_batch(cfg)
    assert [r["observation_id"] for r in batch] == ["r1/0", "r2/0"]


def test_read_batch_missing_file_is_empty(tmp_path):
    ctx = _isolate(tmp_path)
    cfg = _cfg(ctx, _consume_all)
    if cfg.channel.file.exists():
        cfg.channel.file.unlink()
    assert curator.read_batch(cfg) == []
