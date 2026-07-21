"""Executable spec (write-tests step 8) for the curator GLM port's two survival
mechanisms: the ``author_actor_env`` dispatch fix and the batch-granular dead-letter
queue. Pre-implementation — the target code does NOT exist yet, so these tests ARE
the spec:

  * the dispatch tests FAIL with ``KeyError`` against current code — ``_CURATOR_MODULES``
    has no ``"author_actor_env"`` entry, and the ``_CURATOR_MODULES[module_name]``
    subscript at ``orchestrate._run_curator_module`` sits OUTSIDE the SubprocessError/
    OSError ``try``, so the miss wedges the whole drain (the correct red — it pins the
    fix);
  * the DLQ tests are RED until the attempts-bump / ``deadletter.jsonl`` mechanism
    lands. Today a per-run authoring fault returns rc 2 and leaves the active queue
    UNTOUCHED (``_run_batch_inner`` returns before ``rotate_queue``), so a poison batch
    is retried every tick forever — there is no ``attempts`` field and no sidecar.

Every assertion is on OBSERVABLE post-state only — the active queue file, the
``deadletter.jsonl`` sidecar, the return rc, or a propagated exception — never on an
engine internal. Faults are injected through the EXISTING ``cfg.invoke_agent`` seam via
``dataclasses.replace``; the fakes only raise/return, never classify or decide policy.

Substrate assumptions (pinned by the seam contract / working notes, reported to the
caller): the new per-row counter field is named ``attempts``; the sidecar file name
contains ``deadletter`` and lives under ``_pending`` (discovered by glob, so the test
is robust to ``deadletter.jsonl`` vs a per-channel ``*.deadletter.jsonl``); the new
knob is ``LEARNING_AUTHOR_MAX_ATTEMPTS`` (default 3), and quarantine fires when a
batch's rows REACH that count (the ``attempts >= max`` shape of the lead-author
``_quarantine_marker`` precedent).
"""
from __future__ import annotations

import dataclasses
import json
import subprocess
from pathlib import Path

import pytest

from defender.learning.core import orchestrate as orch  # type: ignore[import-not-found]
from defender.learning.author import curator as curator  # type: ignore[import-not-found]
from defender.learning.author.benign_actor import run as aenv  # type: ignore[import-not-found]
from defender.learning.core.config import FatalConfigError, LoopPaths  # type: ignore[import-not-found]




def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _env_repo(tmp_path: Path) -> LoopPaths:
    """An isolated git repo carrying the shared ``lessons-environment/`` corpus,
    committed clean, with the mutable learning state (queues/locks/deadletter) under
    the default in-repo ``_pending`` (gitignored). Returns its ``LoopPaths``."""
    repo = tmp_path / "repo"
    (repo / "defender" / "lessons-environment").mkdir(parents=True)
    (repo / "defender" / "lessons-environment" / ".gitkeep").write_text("")
    (repo / ".gitignore").write_text(
        "defender/learning/_pending/\n"
        "defender/learning/_author.lock\n"
        "defender/learning/.author-drain.lock\n"
        "defender/learning/.lead-author-drain.lock\n"
        "defender/learning/runs/\n"
    )
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return LoopPaths(repo_root=repo)


def _head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _obs(oid: str, outcome: str = "caught") -> dict:
    """One adversarial-env observation row. ``caught``/``incoherent`` are the
    adversarial config's finding-bearing outcomes (→ to_author); ``survived``/
    ``undecidable`` are skip-by-policy (→ consumed, never spawns). ``source_run_dir``
    empty so the partition's source-bundle / held-out checks are short-circuited."""
    return {"observation_id": oid, "judge_outcome": outcome, "source_run_dir": ""}


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _seed(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _append(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _active_by_id(paths: LoopPaths) -> dict[str, dict]:
    """The adversarial-env active queue, indexed by observation_id."""
    return {r["observation_id"]: r for r in _read_jsonl(paths.actor_environment_observations.file)}


def _deadletter_rows(paths: LoopPaths) -> list[dict]:
    """Rows across every ``*deadletter*.jsonl`` sidecar under ``_pending`` — discovered
    by glob so the assertion is robust to the exact sidecar name (a shared
    ``deadletter.jsonl`` or a per-channel ``*.deadletter.jsonl``)."""
    rows: list[dict] = []
    if not paths.pending_dir.exists():
        return rows
    for p in sorted(paths.pending_dir.rglob("*")):
        if p.is_file() and p.suffix == ".jsonl" and "deadletter" in p.name:
            rows.extend(_read_jsonl(p))
    return rows


def _max_attempts_seen(paths: LoopPaths) -> int:
    """Highest ``attempts`` counter across every ``_pending`` jsonl (0 if none carry
    one). The positive-control probe: a run that touched no attempts leaves this 0."""
    hi = 0
    if not paths.pending_dir.exists():
        return hi
    for p in paths.pending_dir.rglob("*.jsonl"):
        if p.is_file():
            for r in _read_jsonl(p):
                v = r.get("attempts")
                if isinstance(v, int):
                    hi = max(hi, v)
    return hi




def _fault_fake(observations: list[dict], batch_id: str, cfg) -> dict:
    """A per-run authoring fault. The ported invoke seam raises ``AuthorError`` on a
    ``RunUnprocessable`` / unparseable AUTHOR_RESULT; ``_author_to_author`` maps it to
    rc 2. This fake injects only that raise — it makes no DLQ decision."""
    raise curator.AuthorError("simulated per-run authoring fault")


def _systemic_fake(observations: list[dict], batch_id: str, cfg) -> dict:
    """A systemic misconfig (unroutable model / missing metered key) surfaces as
    ``FatalConfigError`` and must ESCAPE uncaught — never counted toward the budget."""
    raise FatalConfigError("simulated systemic misconfig")


def _skip_fake(observations: list[dict], batch_id: str, cfg) -> dict:
    """A clean all-skip batch (rc 0): every handed row is consumed-by-policy, nothing
    committed — a successful run that must never touch the attempt counter."""
    return {
        "committed": [],
        "consumed_skip": [{"observation_id": o["observation_id"], "reason": "dup"} for o in observations],
        "commit_message": "",
    }


def _commit_fake(observations: list[dict], batch_id: str, cfg) -> dict:
    """A clean authoring batch that commits: writes a valid lesson .md (so the
    working-tree cross-check's committed⇔dirty invariant holds) and reports every
    handed row committed. The loop is the sole committer."""
    lesson = cfg.corpus_dir / f"lesson-{batch_id}.md"
    lesson.write_text(
        "---\nsource_observation_ids:\n"
        + "".join(f"- {o['observation_id']}\n" for o in observations)
        + "---\n\nbody\n"
    )
    return {
        "committed": [o["observation_id"] for o in observations],
        "consumed_skip": [],
        "commit_message": "author clean environment lessons batch",
    }




def test_dispatch_author_actor_env_resolves_module() -> None:
    """dispatch-author-actor-env: driving the REAL dispatch primitive
    (``_run_curator_module``, whose ``_CURATOR_MODULES[name]`` subscript is the
    KeyError site) for the adversarial-env direction imports and reaches its
    ``run_batch`` WITHOUT KeyError, resolving to the right module.

    Against current code the ``"author_actor_env"`` key is absent, so the subscript
    raises ``KeyError`` — the correct red pinning the fix."""
    seen: dict[str, str] = {}

    def _capture(mod):
        seen["module"] = mod.run_batch.__module__
        return 0

    rc = orch._run_curator_module("author_actor_env", _capture)

    assert rc == 0
    assert seen["module"] == "defender.learning.author.benign_actor.env"


def test_dispatch_at_threshold_drain_completes(tmp_path: Path, monkeypatch) -> None:
    """dispatch-at-threshold-no-crash: with the adversarial-env observation queue at
    threshold, the REAL ``author_drain`` (its default ``_maybe_trigger_author``, NOT
    an injected fake trigger) dispatches curator D and COMPLETES — the uncaught
    ``KeyError`` no longer wedges the whole drain. Positive control: all four curator
    modules still resolve on the real dispatch path.

    The queue is seeded with skip-by-policy rows so curator D reaches ``run_batch``
    (past the KeyError site) but partitions to no ``to_author`` — no LLM spawn."""
    for env in (
        "LEARNING_AUTHOR_THRESHOLD",
        "LEARNING_AUTHOR_ACTOR_THRESHOLD",
        "LEARNING_AUTHOR_ENV_THRESHOLD",
        "LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD",
        "LEARNING_MERGE_MODE",
    ):
        monkeypatch.delenv(env, raising=False)
    paths = _env_repo(tmp_path)
    _seed(paths.actor_environment_observations.file, [_obs(f"env/{i}", "survived") for i in range(5)])

    class _RepoBranch:
        """Branch stub whose 'worktree' IS the real repo, so the curators run their
        real git transaction against a live checkout. No push/PR: a skip-only batch
        produces no commit, so finish_batch reports none."""

        branch_prefix = "lessons/"

        def __init__(self, repo_root: Path) -> None:
            self._repo = repo_root

        def open_pr_exists(self) -> bool:
            return False

        def start_batch(self, batch_id: str) -> Path:
            return self._repo

        def finish_batch(self, batch_id: str, wt: Path):
            return None

        def cleanup(self, wt: Path) -> None:
            pass

    rc = orch.author_drain(paths, branch=_RepoBranch(paths.repo_root))
    assert rc == 0

    expected = {
        "author": "defender.learning.author.lessons.run",
        "author_actor": "defender.learning.author.malicious_actor.run",
        "author_actor_benign": "defender.learning.author.benign_actor.run",
        "author_actor_env": "defender.learning.author.benign_actor.env",
    }
    for name, dotted in expected.items():
        box: list[str] = []
        orch._run_curator_module(name, lambda mod, box=box: (box.append(mod.__name__), 0)[1])
        assert box == [dotted]




def test_dlq_bumps_attempts_on_authoring_fault(tmp_path: Path, monkeypatch) -> None:
    """dlq-attempt-bump: a per-run authoring fault increments an ``attempts`` counter
    on the batch's active queue rows, persisted across ticks (1 → 2). Positive
    control: a SUCCESSFUL batch never writes an attempts counter at all."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "10")
    paths = _env_repo(tmp_path)
    cfg = aenv.build_adversarial_config(paths)
    ch = paths.actor_environment_observations

    _seed(ch.file, [_obs("ok/0", "caught")])
    rc = curator.run_batch(hold_committed=False, cfg=dataclasses.replace(cfg, invoke_agent=_skip_fake))
    assert rc == 0
    assert "ok/0" not in _active_by_id(paths)
    assert _max_attempts_seen(paths) == 0
    assert _deadletter_rows(paths) == []

    _seed(ch.file, [_obs("bad/0", "caught")])
    fault_cfg = dataclasses.replace(cfg, invoke_agent=_fault_fake)
    curator.run_batch(hold_committed=False, cfg=fault_cfg)
    assert _active_by_id(paths)["bad/0"].get("attempts") == 1
    curator.run_batch(hold_committed=False, cfg=fault_cfg)
    assert _active_by_id(paths)["bad/0"].get("attempts") == 2
    assert _deadletter_rows(paths) == []


def test_dlq_quarantines_batch_at_max_attempts(tmp_path: Path, monkeypatch) -> None:
    """dlq-quarantine-at-threshold: when a batch's rows REACH
    ``LEARNING_AUTHOR_MAX_ATTEMPTS`` (default 3) the rows move to the ``deadletter``
    sidecar and are removed from the active queue — the move-aside shape of
    ``_quarantine_marker`` at the queue-row level, so the poison batch stops blocking."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    paths = _env_repo(tmp_path)
    cfg = aenv.build_adversarial_config(paths)
    ch = paths.actor_environment_observations
    _seed(ch.file, [_obs("p/0", "caught")])
    fault_cfg = dataclasses.replace(cfg, invoke_agent=_fault_fake)

    for _ in range(3):
        curator.run_batch(hold_committed=False, cfg=fault_cfg)

    assert "p/0" not in _active_by_id(paths)
    assert "p/0" in {r["observation_id"] for r in _deadletter_rows(paths)}


def test_dlq_quarantine_is_batch_granular(tmp_path: Path, monkeypatch) -> None:
    """dlq-batch-granular: rc 2 originates before any per-row fault attribution, so all
    ``to_author`` rows share the fault and dead-letter AS A UNIT. Below threshold they
    stay queued together; at threshold they all move together, none left behind."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    paths = _env_repo(tmp_path)
    cfg = aenv.build_adversarial_config(paths)
    ch = paths.actor_environment_observations
    ids = ["p/0", "p/1", "p/2"]
    _seed(ch.file, [_obs(i, "caught") for i in ids])
    fault_cfg = dataclasses.replace(cfg, invoke_agent=_fault_fake)

    curator.run_batch(hold_committed=False, cfg=fault_cfg)
    curator.run_batch(hold_committed=False, cfg=fault_cfg)
    active = _active_by_id(paths)
    assert set(ids) <= set(active)
    assert all(active[i].get("attempts") == 2 for i in ids)
    assert _deadletter_rows(paths) == []

    curator.run_batch(hold_committed=False, cfg=fault_cfg)
    active = _active_by_id(paths)
    assert not (set(ids) & set(active))
    assert set(ids) <= {r["observation_id"] for r in _deadletter_rows(paths)}


def test_dlq_does_not_block_subsequent_clean_batch(tmp_path: Path, monkeypatch) -> None:
    """dlq-does-not-block-subsequent: once a poison batch is dead-lettered it no longer
    blocks the queue — a following clean batch of new findings authors and commits
    normally, and the quarantined rows are not resurrected."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    paths = _env_repo(tmp_path)
    cfg = aenv.build_adversarial_config(paths)
    ch = paths.actor_environment_observations
    _seed(ch.file, [_obs("poison/0", "caught")])
    fault_cfg = dataclasses.replace(cfg, invoke_agent=_fault_fake)
    for _ in range(3):
        curator.run_batch(hold_committed=False, cfg=fault_cfg)
    assert "poison/0" in {r["observation_id"] for r in _deadletter_rows(paths)}

    _append(ch.file, [_obs("clean/0", "caught")])
    head_before = _head(paths.repo_root)
    rc = curator.run_batch(hold_committed=True, cfg=dataclasses.replace(cfg, invoke_agent=_commit_fake))

    assert rc == 0
    assert _head(paths.repo_root) != head_before
    assert "poison/0" in {r["observation_id"] for r in _deadletter_rows(paths)}


def test_dlq_systemic_fault_is_exempt_and_propagates(tmp_path: Path, monkeypatch) -> None:
    """dlq-systemic-exempt: a systemic ``FatalConfigError`` (→ exit 2) is NOT counted
    toward the attempt budget and is NOT dead-lettered — it escapes ``run_batch``
    uncaught. Only a per-run authoring fault bumps attempts."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    paths = _env_repo(tmp_path)
    cfg = aenv.build_adversarial_config(paths)
    ch = paths.actor_environment_observations
    _seed(ch.file, [_obs("sys/0", "caught")])
    systemic_cfg = dataclasses.replace(cfg, invoke_agent=_systemic_fake)

    with pytest.raises(FatalConfigError):
        curator.run_batch(hold_committed=False, cfg=systemic_cfg)

    assert _max_attempts_seen(paths) == 0
    assert _deadletter_rows(paths) == []
