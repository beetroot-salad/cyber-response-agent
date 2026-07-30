"""Substrate for the issue-719 executable spec (`spec_graph_719.yaml`).

Pre-implementation. `defender.learning.author.drain` — D3's single folded drain body —
does NOT exist at the base commit, so every module that imports this one errors at
collection. That is the expected red; it is what a spec written before the code looks
like.

**The seam contract this spec pins** (write-code-from-spec implements it):

* `defender/learning/author/drain.py`
  - `run_batch(*, cfg, hold_committed=False, box=None) -> int` — the one drain body both
    direction modules reach (D3/O3). Return alphabet: `0` nothing-to-do / drain lock held
    / repo lock unavailable, `2` a faulted batch on an author channel.
  - `retire(*, channel, batch_ids, reason, max_attempts) -> RetireOutcome` — D9's seam.
    Bumps every named row by one, retires the rows now at or over the ceiling into the
    channel's graveyard, writes them to the consumed ledger, and rewrites the pending
    file through the one locked rotation.
  - `RetireOutcome(bumped: dict[str, int], retired: tuple[str, ...])`.
  - `graveyard_file(channel) -> Path` — `<queue>.deadletter.jsonl`, one per channel.
  - `stuck_report_file(channel) -> Path` — decision 10's operator signal, one per channel,
    beside the graveyard under the same ignored prefix. A fault whose class is NOT in
    `RETIRE_SET` leaves the row queued, so the only thing an operator can see is this: one
    record per non-retiring tick naming the fault CLASS, the row ids it stalled, and how many
    consecutive ticks they have been stuck. A member fault writes nothing here — it retires,
    which is already visible in the graveyard.
  - `LOCK_ORDER: tuple[str, ...]` — the acquisition order, declared in exactly one place.
  - `RETIRE_SET: tuple[type[BaseException], ...]` — decision 8's ENUMERATED retire set:
    exactly `AuthorError`, `GitError`, `ModelRetry`. Retirement is reachable only from a
    member; every other class stays uncaught and leaves the row queued. There is no bare
    `except Exception` and no re-raise carve-out. `GitError` and `ModelRetry` are the two
    members an `except AuthorError` spelling would silently drop, reverting decision 1
    paths 3 and 4 — which is what the membership oracle exists to catch.
  - `BucketSpec(name, disposition, reason_field, formatter)` — D4's bucket as data.
* `QueueChannel` gains `append_lock: Path`, `drain_lock: Path | None`, `id_key: str` (D1/D3).
* `CorpusAuthorConfig` gains `max_attempts: int`, `gate`, `buckets`, `post_rotate` (D3/D4/D7,
  ceiling bound once at config build). `post_rotate` is D7's optional hook — lessons populates
  it with `write_held_report` and the other directions leave it unset — and it is also the ONLY
  seam that runs after the corpus commit and the rotation, which is what lets the guard-extent
  demand observe where the retire-set clauses CLOSE. Without it that edge is unobservable and
  the extent demand degrades to a membership restatement.
* the lock layer is NOT required to name its own fault type. That was a §7 derivation of
  D5/P13's word "explicitly", load-bearing only while a type-based re-raise set could
  over-capture a missing-file `OSError`. Under an allow-list an `OSError` is simply not a
  member, so the derivation is a readability preference and this spec does not inherit it.
* `pitfalls_curator.run_pitfalls` raises `AuthorError` on a nonzero agent rc instead of
  returning 2 (decision 1 path 1).

Project idioms this file obeys, because CI ratchets them: fakes enter through
`dataclasses.replace(cfg, invoke_agent=...)` and constructor arguments, never
`monkeypatch.setattr`; the fakes inject faults only and never classify.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import threading
import time
from pathlib import Path

try:  # NOT YET WRITTEN — D3's `author/drain.py` is what this spec is the contract for
    from defender.learning.author import drain  # type: ignore[import-not-found]
except ImportError as _missing_target:  # pragma: no cover — the pre-implementation state

    class _NotYetWritten:
        """Stands in for the target module until it exists.

        NOT a skip and NOT a soften: every attribute access raises, so each test fails
        loudly on its own. The indirection exists only so a missing target does not abort
        pytest's whole collection and take the rest of the tree's suite down with it."""

        def __init__(self, dotted: str, err: BaseException) -> None:
            self._dotted, self._err = dotted, err

        def __getattr__(self, item: str):
            raise ImportError(
                f"{self._dotted}.{item} does not exist yet — this suite is the executable "
                f"spec for it (spec_graph_719.yaml). Original: {self._err}"
            )

    drain = _NotYetWritten("defender.learning.author.drain", _missing_target)  # type: ignore[assignment]

from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.author.benign_actor import run as benign_run  # type: ignore[import-not-found]
from defender.learning.author.lessons import run as lessons_run  # type: ignore[import-not-found]
from defender.learning.author.malicious_actor import run as actor_run  # type: ignore[import-not-found]
from defender.learning.core import persist  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]

#: The four channels one folded drain body serves. `pitfalls` is the fifth queue but is
#: drained by the lead-author tick, not by a corpus author, so it is named separately.
AUTHOR_CHANNELS = (
    "findings",
    "actor_observations",
    "environment_observations",
    "actor_environment_observations",
)
ALL_CHANNELS = AUTHOR_CHANNELS + ("pitfalls",)

#: channel name -> the direction module's real config builder. The fold keeps these as
#: per-direction config builders (D3); it deletes their batch-driver bodies, not them.
BUILDERS = {
    "findings": lambda paths: lessons_run.build_author_config(paths),
    "actor_observations": lambda paths: actor_run.build_actor_config(paths),
    "environment_observations": lambda paths: benign_run.build_benign_config(paths),
    "actor_environment_observations": lambda paths: benign_run.build_adversarial_config(paths),
}

#: The append-lock file names as they stand at the base commit, per channel. D1 keeps these
#: identities so in-flight appenders need no coordination.
APPEND_LOCK_NAMES_TODAY = {
    "findings": ".findings.lock",
    "actor_observations": ".actor.lock",
    "environment_observations": ".environment.lock",
    "actor_environment_observations": ".actor_environment.lock",
    "pitfalls": ".pitfalls.lock",
}

GIT_IGNORE = (
    "defender/learning/_pending/\n"
    "defender/learning/_pending_leads/\n"
    "defender/learning/_pending_pitfalls/\n"
    "defender/learning/_author.lock\n"
    "defender/learning/.author-drain.lock\n"
    "defender/learning/.lead-author-drain.lock\n"
    "defender/learning/runs/\n"
    "state/\n"
)


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=check
    )


def make_repo(tmp_path: Path) -> Path:
    """A committed-clean git repo carrying all three corpora the four author channels
    write, with the mutable learning state gitignored."""
    repo = tmp_path / "repo"
    for corpus in ("lessons", "lessons-actor", "lessons-environment"):
        d = repo / "defender" / corpus
        d.mkdir(parents=True)
        (d / ".gitkeep").write_text("")
    (repo / "defender" / "skills" / "elastic").mkdir(parents=True)
    (repo / "defender" / "skills" / "gather" / "queries").mkdir(parents=True)
    (repo / ".gitignore").write_text(GIT_IGNORE)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def make_paths(tmp_path: Path, *, state_dir: Path | None = None) -> LoopPaths:
    """`LoopPaths` over a fresh repo. `state_dir` relocates every queue, lock and
    graveyard away from the worktree without moving the corpus."""
    return LoopPaths(repo_root=make_repo(tmp_path), state_dir=state_dir)


def channel_of(paths: LoopPaths, name: str):
    return getattr(paths, name)


def cfg_for(paths: LoopPaths, name: str, **overrides):
    """The real direction builder for `name`, with test overrides applied through the
    injection seams. `max_attempts` defaults to 3 here so a test that cares about the
    ceiling states it, and one that does not gets the shipped default."""
    cfg = BUILDERS[name](paths)
    return dataclasses.replace(cfg, **overrides)


# --------------------------------------------------------------------------------------
# queue rows
# --------------------------------------------------------------------------------------


def obs_row(oid: str, *, outcome: str = "caught", **extra) -> dict:
    """One observation row. `caught`/`incoherent` are the finding-bearing outcomes for the
    actor and actor-env directions; `survived` is the benign direction's. An empty
    `source_run_dir` short-circuits the gate's source-bundle check."""
    return {"observation_id": oid, "judge_outcome": outcome, "source_run_dir": "", **extra}


def finding_row(fid: str, *, run_id: str, direction: str = "adversarial", **extra) -> dict:
    return {
        "schema_version": 1,
        "finding_id": fid,
        "run_id": run_id,
        "alert_rule_key": "rule-5710",
        "direction": direction,
        "type": "lead-set",
        "subject": "subj",
        "finding": "narrative",
        "judge_outcome": "survived",
        "citations": [{"source": "investigation", "quote": "..."}],
        "source_run_dir": f"defender/learning/runs/{run_id}/",
        **extra,
    }


def row_for(name: str, rid: str, **extra) -> dict:
    """A well-formed row for whichever channel `name` is, keyed under that channel's
    own id field."""
    if name == "findings":
        return finding_row(rid, run_id=rid.split("/")[0], **extra)
    if name == "pitfalls":
        return {
            "schema_version": 1,
            "pitfall_id": rid,
            "source_run": "r",
            "system": "elastic",
            "query_id": "elastic.esql",
            "goal": "g",
            "executed_query": "bad pipe",
            "stderr_digest": "exit=1; mismatched input",
            "error_class": "agent-fixable",
            **extra,
        }
    default_outcome = "survived" if name == "environment_observations" else "caught"
    return obs_row(rid, outcome=extra.pop("outcome", default_outcome), **extra)


def write_source_refs(paths: LoopPaths, run_id: str, disposition: str = "benign") -> None:
    import yaml

    rd = paths.runs_dir / run_id
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "investigation.md").write_text("transcript stub")
    (rd / "source_refs.yaml").write_text(
        yaml.safe_dump(
            {"paths": {}, "normalized_disposition": disposition, "alert_rule_key": "rule-5710"}
        )
    )


def seed(channel, rows: list[dict]) -> None:
    channel.file.parent.mkdir(parents=True, exist_ok=True)
    with channel.file.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def pending(channel) -> list[dict]:
    return read_rows(channel.file)


def pending_by_id(channel) -> dict[str, dict]:
    return {r[channel.id_key]: r for r in pending(channel) if channel.id_key in r}


def graveyard(channel) -> list[dict]:
    return read_rows(drain.graveyard_file(channel))


def stuck_records(channel) -> list[dict]:
    return read_rows(drain.stuck_report_file(channel))


def consumed(channel) -> list[dict]:
    return read_rows(channel.consumed)


def attempts_of(channel, rid: str) -> int | None:
    row = pending_by_id(channel).get(rid)
    return None if row is None else row.get("attempts")


# --------------------------------------------------------------------------------------
# fakes — they inject faults or success, never classify
# --------------------------------------------------------------------------------------


def raising(exc: BaseException):
    """An agent call that raises `exc`. The fake decides nothing: the class it raises is
    the whole fault content, and every use in this spec cites the ledger claim that
    observed that class on the real dependency."""

    def fake(rows, batch_id, cfg):
        raise exc

    return fake


def committing(stem: str = "lesson", *, also=None):
    """An agent call that succeeds: writes one corpus `.md` naming every handed row, and
    reports them all committed. `also` runs after the write, so a test can make a
    POST-agent step fail while the agent itself succeeds."""

    def fake(rows, batch_id, cfg):
        key = cfg.channel.id_key
        ids = [r[key] for r in rows]
        # `source_<id_key>s` is the frontmatter key the pre-author idempotency gate reads back
        # off the corpus (`existing_observation_ids` / `existing_finding_ids`), so a lesson
        # written here is one a LATER tick recognises as already authored.
        (cfg.corpus_dir / f"{stem}-{batch_id}.md").write_text(
            f"---\nsource_{key}s:\n" + "".join(f"- {i}\n" for i in ids) + "---\n\nbody\n"
        )
        if also is not None:
            also(rows, batch_id, cfg)
        return {
            "committed": list(ids),
            "consumed_skip": [],
            "held_forward_bad": [],
            "commit_message": f"author {stem} batch",
        }

    return fake


def skipping():
    """A clean all-skip batch: every handed row is consumed by policy, nothing committed."""

    def fake(rows, batch_id, cfg):
        key = cfg.channel.id_key
        return {
            "committed": [],
            "consumed_skip": [{key: r[key], "reason": "dup"} for r in rows],
            "held_forward_bad": [],
            "commit_message": "",
        }

    return fake


def returning(result: dict):
    def fake(rows, batch_id, cfg):
        return dict(result)

    return fake


def recording(inner):
    """Wraps a fake so the test can see whether the agent was reached at all, and with
    what config — the observation that separates "the drain never got there" from "the
    drain got there and the step after it failed"."""
    calls: list[dict] = []

    def fake(rows, batch_id, cfg):
        calls.append({"rows": list(rows), "batch_id": batch_id, "cfg": cfg})
        return inner(rows, batch_id, cfg)

    fake.calls = calls  # type: ignore[attr-defined]
    return fake


def blocking(gate: threading.Event, released: threading.Event, inner=None):
    """An agent call that parks until `gate` is set — the in-flight batch every O2 / O7
    oracle needs. `released` fires the moment the call is entered, so the test can wait
    for the batch to actually be inside the agent phase rather than sleeping."""

    def fake(rows, batch_id, cfg):
        released.set()
        gate.wait(timeout=30)
        return (inner or skipping())(rows, batch_id, cfg)

    return fake


# --------------------------------------------------------------------------------------
# concurrency helpers
# --------------------------------------------------------------------------------------


class Holder:
    """Holds a real `fcntl` lock on `path` from a worker thread until released.

    A thread, not a subprocess, because PJ2a probed that `flock(LOCK_EX)` excludes two OS
    threads of one process from each other — so the exclusion under test is the real one.
    Where a test needs a genuinely separate actor (a second process's own path set), it
    spawns a subprocess instead: `DEFAULT_PATHS` is frozen at import (F7), so an in-process
    env change would not reach it."""

    def __init__(self, path: Path, *, blocking_discipline: bool = True) -> None:
        self.path = path
        self.blocking_discipline = blocking_discipline
        self._held = threading.Event()
        self._release = threading.Event()
        self._thread: threading.Thread | None = None
        self.acquired: bool | None = None

    def __enter__(self) -> Holder:
        self.path.parent.mkdir(parents=True, exist_ok=True)

        def run() -> None:
            if self.blocking_discipline:
                with persist._flock(self.path):
                    self.acquired = True
                    self._held.set()
                    self._release.wait(timeout=60)
            else:
                fh = author_shared.acquire_flock(self.path)
                self.acquired = fh is not None
                self._held.set()
                try:
                    self._release.wait(timeout=60)
                finally:
                    if fh is not None:
                        author_shared.release_flock(fh)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert self._held.wait(timeout=10), f"never acquired {self.path}"
        return self

    def __exit__(self, *exc) -> None:
        self._release.set()
        if self._thread is not None:
            self._thread.join(timeout=10)


class Background:
    """Runs `fn()` on a worker thread and records its result or exception."""

    def __init__(self, fn) -> None:
        self.fn = fn
        self.result = None
        self.error: BaseException | None = None
        self.done = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self.result = self.fn()
        except BaseException as e:  # noqa: BLE001 — the test asserts on what escaped
            self.error = e
        finally:
            self.done.set()

    def __enter__(self) -> Background:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.done.wait(timeout=60)
        self._thread.join(timeout=10)

    def finished_within(self, seconds: float) -> bool:
        return self.done.wait(timeout=seconds)


def elapsed(fn) -> tuple[object, float]:
    t0 = time.monotonic()
    out = fn()
    return out, time.monotonic() - t0


def run_in_subprocess(script: str, *, repo: Path, env_extra: dict[str, str] | None = None):
    """Run `script` in a genuinely fresh interpreter rooted at this checkout.

    C14/P44 is a phase-E constraint, not a fork: `DEFAULT_PATHS` is frozen at import, so a
    test that needs a second actor gets a second process, never an in-process env poke."""
    import defender  # type: ignore[import-not-found]

    root = Path(defender.__path__[0]).resolve().parent  # namespace pkg: __file__ is None
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    env.update(env_extra or {})
    return subprocess.run(
        ["python3", "-c", script, str(repo)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(root),
    )
