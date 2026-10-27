"""Shared scene for the #719 drain tests: a real repo, queue files, lock holders and agent fakes."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T

import dataclasses
import json
import os
import subprocess
import threading
import time
from pathlib import Path

try:  # a missing module fails each test on use rather than aborting collection
    from defender.learning.author import drain  # type: ignore[import-not-found]
except ImportError as _missing_target:  # pragma: no cover — the pre-implementation state

    class _NotYetWritten:
        """Stands in for a missing target module: every attribute access raises, so each test
        fails loudly on its own (not a skip) while the rest of the tree still collects."""

        def __init__(self, dotted: str, err: BaseException) -> None:
            self._dotted, self._err = dotted, err

        def __getattr__(self, item: str):
            raise ImportError(
                f"{self._dotted}.{item} does not exist yet — this suite is the executable "
                f"spec for it (spec_graph_719.yaml). Original: {self._err}"
            )

    drain = _NotYetWritten("defender.learning.author.drain", _missing_target)  # type: ignore[assignment]

from defender.learning.author.lessons import run as lessons_run  # type: ignore[import-not-found]
from defender import _flock as _lockfile  # type: ignore[import-not-found]
from defender.learning.core.state import (  # type: ignore[import-not-found]
    FINDINGS, PITFALLS, QUESTIONER_FINDINGS, Channel, LearningState,
)
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]

#: The channels the folded drain body serves (`pitfalls` is drained by the lead-author tick, so
#: it is named separately). Only `findings` has both a producer and a consumer since #922; it
#: stays a tuple because tests loop "per channel". Between-channel properties (shared
#: retirement, per-channel locks and gates) need a second channel and return with one.
AUTHOR_CHANNELS = (
    "findings",
)
ALL_CHANNELS = AUTHOR_CHANNELS + ("pitfalls",)

#: channel name -> the channel's real config builder.
def _findings_cfg(paths: LoopPaths):
    """The real findings config over `paths`."""
    from defender.tests.support.learning.curation._curator1134 import author_trees

    return lessons_run.build_author_config(
        paths, state=LearningState.open(paths), trees=author_trees(paths))


BUILDERS = {
    "findings": _findings_cfg,
}

#: The append-lock file name per channel, kept stable so in-flight appenders need no
#: coordination.
APPEND_LOCK_NAMES_TODAY = {
    "findings": ".findings.lock",
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
    """`_make_repo`'s repo at `tmp_path / "repo"` (built once per process, then copied)."""
    from defender.tests.support.shared.contracts._repo import build_once_copy

    return build_once_copy("drain719.make_repo", lambda dest: _make_repo(dest.parent), tmp_path / "repo")


def _make_repo(tmp_path: Path) -> Path:
    """A committed-clean git repo carrying the lesson corpora the author channels write, with the
    mutable learning state gitignored."""
    repo = tmp_path / "repo"
    for corpus in ("lessons", "lessons-questioner"):
        d = repo / "defender" / corpus
        d.mkdir(parents=True)
        (d / ".gitkeep").write_text("")
    elastic = repo / "defender" / "skills" / "elastic"
    elastic.mkdir(parents=True)
    # A `SKILL.md` makes `elastic` a system: the pitfalls curator writes `<system>/execution.md`
    # only for existing systems (#855), and git tracks no empty directory.
    (elastic / "SKILL.md").write_text("---\nname: defender-elastic\n---\n# elastic\n")
    (repo / "defender" / "skills" / "gather" / "queries").mkdir(parents=True)
    adapters = repo / "defender" / "integrations"
    adapters.mkdir(parents=True)
    (adapters / "elastic_adapter.py").write_text("VERBS = {}\n")
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
    repo = make_repo(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=state_dir if state_dir is not None else repo / "defender" / "learning")
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return paths


def channel_of(name: str) -> Channel:
    """The state handle's channel called `name`."""
    return {c.name: c for c in (FINDINGS, QUESTIONER_FINDINGS, PITFALLS)}[name]


def cfg_for(paths: LoopPaths, name: str, **overrides):
    """The real builder for `name`, with `overrides` replaced in. A test that cares about the
    ceiling states `max_attempts`; others get the shipped default (3)."""
    cfg = BUILDERS[name](paths)
    return dataclasses.replace(cfg, **overrides)


# queue rows


def obs_row(oid: str, *, outcome: str = "caught", **extra) -> dict:
    """One observation-channel row (those channels retired with #922): `caught`/`incoherent`
    bear findings, `survived` is benign. An empty `source_run_dir` skips the source-bundle check."""
    return {"observation_id": oid, "judge_outcome": outcome, "source_run_dir": "", **extra}


def finding_row(fid: str, *, run_id: str, direction: str = "family", **extra) -> dict:
    """A defender row the lessons gate admits: `direction: family` with the three fields
    `_gate_family` reads (#1234). The gate holds any other direction as `retired_direction(...)`."""
    return {
        "schema_version": 1,
        "finding_id": fid,
        "run_id": run_id,
        "alert_rule_key": "rule-5710",
        "direction": direction,
        "type": "lead-set",
        "subject": "subj",
        "finding": "narrative",
        "citations": [{"source": "investigation", "quote": "..."}],
        "source_run_dir": f"episodes/{run_id}",
        "contrast_evidence": [f"worlds/{T.fixture_world_id('b')}/report.md", f"worlds/{T.fixture_world_id('a')}/report.md"],
        "on_verdict_path": True,
        "world_label_doubted": False,
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
            # Distinct per row: rows sharing a digest collapse into one record (#840), and the
            # curation threshold counts records.
            "stderr_digest": f"exit=1; mismatched input ({rid})",
            "error_class": "agent-fixable",
            **extra,
        }
    default_outcome = "survived" if name == "environment_observations" else "caught"
    return obs_row(rid, outcome=extra.pop("outcome", default_outcome), **extra)


def seed(paths: LoopPaths, channel: Channel, rows: list[dict]) -> None:
    queue = location_path(paths.state_root) / channel.queue
    queue.parent.mkdir(parents=True, exist_ok=True)
    with queue.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def pending(paths: LoopPaths, channel: Channel) -> list[dict]:
    return read_rows(location_path(paths.state_root) / channel.queue)


def pending_by_id(paths: LoopPaths, channel: Channel) -> dict[str, dict]:
    return {r[channel.id_key]: r for r in pending(paths, channel) if channel.id_key in r}


def graveyard(paths: LoopPaths, channel: Channel) -> list[dict]:
    return read_rows(location_path(paths.state_root) / channel.deadletter)


def stuck_records(paths: LoopPaths, channel: Channel) -> list[dict]:
    return read_rows(location_path(paths.state_root) / channel.stuck)


def consumed(paths: LoopPaths, channel: Channel) -> list[dict]:
    return read_rows(location_path(paths.state_root) / channel.consumed)


def attempts_of(paths: LoopPaths, channel: Channel, rid: str) -> int | None:
    row = pending_by_id(paths, channel).get(rid)
    return None if row is None else row.get("attempts")


# fakes — they inject faults or success, never classify


def raising(exc: BaseException):
    """An agent call that raises `exc`; the class it raises is the whole fault, and the fake
    decides nothing."""

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
        # `source_<id_key>s` is the key the pre-author idempotency gate reads back off the
        # corpus, so a later tick recognises this lesson as already authored.
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
    """Wraps a fake to record whether the agent was reached, and with what config: "the drain
    never got there" versus "a step after it failed"."""
    calls: list[dict] = []

    def fake(rows, batch_id, cfg):
        calls.append({"rows": list(rows), "batch_id": batch_id, "cfg": cfg})
        return inner(rows, batch_id, cfg)

    fake.calls = calls  # type: ignore[attr-defined]
    return fake


def blocking(gate: threading.Event, released: threading.Event, inner=None):
    """An agent call that parks until `gate` is set: an in-flight batch. `released` fires on
    entry, so a test waits for the agent phase instead of sleeping."""

    def fake(rows, batch_id, cfg):
        released.set()
        gate.wait(timeout=30)
        return (inner or skipping())(rows, batch_id, cfg)

    return fake


# concurrency helpers


class Holder:
    """Holds a real `fcntl` lock on `path` from a worker thread until released. A thread is
    enough: `flock(LOCK_EX)` on a separately opened file excludes other threads of the same
    process, so the exclusion under test is the real one."""

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
                fh = _lockfile.open_lock(self.path)
                try:
                    _lockfile.take(fh, timeout_seconds=None)
                    self.acquired = True
                    self._held.set()
                    self._release.wait(timeout=60)
                finally:
                    _lockfile.release(fh)
            else:
                fh = _lockfile.open_lock(self.path)
                self.acquired = _lockfile.take(fh, timeout_seconds=0)
                self._held.set()
                try:
                    self._release.wait(timeout=60)
                finally:
                    if self.acquired:
                        _lockfile.release(fh)
                    else:
                        fh.close()

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
    """Run `script` (with `repo` as `argv[1]`) in a fresh interpreter rooted at this checkout:
    a genuinely separate actor."""
    # This checkout's root from this file's place in it, never `defender.__path__[0]`: for the
    # namespace package that can name another `defender/` a test put on the path first (a
    # scratch repo's), and the fresh process would import from the wrong tree.
    root = Path(__file__).resolve().parents[5]
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
