"""#1278 the tick's fault, PR-opening and stop families: a lane scene, its curators as seams, and the injections.

Nothing here implements store or tick policy. `Scene` is one lane (`author` or `lead_author`) over the `world`
fixture: it seeds work for every curator of the lane, runs the lane's real drain with the curators replaced by
`Cast` (each writes one file into its batch's draft and commits it through the batch's own commit-maker, so the
record, the branch and the push are the real ones), and reads the store back. A `Cast` appends every curator
start and commit to a log file, so a forked tick's events survive it. The injections are small: an exception
from a seam, a patched push or PR open, a cancel request followed by a wait the stop must interrupt.
"""
from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    TickChild,
    batches,
    call,
    finding,
    lesson_citing,
    world_finding,
)

#: The curators of each lane, in the order the tick serves them, named by the item kind each is handed.
CURATORS = {AUTHOR_LANE: ("finding", "questioner_finding"), LEAD_LANE: ("curation_request", "pitfall")}
#: The points of a curator's turn a hook can sit at.
START, BEFORE_COMMIT, AFTER_COMMIT = "start", "before_commit", "after_commit"
#: How long a hook that waits for a stop waits at most: only the stop (a signal) ends it sooner.
WAIT_FOR_STOP = 20.0

TEMPLATE = "agent/skills/gather/queries/cmdb/host-owner.md"
PITFALLS_ADDON = "agent/skills/gather/defender-sql.pitfalls.md"


class Cast:
    """The lane's curators as the drain's seams. `commit` names the curators that write and commit (the rest do
    neither); `hooks[(curator, point)](batch)` runs at that point of that curator's turn. Every start, commit and
    push is appended to `log`."""

    def __init__(self, scene: Scene, *, commit: tuple[str, ...] | None = None,
                 hooks: dict[tuple[str, str], Callable[[Any], None]] | None = None, tag: str = "") -> None:
        self.scene = scene
        self.commit = CURATORS[scene.lane] if commit is None else commit
        self.hooks = dict(hooks or {})
        self.log = scene.w.scratch / f"events-{scene.lane}{tag}.log"

    # -- what happened ---------------------------------------------------------------------------

    def event(self, text: str) -> None:
        with self.log.open("a", encoding="utf-8") as out:
            out.write(text + "\n")

    def events(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.is_file() else []

    def started(self) -> list[str]:
        return [e.split()[1] for e in self.events() if e.startswith("start ")]

    def commits(self) -> list[str]:
        return [e.split()[2] for e in self.events() if e.startswith("commit ")]

    # -- the seams ---------------------------------------------------------------------------------

    def serve(self, name: str, batch: Any) -> None:
        self.event(f"start {name}")
        self._hook(name, START, batch)
        if name in self.commit:
            self._write(name, batch)
        self._hook(name, BEFORE_COMMIT, batch)
        if name in self.commit:
            made = batch.commit(batch.change_set(), f"learning: {name} {batch.id}")
            self.event(f"commit {name} {made}")
            batch.reset()
            self._hook(name, AFTER_COMMIT, batch)

    def _hook(self, name: str, point: str, batch: Any) -> None:
        hook = self.hooks.get((name, point))
        if hook is not None:
            hook(batch)

    def _write(self, name: str, batch: Any) -> None:
        root = Path(batch.draft_root)
        if name == "finding":
            target, text = root / "agent/lessons/faults-f.md", lesson_citing("f1")
        elif name == "questioner_finding":
            target, text = root / "agent/lessons-questioner/faults-q.md", lesson_citing("q1")
        elif name == "curation_request":
            target = root / TEMPLATE
            text = target.read_text(encoding="utf-8") + "\nAlso check the asset tag.\n"
        else:
            target = root / PITFALLS_ADDON
            text = target.read_text(encoding="utf-8").rstrip("\n") + "\n- **Name the unnested column.**\n"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def trigger(self, _paths: Any, _state: Any, kind: str, *_rest: Any, batch: Any, **_kw: Any) -> None:
        """The author lane's `trigger_author` seam."""
        self.serve(kind, batch)

    def lead_request(self, _paths: Any, _state: Any, _run: Any, *, batch: Any, **_kw: Any) -> None:
        """The lead lane's `run_lead_author` seam."""
        self.serve("curation_request", batch)

    def pitfalls(self, _paths: Any, _state: Any, *, batch: Any, **_kw: Any) -> int:
        """The lead lane's `run_pitfalls` seam."""
        self.serve("pitfall", batch)
        return 0


class Scene:
    """One lane of the `world`, seeded so every curator of the lane has an item."""

    def __init__(self, w: Any, lane: str) -> None:
        self.w, self.lane = w, lane
        self.tenant = w.t.tenant_id

    def seed(self) -> None:
        w = self.w
        if self.lane == AUTHOR_LANE:
            call(w.dsn, "publish_findings", self.tenant, "run-1", [finding("f1")], kind="finding")
            call(w.dsn, "publish_findings", self.tenant, "run-1", [world_finding("q1")], kind="questioner_finding")
            return
        from defender.tests.support.learning.core._declared870 import shim_row
        from defender.tests.tenancy.tenant_1108_p4._drain_support import queued_run

        w.monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
        queued_run(w.t, w.paths, "faults-lead")
        call(w.dsn, "add_pitfall", self.tenant, shim_row("p4-run:1"))

    def items(self) -> dict[tuple[str, str], Any]:
        return {(i.kind, i.key): i for i in call(self.w.dsn, "work", self.tenant)}

    def batches(self) -> dict[str, Any]:
        return {b.id: b for b in batches(self.w.dsn, self.tenant) if b.lane == self.lane}

    def only_batch(self) -> Any:
        [batch] = self.batches().values()
        return batch

    def set_attempts(self, attempts: int) -> None:
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.w.dsn, "UPDATE learning.work_items SET attempts = %s WHERE tenant_id = %s", (attempts, self.tenant))

    def run(self, cast: Cast, box: Any = None) -> Any:
        """The lane's real drain over `cast`: the tick's return value, or the exception it let out."""
        from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, lead_author_drain

        box = box or BoxSpy()
        try:
            if self.lane == AUTHOR_LANE:
                return author_drain(self.w.t, self.w.paths, trigger=cast.trigger, box=box)
            return lead_author_drain(self.w.t, self.w.paths, box=box, run_lead_author=cast.lead_request,
                                     run_pitfalls=cast.pitfalls)
        except Exception as let_out:  # noqa: BLE001 — a fault the tick does not contain: the case reads the store
            return let_out

    def run_in_child(self, cast: Cast, tag: str) -> TickChild:
        """The same tick in a forked child (a signal reaches it, never the pytest worker), the renewer fast."""
        from defender.tests.support.learning.core._store1278 import RENEW_ENV

        self.w.monkeypatch.setenv(RENEW_ENV, "0.2")
        return TickChild(lambda: _rc(self.run(cast)), self.w.scratch / f"child-{tag}.json")

    def branch_tip_on_remote(self, branch: str) -> str | None:
        from defender.tests.tenancy.tenant_1108_p4._drain_support import remote_branches

        return dict(remote_branches(self.w.t.remote, prefix="")).get(branch)

    def open_prs(self) -> list[dict[str, Any]]:
        return [r for r in self.w.t.forge.prs if r["state"] == "open"]


def _rc(outcome: Any) -> int:
    return outcome if isinstance(outcome, int) else 99


# --- injections -------------------------------------------------------------------------------------------------


def raise_in(exc: Callable[[], BaseException]) -> Callable[[Any], None]:
    """A hook that raises `exc()`."""
    def hook(_batch: Any) -> None:
        raise exc()
    return hook


def ask_for_stop_and_wait(w: Any) -> Callable[[Any], None]:
    """A hook for a forked tick: the store is asked to cancel, and the hook waits; the renewer's stop (a signal to
    the tick's main thread) ends the wait as `TickStopped`. A stop that never comes leaves the wait to run out."""
    def hook(_batch: Any) -> None:
        call(w.dsn, "request_cancel", w.t.tenant_id)
        time.sleep(WAIT_FOR_STOP)
    return hook


class PushSpy:
    """`GitRepository.push` as the tick calls it: each call is logged with the repository's `network_timeout` and,
    in order, may first do `before(call number)`; `fail_from` makes every call from that number on raise `error()`.
    The push itself is the real one unless it fails."""

    def __init__(self, cast: Cast, monkeypatch: Any, *, before: Callable[[int], None] | None = None,
                 fail_from: int | None = None,
                 error: Callable[[], BaseException] = lambda: OSError("injected: the push could not reach the origin")
                 ) -> None:
        from defender.learning.author.version_control.repository import GitRepository

        real = GitRepository.push
        spy = self
        self.calls = 0
        self.cast, self.before, self.fail_from = cast, before, fail_from

        def push(repo: Any, commit: str, branch: str) -> None:
            spy.calls += 1
            number = spy.calls
            cast.event(f"push {number} timeout={repo.network_timeout}")
            if spy.before is not None:
                spy.before(number)
            if spy.fail_from is not None and number >= spy.fail_from:
                raise error()
            real(repo, commit, branch)

        monkeypatch.setattr(GitRepository, "push", push)  # lint-monkeypatch: ok — a counting, failing wrapper of the one push that runs the real push otherwise; the tick builds its repository itself, so no seam carries it

    def timeouts(self) -> list[float]:
        return [float(e.rsplit("=", 1)[1]) for e in self.cast.events() if e.startswith("push ")]


def hang_pushes(remote: Path, seconds: int = 25) -> None:
    """The origin's receive hook sleeps: a push to it does not end until the client's own timeout does."""
    hook = remote / "hooks" / "pre-receive"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text(f"#!/bin/sh\nsleep {seconds}\n", encoding="utf-8")
    os.chmod(hook, 0o755)
