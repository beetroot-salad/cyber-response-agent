"""#1618 G2: ONE table of every reader of Forgejo's commit (K4, K5 minus the grant read per r5.1-a), each with its real entry point
and the existing per-reader driver that runs it. The tests over it are `tenant_1108_p4/test_readers_1618.py`.

A `Reader` opens a `Rig` for one scene. `rig.run(commit, expect)` drives the reader once and reports a `Result` read at the
reader's own boundary (an exit status, a typed refusal, a log line, a skipped tick), never from the production operation.
FORCED (the one place; production spellings are the implementer's):
- the host judge's copy path is the launcher's own `fetch=` seam (`cli.learning.branch.main(..., fetch=)`, the one the corpus and
  tenant check use); a refusal is logged by its judge pass and never raised (the launch goes on);
- a sibling's copy is `copy.make(world=)` alone: the pin is the family's, planted in its episode (`knowledge_pin.json`, what
  `read_pin` reads), never chosen by the container (C20).
"""
from __future__ import annotations

import contextlib
import importlib
import json
import logging
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.tenancy.knowledge_1618 import _readers_1618 as RD
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K

#: How a tick that cannot reach Forgejo may word its transport cause (a tick runs no fetch child, so there is no line to compare
#: with). It is matched only against the text AFTER the drains wrapper's colon ("...delivery refused: <cause>", `drains.py:324`),
#: never the wrapper's own word "refused", which every cause carries.
TICK_CAUSE = re.compile(r"connect|unreach|could not reach|timed out|no route|resolve", re.IGNORECASE)


def tick_cause(text: str) -> re.Match[str] | None:
    """The transport cause a tick's skip names: searched after the last `refused:` (else after the last `: `) of `text`."""
    tail = text.rpartition("refused:")[2] if "refused:" in text else text.rpartition(": ")[2]
    return TICK_CAUSE.search(tail) if tail.strip() else None
LATER = "K1618-LATER"


@dataclass
class Env:
    """What a rig may use: the test's folders and fixtures (`fixture(name)` is the test's `request.getfixturevalue`)."""

    tmp_path: Path
    data_root: Path
    capsys: Any
    caplog: Any
    monkeypatch: Any
    fixture: Callable[[str], Any]


@dataclass
class Result:
    """What one drive of a reader showed, at the reader's own boundary."""

    refused: bool
    text: str = ""  # the refusal as the reader words it (stderr, message, log)
    rc: int | None = None
    asks: list[dict[str, Any]] = field(default_factory=list)  # the fetch child's asks (`commit`, `line`) this drive made
    git_requests: int = 0  # git requests the listener saw (readers that run no child)
    left: list[str] = field(default_factory=list)  # copies / drafts the reader left behind
    seen: str | None = None  # `pin`, `other` or None: which commit's content the reader used
    spent: bool = False  # the reader went on to use knowledge (message 0, a questioner call, a model call, a batch)
    minted: int = 0  # credentials the reader's own process minted (O8)
    out: str = ""  # what the reader printed to stdout (the operator tools)
    stored: int = 0  # findings the reader's pass left in the learning store (the host judge)
    siblings: int = 0  # siblings the launch started (a launch that goes on past a refused judge pass)


@dataclass
class Rig:
    t: Any
    run: Callable[..., Result]  # run(commit=None, expect="ok")
    pin: str  # an older commit than `later()` leaves main at
    later: Callable[[], Any]
    #: Takes Forgejo down for the NEXT `run`; None means at once. A reader whose launch itself fetches (the learning helper
    #: reads `main` at launch, r5.1-a) takes it down inside the job, after launch, before its request.
    down: Callable[[], None] | None = None

    def go_down(self) -> None:
        (self.down or (lambda: K.forge_down(self.t)))()


@dataclass(frozen=True)
class Reader:
    id: str
    entry: str  # the real entry point
    open: Callable[[Env], contextlib.AbstractContextManager[Rig]]
    refusal: str  # `exit` (non-zero), `raise` (typed), `log` (logged, the pass/launch goes on), `skip` (a skipped tick)
    via: str = "child"  # `child` (the fetch child, recorded) or `git` (the tick's own opening fetch)
    pinned: bool = False
    spends: bool = False
    also_main: bool = False  # the same drive also reads main (a tenant check): asks for `None` are allowed
    postgres: bool = False
    shows: bool = False  # the reader prints what it read to stdout when served (an operator tool)
    #: False when the launch that runs the reader refuses an unservable pin earlier than the reader (the host judge: the questioner's
    #: corpus asks the same pin first), so the reader's own refusal of it cannot be reached through the launcher.
    unserved_reachable: bool = True


def _asks(calls: Any, lines: Any = None) -> list[dict[str, Any]]:
    out = []
    for i, call in enumerate(calls):
        line = call.get("line") if lines is None else (lines[i] if i < len(lines) else None)
        out.append({"commit": call.get("commit"), "line": line})
    return out


def _mark_seen(mark: str | None) -> str | None:
    if mark is None:
        return None
    return "pin" if mark == K.mark_text(K.SEEDED_MARK) else "other"


def _settings_seen(t: Any, pin: str, settings: dict[str, bytes] | None) -> str | None:
    """Which commit's `settings/` a copy holds, judged from the remote alone (`half_at`): `pin` when it is exactly the pin's,
    `other` when it is anything else (the later `main`'s, a decoy's), None when nothing was copied. For scenes whose seed carries
    no revision mark (the job scene), so the mark comparison of `_mark_seen` has nothing to tell the pin by."""
    if settings is None:
        return None
    return "pin" if settings == K.half_at(t, pin, "settings") else "other"


def _later(t: Any) -> Callable[[], Any]:
    return lambda: K.advance_main(t, LATER)


# --- run start (unpinned, pinned) ---------------------------------------------------------------------------------------

def _run_start(env: Env) -> contextlib.AbstractContextManager[Rig]:
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    @contextlib.contextmanager
    def opened() -> Iterator[Rig]:
        with K.scene(env.tmp_path, env.data_root, decoy=True) as t:
            def run(commit: str | None = None, expect: str = "ok") -> Result:
                pub = A.fetching(t, env.tmp_path)
                extra = ("--knowledge-commit", commit) if commit else ()
                out = B.launch(t, env.tmp_path, publish=None, fetch=pub, argv_extra=extra)
                assert out.raised is None, out.text()
                mark = A.settings_mark(out.seen[0]) if out.seen else None
                # the exit a refusal by `SystemExit` makes (what a shell sees), else `main`'s return
                rc = out.rc if out.exit_status is None else out.exit_status
                return Result(refused=out.refusal is not None, text=out.refusal or "", rc=rc, asks=_asks(pub.calls, pub.lines),
                              left=A.listing(A.run_copies(t)), seen=_mark_seen(mark), spent=bool(out.reached))
            yield Rig(t, run, t.commit, _later(t))
    return opened()


# --- the learning helper: copy.make (with and without a commit) and a sibling's copy ------------------------------------

def _copy_dirs(scene: Any) -> list[Path]:
    base = scene.root / ".job-scratch" / scene.claim
    return sorted(p for p in base.iterdir() if p.name != "shared") if base.is_dir() else []


def _helper_seam(scene: Any, calls: list) -> Callable[..., str]:
    seam = K.fetch_seam(scene.t)

    def fetch(tenant_id: str, dest: Path, *, data_root: Any = None, commit: str | None = None, **_kw: Any) -> str:
        return seam(tenant_id, dest, data_root=data_root if data_root is not None else scene.root, commit=commit)

    fetch.calls = seam.calls  # type: ignore[attr-defined]
    calls.append(seam)
    return fetch


def _helper(env: Env, *, with_commit: bool, sibling: bool = False) -> contextlib.AbstractContextManager[Rig]:
    from defender import job_host
    from defender.records._knowledge_pin import pin_text
    from defender.tests.support.jobs._job_helper import ForgeCredentialRecorder
    from defender.tests.support.jobs._job_helper_learning import listing, plant_siblings, run_kind

    @contextlib.contextmanager
    def opened() -> Iterator[Rig]:
        scene = env.fixture("job_scene")
        t = scene.t
        armed = {"down": False}

        def run(commit: str | None = None, expect: str = "ok") -> Result:
            seams: list = []
            fetch = _helper_seam(scene, seams)
            forge = ForgeCredentialRecorder()
            fields: dict[str, Any] = {"commit": commit} if (with_commit and commit) else {}
            kw: dict[str, Any] = {}
            if sibling:
                planted = plant_siblings(scene)
                if commit:  # the family's pin, in the family's episode (what `read_pin` reads): the host decides it, not the container
                    (planted.dir / "knowledge_pin.json").write_text(pin_text(commit), encoding="utf-8")
                fields["world"] = planted.worlds["b"]
                kw = {"job_id": planted.job_id, "source": planted.source}
            got: dict[str, Any] = {}

            def job(c: Any) -> int:
                got["mark"] = len(fetch.calls)  # the launch's own ask (`main`, r5.1-a) is before this index
                if armed["down"]:
                    K.forge_down(t)
                before = _copy_dirs(scene)
                try:
                    got["answer"] = c.request("copy.make", **fields)
                    got["settings"] = K.tree_bytes(Path(got["answer"]["path"]) / "settings")
                except job_host.Refused as refusal:
                    got["refusal"] = str(refusal)
                got["new"] = [p.name for p in _copy_dirs(scene) if p not in before
                              and "answer" not in got]
                return 0

            run_kind(scene, "learning", job, forge=forge, fetch=fetch, **kw)
            left = got.get("new", []) + [p.name for p in _copy_dirs(scene)]
            left += listing(scene.root / scene.tenant / "run-knowledge") if sibling else []
            return Result(refused="refusal" in got, text=got.get("refusal", ""), asks=_asks(fetch.calls[got["mark"]:]), left=left,
                          seen=_settings_seen(t, commit or t.commit, got.get("settings")),
                          minted=len(forge.built) + len(forge.asked))
        yield Rig(t, run, t.commit, _later(t), down=lambda: armed.update(down=True))
    return opened()


# --- the judge: bodies in the job container (via the helper) and the host pass ------------------------------------------

def _judge_modules() -> tuple[Any, Any]:
    return (importlib.import_module("defender.tests.tenancy.tenant_1108_p4.test_judge_bodies"),
            importlib.import_module("defender.tests.support.learning.judge._judge_921"))


def _judge_container(env: Env) -> contextlib.AbstractContextManager[Rig]:
    JB, J = _judge_modules()

    @contextlib.contextmanager
    def opened() -> Iterator[Rig]:
        from defender.learning.judge import JudgeRefused

        scene = env.fixture("judge_scene")
        seam = K.fetch_seam(scene.t, env.tmp_path / "judge-fetch")
        with RD.helper_socket(scene.t, env.tmp_path, env.monkeypatch, seam) as helper:
            def run(commit: str | None = None, expect: str = "ok") -> Result:
                JB._stamp(scene, code=scene.product.post, knowledge={"commit": commit or scene.k1})
                judge = J.scripted_judge()
                before = len(seam.calls)
                raised = None
                try:
                    J.grade(scene.ep, judge=judge, git_show=scene.product, draws=1)
                except JudgeRefused as refused:
                    raised = str(refused)
                shown = "\n".join(judge.prompts)
                assert raised is None or not judge.prompts, "the model was called on a pass that refused"
                seen = "pin" if JB.EXPORT in shown else ("other" if JB.CURRENT in shown else None)
                assert all(name == "copy.make" for name, _f in helper.requests)
                return Result(refused=raised is not None, text=raised or "", asks=_asks(seam.calls[before:]), seen=seen,
                              spent=bool(judge.prompts), left=RD.listing(helper.copies) if raised else [])
            yield Rig(scene.t, run, scene.k1, lambda: None)
    return opened()


def _judge_host(env: Env) -> contextlib.AbstractContextManager[Rig]:
    """The host judge pass as the launcher runs it: the real `cli.learning.branch.main(fetch=)` over a family whose siblings ran
    (`J.FakeSibling`, each loading the tenant's lesson), the launcher's grade reading each body at the family's pin."""
    BR = importlib.import_module("defender.tests.tenancy.tenant_1108_p4.test_branch_replay")
    JB, J = _judge_modules()
    from defender.tests.support.learning.branch import _triplet_947 as T

    class Siblings(J.FakeSibling):
        """The siblings loaded `JB.NAME`; Forgejo goes down once the last has run (the launch's own fetches are behind it)."""

        def __init__(self, *, knowledge: Any, down: Callable[[], None] | None, fetch: Any) -> None:
            super().__init__(knowledge=knowledge)
            self.down, self.fetch, self.mark = down, fetch, None

        def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **kw: Any) -> int:
            rc = super().__call__(argv, env=env, **kw)
            episode = self.episode_of(list(argv))
            if episode is not None:
                for path in (episode / "runs").glob("*/lessons_loaded.jsonl"):
                    path.write_text(json.dumps({"lesson_name": JB.NAME, "ts": "2026-10-20T10:00:00Z", "kind": "read", "role": "main"})
                                    + "\n", encoding="utf-8")
            if self.mark is None and len(self.launches) >= len(T.WORLDS):
                self.mark = len(self.fetch.calls)  # every ask from here on is the judge pass's
                if self.down is not None:
                    self.down()
            return rc

    @contextlib.contextmanager
    def opened() -> Iterator[Rig]:
        scene = env.fixture("branch_scene")
        armed = {"down": False}
        env.caplog.set_level(logging.WARNING)
        store = J.install_launcher_store(env.monkeypatch)

        def run(commit: str | None = None, expect: str = "ok") -> Result:
            pin = commit or scene.k1
            BR._stamp_source(scene, knowledge={"commit": pin})
            fetch = K.fetch_seam(scene.t, env.tmp_path / "judge-host-fetch")
            siblings = Siblings(knowledge={"commit": pin}, fetch=fetch,
                                down=(lambda: K.forge_down(scene.t)) if armed["down"] else None)
            judge = J.scripted_judge(default=J.as_reply_text(J.reply_doc(systems=["idp"])))
            env.caplog.clear()
            launch = BR._launch(scene, fetch=fetch, spawn=siblings, judge=judge, live_tree=T.source_capture(knowledge={"commit": pin}))
            logged = "\n".join(r.getMessage() for r in env.caplog.records if r.levelno >= logging.WARNING)
            shown = "\n".join(judge.prompts)
            seen = "other" if JB.CURRENT in shown else ("pin" if "inventory owner first" in shown else None)
            stored = sum(len(held) for held in store.items.values())
            # the launch itself is not refused by the judge's refusal: rc 0 and the siblings went on (grading never fails a launch)
            return Result(refused=not judge.prompts, text=logged, rc=launch.rc, asks=_asks(fetch.calls[siblings.mark or 0:]),
                          seen=seen, spent=bool(judge.prompts), stored=stored, siblings=len(siblings.launches))
        yield Rig(scene.t, run, scene.k1, lambda: K.advance_main(scene.t, files={JB.TENANT_PATH: JB._lesson(JB.CURRENT)}), down=lambda: armed.update(down=True))
    return opened()


# --- the branch launcher: the questioner corpus (pinned) and the tenant check ----------------------------------------------

def _branch(env: Env) -> contextlib.AbstractContextManager[Rig]:
    BR = importlib.import_module("defender.tests.tenancy.tenant_1108_p4.test_branch_replay")
    from defender.tests.support.learning.branch import _triplet_947 as T

    @contextlib.contextmanager
    def opened() -> Iterator[Rig]:
        scene = env.fixture("branch_scene")

        def run(commit: str | None = None, expect: str = "ok") -> Result:
            pin = commit or scene.k1
            BR._stamp_source(scene, knowledge={"commit": pin})
            launch = BR._asking_forgejo(scene, live_tree=T.source_capture(knowledge={"commit": pin}))
            first = launch.questioner.prompts[0] if launch.questioner.prompts else ""
            seen = "pin" if BR.Q_EXPORT in first else ("other" if BR.Q_CURRENT in first else None)
            return Result(refused=launch.rc not in (0, None), text=launch.message, rc=launch.rc, asks=_asks(launch.fetches),
                          seen=seen, spent=bool(launch.questioner.prompts or launch.spawn.launches), minted=launch.minted)
        yield Rig(scene.t, run, scene.k1, lambda: None)
    return opened()


# --- the operator tools -------------------------------------------------------------------------------------------------

def _tool(make: Callable[[str, str, Path], tuple[Callable[..., Any], list[str]]], *, pinned: bool = False,
          later: Callable[[Any], Any] | None = None) -> Callable[[Env], contextlib.AbstractContextManager[Rig]]:
    def open_(env: Env) -> contextlib.AbstractContextManager[Rig]:
        @contextlib.contextmanager
        def opened() -> Iterator[Rig]:
            with K.scene(env.tmp_path, env.data_root, decoy=True) as t:
                def run(commit: str | None = None, expect: str = "ok") -> Result:
                    run_id = RD.plant_run(t, commit or t.commit) if pinned else ""
                    main, argv = make(t.tenant_id, run_id, env.tmp_path)
                    ran = RD.run_tool(t, env.tmp_path, env.capsys, main, argv)
                    lines = ran.out.splitlines()
                    seen = None
                    if pinned and ran.rc == 0:
                        seen = "pin" if "- cmdb (SKILL.md)" in lines else "other"
                    return Result(refused=ran.rc != 0, text=ran.err, rc=ran.rc, asks=_asks(ran.fetches), left=ran.left,
                                  git_requests=ran.requests, seen=seen, minted=ran.minted, out=ran.out)
                yield Rig(t, run, t.commit, (lambda: later(t)) if later else _later(t))
        return opened()
    return open_


def _page(tenant: str, _run: str, _tmp: Path) -> tuple[Callable[..., Any], list[str]]:
    from defender.learning.frontend import serialize
    return serialize.main, ["lessons_page.py", "--tenant", tenant]


def _tracer(tenant: str, _run: str, _tmp: Path) -> tuple[Callable[..., Any], list[str]]:
    from defender.cli.learning import trace_lesson
    return trace_lesson.main, ["--tenant", tenant, "--all"]


def _policy(tenant: str, _run: str, tmp: Path) -> tuple[Callable[..., Any], list[str]]:
    from defender.cli import policy_cli
    return policy_cli.main, ["show", "gather", "--run-dir", str(tmp / "policy-run"), "--tenant", tenant]


def _map(tenant: str, run_id: str, _tmp: Path) -> tuple[Callable[..., Any], list[str]]:
    from defender.cli import workspace_map
    return workspace_map.main, ["workspace_map.py", "--tenant", tenant, run_id]


# --- the drain tick's opening fetch ---------------------------------------------------------------------------------------

def _tick(env: Env) -> contextlib.AbstractContextManager[Rig]:
    from defender.tests.support.learning.core._store1278 import LessonWriter, call, finding, lesson_citing
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        LESSON_NAME,
        BoxSpy,
        author_drain,
        drafts_dir,
        without_clone,
    )

    @contextlib.contextmanager
    def opened() -> Iterator[Rig]:
        w = env.fixture("world")
        without_clone(w.t)
        env.caplog.set_level(logging.WARNING)

        def run(commit: str | None = None, expect: str = "ok") -> Result:
            call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding("f1")], kind="finding")
            writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
            served = len(w.t.server.seen)
            env.caplog.clear()
            rc = author_drain(w.t, w.paths, trigger=writer, box=BoxSpy())
            logged = "\n".join(r.getMessage() for r in env.caplog.records if r.levelno >= logging.WARNING)
            skipped = "skipping this tick" in logged
            return Result(refused=skipped, text=logged, rc=rc, git_requests=len(w.t.server.seen) - served,
                          left=[p.name for p in drafts_dir(w.t).glob("*")] if skipped else [], spent=bool(writer.served))
        yield Rig(w.t, run, w.t.commit, lambda: None)
    return opened()


READERS: tuple[Reader, ...] = (
    Reader("run-start", "run.main -> run_common.materialize (fetch child)", _run_start, "exit", spends=True),
    Reader("run-start-pinned", "run.main --knowledge-commit", _run_start, "exit", pinned=True, spends=True),
    Reader("sibling-copy", "job helper copy.make(world=), pin from the family's episode", lambda e: _helper(e, with_commit=False, sibling=True),
           "raise", pinned=True, postgres=True),
    Reader("drain-tick-opening-fetch", "learning.core.drains.author_drain -> opened_delivery (private repository)",
           _tick, "skip", via="git", spends=True, postgres=True),
    Reader("helper-copy-make", "job helper copy.make (main)", lambda e: _helper(e, with_commit=False), "raise",
           postgres=True),
    Reader("helper-copy-make-commit", "job helper copy.make(commit=)", lambda e: _helper(e, with_commit=True), "raise",
           pinned=True, postgres=True),
    Reader("judge-bodies-container", "learning.judge.grade_episode -> helper copy.make(commit=)", _judge_container, "raise",
           pinned=True, spends=True),
    Reader("judge-host", "branch.cli.main(fetch=) -> its judge pass", _judge_host, "log", pinned=True, spends=True,
           unserved_reachable=False),
    Reader("questioner-corpus", "branch.cli.main (the corpus at the source's commit)", _branch, "exit", pinned=True,
           spends=True, also_main=True),
    Reader("branch-launcher", "branch.cli.main (the tenant check at main)", _branch, "exit", spends=True, also_main=True),
    Reader("workspace-map", "cli.workspace_map.main (a run's recorded commit)",
           _tool(_map, pinned=True, later=lambda t: K.advance_main(t, files={"agent/skills/cmdb/SKILL.md": None})), "exit",
           pinned=True, shows=True),
    Reader("lessons-page", "learning.frontend.serialize.main", _tool(_page), "exit", shows=True),
    Reader("tracer", "cli.learning.trace_lesson.main", _tool(_tracer), "exit", shows=True),
    Reader("policy-cli", "cli.policy_cli.main", _tool(_policy), "exit", shows=True),
)

__all__ = ["LATER", "READERS", "TICK_CAUSE", "Env", "Reader", "Result", "Rig"]
