"""Scene substrate for the lessons drain's tick: a real git repo, a real queue file, and the
curator fake that enters through the config's own injection seam.

Built for #773's drain-owned forward check. #1166 deleted that check, its repair spawn and its
gap ledger, and with them the verifier, repair and key-source fakes this file carried; what
remains drives the commit, deferral, single-truth and adversarial-input behaviour the drain
still has.

Project idioms this file obeys, because CI ratchets them: fakes enter through
`dataclasses.replace(cfg, ...)` and constructor arguments, never `monkeypatch.setattr`;
each fake injects faults only and never classifies or decides policy.
"""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Any

from defender.tests.support.learning.curation._drain719 import (  # noqa: F401 — re-exported substrate
    Background,
    Holder,
    channel_of,
    consumed,
    finding_row,
    git,
    graveyard,
    make_paths,
    make_repo,
    pending,
    pending_by_id,
    read_rows,
    seed,
    stuck_records,
)

from defender.learning.author import drain
from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.core.config import LoopPaths
from defender.learning.core.state import QUESTIONER_FINDINGS, Channel, LearningState
from defender.tests.support.learning.curation._curator1134 import author_trees


#: §7 FK-17: a deferral that reaches the ceiling is greppable apart from a fault exit.
DEFERRED_CEILING_REASON = "deferred_ceiling"


# ---------------------------------------------------------------------------
# corpus bytes
# ---------------------------------------------------------------------------


def lesson(*finding_ids: str, body: str = "the lesson body", **frontmatter: Any) -> str:
    """One corpus `*.md` citing `finding_ids` under the channel's own provenance key.

    `source_finding_ids` is the key `provenance_field("finding_id")` derives and the key
    both the pre-author idempotency gate and M3.2's vouching read (C13/G13), so a file
    written with it is one a later tick recognises."""
    lines = ["---", "source_finding_ids:"]
    lines += [f"- {fid}" for fid in finding_ids]
    for key, val in frontmatter.items():
        lines.append(f"{key}: {json.dumps(val)}")
    lines += ["---", "", body, ""]
    return "\n".join(lines)


def malformed_lesson(body: str = "no frontmatter here at all\n") -> str:
    """Bytes whose frontmatter block cannot be parsed, written by the test itself.

    Real input through the real primitive: `_cited_ids` runs `split_frontmatter` over these
    bytes on every run, so the taxonomy assumption ("malformed cites nothing") is re-probed
    rather than pinned once."""
    return "---\nsource_finding_ids: [unterminated\nbody without a closing fence\n" + body


# ---------------------------------------------------------------------------
# the scene
# ---------------------------------------------------------------------------


@dataclass
class Scene:
    """One tick's world: a real git repo, a real queue file, and the injected fakes."""

    paths: LoopPaths
    cfg: Any
    channel: Channel
    repo: Path
    corpus: Path
    rows: list[dict]
    curator: FakeCurator
    #: The channel module's own `run_batch`; the lessons channel's unless a sibling scene
    #: replaces it. Named so `Scene.run` always drives a production front door.
    runner: Callable[..., int] | None = None
    #: HEAD as the scene was built, so `head_files()` can answer "what this tick committed".
    base_sha: str = ""

    # -- observations -------------------------------------------------------

    def run(self, **kw: Any) -> int:
        """Drive the REAL entry point. `lessons_run.run_batch` -> `drain.run_batch` ->
        `_tick` -> `_author_and_rotate`: the whole tick, not a re-implementation of it."""
        runner = self.runner if self.runner is not None else lessons_run.run_batch
        return runner(cfg=self.cfg, **kw)

    def head_files(self) -> list[str]:
        """The paths THIS TICK committed — asked of git, never of the drain's own record."""
        if self.head_sha() == self.base_sha:
            return []
        out = git(self.repo, "diff", "--no-renames", "--name-only", self.base_sha, "HEAD").stdout
        return sorted(p for p in out.splitlines() if p.strip())

    def head_message(self) -> str:
        return git(self.repo, "log", "-1", "--format=%B").stdout

    def head_sha(self) -> str:
        return git(self.repo, "rev-parse", "HEAD").stdout.strip()

    def head_text(self, rel: str) -> str | None:
        proc = git(self.repo, "show", f"HEAD:{rel}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    def commit_count(self) -> int:
        return int(git(self.repo, "rev-list", "--count", "HEAD").stdout.strip())

    def corpus_files(self) -> list[str]:
        return sorted(
            str(p.relative_to(self.corpus))
            for p in self.corpus.rglob("*")
            if p.is_file() and p.name != ".gitkeep"
        )

    def report_lines(self) -> list[str]:
        """The channel's own disposition report — `held_report` on the lessons channel,
        `skip_report` on the questioner's. One accessor, because both are written by the
        same `shared.write_disposition_report` and both are what "reported" means."""
        path = location_path(self.paths.state_root) / self.cfg.channel.report
        return path.read_text(encoding="utf-8").splitlines() if path.is_file() else []

    def pending(self) -> list[dict]:
        return pending(self.paths, self.channel)

    def pending_by_id(self) -> dict[str, dict]:
        return pending_by_id(self.paths, self.channel)

    def consumed(self) -> list[dict]:
        return consumed(self.paths, self.channel)

    def consumed_by_id(self) -> dict[str, dict]:
        return {r["finding_id"]: r for r in self.consumed() if "finding_id" in r}

    def graveyard(self) -> list[dict]:
        return graveyard(self.paths, self.channel)

    def category_of(self, fid: str) -> str | None:
        row = self.consumed_by_id().get(fid)
        return None if row is None else row.get("consumed_category")


def build_scene(  # noqa: PLR0913 — one tick's whole world, threaded rather than global
    tmp_path: Path,
    *,
    rows: list[dict] | None = None,
    state_dir: Path | None = None,
    curator: FakeCurator | None = None,
    seed_corpus: dict[str, str] | None = None,
    channel_name: str = "findings",
    **cfg_overrides: Any,
) -> Scene:
    """A lessons-channel tick, wired through the config's own injection seams.

    The curator spawn, which the tick would otherwise reach over the network, enters through a
    `dataclasses.replace` on the real config builder's output. Nothing is patched onto a
    module."""
    paths = make_paths(tmp_path, state_dir=state_dir)
    repo = paths.repo_root
    corpus = paths.lessons_dir
    rows = list(rows if rows is not None else [finding_row("f1", run_id="f1")])

    for rel, text in (seed_corpus or {}).items():
        target = corpus / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    if seed_corpus:
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "seed corpus")

    channel = channel_of(channel_name)
    seed(paths, channel, rows)

    curator = curator if curator is not None else FakeCurator()

    base = lessons_run.build_author_config(
        paths, state=LearningState.open(paths), trees=author_trees(paths))
    wiring: dict[str, Any] = {"invoke_agent": curator}
    wiring.update(cfg_overrides)
    cfg = dataclasses.replace(base, **wiring)

    return Scene(
        paths=paths, cfg=cfg, channel=channel, repo=repo, corpus=corpus, rows=rows,
        curator=curator, base_sha=git(repo, "rev-parse", "HEAD").stdout.strip(),
    )


def world_row(fid: str, **extra: Any) -> dict:
    """One QUESTIONER-channel row: a finding about the WORLD, not about the defender.

    That channel carries no `run_id` and no defender disposition, so its gate is
    idempotency-only (#1007 N1) and O7 obliges this delta to leave its behaviour alone. It names
    the systems its lesson is selected by (#1224 O12): the questioner curator drains a world row
    naming none without authoring (`consumed_no_systems`)."""
    return {
        "schema_version": 1,
        "finding_id": fid,
        "subject": "world",
        "type": "lead-set",
        "finding": "the world's facts never backed this field",
        "systems": ["elastic"],
        **extra,
    }


def build_questioner_scene(
    tmp_path: Path,
    *,
    rows: list[dict] | None = None,
    curator: FakeCurator | None = None,
    seed_corpus: dict[str, str] | None = None,
    **cfg_overrides: Any,
) -> Scene:
    """The SIBLING channel's tick, the questioner curator's, on the same drain body."""
    from defender.learning.author.questioner import run as questioner_run

    paths = make_paths(tmp_path)
    repo = paths.repo_root
    corpus = paths.lessons_questioner_dir
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / ".gitkeep").write_text("", encoding="utf-8")
    for rel, text in (seed_corpus or {}).items():
        target = corpus / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    if git(repo, "status", "--porcelain").stdout.strip():  # make_repo may already carry it
        git(repo, "commit", "-q", "-m", "questioner corpus")

    rows = list(rows if rows is not None else [world_row("w1")])
    channel = QUESTIONER_FINDINGS
    seed(paths, channel, rows)

    curator = curator if curator is not None else FakeCurator()

    base = questioner_run.build_questioner_config(
        paths, state=LearningState.open(paths), trees=author_trees(paths))
    wiring: dict[str, Any] = {"invoke_agent": curator}
    wiring.update(cfg_overrides)
    cfg = dataclasses.replace(base, **wiring)

    scene = Scene(
        paths=paths, cfg=cfg, channel=channel, repo=repo, corpus=corpus, rows=rows,
        curator=curator, base_sha=git(repo, "rev-parse", "HEAD").stdout.strip(),
    )
    scene.runner = questioner_run.run_batch  # type: ignore[attr-defined]
    return scene


# ---------------------------------------------------------------------------
# #1108 P4 (O7): the same tick over a git-free draft
# ---------------------------------------------------------------------------

#: The repo-relative spelling of a lesson after P4 (OD6).
DRAFT_LESSONS = "agent/lessons"
DRAFT_QUESTIONER = "agent/lessons-questioner"


@dataclass
class DraftScene(Scene):
    """`Scene` over a P3 batch: `corpus` is the draft's lane, `repo` the tenant clone, and every
    head observation reads the batch branch (what the commit-maker made), never a checkout.
    `head_files()` names `agent/...` paths; `commit_count()` counts the branch tip's history
    (the export commit is the only commit before the tick)."""

    lane: Any = None

    def head_files(self) -> list[str]:
        return self.lane.landed()

    def head_message(self) -> str:
        return self.lane.message()

    def head_sha(self) -> str:
        return self.lane.tip()

    def head_text(self, rel: str) -> str | None:
        return self.lane.text_at_tip(rel)

    def commit_count(self) -> int:
        return int(git(self.repo, "rev-list", "--count", self.lane.tip()).stdout.strip())

    def draft_drift(self) -> list[str]:
        """Every `agent/...` path whose bytes differ between the draft and the batch tip (a
        file only one side has included): `[]` is "the draft is re-synced to what landed"."""
        listed = git(self.repo, "ls-tree", "-r", "--name-only", self.lane.tip(), "--",
                     "agent").stdout.split("\n")
        tip = {rel: git(self.repo, "cat-file", "-p", f"{self.lane.tip()}:{rel}").stdout
               for rel in listed if rel.strip()}
        draft = {f"agent/{p.relative_to(self.lane.agent).as_posix()}":
                 p.read_text(encoding="utf-8", errors="surrogateescape")
                 for p in self.lane.agent.rglob("*") if p.is_file() or p.is_symlink()}
        return sorted(rel for rel in tip.keys() | draft.keys() if tip.get(rel) != draft.get(rel))


def _draft_scene(tmp_path: Path, *, corpus_name: str, rows: list[dict], channel: Channel,
                 curator: FakeCurator | None, seed_corpus: dict[str, str] | None,
                 state_dir: Path | None, build: Callable[..., Any], runner: Callable[..., int],
                 cfg_overrides: dict[str, Any]) -> DraftScene:
    from defender.tests.support.learning.curation import _curator1134 as C

    files = {f"{corpus_name}/{rel}": text for rel, text in (seed_corpus or {}).items()}
    lane = C.draft_lane(tmp_path, files=files, state_dir=state_dir)
    seed(lane.paths, channel, rows)
    curator = curator if curator is not None else FakeCurator()
    curator.outside_root = Path(lane.batch.draft_root)
    base = build(lane, state=LearningState.open(lane.paths))
    wiring: dict[str, Any] = {"invoke_agent": curator}
    wiring.update(cfg_overrides)
    cfg = dataclasses.replace(base, **wiring)
    return DraftScene(
        paths=lane.paths, cfg=cfg, channel=channel, repo=lane.clone,
        corpus=lane.agent / corpus_name, rows=rows, curator=curator, runner=runner,
        base_sha=lane.base, lane=lane,
    )


def build_draft_scene(tmp_path: Path, *, rows: list[dict] | None = None,
                      state_dir: Path | None = None, curator: FakeCurator | None = None,
                      seed_corpus: dict[str, str] | None = None, channel_name: str = "findings",
                      **cfg_overrides: Any) -> DraftScene:
    """`build_scene` after P4: the lessons tick over a draft lane (`_curator1134.draft_lane`),
    `seed_corpus` published in the export commit, the config built with the assumed `batch=`
    seam (`_curator1134.draft_author_cfg`)."""
    from defender.tests.support.learning.curation import _curator1134 as C

    return _draft_scene(
        tmp_path, corpus_name="lessons",
        rows=list(rows if rows is not None else [finding_row("f1", run_id="f1")]),
        channel=channel_of(channel_name), curator=curator, seed_corpus=seed_corpus,
        state_dir=state_dir, build=C.draft_author_cfg, runner=lessons_run.run_batch,
        cfg_overrides=cfg_overrides)


def build_questioner_draft_scene(tmp_path: Path, *, rows: list[dict] | None = None,
                                 curator: FakeCurator | None = None,
                                 seed_corpus: dict[str, str] | None = None,
                                 **cfg_overrides: Any) -> DraftScene:
    """`build_questioner_scene` after P4, over a draft lane (`draft_questioner_cfg`)."""
    from defender.learning.author.questioner import run as questioner_run
    from defender.tests.support.learning.curation import _curator1134 as C

    return _draft_scene(
        tmp_path, corpus_name="lessons-questioner",
        rows=list(rows if rows is not None else [world_row("w1")]),
        channel=QUESTIONER_FINDINGS, curator=curator, seed_corpus=seed_corpus,
        state_dir=None, build=C.draft_questioner_cfg, runner=questioner_run.run_batch,
        cfg_overrides=cfg_overrides)


# ---------------------------------------------------------------------------
# fakes — each injects faults or canned content, and classifies nothing
# ---------------------------------------------------------------------------


@dataclass
class FakeCurator:
    """The first curator spawn (`cfg.invoke_agent`).

    A fault-spec, not a policy: `writes` is what the agent leaves in the worktree,
    `committed`/`consumed_skip` are what it SELF-REPORTS, and the two are deliberately
    independent so a test can drive any report/tree disagreement O5 names. `raises` is the
    declarative fault slot; every use cites the ledger claim that observed its class on the
    real dependency (GL2 for the `RETIRE_SET` members)."""

    writes: dict[str, str] = field(default_factory=dict)
    deletes: tuple[str, ...] = ()
    outside: dict[str, str] = field(default_factory=dict)
    committed: list[str] | None = None
    consumed_skip: list[dict] | None = None
    commit_message: str = "author findings batch"
    extra_result: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    raises: BaseException | None = None
    also: Callable[..., None] | None = None
    calls: list[dict] = field(default_factory=list)
    #: Where `outside` writes land: the repo root by default; a draft scene sets the draft's
    #: root, so `outside` names `agent/<not a lane>/...` (#1108 P4).
    outside_root: Path | None = None

    def __call__(self, rows: list[dict], batch_id: str, cfg: Any) -> dict:
        self.calls.append({"rows": list(rows), "batch_id": batch_id, "cfg": cfg})
        if self.raises is not None:
            raise self.raises
        for rel, text in self.writes.items():
            target = cfg.corpus_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        for rel in self.deletes:
            target = cfg.corpus_dir / rel
            if target.is_file():
                target.unlink()
        for rel, text in self.outside.items():
            root = self.outside_root if self.outside_root is not None else cfg.repo_root
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        if self.also is not None:
            self.also(rows, batch_id, cfg)
        if self.result is not None:
            return dict(self.result)
        ids = [r["finding_id"] for r in rows]
        out: dict[str, Any] = {
            "committed": list(self.committed if self.committed is not None else ids),
            "consumed_skip": list(self.consumed_skip or []),
            "commit_message": self.commit_message,
        }
        out.update(self.extra_result)
        return out


# ---------------------------------------------------------------------------
# fault content, each citing the claim that observed it
# ---------------------------------------------------------------------------


def author_error(msg: str = "injected") -> BaseException:
    """GL2: `AuthorError` is a `RETIRE_SET` member, declared once at `drain.py:73`."""
    return drain.AuthorError(msg)


def git_error(msg: str = "injected") -> BaseException:
    """GL2: `GitError` is a `RETIRE_SET` member."""
    from defender._git import GitError

    return GitError(["status"], 128, msg)


def model_retry(msg: str = "injected") -> BaseException:
    """GL2: `ModelRetry` is a `RETIRE_SET` member."""
    from pydantic_ai.exceptions import ModelRetry

    return ModelRetry(msg)


def stage_abort(msg: str = "injected") -> BaseException:
    """GL2: `StageAbort` is an explicit `RETIRE_SET` EXCLUSION (§7 E waives the cell)."""
    from defender.learning.core.config import StageAbort

    return StageAbort(msg)


def fatal_config(msg: str = "injected") -> BaseException:
    """GL2 / F8: `FatalConfigError` is a `ValueError` and a `RETIRE_SET` exclusion, which is
    why the per-pair handler must re-raise it BEFORE its broad `except Exception`."""
    from defender.learning.core.config import FatalConfigError

    return FatalConfigError(msg)


__all__ = [
    "Background",
    "DEFERRED_CEILING_REASON",
    "FakeCurator",
    "Holder",
    "Scene",
    "author_error",
    "author_shared",
    "build_scene",
    "drain",
    "fatal_config",
    "finding_row",
    "git",
    "git_error",
    "lesson",
    "lessons_run",
    "malformed_lesson",
    "model_retry",
    "read_rows",
    "seed",
    "stage_abort",
]
