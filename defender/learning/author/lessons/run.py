#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
import uuid
from dataclasses import field
from defender._model import model
from pathlib import Path

from typing import Any

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import drain
from defender.learning.author import shared as _shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    LoopPaths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    repo_lock_wait_seconds,
    author_max_attempts,
    author_timeout as _author_timeout,
)
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.core.state import FINDINGS, LearningState
from defender.knowledge._knowledge import LESSONS




AuthorError = _shared.AuthorError

# This channel's name: `cfg.log_prefix`, the envelope and the drain's per-channel logger
# (`drain.channel_logger`) all derive from it.
_LOG_PREFIX = "author"


@model(frozen=True, kw_only=True)
class AuthorConfig(CorpusAuthorConfig):
    """The lessons curator's drain config: the shared corpus-author core plus the held report,
    the manifest seed the lessons prompt takes, and the env-backed model knobs.

    Lock topology lives on `Channel`, not here (#719)."""

    manifest_seed: str | None = None
    # default_factory, not a plain default: these are env-backed knobs and a plain default
    # would freeze at import. A caller that overrides them still wins.
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_author_config(
    paths: LoopPaths, *, state: LearningState, trees: DrainTrees,
    manifest_seed: str | None = None, box: Any = None, batch: Any = None,
) -> AuthorConfig:
    """This channel's config, reading and writing its corpus through `trees`, the lane's open
    trees (`open_drain_trees`), which must hold the corpus itself (`shared.lane_corpus`, else
    `FatalConfigError`): `batch`'s draft `agent/lessons`, or — with no batch — the scene's
    `paths.lessons_dir`. `paths` keeps the learning state and the product checkout. The config
    must not outlive `trees`."""
    from defender.learning.author import shared as _shared

    root, corpus_dir, corpus_rel = _shared.lane_corpus_dir(paths, batch, LESSONS)
    return AuthorConfig(
        repo_root=root,
        corpus_dir=corpus_dir,
        corpus=_shared.lane_corpus(trees, corpus_dir),
        tree_for=trees.tree_for,
        corpus_rel=corpus_rel,
        batch=batch,
        state=state,
        channel=FINDINGS,
        repo_lock_wait_seconds=repo_lock_wait_seconds(),
        log_prefix=_LOG_PREFIX,
        author_prompt=paths.learning_dir / "author" / "lessons" / "prompt.md",
        invoke_agent=invoke_agent,
        gate=_gate_findings,
        buckets=FINDINGS_BUCKETS,
        noun="findings",
        max_attempts=author_max_attempts(),
        post_rotate=_write_held_report_after_rotate,
        manifest_seed=manifest_seed,
        box=box,
    )




def existing_finding_ids(cfg: AuthorConfig) -> set[str]:
    """This channel's name for `shared.existing_finding_ids`."""
    return _shared.existing_finding_ids(cfg)




def build_user_prompt(
    findings: list[dict], batch_id: str, cfg: AuthorConfig, *, salt: str | None = None
) -> str:
    return _shared.build_curator_user_prompt(
        findings, batch_id, corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_rel, label="findings",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: AuthorConfig) -> dict:
    """Spawn the curator to author the batch and self-report."""
    from defender.learning.author import curator_engine

    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        wiring=StageWiring.for_batch(
            cfg.author_prompt, cfg.author_model, cfg.author_effort,
            batch_id=batch_id, label="curator",
        ),
        ctx=StageContext(
            learning_run_dir=cfg.state.stage_dir(AUTHOR_DRAIN_LABEL),
            user=build_user_prompt(findings, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        log=_logger,
    )


FINDINGS_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
)


def write_held_report(
    cfg: AuthorConfig,
    *,
    batch_id: str,
    deferred: list[dict],
    skipped: list[dict],
    gate_held: list[dict],
) -> None:
    """The lessons channel's three decline reasons, as the labels its report line carries.

    `shared.write_disposition_report` composes the line and derives the `<label>_ids` keys;
    this function picks which labels the lessons channel reports. Each implies a different
    recovery:

    - `deferred`: couldn't land through no fault of its own; bounded and still queued.
    - `skipped`: terminal.
    - `gate_held`: never reached the agent; held every tick until a human moves it.

    Nothing is written when the tick declined nothing."""
    _shared.write_disposition_report(
        cfg.state, cfg.channel, batch_id=batch_id,
        groups={
            "deferred": deferred, "skipped": skipped, "gate_held": gate_held,
        },
    )


_logger = logging.getLogger(__name__)


def _write_held_report_after_rotate(outcome, cfg: AuthorConfig) -> None:
    """Runs after both the corpus commit and the queue rotation — the only seam that sees the
    tick's closing edge.

    Unconditional: this report is the operator's one written trace of what the tick declined,
    and must not depend on how the tick's other rows went."""
    write_held_report(
        cfg,
        batch_id=outcome.batch_id,
        deferred=outcome.held.get("deferred", []),
        skipped=outcome.consumed.get("consumed_skip", []),
        gate_held=outcome.gate_held,
    )


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths | None = None,
    state: LearningState | None = None,
    trees: DrainTrees | None = None,
    cfg: AuthorConfig | None = None,
    box: Any = None,
    batch: Any = None,
) -> int:
    """This channel's entry point; the batch body is `drain.run_batch`, one claim of `batch`.
    Exactly one of `trees` (the lane's open trees: the drain's work step opens them over the
    batch's draft, #1134) and `cfg` (a config already built over such trees) is given."""
    if (trees is None) == (cfg is None):
        raise TypeError("run_batch takes exactly one of trees= and cfg=")
    if trees is not None:
        if paths is None or state is None:
            raise TypeError("run_batch with trees= takes paths= and state=")
        cfg = build_author_config(paths, state=state, trees=trees, box=box, batch=batch)
    assert cfg is not None  # narrowed for mypy: exactly one of the two was given
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def _gate_family(entry: dict) -> tuple[str, dict] | None:
    """The family partition inside `_gate_findings`.

    `None` admits the row for authoring; otherwise `("held", row)` with the reason on the row.

    The judge queues a family row only for an investigator finding of a measured, unanimous
    world (#1234 A7, A13), so the row's own fields are its ground truth: it must carry a
    non-empty `contrast_evidence`, a boolean `on_verdict_path` and a boolean
    `world_label_doubted`. A row carrying a retired name (`core/retired`: a pre-#1234 row's
    family word, or the retired finding type) or missing a new field is held naming it — never
    authored, never consumed (I10)."""
    from defender.learning.core.retired import retired_row_names

    retired = retired_row_names(entry)
    if retired:
        rec = dict(entry)
        rec["held_reason"] = f"retired_name({', '.join(retired)})"
        return "held", rec
    contrast = entry.get("contrast_evidence")
    missing = [key for key, ok in (
        ("contrast_evidence", isinstance(contrast, list) and bool(contrast)),
        ("on_verdict_path", isinstance(entry.get("on_verdict_path"), bool)),
        ("world_label_doubted", isinstance(entry.get("world_label_doubted"), bool))) if not ok]
    if missing:
        rec = dict(entry)
        rec["held_reason"] = f"missing_field({', '.join(missing)})"
        return "held", rec
    return None


def _gate_findings(
    batch: list[dict], cfg: AuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """The findings channel's pre-author policy: idempotency against the corpus, then the
    family partition. A row whose `direction` is not `family` — a per-case row from before
    #1234, or one with no direction — is held naming it: nothing left can author it (#1166),
    and a raise here would send the whole tick's batch to stuck.

    An empty batch returns without reading the corpus: `existing_finding_ids` is the most
    expensive non-agent step, and `_tick` runs for all-unreadable queues just to rotate."""
    if not batch:
        return [], [], []
    from defender.learning.judge.run import DIRECTION_FAMILY, SUBJECT_WORLD

    existing_ids = existing_finding_ids(cfg)
    held: list[dict] = []
    consumed_idempotent: list[dict] = []
    for entry in batch:
        # A world row belongs on the questioner channel; refuse it loudly (a hold would look
        # like an ordinary un-authorable finding) so it can't become a defender lesson. Both
        # fields are checked: `subject` is the appender's primary screen, and
        # `{subject: world, direction: family}` must not slip through.
        if SUBJECT_WORLD in (entry.get("direction"), entry.get("subject")):
            raise ValueError(
                f"a {SUBJECT_WORLD!r}-subject row (finding_id={entry.get('finding_id')!r}) "
                "reached the defender curator's gate — it belongs on the questioner channel")
        fid = entry["finding_id"]
        if fid in existing_ids:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_idempotent.append(rec)
            continue
        direction = entry.get("direction")
        if direction != DIRECTION_FAMILY:
            rec = dict(entry)
            rec["held_reason"] = f"retired_direction({direction!r})"
            held.append(rec)
            continue
        # The appender must refuse a row lacking `run_id`; indexing it here (value unused)
        # fails loudly on one that slipped through rather than routing it silently.
        entry["run_id"]  # noqa: B018 — see comment above
        routed = _gate_family(entry)
        if routed is not None:
            kind, rec = routed
            (consumed_idempotent if kind == "consumed" else held).append(rec)
    gated = {h["finding_id"] for h in held} | {c["finding_id"] for c in consumed_idempotent}
    return held, consumed_idempotent, [f for f in batch if f["finding_id"] not in gated]


def main(argv: list[str]) -> int:
    import argparse
    from defender.learning.core.cli import command_line_paths

    from defender.learning.core.cli import _run_stage
    from defender.learning.core.drains import author_drain

    parser = argparse.ArgumentParser(description="Curate this tenant's queued findings")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args(argv[1:])
    paths = command_line_paths(parser, args.tenant)
    # A curator commits only into a batch's draft of the tenant's repo, and it has no batch of
    # its own: both corpus curators run as claims of the author lane's one tick (batch, box,
    # branch, PR lease). So this command is that tick, `loop.py --author-drain --tenant T`
    # (#1108 P4) — never a curator over the checkout, which holds no corpus.
    return _run_stage(lambda: author_drain(paths))


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
