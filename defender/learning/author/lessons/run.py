#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
import uuid
from dataclasses import field
from defender._model import model
from pathlib import Path

from collections.abc import Callable, Sequence
from typing import Any

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender._paths import PATHS
from defender.learning.author import drain
from defender.learning.author import shared as _shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core.config import (
    LoopPaths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    author_timeout as _author_timeout,
)
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.core.state import FINDINGS
from defender.knowledge import LESSONS




AuthorError = _shared.AuthorError

# This channel's name: `cfg.log_prefix`, the envelope and the drain's per-channel logger
# (`drain.channel_logger`) all derive from it.
_LOG_PREFIX = "author"


@model(frozen=True, kw_only=True)
class AuthorConfig(CorpusAuthorConfig):
    """The lessons curator's drain config: the shared corpus-author core plus the held report,
    the manifest seed the lessons prompt takes, and the env-backed model knobs."""

    manifest_seed: str | None = None
    # default_factory, not a plain default: these are env-backed knobs and a plain default
    # would freeze at import. A caller that overrides them still wins.
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_author_config(  # noqa: PLR0913 — the claim's seams: its trees, batch, box, feedback and model
    paths: LoopPaths, *, trees: DrainTrees,
    manifest_seed: str | None = None, box: Any = None, batch: Any = None,
    feedback: str | None = None, make_model: Callable[..., Any] | None = None,
) -> AuthorConfig:
    """This channel's config, reading and writing its corpus through `trees`, the lane's open
    trees (`open_drain_trees`), which must hold the corpus itself (`shared.lane_corpus`, else
    `FatalConfigError`): `batch`'s draft `agent/lessons`, or — with no batch — the scene's
    `paths.lessons_dir`. `paths` keeps the product checkout. `feedback` is a replacement's framed
    review text (#1278 H13), `make_model` the spawn's model seam. The config must not outlive
    `trees`."""
    from defender.learning.author import shared as _shared

    root, corpus_dir, corpus_rel = _shared.lane_corpus_dir(paths, batch, LESSONS)
    return AuthorConfig(
        repo_root=root,
        corpus_dir=corpus_dir,
        corpus=_shared.lane_corpus(trees, corpus_dir),
        tree_for=trees.tree_for,
        corpus_rel=corpus_rel,
        batch=batch,
        channel=FINDINGS,
        log_prefix=_LOG_PREFIX,
        # The prompt is product code: the running checkout's, as the lead lane's (`LEARNING_DIR`).
        author_prompt=PATHS.learning_dir / "author" / "lessons" / "prompt.md",
        invoke_agent=invoke_agent,
        gate=_gate_findings,
        buckets=FINDINGS_BUCKETS,
        noun="findings",
        manifest_seed=manifest_seed,
        box=box,
        feedback=feedback,
        make_model=make_model,
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
        salt=salt, feedback=cfg.feedback,
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
            learning_run_dir=curator_engine.call_folder_of(cfg, "lessons"),
            user=build_user_prompt(findings, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        log=_logger,
        run_author=curator_engine.curator_runner(cfg.make_model),
    )


FINDINGS_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
)


_logger = logging.getLogger(__name__)


def run_batch(  # noqa: PLR0913 — the drain's work step's call shape: the claim, its trees and its seams
    *,
    paths: LoopPaths | None = None,
    trees: DrainTrees | None = None,
    cfg: AuthorConfig | None = None,
    box: Any = None,
    batch: Any = None,
    items: Sequence[drain.Item] = (),
    outcomes: dict[tuple[str, str], Any] | None = None,
    feedback: str | None = None,
    make_model: Callable[..., Any] | None = None,
) -> int:
    """This channel's entry point over a learning store claim (#1278 D1); the claim body is
    `drain.run_batch`, one claim of `batch`. `items` are the claim's findings, `outcomes` the map
    their fates are written to, `feedback` a replacement's framed review text. Exactly one of
    `trees` (the lane's open trees: the drain's work step opens them over the batch's draft, #1134)
    and `cfg` (a config already built over such trees) is given."""
    if (trees is None) == (cfg is None):
        raise TypeError("run_batch takes exactly one of trees= and cfg=")
    if trees is not None:
        if paths is None:
            raise TypeError("run_batch with trees= takes paths=")
        cfg = build_author_config(paths, trees=trees, box=box, batch=batch, feedback=feedback,
                                  make_model=make_model)
    assert cfg is not None  # narrowed for mypy: exactly one of the two was given
    return drain.run_batch(cfg=cfg, items=items, outcomes=outcomes if outcomes is not None else {}, box=box)


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

    from defender.learning.core import cli

    parser = argparse.ArgumentParser(description="Curate this tenant's queued findings")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args(argv[1:])
    # A curator commits only into a batch's draft of the tenant's repo, and it has no batch of
    # its own: both corpus curators run as claims of the author lane's one tick (batch, box,
    # branch, PR lease). So this command is that tick, `loop.py --author-drain --tenant T`
    # (#1108 P4) — never a curator over the checkout, which holds no corpus. It goes through the
    # drain entry itself, so the tenant's host lock and admission apply as they do to `loop.py`
    # (#1214 P3).
    return cli.main(["loop.py", "--author-drain", "--tenant", args.tenant])


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
