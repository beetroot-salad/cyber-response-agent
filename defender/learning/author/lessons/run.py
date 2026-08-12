#!/usr/bin/env python3
from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import drain
from defender.learning.author import shared as _shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender._yaml import safe_load
from defender._corpus import iter_lessons
from defender.learning.core.config import (
    DEFAULT_PATHS,
    LoopPaths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    repo_lock_wait_seconds,
    author_max_attempts,
    author_timeout as _author_timeout,
    make_logger,
    now_iso,
)




AuthorError = _shared.AuthorError

# The ONE spelling of this drain's log prefix. `build_author_config` puts it on
# `cfg.log_prefix` (the field the shared corpus-author base requires) and `_log` below is
# built from it, so the envelope, the curator stage and every message in this module cannot
# drift onto two prefixes.
_LOG_PREFIX = "author"


@dataclass(frozen=True, kw_only=True)
class AuthorConfig(CorpusAuthorConfig):
    """The lessons curator's drain config: the shared corpus-author core (#713) plus the
    three fields only this drain has.

    REVERSED BY #719, which is why this docstring no longer names two locks as a reason
    NOT to fold: the read-side lock and the drain-wide lock are now `channel.append_lock`
    and `channel.drain_lock`, declared on the channel and taken by the shared drain body.
    What is left here is genuinely findings-only — the held report, and the manifest seed
    the lessons prompt takes."""

    held_report: Path
    manifest_seed: str | None = None
    # default_factory, not a plain default: these are env-backed knobs and a plain
    # default would freeze at import (#717). A caller that overrides them still wins.
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_author_config(
    paths: LoopPaths = DEFAULT_PATHS, *, manifest_seed: str | None = None, box: Any = None,
) -> AuthorConfig:
    return AuthorConfig(
        repo_root=paths.repo_root,
        corpus_dir=paths.lessons_dir,
        corpus_dir_rel=paths.lessons_dir_rel,
        runs_dir=paths.runs_dir,
        pending_dir=paths.pending_dir,
        channel=paths.findings,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=repo_lock_wait_seconds(),
        # Channel-scoped, like the graveyard and the stuck-row record beside it: D7
        # keeps this report lessons-local, so it must not sit on a name an
        # observation channel would look like it shares (#719).
        held_report=paths.pending_dir / "findings.held_report.log",
        log_prefix=_LOG_PREFIX,
        author_prompt=paths.learning_dir / "author" / "lessons" / "prompt.md",
        invoke_agent=invoke_agent,
        gate=_gate_findings,
        buckets=FINDINGS_BUCKETS,
        commit_fn=commit_lessons,
        noun="findings",
        max_attempts=author_max_attempts(),
        post_rotate=_write_held_report_after_rotate,
        manifest_seed=manifest_seed,
        box=box,
    )




def disposition_for(cfg: AuthorConfig, run_id: str) -> str | None:
    refs = cfg.runs_dir / run_id / "source_refs.yaml"
    if not refs.is_file():
        return None
    try:
        doc = safe_load(refs.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    val = doc.get("normalized_disposition")
    return val if isinstance(val, str) else None


def existing_finding_ids(cfg: AuthorConfig) -> set[str]:
    ids: set[str] = set()
    for lesson in iter_lessons(
        cfg.corpus_dir, warn_label=lambda p: f"finding-id pre-flight: {p.name}"
    ):
        sids = lesson.fm.get("source_finding_ids") or []
        if isinstance(sids, list):
            ids.update(sid for sid in sids if isinstance(sid, str))
    return ids




def build_user_prompt(
    findings: list[dict], batch_id: str, cfg: AuthorConfig, *, salt: str | None = None
) -> str:
    return _shared.build_curator_user_prompt(
        findings, batch_id, corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_dir_rel, label="findings",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: AuthorConfig) -> dict:
    from defender.learning.author import curator_engine
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        wiring=StageWiring.for_batch(
            cfg.author_prompt, cfg.author_model, cfg.author_effort,
            batch_id=batch_id, label="curator",
        ),
        ctx=StageContext(
            learning_run_dir=cfg.pending_dir,
            user=build_user_prompt(findings, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        cfg=curator_engine.ForwardCheckConfig(
            check=FINDINGS_CHECK,
            runs_dir=cfg.runs_dir,
            pending=cfg.channel.file,
            queued_ids=frozenset(
                str(f["run_id"]) for f in findings if f.get("run_id")
            ),
        ),
        log=_log,
    )



def _forward_bad_reason(reason: str) -> str:
    """The held-reason prefix the forward-check bucket writes. A named function rather
    than an inline lambda so no module-level assignment carries an interpolated string."""
    return f"forward_bad: {reason}"


FINDINGS_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
    # The one genuinely direction-specific bucket: a lesson the forward check says would
    # flip a correctly-resolved case is HELD, not consumed, and its reason is prefixed so
    # an operator can tell it from an ordinary hold.
    BucketSpec(
        name="held_forward_bad", disposition="held", reason_field="held_reason",
        formatter=_forward_bad_reason,
    ),
)


def commit_lessons(message: str, cfg: AuthorConfig) -> str | None:
    return _shared.commit_corpus(cfg.repo_root, cfg.corpus_dir, message)


def write_held_report(
    cfg: AuthorConfig, *, batch_id: str, held_forward_bad: list[dict], skipped: list[dict]
) -> None:
    if not held_forward_bad and not skipped:
        return
    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    line = (
        f"{now_iso()} batch={batch_id} "
        f"forward_bad={len(held_forward_bad)} "
        f"skipped={len(skipped)} "
        f"forward_bad_ids={[h.get('finding_id') for h in held_forward_bad]} "
        f"skipped_ids={[s.get('finding_id') for s in skipped]}\n"
    )
    with cfg.held_report.open("a", encoding="utf-8") as fh:
        fh.write(line)




# This drain's one diagnostic logger, built from the single prefix anchor at the top.
_log = make_logger(_LOG_PREFIX)


def _write_held_report_after_rotate(outcome, cfg: AuthorConfig) -> None:
    """D7's hook, run after BOTH the corpus commit and the queue rotation.

    It is the only seam that observes the tick's closing edge, which is what makes it
    shared config rather than lessons-local decoration — even though only this direction
    populates it.

    UNCONDITIONAL AS OF #852 (F-02). It used to return early on a batch that committed,
    which silenced the report on exactly the batch shape a forward-check hold is most
    interesting in: a MIXED batch, where the held lesson's file sits in a corpus that is
    being committed for its batch-mates. The rows a tick held or skipped are the same rows
    whether or not other rows committed, and the operator's one written trace of a
    `forward_bad` verdict should not depend on how the tick's other rows went."""
    write_held_report(
        cfg,
        batch_id=outcome.batch_id,
        held_forward_bad=outcome.held.get("held_forward_bad", []),
        skipped=outcome.consumed.get("consumed_skip", []),
    )


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths = DEFAULT_PATHS,
    cfg: AuthorConfig | None = None,
    box: Any = None,
) -> int:
    """The findings direction's entry point. The batch body is `drain.run_batch` (#719)."""
    if cfg is None:
        cfg = build_author_config(paths, box=box)
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def _has_confident_ground_truth(direction: str, disposition: str | None) -> bool:
    if direction == "benign":
        return disposition == "malicious"
    return disposition == "benign"


def _gate_findings(
    batch: list[dict], cfg: AuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """The findings direction's pre-author policy: idempotency against the corpus, then
    the `source_refs.yaml` ground truth a finding needs before it can become a lesson.

    `to_author` is derived HERE, by subtraction, rather than by the caller (#719) — the
    shape is now the same 3-tuple both directions return, even though the policies are
    not the same policy parameterised."""
    existing_ids = existing_finding_ids(cfg)
    held: list[dict] = []
    consumed_idempotent: list[dict] = []
    for entry in batch:
        fid = entry["finding_id"]
        if fid in existing_ids:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_idempotent.append(rec)
            continue
        disp = disposition_for(cfg, entry["run_id"])
        direction = entry["direction"]
        if not _has_confident_ground_truth(direction, disp):
            rec = dict(entry)
            rec["held_reason"] = (
                f"no_ground_truth(direction={direction!r}, disposition={disp!r})"
            )
            held.append(rec)
    gated = {h["finding_id"] for h in held} | {c["finding_id"] for c in consumed_idempotent}
    return held, consumed_idempotent, [f for f in batch if f["finding_id"] not in gated]


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
