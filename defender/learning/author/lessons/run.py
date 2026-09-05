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
from defender._vocab import normalized_judge_outcome
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
    provenance_field,
)




AuthorError = _shared.AuthorError

# The ONE spelling of this drain's log prefix: `cfg.log_prefix` and `_log` below both come
# from it, so the envelope, the curator stage and this module cannot drift onto two.
_LOG_PREFIX = "author"


@dataclass(frozen=True, kw_only=True)
class AuthorConfig(CorpusAuthorConfig):
    """The lessons curator's drain config: the shared corpus-author core plus the three
    fields only this drain has — the held report, the manifest seed the lessons prompt
    takes, and the env-backed model knobs.

    A prohibition against carrying lock topology as config once stood here; #719 reversed
    it — the roles are fields on `QueueChannel`."""

    held_report: Path
    manifest_seed: str | None = None
    # default_factory, not a plain default: these are env-backed knobs and a plain default
    # would freeze at import. A caller that overrides them still wins.
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
        # Channel-scoped, like the graveyard and the stuck-row record beside it: this
        # report is lessons-local, so it must not sit on a name an observation channel
        # would look like it shares.
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
    # The same spelling the drain's attribution gate reads: a file attributable there but
    # invisible here is authored again on every following tick.
    field = provenance_field(cfg.channel.id_key)
    for lesson in iter_lessons(
        cfg.corpus_dir, warn_label=lambda p: f"finding-id pre-flight: {p.name}"
    ):
        sids = lesson.fm.get(field) or []
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
            # J12: a family row's id never enters the queued set the model may forward_check —
            # its ground truth is the family record, not a source_refs.yaml under runs_dir.
            queued_ids=forward_checkable_ids(findings),
        ),
        log=_log,
    )



def forward_checkable_ids(findings: list[dict]) -> frozenset[str]:
    """The run ids the model may name in a `forward_check` call for this batch.

    J12: a family row's id never enters it — its ground truth is the family record, not a
    `source_refs.yaml` under the runs dir — so the model-facing tool answers "not in this
    batch's queued rows" for it rather than reaching the check at all. A NAMED function rather
    than a comprehension inlined into the config, because it is the route the exemption IS: a
    test can drive this and fail when the filter is removed, which a test that re-derives the
    same comprehension against its own data cannot."""
    from defender.learning.author.verify_forward.checks import skips_forward_check

    return frozenset(
        str(f["run_id"]) for f in findings
        if f.get("run_id") and not skips_forward_check(f)
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
    """Run after BOTH the corpus commit and the queue rotation — the only seam that
    observes the tick's closing edge, which is why it is shared config rather than
    lessons-local decoration, even though only this direction populates it.

    UNCONDITIONAL: the rows a tick held or skipped are the same rows whether or not other
    rows committed, and the operator's one written trace of a `forward_bad` verdict must
    not depend on how the tick's other rows went — least of all in a MIXED batch, the shape
    a forward-check hold is most interesting in."""
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
    """The findings direction's entry point. The batch body is `drain.run_batch`."""
    if cfg is None:
        cfg = build_author_config(paths, box=box)
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def _has_confident_ground_truth(direction: str, disposition: str | None) -> bool:
    if direction == "benign":
        return disposition == "malicious"
    return disposition == "benign"


#: D6/O2: `judge_outcome` values that are SKIPPED (consumed, never authored) rather than held.
#: `survived` is the one word `_gate_family` admits for authoring; `discard` and
#: `corpus-contradiction` never reach the queue at all (M5 refuses them at the appender), so
#: this partition never sees them.
_FAMILY_SKIP_OUTCOMES = frozenset({"caught", "undecidable"})


def _gate_family(entry: dict) -> dict | None:
    """D6/O2: the family partition inside `_gate_findings`'s one gate.

    A `direction: family` row's ground truth is `disposition_declared` on the family record —
    already resolved into `judge_outcome` by the judge's own mechanical pass — so this
    partition never reads `source_refs.yaml` at all. `survived` is admitted for authoring
    (returns `None`, and the caller lets the row fall through to `to_author` the same way an
    admitted adversarial row does); `caught`/`undecidable` are consumed WITHOUT authoring,
    terminally rather than held — a word that will never change must not sit in the queue
    forever (a hold is forever; a skip is terminal, and the two read differently in the
    drain's own report)."""
    # THROUGH THE OWNER'S NORMALIZER, not a bare `in`. The appender validates `judge_outcome`
    # with `normalized_judge_outcome`, which casefolds and trims — so `Caught` passes validation,
    # is written to the queue verbatim, and a raw membership test here does not recognise it.
    # A family the judge scored as CAUGHT was then authored as though it had survived. This is
    # `lint-vocabulary`'s own shape: one parser, two interpreters, disagreeing on one string.
    if normalized_judge_outcome(entry.get("judge_outcome")) in _FAMILY_SKIP_OUTCOMES:
        rec = dict(entry)
        rec["consumed_category"] = "consumed_family_skip"
        return rec
    return None


def _gate_findings(
    batch: list[dict], cfg: AuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """The findings direction's pre-author policy: idempotency against the corpus, then EITHER
    the family partition (D6) for a `direction: family` row OR the `source_refs.yaml` ground
    truth an adversarial/benign finding needs before it can become a lesson.

    `to_author` is derived HERE by subtraction, so both directions return the same 3-tuple
    even though the policies are not one policy parameterised."""
    # THE SAME PREDICATE THE ROUTE USES, not a second spelling of it. `skips_forward_check`
    # already decides which rows are family rows for `queued_ids` above; re-deriving
    # `entry["direction"] == "family"` here gives one rule two homes, and the duplicate-helper
    # gate keys on the symbol NAME, so it is structurally blind to the copy. Widening the family
    # route later would otherwise update one site and leave the other routing as it always did.
    from defender.learning.author.verify_forward.checks import skips_forward_check

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
        if skips_forward_check(entry):
            # P6's blast radius still applies to a malformed family row: the WRITER is what is
            # supposed to refuse a row lacking `run_id` before it ever reaches this gate
            # (J12), not this partition — indexing it here (never using the value) is what
            # keeps that property true rather than silently routing a row the appender should
            # have refused.
            entry["run_id"]  # noqa: B018 — see comment above
            skipped = _gate_family(entry)
            if skipped is not None:
                consumed_idempotent.append(skipped)
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
