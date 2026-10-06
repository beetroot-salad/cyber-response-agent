#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
import uuid
from dataclasses import field
from defender._model import model
from pathlib import Path

from defender._run_paths import RunPaths
from typing import Any

import yaml

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import drain
from defender.learning.author import shared as _shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender._vocab import normalized_judge_outcome
from defender._yaml import safe_load
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    LoopPaths,
    loop_paths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    repo_lock_wait_seconds,
    author_max_attempts,
    author_timeout as _author_timeout,
)
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.learning.core.state import FINDINGS, LearningState




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
    manifest_seed: str | None = None, box: Any = None,
) -> AuthorConfig:
    """This channel's config over `paths`, reading and writing its corpus through `trees`, the
    lane's open trees (`open_drain_trees`): they must hold `paths.lessons_dir` itself
    (`shared.lane_corpus`, else `FatalConfigError`). The config must not outlive `trees`."""
    from defender.learning.author import shared as _shared
    from defender.learning.author.verify_forward.checks import (
        FINDINGS_CHECK,
        skips_forward_check,
    )

    return AuthorConfig(
        repo_root=paths.repo_root,
        corpus_dir=paths.lessons_dir,
        corpus=_shared.lane_corpus(trees, paths.lessons_dir),
        tree_for=trees.tree_for,
        corpus_dir_rel=paths.lessons_dir_rel,
        runs_dir=paths.runs_dir,
        state=state,
        channel=FINDINGS,
        repo_lock_wait_seconds=repo_lock_wait_seconds(),
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
        # The drain runs this check itself; the curator never does.
        forward_check=FINDINGS_CHECK,
        exempt=skips_forward_check,
        repair_prompt=paths.learning_dir / "author" / "lessons" / "repair.md",
        invoke_repair=_shared.invoke_repair,
    )




def disposition_for(cfg: AuthorConfig, run_id: str) -> str | None:
    refs = RunPaths(cfg.runs_dir / run_id).source_refs
    if not refs.is_file():
        return None
    try:
        doc = safe_load(refs.read_text(encoding="utf-8"))  # lint-whole-read: ok — source_refs.yaml: no host writer, only a box process can write it in the rw run dir; bounded at the writer by the box fsize limit (a 64 MiB YAML parse in the author drain is a separate cost risk)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    val = doc.get("normalized_disposition")
    return val if isinstance(val, str) else None


def existing_finding_ids(cfg: AuthorConfig) -> set[str]:
    """This channel's name for `shared.existing_finding_ids`."""
    return _shared.existing_finding_ids(cfg)




def build_user_prompt(
    findings: list[dict], batch_id: str, cfg: AuthorConfig, *, salt: str | None = None
) -> str:
    return _shared.build_curator_user_prompt(
        findings, batch_id, corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_dir_rel, label="findings",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: AuthorConfig) -> dict:
    """Spawn the curator to author the batch and self-report. It runs no forward check; the
    drain does that before committing."""
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


def commit_lessons(message: str, cfg: AuthorConfig) -> str | None:
    return _shared.commit_corpus(cfg.repo_root, cfg.corpus_dir, message)


def write_held_report(
    cfg: AuthorConfig,
    *,
    batch_id: str,
    forward_bad_terminal: list[dict],
    deferred: list[dict],
    skipped: list[dict],
    gate_held: list[dict],
) -> None:
    """The lessons channel's four decline reasons, as the labels its report line carries.

    `shared.write_disposition_report` composes the line and derives the `<label>_ids` keys;
    this function picks which labels the lessons channel reports. Each implies a different
    recovery:

    - `forward_bad_terminal`: the lesson stayed BAD after the one repair attempt; consumed,
      with its full account in the gap ledger.
    - `deferred`: couldn't land through no fault of its own; bounded and still queued.
    - `skipped`: terminal.
    - `gate_held`: never reached the agent; held every tick until a human moves it.

    Nothing is written when the tick declined nothing."""
    _shared.write_disposition_report(
        cfg.state, cfg.channel, batch_id=batch_id,
        groups={
            "forward_bad_terminal": forward_bad_terminal, "deferred": deferred,
            "skipped": skipped, "gate_held": gate_held,
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
        forward_bad_terminal=outcome.held.get("forward_bad_terminal", []),
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
) -> int:
    """This channel's entry point; the batch body is `drain.run_batch`. Exactly one of `trees`
    (the lane's open trees: the drain's work step and `main` open them for their label, #1134)
    and `cfg` (a config already built over such trees) is given."""
    if (trees is None) == (cfg is None):
        raise TypeError("run_batch takes exactly one of trees= and cfg=")
    if trees is not None:
        if paths is None or state is None:
            raise TypeError("run_batch with trees= takes paths= and state=")
        cfg = build_author_config(paths, state=state, trees=trees, box=box)
    assert cfg is not None  # narrowed for mypy: exactly one of the two was given
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def _has_confident_ground_truth(direction: str, disposition: str | None) -> bool:
    if direction == "benign":
        return disposition == "malicious"
    return disposition == "benign"


#: The one `judge_outcome` admitted for authoring. An allowlist, so an absent, torn or
#: `discard` outcome from any producer on this shared queue is never authored as if the
#: family survived.
_FAMILY_AUTHOR_OUTCOME = "survived"
#: `judge_outcome` values skipped (consumed, never authored) rather than held. `discard` and
#: `corpus-contradiction` are refused by the judge's appender, so a row carrying one came from
#: an ungated producer and is held for a human.
_FAMILY_SKIP_OUTCOMES = frozenset({"caught", "undecidable"})


def _gate_family(entry: dict) -> tuple[str, dict] | None:
    """The family partition inside `_gate_findings`.

    `None` admits the row for authoring; otherwise `("consumed"|"held", row)` says which list
    the caller files it under.

    A family row's ground truth is already resolved into `judge_outcome` by the judge, so
    `source_refs.yaml` isn't read. `survived` is authored; `caught`/`undecidable` are consumed
    without authoring (an outcome that will never change must not be held forever); anything
    else is held with the unreadable value named on the row."""
    # Through the appender's normalizer (casefold and trim), so `Caught` — valid and written
    # verbatim — isn't mistaken for an unknown outcome.
    outcome = normalized_judge_outcome(entry.get("judge_outcome"))
    if outcome == _FAMILY_AUTHOR_OUTCOME:
        return None
    if outcome in _FAMILY_SKIP_OUTCOMES:
        rec = dict(entry)
        rec["consumed_category"] = "consumed_family_skip"
        return "consumed", rec
    rec = dict(entry)
    rec["held_reason"] = (
        f"no_family_ground_truth(judge_outcome={entry.get('judge_outcome')!r})")
    return "held", rec


def _gate_findings(
    batch: list[dict], cfg: AuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """The findings channel's pre-author policy: idempotency against the corpus, then either the
    family partition for a `direction: family` row or the `source_refs.yaml` ground truth an
    adversarial/benign finding needs before it can become a lesson.

    An empty batch returns without reading the corpus: `existing_finding_ids` is the most
    expensive non-agent step, and `_tick` runs for all-unreadable queues just to rotate."""
    if not batch:
        return [], [], []
    # The channel's `exempt` predicate, the same one the drain keys EXEMPT on, rather than
    # re-deriving `direction == "family"` here.
    from defender.learning.author.verify_forward.checks import skips_forward_check
    from defender.learning.judge.run import SUBJECT_WORLD

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
        if skips_forward_check(entry):
            # The appender must refuse a row lacking `run_id`; indexing it here (value unused)
            # fails loudly on one that slipped through rather than routing it silently.
            entry["run_id"]  # noqa: B018 — see comment above
            routed = _gate_family(entry)
            if routed is not None:
                kind, rec = routed
                (consumed_idempotent if kind == "consumed" else held).append(rec)
            continue
        run_id = entry.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            # No `run_id`, no ground truth to gate on; holding it forever would be silent. It
            # falls through to authoring, and the forward check turns the uncheckable pair into
            # a gap-ledgered BAD.
            continue
        disp = disposition_for(cfg, run_id)
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
    paths = loop_paths()
    with LearningState.open(paths) as state, open_drain_trees(
            paths, AUTHOR_DRAIN_LABEL) as trees:
        return run_batch(paths=paths, state=state, trees=trees)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
