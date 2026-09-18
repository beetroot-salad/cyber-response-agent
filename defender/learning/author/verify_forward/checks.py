from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from uuid import uuid4
from defender._untrusted import wrap
from defender.learning.author.verify_forward import forward
from defender.learning.author.verify_forward.shared import (
    parse_verdict,
    reasoning_text,
)
from defender.learning.core import config
from defender.learning.core.config import FatalConfigError
from defender.learning._prompt import stage_user_message


@dataclass(frozen=True)
class CheckContext:

    check: ForwardCheck
    lesson_path: Path
    lesson_text: str
    source_id: str
    direction: str
    runs_dir: Path
    pending: Path
    corpus_dir: Path
    repo_root: Path
    check_index: int
    run_verify: Callable[..., str]


@dataclass(frozen=True)
class ForwardCheck:

    error_prefix: str
    prompt_path: Path | None
    #: `(verdict, reasoning)` — verdict is GOOD or BAD; EXEMPT is the drain's own, via
    #: `cfg.exempt(row)`, never the check's (M2's own data-model note).
    run: Callable[[CheckContext], tuple[str, str]]


def _verify(ctx: CheckContext, user: str, source_run_dir: Path, *, salt: str) -> tuple[str, str]:
    stem = ctx.lesson_path.stem
    prefix = ctx.check.error_prefix
    # `_verify` is the MODEL-BACKED lane, so the check it runs for must carry a prompt.
    # A ForwardCheck may carry `prompt_path=None` — a check whose verdict is mechanical
    # (pure retrieval) — it never reaches here. Checked rather than asserted: `StageWiring`
    # takes a non-optional `Path`, and an assert would be stripped under `python -O`.
    # `FatalConfigError`, not a bare raise: this is a fatal CONFIGURATION fault (O10, "a
    # check with no prompt"), never a per-finding verdict — the drain's per-pair retry
    # handler must let it propagate rather than degrade it to BAD.
    prompt_path = ctx.check.prompt_path
    if prompt_path is None:
        raise FatalConfigError(
            f"{prefix}: this forward-check carries no verifier prompt, so it cannot run the "
            "model-backed verify lane"
        )
    raw = ctx.run_verify(
        config.StageWiring(
            prompt_path=prompt_path,
            model=config.verifier_model(),
            effort=config.verifier_effort(),
            trace_name=f"{prefix}.{stem}.{ctx.check_index}.trace.jsonl",
            label=f"{prefix}:{stem}",
        ),
        user=user,
        source_run_dir=source_run_dir,
        defender_dir=ctx.repo_root / "defender",
        wall_clock_timeout=config.verifier_timeout(),
        salt=salt,
    )
    return parse_verdict(raw, error_prefix=prefix), reasoning_text(raw)


def _run_findings(ctx: CheckContext, *, salt: str | None = None) -> tuple[str, str]:
    # #767 D5: the cited-covering-policy prompt section is deleted along with the
    # resolution-decoding lane it read through — `forward.load_cited_policy` keyed on a
    # cross-run citation menu no non-test code writes (c5), so this section was always the
    # same neutral placeholder in production. Removing it closes the second model-facing read
    # path structurally, rather than leaving a prompt section that never varies.
    stage_salt = salt if salt is not None else uuid4().hex
    transcript, recorded = forward.load_run_context(ctx.source_id, runs_dir=ctx.runs_dir)
    disposition = forward.expected_disposition(ctx.direction, recorded)
    user = stage_user_message(
        stage_salt,
        wrap(transcript, "case_transcript", stage_salt),
        wrap(ctx.lesson_text, "candidate_lesson", stage_salt),
        wrap(disposition, "case_ground_truth_disposition", stage_salt),
    )
    return _verify(ctx, user, ctx.runs_dir / ctx.source_id, salt=stage_salt)






def skips_forward_check(row: dict) -> bool:
    """J12: a `direction: family` row is exempt from the forward check.

    Its ground truth is `disposition_declared` on the family record, not a `source_refs.yaml`
    it does not have — `forward.expected_disposition`/`load_run_context` resolve a row's
    `run_id` under the RUNS dir, and a family row's `run_id` is an episode id under the
    EPISODES root, a different tree entirely. Read by `learning.author.lessons.run.
    invoke_agent` when it builds the batch's `queued_ids`: a family row's id never enters that
    set, so the model-facing `forward_check` tool call for it returns "not in this batch's
    queued rows" (`tool._prepare`) rather than reaching `_run_findings` at all — the exemption
    is a ROUTE, and the model-facing `direction` literal stays `Literal["adversarial",
    "benign"]`, unwidened."""
    return row.get("direction") == "family"


FINDINGS_CHECK = ForwardCheck(
    error_prefix="verify_forward",
    prompt_path=forward.PROMPT_PATH,
    run=_run_findings,
)


