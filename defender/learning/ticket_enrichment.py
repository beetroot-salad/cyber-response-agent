"""Offline ticket enrichment — stamp seed-eligibility onto the case-history store.

The runtime write path (issue #317, slice 1) closes a case-history ticket per
investigated alert but knows nothing of the *adversarial probe* — that verdict only
exists after the learning loop runs. This module is the join: for a benign-disposed
case, after its adversarial leg settles, it reads the probe's `outcome` from
`judge_findings.yaml` and stamps the ticket with a seed-eligibility flag, so the
benign seed sampler (`ticket_seeds.py`) can later filter to benign-and-survived cases.

Direction is one-way: this learning-side driver imports the case-history writer
(`defender.scripts.case_history`), never the reverse. The polarity (which outcomes
seed) lives in the mapper, not here — this module only locates the verdict and hands
the raw `outcome` token over. Non-fatal by construction: a missing/invalid verdict or
an unreachable store is a WARN, never an exception (it must not turn a clean learn
into a failed one — the orchestrator's leg-failure path is for the legs, not for this
post-step).
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from defender.learning._loop_directions import ADVERSARIAL
from defender.learning._loop_config import LoopError
from defender.learning._loop_validate import _outcome_keyword
from defender.scripts.case_history.ticket_writer import annotate_case_ticket


def _log(msg: str) -> None:
    print(f"[ticket_enrichment] {msg}", file=sys.stderr)


def _read_adversarial_outcome(learning_run_dir: Path) -> str | None:
    """The adversarial-probe `outcome` keyword for this case, or None if absent /
    unparseable. Reuses the loop's own tolerant outcome parser so the keyword set
    stays single-sourced with the judge validator."""
    verdict = learning_run_dir / ADVERSARIAL.judge_name
    if not verdict.is_file():
        _log(f"no {ADVERSARIAL.judge_name} in {learning_run_dir}; skipping enrichment")
        return None
    try:
        doc = yaml.safe_load(verdict.read_text())
        if not isinstance(doc, dict):
            _log(f"adversarial verdict is not a mapping ({type(doc).__name__}); "
                 "skipping enrichment")
            return None
        return _outcome_keyword(doc.get("outcome"))
    except (yaml.YAMLError, OSError, LoopError) as e:
        _log(f"unusable adversarial verdict ({e}); skipping enrichment")
        return None


def enrich_case_ticket(run_dir: Path, learning_run_dir: Path) -> None:
    """Stamp the case-history ticket's seed-eligibility flag from the adversarial
    verdict. Caller gates on a benign disposition + a successful adversarial leg; this
    reads the verdict and delegates the (idempotent, non-fatal) write to the writer.
    The ticket key is the run-dir basename — the identity the runtime keyed the
    create under (`open_case_ticket`)."""
    outcome = _read_adversarial_outcome(learning_run_dir)
    if outcome is None:
        return
    annotate_case_ticket(run_dir.name, outcome)
