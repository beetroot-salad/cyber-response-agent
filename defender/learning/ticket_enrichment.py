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

from pathlib import Path

import yaml

from defender.learning._loop_directions import ADVERSARIAL
from defender.learning._loop_config import LoopError, make_logger
from defender.learning._loop_validate import _outcome_keyword
from defender.scripts.case_history import case_ticket
from defender.scripts.case_history.ticket_writer import (
    annotate_case_ticket,
    enrich_case_resolution,
)


_log = make_logger("ticket_enrichment")


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


def _read_resolution_method(learning_run_dir: Path) -> str | None:
    """The adversarial judge's `resolution_method` for this benign case, or None if
    absent / unusable (issue #338). Optional field — the judge emits it only on a
    benign disposition, where it lifts the grounded predicates + policy/authority that
    made the disposition stick — so absence is normal and quiet (not a WARN)."""
    verdict = learning_run_dir / ADVERSARIAL.judge_name
    if not verdict.is_file():
        return None
    try:
        doc = yaml.safe_load(verdict.read_text())
    except (yaml.YAMLError, OSError) as e:
        _log(f"unusable adversarial verdict for resolution-method ({e}); skipping")
        return None
    if not isinstance(doc, dict):
        return None
    method = doc.get("resolution_method")
    if isinstance(method, str) and method.strip():
        return method.strip()
    if method is not None:
        _log(f"resolution_method is not a non-empty string ({type(method).__name__}); "
             "skipping resolution-method enrichment")
    return None


def enrich_case_ticket(
    run_dir: Path,
    learning_run_dir: Path,
    *,
    annotate_fn=annotate_case_ticket,
    enrich_fn=enrich_case_resolution,
) -> None:
    """Stamp the case-history ticket from the adversarial verdict (issue #317 + #338).
    Caller gates on a benign disposition + a successful adversarial leg; this reads the
    verdict and delegates the (idempotent, non-fatal) writes to the writer. The ticket
    key is the run-dir basename — the identity the runtime keyed the create under
    (`open_case_ticket`).

    Two stamps, both idempotent and non-fatal: the seed-eligibility flag from the
    `outcome` (#317), and — when the judge emitted one AND the outcome is seed-eligible
    — the grounded resolution-method inside the existing `resolution` (#338), the policy
    conditions a future benign judge confirms a cited case against. The resolution-method
    rides the SAME polarity as the seed flag, so the store never carries a covering
    policy on a case the probe did not confirm benign (e.g. a `survived` flagged FN)."""
    outcome = _read_adversarial_outcome(learning_run_dir)
    if outcome is None:
        return
    annotate_fn(run_dir.name, outcome)
    method = _read_resolution_method(learning_run_dir)
    if method and case_ticket.outcome_seeds_eligible(outcome):
        enrich_fn(run_dir.name, method)
