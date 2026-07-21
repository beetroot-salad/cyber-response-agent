from __future__ import annotations

from pathlib import Path

import yaml

from defender._yaml import safe_load
from defender.learning.core.directions import ADVERSARIAL
from defender.learning.core.config import RunUnprocessable, make_logger
from defender.learning.core.validate import _outcome_keyword
from defender.scripts.case_history import case_ticket
from defender.scripts.case_history.ticket_writer import (
    annotate_case_ticket,
    enrich_case_resolution,
)


_log = make_logger("ticket_enrichment")


def _read_adversarial_outcome(learning_run_dir: Path) -> str | None:
    verdict = learning_run_dir / ADVERSARIAL.judge_name
    if not verdict.is_file():
        _log(f"no {ADVERSARIAL.judge_name} in {learning_run_dir}; skipping enrichment")
        return None
    try:
        doc = safe_load(verdict.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            _log(f"adversarial verdict is not a mapping ({type(doc).__name__}); "
                 "skipping enrichment")
            return None
        return _outcome_keyword(doc.get("outcome"))
    except (yaml.YAMLError, OSError, RunUnprocessable) as e:
        _log(f"unusable adversarial verdict ({e}); skipping enrichment")
        return None


def _read_resolution_method(learning_run_dir: Path) -> str | None:
    verdict = learning_run_dir / ADVERSARIAL.judge_name
    if not verdict.is_file():
        return None
    try:
        doc = safe_load(verdict.read_text(encoding="utf-8"))
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
    outcome = _read_adversarial_outcome(learning_run_dir)
    if outcome is None:
        return
    annotate_fn(run_dir.name, outcome)
    method = _read_resolution_method(learning_run_dir)
    if method and case_ticket.outcome_seeds_eligible(outcome):
        enrich_fn(run_dir.name, method)
