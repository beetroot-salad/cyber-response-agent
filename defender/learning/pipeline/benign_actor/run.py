"""Benign actor stage — ops-teamer story generation (FP direction).

``invoke_actor_benign`` reconstructs the authorized operation from the alert + the
environment lessons it retrieves, optionally seeded with prior benign-and-survived
closed cases on the same signature. The mirror of ``malicious_actor`` for the
over-escalation hunt.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from defender.learning.core.config import (
    ACTOR_BENIGN_PROMPT,
    BENIGN_ACTOR_EFFORT,
    BENIGN_ACTOR_MODEL,
    BENIGN_ACTOR_SETTINGS,
    LESSONS_ENVIRONMENT_DIR,
)
from defender.learning.core.runner import _copy_transcript, _run_claude, _section
from defender.learning.tickets import ticket_seeds


def invoke_actor_benign(
    alert_path: Path,
    case_entities: str,
    alert_rule_key: str,
    learning_run_dir: Path,
) -> str:
    """Benign (ops-teamer) actor for the FP direction.

    Reconstructs the authorized operation from the alert + the environment lessons
    it retrieves via ``lessons_env_retrieve.py``, keyed by ``case_entities`` +
    ``alert_rule_key`` (both handed in so the actor uses the same deterministic
    anchor the observation + forward-check use).

    When the case-history store has them, an optional ``past_tickets`` seed menu —
    prior benign-and-survived closed cases on this signature — is injected as variance
    (the FP-direction analog of the adversarial actor's MITRE menu). Seeds are the
    actor's *proposal* of a covering operation; the benign judge re-confirms each
    against the actuals, so a contradicted seed just fails to survive. Sampled
    offline and non-fatal: an empty pool (cold start / store unreachable) yields no
    section and the actor grounds off the systems-of-record exactly as before.
    """
    alert_text = alert_path.read_text()
    user = (
        _section("alert", alert_text)
        + _section("alert_rule_id", alert_rule_key)
        + _section("case_entities", case_entities)
    )
    # case_id == the runtime run-dir basename == the learning run dir name == the
    # ticket key, so it's both the self-exclusion key and the reproducible sample seed.
    case_id = learning_run_dir.name
    seeds = ticket_seeds.sample_seeds(json.loads(alert_text), case_id, case_id)
    if seeds:
        menu_text = ticket_seeds.format_seeds(seeds)
        (learning_run_dir / "past_tickets.txt").write_text(menu_text + "\n")
        user += _section("past_tickets", menu_text)
    session_id = str(uuid.uuid4())
    story = _run_claude(
        ACTOR_BENIGN_PROMPT, user, model=BENIGN_ACTOR_MODEL, effort=BENIGN_ACTOR_EFFORT,
        settings_path=BENIGN_ACTOR_SETTINGS, add_dir=LESSONS_ENVIRONMENT_DIR,
        permission_mode="acceptEdits", session_id=session_id,
    )
    _copy_transcript(session_id, learning_run_dir / "actor_benign_trace.jsonl")
    return story
