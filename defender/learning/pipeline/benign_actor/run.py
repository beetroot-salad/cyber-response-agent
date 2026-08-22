from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from defender._untrusted import wrap
from defender.learning.core.config import (
    ACTOR_BENIGN_PROMPT,
    LESSONS_ENV_RETRIEVE_SCRIPT,
    LESSONS_ENVIRONMENT_DIR,
    StageWiring,
    benign_actor_effort,
    benign_actor_model,
)
from defender.learning._prompt import stage_user_message
from defender.learning.tickets import ticket_seeds

#: THIS leg's gate scope — strictly less than the adversarial leg's (one script, one corpus):
#: the FP hunter has no business in the actor lessons. See the sibling declaration in
#: `malicious_actor/run.py` for why each leg must own its own.
ACTOR_SCRIPTS = (LESSONS_ENV_RETRIEVE_SCRIPT,)
ACTOR_READ_CONFINE = (LESSONS_ENVIRONMENT_DIR,)


def invoke_actor_benign(
    alert_path: Path,
    case_entities: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    box,
    actor_fn=None,
    salt: str | None = None,
) -> str:
    alert_text = alert_path.read_text(encoding="utf-8")
    stage_salt = salt if salt is not None else uuid4().hex
    sections = [
        wrap(alert_text, "alert", stage_salt),
        wrap(alert_rule_key, "alert_rule_id", stage_salt),
        wrap(case_entities, "case_entities", stage_salt),
    ]
    case_id = learning_run_dir.name
    seeds = ticket_seeds.sample_seeds(json.loads(alert_text), case_id, case_id)
    if seeds:
        menu_text = ticket_seeds.format_seeds(seeds)
        (learning_run_dir / "past_tickets.txt").write_text(menu_text + "\n", encoding="utf-8")
        sections.append(wrap(menu_text, "past_tickets", stage_salt))
    user = stage_user_message(stage_salt, *sections)
    from defender.learning.pipeline.actor_engine import _ActorScope, _run_actor_pydantic
    actor_fn = actor_fn if actor_fn is not None else _run_actor_pydantic  # lint-default: ok — DI seam owns its default; a signature default needs a module-top import that would defeat the lazy pydantic-ai import (subagents imports this module eagerly)
    return actor_fn(
        StageWiring(
            prompt_path=ACTOR_BENIGN_PROMPT, model=benign_actor_model(),
            effort=benign_actor_effort(), trace_name="actor_benign_trace.jsonl",
            label="actor-benign",
        ),
        user=user, learning_run_dir=learning_run_dir,
        scope=_ActorScope(ACTOR_SCRIPTS, read_confine=ACTOR_READ_CONFINE),
        salt=stage_salt, box=box,
    )
