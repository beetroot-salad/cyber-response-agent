from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from uuid import uuid4

from defender._untrusted import wrap
from defender.learning.core.config import (
    ACTOR_PROMPT,
    LESSONS_ACTOR_DIR,
    LESSONS_ACTOR_INDEX_SCRIPT,
    LESSONS_ENV_RETRIEVE_SCRIPT,
    LESSONS_ENVIRONMENT_DIR,
    RunUnprocessable,  # noqa: F401 — re-exported for ops/replay_actor.py's `sub.RunUnprocessable`
    StageWiring,
    actor_effort,
    actor_model,  # noqa: F401 — re-exported for ops/replay_actor.py's `sub.actor_model`
)
from defender.learning.core.persist import derive_alert_rule_key
from defender.learning.pipeline._prompt import stage_user_message
from defender.learning.pipeline.malicious_actor import mitre_corpus

_SKIP_SCAN_LINES = 8

#: THIS leg's gate scope — the adversarial actor runs both pinned lesson scripts and reads
#: both lesson corpora. Declared here rather than at the call site because the audit CLI
#: (`scripts/policy_cli.py`) must report the scope this leg actually binds: the benign leg
#: below shares `AgentRole.ACTOR` and binds strictly less, so a CLI that transcribed one leg's
#: grants answered `defender-policy show actor` with the other leg's answer half the time.
#: Plain tuples, not a `RunScope`: this module is imported eagerly by `core.subagents`, and
#: reaching for the runtime's scope types here would drag the gate into that import.
ACTOR_SCRIPTS = (LESSONS_ENV_RETRIEVE_SCRIPT, LESSONS_ACTOR_INDEX_SCRIPT)
ACTOR_READ_CONFINE = (LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR)


def _actor_seed(run_id: str) -> int:
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def is_skip_story(actor_story: str) -> bool:
    seen = 0
    for line in actor_story.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("SKIP:"):
            return True
        seen += 1
        if seen >= _SKIP_SCAN_LINES:
            break
    return False


def invoke_actor(alert_path: Path, actor_input_path: Path, learning_run_dir: Path,
                 *, box, actor_fn=None, salt: str | None = None) -> str:
    rng = random.Random(_actor_seed(learning_run_dir.name))
    archetype = rng.choice(["internal", "external"])
    menu_text = mitre_corpus.format_menu(mitre_corpus.sample_menu(rng))
    (learning_run_dir / "actor_archetype.txt").write_text(archetype + "\n", encoding="utf-8")
    (learning_run_dir / "actor_menu.txt").write_text(menu_text + "\n", encoding="utf-8")

    alert_rule_key = derive_alert_rule_key(json.loads(alert_path.read_text(encoding="utf-8")))
    stage_salt = salt if salt is not None else uuid4().hex
    user = stage_user_message(
        stage_salt,
        wrap(alert_path.read_bytes().decode("utf-8"), "alert", stage_salt),
        wrap(alert_rule_key, "alert_rule_id", stage_salt),
        wrap(actor_input_path.read_bytes().decode("utf-8"), "actor_input", stage_salt),
        wrap(archetype, "actor_archetype", stage_salt),
        wrap(menu_text, "mitre_menu", stage_salt),
    )
    from defender.learning.pipeline.actor_engine import _ActorScope, _run_actor_pydantic
    actor_fn = actor_fn if actor_fn is not None else _run_actor_pydantic  # lint-default: ok — DI seam owns its default; a signature default needs a module-top import that would defeat the lazy pydantic-ai import (subagents imports this module eagerly)
    return actor_fn(
        StageWiring(
            prompt_path=ACTOR_PROMPT, model=actor_model(), effort=actor_effort(),
            trace_name="actor_trace.jsonl", label="actor",
        ),
        user=user, learning_run_dir=learning_run_dir,
        scope=_ActorScope(ACTOR_SCRIPTS, read_confine=ACTOR_READ_CONFINE),
        salt=stage_salt, box=box,
    )
