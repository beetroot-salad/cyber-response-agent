from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from uuid import uuid4

from defender._untrusted import wrap
from defender.learning.core.config import (
    ACTOR_EFFORT,
    ACTOR_MODEL,
    ACTOR_PROMPT,
    LESSONS_ACTOR_DIR,
    LESSONS_ACTOR_INDEX_SCRIPT,
    LESSONS_ENV_RETRIEVE_SCRIPT,
    LESSONS_ENVIRONMENT_DIR,
    RunUnprocessable,  # noqa: F401 — re-exported for ops/replay_actor.py's `sub.RunUnprocessable`
)
from defender.learning.core.persist import derive_alert_rule_key
from defender.learning.pipeline._prompt import stage_user_message
from defender.learning.pipeline.malicious_actor import mitre_corpus

_SKIP_SCAN_LINES = 8


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
                 *, actor_fn=None, salt: str | None = None) -> str:
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
        ACTOR_PROMPT, ACTOR_MODEL, ACTOR_EFFORT, "actor_trace.jsonl", "actor",
        user, learning_run_dir,
        scope=_ActorScope(
            (LESSONS_ENV_RETRIEVE_SCRIPT, LESSONS_ACTOR_INDEX_SCRIPT),
            read_confine=(LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR),
        ),
        salt=stage_salt,
    )
