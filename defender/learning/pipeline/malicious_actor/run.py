"""Malicious actor stage — gray-box adversarial story generation (FN direction).

The free function ``invoke_actor`` assembles the actor's inputs (alert + projected
lead sequence + a per-run MITRE menu + archetype) and shells out via the shared
``claude -p`` transport. ``ops/replay_actor.py`` drives this function directly against
a frozen generation, monkeypatching ``_actor_seed`` to pin the menu/archetype to a
stable case id; keep ``_actor_seed`` and ``invoke_actor`` colocated so that override
resolves at call time. ``RunUnprocessable`` is re-exported for that replay path's except-clause.
"""
from __future__ import annotations

import hashlib
import json
import random
import uuid
from pathlib import Path

from defender.learning.core.config import (
    ACTOR_EFFORT,
    ACTOR_MODEL,
    ACTOR_PROMPT,
    ACTOR_SETTINGS,
    LESSONS_ACTOR_DIR,
    LESSONS_ENVIRONMENT_DIR,
    RunUnprocessable,  # noqa: F401 — re-exported for ops/replay_actor.py's `sub.RunUnprocessable`
)
from defender.learning.core.persist import derive_alert_rule_key
from defender.learning.core.runner import _copy_transcript, _run_claude, _section
from defender.learning.pipeline.malicious_actor import mitre_corpus


def _actor_seed(run_id: str) -> int:
    """Stable per-run seed for menu sampling and archetype choice."""
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def is_skip_story(actor_story: str) -> bool:
    for line in actor_story.splitlines():
        s = line.strip()
        if not s:
            continue
        return s.startswith("SKIP:")
    return False


def invoke_actor(alert_path: Path, actor_input_path: Path, learning_run_dir: Path) -> str:
    rng = random.Random(_actor_seed(learning_run_dir.name))
    archetype = rng.choice(["internal", "external"])
    menu_text = mitre_corpus.format_menu(mitre_corpus.sample_menu(rng))
    (learning_run_dir / "actor_archetype.txt").write_text(archetype + "\n")
    (learning_run_dir / "actor_menu.txt").write_text(menu_text + "\n")

    alert_rule_key = derive_alert_rule_key(json.loads(alert_path.read_text()))
    user = (
        _section("alert", alert_path.read_text())
        + _section("alert_rule_id", alert_rule_key,
                   "canonical rule key; pass verbatim to environment-fact retrieval")
        + _section("actor_input", actor_input_path.read_text(),
                   "lead sequence projected for the actor")
        + _section("actor_archetype", archetype)
        + _section("mitre_menu", menu_text)
    )
    session_id = str(uuid.uuid4())
    story = _run_claude(
        ACTOR_PROMPT, user, model=ACTOR_MODEL, effort=ACTOR_EFFORT,
        settings_path=ACTOR_SETTINGS,
        add_dir=[LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR],
        permission_mode="acceptEdits", session_id=session_id,
    )
    _copy_transcript(session_id, learning_run_dir / "actor_trace.jsonl")
    return story
