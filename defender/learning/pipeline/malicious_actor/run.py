"""Malicious actor stage — gray-box adversarial story generation (FN direction).

The free function ``invoke_actor`` assembles the actor's inputs (alert + projected
lead sequence + a per-run MITRE menu + archetype) and runs the actor IN-PROCESS via the
shared PydanticAI engine (``pipeline/actor_engine``). ``ops/replay_actor.py`` drives this
function directly against a frozen generation, monkeypatching ``_actor_seed`` to pin the
menu/archetype to a stable case id; keep ``_actor_seed`` and ``invoke_actor`` colocated so
that override resolves at call time. ``RunUnprocessable`` is re-exported for that replay
path's except-clause.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

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
from defender.learning.core.runner import _section
from defender.learning.pipeline.malicious_actor import mitre_corpus

# How many leading non-blank lines to scan for a ``SKIP:`` line. A reasoning model (GLM@low,
# the shipped default) can prepend a few lines of preamble before the required ``SKIP: …`` line
# despite the prompt forbidding it, so the window must clear that preamble — a too-tight cap
# silently misclassifies a real SKIP as a story (it then wastes an oracle+judge pass on a
# non-story). Kept bounded (not a whole-output scan) so a stray ``SKIP:`` deep inside a real
# story body can't false-positive; format-agnostic (both directions funnel through here, so it
# can't anchor on a story-structure marker like Section 0).
_SKIP_SCAN_LINES = 8


def _actor_seed(run_id: str) -> int:
    """Stable per-run seed for menu sampling and archetype choice."""
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16)


def is_skip_story(actor_story: str) -> bool:
    """True iff the actor short-circuited with a ``SKIP:`` (no coherent story fit the menu).

    Scans the first few non-blank lines for a ``SKIP:`` line rather than trusting only the
    first — a reasoning model (GLM) may prepend a short preamble before the required
    ``SKIP: …`` line, the actor analog of the judge's shared verdict-preamble tolerance."""
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
                 *, actor_fn=None) -> str:
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
    # DI seam that owns its default (CLAUDE.md conventions): the in-process actor engine in
    # production; ClaudePrintSubagents / tests pass an explicit actor_fn.
    from defender.learning.pipeline.actor_engine import _ActorScope, _run_actor_pydantic
    actor_fn = actor_fn if actor_fn is not None else _run_actor_pydantic  # lint-default: ok — DI seam owns its default; a signature default needs a module-top import that would defeat the lazy pydantic-ai import (subagents imports this module eagerly)
    return actor_fn(
        ACTOR_PROMPT, ACTOR_MODEL, ACTOR_EFFORT, "actor_trace.jsonl", "actor",
        user, learning_run_dir,
        scope=_ActorScope(
            (LESSONS_ENV_RETRIEVE_SCRIPT, LESSONS_ACTOR_INDEX_SCRIPT),
            read_confine=(LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR),
        ),
    )
