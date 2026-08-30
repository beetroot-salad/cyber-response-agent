"""The launcher's three model-and-estate seams, resolved for a real episode (#947 M1/M4).

`learning/branch/cli.py` takes `questioner`, `adapters` and `invoke` as injected callables, and
that is right: a launcher that reached for a provider itself could not be driven by a test, and
the review's adapter layer is exactly the thing a test must be able to stand in for. But an
injection seam with no production value is not a seam, it is a hole — the shipped
`__main__` could reach `author_family(invoke=None)` and die on a `TypeError` with an episode id
already burned, and the refusal that replaced that crash still left the entry point unable to
run anything.

This module is the other half: ONE place that says what each seam IS when nobody supplies one.
The launcher resolves them at its boundary, the way it already resolves the write door and the
role preflight, and threads them inward non-`None` — the project's anchoring rule, so no frame
downstream has to ask a second time and no two frames can disagree about which model answered.

WHY THE TWO MODEL SEAMS ARE ONE FUNCTION. `author_family` and `comparator.compare` both call
`(prompt, *, role, agent_id)` and both declare `AgentRole.QUESTIONER`; what separates their calls
is the `agent_id` the wire log and the per-id trace partition on, which is a property of the
CALL and not of the seam. A second builder here would be a second place for the two to acquire
different models, and the family's own comparability stamp cannot see that: it compares the
model across SIBLINGS, and these calls all happen in the launcher.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

#: The questioner's standing system prompt. The per-call task — the base story, one world's
#: elaboration, one payload comparison — is composed into the USER message by its own caller,
#: because this role's whole input is inlined by the host; what belongs here is only what is
#: true of every call it makes.
_ROLE_PROMPT = Path(__file__).resolve().parent / "questioner" / "role.md"

#: One model call per seat and no retry loop inside one, which is `QUESTIONER_REQUEST_LIMIT`'s
#: rule restated at the transport: a questioner that could ask again on its own would spend the
#: operator's money with no operator in the room.
_REQUEST_LIMIT = 1


def model_seam(episode_dir: Path) -> Any:
    """The production `(prompt, *, role, agent_id) -> str` for every questioner-role call.

    Both the authoring fan-out and the comparator go through this. The reply comes back as TEXT
    and is parsed by whoever asked — `_reply_document` for a manifest half, `_verdict_of` for a
    comparison — because what a well-formed answer IS differs per seat and neither wants a
    second opinion about it from the transport.

    THE TRACE LANDS IN THE EPISODE, under the wire-log subdirectory `run_stage` puts every
    stage's stream in. The episode dir is the archive, so an operator asking what the questioner
    was shown reads it beside the manifest it produced rather than in a learning run dir this
    flow does not have.

    `agent_id` reaches the wire log through the stage LABEL, which is what partitions the
    per-call trace: three calls sharing one id would overwrite each other's record, which is the
    reason the fan-out assigns distinct ids in the first place.
    """
    from defender.learning._pydantic_stage import run_stage
    from defender.learning.branch.questioner import (
        QuestionerDeps,
        questioner_effort,
        questioner_model,
    )
    from defender.learning.core.config import StageContext, StageWiring, subagent_timeout

    episode_dir = Path(episode_dir)

    def invoke(prompt: str, *, role: Any = None, agent_id: str = "questioner") -> str:  # noqa: ARG001 — the role is the caller's declaration and is fixed by `QuestionerDeps`; taken so the seam matches the call every caller already makes
        return run_stage(
            stage="questioner",
            wiring=StageWiring(
                prompt_path=_ROLE_PROMPT,
                model=questioner_model(),
                effort=questioner_effort(),
                trace_name=f"{agent_id.replace(':', '_')}_trace.jsonl",
                label=agent_id,
            ),
            ctx=StageContext(
                learning_run_dir=episode_dir,
                user=prompt,
                request_limit=_REQUEST_LIMIT,
                wall_clock_timeout=subagent_timeout(),
            ),
            deps=QuestionerDeps(),
        )

    return invoke


def adapter_seam(episode_dir: Path) -> Any:
    """The production `(system, verb, **params) -> payload` the review replays through.

    THE GATHER GRANT, which is the same roster a sibling serves through — `run.py` builds its
    registry from it, and a review that could reach a verb no sibling can would be measuring a
    world through a door the family cannot open.

    ONE registry and ONE context for the whole review, built here rather than per call: the
    registry does a cold read and parse per system at construction, and the context composes the
    run environment every adapter subprocess inherits. `review.verb_context` owns what that
    context is — including that it writes no query row anywhere, because a review is not a run.

    NOT a `WorldRegistry`. The world's difference is applied by `replay_one`, which stages the
    call itself and then asks the world what it did to the answer; a world registry underneath
    would apply it a second time and write ledger rows into a table the review deliberately
    keeps out of the episode.
    """
    from defender.learning.branch.review import verb_context
    from defender.run_common import DEFENDER_DIR
    from defender.runtime.driver import GATHER_DEF
    from defender.runtime.verbs import ModuleVerbRegistry

    registry = ModuleVerbRegistry(DEFENDER_DIR / "scripts" / "adapters", GATHER_DEF.verb_grant)
    ctx = verb_context(Path(episode_dir))

    def adapters(system: str, verb: str, **params: Any) -> Any:
        return registry.verbs(system)[verb](ctx, **params)  # lint-verb-dispatch: ok — the review's own replay, not the fault seam: a system whose adapter fails to import raises here, inside `replay_one`, where the review records the failure against the world rather than losing a row

    return adapters
