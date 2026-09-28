"""The launcher's model and estate seams, resolved for a real episode.

`learning/branch/cli.py` takes `questioner`, `adapters` and `invoke` as injected callables so a
test can stand in for them. This module says what each seam is when nobody supplies one; the
launcher resolves them at its boundary and threads them inward non-`None`, so no frame
downstream asks again and no two frames can disagree about which model answered.

The two model seams are one function: `author_family` and `comparator.compare` both call
`(prompt, *, role, agent_id)` as `AgentRole.QUESTIONER`, differing only in `agent_id`. A second
builder would be a second place for them to acquire different models, and the family's
comparability stamp cannot see that — it compares the model across siblings, and these calls
all happen in the launcher.
"""

from __future__ import annotations

from dataclasses import replace
from defender._model import model
from defender._run_paths import WIRE_LOG_NAMES
from pathlib import Path
from typing import Any

#: The questioner's standing system prompt. The per-call task is composed into the user message
#: by the caller; only what is true of every call belongs here.
_ROLE_PROMPT = Path(__file__).resolve().parent / "questioner" / "role.md"

#: One model call per seat, no retry: a questioner that could ask again on its own would spend
#: the operator's money with no operator in the room.
_REQUEST_LIMIT = 1


def model_seam(episode_dir: Path) -> Any:
    """The production `(prompt, *, role, agent_id) -> str` for every questioner-role call.

    The reply is returned as text and parsed by the caller, since what a well-formed answer is
    differs per seat. The trace lands in the episode dir's wire-log subdirectory, beside the
    manifest it produced. `agent_id` becomes the stage label, which partitions the per-call
    trace — calls sharing an id would overwrite each other's record.
    """
    from defender.learning._pydantic_stage import run_stage
    from defender.learning.branch.questioner import (
        QuestionerDeps,
        questioner_effort,
        questioner_model,
    )
    from defender.learning.core.config import StageContext, StageWiring, subagent_timeout

    episode_dir = Path(episode_dir)

    def invoke(prompt: str, *, role: Any = None, agent_id: str = "questioner") -> str:  # noqa: ARG001 — the role is fixed by `QuestionerDeps`; taken so the seam matches the callers' signature
        return run_stage(
            stage="questioner",
            wiring=StageWiring(
                prompt_path=_ROLE_PROMPT,
                model=questioner_model(),
                effort=questioner_effort(),
                trace_name=WIRE_LOG_NAMES.agent_trace(agent_id),
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


@model(frozen=True)
class EpisodeAdapters:
    """The review's read side: one registry and one context, plus a per-world view of both.

    Calling it is the base read, with no world declared. A staged read must go through
    `for_world`: a staged call names `wv-<world>-<corpus>`, which no configured pattern reaches,
    and `confine_index` admits it only when the context declares that world. Read through the
    base context, every staged capture re-ask faults, reachability reads as unmeasured, and
    every defender finding is withheld. Tests don't catch this because their stand-in read side
    has no confinement.

    The registry is shared across worlds: it does a cold read and parse per system, and neither
    it nor the context's environment varies with the world.
    """

    registry: Any
    ctx: Any

    def __call__(self, system: str, verb: str, **params: Any) -> Any:
        return self.registry.verbs(system)[verb](self.ctx, **params)  # lint-verb-dispatch: ok — the review's own replay, not the fault seam: an adapter import failure raises inside `replay_one`, which records it against the world rather than losing a row

    def for_world(self, world_id: str) -> EpisodeAdapters:
        """The same registry, read as `world_id` — the composed token, never the short label.

        `confine_index` matches against the view name's world segment, which is the token
        (`wv-<episode>.<label>-<corpus>`); a short label never matches and is refused as if it
        reached for a sibling's view. Uses `replace` rather than `registry._carrying`, which
        guards test-supplied contexts.
        """
        return replace(self, ctx=replace(self.ctx, world_id=world_id))


def adapter_seam(episode_dir: Path, tenant: Any, *, runs_base: Path) -> EpisodeAdapters:
    """The production read side the review replays through.

    Uses the episode tenant's gather grant, the same one every sibling serves through: a review
    that could reach a verb no sibling can would measure a world through a door the family
    cannot open. `tenant` is the launcher's resolved `RunTenant`, and `runs_base` that tenant's
    runs base.

    Not a `WorldRegistry`: `replay_one` stages the call and applies the world's difference
    itself, so a world registry underneath would apply it twice and write ledger rows into a
    table the review keeps out of the episode. `review.verb_context` owns the context, which
    writes no query rows because a review is not a run.
    """
    from defender.learning.branch.review import verb_context
    from defender._paths import adapters_under
    from defender.run_common import DEFENDER_DIR
    from defender.runtime.verbs import ModuleVerbRegistry, read_roster

    return EpisodeAdapters(
        registry=ModuleVerbRegistry(
            read_roster(adapters_under(DEFENDER_DIR)), tenant.grants.gather,
            grant_home=tenant.table_pointer),
        ctx=verb_context(Path(episode_dir), tenant.settings, runs_base=runs_base),
    )
