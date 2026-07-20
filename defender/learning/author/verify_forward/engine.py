"""The forward-check gate on the in-process PydanticAI engine — a drop-in verify transport.

Mirror of the oracle's ``pipeline/oracle_engine.py`` and the actor's ``pipeline/actor_engine.py``:
the forward-check's specifics (its deps identity + a deny-all permission policy) live here, and
the generic in-process transport it shares with the actor / judge / oracle lives in
``pipeline/_pydantic_stage.py``. The forward-check is the FOURTH consumer of that harness.

ONE engine serves BOTH LLM forward-checks — the defender-findings check (``forward.py``) and the
actor-lessons check (``actor.py``) — the way one ``_run_actor_pydantic`` serves both actor
directions: the per-check variation (its prompt text, trace name, and label) is threaded through
``_run_verify_pydantic``'s args, not a second engine module. (``env.py`` is a deterministic
retrieval check with no model, so it does not touch this engine.)

The forward-check emits a short reasoning preamble + a single ``VERDICT: GOOD|BAD`` line and calls
NO tools — its whole input (transcript/story + lesson + disposition) is inlined in the user prompt.
Since #538 that tool-freeness is STRUCTURAL: ``VERIFY_DEF`` registers an empty ``ToolSet()`` (no
``read_file``, no ``bash``), so the adversarial check can no longer ``read_file`` the SOURCE run's
``source_refs.yaml`` — which holds the very ``normalized_disposition`` it is asked to predict (the
answer-key affordance the #534 review flagged; sharpest in the benign direction, where the recorded
malicious call and the corrected benign target disagree, so a stray read CONTRADICTS the check). The
no-toolset build closes it by construction rather than by prompt guarantee, and the request cap drops
to 1 (no tool can be called). ``bind(VERIFY_DEF)`` compiles a deny-all policy as belt-and-suspenders.

Like the pipeline stages, the check now runs IN-PROCESS: the curator's ``forward_check`` tool
(``verify_forward/tool.py``) calls this transport directly, once per pair, on a worker thread. The
metered key is sourced ONCE by the curator spawn (``run_curator_stage``), so this engine sources
none — the CLI-facing ``forward_check()`` wrapper that re-sourced it per check died with the
subprocess lane (#558), along with the ``os.getpid()`` trace key it used, which is constant across
an in-process batch. The trace is keyed on a per-check counter instead; see ``checks.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import (
    VERIFIER_EFFORT,
    VERIFIER_MODEL,
    VERIFIER_TIMEOUT,
)
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.tools import AgentDeps

# The forward-check is TOOL-FREE (#538): VERIFY_DEF registers an empty toolset, so no tool can be
# called and a clean verdict is exactly ONE model request — no headroom above 1 is needed
# (dropped 6→1). A genuinely looping verifier should hit the timeout, not burn a budget.
VERIFY_REQUEST_LIMIT = 1

_VERIFY_DENY_REASON = (
    "Blocked: the forward-check is a pure prediction — its entire input (the transcript or story, "
    "the lesson, the disposition) is inlined in the user prompt and its entire output is two short "
    "paragraphs plus a "
    "single `VERDICT: GOOD|BAD` line. It runs no tools: no data-source adapters, no gather_raw reads, "
    "no writes, no shell. Emit the reasoning + verdict directly."
)


@dataclass(frozen=True)
class VerifierDeps(AgentDeps):
    """The forward-check's per-run deps — plain ``AgentDeps`` shape with a deny-all ``policy`` (data).
    ``run_dir`` is the SOURCE run's dir (so the per-check budget / observability trace lands beside
    the case being regression-checked). ``role`` is a VERIFIER identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.VERIFIER


# The forward-check's AgentDefinition (#538): TOOL-FREE (``tools=ToolSet()`` — the build site
# registers nothing, so there is no ``read_file`` to peek at the SOURCE run's ``source_refs.yaml``
# answer key). ``model``/``effort`` are the declarative stage defaults (glm-5.2 @ low); each check
# re-binds its own per-call model/effort in ``build_stage_agent``. Collected into
# ``defender.agents.AGENTS``; ``bind(VERIFY_DEF)`` compiles the deny-all policy over this empty
# ``ToolSet`` (#551 — the standalone ``_VERIFY_POLICY`` constant + ``VerifierDeps.for_run`` front
# door retired, so there is no second policy source to keep honest by a parity test).
VERIFY_DEF = AgentDefinition(
    anchors_on_tree=True,   # runs over the curator's worktree operands (#540)
    role=AgentRole.VERIFIER,
    model=lambda: VERIFIER_MODEL,
    effort=VERIFIER_EFFORT,
    tools=ToolSet(),
    deps_cls=VerifierDeps,
    deny_reason=_VERIFY_DENY_REASON,
)


def _run_verify_pydantic(  # noqa: PLR0913 — the transport signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    source_run_dir: Path,
    *,
    wall_clock_timeout: int = VERIFIER_TIMEOUT,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """Run one forward-check in-process and return the model's final text VERBATIM.

    Builds the forward-check's deny-all ``VerifierDeps`` via the single ``bind`` seam (#551 —
    ``compile_policy`` over VERIFY_DEF's empty ``ToolSet`` emits the deny-all policy) and delegates
    to the shared ``run_stage`` (agent build + one-shot drive + error mapping + trace logging). The
    caller (``forward.py`` / ``actor.py``)
    parses the returned text with ``shared.parse_verdict``. A timeout / usage-limit / model error →
    ``RunUnprocessable`` (which the tool flattens into that pair's ERROR line
    as ERROR — the same disposition the old ``claude -p`` non-zero exit gave). ``source_run_dir`` is
    where the RequestLogger trace lands; distinct ``trace_name``s per lesson keep concurrent batch
    children from racing on one file."""
    deps = bind(VERIFY_DEF, source_run_dir)
    return run_stage(
        stage="verify_forward",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=source_run_dir, deps=deps,
        request_limit=VERIFY_REQUEST_LIMIT, make_model=make_model,
        wall_clock_timeout=wall_clock_timeout,
    )
