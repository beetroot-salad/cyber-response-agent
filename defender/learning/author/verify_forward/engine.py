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

Unlike the pipeline stages (invoked in-process BY the orchestrator, which sources the metered key
up front), the forward-check runs as a CLI ``python3`` SUBPROCESS spawned by the curator agent
(``verify_forward/{forward,actor}.py``, fanned out by ``batch.py``). The verify subprocess carries
only the ambient credential (or none), so each verify subprocess re-sources its own Fireworks key
from ``.env`` before this engine runs — see the CLI ``main``s, which call
``config.source_first_party_key`` (the same seam ``ops/replay_actor.py`` uses).

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when a forward-check
actually runs, never at import of ``forward.py`` / ``actor.py`` (whose pure helpers, e.g.
``load_run_context``, must stay importable under any interpreter — see ``tests/test_verify_forward``'s
subprocess cases).
"""
from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import (
    VERIFIER_EFFORT,
    VERIFIER_MODEL,
    VERIFIER_TIMEOUT,
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    source_first_party_key,
)
from defender.learning.author.verify_forward.shared import parse_verdict
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
    "Blocked: the forward-check is a pure prediction — its entire input (transcript/story, lesson, "
    "disposition) is inlined in the user prompt and its entire output is two short paragraphs plus a "
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
# ``runtime.agents.AGENTS``; ``bind(VERIFY_DEF)`` compiles the deny-all policy over this empty
# ``ToolSet`` (#551 — the standalone ``_VERIFY_POLICY`` constant + ``VerifierDeps.for_run`` front
# door retired, so there is no second policy source to keep honest by a parity test).
VERIFY_DEF = AgentDefinition(
    role=AgentRole.VERIFIER,
    model=lambda: VERIFIER_MODEL,
    effort=VERIFIER_EFFORT,
    tools=ToolSet(),
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
    ``RunUnprocessable`` (which the CLI ``main`` surfaces as a non-zero exit, reported by ``batch.py``
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


def forward_check(  # noqa: PLR0913 — the CLI-facing verify contract (5 inputs) + its 3 config knobs + 2 DI seams; every param is load-bearing per-call state
    *,
    prompt_path: Path,
    user: str,
    source_run_dir: Path,
    lesson_stem: str,
    error_prefix: str,
    model: str = VERIFIER_MODEL,
    effort: str = VERIFIER_EFFORT,
    timeout: int = VERIFIER_TIMEOUT,
    source_key: Callable[..., object] = source_first_party_key,
    run_verify: Callable[..., str] = _run_verify_pydantic,
) -> str:
    """Source the metered Fireworks key, run the in-process forward-check on GLM, and return the
    parsed ``GOOD``/``BAD`` verdict — the whole CLI-facing path both ``forward.py`` and ``actor.py``
    share, so their ``main``s stay a thin wrapper.

    Sources the key here (not the transport) because the verify subprocess carries only the ambient
    credential (or none); ``source_first_party_key`` re-reads the metered key
    from ``.env`` / ``$DEFENDER_ENV_FILE`` — reaching the MAIN checkout's ``.env`` even from the
    curator's throwaway worktree (``_first_party_key._main_repo_root``). Maps every engine fault to a
    clean ``SystemExit`` (a config fault → no key / unroutable model; an unprocessable run → timeout
    / usage-limit / model error / empty verdict; an unparseable verdict) so a non-zero CLI exit
    surfaces as ``batch.py`` ERROR — the same disposition the old ``claude -p`` non-zero exit gave —
    rather than an uncaught traceback. The per-check trace file is keyed on ``lesson_stem`` AND the
    child's pid (``RequestLogger`` opens in truncate mode), so concurrent batch children that share a
    ``source_run_dir`` and a lesson stem — two lessons with the same basename, or the same lesson in
    both directions — still never clobber one log.

    ``source_key`` / ``run_verify`` are DI seams that OWN their production defaults (the same shape as
    the engines' ``make_model``): production calls with neither, running the real key-sourcing +
    transport; tests inject fakes to exercise this orchestration (contract + fault mapping) without a
    metered key or the pydantic-ai graph — so no ``monkeypatch`` of module globals is needed."""
    # The pydantic-ai engine is heavy; the CLIs import it lazily via this function, so a bad key /
    # missing model surfaces here rather than at module import.
    try:
        source_key(model, label=error_prefix)
    except FatalConfigError as e:
        raise SystemExit(f"{error_prefix}: {e}") from e
    try:
        raw = run_verify(
            prompt_path=prompt_path,
            model=model,
            effort=effort,
            trace_name=f"{error_prefix}.{lesson_stem}.{os.getpid()}.trace.jsonl",
            label=f"{error_prefix}:{lesson_stem}",
            user=user,
            source_run_dir=source_run_dir,
            wall_clock_timeout=timeout,
        )
    except (RunUnprocessable, StageAbort, FatalConfigError) as e:
        raise SystemExit(f"{error_prefix}: forward-check did not complete: {e}") from e
    return parse_verdict(raw, error_prefix=error_prefix)
