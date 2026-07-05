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
NO tools — its whole input (transcript/story + lesson + disposition) is inlined in the user
prompt — so its policy denies everything (the ``["bash", "read_file"]`` tools the shared
``build_agent_core`` always registers stay unused, gated shut). ``VERIFY_REQUEST_LIMIT`` is a tiny
backstop: a clean verdict is one model request; the headroom only absorbs a stray denied tool call
GLM might attempt before it re-emits the verdict.

Unlike the pipeline stages (invoked in-process BY the orchestrator, which sources the metered key
up front), the forward-check runs as a CLI ``python3`` SUBPROCESS spawned by the curator agent
(``verify_forward/{forward,actor}.py``, fanned out by ``batch.py``). The curator's env strips every
provider key (``config.curator_agent_env`` → ``subscription_env``), so each verify subprocess
re-sources its own Fireworks key from ``.env`` before this engine runs — see the CLI ``main``s,
which call ``config.source_first_party_key`` (the same seam ``ops/replay_actor.py`` uses).

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when a forward-check
actually runs, never at import of ``forward.py`` / ``actor.py`` (whose pure helpers, e.g.
``load_run_context``, must stay importable under any interpreter — see ``tests/test_verify_forward``'s
subprocess cases).
"""
from __future__ import annotations

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
from defender.learning.pipeline._pydantic_stage import build_stage_deps, run_stage
from defender.runtime import providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy
from defender.runtime.tools import RunDeps

# The forward-check calls no tools, so a clean verdict is a SINGLE model request. This cap is only
# a backstop: it leaves a little headroom for a stray tool call GLM might attempt (the deny-all
# policy bounces it with ModelRetry, costing one extra request) before it re-emits the verdict.
# Kept tiny — a genuinely looping verifier should hit the timeout, not burn a budget.
VERIFY_REQUEST_LIMIT = 6

_VERIFY_DENY_REASON = (
    "Blocked: the forward-check is a pure prediction — its entire input (transcript/story, lesson, "
    "disposition) is inlined in the user prompt and its entire output is two short paragraphs plus a "
    "single `VERDICT: GOOD|BAD` line. It runs no tools: no data-source adapters, no gather_raw reads, "
    "no writes, no shell. Emit the reasoning + verdict directly."
)


@dataclass(frozen=True)
class VerifierDeps(RunDeps):
    """The forward-check's per-run deps — plain ``RunDeps`` shape with a deny-all ``policy`` (data).
    ``run_dir`` is the SOURCE run's dir (so the per-check budget / observability trace lands beside
    the case being regression-checked). ``role`` is a VERIFIER identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.VERIFIER


# The forward-check's declarative gate policy. Like the oracle's, it takes no per-check input, so it
# is a module CONSTANT built once (not a function rebuilt per call). Deny-all: it predicts one
# disposition from an all-inlined prompt — no ``bash_allow`` matchers, no adapters, no ``adapter |
# defender-sql`` pipe, no ``gather_raw`` reads, no extra read roots. Every field is the deny/empty
# default; they are named explicitly so the deny-all intent is legible (mirrors the actor/oracle
# engines). Reads under ``defender_dir`` / the ``run_dir`` remain allowed by ``decide_read``'s
# defaults, but the verifier never issues one.
_VERIFY_POLICY = AgentPolicy(
    bash_allow=(),
    jq_operand_gated=False,
    adapters=False,
    adapter_sql_pipe=False,
    raw_reads=False,
    read_roots=(),
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
    wall_clock_timeout: int | None = None,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """Run one forward-check in-process and return the model's final text VERBATIM.

    Builds the forward-check's deny-all ``VerifierDeps`` (via the shared ``build_stage_deps``, with
    the module-constant ``_VERIFY_POLICY``) and delegates to the shared ``run_stage`` (agent build +
    one-shot drive + error mapping + trace logging). The caller (``forward.py`` / ``actor.py``)
    parses the returned text with ``shared.parse_verdict``. A timeout / usage-limit / model error →
    ``RunUnprocessable`` (which the CLI ``main`` surfaces as a non-zero exit, reported by ``batch.py``
    as ERROR — the same disposition the old ``claude -p`` non-zero exit gave). ``source_run_dir`` is
    where the RequestLogger trace lands; distinct ``trace_name``s per lesson keep concurrent batch
    children from racing on one file."""
    deps = build_stage_deps(VerifierDeps, source_run_dir, _VERIFY_POLICY)
    return run_stage(
        stage="verify_forward",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=source_run_dir, deps=deps,
        request_limit=VERIFY_REQUEST_LIMIT, make_model=make_model,
        wall_clock_timeout=wall_clock_timeout,
    )


def forward_check(
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

    Sources the key here (not the transport) because the curator strips every provider key from the
    verify subprocess's env (``config.curator_agent_env``); ``source_first_party_key`` re-reads it
    from ``.env`` / ``$DEFENDER_ENV_FILE`` — reaching the MAIN checkout's ``.env`` even from the
    curator's throwaway worktree (``_first_party_key._main_repo_root``). Maps every engine fault to a
    clean ``SystemExit`` (a config fault → no key / unroutable model; an unprocessable run → timeout
    / usage-limit / model error / empty verdict; an unparseable verdict) so a non-zero CLI exit
    surfaces as ``batch.py`` ERROR — the same disposition the old ``claude -p`` non-zero exit gave —
    rather than an uncaught traceback. ``lesson_stem`` disambiguates the per-check trace file so
    concurrent batch children (which may share a ``source_run_dir``) never race on one log.

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
            trace_name=f"{error_prefix}.{lesson_stem}.trace.jsonl",
            label=f"{error_prefix}:{lesson_stem}",
            user=user,
            source_run_dir=source_run_dir,
            wall_clock_timeout=timeout,
        )
    except (RunUnprocessable, StageAbort, FatalConfigError) as e:
        raise SystemExit(f"{error_prefix}: forward-check did not complete: {e}") from e
    return parse_verdict(raw, error_prefix=error_prefix)
