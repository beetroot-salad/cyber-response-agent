"""The lead-author spawn on the in-process PydanticAI engine — a writer-stage transport.

Mirror of the read-only predictors' engines (``pipeline/oracle_engine.py``,
``pipeline/actor_engine.py``, ``author/verify_forward/engine.py``): the lead-author's
specifics (its deps identity + an AgentPolicy that confines the CORPUS WRITERS to
``defender/skills`` and grants a scoped ``rm`` of drafts) live here, and the generic
in-process transport it shares with the four predictors lives in
``pipeline/_pydantic_stage.py``. The lead author is the FIRST *writer* on that harness: its
``LEAD_AUTHOR_DEF`` ToolSet grants the ``write_file``/``edit_file`` tools (``write=True``, registered
from the def by role — #538), and it opts into ``require_output=False`` (a writer legitimately ends
with empty final prose — its output is the committed tree, not a returned verdict).

ONE engine serves BOTH lead-author modes — the per-run catalog/skill author (``lead_author``)
and the cross-run pitfalls curator (``pitfalls_curator``) — the way ``verify_forward``'s one
engine serves both the findings and actor forward-checks: the per-mode variation (its prompt,
batch id, trace anchor, repo_root) is threaded through ``run_author_stage``'s args, not a second
engine module. Both spawn through ``_lead_spine._spawn_author_agent``, which delegates here.

Unlike the pipeline stages (invoked in-process BY the orchestrator, which sources the metered key
up front), the lead-author drain runs in a throwaway worktree carrying only the ambient credential
(or none), so ``run_author_stage`` re-sources its own Fireworks key from ``.env`` before the engine
runs (``config.source_first_party_key``, the same seam ``verify_forward`` uses). A
CONFIG fault (no key / unroutable model / a cross-provider effort like ``claude-* + none``) raises
``FatalConfigError`` and is left to PROPAGATE: a deployment-wide misconfig then fails ONCE, loudly
(systemic exit 2), rather than being mapped to rc 124 and quarantining every queued marker
one-by-one. Only a per-run ``RunUnprocessable`` (timeout / usage-limit / model error) maps to rc
124 — the single-run quarantine the caller's ``run()`` already handles.

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when a spawn actually
runs, never at import of ``_lead_spine`` / ``lead_author`` (whose pure helpers must stay importable
under any interpreter).
"""
from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable
from defender.learning.leads.path_validation import SKILLS_REL
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, BashGrammar, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import build_write_allow
from defender.runtime.tools import AgentDeps

_LEAD_AUTHOR_DENY_REASON = (
    "Blocked: the lead author curates the gather catalog + system skills under "
    "defender/skills only. It reads the corpus, writes/edits skill files there, and rm's a "
    "draft it promotes or discards — no data-source adapters, no gather_raw reads, no shell "
    "beyond the scoped rm, no writes outside defender/skills."
)


def _rm_skills_pattern(skills_dir: Path) -> re.Pattern[str]:
    """The lead author's ONE bash grant: ``rm`` of a SINGLE path under ``defender/skills``
    (promote = write the established template + rm the draft; discard = rm the draft). Mirrors the
    actor's ``_script_pattern`` — an anchored regex over the tokenized argv (operands are unconfined
    on the bash lane, so the skills prefix is baked into the pattern). Two spellings: the fixed
    repo-relative ``defender/skills/…`` (the agent runs with cwd=worktree and issues repo-relative
    paths, and a tmp worktree is NOT under ``REPO_ROOT`` so we can't derive it from
    ``skills_dir.relative_to(REPO_ROOT)``) and the absolute ``<worktree>/defender/skills/…``.

    The operand is one-or-more ``/``-separated segments and every segment is TEXTUALLY not ``..``
    (the same anti-traversal shape ``policies._common._SEG`` uses on the reader lane): the bash lane
    does no ``resolve()``, so a ``..`` must be rejected literally here — else ``rm defender/skills/../
    <anything>`` would escape the worktree and delete a file the loop's git scope gate (which only
    diffs the worktree's own ``git status``) can never see. Single path, no flags — one draft at a
    time."""
    spellings = "|".join(re.escape(s) for s in (SKILLS_REL.rstrip("/"), str(skills_dir)))
    # One path segment that is not a `..` traversal and carries no `/` or real space — the same
    # shape as `policies._common._SEG`. Excluding the real space keeps a multi-path `rm a b` from
    # matching as one long "segment" (a token boundary is a real space; an in-token space is the
    # `_TOKEN_SPACE` \x00 sentinel, which `[^/ ]` still admits, so a space-in-filename draft works).
    seg = r"(?!\.\.(?:/|$))[^/ ]+"
    return re.compile(rf"^rm (?:{spellings})(?:/{seg})+$")


def _lead_author_write_shape(run_dir: Path, defender_dir: Path) -> tuple[re.Pattern[str], ...]:
    """The lead author's write scope (#551 — its ``write_shapes`` builder, resolved by
    ``compile_policy`` into ``write_allow``): a single flat pattern admitting
    ``<defender_dir>/skills/**.md`` ONLY (the corpus is ``.md`` — SKILL.md / execution.md / query
    templates), anchored on the run's ``defender_dir`` (the WORKTREE ``bind`` threads in). The file
    writers may author a skills ``.md`` and NOTHING else. Tighter than a bare skills-subtree grant —
    it denies a write to the ``invlang``/``connect`` Python code that also lives under ``skills``
    (which the loop's ``.md``-only scope gate would only catch at commit, after the worktree already
    carries the edit) — and, being a flat allowlist rather than a run-dir root, it does NOT grant the
    writer its ``run_dir`` (nor the pitfalls curator its ``PENDING_DIR``). Reads under
    ``defender_dir`` stay allowed by ``decide_read``'s defaults (it reads the catalog + siblings —
    LEAD_AUTHOR_DEF carries no ``read_confine`` and no ``read_shapes``)."""
    return (build_write_allow(defender_dir / "skills", suffix=".md"),)


@dataclass(frozen=True)
class LeadAuthorDeps(AgentDeps):
    """The lead author's per-spawn deps — a plain ``AgentDeps`` shape with a WRITER ``policy``.
    ``role`` is a LEAD_AUTHOR identity label — the gate keys on ``policy``, not this. Built via the
    single ``bind`` seam (#551 — ``bind(LEAD_AUTHOR_DEF, run, defender_dir=<wt>/defender)``, which
    threads the worktree tree into BOTH the policy anchor and this deps' ``defender_dir`` field, so
    reads/writes resolve against the throwaway worktree, never the MAIN checkout)."""

    role: ClassVar[AgentRole] = AgentRole.LEAD_AUTHOR


# The lead author's AgentDefinition (#538/#551). It is the loop's FIRST writer, so its ToolSet grants
# the file writers (write=True → write_file/edit_file) on top of read + the scoped bash rm
# (``BashGrammar(skills_rm=True)`` — ``compile_policy`` anchors the ``rm``-of-drafts matcher on the
# run's worktree ``skills``). The build site registers all four from this. ``write_shapes`` is the
# worktree-anchored ``skills/**.md`` write scope as DATA (resolved by ``compile_policy`` — the write
# twin of ``read_shapes``), and ``requires_explicit_tree=True`` makes ``bind`` fail loud without an
# explicit NON-PATHS worktree ``defender_dir`` (the main-checkout-authoring state is UNBUILDABLE,
# checked generically — no role branch). So the lead author is now BOUND like every other role
# (#551 — the bespoke ``LeadAuthorDeps.for_run`` + ``_lead_author_policy`` front door retired).
# ``model``/``effort`` are the declarative stage defaults; each spawn re-binds its own per-run
# model/effort in ``build_stage_agent``.
LEAD_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.LEAD_AUTHOR,
    model=lambda: config.LEAD_AUTHOR_MODEL,
    effort=config.LEAD_AUTHOR_EFFORT,
    tools=ToolSet(read=True, bash=BashGrammar(skills_rm=True), write=True),
    write_shapes=(_lead_author_write_shape,),
    requires_explicit_tree=True,
    deny_reason=_LEAD_AUTHOR_DENY_REASON,
)


def _run_author_pydantic(  # noqa: PLR0913 — the transport signature plus the make_model test seam; every param is load-bearing per-call state
    *,
    prompt_path: Path,
    model: str,
    effort: str | None,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    repo_root: Path,
    request_limit: int = config.LEAD_AUTHOR_REQUEST_LIMIT,
    wall_clock_timeout: int = config.LEAD_AUTHOR_TIMEOUT,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """Run one lead-author spawn in-process and return the model's final text (the caller ignores
    it — the real output is the committed tree). Builds the writer ``LeadAuthorDeps`` via the single
    ``bind`` seam (#551 — ``defender_dir=<worktree>/defender`` threads the throwaway worktree into
    both the policy anchor and the deps field, so the skills ``write_allow`` + ``rm`` grant + reads
    all resolve against the worktree) and delegates to the shared ``run_stage``. The file writers are
    registered from ``LEAD_AUTHOR_DEF``'s ToolSet (``write=True``, looked up by role in
    ``build_stage_agent`` — #538); this stage only opts into ``require_output=False`` (an empty final
    is a valid writer outcome — its output is the committed tree, not a returned verdict).
    ``learning_run_dir`` is where the RequestLogger trace lands; distinct ``trace_name``s (batch_id +
    pid) keep concurrent spawns from racing on one file."""
    deps = bind(LEAD_AUTHOR_DEF, learning_run_dir, defender_dir=repo_root / "defender")
    return run_stage(
        stage="lead_author",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=request_limit, make_model=make_model,
        require_output=False,
        wall_clock_timeout=wall_clock_timeout,
    )


def run_author_stage(  # noqa: PLR0913 — the spawn contract (5 per-mode inputs + logger) + its 4 config knobs + 2 DI seams; every param is load-bearing per-call state
    *,
    system_prompt_file: Path,
    batch_id: str,
    user_prompt: str,
    repo_root: Path,
    learning_run_dir: Path,
    log_label: str,
    log: Callable[[str], None],
    model: str = config.LEAD_AUTHOR_MODEL,
    effort: str | None = config.LEAD_AUTHOR_EFFORT,
    timeout: int = config.LEAD_AUTHOR_TIMEOUT,
    request_limit: int = config.LEAD_AUTHOR_REQUEST_LIMIT,
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_author_pydantic,
) -> int:
    """Source the metered Fireworks key, run the in-process lead-author spawn on GLM, and map faults
    to the int rc both callers (``lead_author.invoke_agent`` / ``pitfalls_curator``) depend on. The
    whole spine-facing path both lead-author modes share, so ``_spawn_author_agent`` stays a thin
    lazy-import wrapper.

    Sources the key here (not the transport) because the drain worktree carries only the ambient
    credential (or none); ``source_first_party_key`` re-reads the metered key from
    ``.env`` / ``$DEFENDER_ENV_FILE`` — reaching the MAIN checkout's ``.env`` even from the
    throwaway worktree.

    Fault mapping (F1): a per-run ``RunUnprocessable`` (timeout / usage-limit / model error / an
    empty verdict — though a writer's empty final is allowed) → rc 124, the single-run quarantine
    ``run()`` maps to exit 2. A systemic ``FatalConfigError`` (no key / unroutable model /
    cross-provider effort, raised by ``source_key`` or by ``run_stage``'s build) OR ``StageAbort``
    PROPAGATES — a deployment-wide misconfig fails ONCE, loudly, instead of quarantining every
    queued marker one-by-one (matches ``run_stage``'s own systemic-vs-per-run split).

    ``source_key`` / ``run_author`` are DI seams that OWN their production defaults (the same shape
    as ``verify_forward.forward_check``): production calls with neither; tests inject fakes to
    exercise this orchestration (key ordering + fault mapping) without a metered key or the
    pydantic-ai graph — so no ``monkeypatch`` of module globals is needed."""
    log(f"spawn {log_label} in-process (model={model}, effort={effort}, timeout={timeout}s)")
    source_key(model, label=log_label)  # FatalConfigError PROPAGATES (systemic — F1)
    trace_name = f"{batch_id}.{os.getpid()}.trace.jsonl"
    try:
        run_author(
            prompt_path=system_prompt_file, model=model, effort=effort,
            trace_name=trace_name, label=f"{log_label}:{batch_id}", user=user_prompt,
            learning_run_dir=learning_run_dir, repo_root=repo_root,
            request_limit=request_limit, wall_clock_timeout=timeout,
        )
    except RunUnprocessable as e:
        # A per-run fault only — quarantine THIS spawn (rc 124 → run() maps to exit 2). StageAbort /
        # FatalConfigError are NOT caught here; they propagate as the systemic exit-2 lane (F1).
        log(f"{log_label} did not complete (per-run fault): {e}")
        return 124
    log(f"{log_label} done")
    return 0
