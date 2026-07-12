"""The judge on the in-process PydanticAI engine — a drop-in ``judge_fn``.

The judge was the first learning-loop agent to run in-process on PydanticAI, on the shared
in-process transport (``pipeline/_pydantic_stage``). Everything judge-specific lives HERE, in the judge's own
directory: its deps identity, its permission policy (data), its one bit of custom logic (the
benign closed-ticket matcher), and its thin ``judge_fn``. The generic in-process transport it
shares with the actor — agent construction, the request-capped one-shot drive, the
error-mapping ladder — lives in ``pipeline/_pydantic_stage.py``; this module only supplies the
judge's specifics and delegates.

This module pulls the pydantic-ai graph (via ``_pydantic_stage``), so it is imported LAZILY —
only when a judge actually runs (``core/subagents.InProcessSubagents.judge``), never at loop
import.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from defender.learning.core.config import JUDGE_EFFORT, JUDGE_MODEL
from defender.learning.pipeline._pydantic_stage import build_stage_agent, run_stage
from defender.runtime import observe, providers
from defender.runtime.agent_definition import (
    AgentDefinition,
    ResolvedRoots,
    RunScope,
    ToolSet,
    bind,
)
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission.command_shape import SQL_SHIM
from defender.runtime.permission.grant import (
    TREE,
    Grant,
    PathShapes,
    program_shape,
    under,
)
from defender.runtime.tools import AgentDeps

from pydantic_ai import Agent

if TYPE_CHECKING:
    from .run import _ToolScope

# Bounds a runaway tool loop (the twin of the gather's per-lead cap). Sized for GLM's
# tool-hunger: GLM issues ~2-3 tool calls per model request and surveys gather_raw per lead
# (bash/read_file) before its verdict — a live smoke run saw the benign judge reach 25/30 and the
# adversarial judge hit 30/30 (29 DISTINCT tool calls, no spin — legitimate grounded work) and
# dead-letter the run on a 7-lead case. Raised to 45 for multi-lead headroom (still a backstop,
# not a budget). Reducing GLM's tool-call count at the source is tracked in #514.
JUDGE_REQUEST_LIMIT = 45

# PROMPT SURFACE: this names only programs the judge's own lane grants (`cat`, `defender-sql`,
# and — benign only — the pinned ticket CLI). A reason naming a program the agent cannot run
# teaches a dead command and burns turns; the suite checks it against the live grant list.
_JUDGE_DENY_REASON = (
    "Blocked: the judge is read-only over the grounded evidence — `cat <payload> | "
    "defender-sql '<SQL>'` to aggregate a gather_raw payload (cat's operands must resolve "
    "inside the read roots; the SQL runs in a sealed sandbox), and read_file (with an "
    "optional substring pattern) for everything else, plus — benign only — the pinned "
    "closed-ticket read. Nothing else in bash: no data-source adapters, no writes, no "
    "arbitrary shell. You never need to list a directory: every payload's absolute path is "
    "named in the comparison files."
)


@dataclass(frozen=True)
class JudgeDeps(AgentDeps):
    """The judge's per-run deps. Identical shape to ``AgentDeps`` (run_dir, defender_dir,
    run_id, salt, policy) — the judge's read roots and its bash allowlist ride in
    ``policy`` (data), not in extra deps fields. ``run_dir`` is the *learning* run dir
    (the judge's own output dir), so budget/lesson-load side effects land there and the
    judge can only reach gather_raw via its policy read roots, never roam the whole
    investigation run dir. ``role`` is a JUDGE identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.JUDGE


def _judge_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    """The judge's bash lane — exactly two programs, split so the one that OPENS files has a
    trivially decidable argv and the one that COMPUTES cannot open a file at all:

      `cat` — the sole opener. Its SCOPE is every root the judge may read: its own (learning)
        run dir, the corpus, and its ``read_roots`` — which is how it reaches ``gather_raw``,
        whose payloads live under the INVESTIGATION run dir, a tree the judge's own ``run_dir``
        never contains. The old textual anchors could not express that (they only knew the
        agent's own run dir), which is why the judge needed a bespoke resolve()-time operand
        gate; one scope over the resolved path expresses both, so the special case is gone.
      `defender-sql` — argument-inert: it reads stdin only, takes exactly one argv (the SQL), and
        seals DuckDB (`enable_external_access=false` + `lock_configuration=true`, one-way) BEFORE
        the caller's SQL runs. The sandbox bounds it, not this shape.

    Because ``bash._decide_readers`` requires EVERY stage to be claimed, `cat X | head` is denied
    while `cat X | defender-sql '<SQL>'` is allowed. grep/head/tail fold into ``read_file`` (with
    its optional ``pattern``).

    The benign leg additionally carries the pinned closed-ticket read (``_ticket_grant``)."""
    scope = PathShapes(
        under(r.resolve(), TREE)
        for r in (roots.run_dir, roots.defender_dir, *roots.read_roots)
    )
    grants = [
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        Grant(program=SQL_SHIM, pattern=program_shape(SQL_SHIM)),
    ]
    if roots.ticket_cli is not None:
        grants.append(_ticket_grant(*roots.ticket_cli))
    return tuple(grants)


def _ticket_grant(py: str, ticket_cli: Path) -> Grant:
    """The benign judge's scoped, CLOSED-ONLY case-history read (#338): a single-stage
    ``<py> <ticket_cli> {list-tickets|get-ticket} … --require-closed …``.

    ``pins_path=True`` — the R1 exemption, and NOT a formality. Two things make "migrate it into
    a flag allowlist like every other program" wrong here:

      - the operand IS the program (`py`/`ticket_cli` are pinned exact strings from
        ``build_judge_invocation``, ``re.escape``-d so a `.`/`-` in the path can't widen the
        match). There is no file operand to resolve, so a scope buys nothing the pattern didn't
        already have;
      - **``--require-closed`` is MANDATORY, and it is the entire security property** — it is
        what stops the benign judge grading against the live, in-flight ticket (the answer key).
        A boolean-flag allowlist makes every flag OPTIONAL, so a mechanical migration would drop
        the requirement SILENTLY. The leading lookahead (the flag must appear as a whole
        space-delimited token — see ``bash._TOKEN_SPACE``, which is what stops it being smuggled
        inside a neighbouring quoted argument) is kept VERBATIM.

    The adversarial judge is built without this grant, so it can never reach the store."""
    head = rf"{re.escape(py)} {re.escape(str(ticket_cli))}"
    return Grant(
        program="python3",
        pattern=re.compile(
            rf"^(?=(?:.* )?--require-closed(?: |$)){head} (?:list-tickets|get-ticket)(?: .*)?$"
        ),
        pins_path=True,
    )


# The judge's AgentDefinition (#538). The judge genuinely USES its tools — `cat` (operand-gated) piped
# into the sandboxed `defender-sql` over the ``gather_raw`` payloads, and ``read_file`` for the
# comparison files and everything else — so ``tools`` keeps the read + bash pair. ``operand_gated``
# marks that bash lane; ``raw_reads`` is DECLARED because the judge has neither ``adapters`` nor
# ``adapter_sql_pipe`` to imply it, yet ``gather_raw`` is the whole point of its bash surface. (The
# per-run read roots + benign closed-ticket pin ride the ``RunScope`` at bind, not this static def.)
# ``model``/``effort`` are the declarative stage defaults (glm-5.2 @ medium); each direction leg
# re-binds its own per-call model/effort in ``build_stage_agent``.
JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=lambda: JUDGE_MODEL,
    effort=JUDGE_EFFORT,
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_judge_bash_shapes,),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
)


def build_judge_agent(
    prompt_path: Path, model: str, effort: str,
    logger: observe.RequestLogger, agent_id: str,
    *, make_model: MakeModel = providers.build_for_effort,
) -> Agent[JudgeDeps, str]:
    """The judge's named build seam — a THIN DELEGATE to the shared ``build_stage_agent``
    (which wraps the single construction site ``build_agent_core``, #493/#538). The toolset comes
    from ``JUDGE_DEF`` (read + the ``cat``/``defender-sql`` bash lane; no writers, no gather
    dispatch). Its
    effort is per-DIRECTION-LEG config (not role-keyed), so the two legs can run concurrently at
    different efforts — re-bound onto the def per call. ``make_model`` is the DI seam tests use to
    inject a FunctionModel."""
    return build_stage_agent(
        JudgeDeps, prompt_path, model, effort, logger, agent_id, make_model=make_model,
    )


def _run_judge_pydantic(  # noqa: PLR0913 — the judge_fn protocol signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    scope: _ToolScope,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """The PydanticAI ``judge_fn`` — the judge_fn protocol signature, so it drops into
    ``invoke_judge(..., judge_fn=_run_judge_pydantic)``.

    Builds the judge's ``JudgeDeps`` via the single ``bind`` seam (#551) from a ``RunScope``
    carrying the tool ``scope`` (read roots = the comparison + gather_raw add-dirs; the benign
    closed-ticket paths) and delegates to the shared ``run_stage`` (agent build + one-shot drive
    + error mapping + trace logging). ``scope.add_dir`` is the ``JudgeInvocation.add_dirs`` list;
    ``None``/a lone Path (a direct unit call, unreachable in prod) → empty roots. The model's
    final text is returned VERBATIM: any prose preamble a reasoning model prepends is left
    intact for the shared ``normalize_judge_yaml`` on the downstream validate path (every judge
    consumer — the live loop and the secondary harness — funnels through it) to strip."""
    read_roots = tuple(scope.add_dir) if isinstance(scope.add_dir, list) else ()
    deps = bind(
        JUDGE_DEF, learning_run_dir,
        scope=RunScope(add_dirs=read_roots, ticket_cli=scope.ticket_cli),
    )
    return run_stage(
        stage="judge",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=JUDGE_REQUEST_LIMIT, make_model=make_model,
    )
