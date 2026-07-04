"""The judge on the in-process PydanticAI engine — a drop-in ``judge_fn``.

The judge was the first learning-loop agent to run in-process on PydanticAI rather than
the shared ``claude -p`` transport. Everything judge-specific lives HERE, in the judge's own
directory: its deps identity, its permission policy (data), its one bit of custom logic (the
benign closed-ticket matcher), and its thin ``judge_fn``. The generic in-process transport it
shares with the actor — agent construction, the request-capped one-shot drive, the
error-mapping ladder — lives in ``pipeline/_pydantic_stage.py``; this module only supplies the
judge's specifics and delegates.

This module pulls the pydantic-ai graph (via ``_pydantic_stage``), so it is imported LAZILY —
only when a judge actually runs (``core/subagents.ClaudePrintSubagents.judge``), never at loop
import.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from defender.learning.core.config import REPO_ROOT
from defender.learning.pipeline._pydantic_stage import build_stage_agent, run_stage
from defender.runtime import observe, providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy, BashDecision, command_shape
from defender.runtime.tools import RunDeps

from pydantic_ai import Agent

if TYPE_CHECKING:
    from defender.runtime.bash_exec import Pipeline

    from .run import _ToolScope

# Bounds a runaway tool loop (the twin of the gather's per-lead cap). Sized for GLM's
# tool-hunger: GLM issues ~2-3 tool calls per model request and surveys gather_raw per lead
# (ls/wc/jq) before its verdict — a live smoke run saw the benign judge reach 25/30 and the
# adversarial judge hit 30/30 (29 DISTINCT tool calls, no spin — legitimate grounded work) and
# dead-letter the run on a 7-lead case. Raised to 45 for multi-lead headroom (still a backstop,
# not a budget). Reducing GLM's tool-call count at the source is tracked in #514.
JUDGE_REQUEST_LIMIT = 45

_JUDGE_DENY_REASON = (
    "Blocked: the judge is read-only over the grounded evidence — jq (path-gated to its "
    "read roots) over the comparison files and gather_raw payloads, and read_file (with "
    "an optional grep pattern) for everything else, plus — benign only — the pinned "
    "closed-ticket read. No cat/grep/ls in bash, no data-source adapters, no writes, no "
    "arbitrary shell."
)


@dataclass(frozen=True)
class JudgeDeps(RunDeps):
    """The judge's per-run deps. Identical shape to ``RunDeps`` (run_dir, defender_dir,
    run_id, salt, policy) — the judge's read roots and its custom matcher ride in
    ``policy`` (data), not in extra deps fields. ``run_dir`` is the *learning* run dir
    (the judge's own output dir), so budget/lesson-load side effects land there and the
    judge can only reach gather_raw via its policy read roots, never roam the whole
    investigation run dir. ``role`` is a JUDGE identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.JUDGE


def _make_ticket_matcher(py: str, ticket_cli: Path):
    """The benign judge's one bit of custom logic (issue #338): allow the scoped,
    CLOSED-ONLY case-history read that confirms a cited past case. Claims exactly a
    single-stage ``<py> <ticket_cli> {list-tickets|get-ticket} … --require-closed …``
    invocation — `py`/`ticket_cli` pinned (exact absolute strings from
    ``build_judge_invocation``), and ``--require-closed`` REQUIRED (the security property
    that the open in-flight ticket stays unreachable rides on that flag). Anything else
    declines (`None`) and falls through to the generic gate, which denies it (``<py>
    <ticket_cli> …`` is not a read-only viewer). The adversarial judge is built with no
    matchers, so it can never reach the store."""
    py_s, cli_s = str(py), str(ticket_cli)

    def _match(pipelines: list[Pipeline]) -> BashDecision | None:
        argv = command_shape.single_stage_argv(pipelines)  # a single command, never a pipe/compound
        if argv is None:
            return None
        if len(argv) < 3 or argv[0] != py_s or argv[1] != cli_s:
            return None
        if argv[2] not in ("list-tickets", "get-ticket"):
            return None
        if "--require-closed" not in argv:
            return None
        return BashDecision(True, pipelines=tuple(pipelines))

    return _match


def _judge_policy(read_roots: tuple[Path, ...], ticket_cli: tuple[str, Path] | None) -> AgentPolicy:
    """The judge's declarative gate policy: read-only, may `jq`/read gather_raw
    (raw_reads) + its comparison dir (read_roots), never runs a data-source adapter,
    and — benign only — carries the pinned closed-ticket matcher as its custom logic.

    ``bash_readers=('jq',)`` (#512): in the bash lane ONLY `jq` survives, and it is
    path-gated to the judge's read roots (every file it opens must resolve within
    them — closing the reader surface as an out-of-roots read oracle). cat/grep/head/
    tail/ls fold into `read_file` (with its optional grep `pattern`). The judge is
    UNCONFINED this slice (no ``read_confine``), so its roots stay
    ``{run_dir, defender_dir, *read_roots}``."""
    matchers = (_make_ticket_matcher(*ticket_cli),) if ticket_cli is not None else ()
    return AgentPolicy(
        adapters=False,
        adapter_sql_pipe=False,
        raw_reads=True,
        read_roots=read_roots,
        bash_readers=("jq",),
        custom_matchers=matchers,
        deny_reason=_JUDGE_DENY_REASON,
    )


def build_judge_agent(
    prompt_path: Path, model: str, effort: str,
    logger: observe.RequestLogger, agent_id: str,
    *, make_model: MakeModel = providers.build_for_effort,
) -> Agent[JudgeDeps, str]:
    """The judge's named build seam — a THIN DELEGATE to the shared ``build_stage_agent``
    (which wraps the single construction site ``build_agent_core``, #493). ``writers=False``
    → the bash + read_file pair only (no writers, no gather dispatch). Its effort is
    per-DIRECTION-LEG config (not role-keyed), so the two legs can run concurrently at
    different efforts — the reason the judge builds its own spec rather than going through
    ``spec_for_role``. ``make_model`` is the DI seam tests use to inject a FunctionModel."""
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

    Builds the judge's ``JudgeDeps`` from the tool ``scope`` (read roots = the comparison +
    gather_raw add-dirs; the benign closed-ticket paths) and delegates to the shared
    ``run_stage`` (agent build + one-shot drive + error mapping + trace logging). The model's
    final text is returned VERBATIM: any prose preamble a reasoning model prepends is left
    intact for the shared ``normalize_judge_yaml`` on the downstream validate path (every judge
    consumer — the live loop and the secondary harness — funnels through it) to strip."""
    # scope.add_dir is the JudgeInvocation.add_dirs list (invoke_judge is the sole
    # constructor of a judge _ToolScope), None only in a direct unit call → empty roots.
    read_roots = tuple(scope.add_dir) if isinstance(scope.add_dir, list) else ()
    deps = JudgeDeps(
        run_dir=learning_run_dir,
        defender_dir=REPO_ROOT / "defender",
        run_id=learning_run_dir.name,
        salt=uuid.uuid4().hex,
        policy=_judge_policy(read_roots, scope.ticket_cli),
    )
    return run_stage(
        stage="judge",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=JUDGE_REQUEST_LIMIT, make_model=make_model,
    )
