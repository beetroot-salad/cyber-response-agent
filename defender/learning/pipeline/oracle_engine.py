"""The oracle stage on the in-process PydanticAI engine — a drop-in ``oracle_fn``.

Mirror of the actor's ``pipeline/actor_engine.py`` and the judge's
``pipeline/judge/engine_pydantic.py``: the oracle's specifics (its deps identity + a locked-down
permission policy) live here, and the generic in-process transport it shares with the actor +
judge lives in ``pipeline/_pydantic_stage.py``. The oracle is the THIRD consumer of that harness.

Unlike the actor/judge (one in-process call per direction), the oracle fans out ONE call per
lead concurrently (``pipeline/oracle/run.py``), so each per-lead call passes its own
``trace_name``/``label``: the ``ThreadPoolExecutor`` worker thread has no running event loop, so
``run_stage``'s ``asyncio.run`` bridge is safe per thread, and a trace name keyed on the
per-direction discriminator AND the lead id keeps the concurrent ``RequestLogger``s from racing
on one file (see ``oracle/run.invoke_oracle``).

The oracle emits a single YAML document and calls NO tools — its whole input is inlined in the
user prompt. Since #538 that tool-freeness is STRUCTURAL: its ``ORACLE_DEF`` registers an empty
``ToolSet()`` (no ``read_file``, no ``bash``), so the pure per-lead projector has no tool to peek at
answer-bearing artifacts with — the barrier is closed by construction, not by the model choosing
never to call one — and the request cap drops to 1 (no tool can be called, so a clean projection is
exactly one model request). Its ``_ORACLE_POLICY`` stays deny-all as belt-and-suspenders.

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when the oracle
actually runs (``core/subagents.InProcessSubagents.oracle``), never at loop import.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import ORACLE_EFFORT, ORACLE_MODEL
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ToolSet
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy
from defender.runtime.tools import AgentDeps

# The oracle is TOOL-FREE (#538): ORACLE_DEF registers an empty toolset, so no tool can be called
# and a clean per-lead projection is exactly ONE model request — no headroom above 1 is needed
# (dropped 6→1). A genuinely looping oracle should quarantine the run, not burn a budget.
ORACLE_REQUEST_LIMIT = 1

_ORACLE_DENY_REASON = (
    "Blocked: the oracle is a pure per-lead projection — its entire input is inlined in the user "
    "prompt and its entire output is one YAML document. It runs no tools: no data-source adapters, "
    "no gather_raw reads, no writes, no shell. Emit the events YAML directly."
)


@dataclass(frozen=True)
class OracleDeps(AgentDeps):
    """The oracle's per-run deps — plain ``AgentDeps`` shape with the locked-down ``policy`` (data).
    One ``OracleDeps`` per lead; ``run_dir`` is the *learning* run dir, so the per-lead budget /
    observability side effects land there. ``role`` is an ORACLE identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.ORACLE

    @classmethod
    def for_run(cls, run_dir: Path) -> OracleDeps:
        """The oracle's front door: its policy is a STATIC constant (``_ORACLE_POLICY``, no
        per-lead scope), so the factory takes only ``run_dir``. Mirrors ``JudgeDeps``/``ActorDeps``
        ``for_scope`` over the base ``_for_run`` — the required policy is the backstop, this is the
        front door (and the one owner of the identity wiring across the three in-process stages)."""
        return cls._for_run(run_dir, _ORACLE_POLICY)


# The oracle's declarative gate policy. Unlike the actor/judge policies (parameterized per leg by
# their pinned scripts / read roots), the oracle's is a CONSTANT — it takes no per-lead input, so
# it is built once here rather than rebuilt on every fan-out call. It locks the tool surface down:
# no adapters, no ``adapter | defender-sql`` pipe, no ``gather_raw`` raw reads, no extra read
# roots, and an EMPTY ``bash_allow`` (no bash reader surface at all — #522). (Reads under
# ``defender_dir`` / the learning ``run_dir`` stay allowed by ``decide_read``'s defaults, but the
# oracle never issues one — its whole input is inlined.)
_ORACLE_POLICY = AgentPolicy(
    bash_allow=(),
    jq_operand_gated=False,
    adapters=False,
    adapter_sql_pipe=False,
    raw_reads=False,
    read_roots=(),
    deny_reason=_ORACLE_DENY_REASON,
)


# The oracle's AgentDefinition (#538): TOOL-FREE (``tools=ToolSet()`` — the build site registers
# nothing, closing the ``read_file`` answer-key affordance structurally). ``model``/``effort`` are the
# declarative stage defaults (glm-5.2, reasoning off); each fan-out call re-binds its own per-lead
# model/effort in ``build_stage_agent``. Collected into ``runtime.agents.AGENTS`` and used by the
# stage harness to register the empty toolset and by ``bind`` for the deny-all policy.
ORACLE_DEF = AgentDefinition(
    role=AgentRole.ORACLE,
    model=lambda: ORACLE_MODEL,
    effort=ORACLE_EFFORT,
    tools=ToolSet(),
    deny_reason=_ORACLE_DENY_REASON,
)


def _run_oracle_pydantic(  # noqa: PLR0913 — the oracle_fn protocol signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """The PydanticAI ``oracle_fn`` — drops into ``invoke_oracle_lead`` as ``oracle_fn=``. Builds
    the oracle's ``OracleDeps`` (via ``OracleDeps.for_run``, carrying the locked-down
    ``_ORACLE_POLICY``) and delegates to the shared ``run_stage`` (agent build + one-shot drive +
    error mapping + per-lead trace logging). Returns the model's final YAML text VERBATIM
    (``sample.parse_lead_events`` parses it downstream). A timeout / usage-limit / model error →
    ``RunUnprocessable`` (quarantines the run — the same disposition a ``claude -p`` non-zero exit
    gave, which the per-lead fan-out surfaces as a whole-direction failure)."""
    deps = OracleDeps.for_run(learning_run_dir)
    return run_stage(
        stage="oracle",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ORACLE_REQUEST_LIMIT, make_model=make_model,
    )
