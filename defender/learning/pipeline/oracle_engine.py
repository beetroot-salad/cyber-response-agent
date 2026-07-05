"""The oracle stage on the in-process PydanticAI engine — a drop-in ``oracle_fn``.

Mirror of the actor's ``pipeline/actor_engine.py`` and the judge's
``pipeline/judge/engine_pydantic.py``: the oracle's specifics (its deps identity + a deny-all
permission policy) live here, and the generic in-process transport it shares with the actor +
judge lives in ``pipeline/_pydantic_stage.py``. The oracle is the THIRD consumer of that harness.

Unlike the actor/judge (one in-process call per direction), the oracle fans out ONE call per
lead concurrently (``pipeline/oracle/run.py``), so each per-lead call passes its own
``trace_name``/``label``: the ``ThreadPoolExecutor`` worker thread has no running event loop, so
``run_stage``'s ``asyncio.run`` bridge is safe per thread, and distinct per-lead trace names keep
the concurrent ``RequestLogger``s from racing on one file.

The oracle emits a single YAML document and calls NO tools — its whole input is inlined in the
user prompt — so its policy denies everything (the ``["bash", "read_file"]`` tools the shared
``build_agent_core`` always registers stay unused, gated shut). ``ORACLE_REQUEST_LIMIT`` is a
tiny backstop: a clean projection is one model request; the headroom only absorbs a stray denied
tool call GLM might attempt before it re-emits the YAML.

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when the oracle
actually runs (``core/subagents.ClaudePrintSubagents.oracle``), never at loop import.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import REPO_ROOT
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy
from defender.runtime.tools import RunDeps

# The oracle calls no tools, so a clean per-lead projection is a SINGLE model request. This cap is
# only a backstop: it leaves a little headroom for a stray tool call GLM might attempt (the
# deny-all policy bounces it with ModelRetry, costing one extra request) before it re-emits the
# YAML. Kept tiny — a genuinely looping oracle should quarantine the run, not burn a budget.
ORACLE_REQUEST_LIMIT = 6

_ORACLE_DENY_REASON = (
    "Blocked: the oracle is a pure per-lead projection — its entire input is inlined in the user "
    "prompt and its entire output is one YAML document. It runs no tools: no data-source adapters, "
    "no gather_raw reads, no writes, no shell. Emit the events YAML directly."
)


@dataclass(frozen=True)
class OracleDeps(RunDeps):
    """The oracle's per-run deps — plain ``RunDeps`` shape with a deny-all ``policy`` (data). One
    ``OracleDeps`` per lead; ``run_dir`` is the *learning* run dir, so the per-lead budget /
    observability side effects land there. ``role`` is an ORACLE identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.ORACLE


def _oracle_policy() -> AgentPolicy:
    """The oracle's declarative gate policy: deny everything. It projects one lead into a YAML diff
    from an all-inlined prompt — no adapters, no ``adapter | defender-sql`` pipe, no ``gather_raw``
    reads, no extra read roots, no custom matchers. Reads under ``defender_dir`` / the learning
    ``run_dir`` remain allowed by ``decide_read``'s defaults, but the oracle never issues one."""
    return AgentPolicy(
        adapters=False,
        adapter_sql_pipe=False,
        raw_reads=False,
        read_roots=(),
        custom_matchers=(),
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
    the oracle's deny-all ``OracleDeps`` and delegates to the shared ``run_stage`` (agent build +
    one-shot drive + error mapping + per-lead trace logging). Returns the model's final YAML text
    VERBATIM (``sample.parse_lead_events`` parses it downstream). A timeout / usage-limit / model
    error → ``RunUnprocessable`` (quarantines the run — the same disposition a ``claude -p``
    non-zero exit gave, which the per-lead fan-out surfaces as a whole-direction failure)."""
    deps = OracleDeps(
        run_dir=learning_run_dir,
        defender_dir=REPO_ROOT / "defender",
        run_id=learning_run_dir.name,
        salt=uuid.uuid4().hex,
        policy=_oracle_policy(),
    )
    return run_stage(
        stage="oracle",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ORACLE_REQUEST_LIMIT, make_model=make_model,
    )
