"""Shared fixtures and drivers for the #836 suite — warn severity, the repair window, `fix_row`."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import os
from dataclasses import replace
import sys
from pathlib import Path
from typing import Any

DEFENDER = Path(__file__).resolve().parents[4]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

import pytest  # noqa: E402

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.agents import MAIN_DEF  # noqa: E402
from defender.investigation import challenge_gate, driver, observe  # noqa: E402
from defender.investigation.run_state import RunState  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.tests.support.runtime.permissions import _review_bundle
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.e2e._replay_harness import ReplayFn, Turn  # noqa: E402

__all__ = [
    "CLEAN_BLOCK",
    "CONCLUDE_BENIGN",
    "DEFENDER",
    "PROLOGUE",
    "REPAIRED_ROW",
    "REPAIRED_ROW_ATTRS",
    "SECOND_WARN_ROW",
    "WARN_DOC",
    "WARN_ROW",
    "attr_block",
    "build_main_agent",
    "flagged_rows",
    "main_deps",
    "offered_tool_defs",
    "offered_tool_names",
    "recording_stages",
    "run_one_response",
    "seed_investigation",
    "warn_window",
]


# documents

#: Two declared vertices and one lead; `diagnose(PROLOGUE, None) == []`.
PROLOGUE = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
v-002|identity|user/known-corp|jsmith|

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-lookup|v-001||cmdb|n/a
```
"""

#: The warn-family row: a refinement key outside `class` / `attrs.*` / `ident`.
WARN_ROW = "l-001|v-001|owner|svc.config-mgmt"
#: A SECOND, textually distinct warn-family row, on the other declared vertex.
SECOND_WARN_ROW = "l-001|v-002|dept|finance"
#: A legal `class` repair of `WARN_ROW`, hand-written: the validator's own `class` offer keeps
#: the author's value, which `compute.role` refuses (#986), so it withholds that route and
#: offers only `REPAIRED_ROW_ATTRS`. Tests feeding this row exercise `fix_row`'s mechanics on a
#: row that lands; `test_class_vocab_986` puts the offered routes back through the validator.
REPAIRED_ROW = "l-001|v-001|class|file-server/internal/known-corp"
#: The other legal repair — the `attrs.<name>` spelling. Keeps the VALUE cell verbatim.
REPAIRED_ROW_ATTRS = "l-001|v-001|attrs.owner|svc.config-mgmt"

#: A `:T conclude` claiming the one disposition with a structural gate (`benign`).
CONCLUDE_BENIGN = """
```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      routine-admin-login
summary                "Login matched established bastion usage"
```
"""


def attr_block(*rows: str) -> str:
    """One `:R attr_updates` block declaring the conventional four-column header."""
    body = "\n".join(rows)
    return (
        "\n```invlang\n:R attr_updates [resolved_by|target|key|value]\n"
        + (body + "\n" if body else "")
        + "```\n"
    )


#: Exactly one diagnostic, the warn-severity `owner` refinement-key finding;
#: `validate_investigation` accepts it.
WARN_DOC = PROLOGUE + attr_block(WARN_ROW)

#: Zero diagnostics; `validate_investigation` accepts it.
CLEAN_BLOCK = attr_block(REPAIRED_ROW)


# the warn window

def warn_window(text: str) -> tuple[Any, ...]:
    """`warn_diagnostics(text)`: the repair window derived from the document's bytes."""
    from defender.skills.invlang.validate import warn_diagnostics

    return tuple(warn_diagnostics(text))


def flagged_rows(text: str) -> tuple[str, ...]:
    """The flagged set as `fix_row` addresses it: one `Locus.row_text` per warn diagnostic.

    `row_text` is the stripped row, not the on-disk line: the two differ when the line
    carries leading or trailing whitespace."""
    return tuple(d.locus.row_text for d in warn_window(text) if d.locus is not None)


# deps and the run dir

def main_deps(tmp_path: Path) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam — real compiled policy, real gate — built as
    `test_append_only_write_lane_810.py::_main_deps` builds them."""
    # A run folder's name is its canonical UUID run id (#1187).
    run = tmp_path / fixture_uuid("run")
    run.mkdir(parents=True)
    dfn = tmp_path / "defender"
    dfn.mkdir(parents=True)
    # Carries run state, as every MAIN the driver builds does: the enforced budget hooks raise
    # on deps without it (#1235).
    from defender.records import Run

    return replace(bind(MAIN_DEF, run, defender_dir=dfn),
                   run=Run.under(fixture_runs_base(run.parent), run.name), run_state=RunState(run, "r-836")), run


def seed_investigation(run_dir: Path, text: str) -> Path:
    """Put `text` on disk as the run's investigation.md, bypassing the write verbs, so a
    scenario's starting state never depends on the verb under test."""
    p = run_dir / "investigation.md"
    p.write_text(text, encoding="utf-8")
    return p


# driving a real MAIN agent

class _Recorder:
    """A FunctionModel callable that records the tool definitions the model was SHOWN.

    `prepare=` filters per-request offers, not registration, so only
    `AgentInfo.function_tools` sees its effect."""

    __name__ = "Recorder"

    def __init__(self, turns: list[Turn] | None = None) -> None:
        self._replay = ReplayFn(turns or [])
        self.offered: list[list[Any]] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        self.offered.append(list(info.function_tools))
        return self._replay(messages, info)

    @property
    def last_offer(self) -> list[Any]:
        assert self.offered, "the model was never called — nothing was offered"
        return self.offered[-1]


def build_main_agent(model_fn: Any, *, review_stages: Any = None) -> Any:
    """MAIN's real agent, built through the real composition root, with a fake model.

    `build_agent`, not `build_agent_core`: only the root registers `close_investigation`."""
    logger = observe.RequestLogger(Path(os.devnull))
    stages = review_stages if review_stages is not None else _review_bundle.bundle(
        composer=_review_bundle.composer_reply("holds")
    )
    with override_allow_model_requests(False):
        return driver.build_agent(
            DEFENDER, logger,
            make_model=lambda name, effort: BuiltModel(FunctionModel(model_fn), None),
            review_stages=stages, bounds=challenge_gate.default_bounds(), catalog=None,
            gather_grant=driver.GATHER_DEF.verb_grant,
        )


def offered_tool_defs(deps: Any, *, turns: list[Turn] | None = None) -> list[Any]:
    """Run ONE real model request against MAIN's real agent and return the ToolDefinitions
    the model was offered on it."""
    import asyncio

    recorder = _Recorder(turns or [Turn(text="done")])
    agent = build_main_agent(recorder)
    with override_allow_model_requests(False):
        asyncio.run(agent.run("probe", deps=deps))
    return recorder.last_offer


def offered_tool_names(deps: Any, *, turns: list[Turn] | None = None) -> list[str]:
    """The names of the tools the model was offered on one real request."""
    return [t.name for t in offered_tool_defs(deps, turns=turns)]


def run_one_response(deps: Any, calls: list[tuple[str, dict]]) -> Any:
    """Drive MAIN's real agent with a model that emits ONE model response carrying every
    call in `calls`, then stops.

    pydantic-ai runs one response's tool calls concurrently unless the tool is
    `sequential=True`, as the write verbs are; this is how a scenario observes that."""
    import asyncio

    agent = build_main_agent(ReplayFn([Turn(tool_calls=calls), Turn(text="done")]))
    with override_allow_model_requests(False):
        return asyncio.run(agent.run("probe", deps=deps))


class RecordingStages:
    """A review bundle that COUNTS its stage calls, so a scenario can assert that a close
    refused for a flagged row never spent a lens."""

    def __init__(self, composer: str = "holds") -> None:
        self.calls: list[str] = []
        self._composer = _review_bundle.composer_reply(composer)

    def _stage(self, role: str, reply: str) -> Any:
        async def call(_request: Any) -> str:
            self.calls.append(role)
            return reply

        return call

    def bundle(self) -> Any:
        from defender.investigation.review_roles import ReviewStages

        return ReviewStages(
            support=self._stage("support", _review_bundle.LENS_READING),
            ablation=self._stage("ablation", _review_bundle.LENS_READING),
            composer=self._stage("composer", self._composer),
        )


def recording_stages(composer: str = "holds") -> RecordingStages:
    return RecordingStages(composer)
