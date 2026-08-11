"""Shared fixtures and drivers for the #836 suite — warn severity, the repair window, `fix_row`.

Five test modules import this one:

    test_invlang_warn_severity_836.py   M1/M2 — Diagnostic.severity and the three validators
    test_invlang_warn_window_836.py     M3/M5 — the derived window and the gate
    test_invlang_fix_row_836.py         M4    — the repair verb
    test_invlang_ident_key_836.py       M6    — `ident` becomes a legal refinement key
    test_invlang_warn_rosters_836.py    the six by-name rosters, the grants, the prose

Nothing here is a test. The fixtures below were EXECUTED against the real `diagnose` at
c0dca747 while this file was written, and each one's recorded diagnostic set is stated in its
comment — a fixture that quietly carried a second fault would let a weaker implementation pass
every `_only`-shaped assertion in the suite (the lesson `test_the_bad_key_is_the_documents_only
_fault` records for #810's sibling suite).

TWO FIXTURE FACTS ARE LOAD-BEARING AND EASY TO GET WRONG:

  * the warn-family key is `owner` / `dept`, never `ident`. M6 makes `ident` LEGAL, so a
    fixture keyed on `ident` stops being flagged the moment M6 lands and every window test
    built on it goes green by vacuity. `owner` and `dept` are outside `class` / `attrs.*` /
    `ident` and stay flagged after M6 — this is the doc's own accepted risk ("M1 upgrades the
    CHECK, not the measured `ident` population") made into a fixture rule.
  * every `:R attr_updates` row targets a vertex the `:V` block DECLARES. H8 mints a refusal
    for a refinement naming an undeclared vertex (PR-11: today it lands with zero diagnostics
    and `_effective_vertex_state` fabricates the vertex), so an undeclared target would add a
    SECOND, error-severity diagnostic and turn a warn-only fixture into a refused one.

Symbols this spec MINTS are imported inside function bodies, never at module scope: the suite
must still COLLECT against `c0dca747`, where `warn_diagnostics` and `_tool_fix_row` do not
exist yet. Red is the expected state of a spec; an uncollectable file is not.

Underscore-prefixed so pytest does not collect it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

import pytest  # noqa: E402

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import challenge_gate, driver, observe  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.tests import _review_bundle  # noqa: E402
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


# --------------------------------------------------------------------------- #
# documents
# --------------------------------------------------------------------------- #

#: Two declared vertices and one lead. EXECUTED: `diagnose(PROLOGUE, None) == []`.
PROLOGUE = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
v-002|identity|user/known-corp|jsmith|

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-lookup|v-001||cmdb|n/a
```
"""

#: The warn-family row: a refinement key outside `class` / `attrs.*` / (post-M6) `ident`.
WARN_ROW = "l-001|v-001|owner|svc.config-mgmt"
#: A SECOND, textually distinct warn-family row, on the other declared vertex.
SECOND_WARN_ROW = "l-001|v-002|dept|finance"
#: What `WARN_ROW` becomes under the validator's own first `use:` alternative for it.
REPAIRED_ROW = "l-001|v-001|class|svc.config-mgmt"
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


#: EXECUTED: exactly one diagnostic, the `owner` refinement-key finding, and
#: `validate_investigation` REFUSES it at c0dca747. M1/M2 are what make it land.
WARN_DOC = PROLOGUE + attr_block(WARN_ROW)

#: EXECUTED: zero diagnostics, and `validate_investigation` accepts it today and after #836.
CLEAN_BLOCK = attr_block(REPAIRED_ROW)


# --------------------------------------------------------------------------- #
# the window, read through the function this spec mints
# --------------------------------------------------------------------------- #

def warn_window(text: str) -> tuple[Any, ...]:
    """`warn_diagnostics(text)` — M3's derived window, imported here so the suite still
    collects on a tree that does not have it yet.

    The module is `defender.skills.invlang.validate`, the module that already owns
    `Diagnostic` and `diagnose`: claim g5 censused exactly one consumer of `Diagnostic`
    outside it, so putting the derivation anywhere else would give the type a second
    importer for no reason. An implementation that spells the name otherwise makes
    `check_binds` skip the concept silently — that is why the name is pinned here."""
    from defender.skills.invlang.validate import warn_diagnostics

    return tuple(warn_diagnostics(text))


def flagged_rows(text: str) -> tuple[str, ...]:
    """The flagged set as `fix_row` addresses it: one `Locus.row_text` per warn diagnostic.

    `row_text` — NOT the on-disk line. `_tokenize_fence` (parser.py:90) strips every row
    before `Locus.row_text` is populated, so the two differ exactly when the on-disk line
    carries leading or trailing whitespace (claim pr1b, REFUTED byte-equality there)."""
    return tuple(d.locus.row_text for d in warn_window(text) if d.locus is not None)


# --------------------------------------------------------------------------- #
# deps and the run dir
# --------------------------------------------------------------------------- #

def main_deps(tmp_path: Path) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam — real compiled policy, real gate.

    Same shape `test_append_only_write_lane_810.py::_main_deps` uses, so the two suites
    exercise one construction path rather than two."""
    run = tmp_path / "run"
    run.mkdir(parents=True)
    dfn = tmp_path / "defender"
    dfn.mkdir(parents=True)
    return bind(MAIN_DEF, run, defender_dir=dfn), run


def seed_investigation(run_dir: Path, text: str) -> Path:
    """Put `text` on disk as the run's investigation.md, bypassing the write verbs.

    Deliberately not through `append_block`: several scenarios need a document the write
    gate would refuse TODAY (a warn-only one) as their STARTING state, and staging it
    through the verb under test would make the fixture depend on the mechanism it is
    there to exercise."""
    p = run_dir / "investigation.md"
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# driving a real MAIN agent
# --------------------------------------------------------------------------- #

class _Recorder:
    """A FunctionModel callable that records the tool definitions the model was SHOWN.

    `prepare=` filters per-request OFFERS, never registration, so "which tools exist on the
    agent" cannot see it — `AgentInfo.function_tools` is the channel that can, and it is the
    one probe b6/p7 executed at the pinned floor (pydantic-ai-slim 1.107.0)."""

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

    `build_agent` rather than `build_agent_core`: `close_investigation` is registered by the
    root, not the core, and half the #836 gate lives on the close path."""
    logger = observe.RequestLogger(Path(os.devnull))
    stages = review_stages if review_stages is not None else _review_bundle.bundle(
        composer=_review_bundle.composer_reply("holds")
    )
    with override_allow_model_requests(False):
        return driver.build_agent(
            DEFENDER, logger,
            make_model=lambda name, effort: BuiltModel(FunctionModel(model_fn), None),
            review_stages=stages, bounds=challenge_gate.default_bounds(),
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

    This is the shape PR-5 executed at the pinned floor: `Turn(tool_calls=[a, b])` becomes a
    single `ModelResponse` with two `ToolCallPart`s, which at pydantic-ai-slim 1.107.0 run
    CONCURRENTLY by default (rt1 REFUTED the sequential reading) and lose one of the two
    writes against the real `write_guarded` primitive (rt2). H6 sets `sequential=True` on the
    write verbs; this is how a scenario observes it."""
    import asyncio

    agent = build_main_agent(ReplayFn([Turn(tool_calls=calls), Turn(text="done")]))
    with override_allow_model_requests(False):
        return asyncio.run(agent.run("probe", deps=deps))


class RecordingStages:
    """A review bundle that COUNTS its stage calls.

    The gate's cost is the thing H5's ordering buys: a close refused for a flagged row must
    never have spent a lens. A bundle that only answers cannot observe that, so this one
    records — the `_review_bundle` docstring's own note that a scenario wanting to inspect
    what reached a role binds its own recording stage."""

    def __init__(self, composer: str = "holds") -> None:
        self.calls: list[str] = []
        self._composer = _review_bundle.composer_reply(composer)

    def _stage(self, role: str, reply: str) -> Any:
        async def call(_request: Any) -> str:
            self.calls.append(role)
            return reply

        return call

    def bundle(self) -> Any:
        from defender.runtime.review_roles import ReviewStages

        return ReviewStages(
            support=self._stage("support", _review_bundle.LENS_READING),
            ablation=self._stage("ablation", _review_bundle.LENS_READING),
            composer=self._stage("composer", self._composer),
        )


def recording_stages(composer: str = "holds") -> RecordingStages:
    return RecordingStages(composer)
