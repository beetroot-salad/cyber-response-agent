"""#950 — the two defects in the write-time close path, pinned as properties rather than lines.

Both are shapes that a reader has to notice, because nothing mechanical was watching for either:

  * **Every writer MAIN can call must be `sequential`.** Two `ToolCallPart`s in one model
    response run as concurrent tasks, so an unserialized writer is a lost update. `append_block`
    and `fix_row` carried `sequential=True` and a comment saying exactly why;
    `close_investigation` did not, and the value it loses is the DISPOSITION — `state.closed`
    is not set until `_commit` has already replaced report.md, so both calls pass the
    already-closed check, both run the review gate, and both write. Pinned over the whole
    writer roster and not over the one tool that was wrong, so the next writer added without
    the flag fails here.

  * **A closed-vocabulary check must refuse a non-string, not raise through it.** Both
    vocabularies live in hash-based containers (`frozenset` / `set`), so a model value spelled
    as a list or a mapping raised `TypeError: unhashable type` past the declared refusal —
    and past every caller, which catches only the declared class. Parametrized over both
    unhashable spellings AND the ordinary near-miss, so a fix that swallows everything
    (rather than refusing precisely) fails the positive control.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402

from defender.learning.core.validate import (  # noqa: E402
    RunUnprocessable,
    _validate_finding,
)
from defender.runtime import challenge_gate  # noqa: E402
from defender.runtime.close_tool import register_close_tool  # noqa: E402
from defender.runtime.review.projector import parse_investigation  # noqa: E402
from defender.runtime.review.reply import (  # noqa: E402
    HOLDS,
    Unreadable,
    citable_refs,
    read_composer_reply,
)
from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime.tools import AgentDeps, register_tools  # noqa: E402
from defender.tests._review_bundle import bundle, composer_reply  # noqa: E402

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3" / "investigation.md"

#: The tools that write ONE SHARED ARTIFACT — the roster this file's serialization rule is
#: about. A read-only tool running concurrently with anything is fine; two writers racing on one
#: file are not. Named here rather than derived, so adding a writer is a deliberate edit to this
#: list and not a silent exemption — which also means this list is the rule's whole reach, and a
#: new writer that never joins it is not checked. What is deliberately OUT: `bash` (writes only
#: inside the box) and `gather` (registered by `driver.build_agent` through
#: `register_gather_tool`, and it persists per `lead_id`, so its own docstring promises the
#: parallel dispatch that `sequential=True` would take away). `write_file`/`edit_file` are not
#: MAIN's — `MAIN_DEF.tools` carries `write=False` — but they are unserialized on the roles that
#: do grant them (CURATOR, LEAD_AUTHOR), which this roster cannot see.
WRITERS = ("append_block", "fix_row", "close_investigation")

#: Two ways a model spells a scalar field as a container. Both are unhashable, which is the
#: property that turned a refusal into a crash; `frozenset`/`set` membership raises on them.
UNHASHABLE = ([HOLDS], {"finding": HOLDS})


@pytest.fixture(scope="module")
def main_tools() -> dict:
    """MAIN's real tool roster, registered once: the whole writer surface in one place.

    `MAIN_DEF.tools`, not a ToolSet built here — the roster under test has to be the one the
    registry actually ships, or a writer that MAIN gains goes unchecked.

    The dict reaches a pydantic-ai private because `sequential` is not on any public surface —
    deliberate: the flag is the thing under test, and a framework rename should fail loudly here
    rather than silently stop checking."""
    agent = Agent("test", deps_type=AgentDeps)
    register_tools(agent, MAIN_DEF.tools)
    register_close_tool(
        agent,
        stages=bundle(composer=composer_reply(finding="holds")),
        bounds=challenge_gate.default_bounds(),
    )
    return dict(agent._function_toolset.tools)


# ── the writer serialization rule ────────────────────────────────────────────
def test_every_writer_main_can_call_is_sequential(main_tools):
    """The rule `append_block` and `fix_row` already followed, applied to the roster.

    A writer without the flag is a lost update whenever the model emits two tool calls in one
    response — for `close_investigation` that is the run's disposition, which report.md's
    frontmatter carries and the learning loop trains on."""
    missing = [
        n for n in WRITERS
        if n in main_tools and not getattr(main_tools[n], "sequential", False)
    ]
    assert not missing, (
        f"writer tool(s) {missing} are registered without sequential=True — two calls in one "
        f"model response would run concurrently and one write would be lost"
    )


def test_the_writer_roster_is_actually_registered(main_tools):
    """The control for the test above, whose `n in tools` guard would otherwise let a renamed
    or unregistered writer pass vacuously."""
    assert set(WRITERS) <= set(main_tools), f"expected {WRITERS} among {sorted(main_tools)}"


# ── the closed-vocabulary rule, both sites ───────────────────────────────────
@pytest.fixture(scope="module")
def refs():
    return citable_refs(parse_investigation(GOLDEN.read_text(encoding="utf-8")))


@pytest.mark.parametrize("finding", [*UNHASHABLE, "nonsense"], ids=["list", "dict", "near-miss"])
def test_a_non_member_finding_is_unreadable_however_it_is_spelled(finding, refs):
    """`Unreadable`, not `TypeError`. The crash escaped `challenge_gate` and
    `run_investigation` both, so the run ended with no report.md, no review record, and this
    stage's trace row still marked `ok: true`."""
    text = json.dumps({"finding": finding, "review": "the close holds", "ask": None})
    with pytest.raises(Unreadable):
        read_composer_reply(text, refs=refs)


def test_a_real_finding_still_reads(refs):
    """The positive control: the guard refuses precisely, it does not refuse everything."""
    text = json.dumps({"finding": HOLDS, "review": "the close holds", "ask": None})
    assert read_composer_reply(text, refs=refs).finding == HOLDS


@pytest.mark.parametrize("kind", [*UNHASHABLE, "nonsense"], ids=["list", "dict", "near-miss"])
def test_a_non_member_judge_type_is_run_unprocessable(kind):
    """The judge-side twin. The `TypeError` escaped `_validate_judge_yaml` BEFORE the
    `*.raw.txt` audit companion was written, losing the only record of what the judge said."""
    finding = {"type": kind, "subject_anchor": "v-001", "subject_topic": "topic",
               "finding": "prose", "citations": []}
    with pytest.raises(RunUnprocessable):
        _validate_finding(0, finding, {"gap", "lead-set"})


def test_a_real_judge_type_still_validates():
    """The positive control for the judge side."""
    finding = {"type": "lead-set", "subject_anchor": "v-001", "subject_topic": "topic",
               "finding": "prose", "citations": []}
    _validate_finding(0, finding, {"gap", "lead-set"})
