"""#836 F-L / A5 / A7 — the rosters, the grants and the model-facing prose the new verb moves.

A second write verb on `investigation.md` is not one change. Phase A's grounding censused SIX
production sites that enumerate main's write verbs BY NAME (claim g6) and FOUR model-facing
prose sites that name `append_block` as the artifact's only writer (brief F13); the design's
M7 named one of the four. Roster #2 in that list — `compaction.apply_writes` — is DEAD CODE
and mints nothing (claim cp1: zero production callers, vulture-baselined UNWIRED, its only
live invocation an offline script outside `specGraph.codeRoots`).

What lands here:

  * the budget roster (`_MAIN_TAIL_TOOLS`, resolution R1) and what tail tier does and does
    NOT buy — claim bd6 REFUTED R1's stated payoff at the ceiling
  * `BUDGET_REFUSAL_MESSAGE`, which today names the wrong survivor set while a window is open
  * the e2e replay harness's own verb predicate — phase E cannot express a `fix_row` turn
    without it (brief F11), so the harness change is part of the spec rather than a detour
  * `visualize_data`'s by-name phase tagger (brief F10)
  * `scripts/lint/lint_vulture_baseline.json` — IN-REPO and CI-BLOCKING (brief F12); the
    answerer excused it as out-of-worktree config and the judge promoted it back
  * A5's grant decision: `fix_row` rides `append=True`, no new capability bit
  * the four prose sites, including `validate_investigation`'s over-bound remedy — which
    today offers the model a verb the M5 gate blocks

And the two negatives O3/SEC1 rest on: main is not re-granted the general write verbs, and no
bash construction reaches `investigation.md`.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from defender.tests._invlang_warn_836 import (
    DEFENDER,
    PROLOGUE,
    WARN_DOC,
    WARN_ROW,
    main_deps,
    offered_tool_names,
    seed_investigation,
)

REPO_ROOT = DEFENDER.parent
VULTURE_BASELINE = REPO_ROOT / "scripts" / "lint" / "lint_vulture_baseline.json"


def _squash(text: str) -> str:
    """SKILL.md is hard-wrapped, so every sentence this module asserts on spans lines. Compare
    on collapsed whitespace or the assertion is really about the wrap width."""
    return " ".join(text.split())


def _paragraph_containing(text: str, needle: str) -> str:
    """The blank-line-delimited paragraph carrying `needle` (HD-3,
    `.spec-flow/frontiers/94-hd-repairs.md`) — SKILL.md's own section granularity at prose
    altitude. Each paragraph is squashed independently before the search, so the hard-wrap
    that forces `_squash` on the whole file doesn't also erase the paragraph boundary the
    anchor needs. Raises if no paragraph carries it, same failure shape as a plain `in`."""
    for para in re.split(r"\n\s*\n", text):
        squashed = _squash(para)
        if needle in squashed:
            return squashed
    raise AssertionError(f"{needle!r} is not in any paragraph of the text")


def _registered_names(defn) -> set[str]:
    """The REGISTERED tool-name census, read off a real Agent — the same route
    `test_budget_seams_631._registered_names` uses, so registration is checked against what
    the framework actually dispatches rather than against a hand-kept list."""
    import os

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import driver, observe
    from defender.runtime.providers import BuiltModel
    from defender.runtime.tools import AgentDeps
    from defender.tests.e2e._replay_harness import ReplayFn

    logger = observe.RequestLogger(Path(os.devnull))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=defn.deps_cls or AgentDeps, instructions="probe", logger=logger,
            agent_id="probe",
            make_model=lambda name, effort: BuiltModel(FunctionModel(ReplayFn([])), None),
            limits=DEFAULT_LIMITS,
        )
    return set(agent._function_toolset.tools)


# A5 — which agents are offered the repair verb

def test_exactly_one_agent_definition_is_offered_record():
    """A5, superseded by #996 D14: `record` (not `fix_row`/`append_block` any more) rides
    `append=True` — no new capability bit, matching N4's posture of not widening the write
    surface — and exactly ONE definition in the tree grants it.

    Probe PR-12 censused it so the test is written against a census rather than a guess: nine
    non-test `ToolSet(` sites, and only `driver.py:298` (MAIN_DEF) sets `append=True` (claim
    bd10). The registry is what PICKS the subjects; what is asserted is that registration is
    genuinely WIRED to the grant — the third block drives a MAIN-shaped definition with
    `append=False` and observes the verb disappear, which a membership assertion alone could
    never see.

    The cost A5 accepted, and the reason this test exists: any future definition granted
    `append` silently gains a write verb on `investigation.md` that nobody decided to give
    it. This is the tripwire for that."""
    from defender.agents import AGENTS
    from defender.runtime.agent_role import AgentRole

    granting = {role for role, defn in AGENTS.items() if defn.tools.append}
    assert granting == {AgentRole.MAIN}

    main_names = _registered_names(AGENTS[AgentRole.MAIN])
    assert "record" in main_names
    assert "fix_row" not in main_names, "fix_row is retired from MAIN's roster (#996, D14)"
    assert "append_block" not in main_names, "append_block is retired from MAIN's roster (#996, D14)"

    ungranted = replace(
        AGENTS[AgentRole.MAIN], tools=replace(AGENTS[AgentRole.MAIN].tools, append=False)
    )
    without_append = _registered_names(ungranted)
    assert "record" not in without_append, "record registers without the append grant"
    assert "read_file" in without_append, "the whole roster vanished — a vacuous comparison"


# R1 — the budget roster, and what tail tier does and does not buy

def _budgeted(tmp_path, tool_calls: int):
    """A run dir whose real `budget.json` records `tool_calls` executed calls."""
    from defender.hooks.budget_enforcer import open_budget, update_budget_locked

    deps, run = main_deps(tmp_path)
    open_budget(run, run.name)
    for _ in range(tool_calls):
        update_budget_locked(run, run.name, "bash")
    return deps, run


def _short_circuit(deps, tool_name, limits):
    import os

    from defender.runtime import driver, observe

    logger = observe.RequestLogger(Path(os.devnull))
    return driver._budget_short_circuit(deps, tool_name, limits, logger, "main")


def test_budget_tripped_run_still_completes_repair_cycle(tmp_path):
    """Resolution R1: `fix_row` joins `_MAIN_TAIL_TOOLS`, so a run that trips its TOOL-CALL
    cap with an outstanding warning can still repair and close.

    Scoped to what claim bd1 actually shows — `should_refuse` never refuses a tail-tier tool,
    at the cap or with wall-clock tripped. The core-tier control in the same state is what
    makes the assertion mean something: `gather` is refused where `fix_row` is not.

    This roster change deliberately BREAKS `tests/test_budget_seams_631.py:456-457`, which
    pins the tail-tier set by exact equality. That is an update, never a weakening (claim
    g16), and the test below is what the updated expectation has to satisfy."""
    from defender.hooks.budget_enforcer import (
        BUDGET_EXEMPT_TOOLS,
        DEFAULT_LIMITS,
        should_refuse,
        tier,
    )
    from defender.runtime.agent_role import AgentRole

    assert tier("fix_row", AgentRole.MAIN) == "tail"
    assert "fix_row" not in BUDGET_EXEMPT_TOOLS, "R1 deliberately did NOT exempt it"

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 3}
    over_cap = {"tool_calls": 99, "started_monotonic": None}
    assert should_refuse(over_cap, "fix_row", tier("fix_row", AgentRole.MAIN), limits) is False
    assert should_refuse(over_cap, "gather", tier("gather", AgentRole.MAIN), limits) is True

    # ...and the whole cycle survives the cap: the repair lands and the close commits.
    deps, run = _budgeted(tmp_path, tool_calls=limits["max_tool_calls"] + 1)
    seed_investigation(run, WARN_DOC)
    assert _short_circuit(deps, "fix_row", limits) is None
    assert _short_circuit(deps, "close_investigation", limits) is None


def test_repair_verb_under_budget_pressure(tmp_path):
    """R1's accepted trade-off, and the boundary the design's own text does not state.

    `fix_row` is METERED, not exempt — a model looping on repairs is still stoppable. Probe
    PR-2 executed the consequence: `driver._budget_short_circuit` checks an UNCONDITIONAL
    `tail_exhausted` hard kill AHEAD of `should_refuse`, gated only by
    `BUDGET_EXEMPT_TOOLS = {close_investigation}` (claim bd2). So at
    `max_tool_calls + TAIL_ALLOWANCE` a tail-tier `fix_row` raises `BudgetKill` and the run
    ends unclosed, while `close_investigation` passes.

    That is precisely why O5 is SCOPED to "closable while the run is still taking turns"
    rather than stated unconditionally (claim bd6 REFUTED R1's "and can therefore still reach
    a close"). The positive control is the close's exemption in the same state.

    The tier assertion is part of the negative rather than decoration: "metered, not exempt"
    says nothing until `fix_row` is tail-tier in the first place — an unlisted verb is `core`
    and permanently refused by `should_refuse` long before the hard kill is reached, which is
    a different (and much earlier) death."""
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS, TAIL_ALLOWANCE, BudgetKill, tier
    from defender.runtime.agent_role import AgentRole

    assert tier("fix_row", AgentRole.MAIN) == "tail"

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 2}
    deps, run = _budgeted(tmp_path, tool_calls=limits["max_tool_calls"] + TAIL_ALLOWANCE)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(BudgetKill):
        _short_circuit(deps, "fix_row", limits)

    assert _short_circuit(deps, "close_investigation", limits) is None


def test_budget_stop_message_while_flagged(tmp_path):
    """`BUDGET_REFUSAL_MESSAGE` names the survivor set the model still has.

    Superseded by #996 (D14/D15): MAIN's repair round now runs INSIDE `record` rather than as
    a separate `fix_row` tool call, so the dead-end this test used to probe (told to close,
    then refused the close, while a window is open) cannot arise from the message naming the
    wrong verb — `record` is the one survivor, window open or not, and D15 forbids naming
    `fix_row`/`append_block` to MAIN at all (verbs its roster no longer holds).

    Asserted through `refusal_message`, the function that actually formats it for the model,
    with a real tripped state — not on the template constant alone."""
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS, refusal_message

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    text = refusal_message({"tool_calls": 99, "started_monotonic": None}, "gather", limits)

    assert "gather" in text, "the message is not about the refused tool at all"
    assert "record" in text, "the model is not told its one surviving document verb"
    assert "append_block" not in text, "D15: the message names a verb MAIN's roster lacks"
    assert "fix_row" not in text, "D15: the message names a verb MAIN's roster lacks"


# the remaining by-name rosters

def test_replay_harness_recognizes_fix_row_as_an_investigation_write():
    """Brief F11, and the one obligation this suite has ON ITSELF.

    Named for the property this suite's OWN harness fix must hold, not the pre-fix gap it
    closes: at `c0dca747`, `_replay_harness._is_investigation_write` keyed on
    `("write_file", "edit_file")` PLUS a path ending in `investigation.md`, and `fix_row`
    carries no path at all — so the project's declared e2e harness could not recognise a
    repair turn, and every `fix_row` scenario written outside it would be the parallel
    machinery the profile forbids. This test pins that the harness now DOES recognise it.

    Both directions are driven, because a predicate widened to `True` would pass the first
    assertion alone: the repair verb IS an investigation write, a `write_file` at another
    path is NOT, and the pre-existing recognitions still hold."""
    from defender.tests.e2e._replay_harness import _is_investigation_write

    assert _is_investigation_write("fix_row", {"old_row": WARN_ROW, "new_row": ""}) is True
    assert _is_investigation_write("append_block", {"text": "x"}) is True

    assert _is_investigation_write("write_file", {"path": "/run/notes.md"}) is False
    assert _is_investigation_write("read_file", {"path": "/run/investigation.md"}) is False
    assert _is_investigation_write("write_file", {"path": "/run/investigation.md"}) is True


def test_visualize_data_tags_fix_row_to_its_phase():
    """Brief F10, observability only: the demand is ROSTER MEMBERSHIP, not the drop
    behaviour. Named for the property asserted, not the pre-fix defect: `visualize_data`'s
    by-name filter drops any verb it does not know, so BEFORE this roster gains `fix_row` a
    repair turn would vanish from the phase attribution the run visualiser is built on. This
    test pins that `fix_row` IS recognised and correctly tagged; the control below — an
    actually-unrecognized verb — is the one that still gets mis-tagged/dropped.

    Driven through `tag_events_by_phase`, the public entry, so what is asserted is that the
    verb reaches the tagger AND that its own text field (`new_row`) is the one read —
    `append_block`'s `text` and `write_file`'s `content` are both already handled, and a
    roster entry with no field mapping would still drop it.

    The header-carrying `new_row` is synthetic: a real repair is one invlang row inside a
    fence and could not introduce a markdown heading. The tagger neither knows nor cares, and
    this is the only channel through which roster membership is OBSERVABLE rather than merely
    declared. The control below is an unknown verb, which must still be dropped."""
    from defender.scripts.visualize.visualize_data import tag_events_by_phase

    def event(name, args):
        return {"type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": f"t-{name}", "name": name,
                                         "input": args}]}}

    order = ["ORIENT the alert", "ANALYZE 1"]
    header = "## ANALYZE 1\nl-001|v-001|class|x"

    assert tag_events_by_phase(
        [event("fix_row", {"old_row": WARN_ROW, "new_row": header})], order,
    ) == ["ANALYZE 1"]
    assert tag_events_by_phase(
        [event("not_a_write_verb", {"new_row": header})], order,
    ) == ["ORIENT the alert"]


@pytest.mark.skip(
    reason="#996 D14 retired fix_row (and append_block) from MAIN's registered @agent.tool "
    "roster entirely -- record replaces both, and its repair round runs as an internal "
    "function call, never a second model-issued tool call. vulture correctly stopped "
    "flagging 'fix_row' as an unused-but-registered symbol because it is no longer "
    "registered at all, so the baseline entry this test pins is gone by design, not by "
    "omission -- see lint_vulture_baseline.json's own diff (2 dropped) and "
    "test_invlang_fix_row_836.py's _996_RETIRED_REASON for the sibling retirement."
)
def test_vulture_baseline_already_carries_the_fix_row_entry():
    """Brief F12: `scripts/lint/lint_vulture_baseline.json` is IN-REPO and its lint is
    CI-BLOCKING. Named for the property asserted, not the defect it forbids: a new
    `@agent.tool`-registered function looks unused to vulture — pydantic-ai dispatches it by
    tool NAME, never by symbol — so WITHOUT a baseline entry the gate would fail on a finding
    that is a false positive by construction. This test pins that the checked-in baseline
    ALREADY carries the `fix_row` entry, not that vulture flags its absence.

    The answerer excused this as "config outside this worktree"; that excuse belongs to
    `.claude/spec-flow.json`, not to a file the repo ships and CI reads. The judge promoted
    it back, and it is a demand rather than a chore because a spec that ships red CI is not
    shipped.

    The four sibling entries are asserted alongside so the shape of the required entry is
    read off the file rather than invented."""
    entries = json.loads(VULTURE_BASELINE.read_text(encoding="utf-8"))["entries"]
    tool_entries = {
        k for k in entries
        if k.startswith("defender/runtime/tools/__init__.py: unused function ")
    }

    assert any("'fix_row'" in k for k in tool_entries), (
        "no vulture baseline entry for the registration-only `fix_row` symbol — CI's vulture "
        f"lint blocks on it. Siblings present: {sorted(tool_entries)}"
    )
    assert {"'append_block'", "'read_file'"} <= {
        k.split("unused function ")[1].split(" (")[0] for k in tool_entries
    }


# A7 — the four model-facing prose sites

@pytest.mark.skip(
    reason="#996 D14/D15 retired MAIN's fix_row roster entry and rewrote SKILL.md's ANALYZE "
    "section to prose-only record() language — this test's exact-wording probes (naming "
    "`fix_row` to MAIN, the specific #810-era paragraph shape) test a surface the port "
    "deliberately removed. test_996_the_shipped_main_skill_is_prose_only and "
    "test_996_no_main_facing_text_instructs_row_syntax_or_a_lost_verb are its successors."
)
def test_model_facing_prose_updated_at_all_four_sites(tmp_path):
    """A7: FOUR model-facing sites, where M7 named one.

    Brief F13 found three in `defender/SKILL.md` — :419 ("`append_block` is its only
    writer"), :425 ("**A refusal means nothing was written**", which needs its warning-side
    counterpart), and :457 ("`append_block` reaches `investigation.md` and nothing else") —
    and the fourth is `validate_investigation`'s OVER-BOUND remedy, which today tells a model
    to "close the investigation on the evidence you already have". With a row flagged, M5
    refuses exactly that close, so the remedy names a verb the gate blocks; the deletion
    escape (`fix_row(old, "")`) is the one that actually shrinks the document.

    The two false sole-writer sentences are asserted GONE and the two new statements asserted
    PRESENT, because a prose site can be wrong by omission or by commission and only the pair
    catches both."""
    from defender._artifact_schema import INVESTIGATION_FILE_MAX, validate_investigation

    skill = _squash((DEFENDER / "SKILL.md").read_text(encoding="utf-8"))

    # sites 1 and 3 — the two sentences a second write verb makes false
    assert "`append_block` is its only writer" not in skill
    assert "`append_block` reaches `investigation.md` and nothing else" not in skill
    assert "fix_row" in skill, "the SKILL never names the verb the model is expected to call"

    # site 2 — the counterpart to "a refusal means nothing was written". HD-3
    # (`.spec-flow/frontiers/94-hd-repairs.md`) anchors this to the SAME PARAGRAPH as the
    # #810 sentence rather than word presence anywhere in a 500-line file — the obligation is
    # that THIS site gained the counterpart, not that the words appear somewhere. The property
    # pinned, not one fixed wording: a warning means the block DID land, and the next write is
    # BLOCKED until the row is repaired. `"block"`/`"refus"` are not used as load-bearing terms
    # — both already occur in this paragraph pre-#836 ("append_block", "fix the block and send
    # it again") and would pass vacuously.
    assert "A refusal means nothing was written" in skill, "the #810 half was dropped"
    site_425 = _paragraph_containing(
        (DEFENDER / "SKILL.md").read_text(encoding="utf-8"),
        "A refusal means nothing was written",
    ).lower()
    assert "warning" in site_425, (
        "site 425's own paragraph never gained a warning-side counterpart to the #810 "
        "sentence — a mention elsewhere in the file does not discharge this site"
    )
    assert "landed" in site_425 or "lands" in site_425, (
        "the warning-side counterpart never states the block DID land"
    )
    assert "blocked" in site_425, (
        "the warning-side counterpart never states the NEXT write is blocked until repaired"
    )
    assert "repair" in site_425, (
        "the warning-side counterpart never names repairing the row as what unblocks the "
        "next write"
    )

    # site 4 — the over-bound remedy, driven rather than read
    committed = PROLOGUE + "\n" + "x" * (INVESTIGATION_FILE_MAX - len(PROLOGUE) - 100)
    flagged_committed = WARN_DOC + "\n" + "x" * (
        INVESTIGATION_FILE_MAX - len(WARN_DOC) - 100
    )
    remedy = validate_investigation(flagged_committed + "y" * 300, flagged_committed)
    assert remedy is not None
    assert "fix_row" in remedy, (
        "the over-bound remedy offers only the close, which M5 refuses while a row is flagged"
    )
    # ...and with nothing flagged the remedy is unchanged from #810's wording.
    clean_remedy = validate_investigation(committed + "y" * 300, committed)
    assert clean_remedy is not None
    assert "close the investigation" in clean_remedy


# O3 / SEC1 — the grants the negative universal rests on

def test_main_is_not_regranted_write_file_or_edit_file():
    """N4: the repair window does not re-open the surface #810 closed on measurement.

    Main's `ToolSet` stays `read/bash/append/close` and `tools.write` stays False, so neither
    `write_file` nor `edit_file` registers — asserted on the REGISTERED roster rather than on
    the declaration, because registration is what the framework dispatches.

    Positive control: the one verb that IS added arrives, so the negative is not green
    because registration broke."""
    from defender.runtime.agent_definition import ToolSet
    from defender.runtime.driver import MAIN_DEF

    assert MAIN_DEF.tools == ToolSet(read=True, bash=True, append=True, close=True)
    assert MAIN_DEF.tools.write is False

    names = _registered_names(MAIN_DEF)
    assert "write_file" not in names
    assert "edit_file" not in names
    # #996, D14: `record` replaces both `append_block` and `fix_row`.
    assert {"record", "read_file", "bash"} <= names


def test_write_file_not_granted_to_main(tmp_path):
    """R3's minted per-cell negative: `investigation_md.access[write_file]` had no demand at
    all, unlike its bash sibling.

    `ToolSet.write` gates BOTH `write_file` and `edit_file` in `register_tools`, and MAIN_DEF
    sets `write=False` (claims r3/p9/g12), so neither can reach `investigation.md` by grant.
    Driven at the address rather than asserted on the flag: the tools are absent from the
    roster the model is OFFERED, and the one write verb that is granted is present."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    offered = offered_tool_names(deps)

    assert "write_file" not in offered
    assert "edit_file" not in offered
    # #996, D14: `record` replaces both `append_block` and `fix_row` — MAIN is never offered
    # `fix_row` directly any more, window open or not; the repair round runs inside `record`.
    assert "record" in offered
    assert "fix_row" not in offered


def test_bash_grant_cannot_construct_a_write_reaching_investigation_md(tmp_path):
    """O3/SEC1 are only as strong as this negative, which the brief stated with no claim
    behind it. Probe PR-6 executed it, and its correction is why the SQL lane is driven here
    too.

    rt4/rt5 hold: main's compiled `bash_allow` contains no writer-shaped grant, and every
    redirection form is denied at the permission gate AND independently at the tokenizer
    (`_PipelineBuilder.feed_token` raises on any `>` except `2>/dev/null` and `2>&1`).

    rt6 is the honest correction the obligation's own wording got wrong: `defender-sql` IS
    gate-ALLOWED to run write-shaped SQL, because its extractor is `OPENS_NOTHING` and the
    gate never parses the SQL argument. What actually refuses is duckdb's own
    `enable_external_access=false` + `lock_configuration=true` inside
    `scripts/gather_tools/sql.py` — a module the obligation never named. A test that stopped
    at `decide_bash` would pin a boundary that is not where the safety lives, so the SQL lane
    is EXECUTED for real and the artifact checked on disk afterwards.

    The positive control is the last block: a sanctioned reader command IS allowed, so the
    denials are about writing rather than about an empty grant set."""
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.driver import MAIN_DEF

    deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, WARN_DOC)
    before = inv.read_bytes()
    policy = compile_policy_for(MAIN_DEF, run, defender_dir=deps.defender_dir)

    def decide(cmd):
        return permission.decide_bash(
            cmd, policy=policy, run_dir=run, defender_dir=deps.defender_dir,
            cwd_anchor=deps.cwd_anchor,
        )

    for cmd in (
        f"echo x > {inv}",
        f"cat /etc/hostname >> {inv}",
        f"printf x > {inv}",
        f"sed -i s/a/b/ {inv}",
        f"tee {inv}",
        f"cp /etc/hostname {inv}",
        f"mv /etc/hostname {inv}",
        f"dd of={inv}",
        f"python3 -c open('{inv}','w')",
        f"rm {inv}",
    ):
        assert decide(cmd).allow is False, cmd

    # rt6 — the gate ALLOWS write-shaped SQL; duckdb's locked configuration is the boundary.
    sql = f"COPY (SELECT 1 AS a) TO '{inv}' (FORMAT CSV)"
    assert decide(f"defender-sql \"{sql}\"").allow is True, (
        "the permission gate started parsing SQL — rt6's correction no longer applies and "
        "this test is pinning the wrong boundary"
    )
    proc = subprocess.run(
        [sys.executable, str(DEFENDER / "scripts" / "gather_tools" / "sql.py"), sql],
        input=b'[{"a": 1}]', capture_output=True, check=False,
    )
    assert proc.returncode != 0, "duckdb executed a write-shaped statement"
    assert inv.read_bytes() == before

    # ...and a sanctioned reader on the same lane IS allowed.
    assert decide(f"cat {inv}").allow is True
