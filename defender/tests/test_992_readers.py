"""#992 — the readers of the change: the investigator's prompt, the close tool's registered
description, and the run page's reviewed/unreviewed split (O2, M1's O2 half, d22 under §7
FK-8/FK-14).

Every test here is one demand of `spec-flow/specs/spec_graph_992.yaml`, named by that demand's
`discharged_by`. RED against 67d29090 is the expected state: SKILL.md and the tool docstring
still say `inconclusive` commits unreviewed, and `visualize_runtime._was_reviewed` splits
attempts on the `NO_REVIEW_DISPOSITIONS` constant (G17), so no reviewed `inconclusive` run dir
can render as reviewed today.

THE TWO POPULATIONS (§7 FK-8 + FK-14, human, with the judge): a POST-CHANGE reviewed
`inconclusive` dir is driven through the real close, and a PRE-#992 one is written by hand to
the bypass's observed shape — record `stands`/`inconclusive`, cause `CAUSE_NOT_REVIEWED`, no
`wire_logs/` (G17/x1). The five Measurement run dirs are the second population. Every reader
keyed on the split must give the same answer per population, on old and new dirs alike.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from defender.runtime.challenge_gate import REVIEW_ROLES
from defender.runtime.close_tool import (
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_NOT_REVIEWED,
    CAUSE_TURN_BUDGET_SPENT,
    STANDS,
    register_close_tool,
)
from defender.scripts.visualize.visualize_run import _gate_badge_html
from defender.scripts.visualize.visualize_runtime import (
    _BYPASS_NOTE, _PRE_RECORD_NOTE, render_review_gate,
)
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests._spec992 import (
    CEILING_EXAMINED,
    DEFENDER,
    CONFIDENT,
    GAP,
    bounds,
    ceiling_companion,
    close_with,
    deps_over,
    frontmatter,
    gap,
    holds,
    parsed_report,
    pre_change_inconclusive_dir,
    record,
    recording,
    reviewed_inconclusive_dir,
    trace_files,
)

SKILL_MD = DEFENDER / "SKILL.md"

#: The bypass sentences the investigator reads today (SKILL.md:521-522, :553) and the tool
#: docstring's (close_tool.py:778-779), each of which becomes false after M1.
BYPASS_PHRASES = (
    "Commits immediately, no review",
    "anything but `inconclusive`",
    "A confident disposition passes a live challenge gate",
)


def _bullet(skill: str, member: str) -> str:
    """One member's own paragraph in SKILL.md §REPORT's roster, whitespace-folded."""
    m = re.search(rf"- `{member}` — (?P<body>.*?)(?=\n- `|\n\n)", skill, re.DOTALL)
    assert m, f"SKILL.md no longer carries a `{member}` roster entry"
    return " ".join(m.group("body").split())


class _ToolRecorder:
    """The `agent` argument `register_close_tool` decorates onto — records the function it
    registers, so the description the model is offered can be read off the real registration
    path without a provider."""

    def __init__(self) -> None:
        self.registered: list[Any] = []

    def tool(self, **_kw):
        def decorate(fn):
            self.registered.append(fn)
            return fn

        return decorate


def test_investigator_prompt_states_the_review(tmp_path):
    """The investigator's system prompt no longer says `inconclusive` commits immediately with
    no review; it says an `inconclusive` close is reviewed against its ceiling claim and may
    come back challenged with one ask like any other close, keeps `unresolved` as the host's
    verdict never written by the model (every roster naming the four members keeps it — G15),
    keeps 'do not pre-emptively call `inconclusive` to route around a challenge', and the close
    tool's own docstring says the same."""
    skill = SKILL_MD.read_text(encoding="utf-8")
    folded = " ".join(skill.split())
    for phrase in BYPASS_PHRASES[:2]:
        assert phrase not in folded, f"SKILL.md still says {phrase!r}"
    bullet = _bullet(skill, "inconclusive").lower()
    assert "review" in bullet, bullet
    assert "challenge" in bullet, bullet
    assert "ceiling" in bullet
    host_bullet = _bullet(skill, "unresolved").lower()
    assert "host" in host_bullet, host_bullet
    assert "never" in host_bullet, host_bullet
    assert "do not pre-emptively call `inconclusive` to route around a challenge" in folded

    recorder = _ToolRecorder()
    register_close_tool(recorder, stages=recording(holds()).bundle(), bounds=bounds())
    (close_tool,) = recorder.registered
    description = close_tool.__doc__ or ""
    assert BYPASS_PHRASES[2] not in description, description
    assert re.search(r"inconclusive[^.]*(review|gate)|(review|gate)[^.]*inconclusive", description, re.I), (
        f"the tool docstring does not say an inconclusive close is reviewed: {description!r}"
    )


def test_close_tool_description_changes_reach_every_run(tmp_path):
    """The close tool's registered description (the schema every run's model reads, through
    MAIN's real composition root) no longer says `inconclusive` commits unreviewed and says
    the same thing SKILL.md says — an `inconclusive` close is reviewed; no golden or schema pin
    holds the old sentence."""
    from defender.tests._invlang_warn_836 import offered_tool_defs

    deps, _run_dir = deps_over(tmp_path, ceiling_companion())
    (close_def,) = [t for t in offered_tool_defs(deps) if t.name == "close_investigation"]
    description = close_def.description or ""
    assert BYPASS_PHRASES[2] not in description, description
    assert re.search(r"inconclusive[^.]*(review|gate)|(review|gate)[^.]*inconclusive", description, re.I), (
        f"the offered description does not say an inconclusive close is reviewed: {description!r}"
    )
    bullet = _bullet(SKILL_MD.read_text(encoding="utf-8"), "inconclusive").lower()
    assert "review" in bullet, "SKILL.md and the tool description disagree about the review"

    goldens = DEFENDER / "fixtures-e2e"
    stale = [
        p for p in goldens.rglob("*")
        if p.is_file() and p.suffix in {".md", ".json", ".jsonl", ".txt", ".yaml"}
        and BYPASS_PHRASES[2] in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert stale == [], f"a golden still pins the old sentence: {stale}"


def test_visualizer_renders_a_reviewed_inconclusive(tmp_path):
    """A run dir whose record is `verdict: stands` / `reviewed_disposition: inconclusive` with
    the seventh cause and three role trace files — written by the real close — renders in
    § Review gate as a reviewed attempt with its role traces and counts as reviewed; the bypass
    note names `unresolved` only; and a PRE-#992 `inconclusive` dir (record stands/inconclusive,
    cause CAUSE_NOT_REVIEWED, no trace files) renders 'not reviewed' in BOTH the § Review gate
    section and the headline badge — `_was_reviewed` reads the record's own `reviewed` field,
    written by the close, never `NO_REVIEW_DISPOSITIONS` — while a gate-forced `unresolved`
    still reads 'not reviewed' in the headline too."""
    reviewed = reviewed_inconclusive_dir(tmp_path)
    assert frontmatter(reviewed)["cause"] == CEILING_EXAMINED
    assert record(reviewed, 1)["reviewed_disposition"] == GAP
    assert record(reviewed, 1)["reviewed"] is True
    assert trace_files(reviewed) == list(REVIEW_ROLES)
    html, n = render_review_gate(reviewed, parsed_report(reviewed))
    assert n == 1, "the reviewed inconclusive attempt does not count as reviewed"
    assert "not reviewed" not in html
    assert "rv-stands" in html
    for role in REVIEW_ROLES:
        assert f">{role}<" in html, f"{role}'s trace card is missing"
    assert "gate: stands" in _gate_badge_html(parsed_report(reviewed))

    assert "inconclusive" not in _BYPASS_NOTE, _BYPASS_NOTE
    assert "unresolved" in _BYPASS_NOTE

    historical = pre_change_inconclusive_dir(tmp_path)
    assert frontmatter(historical)["cause"] == CAUSE_NOT_REVIEWED
    html, n = render_review_gate(historical, parsed_report(historical))
    assert n == 0, "a pre-#992 inconclusive dir counts as reviewed"
    assert "not reviewed" in html
    assert "rv-stands" not in html
    assert "not reviewed" in _gate_badge_html(parsed_report(historical))

    deps, driver_forced = deps_over(tmp_path / "driver-forced", ceiling_companion())
    assert close_with(deps, "unresolved", recording(holds()), forced=True).outcome == STANDS
    assert frontmatter(driver_forced)["cause"] == CAUSE_NOT_REVIEWED
    assert "not reviewed" in _gate_badge_html(parsed_report(driver_forced))


def test_headline_badge_for_a_ceiling_held_versus_an_unaffordable_gap(tmp_path):
    """A ceiling-held `inconclusive` (the seventh cause) renders the `gate: stands` headline
    badge; an unaffordable gap (CAUSE_EVIDENCE_CANNOT_DISCRIMINATE / CAUSE_TURN_BUDGET_SPENT)
    is overridden to `unresolved` and renders the `gate: forced-inconclusive` badge a confident
    close's override renders — the badge tells the two apart, and the cause text says which
    override (F5); neither reads as "not reviewed"."""
    held = reviewed_inconclusive_dir(tmp_path, name="held")
    deps, cannot = deps_over(tmp_path / "cannot", ceiling_companion())
    assert close_with(deps, GAP, recording(gap(None))).outcome == "forced-inconclusive"
    one_turn = bounds(extra_turns=1)
    deps, spent = deps_over(tmp_path / "spent", ceiling_companion())
    assert close_with(deps, GAP, recording(gap("l-004")), bounds=one_turn).outcome == "challenged"
    assert close_with(deps, GAP, recording(gap("l-005")), bounds=one_turn).outcome == "forced-inconclusive"
    twin, confident = deps_over(tmp_path / "confident", ceiling_companion())
    assert close_with(twin, CONFIDENT, recording(gap(None))).outcome == "forced-inconclusive"

    badges = {run.parent.name: _gate_badge_html(parsed_report(run)) for run in (held, cannot, spent, confident)}
    assert "gate: stands" in badges["held"], badges
    assert "gate-stands" in badges["held"], badges
    assert badges["cannot"] == badges["spent"] == badges["confident"], badges
    assert "gate: forced-inconclusive" in badges["cannot"], badges
    assert "gate-forced" in badges["cannot"], badges
    assert all("not reviewed" not in b for b in badges.values())
    causes = {run.parent.name: frontmatter(run)["cause"] for run in (held, cannot, spent)}
    assert set(causes.values()) == {
        CEILING_EXAMINED, CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_TURN_BUDGET_SPENT,
    }, causes


def _split_answers(run_dir: Path) -> dict:
    """Every run-page reader keyed on the reviewed/unreviewed split, as one answer each:
    the § Review gate count, its section guard, the per-attempt badge and bypass note, and
    the headline badge."""
    report = parsed_report(run_dir)
    html, n = render_review_gate(run_dir, report)
    badge = _gate_badge_html(report)
    return {
        "count": n,
        "section-guard": "not reviewed" in html.split("attempt 1")[0] if "attempt 1" in html else "not reviewed" in html,
        "attempt-badge-reviewed": "rv-stands" in html,
        # Either "no review ran" note: the live one names today's bypass set, the other says
        # the record predates the close writing `reviewed` — never the live one beside a row
        # it would contradict.
        "bypass-note": (_BYPASS_NOTE in html) or (_PRE_RECORD_NOTE in html),
        "live-bypass-note": _BYPASS_NOTE in html,
        "role-cards": all(f">{role}<" in html for role in REVIEW_ROLES),
        "headline-not-reviewed": "not reviewed" in badge,
    }


def test_every_reader_of_the_reviewed_split_agrees_on_both_populations(tmp_path):
    """R8's join census for FK-8 — every consumer of `_was_reviewed`'s answer (the § Review
    gate's reviewed list and its count, the section guard, the per-attempt bypassed flag and
    its `_BYPASS_NOTE` vs role-trace rendering, and `visualize_run`'s cause-keyed headline):
    over one run dir of each population (pre-#992 `inconclusive` with no traces; post-change
    reviewed `inconclusive` with three trace files) every one of those readers resolves the
    SAME answer — the count, the section guard, the per-attempt roles and bypass note and the
    headline badge never disagree — and no reader keys on `NO_REVIEW_DISPOSITIONS` for the
    split: the two populations share a `reviewed_disposition` and render differently.

    The split is READ OFF THE RECORD, not inferred from a side artifact: a reviewed record
    whose trace files are gone (a run dir from before the traces moved under `wire_logs/`, or
    one pruned since) still counts as reviewed — the role cards are the one thing it cannot
    show — where an inference from "did a trace row survive" rendered it as a bypass."""
    reviewed_dir = reviewed_inconclusive_dir(tmp_path)
    historical_dir = pre_change_inconclusive_dir(tmp_path)
    reviewed = _split_answers(reviewed_dir)
    historical = _split_answers(historical_dir)

    assert reviewed == {
        "count": 1, "section-guard": False, "attempt-badge-reviewed": True,
        "bypass-note": False, "live-bypass-note": False, "role-cards": True,
        "headline-not-reviewed": False,
    }, reviewed
    assert historical == {
        "count": 0, "section-guard": True, "attempt-badge-reviewed": False,
        "bypass-note": True, "live-bypass-note": False, "role-cards": False,
        "headline-not-reviewed": True,
    }, historical

    # The two populations are told apart by the record's own word, not by the disposition on
    # it — which is the same string in both.
    assert record(reviewed_dir, 1)["reviewed_disposition"] == GAP
    assert record(historical_dir, 1)["reviewed_disposition"] == GAP
    assert record(reviewed_dir, 1)["reviewed"] is True
    assert "reviewed" not in record(historical_dir, 1)

    traceless_dir = reviewed_inconclusive_dir(tmp_path, name="traceless")
    shutil.rmtree(traceless_dir / "wire_logs")
    assert trace_files(traceless_dir) == []
    traceless = _split_answers(traceless_dir)
    assert traceless == {**reviewed, "role-cards": False}, traceless
