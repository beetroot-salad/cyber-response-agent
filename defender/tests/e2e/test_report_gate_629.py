"""#629 — the report.md/investigation.md gate through the REAL write tools + the driver.

The tool-lane and driver demands of `tests/spec_graph_629-report-output-structure.yaml`:
the write-mode family (wm1-wm5, D6 — both write paths route the full resulting text through
`decide_write`), the deny-preserves-disk + mid-run lifecycle legs (ii3, lc1-lc3), and the
end-to-end bounce-and-recover + golden-survival demands (D4, D5, lc6). The pure content
DECISION legs live in `tests/test_permission_report_629.py`, driving `decide_write` directly.

Each test here drives the REAL `_tool_write_file`/`_tool_edit_file` (through the real `bind`
seam) or the REAL replay driver (`drive`), so the ModelRetry chain (C9) and the on-disk
overwrite the pure gate cannot see are pinned. Fakes enter only through injection seams
(`bind`, `drive(main=…)`) — never `monkeypatch.setattr` (CI ratchets new setattr sites).

RED BY CONSTRUCTION: with no report.md branch at HEAD, an over-bound / malformed report
COMMITS through both tools, so the deny + disk-unchanged + bounce assertions are green only
once the guard is written. The investigation over-bound fixtures are invlang-VALID (padding a
real invlang doc keeps it valid), so they are red via the NEW size check, not green for the
wrong reason via the pre-existing invlang branch.
"""
from __future__ import annotations


import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._frontmatter import split_frontmatter  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

BODY_BOUND = 8192
INV_BOUND = 65536
VALID_REPORT = "---\ndisposition: benign\n---\nConcise analysis.\n"
GOLDEN_INV = (GOLDEN_AB3 / "investigation.md").read_text(encoding="utf-8")
GOLDEN_REPORT = (GOLDEN_AB3 / "report.md").read_text(encoding="utf-8")


def _over_report() -> str:
    head = "---\ndisposition: benign\n---\n"
    return head + "x" * (BODY_BOUND + 1 - len(head.encode("utf-8")))


def _deps(tmp_path):
    """MAIN deps through the real `bind` seam — the real compiled policy + gate; nothing faked
    at the gate. No box: the file tools never touch the bash execution boundary."""
    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    return bind(MAIN_DEF, run, defender_dir=dfn), run



def test_both_write_paths_gate(tmp_path):
    """D6 (parity) — BOTH write paths route their full resulting text through decide_write and
    neither commits a report.md the gate denies. An over-bound report is refused via write_file
    AND via edit_file (create), and a valid report commits via both — no second write path
    bypasses the gate."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    over = _over_report()
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, p, over)
    assert not (run / "report.md").exists(), "a denied write_file must not commit"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, "", over)
    assert not (run / "report.md").exists(), "a denied edit_file must not commit"
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    assert (run / "report.md").read_text(encoding="utf-8") == VALID_REPORT
    runtime_tools._tool_edit_file(deps, p, "Concise analysis.", "Revised analysis.")
    assert "Revised analysis." in (run / "report.md").read_text(encoding="utf-8")


def test_report_over_bound_via_write_file(tmp_path):
    """wm1 — an over-bound report.md written via write_file is denied (ModelRetry) and does not
    commit. Positive control: an in-bound report via the same tool commits."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, p, _over_report())
    assert not (run / "report.md").exists()
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    assert (run / "report.md").is_file()


def test_report_over_bound_via_edit_file(tmp_path):
    """wm2 — an edit_file whose FULL resulting text is over the body bound is denied (same checks
    as write_file, over the whole resulting doc). A valid report is committed, then an edit that
    appends past 8,192 B is refused; the prior valid content is preserved."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, "Concise analysis.",
                                      "Concise analysis.\n" + "x" * (BODY_BOUND + 1))
    assert (run / "report.md").read_text(encoding="utf-8") == VALID_REPORT


def test_report_edit_leaves_preexisting_malformed_frontmatter_untouched_by_the_edit(tmp_path):
    """wm3 — edit_file hands the FULL resulting document to the gate; an edit that leaves a
    pre-existing MALFORMED frontmatter untouched (only touches the body) is re-validated and
    fails -> Decision(False). Positive control: the identical body edit on a VALID report
    commits."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    (run / "report.md").write_text("no frontmatter fence\nBODY-OLD marker\n", encoding="utf-8")
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, "BODY-OLD marker", "BODY-NEW marker")
    (run / "report.md").write_text("---\ndisposition: benign\n---\nBODY-OLD marker\n", encoding="utf-8")
    runtime_tools._tool_edit_file(deps, p, "BODY-OLD marker", "BODY-NEW marker")
    assert "BODY-NEW marker" in (run / "report.md").read_text(encoding="utf-8")


def test_edit_file_turns_a_committed_valid_report_into_a_malformed_one(tmp_path):
    """wm4 — prior validity confers no exemption: an edit that INTRODUCES a fault (turning the
    disposition out-of-enum) fails the same demand a first write would -> Decision(False). The
    committed valid content is preserved. Positive control: an edit that keeps disposition
    in-enum commits."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, "disposition: benign", "disposition: hostile")
    assert "disposition: benign" in (run / "report.md").read_text(encoding="utf-8")
    runtime_tools._tool_edit_file(deps, p, "disposition: benign", "disposition: malicious")
    assert "disposition: malicious" in (run / "report.md").read_text(encoding="utf-8")


def test_identical_content_rewrite_of_already_valid_report(tmp_path):
    """wm5 — no memoization: a byte-identical rewrite of an already-valid report is evaluated
    fresh and commits again (Decision(True)). Two successive identical write_file calls both
    succeed."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    assert (run / "report.md").read_text(encoding="utf-8") == VALID_REPORT


def test_denied_write_preserves_prior_disk_content(tmp_path):
    """ii3 (D4) — the Decision is computed and returned strictly BEFORE p.write_text() in both
    callers, so a denied write leaves the prior on-disk content byte-for-byte unchanged. A valid
    report commits; a subsequent over-bound write is denied AND the disk still holds the valid
    bytes."""
    deps, run = _deps(tmp_path)
    p = str(run / "report.md")
    runtime_tools._tool_write_file(deps, p, VALID_REPORT)
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, p, _over_report())
    assert (run / "report.md").read_text(encoding="utf-8") == VALID_REPORT



def test_investigation_crosses_bound_mid_run(tmp_path):
    """lc1 — at turn K only that call's full resulting text is evaluated: an under-bound
    investigation commits, then an over-bound (but invlang-valid) write on the next turn is
    denied for THAT call only, leaving the K-1 committed content untouched on disk."""
    deps, run = _deps(tmp_path)
    p = str(run / "investigation.md")
    runtime_tools._tool_write_file(deps, p, GOLDEN_INV)
    over = GOLDEN_INV.rstrip() + "\n" + "x" * (INV_BOUND + 5000) + "\n"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, p, over)
    assert (run / "investigation.md").read_text(encoding="utf-8") == GOLDEN_INV


def test_edit_file_splice_pushes_investigation_over_bound(tmp_path):
    """lc2 — an edit_file splice that pushes investigation.md past 65,536 B is denied: the gate
    sees the post-splice WHOLE resulting text, not the delta. The splice is an append (invlang
    append-only-valid) so the deny is the NEW size check, not invlang. Prior content preserved."""
    deps, run = _deps(tmp_path)
    p = str(run / "investigation.md")
    runtime_tools._tool_write_file(deps, p, GOLDEN_INV)
    current = (run / "investigation.md").read_text(encoding="utf-8")
    anchor = current.rstrip()[-40:]
    assert current.count(anchor) == 1, "re-probe: the edit anchor is unique"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, anchor, anchor + "\n" + "x" * (INV_BOUND + 5000))
    assert (run / "investigation.md").read_text(encoding="utf-8") == current


def test_edit_file_splice_pulls_investigation_under_bound(tmp_path):
    """lc3 — a shrinking splice landing <= 65,536 B is accepted regardless of the stale
    over-bound baseline it started from (Decision(True), invlang also passing). A grandfathered
    over-bound investigation on disk is edited down under the bound and the edit commits."""
    deps, run = _deps(tmp_path)
    p = str(run / "investigation.md")
    pad = "x" * (INV_BOUND + 5000)
    over = GOLDEN_INV.rstrip() + "\n" + pad + "\n"
    (run / "investigation.md").write_text(over, encoding="utf-8")
    runtime_tools._tool_edit_file(deps, p, "\n" + pad + "\n", "\n")
    shrunk = (run / "investigation.md").read_text(encoding="utf-8")
    assert len(shrunk.encode("utf-8")) <= INV_BOUND
    assert pad not in shrunk



def test_report_deny_bounces_then_recovers(tmp_path):
    """D4 — an over-bound report.md write is denied and the reason reaches the model as
    ModelRetry; a corrected in-bound rewrite then commits. Driven end-to-end through the real
    driver (mirrors test_invlang_deny_bounces_then_recovers): the model writes an over-bound
    report, is bounced, then writes a valid one that commits. The bounce is observable as the
    FIRST (bad) write never producing a `wrote ...report.md` success in the model's history —
    exactly one successful report write reaches the model, and the final on-disk file is the
    corrected content."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    rp = str(run_dir / "report.md")
    head = "---\ndisposition: benign\n---\n"
    over = head + "x" * (BODY_BOUND + 1 - len(head.encode("utf-8")))
    good = "---\ndisposition: malicious\n---\nCorrected, in-bound analysis.\n"
    main = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": rp, "content": over})]),
        Turn(tool_calls=[("write_file", {"path": rp, "content": good})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="rpt-recover", salt="1234123412341234", main=main)

    assert main.calls == 3
    assert (run_dir / "report.md").read_text(encoding="utf-8") == good
    assert main.seen[-1].count("report.md (") == 1


def test_golden_ab_run_still_commits(tmp_path):
    """D5 (survival) — a current-shape golden report.md + investigation.md still commit through
    the gate with the SAME disposition as the pre-guard baseline: the bounds clear every
    current-shape artifact. Driven through the real driver; the committed report.md is
    byte-identical to the golden and its disposition is preserved (positive control for
    D1-D3)."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "investigation.md"),
                                         "content": GOLDEN_INV})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": GOLDEN_REPORT})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="golden-commit", salt="aabbccddeeff0011", main=main)

    assert (run_dir / "report.md").read_text(encoding="utf-8") == GOLDEN_REPORT
    assert (run_dir / "investigation.md").read_text(encoding="utf-8") == GOLDEN_INV
    fm = split_frontmatter(GOLDEN_REPORT)[0]
    assert split_frontmatter((run_dir / "report.md").read_text(encoding="utf-8"))[0]["disposition"] \
        == fm["disposition"]


def test_golden_ab_run_lifecycle_preserves_disposition(tmp_path):
    """lc6 (survival, concrete) — every write in a legit golden sequence returns Decision(True):
    an incremental investigation build (write then append-edit) plus the final report all
    commit, and the run's report.md ends with the SAME disposition the golden carried, its body
    (the analyst's reasoning the HTML renders) intact. The positive control for the whole
    #629 gate — a real run is never denied by the new bounds."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    ip = str(run_dir / "investigation.md")
    rp = str(run_dir / "report.md")
    anchor = GOLDEN_INV.rstrip()[-40:]
    main = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": ip, "content": GOLDEN_INV})]),
        Turn(tool_calls=[("edit_file", {"path": ip, "old_string": anchor,
                                        "new_string": anchor + "\n\nAddendum: no new leads.\n"})]),
        Turn(tool_calls=[("write_file", {"path": rp, "content": GOLDEN_REPORT})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="golden-lifecycle", salt="00112233aabbccdd", main=main)

    assert main.calls == 4
    committed = (run_dir / "report.md").read_text(encoding="utf-8")
    fm, _raw, body = split_frontmatter(committed)
    assert fm["disposition"] == split_frontmatter(GOLDEN_REPORT)[0]["disposition"]
    assert body.strip(), "the analyst's reasoning body must survive for the HTML render"
    assert "Addendum: no new leads." in (run_dir / "investigation.md").read_text(encoding="utf-8")
