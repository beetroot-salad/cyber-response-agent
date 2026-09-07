"""#791 part 4 — the queues the change makes production-facing, the evals that keep the
retired machinery alive, and everything left over that still SPELLS what this change retires:
the live stage the word also names, and the two artifacts outside the product that carry it.

Every test here is one demand of `spec-flow/specs/spec_graph_791-retire-offline-oracle.yaml`,
named by that demand's `discharged_by`. RED against HEAD is the expected state.

TWO INHERITED DEFECTS ARE FIXED IN SCOPE, and both are wider than "a wiring change":

* A marker orphaned in the claim directory by a crashed drain is never reclaimed — the drain
  enumerates the queue's own `*.json` and the claim directory is a SUBDIRECTORY, outside that
  glob by construction: no age-out, no reaper, no quarantine, and the operator's own count line
  reports zero queued while the marker sits there (P1). What earns the fix here is the CUTOVER:
  markers already on disk when the change ships can crash a drain mid-claim.
* The claim is a replace INTO that directory, which FREES the top-level slot — so a retry lands
  unobstructed and the next drain learns the same run a second time (P2, executed and refuted).
  Nothing between the human seam and the gate picked this up.

WHAT "THE EVALS STILL WORK" MEANS NOW: three of the four go dark. The prompt rewrite reaches
every caller that shares the two prompts (E5), so under any reading where they keep judging
they report numbers and measure nothing. They stop judging but keep RUNNING, and the skip
reason has to be loud — a passing eval whose result means nothing is a trap. Only the golden
replay keeps a positive, asserting witness: it binds the per-lead seam directly and never
touches the judge prompts.
"""
from __future__ import annotations

import json
from pathlib import Path


from defender.tests._by_path import load_lint_gate


from defender.tests._spec791 import (  # noqa: E402
    PROJECT_PROFILE,
    RETIRED_DEAD_SYMBOLS,
    RETIRED_TELEMETRY_WRITER,
    VULTURE_BASELINE,
    worktree_package_guard,  # noqa: F401 — session-scoped autouse guard, see _spec791
)

ISSUE = "791"


def _queued_run(tmp_path, name: str) -> Path:
    run_dir = tmp_path / "runs" / name
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    return run_dir














def test_791_every_new_dead_code_baseline_entry_names_this_issue(tmp_path):
    """dead_code_baseline_names_the_issue — every dead-code finding this change baselines
    carries a stated reason naming the issue that made it dead, and the gate REFUSES one that
    does not.

    The demand was written expecting the corpses to fall inside the retired package. They do
    not: `pipeline/oracle/` keeps every symbol live, because the secondary eval still projects
    (deliberately — its sibling demand says so in as many words) and the golden replay binds
    the per-lead seam. What this change actually orphans is the queue API the curation request
    replaced, and the A/B harness's verdict parser. Locating the demand by SYMBOL rather than
    by package is what makes it true of the shipped design; naming them is also stricter than
    the path scan, which any one entry anywhere under the package would have satisfied.

    The enforcement arm is the load-bearing one. "" meaning un-triaged was documented by the
    ratchet and enforced by nothing, so `--update-baseline` could bury any corpse silently —
    which is the shape that let the whole gate go blind for a month. A per-issue test cannot
    hold that; the gate has to, for every change, so it is asserted here against the gate."""
    baseline = json.loads(VULTURE_BASELINE.read_text(encoding="utf-8"))
    entries = baseline["entries"]

    for symbol in RETIRED_DEAD_SYMBOLS:
        ours = {fp: reason for fp, reason in entries.items() if f"'{symbol}'" in fp}
        assert ours, (
            f"{symbol!r} is not on the dead-code record — either it regained a caller (then "
            f"drop it from RETIRED_DEAD_SYMBOLS) or the baseline was never regenerated"
        )
        untriaged = sorted(fp for fp, reason in ours.items() if not reason.strip())
        assert untriaged == [], f"un-triaged dead-code entries: {untriaged}"
        unattributed = sorted(fp for fp, reason in ours.items() if ISSUE not in reason)
        assert unattributed == [], \
            f"dead-code entries with a reason that does not name #{ISSUE}: {unattributed}"

    # The gate itself refuses an un-triaged entry — otherwise every assertion above is one
    # `--update-baseline` away from being vacuous.
    ratchet = _load_lint_ratchet()
    finding = ratchet.Finding("f/x.py: unused function 'z'", "f/x.py:1: unused function 'z'")
    buried = tmp_path / "baseline.json"

    def _rc(reason: str) -> int:
        buried.write_text(
            json.dumps({"//": "h", "entries": {finding.fingerprint: reason}}), encoding="utf-8"
        )
        return ratchet.gate([finding], buried, [], label="l", header="h", require_reasons=True)

    assert _rc("") == 1, "the ratchet accepts a baseline entry nobody triaged"
    assert _rc("intentional: because") == 0, \
        "the ratchet rejects an entry that IS triaged, so the arm above proves nothing"


def _load_lint_ratchet():
    """`scripts/lint/` is a directory of standalone scripts, not an importable package — the
    gate is reached by path, the way CI reaches it."""
    return load_lint_gate("_baseline", name="_spec791_baseline")


def test_791_the_project_profile_census_drops_the_retired_writer(tmp_path):
    """profile_census_drops_the_retired_writer — the project profile's shared-root census no
    longer names the projected-telemetry writer this change deletes.

    A stale census entry fails open BY CONSTRUCTION: a symbol that resolves to nothing reads
    exactly like a row nobody ever wrote, and this file is what seeds the NEXT change's
    grounding pass — the failure this run hit in its own first hour.

    Promoted from a clause. The downgrade rested on "it is an edit to a spec artifact rather
    than to the product", which two other tests in this suite refute by asserting on a
    committed lint baseline and on another test module's source. The assertion is one absent
    substring; it freezes no prose.

    The positive control is the rest of the census: the row this change deletes goes, the
    writers it does not touch stay, so a census emptied into green fails here. The control was
    the pipeline judge's per-lead writer until #922 deleted that judge — and with it the whole
    `learning_run_dir` census — so it now names a writer outside the learning tree entirely."""
    profile = json.loads(PROJECT_PROFILE.read_text(encoding="utf-8"))
    resources = profile["specGraph"]["resources"]
    census = json.dumps(resources)

    assert RETIRED_TELEMETRY_WRITER not in census, (
        f"the profile's census still names {RETIRED_TELEMETRY_WRITER}, a writer this change "
        "deletes — the next grounding pass inherits a symbol that resolves to nothing"
    )
    survivors = [w for entry in resources.values() for w in entry.get("writers", [])]
    assert len(survivors) > 20, (
        f"the census carries only {len(survivors)} writers — it was emptied rather than "
        "corrected, and the absence above means nothing"
    )
    assert any("write_trace" in w for w in survivors), (
        "the wire log's own writer left the census; neither this change nor #922 touches it"
    )
