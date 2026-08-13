"""Tests for defender/hooks/record_lead.py.

`claim_lead` writes the leads-table row `gather_raw/{lead_id}.lead.json` and
claims the `lead_id` with an atomic exclusive create — a reused id fails the
create and returns `ALREADY_CLAIMED`, which `runtime/tools_gather._run_gather`
turns into a `ModelRetry` before gather is spawned.

THE CODES ARE THREE, and every assertion below names which one it means (#855
F-12). They used to be two: success and every silent skip both returned 0, so
the one live caller could not write the check it needed and read "not the reuse
code" as success — which ran a gather session under an id with no leads row,
past the reuse gate that IS that row's exclusive create. An assertion that
spells `== CLAIMED` is one that would have failed when the write did not happen.

Driven through `claim_lead(dispatch)` — the function that live caller reaches,
with the same dict shape it builds from the typed `gather` request. These used
to run through the module's `claude -p` PreToolUse `main()`, which recovered
that dict from a Task prompt's fenced YAML; nothing invokes it, and the lenient
parser it fed (`extract_dispatch`/`_parse_block`) was deleted with it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from defender.hooks.record_lead import (
    ALREADY_CLAIMED,
    CLAIMED,
    NOT_CLAIMED,
    claim_lead,
)


def _dispatch(run_dir: Path, lead_id, goal: str, dims: list[str]) -> dict:
    return {
        "run_dir": str(run_dir),
        "lead_id": lead_id,
        "goal": goal,
        "what_to_summarize": dims,
    }


def test_writes_lead_id_keyed_sidecar(tmp_path):
    run_dir = tmp_path / "run-A"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(
        run_dir, "l-001", "Did the FIM fire trace to apt?", ["apt history", "checksum"]
    )
    assert claim_lead(dispatch) == CLAIMED

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text()) == {
        "goal": "Did the FIM fire trace to apt?",
        "what_to_summarize": ["apt history", "checksum"],
    }


def test_creates_gather_raw_dir_if_missing(tmp_path):
    run_dir = tmp_path / "run-C"
    assert claim_lead(_dispatch(run_dir, "l-002", "g", ["d"])) == CLAIMED
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_distinct_ids_in_a_batch_both_claim(tmp_path):
    run_dir = tmp_path / "run-batch"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g1", ["d"])) == CLAIMED
    assert claim_lead(_dispatch(run_dir, "l-002", "g2", ["d"])) == CLAIMED
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_reused_id_returns_already_claimed_with_remediation(tmp_path, capsys):
    run_dir = tmp_path / "run-reuse"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "first", ["d"])) == CLAIMED
    assert claim_lead(_dispatch(run_dir, "l-001", "second", ["d"])) == ALREADY_CLAIMED
    err = capsys.readouterr().err
    assert "l-001" in err
    assert "append a new :L" in err
    assert json.loads((run_dir / "gather_raw" / "l-001.lead.json").read_text())["goal"] == "first"


def test_the_three_codes_are_distinct(tmp_path):
    """#855 F-12, at the seam that caused it: a caller must be able to write "the row is on
    disk" as a check, and it can only do that if SUCCESS has a code no skip shares. One run
    over the three domains — a good claim, a refused one, a reused one — and the three answers
    are three."""
    run_dir = tmp_path / "run"
    good = claim_lead(_dispatch(run_dir, "l-001", "g", ["d"]))
    refused = claim_lead(_dispatch(run_dir, "l-002", "", ["d"]))
    reused = claim_lead(_dispatch(run_dir, "l-001", "again", ["d"]))
    assert len({good, refused, reused}) == 3, \
        "two of the claim's outcomes share a code — a caller cannot tell them apart"
    assert (good, refused, reused) == (CLAIMED, NOT_CLAIMED, ALREADY_CLAIMED)


def test_an_empty_or_whitespace_goal_claims_nothing(tmp_path):
    """The leads row records the STRIPPED goal, so `"   "` used to claim the id and write a
    row whose goal is `""` — the same empty row the falsy arm refuses, reached by a string
    that merely is not falsy. Both spellings now leave the id unclaimed AND unburnt: the
    corrected re-dispatch of the same id must still be able to take it."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    for empty in ("", "   ", "\n\t"):
        assert claim_lead(_dispatch(run_dir, "l-001", empty, ["d"])) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []
    assert claim_lead(_dispatch(run_dir, "l-001", "a real question", ["d"])) == CLAIMED


def test_an_overlong_lead_id_is_refused_before_os_open(tmp_path):
    """A well-shaped but unbounded id spent as a filename component fails the create with
    ENAMETOOLONG, and "the write failed" is the outcome a caller has the least to say about.
    `LEAD_ID_RE` bounds the body, so the refusal happens at the shape check — and the same
    bound is what `tools_gather`'s own seam check reads."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-" + "a" * 300, "g", ["d"])) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_malformed_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / "run-bad-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "0", "g", ["d"])) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / "run-no-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = {"run_dir": str(run_dir), "goal": "g", "what_to_summarize": ["d"]}
    assert claim_lead(dispatch) == NOT_CLAIMED
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_required_keys_silently_skips_write(tmp_path):
    run_dir = tmp_path / "run-D"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead({"run_dir": str(run_dir), "lead_id": "l-001"}) == NOT_CLAIMED
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def test_non_list_what_to_summarize_silently_skips(tmp_path):
    """The `isinstance(wtc, list)` guard the live caller relies on: `tools_gather`
    unfreezes the request's tuple back to a list at that boundary precisely
    because a non-list is skipped here rather than coerced."""
    run_dir = tmp_path / "run-tuple"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g", ("d",))) == NOT_CLAIMED
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def test_failed_payload_write_removes_empty_sidecar_and_allows_retry(tmp_path, monkeypatch):
    """A write failure after the O_EXCL create must not leave a 0-byte sidecar:
    it would degrade the lead to an orphan AND falsely reject a same-id retry."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])

    real_fdopen = os.fdopen

    def boom(fd, *a, **k):
        os.close(fd)
        raise OSError("disk full")

    monkeypatch.setattr(os, "fdopen", boom)
    assert claim_lead(dispatch) == NOT_CLAIMED
    monkeypatch.setattr(os, "fdopen", real_fdopen)

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert not sidecar.exists()

    assert claim_lead(dispatch) == CLAIMED
    assert json.loads(sidecar.read_text())["goal"] == "g"
