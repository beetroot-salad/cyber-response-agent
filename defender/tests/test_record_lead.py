"""Tests for defender/hooks/record_lead.py.

`claim_lead` writes the leads-table row `gather_raw/{lead_id}.lead.json` and
claims the `lead_id` with an atomic exclusive create — a reused id fails the
create and returns 2, which `runtime/tools_gather.py:428` turns into a
`ModelRetry` before gather is spawned.

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

from defender.hooks.record_lead import claim_lead


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
    assert claim_lead(dispatch) == 0

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text()) == {
        "goal": "Did the FIM fire trace to apt?",
        "what_to_summarize": ["apt history", "checksum"],
    }


def test_creates_gather_raw_dir_if_missing(tmp_path):
    run_dir = tmp_path / "run-C"  # no gather_raw subdir
    assert claim_lead(_dispatch(run_dir, "l-002", "g", ["d"])) == 0
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_distinct_ids_in_a_batch_both_claim(tmp_path):
    run_dir = tmp_path / "run-batch"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g1", ["d"])) == 0
    assert claim_lead(_dispatch(run_dir, "l-002", "g2", ["d"])) == 0
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_reused_id_returns_2_with_remediation(tmp_path, capsys):
    run_dir = tmp_path / "run-reuse"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "first", ["d"])) == 0
    # Second dispatch echoing the same id must be rejected.
    assert claim_lead(_dispatch(run_dir, "l-001", "second", ["d"])) == 2
    err = capsys.readouterr().err
    assert "l-001" in err
    assert "append a new :L" in err
    # The first claim's content is preserved (no overwrite).
    assert json.loads((run_dir / "gather_raw" / "l-001.lead.json").read_text())["goal"] == "first"


def test_malformed_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / "run-bad-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    # `0` is not an l-NNN id → benign skip, no sidecar, no block.
    assert claim_lead(_dispatch(run_dir, "0", "g", ["d"])) == 0
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_lead_id_silently_skips(tmp_path):
    run_dir = tmp_path / "run-no-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = {"run_dir": str(run_dir), "goal": "g", "what_to_summarize": ["d"]}
    assert claim_lead(dispatch) == 0
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_required_keys_silently_skips_write(tmp_path):
    run_dir = tmp_path / "run-D"
    (run_dir / "gather_raw").mkdir(parents=True)
    # No `goal` — a required field.
    assert claim_lead({"run_dir": str(run_dir), "lead_id": "l-001"}) == 0
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def test_non_list_what_to_summarize_silently_skips(tmp_path):
    """The `isinstance(wtc, list)` guard the live caller relies on: `tools_gather`
    unfreezes the request's tuple back to a list at that boundary precisely
    because a non-list is skipped here rather than coerced."""
    run_dir = tmp_path / "run-tuple"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert claim_lead(_dispatch(run_dir, "l-001", "g", ("d",))) == 0
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


def test_failed_payload_write_removes_empty_sidecar_and_allows_retry(tmp_path, monkeypatch):
    """A write failure after the O_EXCL create must not leave a 0-byte sidecar:
    it would degrade the lead to an orphan AND falsely reject a same-id retry."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    dispatch = _dispatch(run_dir, "l-001", "g", ["d"])

    real_fdopen = os.fdopen

    def boom(fd, *a, **k):
        os.close(fd)  # release the fd the way the real fdopen would on success
        raise OSError("disk full")

    monkeypatch.setattr(os, "fdopen", boom)
    assert claim_lead(dispatch) == 0                # fails open, never blocks
    monkeypatch.setattr(os, "fdopen", real_fdopen)

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert not sidecar.exists()                     # no 0-byte orphan left behind

    # A genuine retry of the same id now succeeds (not falsely rejected).
    assert claim_lead(dispatch) == 0
    assert json.loads(sidecar.read_text())["goal"] == "g"
