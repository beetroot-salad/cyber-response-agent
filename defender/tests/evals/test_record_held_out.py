from __future__ import annotations

import json

import pytest
import yaml

from evaluations.oracle_golden import judge, record_held_out

MODEL, EFFORT = "claude-opus-5", "high"


def _case(tmp_path, *, split="held-out", tag=None, judge_block=None):
    tag = tag if tag is not None else f"oracle-x__{judge.tag_suffix(MODEL, EFFORT)}"
    d = tmp_path / "case-h"
    (d / "scores").mkdir(parents=True)
    (d / "manifest.yaml").write_text(
        yaml.safe_dump({"case_id": d.name, "split": split}), encoding="utf-8")
    (d / "scores" / f"{tag}.json").write_text(json.dumps({
        "tag": tag, "judged": True, "rows": [],
        "judge": judge_block if judge_block is not None else {
            "model": MODEL, "effort": EFFORT, "prompts_sha8": judge.prompts_sha8()},
    }), encoding="utf-8")
    return d, tag


def _ledger(tmp_path, entries=()):
    p = tmp_path / "ledger.yaml"
    p.write_text("# header\n" + yaml.safe_dump({"entries": list(entries)}),
                 encoding="utf-8")
    return p


def _run(case_dir, tag, ledger):
    return record_held_out.main([str(case_dir), tag, "--ledger", str(ledger),
                                 "--recorded", "2026-07-27"])


def test_a_matching_result_is_appended_with_the_hash_of_its_artifact(tmp_path):
    case_dir, tag = _case(tmp_path)
    ledger = _ledger(tmp_path)
    assert _run(case_dir, tag, ledger) == 0
    entry = yaml.safe_load(ledger.read_text(encoding="utf-8"))["entries"][0]
    assert (entry["case"], entry["tag"]) == (case_dir.name, tag)
    assert len(entry["sha256"]) == 64


def test_the_header_explaining_the_ledger_survives_a_write(tmp_path):
    """It is the only place that says why the file exists; a rewrite that dropped it
    would leave a bare list of hashes."""
    case_dir, tag = _case(tmp_path)
    ledger = _ledger(tmp_path)
    _run(case_dir, tag, ledger)
    assert ledger.read_text(encoding="utf-8").startswith("# header\n")


def test_a_second_run_of_the_same_tag_is_refused(tmp_path, capsys):
    """Re-running a held-out case under one tag until the number improves is how a
    held-out set stops being held out. There is no flag here to do it."""
    case_dir, tag = _case(tmp_path)
    ledger = _ledger(tmp_path)
    assert _run(case_dir, tag, ledger) == 0
    assert _run(case_dir, tag, ledger) == 1
    assert "already in the ledger" in capsys.readouterr().err


def test_a_dev_case_is_not_ledgerable(tmp_path):
    case_dir, tag = _case(tmp_path, split="dev")
    assert _run(case_dir, tag, _ledger(tmp_path)) == 1


def test_a_score_whose_tag_names_another_judge_is_refused(tmp_path, capsys):
    """§6. `JUDGE_MODEL` has a fallback, so a tag naming opus-5 can hold a score another
    model produced. Ledgering it would attest to a result nothing can attribute."""
    case_dir, tag = _case(tmp_path, judge_block={
        "model": "some-other-judge", "effort": EFFORT,
        "prompts_sha8": judge.prompts_sha8()})
    assert _run(case_dir, tag, _ledger(tmp_path)) == 1
    assert "not the judge its tag names" in capsys.readouterr().err


def test_a_score_produced_under_older_prompts_is_refused(tmp_path):
    stale = f"oracle-x__judge-{MODEL}-{EFFORT}_deadbeef"
    case_dir, tag = _case(tmp_path, tag=stale)
    assert _run(case_dir, tag, _ledger(tmp_path)) == 1


def test_a_missing_score_is_refused(tmp_path):
    case_dir, _ = _case(tmp_path)
    assert _run(case_dir, "a-tag-with-no-artifact", _ledger(tmp_path)) == 1


@pytest.mark.parametrize("block", [None, {}, {"model": MODEL}])
def test_a_score_that_does_not_say_who_judged_it_is_refused(tmp_path, block):
    case_dir, tag = _case(tmp_path, judge_block=block or {})
    assert _run(case_dir, tag, _ledger(tmp_path)) == 1
