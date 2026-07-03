"""Unit test for the Step-2 A/B driver's frozen-case loader (no model calls)."""
from __future__ import annotations

import json

from defender.evals.run_judge_ab import load_cases
from defender.learning.core.directions import ADVERSARIAL_WIRING, BENIGN_WIRING


def _make_case(root, name, direction, *, complete=True):
    d = root / name
    (d / "run_dir").mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"direction": direction}))
    if complete:
        (d / "actor_story.md").write_text("story")
        (d / "projected_telemetry.yaml").write_text("events: []\n")
    return d


def test_load_cases_attaches_wiring_and_skips_incomplete(tmp_path):
    _make_case(tmp_path, "adv", "adversarial")
    _make_case(tmp_path, "ben", "benign")
    _make_case(tmp_path, "broken", "adversarial", complete=False)  # missing artifacts → skip
    _make_case(tmp_path, "bad_dir", "sideways")                    # bad direction → skip

    by_id = {c.case_id: c for c in load_cases(tmp_path)}

    assert set(by_id) == {"adv", "ben"}  # broken + bad_dir skipped
    assert by_id["adv"].wiring is ADVERSARIAL_WIRING
    assert by_id["adv"].direction == "adversarial"
    assert by_id["ben"].wiring is BENIGN_WIRING
