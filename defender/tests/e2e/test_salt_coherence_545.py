"""#545 e2e canary, INVERTED BY #875 — the run's untrusted frames must NOT share one salt."""
from __future__ import annotations

import re

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

from defender.tests.e2e._replay_harness import (
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

_UNTRUSTED_TAG = re.compile(r"<run-([0-9a-f]+)-untrusted>")
_FRAME = re.compile(r"<run-([0-9a-f]+)-untrusted>\n(.*?)\n</run-\1-untrusted>", re.S)


def _driven_transcript(tmp_path, run_id: str) -> str:
    """One driven run that emits at least two untrusted frames: orient's inlined raw alert, and
    the tool return from a read of `alert.json`. Exactly the two surfaces #545 compared."""
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id)
    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return "\n".join(replay.seen)


def test_the_alert_wrap_and_the_tool_wrap_carry_DIFFERENT_salts(tmp_path):
    transcript = _driven_transcript(tmp_path, "salt-split-545")

    salts = set(_UNTRUSTED_TAG.findall(transcript))
    assert salts, "no untrusted-wrapped content seen — the alert wrap and/or tool wrap is missing"
    assert len(salts) > 1, (
        f"every untrusted frame in the run shares one salt {salts} — the #875 F-1 shape is back: "
        "a party shown one frame holds the delimiter of every other"
    )


def test_no_untrusted_frame_contains_its_own_delimiter(tmp_path):
    transcript = _driven_transcript(tmp_path, "salt-noecho-545")

    checked = 0
    for m in _FRAME.finditer(transcript):
        salt, body = m.group(1), m.group(2)
        assert salt not in body, (
            f"frame salt {salt!r} occurs inside its own body — the framed party can close it"
        )
        checked += 1
    assert checked, "no complete untrusted frame was found — the sweep is vacuous"
