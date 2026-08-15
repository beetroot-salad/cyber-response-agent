"""#545 e2e canary, INVERTED BY #875 — the run's untrusted frames must NOT share one salt.

Design #545 routed the MAIN production deps through `bind` and pinned the property that made
that reroute safe: `run_investigation` threads the run's ONE minted salt to BOTH the deps (→
every tool result's `<run-{salt}-untrusted>` wrapper, tools.py) AND orient's inlined alert
wrapper (orient.py), so exactly one distinct salt appears across a driven run. The stated fear
was that a fresh uuid4 leaking into the MAIN deps would "tag tool output with a different salt
than the alert → the tag stops matching → fail-open".

**That fear was misplaced, and the coherence it argued for is what #875 F-1 exploited.**

Nothing ever matched a salt. MAIN is never told a salt value — `defender/SKILL.md` ships a
literal `{salt}` placeholder, as does `skills/gather/SKILL.md` — so the agent reads frames
STRUCTURALLY, by matching an open tag to its own close. Two frames carrying two different
salts are two well-formed frames; there is no "the tag" to stop matching. What one shared salt
DID buy was a token the gather subagent reads in plaintext on every payload view it is handed
(`query_tool._model_view`, `tools._bound_and_wrap`) — and which `_run_gather` then used to
delimit gather's OWN summary. An injected gather echoing one closing tag it had already seen
put its text outside MAIN's frame, in the host-text region. Coherence was the vulnerability.

So this file keeps its job — a characterization canary over a driven run's frames — and
reverses its assertion. `wrap_fresh` mints each frame's delimiter AFTER the content is in hand
and re-mints while the token occurs in that content, so the run emits MANY salts and no framed
party holds the one that delimits it. This goes RED the moment a change re-introduces a single
run-scoped token.

Discharges: main_reroute_salt_coherence (spec_graph_545.yaml), amended premise.
The machinery is the real replay harness — drive() runs the REAL driver.run_investigation with
a FunctionModel, so the salted wrappers observed here are exactly what the model sees.
"""
from __future__ import annotations

import re

import pytest

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
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return "\n".join(replay.seen)


def test_the_alert_wrap_and_the_tool_wrap_carry_DIFFERENT_salts(tmp_path):
    """A driven run wraps its alert (orient) and its tool output (a read of alert.json) with
    DIFFERENT salts. THE INVERSE of this file's original assertion, and the property that makes
    a framed party unable to close the frame its own content arrives in."""
    transcript = _driven_transcript(tmp_path, "salt-split-545")

    salts = set(_UNTRUSTED_TAG.findall(transcript))
    assert salts, "no untrusted-wrapped content seen — the alert wrap and/or tool wrap is missing"
    assert len(salts) > 1, (
        f"every untrusted frame in the run shares one salt {salts} — the #875 F-1 shape is back: "
        "a party shown one frame holds the delimiter of every other"
    )


def test_no_untrusted_frame_contains_its_own_delimiter(tmp_path):
    """The re-mint guarantee, observed on a real run: for every complete frame the model is
    shown, the frame's salt does not occur in the body it delimits. This is what `wrap_fresh`'s
    collision loop buys and what a run-scoped token could not — the salt is drawn after the
    content exists, so the content cannot have anticipated it."""
    transcript = _driven_transcript(tmp_path, "salt-noecho-545")

    checked = 0
    for m in _FRAME.finditer(transcript):
        salt, body = m.group(1), m.group(2)
        assert salt not in body, (
            f"frame salt {salt!r} occurs inside its own body — the framed party can close it"
        )
        checked += 1
    assert checked, "no complete untrusted frame was found — the sweep is vacuous"
