"""#545 e2e canary — the MAIN reroute must NOT split the run's untrusted-data salt.

Design #545 routes the MAIN production deps through `bind`. `bind` mints a FRESH uuid4 salt
via `_for_run`, but `run_investigation` threads the run's ONE persisted salt to BOTH the deps
(→ every tool result's `<run-{salt}-untrusted>` wrapper, tools.py) AND orient's inlined alert
wrapper (orient.py). That one salt is the injection-defense trust token the agent is told to
distrust. A naive `deps = bind(MAIN_DEF, run_dir)` reroute would tag tool output with a
different salt than the alert → the tag stops matching → fail-open.

This is a CHARACTERIZATION guard (GREEN@HEAD): today run_investigation correctly threads one
salt to both surfaces. The reroute (decision 1a: bind gains a `salt` seam, MAIN binds with the
persisted salt) must keep it green. It goes RED the moment a reroute lets a fresh uuid4 leak
into the deps.

Discharges: main_reroute_salt_coherence, replay_salt_golden_survives (spec_graph_545.yaml).
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


def test_main_reroute_salt_coherence(tmp_path):
    """A driven run wraps its alert (orient) AND its tool output (a read of alert.json) with the
    SAME salt — the run's pinned salt. Exactly one distinct salt appears across the whole
    transcript; a reroute that let bind mint a fresh uuid4 for MAIN would inject a second."""
    run_id, salt = "salt-coherence-545", "deadbeefcafe0000"
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id, salt=salt)

    # One read of alert.json (its result is untrusted-wrapped with deps.salt), then stop. The
    # wrapped result rides into the 2nd model request, so ReplayFn.seen captures it alongside
    # the orient alert wrapper from the 1st request.
    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_id, salt=salt, main=replay)

    transcript = "\n".join(replay.seen)
    salts = set(_UNTRUSTED_TAG.findall(transcript))
    assert salts, "no untrusted-wrapped content seen — the alert wrap and/or tool wrap is missing"
    assert salts == {salt}, (
        f"the run's untrusted tag carries >1 salt {salts} — the alert wrapper and the tool-output "
        f"wrapper disagree (a fresh uuid4 leaked into the MAIN deps via bind); expected only {salt!r}"
    )
