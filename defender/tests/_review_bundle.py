"""A review bundle whose four stages answer without a provider — for both test trees.

The gate dispatches three lenses and a composer from inside the close tool, so ANY scenario
that drafts a confident disposition drives four model calls. A hermetic suite therefore needs
a bound bundle the way it needs a fake main model, and it needs the same one on both sides of
the e2e line: `tests/test_796_gate_arms` drives `challenge_gate` directly, the replay harness
drives it through `run_investigation`, and both want "every lens answers, the composer says
X". Neutral home rather than either suite's, exactly as `_docker.py` is.

What deliberately does NOT live here: which finding a scenario's composer returns. That IS
the scenario — a bundle default that picked one would put the interesting half of every gate
test somewhere other than the test — so `composer` is a required argument with no default.
The one exception is the replay harness's own seam default, which is `holds` because a replay
of a real run is a HAPPY-path script: a bundle that overrode every confident close would make
those replays assert a degenerate outcome, which is the state this module was written to end.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
from typing import Any

from defender.runtime.review_roles import ReviewStages

__all__ = ["LENS_READING", "bundle", "composer_reply", "stage"]

#: What a lens returns when the scenario is not about the lenses. Any prose reads: a reading
#: is free text to everything downstream, and only the composer's reply is parsed.
LENS_READING = "l-001 separates h-001 from h-002."


def stage(reply: str) -> Any:
    """One stage: the reply it returns, whatever it is handed.

    It ignores the request rather than asserting on it, so a scenario that wants to inspect
    what reached a role — the frame, the salt, the projection — binds its own recording stage
    instead of growing this one a recorder every caller pays for."""

    async def call(_request):
        return reply

    return call


def composer_reply(finding: str = "holds", review: str = "reads sound", ask: Any = None) -> str:
    """The composer's contract as one JSON line. `finding` is `holds` or `gap`, and an `ask`
    names a target the investigation actually recorded — `citable_refs` refuses anything
    else, which fails the whole review as unreadable rather than routing on it."""
    return json.dumps({"finding": finding, "review": review, "ask": ask})


def bundle(*, composer: str, lens: str = LENS_READING) -> ReviewStages:
    """All four stages bound. Every lens answers with `lens`; only the composer varies.

    The three lens calls are held constant because the routing arms turn on what the COMPOSER
    found — the host is shown a lens reading only through the composer — so a scenario that
    varied them would be varying something the outcome does not read."""
    return ReviewStages(
        discrimination=stage(lens), support=stage(lens), ablation=stage(lens),
        composer=stage(composer),
    )
