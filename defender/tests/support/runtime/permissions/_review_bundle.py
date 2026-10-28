"""A review bundle whose three stages answer without a provider."""
from __future__ import annotations

import json
from typing import Any

from defender.investigation.review_roles import ReviewStages

__all__ = ["LENS_READING", "bundle", "composer_reply", "stage"]

#: What a lens returns when the scenario is not about the lenses. Any prose reads: a reading
#: is free text to everything downstream, and only the composer's reply is parsed.
LENS_READING = "l-001 separates h-001 from h-002."


def stage(reply: str) -> Any:
    """One stage returning `reply`, whatever it is handed. A scenario that inspects what reached
    a role (the frame, the salt, the projection) binds its own recording stage."""

    async def call(_request):
        return reply

    return call


def composer_reply(finding: str = "holds", review: str = "reads sound", ask: Any = None) -> str:
    """The composer's contract as one JSON line. `finding` is `holds` or `gap`, and an `ask`
    names a target the investigation actually recorded — `citable_refs` refuses anything
    else, which fails the whole review as unreadable rather than routing on it."""
    return json.dumps({"finding": finding, "review": review, "ask": ask})


def bundle(*, composer: str, lens: str = LENS_READING) -> ReviewStages:
    """All three stages bound: every lens answers `lens` and only the composer varies, since the
    routing turns on what the composer found (the host sees a lens reading only through it)."""
    return ReviewStages(
        support=stage(lens), ablation=stage(lens),
        composer=stage(composer),
    )
