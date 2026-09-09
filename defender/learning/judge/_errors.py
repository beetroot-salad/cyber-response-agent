"""The judge's own refusal class, in its own module so every submodule can import it without
a package-`__init__` import cycle (`learning/judge/__init__.py` orchestrates the submodules
below it and re-exports this name)."""

from __future__ import annotations


class JudgeRefused(ValueError):
    """A judge pass this design cannot honestly run: a malformed archived input, a manifest
    that fails the judge's own load-time validation (J1's holding-system check, J5 tier 2's
    "malformed refuses loudly", J5 tier 3's duplicate/colliding label), or a reply that fails
    `JudgeReply` validation.

    Never raised for an ABSENT input — J5 tier 1 marks the world `ungradable` instead, named
    and excluded rather than raised on. Raised only for a fault a human has to look at: the
    input exists and is not what this design can honestly read.

    A `ValueError` SUBCLASS (#1007), not a bare `Exception`: `tests/_world_1007.py`'s `refusals()`
    is `_triplet_947.refusals()`, which names `ValueError` and never `JudgeRefused` itself — no
    #1007 test imports this class directly. `grade_episode`'s own conversion set still names
    `JudgeRefused` FIRST in its `except` chain (`except JudgeRefused: raise` ahead of
    `except (OSError, ValueError, ...)`), so this changes no existing behavior there: Python
    matches `except` clauses in order, and the more specific one still wins.
    """
