"""The shipped ```invlang documents, in one place.

Every rule that says "and the corpus stays green" parametrizes over this list, so the list
itself is one fact with one owner rather than a glob each new rule re-derives (#803).

`learning/runs/` is deliberately absent. It is gitignored machine-local run output
(`.gitignore` line 79; `git ls-files` lists nothing under it), so globbing it makes the
parametrization a function of what happens to sit on the developer's disk — empty on CI,
where the guard is supposed to run, and on a laptop able to go red over a run nobody is
shipping.
"""

from __future__ import annotations

import functools
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]


@functools.cache
def corpus_docs() -> list[Path]:
    """The two `fixtures-e2e/` golden runs and the `examples/` the SKILL points at.

    Cached: this is called once per `parametrize` decorator, at COLLECTION time, and each
    call globs two trees and reads every hit to filter on the fence. The list is a fact
    about the tree, not about the caller, and every rule that adopts this helper would
    otherwise add another full pass over the corpus before a single test runs.
    """
    candidates = [
        *sorted((DEFENDER / "examples").glob("*.md")),
        *sorted((DEFENDER / "fixtures-e2e").glob("*/investigation.md")),
    ]
    docs = [p for p in candidates if "```invlang" in p.read_text(encoding="utf-8")]
    # An empty parametrize list is a silently-green suite; if the corpus moves, this must
    # be a loud collection error, not a check that stopped running.
    assert docs, "no ```invlang corpus documents found — did the tree move?"
    return docs


def corpus_id(path: Path) -> str:
    return str(path.relative_to(DEFENDER))
