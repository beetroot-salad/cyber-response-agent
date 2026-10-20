"""The shipped ```invlang documents, in one place."""

from __future__ import annotations

import functools
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[4]


@functools.cache
def corpus_docs() -> list[Path]:
    """The `fixtures-e2e/` golden runs, the `examples/` the SKILL points at, and the
    committed run documents under `tests/_golden_invlang/`.

    Cached: this is called once per `parametrize` decorator, at COLLECTION time, and each
    call globs two trees and reads every hit to filter on the fence. The list is a fact
    about the tree, not about the caller, and every rule that adopts this helper would
    otherwise add another full pass over the corpus before a single test runs.
    """
    candidates = [
        *sorted((DEFENDER / "examples").glob("*.md")),
        *sorted((DEFENDER / "tests" / "fixtures" / "e2e").glob("*/investigation.md")),
        *sorted((DEFENDER / "tests" / "fixtures" / "invlang").glob("*.investigation.md")),
    ]
    docs = [p for p in candidates if "```invlang" in p.read_text(encoding="utf-8")]
    # An empty parametrize list is a silently-green suite; if the corpus moves, this must
    # be a loud collection error, not a check that stopped running.
    assert docs, "no ```invlang corpus documents found — did the tree move?"
    return docs


def corpus_id(path: Path) -> str:
    return str(path.relative_to(DEFENDER))
