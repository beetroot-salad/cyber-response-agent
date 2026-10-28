"""The shipped ```invlang documents, in one place."""

from __future__ import annotations

import functools
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[4]


@functools.cache
def corpus_docs() -> list[Path]:
    """The `examples/` the SKILL points at, the e2e fixture runs and the committed
    `tests/fixtures/invlang/` documents — every one carrying an ```invlang fence.

    Cached: each `parametrize` that adopts it calls it at collection time, and each call
    reads the whole corpus.
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
