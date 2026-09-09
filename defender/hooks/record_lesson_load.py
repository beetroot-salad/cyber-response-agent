from __future__ import annotations

from pathlib import Path

#: Every corpus the AUTHOR side may touch. It was a proper superset of the runtime's set while
#: the old pipeline shipped: `lessons-actor` and `lessons-environment` held the actor- and
#: environment-side observations, written by two curators the deleted judge was the sole
#: producer for. Both retired with it (#922), so the two sets coincide today.
#:
#: KEPT AS TWO NAMES rather than collapsed to one. They answer different questions — what a
#: curator may read and write, versus what the runtime agent loads at PLAN — and a single
#: constant would make the next author-only corpus silently readable by the runtime.
#: #1007 M7 adds `lessons-questioner` here, on the AUTHOR side alone — the questioner curator's
#: own read/write confine. `RUNTIME_LESSON_CORPORA` stays `{"lessons"}`: a world finding is
#: never a lesson the defender agent itself may read at PLAN time.
LESSON_CORPORA = frozenset({"lessons", "lessons-questioner"})

RUNTIME_LESSON_CORPORA = frozenset({"lessons"})


def lesson_name(file_path: str, corpora: frozenset[str] = LESSON_CORPORA) -> str | None:
    p = Path(file_path)
    if (
        p.suffix == ".md"
        and not p.name.startswith("_")
        and p.parent.name in corpora
        and p.parent.parent.name == "defender"
    ):
        return p.stem
    return None


