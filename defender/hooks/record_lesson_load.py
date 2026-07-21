from __future__ import annotations

from pathlib import Path

LESSON_CORPORA = frozenset({"lessons", "lessons-actor", "lessons-environment"})

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


