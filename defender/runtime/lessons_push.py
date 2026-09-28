"""The frontier-keyed lessons push, shared by its two callers so they agree on what "the
lessons for this document" means:

  * the `append_block` / `fix_row` return (`runtime/tools/_document._frontier_recall`),
    pushed when a write changes the top hits;
  * the compaction fold's frontier row (`runtime/driver/_build._make_store_render_processor`):
    the fold displaces the turns that carried earlier blocks, so the row carries a block
    derived fresh over the full document at mint (`compose_fold`). Not over
    `compaction.frontier_text`, which may be cut before the slot a lesson keys on, and not
    a copy of the displaced blocks, which reflect an earlier state.

Each caller keeps its own gate for whether to push. Not gated by `permission.decide_read`:
that governs what the model may read, and this is the runtime composing text from a fixed
internal path, never a model operand.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from defender.hooks.record_lesson_load import LOAD_KIND_PUSH

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from defender.scripts.lessons.lessons_frontier import Hit

    from .tools._deps import AgentDeps


def corpus_dir(deps: AgentDeps, *, lane: str) -> Path | None:
    """`defender_dir/lessons`, or `None` with a warning under the caller's `lane` prefix. A
    missing corpus is otherwise silent (the model reads silence as "nothing new matched"), so
    a mis-resolved `defender_dir` would disable the lane unnoticed."""
    corpus = deps.defender_dir / "lessons"
    if not corpus.is_dir():
        _logger.warning(f"{lane} no lessons corpus at {corpus}; omitting the lessons push")
        return None
    return corpus


def shape(hits: Iterable[Hit]) -> list[tuple[str, int]]:
    """Which lessons at what score: the identity a block is compared on. Sorted, because the
    ranking is reordered by which frontier item won, and that alone must not re-emit an
    identical block."""
    return sorted((str(h.path), h.score) for h in hits)


def record(deps: AgentDeps, hits: Iterable[Hit]) -> None:
    """One `push` row per hit, like a Read. `lessons_loaded.jsonl` is the only "was this
    lesson in context" signal (e.g. for `learning/ops/trace_lesson.py`).

    Paths are resolved: `record_lesson_load.lesson_name` checks
    `p.parent.parent.name == "defender"`, so a symlink or `..` would drop the row.
    """
    from .tools._deps import _record_lesson_load

    for hit in hits:
        _record_lesson_load(deps, hit.path.resolve(), kind=LOAD_KIND_PUSH)


_FOLD_LANE = "[driver]"


def compose_fold(
    deps: AgentDeps, record_text: str, document: str,
) -> tuple[str, Callable[[], None] | None]:
    """The frontier row's text (`record_text` plus the block over the full `document`) and
    the after-commit action that records the push, as `selection.Composer` expects. The action
    runs only after the row lands, so a failed mint records nothing.

    Fails open (with a log line) on both halves: this runs in the history processor for
    main's next request, and the row must mint regardless of the lessons lane.
    """
    try:
        from defender._corpus import iter_lessons
        from defender.scripts.lessons.lessons_frontier import FOLD_LEAD, match_loaded, render
        from defender.skills.invlang.frontier import frontier_from_text

        corpus = corpus_dir(deps, lane=_FOLD_LANE)
        if corpus is None:
            return record_text, None
        frontier = frontier_from_text(document)
        if frontier.is_empty():
            return record_text, None
        hits = match_loaded(frontier, list(iter_lessons(corpus)))
        if not hits:
            return record_text, None
        block = render(hits, lead=FOLD_LEAD)
    except Exception as e:  # noqa: BLE001 — fail open; the frontier row mints regardless
        _logger.warning(f"{_FOLD_LANE} fold lessons push failed, omitting it: {e!r}")
        return record_text, None

    def on_minted() -> None:
        try:
            record(deps, hits)
        except Exception as e:  # noqa: BLE001 — fail open; the row is already in front of MAIN
            _logger.warning(f"{_FOLD_LANE} fold lessons push minted but did not record: {e!r}")

    return record_text + "\n\n" + block, on_minted
