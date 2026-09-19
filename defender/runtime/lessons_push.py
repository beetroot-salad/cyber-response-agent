"""The frontier-keyed lessons push, shared by its two callers (#919, #936).

A lessons block reaches MAIN on two occasions, and both derive it HERE so they cannot
disagree on what "the lessons for this document" means:

  * the `append_block` / `fix_row` RETURN (`runtime/tools/_document._frontier_recall`) —
    pushed when the write moved the top three, and gated on a diff of the pre- and post-write
    documents so an unchanged block is never re-stapled;
  * the compaction FOLD's frontier row (`runtime/driver/_build._make_store_render_processor`)
    — the store-backed fold displaces every turn before the boundary, the write returns that
    carried earlier blocks with them, and `_frontier_recall`'s gate is stateless over the
    on-disk documents, so nothing would re-push what the model no longer holds. The frontier
    row carries a block derived over the FULL document at mint (`compose_fold`), once per
    boundary. Not the record `compaction.frontier_text` builds, which may be cut before the
    slot a lesson keys on; and not a verbatim carry-over of the blocks the displaced turns
    held, which would re-show what an earlier state matched rather than what this one does.

The gate that decides WHETHER to push stays with each caller — the write return diffs the
hits of two documents and renders only when they differ, the fold composes only when the
mint primitive asks it to (`selection.Composer`). The walk, the match and the render are
`_corpus.iter_lessons` and `lessons_frontier.match_loaded` / `render`, called directly by
both — this module holds only what has logic of its own: the corpus check with its stderr
line, the identity a block is compared on, the record, and the fold's composition.

NOT gated by `permission.decide_read`, deliberately, on the same terms `_frontier_recall`
states: the gate governs what the MODEL may read; this is the runtime composing text to hand
it. The corpus is a fixed internal path under `defender_dir`, never a model operand.
"""
from __future__ import annotations

import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from defender.hooks.record_lesson_load import LOAD_KIND_PUSH

if TYPE_CHECKING:
    from defender.scripts.lessons.lessons_frontier import Hit

    from .tools._deps import AgentDeps


def corpus_dir(deps: AgentDeps, *, lane: str) -> Path | None:
    """`defender_dir/lessons`, or `None` — LOUD under the caller's stderr prefix (`lane`,
    the same one its own failure line wears), on the same terms `frontier_from_text` states:
    a corpus that is not there produces the same silence as a corpus that matched nothing,
    and SKILL.md tells the model to read that silence as "nothing NEW matched". A
    mis-resolved `defender_dir` would otherwise disable the lane for the whole run with no
    exception, no test red, and no operator signal."""
    corpus = deps.defender_dir / "lessons"
    if not corpus.is_dir():
        print(f"{lane} no lessons corpus at {corpus}; omitting the lessons push", file=sys.stderr)
        return None
    return corpus


def shape(hits: Iterable[Hit]) -> list[tuple[str, int]]:
    """WHICH lessons, at what score — the identity a block is compared on. SORTED: the ranked
    list is re-ordered by which frontier item won (`_spread_over_items`, #935), so an
    unsorted comparison would re-emit a byte-identical block because one hit's winner moved.
    `_frontier_recall`'s own comment carries the full argument."""
    return sorted((str(h.path), h.score) for h in hits)


def record(deps: AgentDeps, hits: Iterable[Hit]) -> None:
    """One `push` row per hit, on the same terms a Read is recorded. `lessons_loaded.jsonl`
    is the loop's only "was this lesson in context" signal and the post-merge control
    `learning/ops/trace_lesson.py` reasons from — a push that left no row makes a merged
    lesson look inert to the human reviewing its impact.

    RESOLVED, the same spelling `render` hands the model and the same one `_gated_read`
    records: `record_lesson_load.lesson_name` gates on `p.parent.parent.name == "defender"`,
    so an unresolved `defender_dir` carrying a symlink or a `..` would show the block and
    write no row.
    """
    from .tools._deps import _record_lesson_load

    for hit in hits:
        _record_lesson_load(deps, hit.path.resolve(), kind=LOAD_KIND_PUSH)


_FOLD_LANE = "[driver]"


def compose_fold(
    deps: AgentDeps, record_text: str, document: str,
) -> tuple[str, Callable[[], None] | None]:
    """The frontier row's text — `record_text` plus the fold's block over the FULL `document`
    — and the after-commit action that records the push, in the shape `selection.Composer`
    names. The mint primitive calls this on the append path only and runs the action right
    after the row landed: a row says the lesson was in front of the model, so a reuse round
    neither derives nor records, and a mint that raised records nothing.

    FAILS OPEN on both halves, and that is not optional here: this runs inside the history
    processor that prepares MAIN's next request, so an exception would surface as a failed
    round on a fold that is otherwise sound — the frontier row must mint whether or not the
    lessons lane could contribute to it, and a row that minted must not fail its round over
    the record. One stderr line, never silence.
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
        print(f"{_FOLD_LANE} fold lessons push failed, omitting it: {e!r}", file=sys.stderr)
        return record_text, None

    def on_minted() -> None:
        try:
            record(deps, hits)
        except Exception as e:  # noqa: BLE001 — fail open; the row is already in front of MAIN
            print(f"{_FOLD_LANE} fold lessons push minted but did not record: {e!r}",
                  file=sys.stderr)

    return record_text + "\n\n" + block, on_minted
