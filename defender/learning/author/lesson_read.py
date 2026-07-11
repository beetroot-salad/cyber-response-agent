"""The curators' ``lesson_read`` tool: ``read_file`` with a ``part`` mode (#559).

The four lesson curators lose the generic ``read_file`` (``read=True`` dropped from
``CORPUS_AUTHOR_DEF``) and gain ``lesson_read``, which wraps the SAME gate + bounded-read +
untrusted-wrap core (``runtime.tools`` ``_gated_read`` / ``_bound_and_wrap``) and adds ONE
seam: ``part``. ``part='body'`` (the default) strips the YAML frontmatter and returns the
lesson prose; ``part='full'`` returns the whole file including the frontmatter. A non-fenced
file (``parse_frontmatter`` raises ``FrontmatterError``) DEGRADES to whole text under body
rather than raising — a plain ``.md`` doc stays readable. ``pattern`` grep-folds the SELECTED
text (part-then-grep), so the curator keeps the substring fold ``read_file`` had.

The read surface is IDENTICAL to the removed ``read_file``'s — root-only ``decide_read``
(confined to ``{run_dir, defender_dir}``) — so a sibling corpus lesson and the actor/env
``_TEMPLATE.md`` schema stay reachable where the corpus-anchored bash ``cat`` lane cannot go.
It is neither narrowed to ``cat``'s corpus subdir (that would break the ``_TEMPLATE``/doc/
sibling reads the curator legitimately makes) nor broadened past ``read_file``. A lesson is
trusted (not ``is_untrusted_read``), so the reused salted wrap tail is inert for the corpus.

Lives here, not in ``runtime/tools.py``, so nothing curator-specific (the ``part`` mode, the
``_frontmatter`` dependency) leaks into the runtime — the shape ``register_forward_check_tool``
already uses. ``register_tools`` delegates to ``register_lesson_read_tool`` via a deferred import.
"""
from __future__ import annotations

from typing import Literal

from pydantic_ai import RunContext

from defender._frontmatter import FrontmatterError, parse_frontmatter
from defender.hooks.record_lesson_load import LESSON_CORPORA
from defender.runtime.tools import AgentDeps, _bound_and_wrap, _gated_read, _grep_lines


def _select_part(text: str, part: str) -> str:
    """The ``part`` seam over an already-read file. ``body`` strips the frontmatter — degrading
    to the whole text on a non-fenced file (``parse_frontmatter`` raises ``FrontmatterError``)
    rather than raising, so a plain ``.md`` doc is still readable. ``full`` is the whole file
    unconditionally (never parses). The tool arg's ``Literal`` pins ``part`` to ``{body, full}``,
    so there is no third branch to consider."""
    if part == "body":
        try:
            return parse_frontmatter(text)[1]
        except FrontmatterError:
            return text  # non-fenced file → whole text, not a raise
    return text  # full: the whole file, frontmatter included


def _tool_lesson_read(
    deps: AgentDeps, path: str, part: str = "body", pattern: str | None = None
) -> str:
    """Logic for ``lesson_read``: the shared gate+read core, then select ``part``, then the
    optional grep fold over the SELECTED text (part-then-grep), then the shared bound+wrap tail.
    One core with ``read_file`` — ``part`` is the only added seam.

    This tool is the ONE caller that widens the lesson-load trace to all three corpora (#559 F3):
    a curator folding an actor/env lesson records it symmetrically with a findings one. Every
    other reader keeps ``_gated_read``'s ``RUNTIME_LESSON_CORPORA`` default, because their
    ``run_dir`` is a durable per-case bundle ``trace_lesson`` reads as the DEFENDER's loads."""
    p, text = _gated_read(deps, path, lesson_corpora=LESSON_CORPORA)
    text = _select_part(text, part)
    if pattern is not None:
        text = _grep_lines(text, pattern)
    return _bound_and_wrap(deps, p, path, text)


def register_lesson_read_tool(agent) -> None:
    """Register the curator's ``lesson_read`` tool on ``agent`` (``deps_type`` must be an
    ``AgentDeps``). Called from ``register_tools`` when ``ToolSet.lesson_read`` is set — the
    curator's SOLE read surface after ``read=True`` is dropped. Lives here (not in
    ``runtime/tools.py``) so nothing curator-specific leaks into the runtime, mirroring
    ``register_forward_check_tool``."""

    @agent.tool
    async def lesson_read(
        ctx: RunContext[AgentDeps],
        path: str,
        part: Literal["body", "full"] = "body",
        pattern: str | None = None,
    ) -> str:
        """Read a lesson. ``part='body'`` (the default) returns the lesson prose with the YAML
        frontmatter stripped; ``part='full'`` returns the whole file INCLUDING the frontmatter
        (use it to read a ``_TEMPLATE.md`` schema, which lives in the frontmatter). Pass
        ``pattern`` to return only the lines of the selected text containing that substring — the
        grep fold, for scanning a large lesson."""
        return _tool_lesson_read(ctx.deps, path, part, pattern)
