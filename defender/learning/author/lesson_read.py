from __future__ import annotations

from typing import Literal

from pydantic_ai import RunContext

from defender._frontmatter import FrontmatterError, parse_frontmatter
from defender.hooks.record_lesson_load import LESSON_CORPORA
from defender.runtime.tools import AgentDeps, _bound_and_wrap, _gated_read, _grep_lines


def _select_part(text: str, part: str) -> str:
    if part == "body":
        try:
            return parse_frontmatter(text)[1]
        except FrontmatterError:
            return text
    return text


def _tool_lesson_read(
    deps: AgentDeps, path: str, part: str = "body", pattern: str | None = None
) -> str:
    p, text = _gated_read(deps, path, lesson_corpora=LESSON_CORPORA)
    text = _select_part(text, part)
    if pattern is not None:
        text = _grep_lines(text, pattern)
    return _bound_and_wrap(deps, p, path, text, read_tool="lesson_read")


def register_lesson_read_tool(agent) -> None:

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
