"""The agent's tool surface: what a role may call, and the wiring that registers it.

The tool bodies live in four modules, layered one way:

  * `_deps`     — `AgentDeps`/`GatherDeps`, the objects every tool is handed, plus the
                  read caps and result formatting they share.
  * `_bash`     — the bash verb and the path plumbing that decides what a command may open.
  * `_files`    — read, write and edit, each through the permission gate.
  * `_document` — the invlang repair window, and the three verbs that move the
                  investigation: append a block, repair a row, recall the frontier.

This module keeps the registration functions — the only place that knows which verbs a
role actually gets — and re-exports the tool bodies for existing importers.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Self

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    from defender.skills.invlang.validate import Diagnostic

from defender._clock import now_iso
from defender._paths import PATHS

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from .. import box as box_mod
from .. import permission
from ..agent_definition import ResolvedRoots, ToolSet
from ..agent_role import AgentRole
from ..permission.files import RESOLVE_ERRORS

from defender._untrusted import wrap_fresh
from defender._artifact_schema import _utf8_len
from defender._env import FatalConfigError, env_int
from defender.scripts.adapters.faults import USAGE_EXIT_CODE
from defender.runtime.sql_engine import sql as defender_sql
from defender.scripts.gather_tools import record_query
from defender.runtime.payload_view import (
    passthrough_max_bytes as _capture_view_cap,
)
from defender._knowledge import RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA
from defender.hooks.record_lesson_load import lesson_name as _lesson_name
from ._deps import (
    AgentDeps,
    DeadEnd,
    GatherDeps,
    LeadStop,
    _BASH_TIMEOUT_S,
    _BASH_VERB,
    _INFRA_EXIT_CODE,
    _bounded_read,
    _cap_for,
    _format_bash_result,
    _lane_admits,
    _overflow_filter_hint,
    _read_char_cap,
    _record_lesson_load,
)
from ._bash import (
    _BASH_NO_OPERAND_HINT,
    _BASH_REDUCED_HINT,
    _bash_env,
    _bash_overflow_hint,
    _bounded_bash_stream,
    _deny_authored_bash_read,
    _deny_authored_read,
    _grep_lines,
    _is_cross_agent_read,
    _is_learning_role,
    _opened_operands,
    _opens_untrusted_read,
    _record_shim_failure,
    _resolve_operand,
    _resolved,
    _rooted_operand,
    _shim_exit_code,
    _tool_bash,
    _under,
)
from ._files import (
    _bound_and_wrap,
    _closed_for_investigation_write,
    _gated_read,
    _read_operand,
    _tail_chars,
    _tool_edit_file,
    _tool_read_file,
    _tool_write_file,
    _write_operand,
)
from ._document import (
    _LINE_SEP_RE,
    _addressable,
    _attr_block_columns,
    _flagged_rows,
    _frontier_recall,
    _investigation_path,
    _new_row_shape_reason,
    _split_lines,
    _tool_append_block,
    _tool_fix_row,
    _warn_over,
    _warning_return,
    CompanionRead,
    committed_document_refusal,
    flagged_diagnostics,
    flagged_in,
    flagged_write_refusal,
    read_companion,
    repairable_diagnostics,
    repairable_in,
    unreadable_write_refusal,
)


def register_tools(agent, tools: ToolSet, verbs: Any = None) -> None:

    if tools.bash:
        @agent.tool
        async def bash(ctx: RunContext[AgentDeps], command: str) -> str:
            """Run a shell command. Use the `defender-*` shims (defender-invlang,
            defender-lessons, …) for first-party tooling. Data-source adapters are
            not runnable from the main loop — dispatch gather instead."""
            return _tool_bash(ctx.deps, command)

    if tools.read:
        @agent.tool
        async def read_file(
            ctx: RunContext[AgentDeps],
            path: str,
            pattern: str | None = None,
            tail: int | None = None,
        ) -> str:
            """Read a file's contents (e.g. alert.json, a SKILL, a lesson). Pass
            `pattern` to return only the lines containing that substring — the grep
            fold, for scanning a large file (or when the read-only bash grep/cat
            viewers are not available to this agent). Pass `tail` for at most the last
            N characters instead of the whole file, never starting mid-row — the cheap
            way to re-sync with `investigation.md` after a frontier fold. Both compose:
            `pattern` narrows first, then `tail` takes the end of what is left."""
            return _tool_read_file(ctx.deps, path, pattern, tail)

    if tools.write:
        # `sequential=True`: tool calls in one response otherwise run concurrently, and two
        # writes (especially read-modify-write edits) to one file would silently lose one.
        @agent.tool(sequential=True)
        async def write_file(ctx: RunContext[AgentDeps], path: str, content: str) -> str:
            """Write a file within this agent's declared write scope, replacing it whole.
            Content is validated against the schema for whatever artifact the path names."""
            return _tool_write_file(ctx.deps, path, content)

        @agent.tool(sequential=True)
        async def edit_file(
            ctx: RunContext[AgentDeps], path: str, old_string: str, new_string: str
        ) -> str:
            """Replace the first occurrence of old_string with new_string in a file within
            this agent's declared write scope. old_string must match exactly once. The
            resulting full text is validated."""
            return _tool_edit_file(ctx.deps, path, old_string, new_string)

    if tools.append:
        _register_investigation_verbs(agent)

    _register_deferred_tools(agent, tools, verbs)


def _register_investigation_verbs(agent) -> None:
    """The two verbs bound to `investigation.md` — the append and the repair.

    `fix_row` rides `append=True`: an agent that may grow the transcript may repair it."""
    # `sequential=True`: concurrent calls in one response would lose an update while both
    # report success.
    @agent.tool(sequential=True)
    async def append_block(ctx: RunContext[AgentDeps], text: str) -> str:
        """Append to investigation.md, the invlang work log — no path and no anchor,
        because the run has one transcript and it only ever grows. Send ONE invlang
        block per call. The resulting full document is validated (invlang); if it is
        refused, nothing is written and the file still does not contain your text. A
        WARNING is different: the block DID land, and the flagged row blocks the next
        write until you repair it with fix_row. To record a disposition use
        close_investigation, the report's only writer."""
        return _tool_append_block(ctx.deps, text)

    @agent.tool(prepare=_prepare_fix_row, sequential=True)
    async def fix_row(ctx: RunContext[AgentDeps], old_row: str, new_row: str) -> str:
        """Repair ONE flagged row of investigation.md in place — offered only while a
        row is flagged. `old_row` must be a currently-flagged row, copied exactly as the
        warning printed it; it is matched as a whole line, never as a substring, and
        never outside the flagged set. `new_row` replaces it and must be a single row of
        the same block with the same columns; an EMPTY `new_row` deletes the line. This
        is not a general editor: nothing else in the document is reachable through it."""
        return _tool_fix_row(ctx.deps, old_row, new_row)


async def _prepare_fix_row(ctx: RunContext[AgentDeps], tool_def: Any) -> Any:
    """Offer `fix_row` only while the repair set is non-empty.

    Ergonomics, not a control: a model can still emit the call later, and `_tool_fix_row`
    re-derives and refuses. Keyed on the repair set (not the warn window) so error-severity
    rows still get the verb."""
    return tool_def if repairable_diagnostics(ctx.deps) else None


def _register_deferred_tools(agent, tools: ToolSet, verbs: Any = None) -> None:
    if tools.lesson_read:
        from defender.learning.author.lesson_read import register_lesson_read_tool

        register_lesson_read_tool(agent)

    if tools.template_search:
        from defender.runtime.tools_gather import register_template_search_tool

        register_template_search_tool(agent)

    if tools.query:
        from defender.runtime.query_tool import register_query_tool

        if verbs is None:
            raise ValueError(
                "ToolSet(query=True) needs a verb registry — thread one from "
                "run_investigation(verbs=…); a query tool with no registry has no allowlist."
            )
        register_query_tool(agent, verbs)

    if tools.list_verbs:
        from defender.runtime.query_tool import register_list_verbs_tool

        if verbs is None:
            raise ValueError(
                "ToolSet(list_verbs=True) needs a verb registry — thread one from "
                "run_investigation(verbs=…); the tool answers off the registry's grant, and "
                "with no registry it has no surface to report and no allowlist to filter by."
            )
        register_list_verbs_tool(agent, verbs)


from ..tools_gather import (  # noqa: E402, F401  (re-exported — public surface)
    GatherRequest,
    _gather_prompt,
    _payload_note,
    _persist_gather_summary,
    _run_gather,
    _tripped_message,
    register_gather_tool,
)


#: Re-exports; each name's home is the module it is imported from.
__all__ = [
    "Diagnostic",
    "AgentDeps",
    "AgentRole",
    "Any",
    "ClassVar",
    "FatalConfigError",
    "DeadEnd",
    "GatherDeps",
    "LeadStop",
    "Iterable",
    "Iterator",
    "ModelRetry",
    "PATHS",
    "Path",
    "RESOLVE_ERRORS",
    "ResolvedRoots",
    "Self",
    "TYPE_CHECKING",
    "USAGE_EXIT_CODE",
    "_BASH_NO_OPERAND_HINT",
    "_BASH_REDUCED_HINT",
    "_BASH_TIMEOUT_S",
    "_BASH_VERB",
    "_INFRA_EXIT_CODE",
    "_LINE_SEP_RE",
    "_RUNTIME_LESSON_CORPORA",
    "_addressable",
    "_attr_block_columns",
    "_bash_env",
    "_bash_overflow_hint",
    "_bound_and_wrap",
    "_bounded_bash_stream",
    "_bounded_read",
    "_cap_for",
    "_capture_view_cap",
    "_closed_for_investigation_write",
    "_deny_authored_bash_read",
    "_deny_authored_read",
    "_flagged_rows",
    "_format_bash_result",
    "_frontier_recall",
    "_gated_read",
    "_read_operand",
    "_grep_lines",
    "_investigation_path",
    "_is_cross_agent_read",
    "_is_learning_role",
    "_lane_admits",
    "_lesson_name",
    "_new_row_shape_reason",
    "_opened_operands",
    "_opens_untrusted_read",
    "_overflow_filter_hint",
    "_prepare_fix_row",
    "_read_char_cap",
    "_record_lesson_load",
    "_record_shim_failure",
    "_register_deferred_tools",
    "_register_investigation_verbs",
    "_resolve_operand",
    "_resolved",
    "_rooted_operand",
    "_shim_exit_code",
    "_split_lines",
    "_tail_chars",
    "_tool_append_block",
    "_tool_bash",
    "_tool_edit_file",
    "_tool_fix_row",
    "_tool_read_file",
    "_tool_write_file",
    "_write_operand",
    "_under",
    "_utf8_len",
    "_warn_over",
    "_warning_return",
    "box_mod",
    "CompanionRead",
    "committed_document_refusal",
    "dataclass",
    "defender_sql",
    "env_int",
    "field",
    "flagged_diagnostics",
    "flagged_in",
    "flagged_write_refusal",
    "json",
    "now_iso",
    "permission",
    "re",
    "record_query",
    "register_tools",
    "read_companion",
    "repairable_diagnostics",
    "repairable_in",
    "subprocess",
    "sys",
    "time",
    "unreadable_write_refusal",
    "wrap_fresh",
]
