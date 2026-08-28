"""The agent's tool surface: what a role may call, and the wiring that registers it.

The tool bodies live in four modules, layered one way and split out of this one when it
reached 1503 lines:

  * `_deps`     — `AgentDeps`/`GatherDeps`, the objects every tool is handed, plus the
                  read caps and result formatting they share.
  * `_bash`     — the bash verb and the path plumbing that decides what a command may open.
  * `_files`    — read, write and edit, each through the permission gate.
  * `_document` — the invlang repair window, and the three verbs that move the
                  investigation: append a block, repair a row, recall the frontier.

This module keeps the registration functions — the only place that knows which verbs a
role actually gets — and re-exports the tool bodies, so the split is invisible to the 72
files that import from here.
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

from defender._io import guarded_mkdir, read_text_utf8, write_guarded
from .. import box as box_mod
from .. import permission
from ..agent_definition import ResolvedRoots, ToolSet
from ..agent_role import AgentRole
from ..permission.files import RESOLVE_ERRORS

from defender._untrusted import wrap_fresh
# The SAME byte ruler the artifact bounds are measured with — a write tool that reports
# "bytes" must report the number the gate will judge, not a codepoint count that under-reads it.
from defender._artifact_schema import _utf8_len
from defender._env import FatalConfigError, env_int
from defender.scripts.adapters.faults import USAGE_EXIT_CODE
from defender.scripts.gather_tools import sql as defender_sql
from defender.scripts.gather_tools import record_query
from defender.scripts.gather_tools.payload_view import (
    passthrough_max_bytes as _capture_view_cap,
)
from defender.hooks.record_lesson_load import (
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
    lesson_name as _lesson_name,
)
from ._deps import (
    AgentDeps,
    GatherDeps,
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
    _guarded_parents,
    _is_cross_agent_read,
    _is_learning_role,
    _opened_operands,
    _opens_untrusted_read,
    _record_shim_failure,
    _resolve_operand,
    _resolved,
    _shim_exit_code,
    _tool_bash,
    _tree_root_for,
    _under,
)
from ._files import (
    _bound_and_wrap,
    _closed_for_investigation_write,
    _gated_read,
    _probe_is_file,
    _probe_read_text,
    _tail_chars,
    _tool_edit_file,
    _tool_read_file,
    _tool_write_file,
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
    committed_document_refusal,
    flagged_diagnostics,
    flagged_write_refusal,
    repairable_diagnostics,
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
        # `sequential=True` on BOTH, the same rule `append_block`/`fix_row` carry below and the
        # close tool carries in close_tool.py: these two write a SHARED ARTIFACT, so two
        # `ToolCallPart`s in one model response would otherwise run as concurrent tasks and one
        # write would be lost. `edit_file` is the worse of the two — it is a read-modify-write
        # (`_probe_read_text`, splice, `write_guarded`), so two concurrent edits on one file both
        # read the same pre-image and one splice vanishes while both calls report success. These
        # are granted to CORPUS_AUTHOR and LEAD_AUTHOR, whose lesson files the learning corpus is
        # built from.
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

    One grant, one registration site: `fix_row` rides `append=True` rather than minting a
    capability bit, so an agent that may grow the transcript may also repair a row it landed
    in it. Split out of `register_tools` to keep that function under the complexity gate."""
    # `sequential=True`: two `ToolCallPart`s in ONE model response otherwise run concurrently,
    # and against the real write primitive that is a genuine LOST UPDATE — both calls read the
    # same pre-image, one change reaches disk, and both report success. A `fix_row` paired with
    # an `append_block` could discard the repair while telling the model it landed, leaving a
    # window that looks shut and is not.
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
    """Offer `fix_row` only while the repair window is open.

    ERGONOMICS, not a control. The offer is computed once per model REQUEST, so a model that
    saw the definition on an earlier turn can still emit the call after the window closed;
    `_tool_fix_row` re-derives and refuses. The security property rests on that body.

    Offered on the REPAIR set, which the body also gates on: a document whose only defect is
    error-severity has no warn window, and offering on that would hide the verb in exactly the
    case the close is about to demand it."""
    return tool_def if repairable_diagnostics(ctx.deps) else None


def _register_deferred_tools(agent, tools: ToolSet, verbs: Any = None) -> None:
    if tools.forward_check:
        from defender.learning.author.verify_forward.tool import register_forward_check_tool

        register_forward_check_tool(agent)

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

    if tools.closed_tickets:
        from defender.learning.pipeline.judge.closed_ticket_tool import (
            register_closed_ticket_tools,
        )

        register_closed_ticket_tools(agent, verbs)


from ..tools_gather import (  # noqa: E402, F401  (re-exported — public surface)
    GatherRequest,
    _gather_prompt,
    _payload_note,
    _persist_gather_summary,
    _run_gather,
    _tripped_message,
    register_gather_tool,
)


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "Diagnostic",
    "AgentDeps",
    "AgentRole",
    "Any",
    "ClassVar",
    "FatalConfigError",
    "GatherDeps",
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
    "_grep_lines",
    "_guarded_parents",
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
    "_probe_is_file",
    "_probe_read_text",
    "_read_char_cap",
    "_record_lesson_load",
    "_record_shim_failure",
    "_register_deferred_tools",
    "_register_investigation_verbs",
    "_resolve_operand",
    "_resolved",
    "_shim_exit_code",
    "_split_lines",
    "_tail_chars",
    "_tool_append_block",
    "_tool_bash",
    "_tool_edit_file",
    "_tool_fix_row",
    "_tool_read_file",
    "_tool_write_file",
    "_tree_root_for",
    "_under",
    "_utf8_len",
    "_warn_over",
    "_warning_return",
    "box_mod",
    "committed_document_refusal",
    "dataclass",
    "defender_sql",
    "env_int",
    "field",
    "flagged_diagnostics",
    "flagged_write_refusal",
    "guarded_mkdir",
    "json",
    "now_iso",
    "permission",
    "re",
    "read_text_utf8",
    "record_query",
    "register_tools",
    "repairable_diagnostics",
    "subprocess",
    "sys",
    "time",
    "wrap_fresh",
    "write_guarded",
]
