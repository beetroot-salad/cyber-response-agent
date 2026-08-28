
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    pass


from pydantic_ai.exceptions import ModelRetry

from defender._io import read_text_utf8, write_guarded
from .. import permission
from ..permission.files import RESOLVE_ERRORS

from defender._untrusted import wrap_fresh
# The SAME byte ruler the artifact bounds are measured with — a write tool that reports
# "bytes" must report the number the gate will judge, not a codepoint count that under-reads it.
from defender.hooks.record_lesson_load import (
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
)
from ._deps import AgentDeps, _bounded_read, _cap_for, _overflow_filter_hint, _record_lesson_load
from ._bash import _deny_authored_read, _grep_lines, _guarded_parents, _is_cross_agent_read, _is_learning_role, _resolve_operand, _resolved


def _probe_is_file(p: Path, path: str) -> bool:
    """`p.is_file()` over a MODEL-AUTHORED path, as a refusal rather than a traceback.

    `pathlib` swallows only `_IGNORED_ERRNOS` — ENOENT/ENOTDIR/EBADF/ELOOP — and every other
    `os.stat` error comes back out. The reachable one is ENAMETOOLONG: the read gate ALLOWS a
    basename over `NAME_MAX`, because MAIN's and GATHER's run-root read shape is
    `under(run, SEG)` with `SEG = [\\w.@=+-]+`, which places no length bound, and
    `Path.resolve()` does not stat. So an allowed path reaches the probe and raises — outside
    every `try`, past `on_tool_execute_error`, past `_drive_agent`'s handlers and out of
    `asyncio.run` — ending the run with no disposition and no `report.md`.

    Bounding `SEG` is deliberately NOT the fix: the probe has to survive an allowed path
    whatever its shape."""
    try:
        return p.is_file()
    except OSError as e:
        raise ModelRetry(f"could not read {path}: {e}") from None


def _probe_read_text(p: Path, path: str) -> str:
    """`read_text_utf8(p)` over a MODEL-AUTHORED path, as a refusal rather than a traceback.

    The other half of `_probe_is_file`, and ONE copy: `_gated_read` and `_tool_edit_file` both
    read the same operand under the same two fault classes (undecodable, unreadable) and owe
    the model the same two refusals."""
    try:
        return read_text_utf8(p)
    except UnicodeDecodeError:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)") from None
    except OSError as e:
        raise ModelRetry(f"could not read {path}: {e}") from None


def _gated_read(
    deps: AgentDeps, path: str, *, lesson_corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA
) -> tuple[Path, str]:
    p = _resolve_operand(deps, path)
    decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    if not _probe_is_file(p, path):
        raise ModelRetry(f"file not found: {path}")
    _deny_authored_read(deps, p)
    text = _probe_read_text(p, path)
    _record_lesson_load(deps, p, lesson_corpora)
    return p, text


def _bound_and_wrap(
    deps: AgentDeps, p: Path, path: str, text: str, *, read_tool: str
) -> str:
    text = _bounded_read(
        text, path, cap=_cap_for(p),
        filter_hint=_overflow_filter_hint(path, deps.policy, read_tool),
        read_tool=read_tool,
    )
    if permission.is_untrusted_read(p) or (
        _is_learning_role(deps) and _is_cross_agent_read(deps, p)
    ):
        return wrap_fresh(text, "untrusted")
    return text


def _tail_chars(text: str, n: int) -> str:
    """The last `n` characters, trimmed FORWARD to the next line start so a `|`-delimited
    invlang row never arrives cut in half and reads as truncated data. `n` is a ceiling, not a
    target. `n <= 0` yields nothing; a file shorter than `n` is returned whole; text with no
    newline in the window is cut at `n`.

    Its own fold rather than a reuse of `_bounded_read`, whose overflow path keeps the HEAD —
    the wrong end of an append-only log."""
    if n <= 0:
        return ""
    if len(text) <= n:
        return text
    cut = len(text) - n  # >= 1, since the whole-file case returned above
    nl = text.find("\n", cut - 1)
    return text[nl + 1:] if nl != -1 else text[cut:]


def _tool_read_file(
    deps: AgentDeps, path: str, pattern: str | None = None, tail: int | None = None
) -> str:
    p, text = _gated_read(deps, path)
    if pattern is not None:
        text = _grep_lines(text, pattern)
    if tail is not None:
        text = _tail_chars(text, tail)
    return _bound_and_wrap(deps, p, path, text, read_tool="read_file")


def _closed_for_investigation_write(deps: AgentDeps, p: Path) -> bool:
    """RS15. `investigation.md` becomes review-state-aware AFTER a close commits, so no
    post-close write can silently move the recorded disposition. Up to the close the document
    stays model-writable; this is the ONE gate on it.

    The `resolve()` here runs one line AHEAD of `decide_write`/`decide_read`, so an operand it
    cannot resolve (an embedded NUL — `ValueError`; a symlink cycle — `RuntimeError`) would
    escape the write/edit tool as an unhandled exception, routing around the fail-closed
    `Decision(False)` the gate's `RESOLVE_ERRORS` rule produces. An unresolvable operand is
    certainly not `<run_dir>/investigation.md`, so answering False is honest — and it hands the
    operand to the gate, which denies it with a correctable reason."""
    try:
        if p.resolve() != (deps.run_dir / "investigation.md").resolve():
            return False
    except RESOLVE_ERRORS:
        return False
    from ..challenge_gate import ReviewState

    return ReviewState.of(deps).closed


def _tool_write_file(deps: AgentDeps, path: str, content: str) -> str:
    p = _resolve_operand(deps, path)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further write could silently "
            "move it. The case is closed."
        )
    decision = permission.decide_write(
        p, content, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, content)
    deps.authored_paths.add(_resolved(p))
    return f"wrote {path} ({len(content)} bytes)"


def _tool_edit_file(deps: AgentDeps, path: str, old_string: str, new_string: str) -> str:
    p = _resolve_operand(deps, path)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further edit could silently "
            "move it. The case is closed."
        )
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    # ONE probe, not one here and another in the empty-`old_string` check below: they ask the
    # same question about the same path, and a second stat could answer it differently.
    exists = _probe_is_file(p, path)
    current = _probe_read_text(p, path) if exists else ""
    if not old_string and exists:
        raise ModelRetry(
            f"{path} already exists; an empty old_string would overwrite it. "
            "Pass a unique old_string to edit, or use write_file to replace it."
        )
    if old_string and old_string not in current:
        raise ModelRetry(f"old_string not found in {path}")
    if old_string and current.count(old_string) > 1:
        raise ModelRetry(
            f"old_string is not unique in {path} ({current.count(old_string)} "
            "occurrences); include enough surrounding context to match exactly "
            "one, or use write_file to replace the whole file."
        )
    new_text = current.replace(old_string, new_string, 1) if old_string else new_string
    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, new_text)
    deps.authored_paths.add(_resolved(p))
    return f"edited {path} ({len(new_text)} bytes)"
