
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    pass


from pydantic_ai.exceptions import ModelRetry

from defender._io import (
    REFUSED_NOT_FILE,
    REFUSED_UNDECODABLE,
    bind,
    rooted_mkdir,
    rooted_write,
)
from defender._run_paths import RunPaths
from .. import permission
from ..permission.files import RESOLVE_ERRORS

from defender._untrusted import wrap_fresh
from defender.hooks.record_lesson_load import (
    LOAD_KIND_READ as _LOAD_KIND_READ,
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
)
from ._deps import AgentDeps, _bounded_read, _cap_for, _overflow_filter_hint, _record_lesson_load
from ._bash import _deny_authored_read, _grep_lines, _is_cross_agent_read, _is_learning_role, _resolve_operand, _resolved, _rooted_operand


def _read_operand(deps: AgentDeps, p: Path, path: str) -> str | None:
    """The text of the plain file at the operand `p` through the rooted core, `None` when no
    file stands there (nothing, or a folder or FIFO, as `is_file()` answered before). Every
    other refusal is a `ModelRetry` naming no host path: a link anywhere below the root or a
    hard link at the name is refused, never followed, and the open never blocks."""
    root, name = _rooted_operand(deps, p, path=path)
    try:
        with bind(root) as tree:
            got = tree.read(name)
    except (OSError, ValueError) as e:
        raise ModelRetry(f"could not read {path}: {getattr(e, 'strerror', None) or e}") from None
    if got.absent or got.refused_by == REFUSED_NOT_FILE:
        return None
    if got.refused_by == REFUSED_UNDECODABLE:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)")
    if got.reason is not None:
        raise ModelRetry(f"could not read {path}: {got.reason}")
    return got.text


def _write_operand(deps: AgentDeps, p: Path, path: str, text: str) -> None:
    """Replace the file at the operand `p` with `text` through the rooted core, off the same
    root its read takes, making its missing holding folders: nothing below the root is
    followed, a non-plain entry at the name is refused and left in place, and every refusal is
    a `ModelRetry` naming no host path."""
    root, name = _rooted_operand(deps, p, path=path)
    try:
        rooted_mkdir(root, PurePosixPath(name).parent.as_posix())
        rooted_write(root, name, text, mode="replace")
    except (OSError, ValueError) as e:
        raise ModelRetry(f"could not write {path}: {getattr(e, 'strerror', None) or e}") from None


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
    _deny_authored_read(deps, p)
    text = _read_operand(deps, p, path)
    if text is None:
        raise ModelRetry(f"file not found: {path}")
    _record_lesson_load(deps, p, lesson_corpora, kind=_LOAD_KIND_READ)
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
    """At most the last `n` characters, trimmed forward to a line start so an invlang row is
    never cut in half. `n <= 0` yields nothing; with no newline in the window, cut at `n`."""
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
    """Whether `p` is `investigation.md` after a close has committed, so no post-close write
    can move the recorded disposition.

    An unresolvable operand answers False (it is not the investigation) and is left for the
    permission gate to deny with a correctable reason, rather than raising here."""
    try:
        if p.resolve() != RunPaths(deps.run_dir).investigation.resolve():
            return False
    except RESOLVE_ERRORS:
        return False
    from ..challenge_gate import ReviewState

    return ReviewState.of(deps).closed


def _tool_write_file(deps: AgentDeps, path: str, content: str) -> str:
    p = _resolve_operand(deps, path)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "recorded disposition for this run, and a further write could silently "
            "move it. The case is closed."
        )
    decision = permission.decide_write(
        p, content, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _write_operand(deps, p, path, content)
    deps.authored_paths.add(_resolved(p))
    return f"wrote {path} ({len(content)} bytes)"


def _tool_edit_file(deps: AgentDeps, path: str, old_string: str, new_string: str) -> str:
    p = _resolve_operand(deps, path)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "recorded disposition for this run, and a further edit could silently "
            "move it. The case is closed."
        )
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    # One read, so both checks below see the same answer.
    read = _read_operand(deps, p, path)
    exists = read is not None
    current = read if read is not None else ""
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
    _write_operand(deps, p, path, new_text)
    deps.authored_paths.add(_resolved(p))
    return f"edited {path} ({len(new_text)} bytes)"
