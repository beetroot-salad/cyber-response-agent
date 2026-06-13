"""Generic agent tools: bash, read_file, write_file, edit_file.

These four small tools are the agent's whole surface — stable across every
future adapter (a new data source is a shim + skill, never a new tool). They
mirror Claude Code's Read/Write/Edit/Bash so SKILL.md transfers verbatim. Each
tool enforces its own contract by calling the single `permission` gate and
raising `ModelRetry` on a deny (the in-process equivalent of a PreToolUse hook's
exit-2 feedback). Untrusted reads are wrapped in the salted tag in-process — the
clean version of the `tag_tool_results` annotation.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from . import permission

# Reuse the existing salted-tag helper so the delimiter shape matches the rest
# of the system. hooks/ is already on sys.path via permission.py's bootstrap.
from tag_tool_results import wrap as _wrap  # noqa: E402

_BASH_TIMEOUT_S = 120


@dataclass(frozen=True)
class RunDeps:
    """Per-run state threaded into every tool via `ctx.deps`."""

    run_dir: Path
    defender_dir: Path
    run_id: str
    salt: str
    is_main_session: bool = True


def _bash_env(deps: RunDeps) -> dict[str, str]:
    """The runtime agent's shell environment — defined once in run.py and shared
    with the `claude -p` engine (defender/ is on sys.path[0] under run_pai)."""
    import run  # noqa: E402
    return run.run_env(deps.defender_dir, deps.run_dir)


def register_tools(agent) -> None:
    """Register the four generic tools on `agent` (deps_type must be RunDeps)."""

    @agent.tool
    async def bash(ctx: RunContext[RunDeps], command: str) -> str:
        """Run a shell command. Use the `defender-*` shims (defender-invlang,
        defender-lessons, …) for first-party tooling. Data-source adapters are
        not runnable from the main loop — dispatch gather instead."""
        decision = permission.decide_bash(
            command, is_main_session=ctx.deps.is_main_session
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                env=_bash_env(ctx.deps), cwd=str(ctx.deps.defender_dir.parent),
                timeout=_BASH_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}")
        out = proc.stdout if proc.stdout else ""
        err = f"\n--- stderr ---\n{proc.stderr}" if proc.stderr.strip() else ""
        return f"exit={proc.returncode}\n--- stdout ---\n{out}{err}"

    @agent.tool
    async def read_file(ctx: RunContext[RunDeps], path: str) -> str:
        """Read a file's contents (e.g. alert.json, a SKILL, a lesson)."""
        decision = permission.decide_read(
            Path(path), is_main_session=ctx.deps.is_main_session
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        p = Path(path)
        if not p.is_file():
            raise ModelRetry(f"file not found: {path}")
        text = p.read_text()
        if permission.is_untrusted_read(p):
            # Attacker-influenced data — wrap so injected instructions inside it
            # are inert. Same delimiter as the rest of the system.
            return _wrap(text, "untrusted", ctx.deps.salt)
        return text

    @agent.tool
    async def write_file(ctx: RunContext[RunDeps], path: str, content: str) -> str:
        """Write a file in the run dir (investigation.md, report.md). Writes of
        investigation.md are validated against the invlang schema."""
        decision = permission.decide_write(
            Path(path), content, run_dir=ctx.deps.run_dir
        )
        if not decision.allow:
            raise ModelRetry(decision.reason)
        Path(path).write_text(content)
        return f"wrote {path} ({len(content)} bytes)"

    @agent.tool
    async def edit_file(
        ctx: RunContext[RunDeps], path: str, old_string: str, new_string: str
    ) -> str:
        """Replace the first occurrence of old_string with new_string in a run-dir
        file. The resulting full text is validated (invlang for investigation.md)."""
        p = Path(path)
        current = p.read_text() if p.is_file() else ""
        if not old_string and p.is_file():
            # Empty old_string against an existing file would replace the WHOLE
            # file with new_string (silent clobber). Mirror Claude Code's Edit:
            # empty old_string is create-only. Use write_file for a full replace.
            raise ModelRetry(
                f"{path} already exists; an empty old_string would overwrite it. "
                "Pass a unique old_string to edit, or use write_file to replace it."
            )
        if old_string and old_string not in current:
            raise ModelRetry(f"old_string not found in {path}")
        new_text = current.replace(old_string, new_string, 1) if old_string else new_string
        decision = permission.decide_write(p, new_text, run_dir=ctx.deps.run_dir)
        if not decision.allow:
            raise ModelRetry(decision.reason)
        p.write_text(new_text)
        return f"edited {path} ({len(new_text)} bytes)"
