#!/usr/bin/env python3
"""PostToolUse hook: Auto-allow manually approved commands.

When a Bash command or Read file access succeeds and is NOT already covered by
an existing allow-list pattern in settings.local.json, the user must have just
approved it manually. This hook adds the exact command/path to the allow list
so the user won't be prompted again for the same operation.

Dangerous commands (destructive ops, force pushes, etc.) are excluded even if
manually approved — they always require explicit approval.

Exit codes:
    0 - Always (should never block the agent)
"""

import fnmatch
import json
import os
import re
import sys
import tempfile
from pathlib import Path

SETTINGS_PATH = Path(__file__).resolve().parent.parent / "settings.local.json"

# Commands that should NEVER be auto-persisted, even if manually approved.
# Patterns use fnmatch-style matching against the full command string.
DENY_PATTERNS = [
    "rm -rf *",
    "rm -r *",
    "rmdir *",
    "git push --force*",
    "git push -f*",
    "git push * --force*",
    "git push * -f*",
    "git reset --hard*",
    "git checkout -- *",
    "git clean *",
    "git branch -D *",
    "git branch -d *",
    "git rebase *",
    "docker stop *",
    "docker kill *",
    "docker rm *",
    "docker rmi *",
    "docker system prune*",
    "docker volume rm *",
    "docker compose down*",
    "pkill *",
    "kill *",
    "killall *",
    "shutdown *",
    "reboot*",
    "dd *",
    "mkfs*",
    "curl * -X DELETE*",
    "curl * -X PUT*",
    "curl * -X POST*",
    "wget *",
    # GitHub PR mutations — always require explicit approval
    "gh pr create*",
    "gh pr merge*",
    # Pipe to file overwrites (> but not >>)
    "* > *",
]

# Safe command prefixes — when a command matches, persist the PREFIX pattern
# (e.g. "Bash(git status:*)") instead of the exact command string.
# This keeps settings.local.json clean and covers future variations.
SAFE_PREFIXES = [
    "git status",
    "git diff",
    "git log",
    "git add",
    "git commit",
    "git push",
    "git checkout -b",
    "git -C",
    "pytest",
    "python -m pytest",
    "python3 --version",
    "ls",
    "tree",
    "find",
    "mkdir",
    "cat",
    "grep",
    "head",
    "tail",
    "docker logs",
    "docker inspect",
    "docker ps",
    "docker exec",
    "docker restart",
    "gh pr view",
    "gh pr diff",
    "gh pr checks",
    "gh run view",
    "gh run list",
    "gh issue view",
    "gh issue list",
    "uv lock",
    "wc",
    "which",
    "type",
    "file",
]

# Patterns that look like compound commands — skip these, they're ambiguous.
COMPOUND_OPERATORS = re.compile(r"\s*[;&|]{1,2}\s*")


def is_denied(command: str) -> bool:
    """Check if command matches any deny pattern."""
    for pattern in DENY_PATTERNS:
        if fnmatch.fnmatch(command, pattern):
            return True
    return False


def is_compound(command: str) -> bool:
    """Check if command contains shell operators (&&, ||, ;, |)."""
    # Ignore operators inside quotes
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        c = command[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if c in (";", "|") or (c == "&" and i + 1 < len(command) and command[i + 1] == "&"):
                return True
        i += 1
    return False


def claude_pattern_matches(pattern: str, tool_name: str, value: str) -> bool:
    """Replicate Claude Code's permission pattern matching.

    Patterns look like:
        Bash(command)         — exact match
        Bash(prefix *)        — prefix with word boundary
        Bash(prefix:*)        — prefix (colon variant, equivalent to space-*)
        Bash(prefix*)         — prefix without word boundary
        Read(//etc/hosts)     — absolute path (// = filesystem root)
        Read(//var/log/**)    — recursive glob
    """
    # Parse the pattern: ToolName(content)
    m = re.match(r"^(\w+)\((.+)\)$", pattern)
    if not m:
        # Bare tool name like "Bash" — matches all uses of that tool
        return pattern == tool_name

    pat_tool, pat_content = m.group(1), m.group(2)
    if pat_tool != tool_name:
        return False

    # Wildcard matching for Bash commands and Read paths
    if "*" not in pat_content:
        # Exact match
        return value == pat_content

    # Convert Claude's simple wildcard to a regex.
    # Split on * and re-join with .* for matching.
    parts = pat_content.split("*")
    regex = ".*".join(re.escape(p) for p in parts)
    regex = "^" + regex + "$"
    return bool(re.match(regex, value, re.DOTALL))


def is_already_allowed(allow_list: list, tool_name: str, value: str) -> bool:
    """Check if a command/URL is already covered by an existing allow pattern."""
    for pattern in allow_list:
        if claude_pattern_matches(pattern, tool_name, value):
            return True
    return False


def matching_safe_prefix(command: str) -> str | None:
    """Return the longest SAFE_PREFIXES entry that matches command, or None."""
    best = None
    for prefix in SAFE_PREFIXES:
        if command == prefix or command.startswith(prefix + " ") or command.startswith(prefix + "\t"):
            if best is None or len(prefix) > len(best):
                best = prefix
    return best


def build_rule(tool_name: str, tool_input: dict) -> str | None:
    """Build the permission rule string for the given tool call.

    Returns None if the command should not be auto-allowed.
    If the command matches a safe prefix, returns a prefix pattern
    (e.g. "Bash(git status:*)") instead of the exact command.
    """
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if not command:
            return None
        if is_denied(command):
            return None
        if is_compound(command):
            return None
        # Only persist commands that match a known safe prefix.
        # Always save the exact command (useful for debugging iteration).
        if matching_safe_prefix(command) is None:
            return None
        return f"Bash({command})"

    if tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if not file_path:
            return None
        # Only auto-allow reads outside the project directory.
        # In-project reads are already permitted by default.
        if file_path.startswith("/workspace"):
            return None
        # Absolute paths use // prefix in Claude Code permission syntax.
        return f"Read(/{file_path})"

    return None


def update_settings(rule: str) -> None:
    """Add a rule to settings.local.json's allow list atomically."""
    settings = {}
    if SETTINGS_PATH.exists():
        try:
            settings = json.loads(SETTINGS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return  # Don't clobber a broken file

    permissions = settings.setdefault("permissions", {})
    allow = permissions.setdefault("allow", [])

    if rule in allow:
        return

    allow.append(rule)

    # Atomic write: write to temp file, then rename
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=SETTINGS_PATH.parent, suffix=".tmp", prefix=".settings_"
        )
        with os.fdopen(fd, "w") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp_path, SETTINGS_PATH)
    except OSError:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main():
    try:
        hook_data = json.loads(sys.stdin.read())
    except Exception:
        sys.exit(0)

    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})

    rule = build_rule(tool_name, tool_input)
    if rule is None:
        sys.exit(0)

    # Read current allow list to check coverage
    allow_list = []
    if SETTINGS_PATH.exists():
        try:
            settings = json.loads(SETTINGS_PATH.read_text())
            allow_list = settings.get("permissions", {}).get("allow", [])
        except (json.JSONDecodeError, OSError):
            pass

    # Determine the value to match against existing patterns
    if tool_name == "Bash":
        value = tool_input.get("command", "")
    elif tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        # Value for matching uses the // prefix (absolute path syntax)
        value = f"/{file_path}" if file_path.startswith("/") else file_path
    else:
        sys.exit(0)

    if is_already_allowed(allow_list, tool_name, value):
        sys.exit(0)

    update_settings(rule)
    sys.exit(0)


if __name__ == "__main__":
    main()
