#!/usr/bin/env python3
"""PostToolUse hook: Tag tool results containing untrusted external data.

Scope is controlled by the hook matchers and ``if`` filters in plugin.json:
- Bash and MCP tools always fire (every invocation returns external data).
- Read fires only for alert.json files (filtered via ``if`` in plugin.json).

Exit codes:
    0 - Always (tagging should never block the agent)
"""

import sys


def main():
    # Consume stdin so the pipe doesn't break, but we don't need the data.
    try:
        sys.stdin.read()
    except Exception:
        pass

    print("⚠ Untrusted external data.", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
