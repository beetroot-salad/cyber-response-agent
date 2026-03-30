#!/usr/bin/env python3
"""PostToolUse hook: Tag tool results containing untrusted external data.

Scope is controlled by the hook matcher in plugin.json. For most tools
(Bash, MCP), every invocation returns external data and is always tagged.
For Read, only files matching the alert naming convention are tagged —
this replaces the need for a separate wrapped alert file.

Exit codes:
    0 - Always (tagging should never block the agent)
"""

import json
import re
import sys

# Alert files live inside run directories (UUID-named) under the runs dir.
_ALERT_FILE_PATTERN = re.compile(r"/[0-9a-f-]{36}/alert\.json$")


def main():
    try:
        raw = sys.stdin.read()
        hook_data = json.loads(raw)
    except Exception:
        sys.exit(0)

    tool_name = hook_data.get("tool_name", "")

    # For Read calls, only tag alert files — not knowledge base or other reads.
    if tool_name == "Read":
        file_path = hook_data.get("tool_input", {}).get("file_path", "")
        if not _ALERT_FILE_PATTERN.search(file_path):
            sys.exit(0)

    print("⚠ Untrusted external data.", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
