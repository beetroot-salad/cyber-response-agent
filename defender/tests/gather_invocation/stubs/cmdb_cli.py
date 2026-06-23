#!/usr/bin/env python3
"""Stub cmdb_cli for A2 (wrong-system) fixture.

Reads $STUB_CMDB_PAYLOAD if set, otherwise returns a generic 'host record
not found' shape. The A2 fixture's payload is irrelevant to the test —
the assertion is whether gather refuses the dispatch *before* running
this stub, having read the system SKILL's injected description and
noticed the lead targets an event store, not an asset store.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    path = os.environ.get("STUB_CMDB_PAYLOAD")
    if path and os.path.isfile(path):
        with open(path) as f:
            sys.stdout.write(f.read())
    else:
        sys.stdout.write('{"error": "host record not found", "results": []}\n')
    return 0


if __name__ == "__main__":
    sys.exit(main())
