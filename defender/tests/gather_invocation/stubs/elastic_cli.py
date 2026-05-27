#!/usr/bin/env python3
"""Stub elastic_cli for the gather invocation test harness.

Reads the fixture payload path from $STUB_ELASTIC_PAYLOAD and prints it to
stdout. Ignores all query args — the harness controls the payload via the
fixture, not via the query body.

The real elastic_cli has many subcommands and flags. This stub accepts any
argv shape and produces the same payload, so SKILL §3 query construction
doesn't need to match the live CLI's exact surface for the test to run.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    path = os.environ.get("STUB_ELASTIC_PAYLOAD")
    if not path:
        sys.stderr.write("stub elastic_cli: $STUB_ELASTIC_PAYLOAD not set\n")
        return 2
    try:
        sys.stdout.write(open(path).read())
    except OSError as e:
        sys.stderr.write(f"stub elastic_cli: cannot read {path}: {e}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
