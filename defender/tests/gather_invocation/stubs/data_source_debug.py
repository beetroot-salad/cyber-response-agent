#!/usr/bin/env python3
"""Stub data-source-debug wrapper for the gather invocation test harness.

Records each invocation (args + timestamp) to $STUB_DSD_TRACE as a JSONL
line, then prints a canned verdict from $STUB_DSD_VERDICT (or a default
verdict) to stdout. The test asserts on the trace file's existence and
contents to confirm gather invoked the wrapper.

The default verdict matches the Falco container.name=<NA> case: substitute
field is container.id, scope is system-wide, draft path is the stub deposit
target. Tests that need different verdicts override via $STUB_DSD_VERDICT.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time


DEFAULT_VERDICT = """## Verdict
data-source-quirk

## Workaround
substitute_field: falco.output_fields.container.id
cross_source_query: null
explanation: Falco container plugin writes <NA> for container.name when its docker-socket lookup races the container exit; container.id is populated by the syscall enricher and reliable.

## Deposited
draft: /tmp/stub-dsd-deposit.md
scope: system-wide
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--defender-dir", required=True)
    parser.add_argument("--system", required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--question", required=True)
    args = parser.parse_args()

    trace = os.environ.get("STUB_DSD_TRACE")
    if trace:
        with open(trace, "a") as f:
            f.write(json.dumps({
                "ts": time.time(),
                "defender_dir": args.defender_dir,
                "system": args.system,
                "payload": args.payload,
                "question": args.question,
            }) + "\n")

    verdict_path = os.environ.get("STUB_DSD_VERDICT")
    if verdict_path and os.path.isfile(verdict_path):
        sys.stdout.write(open(verdict_path).read())
    else:
        sys.stdout.write(DEFAULT_VERDICT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
