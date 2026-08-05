#!/usr/bin/env python3
"""Vulture dead-code gate — runs vulture over defender/ and ratchets its findings.

Vulture itself is the detector; this wrapper exists only to put its output behind
the shared baseline ratchet (scripts/lint/_baseline.py) so the check can BLOCK on
newly-introduced dead code without forcing a big-bang cleanup of pre-existing
findings. The vulture invocation mirrors the one the code-smells job used while
this was a soft `|| true` step.

Fingerprint is the vulture finding with its line number stripped (path + message),
so dead code that merely shifts lines does not re-trip the gate.

Run from repo root:  python scripts/lint/lint_vulture.py
Regenerate the baseline:  python scripts/lint/lint_vulture.py --update-baseline
Exit 0 = clean (no new dead code), 1 = new dead code, 2 = vulture not runnable.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = Path(__file__).with_name("lint_vulture_baseline.json")

# Confidence 60, NOT 80. Vulture scores unused *functions/classes/methods* at 60 and only
# unused imports (90) / unreachable code (100) at 80 — so `--min-confidence 80` makes this
# gate structurally incapable of reporting the category it is named for. It ran clean with an
# empty baseline while a 9-function dead subtree sat in
# scripts/visualize/visualize_primitives.py (the retired Claude-Code stream-JSON renderer,
# orphaned by the move to the in-process PydanticAI driver). 60 is vulture's own default.
#
# The cost is that 60 also reports names reached by a mechanism vulture cannot see —
# @agent.tool decorator registration, Protocol methods, PyYAML representer hooks. Those are
# real false positives, and they live in the baseline ANNOTATED with why, so a genuine new
# corpse still trips the gate.
# invlang/schema.py is excluded wholesale: it is a declarative TypedDict schema, and vulture
# cannot see a TypedDict field being read through `rec["source_vertex"]`. It alone produced ~90
# of the 96 findings at confidence 60 — baselining that is not triage, it is a second empty
# baseline wearing a disguise. Excluding it keeps the gate's signal readable.
#
# This block was set by #721 and then silently reverted to 80 by #744's squash merge, which
# restored the pre-#721 file wholesale. The gate was blind to dead functions for the whole
# window between. If you find yourself raising this back to 80, you are re-opening that hole.
VULTURE_ARGS = [
    "defender",
    "--min-confidence", "60",
    "--exclude", "defender/.venv,defender/tests,defender/skills/invlang/schema.py",
    "--ignore-names", "key_field,key_value",
]

# `path:lineno: message` — strip the lineno for a line-stable fingerprint.
LINE_RE = re.compile(r"^(?P<path>[^:]+):(?P<lineno>\d+): (?P<msg>.*)$")


def _vulture_bin() -> str | None:
    venv = REPO_ROOT / "defender" / ".venv" / "bin" / "vulture"
    if venv.exists():
        return str(venv)
    return shutil.which("vulture")


def _scan(vulture: str) -> list[Finding]:
    proc = subprocess.run(
        [vulture, *VULTURE_ARGS],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )
    # vulture's own ExitCode enum (vulture.utils): 0=NoDeadCode, 1=InvalidInput,
    # 2=InvalidCmdlineArguments, 3=DeadCode — findings are reported on 0 OR 3; 1/2 are
    # real usage/parse errors. (The installed 2.16 differs from whatever version this
    # wrapper was first written against, where 1 meant "dead code found".)
    if proc.returncode not in (0, 3):
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f"vulture exited {proc.returncode}")
    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        findings.append(
            Finding(
                fingerprint=f"{m['path']}: {m['msg']}",
                display=line,
            )
        )
    return findings


HEADER = (
    "lint_vulture baseline — dead-code findings from vulture over defender/. "
    "Fingerprint is the finding with the line number stripped. CI fails on a "
    "finding absent here. Regenerate: "
    "python scripts/lint/lint_vulture.py --update-baseline. "
    'Annotate intentional entries (e.g. "intentional: public API"); "" = un-triaged.'
)


def main(argv: list[str]) -> int:
    vulture = _vulture_bin()
    if not vulture:
        print("vulture not found (defender/.venv/bin/vulture or PATH)", file=sys.stderr)
        return 2
    try:
        findings = _scan(vulture)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_vulture", header=HEADER,
        # A dead-code gate whose baseline accepts "" is a gate you can walk past by running
        # --update-baseline. Every entry here states why the corpse is acceptable.
        require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
