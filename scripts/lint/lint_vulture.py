#!/usr/bin/env python3
"""Vulture dead-code gate — runs vulture over defender/ and ratchets its findings.

Vulture is the detector; this wrapper puts its output behind the shared baseline ratchet
(scripts/lint/_baseline.py) so the check blocks newly introduced dead code without forcing a
cleanup of pre-existing findings.

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

# Confidence 60, not 80. Vulture scores unused functions/classes/methods at 60 and only unused
# imports (90) / unreachable code (100) at or above 80, so `--min-confidence 80` cannot report
# the category this gate is named for. Do not raise it. 60 is vulture's own default.
#
# The cost is that 60 also reports names reached by a mechanism vulture cannot see —
# @agent.tool registration, Protocol methods, PyYAML representer hooks. Those false positives
# live in the baseline annotated with why, so a genuine new corpse still trips the gate.
#
# invlang/schema.py is excluded wholesale: a declarative TypedDict schema whose fields are read
# through `rec["source_vertex"]`, invisible to vulture. It would dominate the findings, and
# baselining it would bury the signal.
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
    # vulture's ExitCode enum (vulture.utils): 0=NoDeadCode, 1=InvalidInput,
    # 2=InvalidCmdlineArguments, 3=DeadCode — findings come on 0 or 3; 1/2 are real errors.
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
        # A dead-code baseline that accepts "" could be walked past with --update-baseline.
        require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
