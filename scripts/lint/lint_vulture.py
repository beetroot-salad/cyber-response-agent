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

# Mirror the invocation the soft code-smells step used.
VULTURE_ARGS = [
    "defender",
    "--min-confidence", "80",
    "--exclude", "defender/.venv,defender/tests",
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
    if proc.returncode not in (0, 1):  # 2+ = vulture usage/internal error
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
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
