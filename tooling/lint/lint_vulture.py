#!/usr/bin/env python3
"""Vulture dead-code gate — runs vulture over defender/ and ratchets its findings.

Vulture is the detector; this wrapper puts its output behind the shared baseline ratchet
(tooling/lint/_baseline.py) so the check blocks newly introduced dead code without forcing a
cleanup of pre-existing findings.

Fingerprint is the vulture finding with its line number stripped (path + message),
so dead code that merely shifts lines does not re-trip the gate.

Run from repo root:  python tooling/lint/lint_vulture.py
Regenerate the baseline:  python tooling/lint/lint_vulture.py --update-baseline
Exit 0 = clean (no new dead code), 1 = new dead code, 2 = vulture not runnable.
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import tempfile
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
    "evaluations",
    "--min-confidence", "60",
    "--exclude", "defender/.venv,defender/tests,defender/skills/invlang/schema.py",
    # event_time is the alert mapping's entry in its wire model and its table: read through pydantic and SQLAlchemy.
    # #1366 K2/O2: `DISPLAY_NAME` and `EXAMPLE` are catalog declarations read cold (AST, `systems.catalog` and
    # lint_catalog_declarations), never by attribute. `written_at` is a version row's audit column (P3, R9): written by
    # the store's inserts, read by no code. `add_records` is the memory twin's public seeder beside `add_generation`
    # (R10: planting helpers seed records with it).
    "--ignore-names", "key_field,key_value,event_time,DISPLAY_NAME,EXAMPLE,written_at,add_records",
    # pydantic calls its validators, and SQLAlchemy a hybrid property's SQL side, by decorator registration, never by name.
    # FastAPI calls a route by its router decorator (`@<router>.get(...)`, ...), never by name.
    "--ignore-decorators",
    "@field_validator,@model_validator,@*.inplace.expression,@*.get,@*.post,@*.put,@*.patch,@*.delete",
]

#: The API's wire models: pydantic reads every field (validation, serialisation), so none is read by attribute.
WIRE_MODELS = REPO_ROOT / "defender" / "api" / "models.py"


def wire_fields(source: str) -> list[str]:
    """The field names (and `model_config`) of every class in `source` that is a pydantic model: one whose base is
    `BaseModel`, or a class of `source` that is one."""
    tree = ast.parse(source)
    models: set[str] = {"BaseModel"}
    fields: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(isinstance(b, ast.Name) and b.id in models for b in node.bases):
            models.add(node.name)
            fields |= {stmt.target.id for stmt in node.body
                       if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)}
            fields |= {t.id for stmt in node.body if isinstance(stmt, ast.Assign)
                       for t in stmt.targets if isinstance(t, ast.Name) and t.id == "model_config"}
    return sorted(fields)

# `path:lineno: message` — strip the lineno for a line-stable fingerprint.
LINE_RE = re.compile(r"^(?P<path>[^:]+):(?P<lineno>\d+): (?P<msg>.*)$")


def _vulture_bin() -> str | None:
    venv = REPO_ROOT / "defender" / ".venv" / "bin" / "vulture"
    if venv.exists():
        return str(venv)
    return shutil.which("vulture")


def _scan(vulture: str) -> list[Finding]:
    # A vulture whitelist: each wire field, used once by attribute, so vulture counts it read.
    with tempfile.NamedTemporaryFile("w", suffix="_wire_whitelist.py", delete=False) as whitelist:
        whitelist.write("".join(f"_.{name}\n" for name in wire_fields(WIRE_MODELS.read_text(encoding="utf-8"))))
    try:
        proc = subprocess.run(
            [vulture, whitelist.name, *VULTURE_ARGS],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
        )
    finally:
        Path(whitelist.name).unlink()
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
    "python tooling/lint/lint_vulture.py --update-baseline. "
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
