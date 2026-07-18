#!/usr/bin/env python3
"""Shippable-surface discipline — flag env-specific tokens in files that
ship as part of the product.

The defender plugin is meant to be vendor-neutral. Per-vendor knowledge
lives under explicitly carved-out directories (the "systems skills" and
their query templates). The rest of `defender/` must read as
environment-agnostic.

A token match is not automatically a bug: defender/SKILL.md may
legitimately reference `wazuh.auth-events` as a query-template
identifier, since `{system}.{template-name}` is the protocol surface.
This lint surfaces references so they can be triaged — suppress
intentional ones with `# lint-shippable: ok — <reason>` on the line.
Pre-existing references are ratcheted via lint_shippable_surface_baseline.json
(see scripts/lint/_baseline.py); the gate fails only on a NEW file+token pair.

Run from repo root:  python scripts/lint/lint_shippable_surface.py
Regenerate the baseline:  python scripts/lint/lint_shippable_surface.py --update-baseline
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from _astlib import ScanBlind, read_source
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_shippable_surface_baseline.json")

# Directories under defender/ that are allowed to contain vendor names
# (they ARE per-vendor by design, or are not part of the shipped surface).
EXCLUDED_PREFIXES = (
    # Per-vendor systems skills (the v2 data-source carve-out) — vendor-named BY
    # DESIGN. The v1 names (wazuh/host-query/stub-cmdb/stub-iam) were renamed to
    # these; keep this list in step with the actual skills/<system>/ dirs.
    "defender/skills/elastic/",
    "defender/skills/cmdb/",
    "defender/skills/identity/",
    "defender/skills/host-state/",
    "defender/skills/change-mgmt/",
    "defender/skills/threat-intel/",
    "defender/skills/ticket/",
    # Gather query templates are all per-system (+ the SCHEMA doc that documents
    # them) — the per-vendor surface, not env-agnostic code.
    "defender/skills/gather/queries/",
    "defender/knowledge/environment/systems/",
    "defender/fixtures/",
    # Vendored golden RUNS replayed by the e2e harness (tests/test_replay_*) —
    # captured from the v2 playground, so env-specific test data BY DESIGN, like
    # defender/fixtures/ above; not the shipped vendor-neutral surface.
    "defender/fixtures-e2e/",
    "defender/tests/",
    "defender/run-visualizations/",
    "defender/run-transcripts/",
    "defender/lessons/",
    "defender/lessons-actor/",
    # Per-environment lesson corpus (sibling to lessons-actor) + learning-loop
    # calibration/eval fixtures — internal, not the shipped vendor-neutral surface.
    "defender/lessons-environment/",
    "defender/learning/judge-alignment/",
    "defender/evals/",
    "defender/.venv/",
    "defender/__pycache__/",
    # POC design notes — internal-facing, not agent runtime.
    "defender/docs/",
    # Per-vendor adapters live under scripts/adapters/ — by design vendor-named.
    "defender/scripts/adapters/",
)

EXCLUDED_FILES = {
    "defender/CLAUDE.md",              # internal structure doc
    "defender/learning/actor-settings.json",  # settings file
    "defender/uv.lock",
    "defender/pyproject.toml",         # may name vendor-specific deps
    # The lint scripts themselves live at repo-root scripts/lint/, outside the
    # scanned defender/ surface, so they need no exclusion here.
}

# Suffixes considered text.
TEXT_SUFFIXES = {".py", ".md", ".json", ".sh", ".yaml", ".yml", ".toml"}

# Word-boundary patterns. Case-insensitive. The order is irrelevant
# (each line is checked against all). Hyphen + underscore variants
# both covered explicitly.
FORBIDDEN = [
    re.compile(r"\bwazuh\b", re.IGNORECASE),
    re.compile(r"\belastic(?:search)?\b", re.IGNORECASE),
    re.compile(r"\bopensearch\b", re.IGNORECASE),
    re.compile(r"\bfalco\b", re.IGNORECASE),
    re.compile(r"\bkeycloak\b", re.IGNORECASE),
    re.compile(r"\bhost[-_]query\b", re.IGNORECASE),
    re.compile(r"\bstub[-_]cmdb\b", re.IGNORECASE),
    re.compile(r"\bstub[-_]iam\b", re.IGNORECASE),
    re.compile(r"\bstub[-_]ticket\b", re.IGNORECASE),
    re.compile(r"\bcmdb_adapter\b", re.IGNORECASE),
    re.compile(r"\bplayground\b", re.IGNORECASE),
    re.compile(r"\btarget-endpoint\b", re.IGNORECASE),
]


def _excluded(rel: str) -> bool:
    if rel in EXCLUDED_FILES:
        return True
    # Flat pytest modules (test_*.py / *_test.py) anywhere — fixture/scaffold code
    # that names systems for its scenarios, like the already-excluded tests/ dir.
    name = rel.rsplit("/", 1)[-1]
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    return any(rel.startswith(p) for p in EXCLUDED_PREFIXES)


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in DEFENDER.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if _excluded(rel):
            continue
        text = read_source(path, rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "lint-shippable: ok" in line:
                continue
            for pat in FORBIDDEN:
                m = pat.search(line)
                if m:
                    token = m.group(0).lower()
                    # Fingerprint is file+token, line-number-free: a new line that
                    # references an already-accepted token in the same file does
                    # not re-trip the gate; a token in a NEW file does.
                    findings.append(
                        Finding(
                            fingerprint=f"{rel}:{token}",
                            display=f"{rel}:{lineno}: [{m.group(0)}] {line.strip()[:140]}",
                        )
                    )
                    break  # one finding per line
    return findings


HEADER = (
    "lint_shippable_surface baseline — env-specific (vendor) tokens in the "
    "shipped defender/ surface. Fingerprint is file:token (no line number). CI "
    "fails on a file:token absent here. Regenerate: "
    "python scripts/lint/lint_shippable_surface.py --update-baseline. "
    'Annotate intentional entries (e.g. "intentional: protocol-surface identifier"); '
    '"" means un-triaged debt to fix or annotate.'
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Exit 2 — the
    # gate could not run, which is categorically not "clean" (#618/#621/#652).
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_shippable_surface: {exc}", file=sys.stderr)
        return 2
    print("Suppress legitimate references with `# lint-shippable: ok — <reason>` on the line.")
    print("Per-vendor systems skills are excluded by directory (see EXCLUDED_PREFIXES).")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_shippable_surface", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
