#!/usr/bin/env python3
"""Shippable-surface discipline — flag env-specific tokens in files that
ship as part of the product.

The defender plugin is meant to be vendor-neutral. Per-vendor knowledge (the systems
skills and their query templates) is each tenant's, in its own repo, and the adapters sit
in the carved-out `integrations/`. The rest of `defender/` must read as
environment-agnostic.

A token match is not automatically a bug: defender/SKILL.md may
legitimately reference `wazuh.auth-events` as a query-template
identifier, since `{system}.{template-name}` is the protocol surface.
This lint surfaces references so they can be triaged — suppress
intentional ones with `# lint-shippable: ok — <reason>` on the line.
Pre-existing references are ratcheted via lint_shippable_surface_baseline.json
(see tooling/lint/_baseline.py); the gate fails only on a NEW file+token pair.

Run from repo root:  python tooling/lint/lint_shippable_surface.py
Regenerate the baseline:  python tooling/lint/lint_shippable_surface.py --update-baseline
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from _astlib import ScanBlind, read_source, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_shippable_surface_baseline.json")

# Directories under defender/ allowed to contain vendor names (per-vendor by design, or not
# part of the shipped surface).
EXCLUDED_PREFIXES = (
    # No settings or knowledge carve-out (#1108 P4): per-tenant settings, system skills, query
    # templates and lessons live in each tenant's own repo, outside this tree.
    # Vendored golden runs replayed by the e2e harness: env-specific test data by design.
    "defender/tests/fixtures/e2e/",
    "defender/tests/",
    "evaluations/judge_alignment/",
    "evaluations/",
    "defender/.venv/",
    "defender/__pycache__/",
    # POC design notes — internal-facing, not agent runtime.
    "defender/docs/",
    # Per-vendor adapters live under integrations/ — by design vendor-named.
    "defender/integrations/",
    # The sign-in provider's adapter (#1306 K1): the product's one named identity engine, behind
    # the `SignInPort`; nothing else in `identity/` or `api/` names it.
    "defender/identity/keycloak.py",
    # The record's settings parts (#1107): the ONE module that reads each system's `config.env`
    # into the run's record, so that no other platform module interprets them (the census test
    # `d4_elastic_keys_one_place` holds that for the corpus engine's keys). A file, not a directory: the carve-out is this module and nothing beside it.
    "defender/runtime/tenant_settings.py",
)

EXCLUDED_FILES = {
    "defender/CLAUDE.md",              # internal structure doc
    "defender/uv.lock",
    "defender/pyproject.toml",         # may name vendor-specific deps
}

# Suffixes considered text.
TEXT_SUFFIXES = {".py", ".md", ".json", ".sh", ".yaml", ".yml", ".toml"}

# Word-boundary patterns, case-insensitive; hyphen and underscore variants listed explicitly.
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


def excluded_prefixes(root: Path) -> tuple[str, ...]:
    """The prefixes excluded under `root`: `EXCLUDED_PREFIXES`. There is no per-system
    carve-out any more (#1108 P4): a system's skill is tenant knowledge, in the tenant's own
    repo, so nothing under `defender/skills/` is vendor-named by design. This decides only
    which files may name a vendor, nothing about permissions."""
    del root  # one tree, one list: kept so callers name the tree they scan
    return EXCLUDED_PREFIXES


def _excluded(rel: str, prefixes: tuple[str, ...]) -> bool:
    """`prefixes` is required rather than defaulted: resolving them shells out to git, and
    this is called once per file across thousands of files."""
    if rel in EXCLUDED_FILES:
        return True
    # Flat pytest modules anywhere are fixture code, like the excluded tests/ dir.
    name = rel.rsplit("/", 1)[-1]
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    return any(rel.startswith(p) for p in prefixes)


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    # The shared listing drops what git ignores: run artifacts a working tree accumulates but
    # a fresh CI checkout never has. Prefixes are resolved once, since the resolver shells out.
    prefixes = excluded_prefixes(REPO_ROOT)
    candidates = [
        DEFENDER / rel
        for rel in source_files(DEFENDER, (".venv", "__pycache__"),
                                suffixes=tuple(sorted(TEXT_SUFFIXES)))
        if not _excluded(f"defender/{rel}", prefixes)
    ]
    for path in candidates:
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = read_source(path, rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "lint-shippable: ok" in line:
                continue
            for pat in FORBIDDEN:
                m = pat.search(line)
                if m:
                    token = m.group(0).lower()
                    # File+token, no line number: another line with an accepted token in
                    # the same file does not re-trip the gate.
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
    "python tooling/lint/lint_shippable_surface.py --update-baseline. "
    'Annotate intentional entries (e.g. "intentional: protocol-surface identifier"); '
    '"" means un-triaged debt to fix or annotate.'
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_shippable_surface: {exc}", file=sys.stderr)
        return 2
    print("Suppress legitimate references with `# lint-shippable: ok — <reason>` on the line.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_shippable_surface", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
