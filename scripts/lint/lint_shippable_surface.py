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
from _gitscope import git_ignored

REPO_ROOT = Path(__file__).resolve().parents[2]

# The per-system carve-out is derived from the resolver (see `excluded_prefixes`) rather than
# re-typed here, so this file keeps no separate idea of which systems exist.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from defender.learning.leads.declared_systems import declared_systems  # noqa: E402
from defender.learning.leads.lead_extraction import LeadAuthorError  # noqa: E402

DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_shippable_surface_baseline.json")

# Directories under defender/ allowed to contain vendor names (per-vendor by design, or not
# part of the shipped surface).
EXCLUDED_PREFIXES = (
    # Gather query templates (+ their SCHEMA doc) are per-system.
    "defender/skills/gather/queries/",
    # No settings carve-out: per-tenant settings live under `knowledge/tenants/<id>/settings/`
    # at the repo root, outside the scanned surface.
    "defender/fixtures/",
    # Vendored golden runs replayed by the e2e harness: env-specific test data by design.
    "defender/fixtures-e2e/",
    "defender/tests/",
    "defender/lessons/",
    "defender/lessons-actor/",
    # Per-environment lesson corpus + learning-loop calibration/eval fixtures (internal).
    "defender/lessons-environment/",
    # The questioner's corpus: findings about a world, not the runtime agent (internal).
    "defender/lessons-questioner/",
    "defender/learning/judge-alignment/",
    "defender/evals/",
    "defender/.venv/",
    "defender/__pycache__/",
    # POC design notes — internal-facing, not agent runtime.
    "defender/docs/",
    # Per-vendor adapters live under scripts/adapters/ — by design vendor-named.
    "defender/scripts/adapters/",
    # Per-vendor corpus stagers, the read-side twin of scripts/adapters/: how an index is
    # addressed is irreducibly per-vendor. One directory deep so `estate/registry.py` beside
    # it stays inside the gate.
    "defender/learning/branch/estate/stagers/",
)

EXCLUDED_FILES = {
    "defender/CLAUDE.md",              # internal structure doc
    "defender/learning/actor-settings.json",  # settings file
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
    """`EXCLUDED_PREFIXES` plus one `defender/skills/<system>/` per system `root` declares.

    Derived from the resolver rather than hand-listed: a hand-kept list drifts silently when
    a system's name is not a vendor word this scanner looks for. This decides only which
    files may name a vendor, nothing about permissions.
    """
    return (*EXCLUDED_PREFIXES, *(
        f"defender/skills/{system}/" for system in sorted(declared_systems(root))
    ))


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
    # Minus what git ignores (see `_gitscope`): run artifacts a working tree accumulates but a
    # fresh CI checkout never has. Prefixes are resolved once, since the resolver shells out.
    prefixes = excluded_prefixes(REPO_ROOT)
    candidates = [
        p for p in DEFENDER.rglob("*")
        if p.is_file() and p.suffix in TEXT_SUFFIXES
        and not _excluded(p.relative_to(REPO_ROOT).as_posix(), prefixes)
    ]
    ignored = git_ignored(REPO_ROOT, candidates)
    for path in candidates:
        if path in ignored:
            continue
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
    "python scripts/lint/lint_shippable_surface.py --update-baseline. "
    'Annotate intentional entries (e.g. "intentional: protocol-surface identifier"); '
    '"" means un-triaged debt to fix or annotate.'
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus, and an unresolvable systems roster would
    # run the scan with the wrong exclusions. Exit 2: the gate could not run, which is not
    # "clean".
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_shippable_surface: {exc}", file=sys.stderr)
        return 2
    except LeadAuthorError as exc:
        print(f"lint_shippable_surface: cannot resolve systems: {exc}", file=sys.stderr)
        return 2
    print("Suppress legitimate references with `# lint-shippable: ok — <reason>` on the line.")
    print("Per-vendor systems skills are excluded by directory (see excluded_prefixes).")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_shippable_surface", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
