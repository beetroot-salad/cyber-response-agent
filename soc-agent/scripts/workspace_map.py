#!/usr/bin/env python3
"""Print a slim starting map of the soc-agent knowledge tree.

Used as a `!command` preamble in `skills/investigate/SKILL.md` so the
workspace map gets baked into the skill prompt at load time, derived from
the actual on-disk structure rather than hand-maintained markdown. This
keeps the generic skill vendor-neutral: which SIEM and host-inspection
systems are available is determined by what's in
`knowledge/environment/systems/`, not by hardcoded prose in the skill.

The output is intentionally **slim** — it lists what *varies* between
deployments (vendor systems, lead catalog, signature catalog) rather than
dumping per-file contents. The agent is encouraged to `ls`, `Glob`, or
`Read` further when it needs specifics. Treating this as the complete and
authoritative map (rather than a starting orientation) is a mistake we
have explicitly seen the agent make in past evaluation runs.

Excludes: hidden files, __pycache__, _template/, .venv/, venv/, ad-hoc
(the lead fallback is called out in the skill itself).

Usage:
  cd soc-agent && python3 scripts/workspace_map.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_NAMES = {"__pycache__", "_template", ".venv", "venv"}


def is_excluded(p: Path) -> bool:
    return p.name.startswith(".") or p.name in EXCLUDED_NAMES


def list_subdir_names(d: Path, *, exclude: set[str] = frozenset()) -> list[str]:
    if not d.is_dir():
        return []
    return sorted(
        p.name for p in d.iterdir()
        if p.is_dir() and not is_excluded(p) and p.name not in exclude
    )


def main() -> int:
    env_root = ROOT / "knowledge" / "environment"
    leads = list_subdir_names(
        ROOT / "knowledge" / "common-investigation" / "leads",
        exclude={"ad-hoc"},
    )
    signatures = list_subdir_names(ROOT / "knowledge" / "signatures")
    systems = list_subdir_names(env_root / "systems")

    # Knowledge tree — one line per layer, no per-file enumeration
    print("**Knowledge tree:**")
    print("- `knowledge/environment/{context, data-sources, operations, systems}/` — org-specific deployment knowledge. Each layer has a `SKILL.md` index. The `operations/` files are trust anchors (change-windows, deploy-runs, etc.); many are template scaffolding in this environment, so verify before relying on them.")
    if leads:
        print(f"- `knowledge/common-investigation/leads/` — {', '.join(leads)}. Each lead is a directory with `definition.md` and optional `templates/{{vendor}}.md`. Use `data-source-debug` when a query returns suspicious results, and `ad-hoc` as the fallback.")
    if signatures:
        print(f"- `knowledge/signatures/` — {', '.join(signatures)}")
    print()

    # Systems — names with explicit "read SKILL.md before using" cue
    if systems:
        print("**Systems available in this deployment:**")
        for s in systems:
            print(f"- `{s}/` — read `knowledge/environment/systems/{s}/SKILL.md` before invoking any command against it")
        print()

    # Skill-internal scripts — these are part of the skill machinery and don't vary
    print("**Skill-internal scripts** (relative to your shell cwd at startup, which is the soc-agent root):")
    print("- `scripts/resolve_imports.py` — bakes signature knowledge (loaded automatically)")
    print("- `scripts/setup_run.py` — creates the run dir (loaded automatically)")
    print("- State transitions are inferred automatically by the `infer_state.py` hook from `## PHASE` headers in `investigation.md`")
    print()
    print("For environment-specific tooling (SIEM CLIs, host inspection utilities), read the relevant `knowledge/environment/systems/{vendor}/SKILL.md` file.")
    print()
    print("> This is a starting map. Use `ls`, `Glob`, or `Read` to discover further when you need specifics — for instance, `ls knowledge/environment/operations/` to see which trust anchor files are populated, or `ls hooks/scripts/` if you need to verify a script's exact path before invoking it.")

    return 0


if __name__ == "__main__":
    sys.exit(main())