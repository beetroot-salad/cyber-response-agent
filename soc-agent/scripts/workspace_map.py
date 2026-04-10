#!/usr/bin/env python3
"""Print a structured listing of the soc-agent knowledge tree.

Used as a `!command` preamble in `skills/investigate/SKILL.md` so the
workspace map gets baked into the skill prompt at load time, derived from
the actual on-disk structure rather than hand-maintained markdown. This
keeps the generic skill vendor-neutral: which SIEM and host-inspection
systems are available is determined by what's in
`knowledge/environment/systems/`, not by hardcoded prose in the skill.

The script walks four enforced layers:
  - knowledge/environment/{context,data-sources,operations,systems}/
  - knowledge/common-investigation/leads/
  - knowledge/signatures/
  - skill-internal scripts (still hardcoded — the script set is part of
    the skill machinery, not a deployment variable)

Excludes: hidden files, __pycache__, _template/, .venv/, venv/.

Usage:
  cd /workspace/soc-agent && python3 scripts/workspace_map.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXCLUDED_NAMES = {"__pycache__", "_template", ".venv", "venv"}


def is_excluded(p: Path) -> bool:
    return p.name.startswith(".") or p.name in EXCLUDED_NAMES


def list_md_files(d: Path) -> list[str]:
    if not d.is_dir():
        return []
    return sorted(
        p.name for p in d.iterdir()
        if p.is_file() and p.suffix == ".md" and not is_excluded(p)
    )


def list_subdirs(d: Path) -> list[Path]:
    if not d.is_dir():
        return []
    return sorted(
        p for p in d.iterdir() if p.is_dir() and not is_excluded(p)
    )


def print_environment() -> None:
    print("### `knowledge/environment/` — org-specific deployment knowledge")
    print()
    env_root = ROOT / "knowledge" / "environment"
    for layer in ("context", "data-sources", "operations"):
        layer_dir = env_root / layer
        if not layer_dir.is_dir():
            continue
        files = [f for f in list_md_files(layer_dir) if f != "SKILL.md"]
        files_str = ", ".join(files) if files else "(empty)"
        print(f"- `{layer}/` — {files_str}")

    systems_dir = env_root / "systems"
    if systems_dir.is_dir():
        print("- `systems/` — per-vendor SKILL.md files. **Read the relevant system's SKILL.md before invoking any command against that system.** Available in this deployment:")
        for sysdir in list_subdirs(systems_dir):
            files = list_md_files(sysdir)
            other = [f for f in files if f != "SKILL.md"]
            extra = f" (+ {', '.join(other)})" if other else ""
            print(f"    - **{sysdir.name}/** — SKILL.md{extra}")
    print()
    print(
        "Each layer has a `SKILL.md` index. The `operations/` files are trust "
        "anchors (change-windows, deploy-runs, etc.) — many are template "
        "scaffolding in this environment, so always check whether the file is "
        "customized before relying on it."
    )
    print()


def print_leads() -> None:
    print("### `knowledge/common-investigation/leads/` — reusable lead definitions")
    print()
    leads_dir = ROOT / "knowledge" / "common-investigation" / "leads"
    if leads_dir.is_dir():
        for d in list_subdirs(leads_dir):
            if d.name == "ad-hoc":
                continue  # ad-hoc is the fallback, called out in the skill
            print(f"- {d.name}")
    print()
    print(
        "Each lead is a directory with `definition.md` (methodology, pitfalls) "
        "and optionally `templates/{vendor}.md` (pre-built query templates). "
        "Use `data-source-debug` when a query returns suspicious results "
        "(zero matches, stale events, unexpectedly low counts) — its "
        "definition.md has the diagnostic checklist. Use `ad-hoc` as the "
        "fallback when no lead directory matches what you need."
    )
    print()


def print_signatures() -> None:
    print("### `knowledge/signatures/` — signatures with playbooks and precedents")
    print()
    sigs_dir = ROOT / "knowledge" / "signatures"
    if sigs_dir.is_dir():
        for d in list_subdirs(sigs_dir):
            print(f"- {d.name}")
    print()


def print_scripts() -> None:
    print("### Skill-internal scripts the agent invokes via Bash")
    print()
    print("```")
    print("scripts/resolve_imports.py        — bakes signature knowledge (loaded automatically)")
    print("scripts/setup_run.py              — creates the run dir (loaded automatically)")
    print("scripts/search_precedents.py      — search/list precedents for a signature")
    print("hooks/scripts/write_state.py      — state machine transitions")
    print("```")
    print()
    print(
        "For environment-specific tooling (SIEM CLIs, host inspection utilities), "
        "read the relevant `knowledge/environment/systems/{vendor}/SKILL.md` file. "
        "Each vendor's SKILL.md documents the concrete invocation patterns for "
        "that environment. The generic skill is vendor-neutral and does not "
        "assume any specific CLI or path."
    )
    print()


def main() -> int:
    print_environment()
    print_leads()
    print_signatures()
    print_scripts()
    return 0


if __name__ == "__main__":
    sys.exit(main())
