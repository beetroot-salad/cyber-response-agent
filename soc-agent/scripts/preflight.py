#!/usr/bin/env python3
"""Preflight — validate the current soc-agent environment.

Runs health checks on every connected adapter and validates the knowledge
base structure. Deterministic. No LLM. Safe to run any time.

Usage:
    python3 scripts/preflight.py              # full check
    python3 scripts/preflight.py --systems    # only systems
    python3 scripts/preflight.py --kb         # only knowledge base
    python3 scripts/preflight.py --json       # machine-readable output

Exit codes:
    0 — ready (all systems connected, knowledge base complete)
    1 — degraded (some systems unreachable or knowledge gaps)
    2 — not configured (no systems connected at all)

What it checks
--------------
1. Systems: for every adapter under `scripts/tools/*.py`, runs
   `<cli> health-check` and reports connected / error. Adapter
   filenames may end in `_cli` for readability (the suffix is
   stripped from the reported system name).

2. System knowledge: for each system that exposes a CLI, confirms that
   `knowledge/environment/systems/{system}/` exists and contains at least
   one documentation file. Preflight does NOT enforce specific filenames —
   `/connect` scaffolds the preferred files at connect time, but the env
   knowledge layout is deliberately flexible (data sources may be
   organized by data type rather than per-system).

3. Signatures: for each signature directory under knowledge/signatures/
   that isn't the `_template/`, checks that context.md + playbook.md exist
   and at least one archetype subdirectory is present.

What it deliberately doesn't check
----------------------------------
- Data freshness (unbounded problem — investigation methodology handles it).
- Credentials validity beyond what the health-check tells us.
- Whether the adapter actually implements the full contract (that's the
  `/connect` test phase; preflight trusts a green health-check).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SOC_AGENT_DIR = Path(os.environ.get("SOC_AGENT_DIR", SCRIPT_DIR.parent))

TOOLS_DIR = SOC_AGENT_DIR / "scripts" / "tools"
KNOWLEDGE_DIR = SOC_AGENT_DIR / "knowledge"
SYSTEMS_DIR = KNOWLEDGE_DIR / "environment" / "systems"
DATA_SOURCES_DIR = KNOWLEDGE_DIR / "environment" / "data-sources"
SIGNATURES_DIR = KNOWLEDGE_DIR / "signatures"

HEALTH_CHECK_TIMEOUT_SEC = 15

# Color helpers — only when writing to a TTY.
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, s: str) -> str:
    if not _USE_COLOR:
        return s
    return f"\033[{code}m{s}\033[0m"


OK = _c("32", "✓")
WARN = _c("33", "!")
BAD = _c("31", "✗")


@dataclass
class SystemStatus:
    system: str
    cli_path: str
    connected: bool
    error: str | None = None
    knowledge_gaps: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.connected and not self.knowledge_gaps


@dataclass
class SignatureStatus:
    signature: str
    complete: bool
    missing: list[str] = field(default_factory=list)


@dataclass
class PreflightReport:
    systems: list[SystemStatus]
    signatures: list[SignatureStatus]
    checked_systems: bool = True
    checked_signatures: bool = True

    @property
    def exit_code(self) -> int:
        # "Not configured" only applies when we actually ran the systems check
        # and found nothing. Skipping systems (--kb) doesn't trigger it.
        if self.checked_systems and not self.systems:
            return 2
        systems_ok = all(s.ok for s in self.systems)
        signatures_ok = all(sig.complete for sig in self.signatures)
        if systems_ok and signatures_ok:
            return 0
        return 1


# ---------------------------------------------------------------------------
# System discovery + health
# ---------------------------------------------------------------------------


def discover_adapters() -> list[tuple[str, Path]]:
    """Return [(system_name, cli_path)] for every adapter under scripts/tools/.

    Every adapter exposes a `health-check` subcommand; there is no other
    contract. Filenames like `wazuh_cli.py` are allowed for readability
    but the `_cli` suffix is dropped from the system name.
    """
    adapters: list[tuple[str, Path]] = []
    if not TOOLS_DIR.is_dir():
        return adapters
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        name = path.stem.removesuffix("_cli")
        adapters.append((name, path))
    return adapters


def _adapter_python(cli_path: Path) -> str:
    """Python interpreter for running the given adapter CLI.

    Adapters live under `scripts/tools/` with a shared `scripts/tools/.venv/`
    created by `scripts/tools/setup.sh`. The venv carries vendor deps
    (e.g. opensearch-py for wazuh_cli). Prefer `{cli_path.parent}/.venv/bin/python`
    when present; fall back to system `python3` otherwise (tests, CI,
    environments without a venv).
    """
    venv_python = cli_path.parent / ".venv" / "bin" / "python"
    if venv_python.is_file():
        return str(venv_python)
    return "python3"


def run_health_check(cli_path: Path) -> tuple[bool, str | None]:
    """Invoke an adapter's `health-check` subcommand. Returns (connected, error)."""
    python = _adapter_python(cli_path)
    cmd = [python, str(cli_path), "health-check"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=HEALTH_CHECK_TIMEOUT_SEC,
            cwd=str(SOC_AGENT_DIR),
        )
    except subprocess.TimeoutExpired:
        return False, f"health-check timed out after {HEALTH_CHECK_TIMEOUT_SEC}s"
    except FileNotFoundError as e:
        return False, f"python3 missing: {e}"

    if result.returncode == 0:
        return True, None

    stderr = (result.stderr or result.stdout or "").strip().splitlines()
    first_line = stderr[0] if stderr else f"exit {result.returncode}"
    return False, first_line[:200]


def check_knowledge(system: str) -> list[str]:
    """Return list of missing knowledge artifacts for a system (empty = ok).

    Intentionally loose: we require the per-system directory to exist and
    contain at least one documentation file. Filename conventions are
    /connect's job to scaffold; preflight only flags a system with no
    environment knowledge at all.

    Adapter filenames use underscores (Python identifier constraint);
    knowledge directory names often use hyphens. Accept either form so
    `host_query.py` matches `knowledge/environment/systems/host-query/`.
    """
    candidates = [system]
    if "_" in system:
        candidates.append(system.replace("_", "-"))

    for name in candidates:
        sys_dir = SYSTEMS_DIR / name
        if sys_dir.is_dir():
            docs = [p for p in sys_dir.iterdir() if p.is_file() and p.suffix == ".md"]
            if not docs:
                return [f"knowledge/environment/systems/{name}/ (no .md docs)"]
            return []

    return [f"knowledge/environment/systems/{system}/ (missing directory)"]


def check_systems() -> list[SystemStatus]:
    adapters = discover_adapters()
    statuses: list[SystemStatus] = []
    for name, cli_path in adapters:
        connected, err = run_health_check(cli_path)
        gaps = check_knowledge(name)
        statuses.append(
            SystemStatus(
                system=name,
                cli_path=str(cli_path.relative_to(SOC_AGENT_DIR)),
                connected=connected,
                error=err,
                knowledge_gaps=gaps,
            )
        )
    return statuses


# ---------------------------------------------------------------------------
# Knowledge base validation
# ---------------------------------------------------------------------------


def check_signatures() -> list[SignatureStatus]:
    if not SIGNATURES_DIR.is_dir():
        return []

    statuses: list[SignatureStatus] = []
    for path in sorted(SIGNATURES_DIR.iterdir()):
        if not path.is_dir() or path.name.startswith("_"):
            continue

        missing: list[str] = []
        if not (path / "context.md").exists():
            missing.append("context.md")
        if not (path / "playbook.md").exists():
            missing.append("playbook.md")

        archetypes_dir = path / "archetypes"
        if not archetypes_dir.is_dir() or not any(
            p.is_dir() for p in archetypes_dir.iterdir()
        ):
            missing.append("archetypes/ (empty)")

        statuses.append(
            SignatureStatus(
                signature=path.name,
                complete=not missing,
                missing=missing,
            )
        )
    return statuses


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def print_human(report: PreflightReport) -> None:
    if report.checked_systems:
        print("Systems:")
        if not report.systems:
            print(f"  {WARN} no adapters found under scripts/tools/")
            print("    Run /connect to add your first system.")
        else:
            for s in report.systems:
                if s.connected:
                    label = f"{OK} {s.system:<14}— connected"
                else:
                    label = f"{BAD} {s.system:<14}— {s.error or 'unknown error'}"
                print(f"  {label}  ({s.cli_path})")
                for gap in s.knowledge_gaps:
                    print(f"    {WARN} missing: {gap}")
        print()

    if report.checked_signatures:
        print("Knowledge base:")
        if not report.signatures:
            print(f"  {WARN} no signatures found under knowledge/signatures/")
        else:
            for sig in report.signatures:
                if sig.complete:
                    print(f"  {OK} signatures/{sig.signature}")
                else:
                    print(
                        f"  {WARN} signatures/{sig.signature} — missing: "
                        f"{', '.join(sig.missing)}"
                    )
        print()

    code = report.exit_code
    if code == 0:
        print(f"Result: {_c('32', 'READY')}")
    elif code == 1:
        print(f"Result: {_c('33', 'DEGRADED')}")
    else:
        print(f"Result: {_c('31', 'NOT CONFIGURED')} (no systems connected)")


def print_json(report: PreflightReport) -> None:
    payload = {
        "systems": [asdict(s) for s in report.systems] if report.checked_systems else None,
        "signatures": [asdict(s) for s in report.signatures] if report.checked_signatures else None,
        "exit_code": report.exit_code,
    }
    print(json.dumps(payload, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate soc-agent environment — adapters + knowledge base."
    )
    parser.add_argument(
        "--systems", action="store_true", help="Only check system adapters."
    )
    parser.add_argument(
        "--kb", action="store_true", help="Only check knowledge base structure."
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of human-readable."
    )
    args = parser.parse_args()

    checked_systems = not args.kb
    checked_signatures = not args.systems
    systems = check_systems() if checked_systems else []
    signatures = check_signatures() if checked_signatures else []
    report = PreflightReport(
        systems=systems,
        signatures=signatures,
        checked_systems=checked_systems,
        checked_signatures=checked_signatures,
    )

    if args.json:
        print_json(report)
    else:
        print_human(report)

    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
