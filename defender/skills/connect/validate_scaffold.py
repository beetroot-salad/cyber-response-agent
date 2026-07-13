#!/usr/bin/env python3
"""Validate a connected system's onboarding scaffold against the connect
contract — the mechanical half of `checklist.md`. This is NOT a
connectivity probe: it checks the files `/connect` generated (adapter,
shim, per-system skill, config, templates), not whether the live system
is reachable.

    python3 defender/skills/connect/validate_scaffold.py <system>

Verifies the structural bar `/connect` aims for without needing the live
system: the adapter and shared module are in place, the CLI honours the
exit-code contract, the shim is registered, config.env carries no
secrets, and the per-system skill has the right shape. Connectivity and
"do the results look right?" are judgment checks the agent/maintainer
still does by hand (see checklist.md).

Exit 0 if nothing FAILed (WARN is allowed); exit 1 on any FAIL; exit 2 if
the system can't be located at all.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

# Put the workspace root on sys.path so the `defender.*` import below resolves when this file is
# run directly as the CLI in the usage above — where sys.path[0] is this script's own dir and the
# package would not resolve. Same bootstrap as `scripts/workspace_map.py`.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates  # noqa: E402
from defender._frontmatter import parse_frontmatter_or_none  # noqa: E402
from defender._io import read_text_soft  # noqa: E402

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
_GLYPH = {PASS: "✓", WARN: "!", FAIL: "✗"}

# config.env keys that must reference a secret by env-var *name*, never hold
# the value inline.
_SECRET_KEYS = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)$", re.I)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_HIGH_ENTROPY = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def add(self, status: str, message: str) -> None:
        self.rows.append((status, message))

    def render_and_exit(self) -> None:
        for status, message in self.rows:
            print(f"  [{_GLYPH[status]}] {message}")
        fails = sum(1 for s, _ in self.rows if s == FAIL)
        warns = sum(1 for s, _ in self.rows if s == WARN)
        print(f"\n{len(self.rows)} checks: "
              f"{len(self.rows) - fails - warns} pass, {warns} warn, {fails} fail")
        raise SystemExit(1 if fails else 0)


def _defender_dir() -> Path:
    env = os.environ.get("DEFENDER_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[2]


def _venv_python(defender: Path) -> str:
    candidate = defender / ".venv" / "bin" / "python3"
    return str(candidate) if candidate.exists() else (sys.executable or "python3")


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, encoding="utf-8")


def check_adapter(report: Report, defender: Path, system: str, python: str) -> Path | None:
    cli = defender / "scripts" / "adapters" / f"{system}_cli.py"
    if not cli.exists():
        report.add(FAIL, f"adapter {cli.relative_to(defender)} is missing")
        return None
    report.add(PASS, f"adapter {cli.relative_to(defender)} exists")

    # Reuse a shared module (the bundled _adapter.py, or whatever module the
    # siblings import — e.g. _stub_transport.py) rather than re-implementing
    # the parser/config/exit-codes/auth inline. Don't hard-require _adapter
    # specifically: a populated tree may standardize on a different module.
    src = cli.read_text(encoding="utf-8")
    adapters = defender / "scripts" / "adapters"
    present = {p.stem for p in adapters.glob("_*.py")}
    referenced = {m for m in present
                  if re.search(rf"(?:import|from)\s+\.?{re.escape(m)}\b", src)}
    if referenced:
        report.add(PASS, f"adapter reuses shared module(s): {', '.join(sorted(referenced))}")
    elif re.search(r"(?:^import|from)\s+_\w+", src, re.M):
        report.add(FAIL, "adapter imports a shared module that isn't present in scripts/adapters/")
    else:
        report.add(WARN, "adapter imports no shared module — it may be re-implementing "
                         "the contract (parser/config/exit-codes/auth) inline")

    help_run = _run([python, str(cli), "--help"])
    if help_run.returncode == 0 and "health-check" in help_run.stdout:
        report.add(PASS, "CLI --help runs and exposes a health-check subcommand")
    else:
        report.add(FAIL, "CLI --help failed or has no health-check subcommand")

    usage = _run([python, str(cli), "--not-a-real-flag"])
    report.add(PASS if usage.returncode == 64 else FAIL,
               f"bad invocation exits 64 (got {usage.returncode})")
    return cli


def check_shim(report: Report, defender: Path, system: str) -> None:
    shim = defender / "bin" / f"defender-{system}"
    if not shim.exists():
        report.add(FAIL, f"shim bin/defender-{system} is missing")
        return
    report.add(PASS if os.access(shim, os.X_OK) else FAIL,
               f"shim bin/defender-{system} "
               f"{'is executable' if os.access(shim, os.X_OK) else 'is not executable (chmod +x)'}")
    try:
        seg_path = defender / "hooks" / "_cmd_segments.py"
        spec = importlib.util.spec_from_file_location("_cmd_segments", seg_path)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        non_adapter = set(module.NON_ADAPTER_SHIMS)
        if f"defender-{system}" in non_adapter:
            report.add(FAIL, f"defender-{system} is in NON_ADAPTER_SHIMS — it won't gate as an adapter")
        else:
            report.add(PASS, "shim auto-gates as a data-source adapter (not in NON_ADAPTER_SHIMS)")
    except Exception as exc:  # noqa: BLE001 — verification is best-effort
        report.add(WARN, f"could not verify NON_ADAPTER_SHIMS ({exc})")


def check_config(report: Report, defender: Path, system: str) -> None:
    path = defender / "knowledge" / "environment" / "systems" / system / "config.env"
    if not path.exists():
        report.add(WARN, f"no config.env at {path.relative_to(defender)} (fine only if the adapter needs none)")
        return
    secrets_found = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if not val:
            continue
        if key.endswith("_ENV"):
            if not _ENV_NAME.match(val):
                report.add(FAIL, f"config.env: {key}={val!r} should name an env var, not hold a value")
                secrets_found = True
        elif _SECRET_KEYS.search(key):
            report.add(FAIL, f"config.env: {key} holds a value inline — reference a secret via {key}_ENV instead")
            secrets_found = True
        elif _HIGH_ENTROPY.match(val):
            report.add(WARN, f"config.env: {key} looks high-entropy — confirm it isn't a secret")
    if not secrets_found:
        report.add(PASS, "config.env carries no inline secrets")


def check_skill(report: Report, defender: Path, system: str) -> None:
    skill = defender / "skills" / system / "SKILL.md"
    if not skill.exists():
        report.add(FAIL, f"per-system skill skills/{system}/SKILL.md is missing")
    else:
        # The canonical grammar (#591), not a hand-rolled `text.split("---", 2)`. The split was
        # LOOSER than `_frontmatter`: it fenced on a bare `---` prefix rather than `---\n`, and it
        # then regex-matched `name:` over the raw YAML text, so a `name:` inside a quoted string or
        # a nested mapping satisfied it. A scaffold linter that accepts documents the real parser
        # rejects passes files the runtime will later fail on — which is the one thing it exists
        # not to do. Soft read: unreadable bytes are a FAIL row, not a crash.
        text, _reason = read_text_soft(skill)
        front = parse_frontmatter_or_none(text) if text is not None else None
        if front is not None and front.get("name") == f"defender-{system}":
            report.add(PASS, f"skills/{system}/SKILL.md has frontmatter name: defender-{system}")
        else:
            report.add(FAIL, f"skills/{system}/SKILL.md frontmatter name is not 'defender-{system}'")
        has_execution = text is not None and "## Execution" in text
        report.add(PASS if has_execution else WARN,
                   "SKILL.md has a ## Execution pointer" if has_execution
                   else "SKILL.md has no ## Execution pointer to execution.md")

    execution = defender / "skills" / system / "execution.md"
    report.add(PASS if execution.exists() else FAIL,
               f"skills/{system}/execution.md "
               f"{'exists' if execution.exists() else 'is missing'}")


def check_templates(report: Report, defender: Path, system: str) -> None:
    qdir = defender / "skills" / "gather" / "queries" / system
    files = sorted(p for p in qdir.glob("*.md") if p.is_file()) if qdir.is_dir() else []
    if not files:
        report.add(WARN, f"no seed query templates under skills/gather/queries/{system}/ (they grow post-merge)")
        return
    # `iter_query_templates` is THE walk over this corpus (#585) — this was the third hand-rolled
    # one, and folding it is what makes that claim true. It also tightens the check: the regex it
    # replaces ran `^\s*id:` over the WHOLE file under re.M, so an `id:` line inside a ## Query
    # body satisfied it; the walk reads real frontmatter, which cannot be faked from the body.
    #
    # The walk SKIPS a template it cannot parse (bad frontmatter, or no `id:` at all) — and that
    # defect is precisely what this check exists to FAIL on. So the verdict is taken against the
    # file listing, not against the walk's output: a file the walk dropped is bad, not absent.
    walked = {
        t.path: t.id
        for t in iter_query_templates(qdir.parent)
        if t.system == system and "_draft" not in t.path.parts
    }
    bad = [p.name for p in files if not walked.get(p, "").startswith(f"{system}.")]
    if bad:
        report.add(FAIL, f"templates missing 'id: {system}.<name>' frontmatter: {', '.join(bad)}")
    else:
        report.add(PASS, f"{len(files)} seed template(s) have valid id frontmatter")


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <system>", file=sys.stderr)
        raise SystemExit(2)
    system = sys.argv[1]
    defender = _defender_dir()
    os.environ.setdefault("DEFENDER_DIR", str(defender))
    python = _venv_python(defender)

    print(f"validate_scaffold: {system}\n")
    report = Report()
    check_adapter(report, defender, system, python)
    check_shim(report, defender, system)
    check_config(report, defender, system)
    check_skill(report, defender, system)
    check_templates(report, defender, system)
    report.render_and_exit()


if __name__ == "__main__":
    main()
