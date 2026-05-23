#!/usr/bin/env python3
"""Static tier-A smoke — verify run-settings.json covers the Bash forms
that prompts actually use, without paying for a full claude run.

Catches the class of bug from commit 5fc280b (gather_raw stayed empty
because compound Bash commands tripped the permission gate under `-p`
mode). In a strict allowlist regime, every Bash invocation referenced
in a skill prompt should match at least one allow entry.

Two checks:

  - prompt-vs-allowlist  Every `Bash(...)` form mentioned in a skill
                         prompt is covered by an entry in
                         defender/run-settings.json. Forms that include
                         pipes / `2>&1` / `&&` require an allow entry
                         broad enough to admit compound commands (i.e.
                         `Bash(*)` or a pattern with `*` after the CLI).

  - cli-invocation-shape For each Bash invocation example in a prompt,
                         the CLI script path must exist on disk and the
                         allow entry's prefix must match the first ~3
                         words of the command. Catches arg-order
                         typos like commit 0a1b889 (`cli advisory <root>`
                         vs `cli <root> advisory`).

Run from repo root:  python defender/scripts/lint_static_smoke.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
RUN_SETTINGS = DEFENDER / "run-settings.json"

# Match Bash code blocks in markdown that invoke a Python script under
# defender/. The block-delimited form ```bash ... ``` is the primary
# shape; inline backticks are also captured.
BASH_BLOCK = re.compile(r"```bash\s*\n(.*?)```", re.DOTALL)
PYTHON_INVOC = re.compile(
    r"python3?\s+(?:-m\s+)?([\w/.\-]+(?:\.py)?)\s+([\w\-]+)?",
)

# Heuristic — compound bash markers that require a broad allow entry.
COMPOUND_MARKERS = ("|", "2>&1", "&&", "||", "$(", "`", ">>", ">/")


def _load_allow_patterns() -> list[str]:
    if not RUN_SETTINGS.exists():
        return []
    try:
        data = json.loads(RUN_SETTINGS.read_text())
    except json.JSONDecodeError as e:
        print(f"FAIL: run-settings.json is not valid JSON: {e}", file=sys.stderr)
        return []
    return [p for p in data.get("permissions", {}).get("allow", []) if p.startswith("Bash(")]


def _allow_matches(invocation: str, allow_patterns: list[str]) -> str | None:
    """Return the matching allow pattern (or None) for a Bash invocation
    string (the body inside `bash ...` fence)."""
    cmd = invocation.strip().split("\n", 1)[0].strip()
    if cmd.endswith("\\"):
        # Multi-line continuation — collapse for matching.
        cmd = " ".join(line.strip().rstrip("\\") for line in invocation.strip().splitlines())
    for pat in allow_patterns:
        # Extract the inner spec: Bash(<spec>)
        m = re.fullmatch(r"Bash\((.*)\)", pat)
        if not m:
            continue
        spec = m.group(1)
        if spec == "*":
            return pat
        # Simple prefix match: replace `*` with `.*`, anchor at start.
        regex = re.escape(spec).replace(r"\*", ".*")
        if re.match(regex, cmd):
            return pat
    return None


def _iter_bash_invocations() -> list[tuple[Path, int, str]]:
    """Yield (file, lineno, invocation_text) for every Bash code block in
    skill prompts under defender/. CLAUDE.md is excluded (human-facing
    setup docs, not agent runtime)."""
    out: list[tuple[Path, int, str]] = []
    targets = list(DEFENDER.rglob("SKILL.md"))
    targets.extend(DEFENDER.rglob("*.md"))  # also catches knowledge docs
    excluded_parts = {"run-visualizations", "fixtures", "tests", "docs",
                      "run-transcripts", "lessons", "lessons-actor", ".venv"}
    seen: set[Path] = set()
    for path in targets:
        if path in seen:
            continue
        if path.name in {"CLAUDE.md", "README.md"}:
            continue
        if any(p in excluded_parts for p in path.parts):
            continue
        seen.add(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in BASH_BLOCK.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            out.append((path, lineno, m.group(1)))
    return out


def check_prompt_vs_allowlist(allow_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    for path, lineno, body in _iter_bash_invocations():
        rel = path.relative_to(REPO_ROOT).as_posix()
        first = body.strip().split("\n", 1)[0].strip()
        if not first:
            continue
        # Skip variable-only or comment-only blocks.
        if first.startswith("#") or first.startswith("$"):
            continue
        match = _allow_matches(body, allow_patterns)
        if match is None:
            findings.append(
                f"{rel}:{lineno}: NO allow pattern matches: `{first[:120]}`"
            )
            continue
        # If body contains compound markers, require a `*` in spec.
        body_text = body
        if any(marker in body_text for marker in COMPOUND_MARKERS):
            if "(*)" not in match and not match.endswith("*)"):
                findings.append(
                    f"{rel}:{lineno}: compound bash invocation matched only a narrow allow "
                    f"pattern `{match}` — under -p mode the multi-op permission check may "
                    f"reject pipes/redirects; broaden to `Bash(...*)` or add `Bash(*)`"
                )
    return findings


def check_cli_invocation_shape() -> list[str]:
    """For each python invocation in a prompt, verify the script exists."""
    findings: list[str] = []
    for path, lineno, body in _iter_bash_invocations():
        rel = path.relative_to(REPO_ROOT).as_posix()
        for m in PYTHON_INVOC.finditer(body):
            target = m.group(1)
            if target.endswith(".py"):
                script_path = (REPO_ROOT / target).resolve()
                if not script_path.exists():
                    # Try common search locations.
                    alt = list(REPO_ROOT.rglob(Path(target).name))
                    if not alt:
                        findings.append(
                            f"{rel}:{lineno}: script `{target}` referenced but not found"
                        )
            elif "." in target and "/" not in target:
                # Module form: `python -m defender.skills.invlang.cli`
                mod_path = REPO_ROOT / (target.replace(".", "/") + ".py")
                pkg_init = REPO_ROOT / (target.replace(".", "/") + "/__init__.py")
                if not mod_path.exists() and not pkg_init.exists():
                    findings.append(
                        f"{rel}:{lineno}: module `{target}` referenced but not found "
                        f"as either {target.replace('.','/')}.py or as a package"
                    )
    return findings


def main() -> int:
    if not RUN_SETTINGS.exists():
        print(f"run-settings.json not found at {RUN_SETTINGS}", file=sys.stderr)
        return 2

    allow_patterns = _load_allow_patterns()
    if not allow_patterns:
        print("WARN: no Bash() allow patterns found in run-settings.json", file=sys.stderr)

    prompt_findings = check_prompt_vs_allowlist(allow_patterns)
    shape_findings = check_cli_invocation_shape()

    print(f"\n=== prompt-vs-allowlist ({len(prompt_findings)} finding(s)) ===")
    for f in prompt_findings:
        print(f"  {f}")

    print(f"\n=== cli-invocation-shape ({len(shape_findings)} finding(s)) ===")
    for f in shape_findings:
        print(f"  {f}")

    total = len(prompt_findings) + len(shape_findings)
    print(f"\nTotal: {total} finding(s).")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
