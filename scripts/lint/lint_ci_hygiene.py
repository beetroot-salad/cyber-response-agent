#!/usr/bin/env python3
"""Hygiene lint — catches the recurring "easy" bugs that pass tests but bite live.

Scope: `defender/` only (matches the shippable-surface lint). Per-vendor
systems-skill dirs are excluded by directory.

Three sub-checks, all soft (intended for the code-smells report job):

  - hardcoded-paths      `/workspace/...` or `/tmp/(defender|soc-agent)/...`
                         in code that ships. `os.environ.get(..., "/tmp/...")`
                         and `DEFAULT_X = "/tmp/..."` patterns are allowed
                         (documented defaults, not hardcoded leaks).

  - python-interpreter   bare `python3 X.py` in JSON hook `command:` fields
                         (not in `Bash(python3 ...)` allow patterns, which
                         are permission scopes rather than invocations).
                         Hooks need ${PYTHON} or an absolute venv path to
                         avoid system python.

  - hook-matcher         hook matcher containing exactly one of `Task` /
                         `Agent` rather than both. Production dispatches
                         as both; missing one means the hook silently
                         never fires.

Pre-existing findings are ratcheted via lint_ci_hygiene_baseline.json (see
scripts/lint/_baseline.py); the gate fails only on a NEW finding.

Run from repo root:  python scripts/lint/lint_ci_hygiene.py
Regenerate the baseline:  python scripts/lint/lint_ci_hygiene.py --update-baseline
Exit 0 = clean (no new findings), 1 = new findings.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from _astlib import ScanBlind, read_source, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_ci_hygiene_baseline.json")

# Files where these patterns are deliberate; do not flag.
PATH_ALLOWLIST = {
    "defender/CLAUDE.md",
    "defender/learning/actor-settings.json",
}

# Directories under defender/ that are either out-of-scope or are
# per-vendor systems-skill content (where playground paths are by design).
EXCLUDED_PREFIXES = (
    "defender/.venv/",
    "defender/__pycache__/",
    "defender/fixtures/",
    "defender/tests/",
    "defender/lessons/",
    "defender/lessons-actor/",
    "defender/lessons-questioner/",
    "defender/docs/",                                  # POC design notes
    "defender/skills/wazuh/",
    "defender/skills/host-query/",
    "defender/skills/stub-cmdb/",
    "defender/skills/stub-iam/",
    "defender/skills/gather/queries/wazuh/",
    "defender/skills/gather/queries/host-query/",
    "defender/skills/gather/queries/stub-cmdb/",
    "defender/skills/gather/queries/stub-iam/",
    "defender/scripts/adapters/",                         # per-vendor adapters
)

#: Directory names the listing never enters (a venv is huge, and never shipped source).
_PRUNED = (".venv", "venv", "__pycache__")
TEXT_SUFFIXES = {".py", ".md", ".json", ".sh", ".yaml", ".yml", ".toml"}

PATH_PATTERN = re.compile(r"/workspace/|/tmp/(?:defender|soc-agent)[/_-]")

# Allow documented defaults — these are good practice, not bugs.
# #1078 D8: the three /tmp/defender-runs allowances are RETIRED — their last users (the
# module-level runs-base default this file used to carry, generate_case.py's own hardcoded
# fallback) are gone, and there is deliberately no default data root to allow in their place
# (§7 J01).
DEFAULT_PATTERNS: list[re.Pattern[str]] = []

# Bare `python3 X.py` — only flagged in JSON `command:` fields.
INTERPRETER_PATTERN = re.compile(r"\bpython3\s+[\w./${}-]+\.py\b")
INTERPRETER_OK_PREFIX = re.compile(r"\$\{PYTHON\}|/\.venv/bin/python|uv run python")


def _is_excluded(rel: str) -> bool:
    if rel in PATH_ALLOWLIST:
        return True
    return any(rel.startswith(p) for p in EXCLUDED_PREFIXES)


def _listing() -> list[str]:
    """Every text file under `defender/` the shared listing (`_astlib.source_files`) yields —
    git-ignored run output (`learning/runs/`, `author-queue/`) never among them. Taken once per
    run by `main` and handed to each check."""
    if not DEFENDER.is_dir():
        return []
    return source_files(DEFENDER, _PRUNED, suffixes=tuple(sorted(TEXT_SUFFIXES)))


def _iter_defender_files(listed: list[str]) -> list[Path]:
    """The shipped text files of `listed`, minus `EXCLUDED_PREFIXES` (deliberately out of
    scope)."""
    return [DEFENDER / rel for rel in listed if not _is_excluded(f"defender/{rel}")]


def check_hardcoded_paths(listed: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_defender_files(_listing() if listed is None else listed):
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = read_source(path, rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "lint-hygiene: ok" in line:
                continue
            m = PATH_PATTERN.search(line)
            if not m:
                continue
            if any(p.search(line) for p in DEFAULT_PATTERNS):
                continue
            findings.append(
                Finding(
                    fingerprint=f"hardcoded-path:{rel}:{m.group(0)}",
                    display=f"[hardcoded-path] {rel}:{lineno}: {line.strip()[:140]}",
                )
            )
    return findings


def _iter_command_fields(node, path_prefix: str = ""):
    """Yield (jsonpath, command_string) for every `command` field in JSON."""
    if isinstance(node, dict):
        for key, value in node.items():
            new_prefix = f"{path_prefix}.{key}" if path_prefix else key
            if key == "command" and isinstance(value, str):
                yield new_prefix, value
            else:
                yield from _iter_command_fields(value, new_prefix)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            yield from _iter_command_fields(item, f"{path_prefix}[{idx}]")


def _settings_files(listed: list[str]) -> list[Path]:
    """Known JSON config locations under defender/, out of `listed`: the top-level `*.json`,
    every nested `*-settings.json`, and the plugin manifest."""
    rels = [rel for rel in listed
            if ("/" not in rel and rel.endswith(".json")) or rel.endswith("-settings.json")]
    manifest = ".claude-plugin/plugin.json"
    if manifest not in rels and (DEFENDER / manifest).exists():
        rels.append(manifest)
    return [DEFENDER / rel for rel in rels]


def check_python_interpreter(listed: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in _settings_files(_listing() if listed is None else listed):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if _is_excluded(rel):
            continue
        # An unparseable settings file must not read as clean.
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanBlind(
                f"{rel}: could not be parsed ({exc.__class__.__name__}: {exc}) — this gate "
                f"reads its interpreter line out of that JSON, so an unparseable file reports clean."
            ) from exc
        for jp, cmd in _iter_command_fields(data):
            if "lint-hygiene: ok" in cmd:
                continue
            if INTERPRETER_PATTERN.search(cmd) and not INTERPRETER_OK_PREFIX.search(cmd):
                findings.append(
                    Finding(
                        fingerprint=f"python-interpreter:{rel}:{jp}",
                        display=(
                            f"[python-interpreter] {rel}: {jp} uses bare `python3` — "
                            f"substitute ${{PYTHON}} or an absolute venv path: {cmd[:100]}"
                        ),
                    )
                )
    return findings


def _iter_matchers(node, path_prefix: str = ""):
    if isinstance(node, dict):
        for key, value in node.items():
            new_prefix = f"{path_prefix}.{key}" if path_prefix else key
            if key == "matcher" and isinstance(value, str):
                yield new_prefix, value
            else:
                yield from _iter_matchers(value, new_prefix)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            yield from _iter_matchers(item, f"{path_prefix}[{idx}]")


def check_hook_matchers(listed: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in _settings_files(_listing() if listed is None else listed):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if _is_excluded(rel):
            continue
        # An unparseable settings file must not read as clean.
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanBlind(
                f"{rel}: could not be parsed ({exc.__class__.__name__}: {exc}) — this gate "
                f"reads its hook matchers out of that JSON, so an unparseable file reports clean."
            ) from exc
        for jp, matcher in _iter_matchers(data):
            if "Task" in matcher or "Agent" in matcher:
                if not ("Task" in matcher and "Agent" in matcher):
                    findings.append(
                        Finding(
                            fingerprint=f"hook-matcher:{rel}:{jp}",
                            display=(
                                f"[hook-matcher] {rel}: matcher='{matcher}' at {jp} — "
                                f"should match both `Task` AND `Agent` "
                                f"(production dispatches as both)"
                            ),
                        )
                    )
    return findings


HEADER = (
    "lint_ci_hygiene baseline — hardcoded-paths / bare-python3 / split hook-matcher "
    "smells in defender/. Fingerprint is check:file:token (no line number). CI fails "
    "on a fingerprint absent here. Regenerate: "
    "python scripts/lint/lint_ci_hygiene.py --update-baseline. "
    'Annotate intentional entries; "" means un-triaged debt to fix or annotate.'
)


def main(argv: list[str]) -> int:
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        listed = _listing()
        findings = (
            check_hardcoded_paths(listed)
            + check_python_interpreter(listed)
            + check_hook_matchers(listed)
        )
    except ScanBlind as exc:
        print(f"lint_ci_hygiene: {exc}", file=sys.stderr)
        return 2
    print("Suppress legitimate references with `# lint-hygiene: ok — <reason>` on the line.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_ci_hygiene", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
