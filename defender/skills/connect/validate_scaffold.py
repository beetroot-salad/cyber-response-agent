#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates  # noqa: E402
from defender._frontmatter import parse_frontmatter_or_none  # noqa: E402
from defender._io import read_text_soft  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    ADAPTER_SUFFIX,
    ModuleVerbRegistry,
    declared_params,
    engine_of,
)

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
_GLYPH = {PASS: "✓", WARN: "!", FAIL: "✗"}

_SECRET_KEYS = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)$", re.I)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_HIGH_ENTROPY = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")

_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}")
_VERB_LINE_RE = re.compile(r"(?m)^\s*verb:\s*(\S+)\s*$")


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


def check_registry(report: Report, defender: Path, system: str):
    adapter = defender / "scripts" / "adapters" / f"{system.replace('-', '_')}{ADAPTER_SUFFIX}"
    registry = ModuleVerbRegistry(defender / "scripts" / "adapters")
    try:
        verbs = registry.verbs(system)
    except KeyError:
        report.add(FAIL, f"adapter module {adapter.name} is missing or its `system` is malformed")
        return None
    except BaseException as exc:  # noqa: BLE001 — a module that will not import is a broken adapter
        report.add(FAIL, f"adapter module {adapter.name} failed to import: {type(exc).__name__}: {exc}")
        return None
    if not verbs:
        report.add(FAIL, f"adapter module {adapter.name} declares no verbs (empty or missing VERBS)")
        return None
    report.add(PASS, f"adapter {adapter.name} imports; VERBS declares {len(verbs)} verb(s)")
    if "health-check" in verbs:
        report.add(PASS, "VERBS declares a health-check verb")
    else:
        report.add(FAIL, f"VERBS declares no health-check verb (has {sorted(verbs)})")
    return verbs


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
        return
    text, _reason = read_text_soft(skill)
    front = parse_frontmatter_or_none(text) if text is not None else None
    if front is not None and front.get("name") == f"defender-{system}":
        report.add(PASS, f"skills/{system}/SKILL.md has frontmatter name: defender-{system}")
    else:
        report.add(FAIL, f"skills/{system}/SKILL.md frontmatter name is not 'defender-{system}'")

    execution = defender / "skills" / system / "execution.md"
    has_inline = text is not None and "## Execution" in text
    if execution.exists():
        report.add(PASS, f"skills/{system}/execution.md exists")
    elif has_inline:
        report.add(PASS, "SKILL.md embeds a ## Execution section inline (no separate execution.md)")
    else:
        report.add(WARN, "no execution.md and no inline ## Execution section")


def _template_verb(fm: dict, query_body: str) -> str | None:
    if isinstance(fm, dict) and fm.get("verb"):
        return str(fm["verb"])
    m = _VERB_LINE_RE.search(query_body)
    if m:
        return m.group(1)
    for line in query_body.splitlines():
        s = line.strip()
        if s and not s.startswith(("#", "```", "~~~")):
            return s.split()[0]
    return None


def _body_substitutions(fm: dict) -> set[str]:
    subs = fm.get("body_substitutions") if isinstance(fm, dict) else None
    return {str(s) for s in subs} if isinstance(subs, (list, tuple)) else set()


def check_templates(report: Report, defender: Path, system: str, verbs) -> None:
    qdir = defender / "skills" / "gather" / "queries" / system
    templates = [
        t for t in iter_query_templates(qdir.parent)
        if t.system == system and "_draft" not in t.path.parts
    ]
    if not templates:
        report.add(WARN, f"no seed query templates under skills/gather/queries/{system}/ (they grow post-merge)")
        return
    verbs = verbs or {}
    failures: list[str] = []
    for t in templates:
        fm = parse_frontmatter_or_none(t.path.read_text(encoding="utf-8")) or {}
        verb_name = _template_verb(fm, t.query)
        if verb_name is None:
            failures.append(f"{t.path.name}: no verb (no `verb:` frontmatter and an empty ## Query)")
            continue
        if verb_name not in verbs:
            failures.append(f"{t.path.name}: verb {verb_name!r} is not a declared verb of {system}")
            continue
        placeholders = set(_PLACEHOLDER_RE.findall(t.query))
        if engine_of(verbs[verb_name]) != "none":
            continue
        allowed = set(declared_params(verbs[verb_name])) | _body_substitutions(fm)
        undeclared = sorted(placeholders - allowed)
        if undeclared:
            failures.append(
                f"{t.path.name}: ${{{undeclared[0]}}} is neither a declared param of {verb_name} "
                f"nor a marked body_substitution"
            )
    if failures:
        for f in failures:
            report.add(FAIL, f"template placeholder invariant: {f}")
    else:
        report.add(PASS, f"{len(templates)} template(s) satisfy the placeholder<->param invariant")


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <system>", file=sys.stderr)
        raise SystemExit(2)
    system = sys.argv[1]
    defender = _defender_dir()
    os.environ.setdefault("DEFENDER_DIR", str(defender))

    print(f"validate_scaffold: {system}\n")
    report = Report()
    verbs = check_registry(report, defender, system)
    check_config(report, defender, system)
    check_skill(report, defender, system)
    check_templates(report, defender, system, verbs)
    report.render_and_exit()


if __name__ == "__main__":
    main()
