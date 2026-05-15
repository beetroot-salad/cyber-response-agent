#!/usr/bin/env python3
"""Tier 1 lead-author gate: per-template static + customization checks.

Tier 1 is the fast gate the lead-author agent invokes on every touched
template before committing. Two responsibilities, one CLI:

* **Static checks** — frontmatter shape, required sections, parameter
  documentation discipline. Deterministic; no LLM. Calibrated against
  the existing wazuh templates (see ``defender/skills/gather/queries/wazuh/``).
* **Customization runner** — wraps
  ``defender.learning.customization_test`` with the matching
  ``customization.yaml`` fixture under
  ``defender/skills/gather/queries/tests/{system}/{template-id}/customization.yaml``.

The combined verdict is ``pass`` only when both legs pass.

CLI::

    python3 -m defender.learning.lead_tier1 <template-path> [--trials 3] [--out-dir DIR]

Invoke from the workspace root. Exit codes:

* ``0`` — both legs pass.
* ``1`` — regression (static failure or customization fail).
* ``2`` — harness / system error (missing file, unparseable yaml,
  etc.). Distinct from a real regression.

Final stdout line is parseable: ``TIER1_RESULT: { ... }``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    from defender.learning import customization_test as _ct
except ImportError:  # pragma: no cover — direct-script execution fallback
    import customization_test as _ct  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_ROOT = REPO_ROOT / "defender" / "skills" / "gather" / "queries"
TESTS_ROOT = CATALOG_ROOT / "tests"


# Parameters that are framework plumbing, not content. The lead-author
# must NOT have to document these in template prose — they describe
# *where* the result lands or *how much* of it, not *what* is being
# measured. ``agent_name`` is content (it names a host), not plumbing,
# and is intentionally absent here.
PLUMBING_PARAMS = frozenset(
    {"run_dir", "position", "window", "start", "end", "limit"}
)


REQUIRED_SECTIONS = (
    "Goal",
    "What to characterize",
    "Query",
    "Common pitfalls",
)

OPTIONAL_SECTIONS = ("Filter binding", "Baseline")

_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)
_SECTION_RE = re.compile(r"^## (.+)$", re.MULTILINE)
_PARAM_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


def parse_frontmatter(text: str) -> tuple[dict | None, str]:
    """Return (frontmatter_dict, body). Frontmatter is None on absence."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None, text
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return None, text[m.end() :]
    if not isinstance(data, dict):
        return None, text[m.end() :]
    body = text[m.end() :].lstrip("\n")
    return data, body


def parse_sections(body: str) -> dict[str, str]:
    """Map section name -> body slice (header excluded)."""
    out: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(body))
    for i, m in enumerate(matches):
        name = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        out[name] = body[start:end].strip()
    return out


def strip_fenced_blocks(text: str) -> str:
    """Remove ``` fenced blocks (keeps inline backticks)."""
    return _FENCE_RE.sub("", text)


def static_checks(template_path: Path) -> dict:
    """Return ``{passed: bool, errors: [str], warnings: [str], detail: ...}``.

    Rules (calibrated against the existing wazuh catalog):

    1. Frontmatter exists with an ``id:`` key.
    2. ``id`` value matches the file path: ``{system}.{stem}``
       where ``{system}`` is the parent dir name and ``{stem}`` is the
       file's basename without ``.md``.
    3. Required sections present: Goal (non-empty), What to characterize
       (≥1 bullet), Query, Common pitfalls.
    4. Filter binding is optional (only 2 of 6 current templates have it).
    5. Every ``${param}`` substituted inside ``## Query`` must be either
       in ``PLUMBING_PARAMS`` or referenced in template prose outside
       fenced code blocks. The prose may use ``${name}``, the bareword
       ``name``, or a dotted-form ``name.something`` (since fields like
       ``rule.id`` map to params named ``rule_id``).
    """
    try:
        text = template_path.read_text()
    except OSError as e:
        return {
            "passed": False,
            "errors": [f"could not read {template_path}: {e}"],
            "warnings": [],
        }

    errors: list[str] = []
    warnings: list[str] = []

    frontmatter, body = parse_frontmatter(text)
    if frontmatter is None:
        errors.append("missing or malformed YAML frontmatter (--- ... ---)")
    elif "id" not in frontmatter:
        errors.append("frontmatter missing required key: id")
    else:
        actual_id = frontmatter["id"]
        system = template_path.parent.name
        stem = template_path.stem
        expected_id = f"{system}.{stem}"
        if actual_id != expected_id:
            errors.append(
                f"frontmatter id={actual_id!r} does not match path "
                f"({expected_id!r} expected from {template_path})"
            )

    sections = parse_sections(body)
    for req in REQUIRED_SECTIONS:
        if req not in sections:
            errors.append(f"missing required section: ## {req}")

    goal = sections.get("Goal", "").strip()
    if "Goal" in sections and not goal:
        errors.append("## Goal section is empty")

    wtc = sections.get("What to characterize", "")
    if "What to characterize" in sections:
        bullets = [
            line
            for line in wtc.splitlines()
            if line.lstrip().startswith(("-", "*"))
        ]
        if not bullets:
            errors.append("## What to characterize must contain ≥1 bullet")

    # Parameter documentation discipline.
    query_body = sections.get("Query", "")
    params_in_query = _collect_params(query_body)
    # Strip fenced blocks from the FULL body — prose anywhere counts.
    prose = strip_fenced_blocks(body)
    for name in sorted(params_in_query):
        if name in PLUMBING_PARAMS:
            continue
        if _param_documented(name, prose):
            continue
        errors.append(
            f"${{{name}}} appears in ## Query but is not documented in "
            f"prose (outside fenced blocks). Add a sentence describing "
            f"the parameter, list it under ## Filter binding, or rename "
            f"to a plumbing identifier."
        )

    return {
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "frontmatter": frontmatter,
        "sections_present": sorted(sections),
        "params_in_query": sorted(params_in_query),
    }


def _collect_params(text: str) -> set[str]:
    return {m.group(1) for m in _PARAM_RE.finditer(text)}


def _param_documented(name: str, prose: str) -> bool:
    """True if ``name`` appears in prose under any reasonable form."""
    # ${name} verbatim, e.g. "${host_clause} is ..."
    if f"${{{name}}}" in prose:
        return True
    # Bareword "name" (with word boundaries on both sides) — accept
    # within backticks or plain prose.
    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", prose):
        return True
    # Dotted alternative: "rule_id" ↔ "rule.id". Replace underscores
    # with dots before searching.
    dotted = name.replace("_", ".")
    if dotted != name and re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(dotted)}(?![A-Za-z0-9_.])", prose
    ):
        return True
    return False


def find_customization_fixture(template_path: Path) -> Path | None:
    """Locate the matching ``customization.yaml`` under tests/, if present."""
    system = template_path.parent.name
    stem = template_path.stem
    candidate = TESTS_ROOT / system / stem / "customization.yaml"
    return candidate if candidate.is_file() else None


def run_tier1(
    template_path: Path,
    *,
    trials: int,
    out_dir: Path | None = None,
    customization_invoker: Any = None,
) -> dict:
    """Run static checks + (if fixture present) customization."""
    system = template_path.parent.name
    stem = template_path.stem
    template_id = f"{system}.{stem}"

    static = static_checks(template_path)

    fixture = find_customization_fixture(template_path)
    if fixture is None:
        customization = {
            "verdict": "skipped",
            "reason": "no customization.yaml fixture present",
        }
    else:
        kwargs = {"trials": trials, "out_dir": out_dir}
        if customization_invoker is not None:
            kwargs["invoker"] = customization_invoker
        customization = _ct.run_file(template_path, fixture, **kwargs)

    static_ok = static["passed"]
    cust_ok = customization.get("verdict") in ("pass", "skipped")
    verdict = "pass" if (static_ok and cust_ok) else "fail"
    return {
        "template_id": template_id,
        "template_path": str(template_path),
        "trials": trials,
        "static": static,
        "customization": customization,
        "verdict": verdict,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="lead_tier1")
    p.add_argument("template", type=Path)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--out-dir", type=Path, default=None)
    args = p.parse_args(argv)
    if not args.template.is_file():
        print(f"template not found: {args.template}", file=sys.stderr)
        print(f"TIER1_RESULT: {json.dumps({'verdict': 'fail', 'error': 'template_not_found'})}")
        return 2
    try:
        result = run_tier1(
            args.template, trials=args.trials, out_dir=args.out_dir
        )
    except Exception as e:  # pragma: no cover — harness error path
        print(f"harness error: {e}", file=sys.stderr)
        print(
            f"TIER1_RESULT: {json.dumps({'verdict': 'fail', 'error': str(e)})}"
        )
        return 2
    print(f"TIER1_RESULT: {json.dumps(result)}")
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
