#!/usr/bin/env python3
"""Sole-producer lint: checks the `@owns <field>` docstring tags, and nothing else.

This repo's recurring bug is two pieces of code deriving one quantity by different means —
e.g. a size bound charged on raw text while the renderer emits quoted YAML, so a document that
passes the write gate is refused at commit. The derivations share meaning but no syntax, so
jscpd and lint_duplicate_helpers cannot see them.

Detecting "these two functions compute the same thing" would be a noisy similarity search
needing per-site exclusions that rot into prose, and would still miss derivations as different
as `len(text.encode())` and dump-then-measure. So this gate checks only what is exact: an
author who knows a value is owned writes `@owns <field>` in the owning function's docstring
(discovery is the grep-before-you-derive rule in the write-code-from-spec skill). Three checks:

  - duplicate-owner   two or more functions claim `@owns X` for the same X: a second
                      producer, named before it can drift from the first.

  - malformed-tag     `@owns` with no field token after it — a tag the grep will never find.

  - stale-tag         `@owns X` where `X` appears nowhere in `defender/` except inside
                      `@owns` tags: the field was renamed, the claim was not.

A fourth check — every field of a model-authored artifact has an owner — is not implemented
because `_artifact_schema` does not expose its frontmatter fields as a list; scraping them from
the validator would be a second derivation of the schema. If that list becomes a value, read
it here.

Ratchet model: today's findings live in `lint_unowned_field_baseline.json` and the lint fails
only on a new fingerprint. `require_reasons=True`: the baseline started empty, so burying a
finding costs a sentence.

Inline suppression: `# lint-owns: ok — <reason>` on the `def` line. The reason must name the
other owner ("`render_x` produces this instead"), a destination the next reader can check.

Run from repo root:  python scripts/lint/lint_unowned_field.py
Regenerate the baseline:  python scripts/lint/lint_unowned_field.py --update-baseline
Exit 0 = clean, 1 = new findings, 2 = a file could not be scanned.
"""
from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse, source_files

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unowned_field_baseline.json")
HEADER = "Sole-producer `@owns` tags. See scripts/lint/lint_unowned_field.py."

#: `@owns <field>` in a docstring. The field token allows `.` and `-` because it names an
#: artifact field, not a Python symbol — `ceiling_test`, `attrs.owner`, `case-id`.
OWNS_RE = re.compile(r"@owns\s+(?P<field>[A-Za-z_][A-Za-z0-9_.\-]*)")
#: `@owns` with nothing usable after it, matched separately so a typo'd tag is reported: its
#: author believes the field is claimed.
BARE_OWNS_RE = re.compile(r"@owns(?![A-Za-z0-9_])")

EXCLUDED_DIRS = (".venv", "runs")
SUPPRESS = "lint-owns: ok"


def _sources() -> list[tuple[Path, str]]:
    return [(DEFENDER / rel, f"defender/{rel}") for rel in source_files(DEFENDER, EXCLUDED_DIRS)]


def _suppressed(source: str, node: ast.AST) -> bool:
    """Is the `def` line carrying the inline suppression comment?"""
    lineno = getattr(node, "lineno", 0)
    lines = source.splitlines()
    return 0 < lineno <= len(lines) and SUPPRESS in lines[lineno - 1]


def _claims(tree: ast.Module, source: str, rel: str) -> tuple[list, list]:
    """Every `@owns` claim and every malformed tag in one module. Classes count as well as
    functions, so authors are not pushed to the shape the lint happens to read."""
    owned: list[tuple[str, str, int, str]] = []
    malformed: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        doc = ast.get_docstring(node) or ""
        if "@owns" not in doc or _suppressed(source, node):
            continue
        fields = OWNS_RE.findall(doc)
        for field in fields:
            owned.append((field, rel, node.lineno, node.name))
        if len(BARE_OWNS_RE.findall(doc)) > len(fields):
            malformed.append((rel, node.lineno, node.name))
    return owned, malformed


def _stale(field: str, sources: list[tuple[Path, str]], texts: dict[str, str]) -> bool:
    """Does `field` appear anywhere in scope other than inside an `@owns` tag?

    Conservative: a common-word field will match somewhere and never be reported; this
    fires only when the name occurs nowhere at all."""
    for _, rel in sources:
        stripped = OWNS_RE.sub(" ", texts[rel])
        if field in stripped:
            return False
    return True


def main(argv: list[str]) -> int:
    try:
        sources = _sources()
    except ScanBlind as exc:
        print(f"lint_unowned_field: {exc}", file=sys.stderr)
        return 2
    texts: dict[str, str] = {}
    owned: list[tuple[str, str, int, str]] = []
    malformed: list[tuple[str, int, str]] = []
    for path, rel in sources:
        try:
            source, tree = read_and_parse(path, rel)
        except ScanBlind as exc:
            print(f"lint_unowned_field: {exc}", file=sys.stderr)
            return 2
        texts[rel] = source
        mod_owned, mod_malformed = _claims(tree, source, rel)
        owned.extend(mod_owned)
        malformed.extend(mod_malformed)

    by_field: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for field, rel, lineno, name in owned:
        by_field[field].append((rel, lineno, name))

    findings: list[Finding] = []
    for field, sites in sorted(by_field.items()):
        if len(sites) > 1:
            where = ", ".join(f"{rel}:{ln} {name}()" for rel, ln, name in sites)
            findings.append(Finding(
                fingerprint=f"duplicate-owner {field}",
                display=f"duplicate-owner @owns {field}: claimed by {len(sites)} — {where}. "
                        f"One producer, or suppress naming which of these owns it.",
            ))
        elif _stale(field, sources, texts):
            rel, ln, name = sites[0]
            findings.append(Finding(
                fingerprint=f"stale-tag {field}",
                display=f"stale-tag @owns {field} at {rel}:{ln} {name}(): '{field}' appears "
                        f"nowhere else in defender/ — renamed field, orphaned claim.",
            ))
    for rel, lineno, name in malformed:
        findings.append(Finding(
            fingerprint=f"malformed-tag {rel}:{name}",
            display=f"malformed-tag at {rel}:{lineno} {name}(): `@owns` with no field name "
                    f"after it — nothing will ever grep this.",
        ))

    for finding in findings:
        print(finding.display)

    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_unowned_field", header=HEADER, require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
