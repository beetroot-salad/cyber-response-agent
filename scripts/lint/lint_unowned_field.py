#!/usr/bin/env python3
"""Sole-producer lint — checks the `@owns <field>` docstring tags, and nothing else.

Why this exists: this repo's recurring bug is TWO pieces of code deriving one
quantity by different means — one parser with six interpreters that disagreed,
three readers each deriving the same split and each dropping its complement, a
size bound charged on raw text while the renderer emitted quoted YAML so a
document that paid at the write gate was refused at the commit. The two
derivations share no syntax, only meaning, so jscpd and lint_duplicate_helpers
are both structurally blind to them: there is no token run to match and no
shared name.

What is NOT attempted here, deliberately. A detector that asks "are these two
functions computing the same thing?" is a similarity search — it would be noisy,
it would need per-site exclusions, and the exclusions would degrade into prose
the same author supplies to themselves (this repo has already shipped one guard
that rotted exactly that way). It would also have MISSED the motivating bug,
whose two derivations were `len(text.encode())` and dump-then-measure.

So this gate checks only what is exact. An author who knows a value is owned
writes `@owns <field>` in the owning function's docstring; the tag is the
machine-readable half of that decision, and the discovery half is the
grep-before-you-derive rule the write-code-from-spec skill states. Three checks,
each a membership or presence question with no judgment in it:

  - duplicate-owner   two or more functions claim `@owns X` for the same X.
                      THE check: a second producer, declared honestly, named
                      before it can drift from the first.

  - malformed-tag     `@owns` with no field token after it — a tag that will
                      never match the grep it exists to be found by.

  - stale-tag         `@owns X` where `X` appears nowhere in `defender/` except
                      inside `@owns` tags. The rename-left-the-tag case: the
                      field moved, the claim of ownership did not.

The obvious fourth check — "every field of a model-authored artifact has an
owner" — is not implemented, because `_artifact_schema` does not enumerate its
frontmatter fields as a list this could read. Scraping them out of the validator
would be a second derivation of the schema's own field set, which is the bug
this file is about. If that list ever becomes a value, this is where to read it.

Ratchet model (mirrors every other gate here): today's findings live in
`lint_unowned_field_baseline.json` and the lint fails only on a fingerprint that
is not already there. `require_reasons=True` is on — the baseline starts empty,
so there is no pre-existing debt to grandfather, and burying a finding should
cost a sentence saying why.

Inline suppression: `# lint-owns: ok — <reason>` on the `def` line. The reason
must NAME THE OTHER OWNER ("`render_x` produces this instead"), not assert that
this case is fine — a destination is checkable by the next reader, a reason is
not. This mirrors the invlang fence rule, whose suppression must state where the
complement goes.

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
from _astlib import ScanBlind, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unowned_field_baseline.json")
HEADER = "Sole-producer `@owns` tags. See scripts/lint/lint_unowned_field.py."

#: `@owns <field>` in a docstring. The field token is deliberately permissive
#: (identifier characters plus `.` and `-`) because it names a FIELD of some
#: artifact, not a Python symbol — `ceiling_test`, `attrs.owner`, `case-id`.
OWNS_RE = re.compile(r"@owns\s+(?P<field>[A-Za-z_][A-Za-z0-9_.\-]*)")
#: `@owns` with nothing usable after it. Matched separately so a typo'd tag is
#: REPORTED rather than silently not-a-tag: an unparsed tag is worse than no
#: tag, because its author believes the field is claimed.
BARE_OWNS_RE = re.compile(r"@owns(?![A-Za-z0-9_])")

EXCLUDED_DIRS = (".venv", "runs", "run-visualizations")
SUPPRESS = "lint-owns: ok"


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.relative_to(DEFENDER).parts)


def _sources() -> list[tuple[Path, str]]:
    return sorted(
        ((p, p.relative_to(REPO_ROOT).as_posix()) for p in DEFENDER.rglob("*.py") if _in_scope(p)),
        key=lambda pair: pair[1],
    )


def _suppressed(source: str, node: ast.AST) -> bool:
    """Is the `def` line carrying the inline suppression comment?"""
    lineno = getattr(node, "lineno", 0)
    lines = source.splitlines()
    return 0 < lineno <= len(lines) and SUPPRESS in lines[lineno - 1]


def _claims(tree: ast.Module, source: str, rel: str) -> tuple[list, list]:
    """Every `@owns` claim and every malformed tag in one module.

    Functions AND classes: a class can own a field as well as a function can, and
    a tag that only counted on `def` would push authors to the shape the lint
    happens to read rather than the one the code wants."""
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
    """Does `field` appear anywhere in scope OTHER than inside an `@owns` tag?

    Conservative on purpose: a field named by a common word will match somewhere
    and never be reported. This only fires when the name occurs nowhere at all —
    the rename that left its ownership claim behind."""
    for _, rel in sources:
        stripped = OWNS_RE.sub(" ", texts[rel])
        if field in stripped:
            return False
    return True


def main(argv: list[str]) -> int:
    sources = _sources()
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
