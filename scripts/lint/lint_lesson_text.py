#!/usr/bin/env python3
"""Lesson text leaves the shared loader in the form its destination needs — or says why not.

A lesson's frontmatter and body are corpus text a model wrote (#1206). `defender._corpus.Lesson`
hands it out as `line` / `lines` (one printed line: a line break or a terminal control in a
value would forge rows) and `match_text` (what a search runs over, in the same spelling); text
bound for model context goes inside a `defender._untrusted` frame. The raw fields — `fm`, and a
lesson's `raw` and `body` — are for matching, authoring and the HTML views, which need the
values as written.

So every read of `<x>.fm`, of `.raw` / `.body` on a name spelled `lesson…`, and of
`.frontmatter` on a name spelled `hit…` (a frontier `Hit` carries a lesson's frontmatter) outside
`defender/_corpus.py` carries `# lint-lesson-text: ok — <reason>` on a line the read spans, the
reason saying where the raw text goes and what protects it there.

A HEURISTIC, not a proof: the shape is matched by attribute and receiver name, not type, so
lesson text reached another way passes unseen — a lesson file parsed directly with
`_frontmatter.split_frontmatter` / `parse_frontmatter` (as `lessons_fm.cmd_show` and
`trace_lesson`'s one-lesson path do), or a frontmatter dict under another name. Those readers
are framed or flattened by hand and pinned by their own tests.

Run from repo root:  python scripts/lint/lint_lesson_text.py
Exit 0 = clean, 1 = a raw read that does not say why, 2 = could not scan.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse, source_files

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_lesson_text_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "tests")
#: The loader itself: it builds the one-line and match forms from the raw fields.
OWNER = "defender/_corpus.py"
#: The suppression, with its reason: a bare `ok` is not one.
SUPPRESS = re.compile(r"#\s*lint-lesson-text: ok\s*(?:—|--|-)\s*\S")
#: Raw fields read only on a receiver spelled with the prefix: common attribute names elsewhere.
_ON_A_NAMED = {"raw": "lesson", "body": "lesson", "frontmatter": "hit"}


def _receiver_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def raw_reads(tree: ast.AST) -> list[ast.Attribute]:
    """Each `<x>.fm`, and each `.raw` / `.body` on a name spelled `lesson…`, read in `tree`."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
            continue
        if node.attr == "fm" or (
            node.attr in _ON_A_NAMED
            and _receiver_name(node.value).lower().startswith(_ON_A_NAMED[node.attr])
        ):
            found.append(node)
    return found


def suppressed(node: ast.Attribute, lines: list[str]) -> bool:
    """A reasoned suppression on any line the read spans (a call split over lines included)."""
    last = node.end_lineno or node.lineno
    return any(SUPPRESS.search(lines[i - 1]) for i in range(node.lineno, last + 1))


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for name in source_files(DEFENDER, EXCLUDED_DIRS):
        path = DEFENDER / name
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel == OWNER:
            continue
        text, tree = read_and_parse(path, rel)
        lines = text.splitlines()
        for node in raw_reads(tree):
            if suppressed(node, lines):
                continue
            findings.append(Finding(
                fingerprint=f"{rel}:{node.lineno}:{node.attr}",
                display=f"{rel}:{node.lineno}: raw lesson text `.{node.attr}` read without a reason",
            ))
    return findings


HEADER = (
    "lint_lesson_text baseline — raw lesson-text reads (`.fm`, a lesson's `.raw` / `.body`, "
    "a hit's `.frontmatter`) "
    "outside defender/_corpus.py without `# lint-lesson-text: ok — <reason>`. Ships EMPTY. "
    "Regenerate: python scripts/lint/lint_lesson_text.py --update-baseline."
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_lesson_text: {exc}", file=sys.stderr)
        return 2
    print("Take lesson text through Lesson.line / .lines / .match_text (and frame it for model")
    print("context), or mark the raw read `# lint-lesson-text: ok — <where it goes, what guards it>`.")
    return gate(findings, BASELINE_PATH, argv, label="lint_lesson_text", header=HEADER,
                require_reasons=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
