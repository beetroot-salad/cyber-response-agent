#!/usr/bin/env python3
"""List or validate the tag vocabulary across lead query templates.

General-purpose utility: walks `knowledge/common-investigation/leads/*/templates/*.md`,
reads the YAML frontmatter from each template, and either prints the collected
vocabulary or checks a specific file's tags against it.

Usage:
    python3 scripts/tools/list_lead_tags.py
        Print every unique tag in the vocabulary with its frequency.

    python3 scripts/tools/list_lead_tags.py --check <template-path>
        Validate a specific template's tags. Reports tags that are new to the
        vocabulary, near-duplicates of existing tags, and tags that violate the
        snake_case convention.

    python3 scripts/tools/list_lead_tags.py --root <kb-root>
        Override the knowledge base root (defaults to <repo>/soc-agent/knowledge).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

SNAKE_CASE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KB_ROOT = REPO_ROOT / "knowledge"


def parse_frontmatter(path: Path) -> dict:
    text = path.read_text()
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    block = text[4:end]
    try:
        import yaml  # type: ignore
        return yaml.safe_load(block) or {}
    except ImportError:
        return _parse_frontmatter_fallback(block)


def _parse_frontmatter_fallback(block: str) -> dict:
    """Minimal YAML parser for the subset used in template frontmatter.

    Handles flat scalar keys and one-line flow-style lists like `tags: [a, b]`.
    """
    out: dict = {}
    for line in block.splitlines():
        if ":" not in line or line.startswith(" "):
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            out[key] = [v.strip() for v in inner.split(",") if v.strip()] if inner else []
        else:
            out[key] = value
    return out


def collect_templates(kb_root: Path) -> list[Path]:
    leads_root = kb_root / "common-investigation" / "leads"
    if not leads_root.is_dir():
        return []
    return [
        p
        for p in sorted(leads_root.glob("*/templates/*.md"))
        if "_template" not in p.parts
    ]


def collect_vocabulary(kb_root: Path) -> tuple[Counter, dict[str, list[Path]]]:
    counts: Counter = Counter()
    provenance: dict[str, list[Path]] = {}
    for template in collect_templates(kb_root):
        frontmatter = parse_frontmatter(template)
        tags = frontmatter.get("tags") or []
        if not isinstance(tags, list):
            continue
        for tag in tags:
            if not isinstance(tag, str):
                continue
            counts[tag] += 1
            provenance.setdefault(tag, []).append(template)
    return counts, provenance


def near_duplicates(tag: str, vocabulary: set[str]) -> list[str]:
    """Cheap near-duplicate detection.

    A candidate matches if it shares a prefix of at least 4 characters with the
    target, or if one is contained in the other. Catches drift like
    `auth`/`authentication` or `net`/`network` without pulling in a real
    similarity library.
    """
    matches = []
    for other in vocabulary:
        if other == tag:
            continue
        if tag in other or other in tag:
            matches.append(other)
            continue
        if len(tag) >= 4 and len(other) >= 4 and tag[:4] == other[:4]:
            matches.append(other)
    return sorted(set(matches))


def cmd_list(kb_root: Path) -> int:
    counts, _ = collect_vocabulary(kb_root)
    if not counts:
        print(f"no templates found under {kb_root}", file=sys.stderr)
        return 1
    width = max(len(tag) for tag in counts)
    for tag, count in sorted(counts.items()):
        marker = "" if SNAKE_CASE_RE.match(tag) else "  (non-snake_case)"
        print(f"  {tag.ljust(width)}  x{count}{marker}")
    print(f"\n{len(counts)} unique tags across {sum(counts.values())} tag uses")
    return 0


def cmd_check(kb_root: Path, target: Path) -> int:
    if not target.is_file():
        print(f"error: {target} is not a file", file=sys.stderr)
        return 2
    frontmatter = parse_frontmatter(target)
    tags = frontmatter.get("tags") or []
    if not isinstance(tags, list) or not tags:
        print(f"error: {target} has no tags in frontmatter", file=sys.stderr)
        return 2

    counts, _ = collect_vocabulary(kb_root)
    # Exclude the target's own contribution when computing the comparison
    # vocabulary, so a brand-new template is checked against siblings only.
    target_resolved = target.resolve()
    siblings_vocab: set[str] = set()
    for sibling in collect_templates(kb_root):
        if sibling.resolve() == target_resolved:
            continue
        sib_fm = parse_frontmatter(sibling)
        sib_tags = sib_fm.get("tags") or []
        if isinstance(sib_tags, list):
            siblings_vocab.update(t for t in sib_tags if isinstance(t, str))

    problems_found = False
    print(f"checking {target.relative_to(REPO_ROOT) if target.is_relative_to(REPO_ROOT) else target}")
    for tag in tags:
        if not isinstance(tag, str):
            print(f"  ! non-string tag: {tag!r}")
            problems_found = True
            continue

        issues = []
        if not SNAKE_CASE_RE.match(tag):
            issues.append("not snake_case")
        if tag not in siblings_vocab:
            dupes = near_duplicates(tag, siblings_vocab)
            if dupes:
                issues.append(f"new, near-duplicate of existing: {', '.join(dupes)}")
            else:
                issues.append("new to vocabulary")

        if issues:
            print(f"  - {tag}: {'; '.join(issues)}")
            problems_found = True
        else:
            print(f"  ok  {tag}")

    if problems_found:
        print(
            "\nflagged tags are edit decisions, not errors — reuse an existing "
            "term if one fits, introduce the new term deliberately, or rename "
            "to snake_case.",
            file=sys.stderr,
        )
        return 1
    print("\nall tags match the existing vocabulary and convention")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_KB_ROOT,
        help="knowledge base root (default: soc-agent/knowledge)",
    )
    parser.add_argument(
        "--check",
        type=Path,
        metavar="PATH",
        help="validate the tags on a single template file",
    )
    args = parser.parse_args()

    kb_root = args.root.resolve()
    if not kb_root.is_dir():
        print(f"error: {kb_root} is not a directory", file=sys.stderr)
        return 2

    if args.check is not None:
        return cmd_check(kb_root, args.check.resolve())
    return cmd_list(kb_root)


if __name__ == "__main__":
    sys.exit(main())
