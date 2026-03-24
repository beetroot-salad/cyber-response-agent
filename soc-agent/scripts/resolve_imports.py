#!/usr/bin/env python3
"""Resolve and concatenate signature knowledge for skill preprocessing.

Usage: python3 scripts/resolve_imports.py <signature_id>

Scans the signature's playbook.md for inline @import:name references,
resolves each to a file in knowledge/common/, and outputs all knowledge
to stdout for !`command` substitution in SKILL.md.

Output order:
1. knowledge/signatures/{sig_id}/context.md (always)
2. knowledge/signatures/{sig_id}/playbook.md (always)
3. knowledge/common/checklist.md (always — safety artifact)
4. Each unique @import:name found in playbook body

Resolution: @import:name looks in lessons/{name}.md then utilities/{name}.md.

Exit codes:
  0 — success (partial success if some imports unresolvable)
  1 — signature directory or required files missing
"""

import re
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = SOC_AGENT_ROOT / "knowledge"
COMMON_DIR = KNOWLEDGE_DIR / "common"
SIGNATURES_DIR = KNOWLEDGE_DIR / "signatures"

IMPORT_PATTERN = re.compile(r"@import:([a-zA-Z0-9_-]+)")

SEARCH_DIRS = [
    COMMON_DIR / "lessons",
    COMMON_DIR / "utilities",
]


def resolve_import(name: str) -> Path | None:
    """Resolve an import name to a file path."""
    for search_dir in SEARCH_DIRS:
        candidate = search_dir / f"{name}.md"
        if candidate.exists():
            return candidate
    return None


def extract_imports(playbook_text: str) -> list[str]:
    """Extract unique @import:name references from playbook body, in order."""
    seen = set()
    imports = []
    for match in IMPORT_PATTERN.finditer(playbook_text):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            imports.append(name)
    return imports


def emit_file(path: Path, label: str | None = None) -> None:
    """Print a file's contents with a source comment separator."""
    rel = path.relative_to(SOC_AGENT_ROOT)
    print(f"\n<!-- source: {label or rel} -->")
    print(path.read_text().rstrip())


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <signature_id>", file=sys.stderr)
        return 1

    signature_id = sys.argv[1]
    sig_dir = SIGNATURES_DIR / signature_id

    if not sig_dir.is_dir():
        print(f"Error: signature directory not found: {sig_dir}", file=sys.stderr)
        return 1

    context_path = sig_dir / "context.md"
    playbook_path = sig_dir / "playbook.md"
    checklist_path = COMMON_DIR / "checklist.md"

    for required in (context_path, playbook_path):
        if not required.exists():
            print(f"Error: required file missing: {required}", file=sys.stderr)
            return 1

    # 1. Signature context
    emit_file(context_path)

    # 2. Signature playbook
    emit_file(playbook_path)

    # 3. Checklist (always)
    if checklist_path.exists():
        emit_file(checklist_path)
    else:
        print(f"\n<!-- warning: checklist not found at {checklist_path} -->")

    # 4. Resolve inline imports from playbook body
    playbook_text = playbook_path.read_text()
    imports = extract_imports(playbook_text)

    for name in imports:
        resolved = resolve_import(name)
        if resolved:
            emit_file(resolved)
        else:
            print(f"\n<!-- warning: @import:{name} could not be resolved -->")

    return 0


if __name__ == "__main__":
    sys.exit(main())
