#!/usr/bin/env python3
"""Borrowed-vocabulary smell — flag a module that imports someone else's closed vocabulary and
re-derives, itself, what a value in it means.

The mechanical shape of #785. `report.md`'s disposition had one parser and six interpreters:
each consumer imported ``DISPOSITION_ENUM`` and wrote its own membership test on top of the
shared parse. They then disagreed on the same bytes — three different reactions to an invalid
value — and five of the six silently dropped #722's zero-width strip, on a field an attacker
influences by construction. No single site looked wrong; the divergence only existed BETWEEN
them, which is why review never caught it and a census did.

What arms this gate is the *existence of an owner's answer*. A vocabulary is watched once the
module that DEFINES it also defines a function that tests membership on it — that function is
the owner's answer to "is this value in the vocabulary, and what does it normalize to", and
every other module should be calling it. Until such a function exists there is nothing to
call, so the vocabulary is not watched and a plain membership test elsewhere is fine. That
makes the gate self-arming: the next fold that adds a normalizer starts guarding its own
vocabulary the moment it lands, with no edit here.

What this flags: ``x in NAME`` / ``x not in NAME`` where ``NAME`` is an ALL-CAPS module-level
constant IMPORTED from another module, and that module has an armed normalizer for it. Import
aliases are resolved, so ``from m import NAME as N`` then ``x in N`` still flags.

What it does NOT flag:
  - a module testing membership on a vocabulary it defines itself — that IS the owner's
    answer, and 54 of the 62 membership tests in the tree today are this shape.
  - passing the vocabulary somewhere (``_check_vocab(v, NAME, ...)``) — that is delegating to
    a shared checker, the cure rather than the smell.
  - equality against a bare literal (``x == "benign"``). This is a real hole and named
    deliberately: the invlang validator's benign gate failed open on exactly that form and
    this lint would NOT have caught it. Flagging every ``==`` against every vocabulary member
    is too noisy to gate on; the defence there is that the vocabulary now has one normalizer
    and one place to route through, not a lint.
  - test modules — a test legitimately parametrizes over a vocabulary to assert on it.

Mark a deliberate site with ``# lint-vocabulary: ok — <reason>``, on the site's own lines or
anywhere in the comment block directly above it. There is at least one real
one: a WRITE gate is supposed to be exact where a reader normalizes, because on write there is
still an author to send retry text to. The suppression is how that asymmetry gets STATED at
the site instead of being rediscovered.

Pre-existing sites are ratcheted via ``lint_borrowed_vocabulary_baseline.json`` (see
scripts/lint/_baseline.py); the gate fails only on a NEW file+function+vocabulary triple.

Run from repo root:  python scripts/lint/lint_borrowed_vocabulary.py
Regenerate the baseline:  python scripts/lint/lint_borrowed_vocabulary.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_borrowed_vocabulary_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts", "runs")

SUPPRESS = "lint-vocabulary: ok"

# An ALL-CAPS name shorter than this is more likely a flag or an abbreviation than a
# vocabulary, and a one-letter loop constant would make the census meaningless.
_MIN_NAME_LEN = 4


def _in_scope(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in EXCLUDED_DIRS for part in rel.parts):
        return False
    # A test asserting over a vocabulary is asserting, not interpreting.
    return "tests" not in rel.parts


def _is_vocabulary_name(name: str) -> bool:
    """ALL-CAPS and long enough to be a vocabulary. `str.isupper()` already requires at least
    one cased character, so digits-and-underscores alone do not qualify."""
    return len(name) >= _MIN_NAME_LEN and name.isupper()


def _module_level_names(tree: ast.Module) -> set[str]:
    """The ALL-CAPS constants this module DEFINES at module level — the vocabularies it owns."""
    names: set[str] = set()
    for node in tree.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for t in targets:
            if isinstance(t, ast.Name) and _is_vocabulary_name(t.id):
                names.add(t.id)
    return names


def _membership_targets(tree: ast.AST) -> set[str]:
    """Every bare ``NAME`` this tree tests membership against."""
    hits: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.In, ast.NotIn)) and isinstance(comparator, ast.Name):
                hits.add(comparator.id)
    return hits


def _armed_vocabularies(tree: ast.Module) -> set[str]:
    """The vocabularies this module owns AND answers for — defined here, and tested for
    membership inside a function here. That function is what every other module should call."""
    owned = _module_level_names(tree)
    answered: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            answered |= _membership_targets(node) & owned
    return answered


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """local name -> original name, for every ``from m import NAME`` in the module."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if _is_vocabulary_name(a.name):
                    aliases[a.asname or a.name] = a.name
    return aliases


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    """The marker on the site's own line span, OR anywhere in the contiguous comment block
    directly above it. The block form is deliberate: a suppression here has to explain why one
    site is exempt from a rule the rest of the tree follows, and that never fits on one line —
    forcing it to would buy a shorter comment at the cost of the reason being written down."""
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    if any(SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)):
        return True
    i = start - 1
    while i > 0 and lines[i - 1].lstrip().startswith("#"):
        if SUPPRESS in lines[i - 1]:
            return True
        i -= 1
    return False


def _scan_file(
    rel: str, tree: ast.Module, lines: list[str], armed: dict[str, str]
) -> list[Finding]:
    """Flag membership tests on an armed vocabulary this module does not own."""
    owned = _module_level_names(tree)
    aliases = _import_aliases(tree)
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*scope, node.name)
        if isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                if not isinstance(op, (ast.In, ast.NotIn)):
                    continue
                if not isinstance(comparator, ast.Name):
                    continue
                original = aliases.get(comparator.id, comparator.id)
                if original in owned or original not in armed:
                    continue
                if _suppressed(node, lines):
                    continue
                qual = ".".join(scope) or "<module>"
                fp = f"{rel}:{qual}:{original}"
                if fp in seen:
                    continue
                seen.add(fp)
                findings.append(
                    Finding(
                        fingerprint=fp,
                        display=(
                            f"{rel}:{node.lineno}: {qual}() re-derives membership in "
                            f"{original} — call {armed[original]}'s normalizer instead of "
                            f"borrowing its vocabulary"
                        ),
                    )
                )
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, ())
    return findings


def _corpus(root: Path) -> list[tuple[str, ast.Module, list[str]]]:
    out: list[tuple[str, ast.Module, list[str]]] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path, root):
            continue
        rel = path.relative_to(root.parent).as_posix()
        text, tree = read_and_parse(path, rel)
        assert isinstance(tree, ast.Module)
        out.append((rel, tree, text.splitlines()))
    return out


def _scan(root: Path = DEFENDER) -> list[Finding]:
    """Two passes over ONE corpus. `root` is the scan scope — the testability seam the other
    gates carry, and load-bearing here beyond convenience: arming is a whole-corpus property,
    so a gate that could only ever scan the real tree could not be shown to arm and disarm."""
    corpus = _corpus(root)
    # Pass 1: which vocabularies have an owner's answer, and whose is it.
    armed: dict[str, str] = {}
    for rel, tree, _lines in corpus:
        for name in _armed_vocabularies(tree):
            armed[name] = rel
    # Pass 2: everyone else re-deriving that answer.
    findings: list[Finding] = []
    for rel, tree, lines in corpus:
        findings.extend(_scan_file(rel, tree, lines, armed))
    return findings


HEADER = (
    "lint_borrowed_vocabulary baseline — a module importing another module's closed "
    "vocabulary and re-deriving the membership test itself, instead of calling the "
    "normalizer the owning module already exposes (the #785 smell: one parser, six "
    "interpreters, five of which lost the #722 zero-width strip). A vocabulary is watched "
    "only once its owner defines a function that tests membership on it, so the gate arms "
    "itself as folds land. Fingerprint is file:function:VOCABULARY (no line number). CI "
    "fails on a triple absent here. Regenerate: python "
    "scripts/lint/lint_borrowed_vocabulary.py --update-baseline. Annotate intentional "
    'entries; "" = un-triaged debt to fold.'
)


def main(
    argv: list[str], *, scope: Path | None = None, baseline_path: Path | None = None
) -> int:
    root = scope if scope is not None else DEFENDER
    baseline = baseline_path if baseline_path is not None else BASELINE_PATH
    if not root.is_dir():
        print(f"scan root not found at {root}", file=sys.stderr)
        return 2
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Worse here
    # than for a single-pass lint: an unreadable OWNER silently disarms its vocabulary for the
    # whole repo. Exit 2 — the gate could not run, which is not "clean" (#618/#621/#652).
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_borrowed_vocabulary: {exc}", file=sys.stderr)
        return 2
    print(
        "A closed vocabulary's owner owns what a value in it MEANS. Call the normalizer "
        "beside the vocabulary instead of importing the vocabulary and re-deriving the test."
    )
    print("Suppress a deliberate site with `# lint-vocabulary: ok — <reason>`.")
    return gate(
        findings, baseline, argv,
        label="lint_borrowed_vocabulary", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
