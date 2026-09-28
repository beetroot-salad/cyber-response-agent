#!/usr/bin/env python3
"""Ungated artifact write: flag a function under ``defender/`` that writes one of the two
model-authored artifacts (``investigation.md``, ``report.md``) without that artifact's content
schema being applied anywhere in the same function.

``defender/_artifact_schema.py`` owns what a well-formed artifact is, and the permission gate
applies it to every write a model makes. That makes "a committed investigation parses" true
only of the paths through the gate. A harness writer that calls ``write_guarded`` directly, or
a verb that validates the report it writes but not the companion it publishes, reaches the same
sink another way, and every downstream claim about the artifact is silently narrowed. The
pattern: an invariant enforced at a gate, and believed of the artifact.

What it flags — under ``defender/``, production code only. A function containing both:

- a write — a call resolved by origin to ``defender._io``'s ``write_guarded`` /
  ``write_atomic`` / ``open_guarded`` / ``append_jsonl``, or the duck-typed
  ``<x>.write_text(...)`` / ``<x>.write_bytes(...)`` (the receiver is a Path value);
- a gated artifact name — the literals ``"investigation.md"`` / ``"report.md"``, the constant
  spellings of them, or the ``RunPaths`` accessors for them;

and no validation — a call whose resolved callee ends in ``validate_artifact``,
``validate_investigation``, ``validate_report``, ``committed_investigation_reason``,
``decide_write``, or ``validator`` (the close's injected schema seam, a parameter with no
import to resolve).

Co-occurrence within one function, not dataflow. It ensures a writer of these artifacts
cannot be added without the schema visibly nearby, or else a baseline row in the same diff.

What it does not see — read this before treating a green run as proof:

- Whether the validated text is the written text: ``validate_artifact(name, a, ...)``
  beside ``write_guarded(p, b)`` passes.
- A write split across functions: a helper that writes an already-composed string, called by
  a function that validated nothing, is invisible from either side.
- A consumer that publishes without validating: "expose" is not a syntactic act. That half is
  held by ``tests/test_ungated_artifact_write_961_964.py`` and by review.
- Artifacts reached through a computed name.

So a clean run means "no writer of these two artifacts is missing their schema in its own
frame", not "every path that publishes them is gated".

The baseline ships empty, so an entry is a chosen regression. Mark a deliberate site with
``# lint-artifact-gate: ok — <reason>`` on the flagged line or anywhere in the flagged node's
span, and say in the reason which gate covers that write instead.

Run from repo root:  python scripts/lint/lint_ungated_artifact_write.py
Regenerate the baseline:  python scripts/lint/lint_ungated_artifact_write.py --update-baseline
Exit 0 = clean, 1 = new sites, 2 = scan blind.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_ungated_artifact_write_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKERS = ("lint-artifact-gate: ok",)

#: The module that owns the schema. Exempted by full relative path, not basename, so a new
#: `_artifact_schema.py` elsewhere under the scope is not waved through.
CANONICAL_MODULE = "_artifact_schema.py"

#: The two artifacts as spelled in code: bare filenames, and the constant spellings a writer
#: might use instead. `_artifact_schema` does not export those constants (nothing outside the
#: owner may hold a record name), but they stay here because a writer may re-introduce one.
ARTIFACT_LITERALS = frozenset({"investigation.md", "report.md"})
ARTIFACT_CONSTS = frozenset({  # lint-stale-ref: ok — spellings this gate WATCHES FOR, not ones it resolves
    "INVESTIGATION_NAME", "REPORT_NAME"})

def _artifact_accessors() -> frozenset[str]:
    """`RunPaths`' accessors for the two schema'd artifacts, derived from the owner: every
    public accessor resolving to one of `ARTIFACT_LITERALS`. Only the two model-authored
    documents have a content schema, so accessors for other records are never included.
    Matched as bare attribute names because the receiver is a value — `rp.investigation` has
    no resolvable origin."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from defender._run_paths import RunPaths  # noqa: PLC0415

    probe = RunPaths(Path("/probe"))
    names: set[str] = set()
    for attr in dir(RunPaths):
        if attr.startswith("_") or not isinstance(getattr(RunPaths, attr), property):
            continue
        resolved = getattr(probe, attr)
        if isinstance(resolved, Path) and resolved.name in ARTIFACT_LITERALS:
            names.add(attr)
    return frozenset(names)


ARTIFACT_ACCESSORS = _artifact_accessors()

#: Resolved by origin through `_astlib.callee`, so aliased imports count. The same primitives
#: `lint_unguarded_tree_write` watches, for a different question: that gate asks whether the
#: write is alias-safe, this one whether its content met a schema.
WRITE_CALLEES = frozenset({
    "defender._io.write_guarded",
    "defender._io.write_atomic",
    "defender._io.open_guarded",
    "defender._io.append_jsonl",
})

#: Duck-typed write shapes, with no import to resolve.
WRITE_METHODS = frozenset({"write_text", "write_bytes"})

#: Matched on the callee's last segment, not its origin: the close injects its schema as a
#: parameter (`validator: ArtifactValidator = validate_artifact`), which origin resolution
#: cannot see through. The leniency risks a false negative on an incidentally named
#: `validator`; a false positive on the DI seam would train people to suppress the gate.
VALIDATOR_NAMES = frozenset({
    "validate_artifact",
    "validate_investigation",
    "validate_report",
    "committed_investigation_reason",
    "decide_write",
    "validator",
})


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _is_write(node: ast.AST, env: ModuleEnv) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if callee(node, env) in WRITE_CALLEES:
        return True
    return isinstance(node.func, ast.Attribute) and node.func.attr in WRITE_METHODS


def _is_validation(node: ast.AST, env: ModuleEnv) -> bool:
    if not isinstance(node, ast.Call):
        return False
    target = callee(node, env)
    if target is not None and target.split(".")[-1] in VALIDATOR_NAMES:
        return True
    # `callee` returns None for an unresolvable bare local name — the shape of the close's
    # injected `validator(...)` — so read the name off the node.
    if isinstance(node.func, ast.Name) and node.func.id in VALIDATOR_NAMES:
        return True
    return isinstance(node.func, ast.Attribute) and node.func.attr in VALIDATOR_NAMES


def _names_artifact(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value in ARTIFACT_LITERALS
    if isinstance(node, ast.Name):
        return node.id in ARTIFACT_CONSTS
    if isinstance(node, ast.Attribute):
        return node.attr in ARTIFACT_ACCESSORS or node.attr in ARTIFACT_CONSTS
    return False


def _walk_body(func: ast.AST) -> list[ast.AST]:
    """Every node under `func` except the bodies of nested functions.

    A nested def is its own frame with its own verdict; folding it in would let an inner
    validation excuse an outer write (and the reverse)."""
    out: list[ast.AST] = []
    for child in ast.iter_child_nodes(func):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        out.append(child)
        out.extend(_walk_body(child))
    return out


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    env = module_env(tree)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = _walk_body(node)
        writes = [n for n in body if _is_write(n, env)]
        if not writes:
            continue
        if not any(_names_artifact(n) for n in body):
            continue
        if any(_is_validation(n, env) for n in body):
            continue
        if _suppressed(node, lines):
            continue
        # No line number, so moving the write within its function is not a new finding.
        fingerprint = f"{rel}:{node.name}"
        findings.append(Finding(
            fingerprint=fingerprint,
            display=(
                f"{rel}:{writes[0].lineno}: {node.name}() writes a gated artifact "
                f"(investigation.md / report.md) with no content schema applied in the same "
                f"function — route it through permission.decide_write, or call "
                f"_artifact_schema.validate_artifact and OBEY the reason it returns"
            ),
        ))
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
        if rel == CANONICAL_MODULE or _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return sorted(findings, key=lambda f: f.fingerprint)


HEADER = (
    "lint_ungated_artifact_write baseline — functions under defender/ that write "
    "investigation.md or report.md with no content schema applied in the same frame "
    "(#961, #964). Fingerprint is file:function (no line number), file relative to the scan "
    "scope. CI fails on a fingerprint absent here. This baseline ships EMPTY — both known "
    "sites were fixed when the gate landed, so an entry in it is a regression someone chose. "
    "Regenerate: python scripts/lint/lint_ungated_artifact_write.py --update-baseline."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    # DI/test seams: the tests drive injected tmp trees and baselines.
    args = sys.argv[1:] if argv is None else argv
    root = SCOPE if scope is None else scope
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_ungated_artifact_write: {exc}", file=sys.stderr)
        return 2
    print(
        "Every writer of investigation.md / report.md meets the content schema in its own "
        "frame — #961 (the close published a document it never validated) and #964 (the "
        "harness seeded rows past the gate) were both writers nobody had censused, under an "
        "invariant everybody had inherited."
    )
    print("Mark a deliberate site with `# lint-artifact-gate: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_ungated_artifact_write", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
