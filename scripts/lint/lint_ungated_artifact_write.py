#!/usr/bin/env python3
"""Ungated artifact write — flag a function under ``defender/`` that WRITES one of the two
model-authored artifacts (``investigation.md``, ``report.md``) without that artifact's content
schema being applied anywhere in the same function.

WHAT WENT WRONG.  ``defender/_artifact_schema.py`` owns what a well-formed artifact IS, and
the permission gate applies it to every write a MODEL makes. That made a sentence true and
tempting: *a committed investigation parses*. It was true of the verbs the agent writes
through, and the design of everything downstream rested on it — including #954's, whose whole
argument was that a malformed document cannot form because the write gate refuses it.

Two writers were outside that set. ``lead_zero._declare_l_finding`` seeds a ``:L findings``
row into ``investigation.md`` before MAIN's first turn by concatenating text and calling
``write_guarded`` directly — no tool call, so no ``decide_write``, so no schema (#964). And
``close_investigation`` — the one verb that PUBLISHES, committing the report and handing the
parsed companion to the review gate — validated the report it wrote and never the companion it
published, so a document carrying an error-severity finding closed successfully (#961).
Neither was a bypass anyone chose; both were writers nobody had censused, under an invariant
everyone had inherited.

THE PATTERN, stated so it is recognisable next time: *an invariant enforced at a gate, and
believed of the artifact.* A gate can only promise something about the paths that run through
it. The moment a second writer reaches the same sink another way, every downstream claim about
the artifact is quietly narrowed to "…except by that route" — and nothing in the type system,
the tests, or the reading of any one file says so.

WHAT IT FLAGS — under ``defender/``, production code only. A function is a finding when it
contains BOTH:

- a **write** — a call resolved by ORIGIN to ``defender._io``'s ``write_guarded`` /
  ``write_atomic`` / ``open_guarded`` / ``append_jsonl``, or the duck-typed
  ``<x>.write_text(...)`` / ``<x>.write_bytes(...)`` shapes (a receiver is a Path VALUE, so
  there is no import to resolve);
- a **gated artifact name** — the literals ``"investigation.md"`` / ``"report.md"``, the
  ``_artifact_schema`` constants that spell them, or the ``RunPaths`` accessors
  ``.investigation`` / ``.report``;

and NO **validation** — a call whose resolved callee ends in ``validate_artifact``,
``validate_investigation``, ``validate_report``, ``committed_investigation_reason``,
``decide_write``, or ``validator`` (the close's injected schema seam, which is a parameter and
so has no import to resolve).

Co-occurrence inside one function, deliberately, rather than dataflow from the validated text
to the written text. Dataflow would be the stronger question and this gate does not ask it:
see the blind spots below. What it does buy is that a writer of these artifacts cannot be
added without the schema being visibly nearby — and if it is added anyway, the diff that adds
it also has to add a baseline row, which is the review moment #964 never got.

WHAT IT DOES *NOT* SEE — read this before treating a green run as proof:

- **Whether the validated text is the written text.** ``validate_artifact(name, a, ...)``
  beside ``write_guarded(p, b)`` passes. The gate asks whether the schema was consulted, not
  whether it was obeyed.
- **A write split across functions.** A helper that takes an already-composed string and
  writes it, called by a function that validated nothing, is invisible from either side.
  ``lead_zero._declare_l_finding`` composed and wrote in one frame, which is why this shape
  catches it; a two-frame version would not be caught.
- **A CONSUMER that publishes without validating.** #961 is only half a write bug: the close
  did write report.md, but what went unchecked was the companion it published alongside.
  Nothing structural can ask "did this function validate everything it is about to expose",
  because "expose" is not a syntactic act. That half is held by
  ``tests/test_ungated_artifact_write_961_964.py`` and by review, not by this gate.
- **Artifacts reached through a computed name.** The gate reads names, not values.

So a clean run means "no writer of these two artifacts is missing their schema in its own
frame", not "every path that publishes them is gated". The second is what the census in
``ARTIFACT_NAMES`` and the suite are for.

THE BASELINE SHIPS EMPTY. Both known sites were fixed in the change that added this gate, so
an entry appearing here is a regression someone chose. Mark a deliberate site with
``# lint-artifact-gate: ok — <reason>`` on the flagged line or anywhere in the flagged node's
span, and say in the reason WHICH gate covers that write instead.

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

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-artifact-gate: ok",)

#: The module that OWNS the schema. Exempted by full relative path rather than basename, the
#: same way the sibling gates exempt their canonical module: a basename match would wave
#: through any new `_artifact_schema.py` anywhere under the scope.
CANONICAL_MODULE = "_artifact_schema.py"

#: The two artifacts, as they are spelled in code. The bare filenames are what most call sites
#: write; the constants are what `_artifact_schema` exports for the ones that would rather not
#: repeat a literal. Both spellings count — a writer that imports the constant is no less a
#: writer than one that types the string.
ARTIFACT_LITERALS = frozenset({"investigation.md", "report.md"})
ARTIFACT_CONSTS = frozenset({"INVESTIGATION_NAME", "REPORT_NAME"})

#: `RunPaths`' accessors for the same two files. Matched as bare attribute names because the
#: receiver is a VALUE — `RunPaths(run_dir).investigation` and `rp.investigation` are the same
#: write and only one of them has a resolvable origin.
ARTIFACT_ACCESSORS = frozenset({"investigation", "report"})

#: Resolved by ORIGIN through `_astlib.callee`, so `from defender._io import write_guarded as w`
#: is the same finding as the dotted spelling. This is the same primitive set
#: `lint_unguarded_tree_write` watches, for a different question: that gate asks whether the
#: write is alias-safe, this one asks whether its CONTENT met a schema. A write can pass one
#: and fail the other, which is why they are two gates and not one.
WRITE_CALLEES = frozenset({
    "defender._io.write_guarded",
    "defender._io.write_atomic",
    "defender._io.open_guarded",
    "defender._io.append_jsonl",
})

#: Duck-typed write shapes — no import to resolve, matched the way `lint_unguarded_tree_write`
#: matches them.
WRITE_METHODS = frozenset({"write_text", "write_bytes"})

#: Matched on the callee's LAST SEGMENT, not its origin, and that leniency is deliberate. The
#: close injects its schema as a PARAMETER (`validator: ArtifactValidator = validate_artifact`)
#: so the seam can be driven in tests; a parameter has no import and origin resolution cannot
#: see through it. Erring lenient here costs a false NEGATIVE — a function that calls something
#: incidentally named `validator` passes — which the baseline's review moment still catches,
#: where a false POSITIVE on the DI seam would train people to suppress the gate.
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
    # `callee` returns None for a call on a bare local name it cannot resolve to an import —
    # which is exactly the shape of the close's injected `validator(...)`. Read the name off
    # the node instead of treating the unresolved call as "not a validation".
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
    """Every node under `func` EXCEPT the bodies of nested functions.

    A nested def is its own frame and gets its own verdict from the outer walk in `_scan_file`,
    so folding its nodes into the enclosing function's would let an inner validation excuse an
    outer write (and the reverse). The nested def's own name still shows up in the fingerprint,
    which is what makes a finding inside one addressable."""
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
        # Fingerprint carries no line number, so moving the write within its function does not
        # read as a new finding — same convention as the sibling gates.
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
    """Findings under ``root``, fingerprints relative to it — so the gate is drivable on an
    injected tmp tree, not just the repo checkout."""
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
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Exit 2 — the
    # gate could not run, which is categorically not "clean".
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
