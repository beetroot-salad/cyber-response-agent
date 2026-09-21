#!/usr/bin/env python3
"""Run-records name gate (#1077 D6) — no code outside the four name-owner modules
(`defender/_run_paths.py`, `defender/_episode_paths.py`, `defender/_tenant.py`,
`defender/_run_handle.py`) may spell a run or episode record's name, whole or as a composed
part, and no code outside them may join a name onto a run or episode root.

#1076's call-site census (`run-records.tsv`, the old `scan()`/`findings()` over "every file
access call, attributed to a kind") retired with this rewrite: it proved page == table, never
table == tree, and could never see a subprocess writing a file or a SQL statement on an open
connection. This gate proves something narrower and checkable instead — TWO name-keyed checks:

  (a) NEGATIVE, root-agnostic, literal pass. Outside the owner modules, any `ast.Constant`
      string, any `ast.JoinedStr` piece, or any `glob`/`rglob` call's string argument that
      CONTAINS a whole record name or a composed PART from the owners' own constant set is a
      finding — and any `BinOp(/)` whose RIGHT operand is such a string is a finding whatever
      the left operand is called (`child`, `dst_dir`, `source`, ... — no identifier list to
      guess). The composed-part set is deliberately narrow (`COMPOSED_PARTS`, five
      DISCRIMINATING fragments): a bare generic suffix (`.json`, `.db`) alone matches ~1065
      non-target literals in this tree and would make the check unimplementable (§7 decision
      6, fork D-F5). A quoted name inside a message string is still a finding unless the line
      carries the inline `# lint-run-records: ok — <reason>` suppression.

  (b) An ACCESSOR-DERIVED pass, using `_astlib.owner_derived` (shared with
      `lint_hand_rolled_name_resolution.py`): a join `/` onto a value the pass traces back to
      an owner (`RunPaths(run_dir).gather_raw / lead_id`, which carries no literal and is
      therefore invisible to (a)) is a finding; an accessor-NAMED attribute read
      (`.gather_raw`, `.executed_queries`, ...) on a value the pass cannot trace is reported as
      `unresolvable accessor use` — never a skip.

SCOPE_STATEMENT names what this gate does not (and structurally cannot) see: the three trees it
never enters, and the one composition class — a name assembled so that NO WHOLE PART is ever an
AST literal — that (a) is blind to regardless of which of the five ordinary composition idioms
(concatenation, `%`-formatting, `.format`, `os.path.join`, multi-arg `Path()`) does the
assembling; carrying the name as ONE literal, in any of those five forms, IS still caught.

A source file the sweep cannot parse is reported as a finding, never skipped and never a crash
of the whole sweep (`_astlib.ScanBlind` is caught per file, here, not allowed to propagate).

Run from repo root:  python scripts/lint/lint_run_records.py [--render]
Exit 0 = clean and the page is up to date, 1 = findings or a stale render, 2 = could not run.
"""
from __future__ import annotations

import ast
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

from _astlib import ScanBlind, module_env, owner_derived, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"
PAGE = DEFENDER / "docs" / "run-records.md"

BEGIN_MARK = "<!-- generated: run-records kinds table — edit run-records-kinds.tsv and run scripts/lint/lint_run_records.py --render -->"  # noqa: E501
END_MARK = "<!-- end generated -->"

#: The four owner modules (#1077 D1/D5) — the exempt set every other constant and check below
#: is defined relative to. Exactly `defender.tests._spec1077.OWNER_MODULE_FILES`.
OWNER_MODULES: frozenset[str] = frozenset(
    {"_run_paths.py", "_episode_paths.py", "_tenant.py", "_run_handle.py"})

#: The sweep set — unchanged from #1076, plus the top level of `defender/`. Never shrinks
#: below this (decision 5's standing check).
SWEEP_DIRS: tuple[str, ...] = ("runtime", "learning", "scripts", "evals", "hooks")
SWEEP_TOP_LEVEL = True
EXCLUDED_DIRS: tuple[str, ...] = (".venv", "__pycache__", "tests", "run-visualizations", "run-transcripts")

#: §7 decision 5's carve-out: the three trees this sweep never enters, each holding live
#: record-name use today (claims S10/G1/G3, brief red flag R3). The written obligation (O1)
#: names them rather than claiming a coverage it does not have.
UNSCANNED_TREES: tuple[str, ...] = ("defender/skills", "scripts", "experiments")

SCOPE_STATEMENT = (
    "This gate sweeps defender/runtime, defender/learning, defender/scripts, defender/evals, "
    "defender/hooks and the top level of defender/*.py (tests excluded) — it never enters "
    "defender/skills, top-level scripts, or top-level experiments (§7 decision 5), and it is "
    "structurally blind to a record name that never reaches the AST as a whole literal — an "
    "assembly in which no single part is ever a literal string, whichever of concatenation, "
    "%-formatting, .format, os.path.join or multi-argument Path() does the assembling (§7 "
    "decision 6, settled premise s34). The same five forms carrying the name as ONE literal "
    "are caught."
)

APPENDIX_ONLY_KINDS = frozenset({"tool_seam"})

def _composed_parts() -> tuple[str, ...]:
    """The five DISCRIMINATING composed-name PARTS (§7 decision 6 / fork D-F5, reading 1),
    READ from the owners' own constants rather than re-spelled here — this gate's own source
    is not an exempt owner module, and D6(a) protects these five fragments too."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from defender import _run_paths  # noqa: PLC0415

    return (
        _run_paths.LEAD_CLAIM_SUFFIX, _run_paths.REVIEW_RECORD_PREFIX,
        _run_paths.TRACE_SUFFIX, _run_paths.REVIEW_TRACE_SUFFIX, _run_paths.SERVED_PREFIX)


#: The gate's substring-match set for a composed name, kept narrow on purpose: the generic bare
#: suffixes (`.json`, `.db`, ...) match ~1065 non-target literals and are deliberately excluded.
COMPOSED_PARTS: tuple[str, ...] = _composed_parts()

#: Owner constants equal to one of these are too generic to enter the WHOLE-NAME match set —
#: the same reading decision 6 applies to `COMPOSED_PARTS`, extended to whole-constant values.
_GENERIC_WHOLE = frozenset({".json", ".db", ".jsonl", ".md", ".yaml", "json"})

#: Owner constants that are NOT record names at all (a wire-body metadata key, not a filename)
#: — named by their own constant NAME so a short, generic value like `"json"` cannot leak into
#: the match set through them.
_NON_RECORD_CONSTANT_NAMES = frozenset({"GATE_METADATA_KEY"})

#: The inline escape — the ONLY one D6(a) admits, and only with a non-empty reason after the
#: em dash.
_SUPPRESSION_MARKER = "lint-run-records: ok"


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    display: str


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def sweep_files(root: Path = DEFENDER) -> list[Path]:
    files: list[Path] = []
    if SWEEP_TOP_LEVEL:
        files.extend(p for p in root.glob("*.py") if _in_scope(p))
    for d in SWEEP_DIRS:
        files.extend(p for p in sorted((root / d).rglob("*.py")) if _in_scope(p))
    return sorted(files)


def _owner_constants() -> tuple[frozenset[str], frozenset[str]]:
    """`(whole_names, composed_parts)` — the owners' own string constants, split the way
    decision 6 splits them: every UPPERCASE module-level string EXCEPT the too-generic bare
    suffixes, and the five curated fragments."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from defender import _episode_paths, _run_paths, _tenant  # noqa: PLC0415

    whole: set[str] = set()
    for mod in (_run_paths, _episode_paths, _tenant):
        for k, v in vars(mod).items():
            if (
                k.isupper() and isinstance(v, str) and v not in _GENERIC_WHOLE
                and k not in _NON_RECORD_CONSTANT_NAMES
            ):
                whole.add(v)
    return frozenset(whole), frozenset(COMPOSED_PARTS)


def _accessor_names() -> frozenset[str]:
    """Every public accessor name on `RunPaths`/`EpisodePaths` — computed, not typed out, so
    it never goes stale as D1 grows the owners."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from defender._episode_paths import EpisodePaths  # noqa: PLC0415
    from defender._run_paths import RunPaths  # noqa: PLC0415

    return frozenset(
        n for n in (*dir(RunPaths), *dir(EpisodePaths)) if not n.startswith("_"))


def _is_owner_module(rel: str) -> bool:
    return Path(rel).name in OWNER_MODULES


def _record_shaped(text: str, whole: frozenset[str], parts: frozenset[str]) -> bool:
    return any(name in text for name in whole) or any(part in text for part in parts)


def _suppressed(lineno: int, lines: list[str]) -> bool:
    if not (0 < lineno <= len(lines)):
        return False
    line = lines[lineno - 1]
    if _SUPPRESSION_MARKER not in line:
        return False
    after = line.split(_SUPPRESSION_MARKER, 1)[1]
    # The escape requires a REASON after the marker's own `— <reason>` em dash — a bare
    # marker, or one with nothing following the dash, does not suppress.
    reason = after.split("—", 1)[1].strip() if "—" in after else ""
    return bool(reason)


def _glob_call_names(node: ast.Call) -> list[str]:
    if not (isinstance(node.func, ast.Attribute) and node.func.attr in ("glob", "rglob")):
        return []
    return [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]


def _scan_literal_pass(
    rel: str, tree: ast.Module, lines: list[str],
    whole: frozenset[str], parts: frozenset[str],
) -> list[Finding]:
    findings: list[Finding] = []
    owner = _enclosing(tree)

    def report(node: ast.AST, why: str) -> None:
        lineno = getattr(node, "lineno", 0)
        if _suppressed(lineno, lines):
            return
        fn = owner.get(node, "<module>")
        findings.append(Finding(
            fingerprint=f"{rel}::{fn}::{lineno}::{why}",
            display=f"{rel}:{lineno} {fn}(): {why} — no code outside the owner modules may "
                     "spell a run or episode record's name",
        ))

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _record_shaped(node.value, whole, parts):
                report(node, f"record-name literal {node.value!r}")
        elif isinstance(node, ast.JoinedStr):
            for piece in node.values:
                if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                    if _record_shaped(piece.value, whole, parts):
                        report(node, f"record-name f-string piece {piece.value!r}")
        elif isinstance(node, ast.Call):
            for value in _glob_call_names(node):
                if _record_shaped(value, whole, parts):
                    report(node, f"record-name glob argument {value!r}")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            right = node.right
            if isinstance(right, ast.Constant) and isinstance(right.value, str):
                if _record_shaped(right.value, whole, parts):
                    report(node, f"join onto record name {right.value!r} (right operand)")
    return findings


def _scan_accessor_pass(rel: str, tree: ast.Module, lines: list[str],
                        accessor_names: frozenset[str]) -> list[Finding]:
    findings: list[Finding] = []
    owner = _enclosing(tree)
    env = module_env(tree)

    def report(node: ast.AST, why: str) -> None:
        lineno = getattr(node, "lineno", 0)
        if _suppressed(lineno, lines):
            return
        fn = owner.get(node, "<module>")
        findings.append(Finding(
            fingerprint=f"{rel}::{fn}::{lineno}::{why}",
            display=f"{rel}:{lineno} {fn}(): {why}",
        ))

    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if owner_derived(node.left, env):
                report(node, "literal-free join onto an owner-derived value")
        elif isinstance(node, ast.Attribute) and node.attr in accessor_names:
            if not owner_derived(node, env):
                report(node, f"unresolvable accessor use (.{node.attr})")
    return findings


def _enclosing(tree: ast.Module) -> dict[ast.AST, str]:
    names: dict[ast.AST, str] = {}

    def walk(node: ast.AST, fn: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = node.name
        for child in ast.iter_child_nodes(node):
            names[child] = fn
            walk(child, fn)

    walk(tree, "<module>")
    return names


def scan(root: Path = DEFENDER, *, allow_list: dict[str, int] | None = None) -> list[Finding]:
    """The gate's whole sweep: checks (a) and (b), over every file `sweep_files` names minus
    the ones an `allow_list` entry admits (D7's migration-in-flight mechanism — a module named
    there is skipped entirely, however many findings it would otherwise carry).

    A file the sweep cannot parse is a FINDING (`unresolvable accessor use` never a skip): the
    scan continues to the rest of the tree, but this one file is reported, not certified clean.
    """
    allow_list = allow_list if allow_list is not None else ALLOW_LIST
    whole, parts = _owner_constants()
    accessor_names = _accessor_names()
    findings: list[Finding] = []
    for path in sweep_files(root):
        rel = path.relative_to(root).as_posix()
        if _is_owner_module(rel) or rel in allow_list:
            continue
        try:
            text, tree = read_and_parse(path, rel)
        except ScanBlind as exc:
            findings.append(Finding(fingerprint=f"{rel}::<unparseable>",
                                    display=f"{rel}: {exc}"))
            continue
        lines = text.splitlines()
        findings.extend(_scan_literal_pass(rel, tree, lines, whole, parts))
        findings.extend(_scan_accessor_pass(rel, tree, lines, accessor_names))
    return findings


#: D7's migration-in-flight mechanism: a module named here (relative to `DEFENDER`, as
#: `sweep_files` spells it) is skipped by `scan` entirely, however many findings it would
#: otherwise carry — the observable shape of a mixed-route intermediate state. The terminal
#: state (D7 step 4) is an EMPTY dict; `test_gate_passes_with_an_empty_allow_list` is the one
#: demand that cannot be green at any earlier commit (cluster O).
ALLOW_LIST: dict[str, int] = {}


# ---------------------------------------------------------------------------------------
# the render — the kinds table only (N6: no reader/writer census, no site data)
# ---------------------------------------------------------------------------------------

def load_kinds(path: Path = KINDS_TSV) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def render(kinds: list[dict[str, str]]) -> str:
    out: list[str] = [BEGIN_MARK, "", "| kind | table | path | denied to | archived as | sub-collection | note |",
                      "|---|---|---|---|---|---|---|"]
    for k in kinds:
        cells = [k["kind"], k.get("table", ""), f"`{k['path']}`", k.get("deny") or "—",
                 k.get("archived_as") or "—", k.get("subcollection") or "—",
                 (k.get("note") or "").replace("|", "\\|")]
        out.append("| " + " | ".join(cells) + " |")
    out += ["", END_MARK]
    return "\n".join(out)


def render_page(kinds: list[dict[str, str]], page_text: str) -> str:
    start = page_text.index(BEGIN_MARK)
    end = page_text.index(END_MARK) + len(END_MARK)
    return page_text[:start] + render(kinds) + page_text[end:]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    kinds = load_kinds()
    page = PAGE.read_text(encoding="utf-8")
    rendered = render_page(kinds, page)
    if "--render" in args:
        PAGE.write_text(rendered, encoding="utf-8")
        print(f"[lint_run_records] rendered -> {PAGE.relative_to(REPO_ROOT)}")
        page = rendered
    found = scan()
    if found:
        print(f"\n[lint_run_records] {len(found)} finding(s):")
        for f in found:
            print(f"  {f.display}")
        print(
            "\nNo code outside defender/_run_paths.py, _episode_paths.py, _tenant.py and "
            "_run_handle.py may spell a run or episode record's name — reach it through the "
            "owner, or mark a deliberate diagnostic with "
            "`# lint-run-records: ok — <reason>`."
        )
    if page != rendered:
        print(
            "\n[lint_run_records] STALE RENDER: docs/run-records.md differs from its table — "
            "run `python scripts/lint/lint_run_records.py --render` and commit.")
    print(f"[lint_run_records] {len(found)} finding(s).")
    return 1 if (found or page != rendered) else 0


if __name__ == "__main__":
    sys.exit(main())
