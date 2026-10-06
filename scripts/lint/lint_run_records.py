#!/usr/bin/env python3
"""Run-records name gate: no code outside the name-owner modules (every file of the runs
repository package `defender/run_repository/`, `defender/_episode_paths.py`,
`defender/_tenant.py`) may spell or hold a run or episode record's name, whole or as a
composed part, or join a name onto a run or episode root.

Three checks:

  (a) Literal pass, root-agnostic. Outside the owners, any string constant, f-string piece,
      or `glob`/`rglob` string argument that contains a whole record name or a composed part
      is a finding, as is any `BinOp(/)` whose right operand is such a string, whatever the
      left operand is called. `COMPOSED_PARTS` is narrow (five discriminating fragments): a
      generic suffix like `.json` or `.db` matches over a thousand unrelated literals. A name
      quoted in a message string is still a finding unless the line carries
      `# lint-run-records: ok — <reason>`.

  (b) Accessor-derived pass, using `_astlib.owner_derived` (shared with
      `lint_hand_rolled_name_resolution.py`): a join `/` onto a value traced
      back to an owner (`RunPaths(run_dir).gather_raw / lead_id`, invisible to (a)) is a
      finding; an accessor-named attribute read (`.gather_raw`, `.executed_queries`, ...) on
      a value the pass cannot trace is reported as `unresolvable accessor use`, never skipped.

  (c) Import pass: importing or reading a record-name constant off an owner module (see
      `_scan_import_pass`).

SCOPE_STATEMENT names what the gate cannot see: the trees it never enters, and a name
assembled so that no whole part is ever an AST literal.

A source file the sweep cannot parse is reported as a finding, never skipped and never a crash
of the whole sweep (`_astlib.ScanBlind` is caught per file).

Run from repo root:  python scripts/lint/lint_run_records.py [--render]
Exit 0 = clean and the page is up to date, 1 = findings or a stale render, 2 = could not run,
or the sweep's scope is not closed over this repo (a listed dir gone, or a defender/ dir holding
source that is neither swept nor in UNSCANNED_TREES).
"""
from __future__ import annotations

import ast
import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from _astlib import (
    PARTIAL_OWNER_ATTRS, ScanBlind, import_source, module_and_package, module_env, owner_derived,
    read_and_parse, require_claimed, require_selected, scan_guard, selects, source_files,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"
PAGE = DEFENDER / "docs" / "run-records.md"

BEGIN_MARK = "<!-- generated: run-records kinds table — edit run-records-kinds.tsv and run scripts/lint/lint_run_records.py --render -->"  # noqa: E501
END_MARK = "<!-- end generated -->"

#: The runs repository package's folder under `defender/`: every module in it is an owner
#: (#1105 D1.5, which absorbed the layout and the handle), read off disk, so a module the
#: package gains is an owner the day it lands rather than when a list is edited.
OWNER_PACKAGE = "run_repository"
#: The two owners outside the package.
_OWNER_FLAT_MODULES = ("_episode_paths.py", "_tenant.py")

#: The owner modules by their path under `defender/`, the exempt set everything below is
#: defined relative to. Matched by path, never by basename — a package submodule's basename
#: (`__init__.py`, `_handle.py`) would otherwise exempt every same-named file in the sweep.
#: Equals `defender.tests._spec1077.OWNER_MODULE_FILES`, which reads the same folder.
OWNER_MODULES: frozenset[str] = frozenset({
    *(f"{OWNER_PACKAGE}/{p.name}" for p in (DEFENDER / OWNER_PACKAGE).glob("*.py")),
    *_OWNER_FLAT_MODULES,
})

#: The sweep set. Never shrinks below this.
SWEEP_DIRS: tuple[str, ...] = ("runtime", "learning", "scripts", "evals", "hooks",
                               "run_repository", "api")
SWEEP_TOP_LEVEL = True
EXCLUDED_DIRS: tuple[str, ...] = (".venv", "__pycache__", "tests")

#: The trees this sweep never enters, each holding live record-name use; named so the gate
#: does not claim coverage it lacks.
UNSCANNED_TREES: tuple[str, ...] = ("defender/skills", "scripts", "experiments")

SCOPE_STATEMENT = (
    f"This gate sweeps {', '.join(f'defender/{d}' for d in SWEEP_DIRS)}"
    f"{' and the top level of defender/*.py' if SWEEP_TOP_LEVEL else ''} (tests excluded) — it "
    f"never enters {', '.join(t if '/' in t else f'top-level {t}' for t in UNSCANNED_TREES)} "
    "(§7 decision 5), and it is "
    "structurally blind to a record name that never reaches the AST as a whole literal — an "
    "assembly in which no single part is ever a literal string, whichever of concatenation, "
    "%-formatting, .format, os.path.join or multi-argument Path() does the assembling (§7 "
    "decision 6, settled premise s34). The same five forms carrying the name as ONE literal "
    "are caught."
)

APPENDIX_ONLY_KINDS = frozenset({"tool_seam"})

def _composed_parts() -> tuple[str, ...]:
    """The five discriminating composed-name parts, read from the owners' constants rather
    than re-spelled here: this file is not an owner module, and (a) protects these too."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from defender.run_repository import _layout  # noqa: PLC0415

    return (
        _layout.LEAD_CLAIM_SUFFIX, _layout.REVIEW_RECORD_PREFIX,
        _layout.TRACE_SUFFIX, _layout.REVIEW_TRACE_SUFFIX, _layout.SERVED_PREFIX)


#: The substring-match set for a composed name, kept narrow: generic bare suffixes (`.json`,
#: `.db`, ...) match over a thousand non-target literals.
COMPOSED_PARTS: tuple[str, ...] = _composed_parts()

#: A kinds-registry path segment enters the whole-name set only when discriminating — `name.ext`,
#: or multi-word like `wire_logs` / `.box-sentinel`. A bare English word (`runs`, `judge`,
#: `served`) would report every docstring and log line using it; such directories are reached
#: as composed parts or not at all.
_SEGMENT_PLACEHOLDER = re.compile(r"<[^>]*>")

#: The only inline escape, and only with a non-empty reason after the em dash.
_SUPPRESSION_MARKER = "lint-run-records: ok"


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    display: str


def sweep_files(root: Path = DEFENDER) -> list[Path]:
    """Every file the gate sweeps under `root`. Over this repo, ScanBlind when a swept dir
    selects no file, or when a directory holding source is neither swept nor named in
    `UNSCANNED_TREES` (`_astlib.require_selected` / `require_claimed`); a planted tree under
    test holds a subset on purpose."""
    rels = source_files(root, EXCLUDED_DIRS)
    swept = [f"{d}/" for d in SWEEP_DIRS]
    declared = [t.removeprefix("defender/") + "/" for t in UNSCANNED_TREES
                if t.startswith("defender/")]
    require_selected(root, DEFENDER, swept + declared, rels)
    require_claimed(root, DEFENDER, swept + declared, [rel for rel in rels if "/" in rel])
    return [root / rel for rel in rels
            if ("/" not in rel and SWEEP_TOP_LEVEL) or any(selects(d, rel) for d in swept)]


def _discriminating(segment: str) -> bool:
    stem, dot, ext = segment.rpartition(".")
    if dot and stem and ext:
        return True  # `alert.json`, `family.yaml`
    return any(c in segment for c in "_-")  # `wire_logs`, `gather_raw`, `.box-sentinel`


def registry_names(kinds: list[dict[str, str]] | None = None) -> frozenset[str]:
    """The whole record names the gate bans, read from the kinds registry
    (`run-records-kinds.tsv`) rather than the owner modules' namespaces: every discriminating
    whole segment of every kind's `path` cell. A segment with a placeholder
    (`<lead>.lead.json`) is a composition, contributing only its discriminating fragments."""
    kinds = kinds if kinds is not None else load_kinds()
    names: set[str] = set()
    for row in kinds:
        for spelled in row.get("path", "").split(","):
            spelled = spelled.strip()
            if not spelled or spelled.startswith("("):
                continue  # `(the role's declared read/write targets)` — not a path
            for segment in spelled.split("/"):
                if _SEGMENT_PLACEHOLDER.search(segment):
                    # A composed segment is not a whole name; its literal head and tail are
                    # what a spelling outside the owner would carry, admitted when
                    # file-name-shaped and discriminating (`.run-end.json`, never `.json`).
                    # `COMPOSED_PARTS` is a subset of what this yields.
                    head = segment[:segment.index("<")]
                    tail = segment[segment.rindex(">") + 1:]
                    for fragment in (head, tail):
                        if "." in fragment and _discriminating(fragment):
                            names.add(fragment)
                    continue
                if _discriminating(segment):
                    names.add(segment)
    return frozenset(names)


def _owner_constants() -> tuple[frozenset[str], frozenset[str]]:
    """`(whole_names, composed_parts)`."""
    return registry_names(), frozenset(COMPOSED_PARTS)


def _accessor_names() -> frozenset[str]:
    """Every public accessor name on the path owners (`RunPaths`, `SessionPaths`,
    `EpisodePaths`), computed so it never goes stale, plus the members a partial owner owns
    (`_astlib.PARTIAL_OWNER_ATTRS`: an accepted `Tenant`'s record locations, never its
    knowledge halves). A new owner class needs a line here and in
    `_astlib._OWNER_CLASS_ORIGINS`."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from defender._episode_paths import EpisodePaths  # noqa: PLC0415
    from defender.run_repository import RunPaths, SessionPaths  # noqa: PLC0415

    partial = (name for owned in PARTIAL_OWNER_ATTRS.values() for name in owned)
    return frozenset(
        n for n in (*dir(RunPaths), *dir(SessionPaths), *dir(EpisodePaths), *partial)
        if not n.startswith("_"))


def _is_owner_module(rel: str) -> bool:
    return rel.startswith(f"{OWNER_PACKAGE}/") or rel in _OWNER_FLAT_MODULES


def _record_shaped(text: str, whole: frozenset[str], parts: frozenset[str]) -> bool:
    return any(name in text for name in whole) or any(part in text for part in parts)


def _suppressed(lineno: int, lines: list[str]) -> bool:
    if not (0 < lineno <= len(lines)):
        return False
    line = lines[lineno - 1]
    if _SUPPRESSION_MARKER not in line:
        return False
    after = line.split(_SUPPRESSION_MARKER, 1)[1]
        # A bare marker, or one with nothing after the em dash, does not suppress.
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

    docstrings = _docstring_nodes(tree)
    # A constant that is a piece of something reported as a whole (an f-string's literal part,
    # a join's right operand) is reported once, at the whole.
    covered: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            covered.update(node.values)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            # Only a constant right operand is the join's to report; an f-string there is
            # reported as the f-string piece, so it must not be covered twice into silence.
            if isinstance(node.right, ast.Constant):
                covered.add(node.right)
    for node in ast.walk(tree):
        if node in covered:
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # A docstring describes a record; it cannot reach the filesystem. Reporting it
            # would only teach docstrings to spell names in pieces. A name quoted in a
            # message (an argument, not a statement) is still reported.
            if node in docstrings:
                continue
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
    module, package = module_and_package(rel)
    env = module_env(tree, module=module, package=package)

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
            # Reported only when the name is discriminating, i.e. one only an owner answers:
            # `x.wire_log` on an unknown `x` is a record reached around the owner, while
            # `args.alert` or `self.budget` merely share an English word with an accessor
            # (their spelled names would be caught by pass (a)).
            if not owner_derived(node, env) and _discriminating(node.attr):
                report(node, f"unresolvable accessor use (.{node.attr})")
    return findings


def _docstring_nodes(tree: ast.Module) -> set[ast.AST]:
    """The `ast.Constant` of every bare-string statement (docstrings, attribute docs). A
    whole-statement string is prose: no expression consumes it, so it reaches no path."""
    out: set[ast.AST] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            out.add(node.value)
    return out


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


#: The owner modules' non-record exports, which a swept module may import. Everything else an
#: owner binds at module level is a record name, and importing one is refused.
#:
#: An allow-list because the deny side is what grows: a new record is refused by default, and a
#: new non-record export is a deliberate line here.
_OWNER_NON_RECORD_EXPORTS: frozenset[str] = frozenset({
    # The handles and their layout views.
    "RunPaths", "RunLayout", "RUN_LAYOUT", "WireLogNames", "WIRE_LOG_NAMES",
    "EpisodePaths", "EpisodeLayout", "LAYOUT", "WorldPaths", "WorldLayout",
    "ArchivedWorldLeaves", "WORLD_LEAVES", "Run", "RunRecord",
    # Entry screens, which take a path and answer about the entry, never a name.
    "artifact_file", "artifact_dir", "plain_file", "contained_payload", "entry_present",
    # Not record names: an id shape, a regex body, a read-grant shape, a metadata key on a
    # tool-return part, a refusal sentence, and the tenant vocabulary.
    "LEAD_ID_RE", "LEAD_ID_BODY", "GATHER_RAW_SHAPE", "GATE_METADATA_KEY",
    "ALIAS_READ_REFUSAL", "CASE_STABLE_REQUIRED",
    "TENANT_RECORD_NAME",
})

#: The owner modules' dotted names (`defender.run_repository`, `defender._tenant`, ...): arm
#: (c) matches an import's fully resolved module against these, so an unrelated module that
#: shares a last segment (`defender.learning._errors`) is not an owner.
_OWNER_MODULE_NAMES: frozenset[str] = frozenset(
    "defender." + m.removesuffix(".py").removesuffix("/__init__").replace("/", ".")
    for m in OWNER_MODULES)


def _owner_record_names() -> frozenset[str]:
    """Every name an owner module binds to a string at module level, minus the non-record
    exports above — computed by importing the owners, so a new record is protected the day
    it lands. Non-string bindings are not record names.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import importlib  # noqa: PLC0415

    names: set[str] = set()
    for mod_name in sorted(_OWNER_MODULE_NAMES):
        mod = importlib.import_module(mod_name)
        names |= {
            n for n, v in vars(mod).items()
            if isinstance(v, str) and not n.startswith("_")
            and n not in _OWNER_NON_RECORD_EXPORTS
        }
    return frozenset(names)


#: The names the import arm refuses, read off the owners themselves.
OWNER_RECORD_NAMES: frozenset[str] = _owner_record_names()


def _scan_import_pass(rel: str, tree: ast.Module, lines: list[str]) -> list[Finding]:
    """(c) No module outside the owners may hold a record name.

    Banning spelling alone is too loose: a module that imports a record-name constant and
    joins it onto a run dir spells nothing pass (a) sees and carries no owner value pass (b)
    traces. And an alias outlives its home, so when the owner stops exporting a name every
    re-binder breaks at import.

    Three fixed shapes, checkable without dataflow:

      * `from <owner> import NAME` — the name a consumer binds.
      * `<owner_alias>.NAME` — an attribute read on an owner imported whole.
      * a re-export of either under `__all__`.
    """
    findings: list[Finding] = []
    owner = _enclosing(tree)
    whole_module_aliases: dict[str, str] = {}

    def report(node: ast.AST, name: str, why: str) -> None:
        lineno = getattr(node, "lineno", 0)
        if _suppressed(lineno, lines):
            return
        fn = owner.get(node, "<module>")
        findings.append(Finding(
            fingerprint=f"{rel}::{fn}::{lineno}::holds record name ({name})",
            display=f"{rel}:{lineno} {fn}(): {why} — nothing outside the owner modules may "
                     f"HOLD a record name; ask the owner for the path or its relative form",
        ))

    _module, package = module_and_package(rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = import_source(node, package)
            # `from defender import _episode_paths` binds the module, not a name in it; record
            # it as well as `import x.y`, or the attribute arm below never sees it.
            for alias in node.names:
                if f"{module}.{alias.name}" in _OWNER_MODULE_NAMES:
                    whole_module_aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
            if module not in _OWNER_MODULE_NAMES:
                continue
            for alias in node.names:
                if alias.name not in OWNER_RECORD_NAMES:
                    continue
                report(node, alias.name,
                       f"imports the record name {alias.name!r} from an owner module")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _OWNER_MODULE_NAMES:
                    whole_module_aliases[alias.asname or alias.name.split(".")[-1]] = alias.name

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in whole_module_aliases
            and node.attr in OWNER_RECORD_NAMES
        ):
            report(node, node.attr,
                   f"reads the record name {node.attr!r} off an owner module")
    return findings


def scan(root: Path = DEFENDER, *, allow_list: dict[str, int] | None = None) -> list[Finding]:
    """The gate's whole sweep over every file `sweep_files` names, minus those `allow_list`
    admits (skipped entirely).

    A file the sweep cannot parse is a finding: the scan continues, but that file is
    reported, not certified clean.
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
            lines = text.splitlines()
            with scan_guard(rel):
                found = [*_scan_literal_pass(rel, tree, lines, whole, parts),
                         *_scan_accessor_pass(rel, tree, lines, accessor_names),
                         *_scan_import_pass(rel, tree, lines)]
        except ScanBlind as exc:
            findings.append(Finding(fingerprint=f"{rel}::<unparseable>",
                                    display=f"{rel}: {exc}"))
            continue
        findings.extend(found)
    return findings


#: Migration-in-flight mechanism: a module named here (relative to `DEFENDER`, as
#: `sweep_files` spells it) is skipped by `scan` entirely. The terminal state is empty;
#: `test_gate_passes_with_an_empty_allow_list` pins that.
ALLOW_LIST: dict[str, int] = {}


# ---------------------------------------------------------------------------------------
# the render — the kinds table only
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
    try:
        found = scan()  # before any render: a blind run writes nothing
    except ScanBlind as exc:
        print(f"[lint_run_records] {exc}", file=sys.stderr)
        return 2
    if "--render" in args:
        PAGE.write_text(rendered, encoding="utf-8")
        print(f"[lint_run_records] rendered -> {PAGE.relative_to(REPO_ROOT)}")
        page = rendered
    if found:
        print(f"\n[lint_run_records] {len(found)} finding(s):")
        for f in found:
            print(f"  {f.display}")
        print(
            "\nNo code outside defender/run_repository/, _episode_paths.py and _tenant.py "
            "may spell a run or episode record's name — reach it through the "
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
