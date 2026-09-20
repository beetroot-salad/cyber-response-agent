#!/usr/bin/env python3
"""Run-records inventory gate (#1076) — the page is a RENDER of a checked-in attribution
table, and the table is held against the tree.

Why a gate and not a page. The first version of `defender/docs/run-records.md` was written by
hand from a grep for filename mentions, and its cold review found a third of the table cells
wrong: the citation pointed at the constant that spells a name, the docstring that explains it,
or the message that quotes it, never at the call that reads or writes. The appendix of the same
page — built by opening every call site — had no drift. Two sources for one fact is where every
contradiction came from, so this gate keeps ONE source:

  defender/docs/run-records.tsv        one row per file-access CALL SITE: path, line, kind,
                                       op, function, when, note
  defender/docs/run-records-kinds.tsv  one row per record KIND: the static columns a call
                                       site cannot carry (path pattern, table, deny mode,
                                       archived-as, sub-collection)

and derives the page's tables 1–4 and 7 from them (`--render`). Three things are checked:

  1. UNATTRIBUTED SITE — a file-access call in the sweep set with no row. The sites are found
     by AST, resolved through `_astlib.callee` (so `from shutil import copy2 as cp` still
     counts and a docstring that says "open(" never does): `builtins.open`, `os.open`,
     `json.load`/`json.dump`, `shutil.copy*`/`copytree`, every `defender._io` reader/writer,
     and the duck-typed `.open/.read_text/.write_text/.read_bytes/.write_bytes` on a value.
     Fingerprint: `path::function::callee` — no line number, so an edit above the call does
     not churn the baseline.
  2. STALE ROW — a row whose `path::function` no longer holds any such call. Same fingerprint
     shape.
  3. STALE RENDER — the page's generated block differs from what the two tables render to.
     Never baselined: run `--render` and commit.

Line numbers in the TSV are for the reader, not the gate: `--refresh` re-resolves each row's
line to the call it names (matching by path, function and op class) and rewrites the file, so
the page can be regenerated after any edit without re-attributing anything.

Once #1077's handle owns every path, this gate's job collapses into "no module outside the
handle builds a run path" and the tables retire with the doc; the TSV is the seed of the file
backend until then.

Run from repo root:  python scripts/lint/lint_run_records.py [--refresh] [--render]
Regenerate the baseline:  python scripts/lint/lint_run_records.py --update-baseline
Exit 0 = clean, 1 = new findings or stale render, 2 = could not run.
"""
from __future__ import annotations

import ast
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from _astlib import ScanBlind, callee, module_env, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_run_records_baseline.json")
SITES_TSV = DEFENDER / "docs" / "run-records.tsv"
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"
PAGE = DEFENDER / "docs" / "run-records.md"

BEGIN_MARK = "<!-- generated: run-records tables — edit run-records.tsv / run-records-kinds.tsv and run scripts/lint/lint_run_records.py --render -->"
END_MARK = "<!-- end generated -->"

#: The sweep set the issue names, plus the writers that live outside it (hooks and the
#: top-level entry modules). Tests excluded.
SWEEP_DIRS = ("runtime", "learning", "scripts", "evals", "hooks")
EXCLUDED_DIRS = (".venv", "__pycache__", "tests", "run-visualizations", "run-transcripts")

#: Resolved callees that touch a file, with the op class each implies. `callee()` answers the
#: ORIGIN, so an alias or a from-import lands on the same key.
CALLEES: dict[str, str] = {
    "builtins.open": "open",
    "os.open": "open",
    "json.load": "read",
    "json.dump": "write",
    "shutil.copy": "copy",
    "shutil.copy2": "copy",
    "shutil.copyfile": "copy",
    "shutil.copytree": "copy",
    "defender._io.read_text_utf8": "read",
    "defender._io.read_text_soft": "read",
    "defender._io.read_guarded": "read",
    "defender._io.read_plain": "read",
    "defender._io.read_jsonl_rows": "read",
    "defender._io.read_jsonl_rows_report": "read",
    "defender._io.append_jsonl": "write",
    "defender._io.write_atomic": "write",
    "defender._io.write_guarded": "write",
    "defender._io.open_guarded": "open",
    "defender._io.locked_for_rewrite": "open",
    "defender._io.open_nofollow_fd": "open",
    "defender._io.guarded_mkdir": "write",
    "sqlite3.connect": "open",
}
#: Duck-typed attribute calls on a value (`p.read_text()`): `callee()` is None there by
#: design, so the attribute NAME is the key.
DUCK_ATTRS: dict[str, str] = {
    "open": "open",
    "read_text": "read",
    "write_text": "write",
    "read_bytes": "read",
    "write_bytes": "write",
}
WRITE_OPS = frozenset({"write", "append", "copy", "mkdir", "unlink"})
#: `names`: not a call — the one line that MINTS a record's filename for a shared writer seam
#: (a stage's `trace_name`, a ledger's file name). Rendered as evidence, never checked against
#: the sweep, and never the only row a kind may have if a real call exists.
NAMES_OP = "names"
WHEN_ORDER = ("host", "live", "end")
WHEN_ALIASES = {"host-before-agent": "host", "n-a": ""}

SUPPRESS = "lint-run-records: ok"

HEADER = (
    "Baseline for scripts/lint/lint_run_records.py: file-access call sites with no row in "
    "defender/docs/run-records.tsv, and rows naming a call that is gone. Regenerate with "
    "--update-baseline; attribute the site instead wherever possible."
)


@dataclass(frozen=True)
class Site:
    path: str        # relative to defender/
    line: int
    function: str    # innermost enclosing def, or <module>
    what: str        # resolved callee or `.attr`
    opclass: str     # open / read / write / copy

    @property
    def key(self) -> str:
        return f"{self.path}::{self.function}"


@dataclass
class Row:
    path: str
    line: int
    kind: str
    op: str
    function: str
    when: str
    note: str

    @property
    def key(self) -> str:
        return f"{self.path}::{self.function}"

    @property
    def opclass(self) -> str:
        return "write" if self.op in WRITE_OPS else "read"


# ---------------------------------------------------------------------------------------
# the sweep
# ---------------------------------------------------------------------------------------

def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def sweep_files(root: Path = DEFENDER) -> list[Path]:
    files = [p for p in root.glob("*.py") if _in_scope(p)]
    for d in SWEEP_DIRS:
        files.extend(p for p in sorted((root / d).rglob("*.py")) if _in_scope(p))
    return sorted(files)


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


def scan_file(path: Path, rel: str) -> list[Site]:
    text, tree = read_and_parse(path, rel)
    lines = text.splitlines()
    env = module_env(tree)
    owner = _enclosing(tree)
    out: list[Site] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        origin = callee(node, env)
        what, opclass = None, None
        if origin in CALLEES:
            what, opclass = origin, CALLEES[origin]
        elif origin is None and isinstance(node.func, ast.Attribute) and node.func.attr in DUCK_ATTRS:
            what, opclass = f".{node.func.attr}", DUCK_ATTRS[node.func.attr]
        if what is None:
            continue
        line = lines[node.lineno - 1] if node.lineno - 1 < len(lines) else ""
        if SUPPRESS in line:
            continue
        out.append(Site(rel, node.lineno, owner.get(node, "<module>"), what, opclass))
    return out


def scan(root: Path = DEFENDER) -> list[Site]:
    sites: list[Site] = []
    for path in sweep_files(root):
        rel = path.relative_to(root).as_posix()
        sites.extend(scan_file(path, rel))
    return sites


# ---------------------------------------------------------------------------------------
# the tables
# ---------------------------------------------------------------------------------------

def load_rows(path: Path = SITES_TSV) -> list[Row]:
    with path.open(encoding="utf-8", newline="") as fh:
        return [
            Row(r["path"], int(r["line"]), r["kind"], r["op"], r["function"], r["when"], r["note"])
            for r in csv.DictReader(fh, delimiter="\t")
        ]


def save_rows(rows: list[Row], path: Path = SITES_TSV) -> None:
    rows = sorted(rows, key=lambda r: (r.path, r.line, r.kind))
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(["path", "line", "kind", "op", "function", "when", "note"])
        for r in rows:
            w.writerow([r.path, r.line, r.kind, r.op, r.function, r.when, r.note])


def load_kinds(path: Path = KINDS_TSV) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def refresh_lines(rows: list[Row], sites: list[Site]) -> int:
    """Re-point each row's line at the call it names. Rows in one function with one op
    class are matched to that function's sites of the same class in line order, so two
    reads in one function keep their relative order and a moved function moves them all."""
    by_key: dict[str, list[Site]] = defaultdict(list)
    for s in sites:
        by_key[s.key].append(s)
    grouped: dict[tuple[str, str], list[Row]] = defaultdict(list)
    for r in rows:
        grouped[(r.key, r.opclass)].append(r)
    changed = 0
    for (key, opclass), rs in grouped.items():
        cands = sorted(
            (s for s in by_key.get(key, ()) if (s.opclass in WRITE_OPS or s.opclass == "write") == (opclass == "write") or s.opclass == "open"),
            key=lambda s: s.line,
        )
        for r, s in zip(sorted(rs, key=lambda r: r.line), cands):
            if r.line != s.line:
                r.line = s.line
                changed += 1
    return changed


# ---------------------------------------------------------------------------------------
# the render
# ---------------------------------------------------------------------------------------

def _pkg(path: str) -> str:
    head = path.split("/", 1)[0]
    return head if "/" in path else "top"


def _cite(r: Row) -> str:
    tag = " names it" if r.op == NAMES_OP else ""
    return f"`{r.function}` (`{r.path}:{r.line}`){tag}"


def _cell(rows: list[Row]) -> str:
    if not rows:
        return "—"
    by_pkg: dict[str, list[Row]] = defaultdict(list)
    for r in sorted(rows, key=lambda r: (r.path, r.line)):
        by_pkg[_pkg(r.path)].append(r)
    return "; ".join(f"**{p}**: " + ", ".join(_cite(r) for r in rs) for p, rs in by_pkg.items())


def _when(rows: list[Row]) -> str:
    seen = {WHEN_ALIASES.get(r.when, r.when) for r in rows}
    return " + ".join(w for w in WHEN_ORDER if w in seen) or "—"


def _esc(s: str) -> str:
    return s.replace("|", "\\|")


def render(rows: list[Row], kinds: list[dict[str, str]]) -> str:
    by_kind: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        by_kind[r.kind].append(r)
    facts: dict[str, dict[str, object]] = {}
    for k in kinds:
        rs = by_kind.get(k["kind"], [])
        writers = [r for r in rs if r.op in WRITE_OPS or r.op == NAMES_OP]
        readers = [r for r in rs if r.op in ("read", "open")]  # an `open` is access either way
        pkgs = {_pkg(r.path) for r in rs}
        # The archive copy is a READER of every kind it carries (its call sites are tagged
        # `archive_proj`, section 5), and a record read only through a top-level helper is
        # read by that helper's callers: `via` names them, since the sweep sees the innermost
        # call only.
        if k["archived_as"] not in ("", "—"):
            pkgs.add("learning")
        if k.get("via"):
            pkgs.add("via")
        facts[k["kind"]] = {
            "writers": writers, "readers": readers,
            "crosses": "yes" if len(pkgs) > 1 else "no",
            "when": _when(writers),
        }
    out: list[str] = [BEGIN_MARK, ""]
    tables = (
        ("1", "## 1. Records inside the run dir", True),
        ("2", "## 2. Records beside the run dir (siblings under `<runs_base>`)", False),
        ("3", "## 3. Session history", False),
        ("4", "## 4. Episode-level records (under `<episode>`)", False),
    )
    for tid, title, with_deny in tables:
        ks = [k for k in kinds if k["table"] == tid]
        out += [title, ""]
        if k_note := next((k["table_note"] for k in ks if k.get("table_note")), ""):
            out += [k_note, ""]
        hdr = ["kind", "path", "writer", "when", "readers"]
        if with_deny:
            hdr.append("denied to")
        hdr += ["crosses boundary", "archived as", "note"]
        out.append("| " + " | ".join(hdr) + " |")
        out.append("|" + "---|" * len(hdr))
        for k in ks:
            f = facts[k["kind"]]
            cells = [k["kind"], f"`{k['path']}`", _cell(f["writers"]), f["when"], _cell(f["readers"])]
            if with_deny:
                cells.append(k["deny"] or "—")
            note = k["note"] + (f" Read via: {k['via']}." if k.get("via") else "")
            cells += [f["crosses"], k["archived_as"] or "—", _esc(note.strip())]
            out.append("| " + " | ".join(cells) + " |")
        out.append("")
    # table 7 — derived
    out += ["## 7. Sub-collections for the run handle (#1077)", "",
            "Kinds whose call sites span more than one package (*crosses boundary = yes*), grouped by "
            "the concept the handle names. Derived from tables 1–3; a kind with `subcollection` empty "
            "in `run-records-kinds.tsv` is learning-internal or episode-level and is not a sub-collection.", "",
            "| sub-collection | kinds | write owner(s) | writes when |", "|---|---|---|---|"]
    subs: dict[str, list[dict[str, str]]] = defaultdict(list)
    for k in kinds:
        if k["subcollection"] and facts[k["kind"]]["crosses"] == "yes":
            subs[k["subcollection"]].append(k)
    for sub, ks in subs.items():
        owners = sorted({_pkg(r.path) for k in ks for r in facts[k["kind"]]["writers"]})
        whens = " / ".join(facts[k["kind"]]["when"] for k in ks)
        out.append(f"| `{sub}` | {', '.join(k['kind'] for k in ks)} | {', '.join(owners) or '—'} | {whens} |")
    out += ["", END_MARK]
    return "\n".join(out)


def render_page(rows: list[Row], kinds: list[dict[str, str]], page_text: str) -> str:
    start = page_text.index(BEGIN_MARK)
    end = page_text.index(END_MARK) + len(END_MARK)
    return page_text[:start] + render(rows, kinds) + page_text[end:]


def render_appendix(rows: list[Row]) -> str:
    out = ["| call site | kind | op | function | when | note |", "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (r.path, r.line)):
        out.append(f"| `{r.path}:{r.line}` | {r.kind} | {r.op} | `{r.function}` | {WHEN_ALIASES.get(r.when, r.when) or 'n-a'} | {_esc(r.note)} |")
    return "\n".join(out)


# ---------------------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------------------

def findings(sites: list[Site], rows: list[Row]) -> list[Finding]:
    have = {r.key for r in rows}
    seen = {s.key for s in sites}
    out: list[Finding] = []
    for s in sites:
        if s.key not in have:
            out.append(Finding(f"{s.key}::{s.what}", f"{s.path}:{s.line} {s.function}: {s.what} has no row in run-records.tsv"))
    for r in rows:
        if r.op == NAMES_OP:
            continue
        if r.key not in seen and not r.kind.startswith("NOT:not_file_io"):
            out.append(Finding(f"stale::{r.key}", f"{r.path}:{r.line} {r.function}: row names a call that is gone"))
    return out


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        sites = scan()
    except ScanBlind as exc:
        print(f"lint_run_records: {exc}", file=sys.stderr)
        return 2
    rows = load_rows()
    kinds = load_kinds()
    if "--refresh" in args:
        n = refresh_lines(rows, sites)
        save_rows(rows)
        print(f"[lint_run_records] refreshed {n} line number(s) -> {SITES_TSV.name}")
    page = PAGE.read_text(encoding="utf-8")
    rendered = render_page(rows, kinds, page)
    appendix_mark = "## Appendix — call-site attribution"
    if appendix_mark in rendered:
        head, _, _ = rendered.partition(appendix_mark)
        pre = "".join(_appendix_preamble())
        rendered = head + appendix_mark + "\n\n" + pre + render_appendix(rows) + "\n"
    if "--render" in args:
        PAGE.write_text(rendered, encoding="utf-8")
        print(f"[lint_run_records] rendered -> {PAGE.relative_to(REPO_ROOT)}")
        page = rendered
    found = findings(sites, rows)
    rc = gate(found, BASELINE_PATH, args, label="lint_run_records", header=HEADER)
    if page != rendered and "--update-baseline" not in args:
        print("\n[lint_run_records] STALE RENDER: docs/run-records.md differs from its tables — "
              "run `python scripts/lint/lint_run_records.py --render` and commit.")
        rc = 1
    print(f"[lint_run_records] {len(sites)} call site(s) in scope, {len(rows)} row(s).")
    return rc


def _appendix_preamble() -> list[str]:
    return [
        "Every file-access call site in `runtime/`, `learning/`, `scripts/`, `evals/`, `hooks/` and the\n",
        "top-level `defender/*.py` modules (tests excluded), found by AST and resolved through the lint\n",
        "suite's callee resolver, so a docstring that mentions `open(` is not a site and an aliased\n",
        "import still is. Rendered from `run-records.tsv` by `scripts/lint/lint_run_records.py`, which\n",
        "fails CI when a site has no row or a row's call is gone. Column 2 is a kind id from the tables\n",
        "above, `NOT:<tag>` for a non-record (tags follow section 6), or `archive_proj` for the archive\n",
        "copy's own call sites (section 5). `tool_seam` marks the model's generic read and write tools:\n",
        "the file they touch is whichever record the role's grant names, so the kind is decided by the\n",
        "gate at the call, not by the seam. `NOT:not_file_io` rows are the generic `_io` helpers\n",
        "themselves, attributed at their callers.\n\n",
    ]


if __name__ == "__main__":
    sys.exit(main())
