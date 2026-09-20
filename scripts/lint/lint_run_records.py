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
from _baseline import Finding

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
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
    "os.unlink": "write",
    "os.remove": "write",
    "os.replace": "write",
    "os.link": "write",
    "os.mkdir": "write",
    "os.makedirs": "write",
    "shutil.rmtree": "write",
    "shutil.move": "write",
    "tarfile.open": "open",
}
#: Duck-typed attribute calls on a value (`p.read_text()`): `callee()` is None there by
#: design, so the attribute NAME is the key.
DUCK_ATTRS: dict[str, str] = {
    "open": "open",
    "read_text": "read",
    "write_text": "write",
    "read_bytes": "read",
    "write_bytes": "write",
    # `_io.Bound` — the repo's own guarded read seam (`_io.py:440-535`) — and the plain
    # directory/unlink calls on a path value. `.read` also matches a stream's `.read()`, which
    # is attributed `NOT:not_file_io` rather than hidden from the sweep.
    "read": "read",
    "read_jsonl": "read",
    "entries": "read",
    "mkdir": "write",
    "unlink": "write",
    "rmdir": "write",
    "touch": "write",
    "rename": "write",
    # not `.replace`: on a path value it is a rename, but the same attribute on a str is the
    # tree's commonest call, and `callee()` cannot tell them apart. `os.replace` is resolved.
}
#: Row `op` values a site of each op class may carry. `open` is ambiguous at the call (mode is
#: a runtime value), so any op fits it; a `copy` site is a write on one side and a read on the
#: other and the row says which record it is attributed to.
OP_CLASSES: dict[str, frozenset[str]] = {
    "read": frozenset({"read"}),
    "write": frozenset({"write", "append", "mkdir", "unlink"}),
    "copy": frozenset({"copy", "read"}),
    "open": frozenset({"open", "read", "write", "append"}),
}
#: Kinds the appendix may carry that no rendered table lists. Everything else must be a row
#: of `run-records-kinds.tsv` or a `NOT:<tag>`.
APPENDIX_ONLY_KINDS = frozenset({"tool_seam"})
WRITE_OPS = frozenset({"write", "append", "copy", "mkdir", "unlink"})
#: `names`: not a call — the one line that MINTS a record's filename for a shared writer seam
#: (a stage's `trace_name`, a ledger's file name). Rendered as evidence, never checked against
#: the sweep, and never the only row a kind may have if a real call exists.
NAMES_OP = "names"
WHEN_ORDER = ("host", "live", "end", "later")
WHEN_ALIASES = {"host-before-agent": "host", "n-a": ""}



@dataclass(frozen=True)
class Site:
    path: str        # relative to defender/
    line: int
    function: str    # innermost enclosing def, or <module>
    what: str        # resolved callee or `.attr`
    opclass: str     # open / read / write / copy

    @property
    def key(self) -> str:
        return f"{self.path}::{self.function}::{self.what}"


@dataclass
class Row:
    path: str
    line: int
    kind: str      # one kind id, or several comma-separated when one helper touches several
    op: str
    function: str
    callee: str    # the resolved callee (`Site.what`), so the row names the CALL
    when: str
    note: str

    @property
    def key(self) -> str:
        return f"{self.path}::{self.function}::{self.callee}"

    @property
    def kinds(self) -> list[str]:
        return [k.strip() for k in self.kind.split(",") if k.strip()]

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
    _text, tree = read_and_parse(path, rel)
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
            Row(r["path"], int(r["line"]), r["kind"], r["op"], r["function"], r["callee"], r["when"], r["note"])
            for r in csv.DictReader(fh, delimiter="\t")
        ]


def save_rows(rows: list[Row], path: Path = SITES_TSV) -> None:
    rows = sorted(rows, key=lambda r: (r.path, r.line, r.kind))
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(["path", "line", "kind", "op", "function", "callee", "when", "note"])
        for r in rows:
            w.writerow([r.path, r.line, r.kind, r.op, r.function, r.callee, r.when, r.note])


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
    grouped: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        if r.op != NAMES_OP:
            grouped[r.key].append(r)
    changed = 0
    for key, rs in grouped.items():
        cands = sorted(by_key.get(key, ()), key=lambda s: s.line)
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
        for k in r.kinds:
            by_kind[k].append(r)
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

def findings(sites: list[Site], rows: list[Row], kinds: list[dict[str, str]] | None = None) -> list[Finding]:
    """Three checks, all keyed on the CALL (`path::function::callee`), as multisets, so a
    second call of the same helper in an attributed function is not hidden by the first:

      - a site with more calls than rows      -> unattributed
      - a row with more entries than calls     -> stale (its call is gone)
      - a row whose `op` does not fit the callee's op class, or whose kind no table knows
    """
    site_n: dict[str, int] = defaultdict(int)
    site_class: dict[str, str] = {}
    for s in sites:
        site_n[s.key] += 1
        site_class[s.key] = s.opclass
    row_n: dict[str, int] = defaultdict(int)
    for r in rows:
        if r.op != NAMES_OP:
            row_n[r.key] += 1
    known = {k["kind"] for k in kinds} if kinds is not None else None
    out: list[Finding] = []
    for key, n in site_n.items():
        if n > row_n.get(key, 0):
            path, fn, what = key.split("::", 2)
            out.append(Finding(key, f"{path} {fn}: {what} called {n}x, {row_n.get(key, 0)} row(s) in run-records.tsv"))
    for key, n in row_n.items():
        if n > site_n.get(key, 0):
            path, fn, what = key.split("::", 2)
            out.append(Finding(f"stale::{key}", f"{path} {fn}: {n} row(s) for {what}, {site_n.get(key, 0)} call(s) in the tree"))
    for r in rows:
        if r.op == NAMES_OP:
            continue
        cls = site_class.get(r.key)
        if cls is not None and r.op not in OP_CLASSES[cls]:
            out.append(Finding(f"op::{r.key}::{r.op}", f"{r.path}:{r.line} {r.function}: op {r.op!r} does not fit a {cls} call ({r.callee})"))
    if known is not None:
        for r in rows:
            for k in r.kinds:
                if not (k in known or k.startswith("NOT:") or k in APPENDIX_ONLY_KINDS):
                    out.append(Finding(f"kind::{r.key}::{k}", f"{r.path}:{r.line}: kind {k!r} is in no table"))
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
        rendered = head + appendix_mark + "\n\n" + "".join(_appendix_preamble()) + render_appendix(rows) + "\n"
    if "--render" in args:
        PAGE.write_text(rendered, encoding="utf-8")
        print(f"[lint_run_records] rendered -> {PAGE.relative_to(REPO_ROOT)}")
        page = rendered
    found = findings(sites, rows, kinds)
    # NO BASELINE and no inline suppression, deliberately: this gate's product is
    # completeness, and a fingerprint accepted once would cover every future call of that
    # callee in that function. An unattributed site gets a row — `NOT:<tag>` if it is not a
    # run record — never a waiver.
    if found:
        print(f"\n[lint_run_records] {len(found)} finding(s):")
        for f in found:
            print(f"  {f.display}")
        print("\nAttribute the site in defender/docs/run-records.tsv (a NOT:<tag> row if it is not a "
              "run record), then run `python scripts/lint/lint_run_records.py --render`.")
    if page != rendered:
        print("\n[lint_run_records] STALE RENDER: docs/run-records.md differs from its tables — "
              "run `python scripts/lint/lint_run_records.py --render` and commit.")
    print(f"[lint_run_records] {len(sites)} call site(s) in scope, {len(rows)} row(s), {len(found)} finding(s).")
    return 1 if (found or page != rendered) else 0


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
