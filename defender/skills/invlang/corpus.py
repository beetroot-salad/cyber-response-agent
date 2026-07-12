"""Defender-side invlang corpus loader (strict, aligned with current schema).

Walks `**/investigation.md` under an explicit corpus root, parses each
file with the strict defender parser, and exposes a list of
`Companion` records. Parse warnings (per-row skips) are threaded
through so post-mortem debugging always has a paper trail.

Signature ID: drawn from the sibling `alert.json`'s `rule.id` field
(defender runs don't follow the `ruleNNN/` path convention).

created_at: drawn from the run directory's mtime (defender writers
don't stamp the `<!-- created: -->` header that soc-agent uses).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from defender._io import read_text_soft, use_utf8_stdio
from defender._run_paths import RunPaths

from .parser import ParseWarning, parse_dense_companion
from .schema import (
    CompanionBody,
    Conclude,
    FindingRecord,
    HypothesisRecord,
    Prologue,
)


@dataclass
class Companion:
    case_id: str
    source_path: Path
    body: CompanionBody
    signature_id: str | None = None
    created_at: str | None = None
    parse_warnings: list[ParseWarning] = field(default_factory=list)

    @property
    def prologue(self) -> Prologue:
        return self.body.get("prologue", {})

    @property
    def hypotheses(self) -> list[HypothesisRecord]:
        return self.body.get("hypothesize", {}).get("hypotheses", [])

    @property
    def leads(self) -> list[FindingRecord]:
        return [e for e in self.body.get("findings", []) if isinstance(e, dict)]

    @property
    def conclude(self) -> Conclude:
        return self.body.get("conclude", {})


@dataclass
class LoadReport:
    """Telemetry from one corpus scan. `skipped` = whole-file rejects;
    `partial` = files that loaded but had at least one row-level
    warning. Both lists carry enough context to diagnose.
    """
    root: Path
    scanned: int = 0
    loaded: int = 0
    skipped: list[tuple[Path, str]] = field(default_factory=list)
    partial: list[tuple[Path, list[ParseWarning]]] = field(default_factory=list)

    @property
    def total_warnings(self) -> int:
        return sum(len(ws) for _, ws in self.partial)


def _read_signature_id(alert_path: Path) -> str | None:
    # Read through `read_text_soft`, not `alert_path.open()` + `json.load`. The old guard was
    # `except (OSError, json.JSONDecodeError)`, and JSONDecodeError is a *sibling* of
    # UnicodeDecodeError under ValueError, not its superclass — so an undecodable alert.json
    # (vendor-supplied bytes) escaped this guard and killed the whole corpus walk. Same defect as
    # `_load_one` below, same file. A missing signature degrades the companion; it never sinks it.
    text, _err = read_text_soft(alert_path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    rule = data.get("rule") if isinstance(data, dict) else None
    if not isinstance(rule, dict):
        return None
    rid = rule.get("id")
    if rid is None:
        return None
    # The case signature is its bare `rule.id` — the same vendor-neutral
    # convention as `case_history.case_ticket._signature_id`. It is only an
    # opaque cross-case join key (advisory Classes 5/6/8), recomputed live on
    # every corpus load and never persisted, so the format is free to change.
    return str(rid)


def _read_created_at(run_dir: Path) -> str | None:
    try:
        st = run_dir.stat()
    except OSError:
        return None
    return _dt.datetime.fromtimestamp(st.st_mtime, tz=_dt.UTC).isoformat()


_REQUIRED_KEYS = {"prologue", "findings", "conclude"}


def _load_one(
    path: Path,
) -> tuple[Companion | None, str | None, list[ParseWarning]]:
    if path.suffix != ".md":
        return None, f"not a .md file: {path.name}", []
    # `read_text_soft` owns both halves of the read (#589): the utf-8 pin, and the guard — which
    # must catch UnicodeDecodeError, a ValueError and NOT an OSError. The `except OSError` that
    # stood here let an undecodable investigation.md escape `_load_one`, escape `load_corpus`
    # (which has no try), and take down `defender-invlang` — an allowed main-loop shim — over one
    # bad byte in one past run. `defender/_corpus.py` had the guard right; this was a hand-rolled
    # copy of it that dropped half.
    text, err = read_text_soft(path)
    if text is None:
        return None, f"read error: {err}", []
    body, warnings = parse_dense_companion(text)
    for w in warnings:
        w.file_path = str(path)
    if not body:
        return None, "no ```invlang fences found", warnings
    missing = _REQUIRED_KEYS - body.keys()
    if missing:
        return None, f"missing top-level keys: {sorted(missing)}", warnings

    run_dir = path.parent
    alert_path = RunPaths(run_dir).alert
    companion = Companion(
        case_id=run_dir.name or path.stem,
        source_path=path,
        body=body,
        signature_id=_read_signature_id(alert_path),
        created_at=_read_created_at(run_dir),
        parse_warnings=warnings,
    )
    return companion, None, warnings


def load_corpus(root: Path | str) -> tuple[list[Companion], LoadReport]:
    """Walk `root` for investigation.md files. Returns (companions, report)."""
    root_p = Path(root)
    report = LoadReport(root=root_p)
    companions: list[Companion] = []
    if not root_p.exists():
        return companions, report
    for md in sorted(root_p.rglob("investigation.md")):
        report.scanned += 1
        comp, err, warnings = _load_one(md)
        if comp is not None:
            report.loaded += 1
            companions.append(comp)
            if warnings:
                report.partial.append((md, warnings))
        else:
            report.skipped.append((md, err or "unknown"))
    return companions, report


# ---------------------------------------------------------------------------
# CLI: report parse health
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    use_utf8_stdio()  # the corpus is model-authored and carries non-ASCII; see cli.main
    verbose = "--verbose" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = (
        args[0] if args
        else os.environ.get("DEFENDER_INVLANG_CORPUS_ROOT", "")
    )
    if not root:
        print(
            "usage: python -m defender.skills.invlang.corpus <corpus-root> [--verbose]",
            file=sys.stderr,
        )
        return 2
    companions, report = load_corpus(root)
    print(f"corpus_root:    {report.root}")
    print(f"scanned:        {report.scanned}")
    print(f"loaded:         {report.loaded}")
    print(f"skipped (file): {len(report.skipped)}")
    print(f"partial loads:  {len(report.partial)}  ({report.total_warnings} warnings)")
    if report.skipped:
        print("\nSkipped files:")
        for path, reason in report.skipped:
            print(f"  - {path.parent.name}: {reason}")
    if report.partial:
        print("\nPartial loads (file-level summary):")
        for path, warnings in report.partial:
            print(f"  - {path.parent.name}: {len(warnings)} row(s) skipped")
            if verbose:
                for w in warnings:
                    print(f"      [{w.block} row {w.row_index}] {w.reason}")
    if companions:
        print(f"\nLoaded {len(companions)} cases (showing first 20):")
        for c in companions[:20]:
            sig = c.signature_id or "-"
            disp = c.conclude.get("disposition") or "-"
            arche = c.conclude.get("matched_archetype") or "-"
            print(f"  {c.case_id:50s}  sig={sig:18s}  disp={disp:12s}  arche={arche}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
