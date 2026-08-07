
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from defender._io import read_text_soft
from defender._run_paths import RunPaths

from .parser import ParseWarning, parse_dense_companion
from .schema import (
    CompanionBody,
    Conclude,
    FindingRecord,
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
    def leads(self) -> list[FindingRecord]:
        return [e for e in self.body.get("findings", []) if isinstance(e, dict)]

    @property
    def conclude(self) -> Conclude:
        return self.body.get("conclude", {})


@dataclass
class LoadReport:
    root: Path
    scanned: int = 0
    loaded: int = 0
    skipped: list[tuple[Path, str]] = field(default_factory=list)
    partial: list[tuple[Path, list[ParseWarning]]] = field(default_factory=list)

    @property
    def total_warnings(self) -> int:
        return sum(len(ws) for _, ws in self.partial)

    def detail_lines(self, *, verbose: bool) -> list[str]:
        """The per-file reasons behind the counts — empty when every scanned file loaded whole.

        The counts alone say a case is missing from the corpus or came in short; only these lines
        say WHICH case and why, which is the difference between a query that quietly answers off a
        smaller corpus than the operator thinks they have and one they can fix. `verbose` expands
        each partial file's per-row parse warnings; without it a partial file reports how many
        rows it dropped, since a file with a systematically bad block drops many identical ones.
        """
        lines = [f"  skipped {path.parent.name}: {reason}" for path, reason in self.skipped]
        for path, warnings in self.partial:
            lines.append(f"  partial {path.parent.name}: {len(warnings)} row(s) skipped")
            if verbose:
                lines += [f"    [{w.block} row {w.row_index}] {w.reason}" for w in warnings]
        return lines


def _read_signature_id(alert_path: Path) -> str | None:
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
