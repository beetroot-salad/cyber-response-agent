
from __future__ import annotations

import datetime as _dt
import os
from dataclasses import field
from pathlib import Path
from typing import Annotated

from pydantic import SkipValidation

from defender.records import _alert_input
from defender._shown import quoted
from defender._io import read_text_soft
from defender._model import model
from defender.run_repository import RunPaths

from .parser import ParseWarning, parse_dense_companion
from .schema import (
    CompanionBody,
    Conclude,
    FindingRecord,
)


@model
class Companion:
    case_id: str
    source_path: Path
    #: `SkipValidation`: `CompanionBody` is a static typing aid over a dict the projector builds
    #: incrementally, so required keys may be absent; `validate.diagnose` is the
    #: well-formedness check, not pydantic.
    body: Annotated[CompanionBody, SkipValidation]
    signature_id: str | None = None
    created_at: str | None = None
    parse_warnings: list[ParseWarning] = field(default_factory=list)

    @property
    def leads(self) -> list[FindingRecord]:
        return [e for e in self.body.get("findings", []) if isinstance(e, dict)]

    @property
    def conclude(self) -> Conclude:
        return self.body.get("conclude", {})


@model
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
        """The per-file reasons behind the counts; empty when every scanned file loaded whole.

        Says which case is missing or short and why. `verbose` expands each partial file's
        per-row parse warnings; otherwise only the dropped-row count is shown, since one bad
        block often drops many identical rows.
        """
        lines = [f"  skipped {quoted(path.parent.name)}: {reason}" for path, reason in self.skipped]
        for path, warnings in self.partial:
            lines.append(f"  partial {quoted(path.parent.name)}: {len(warnings)} row(s) skipped")
            if verbose:
                lines += [f"    [{w.block} row {w.row_index}] {w.reason}" for w in warnings]
        return lines


def _read_signature_id(record_path: Path) -> str | None:
    """The signature the run's record carries (never re-derived from the alert's bytes); `None`
    when there is no record or it names no signature."""
    record = _alert_input.read_record(record_path)
    return None if record is None else record.facts.signature


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
    record_path = RunPaths(run_dir).alert_record
    # A folder with no readable record is not a run (A8): named and counted, never attributed.
    if _alert_input.read_record(record_path) is None:
        if not os.path.lexists(record_path):
            return None, "no run record (not a run of this version)", warnings
        return None, "run record unreadable (not a record of this version)", warnings
    companion = Companion(
        case_id=run_dir.name or path.stem,
        source_path=path,
        body=body,
        signature_id=_read_signature_id(record_path),
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
