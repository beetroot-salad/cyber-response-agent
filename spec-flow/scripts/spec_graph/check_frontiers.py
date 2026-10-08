#!/usr/bin/env python3
"""spec-graph check #5 — frontier-chain shape and the resume scan.

The write-tests frontier files (SKILL.md, "Frontiers") carry YAML frontmatter with `phase`,
`status`, and `inputs` naming the frontiers they consumed. The chain is a checkpoint, not an
accounting ledger: the per-frontier count echoes this check used to reconcile caught
bookkeeping slips and never a dropped item (the drops were found by the cold reconciler's
trail walk), so they are gone. An old chain that still carries `inventory_echo` entries
parses unchanged; the echoes are ignored.

What is checked, per `*.md` file in the frontiers directory:

* frontmatter parses, `status` is in the closed vocabulary, `phase` is present, and an
  `inventory` — optional — is a mapping of category → integer count;
* every `inputs` entry is a frontier filename or a mapping with `path`, and a
  numeric-prefixed `.md` name it gives exists in the chain;
* the `## Digest` section exists and holds ≤15 lines (the leaf's inline return, verbatim).

`--only <file>` lints that one frontier and reports nothing else — the leaf's pre-return
self-check, run while its phase siblings may still be half-written beside it.

`--resume` prints the chain's state (file, phase, status, staleness against its inputs)
and where to re-enter: the first frontier that is blocked, unparseable, or older than an
input. Informational — always exits 0 when the directory exists.

Usage:
    spec-graph frontiers [dir] [--resume | --only <file>]
(default dir: <repo root>/.spec-flow/frontiers)
Exit codes: 0 clean, 1 findings, 2 the directory is missing or holds no frontiers, or
`--only` names no frontier in it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

import _cli
import _config

_STATUS = {"complete", "design-refuted", "blocked"}
_DIGEST_CAP = 15
# One line, so a finding stays one line; write-tests' references/frontier.md has the full shape.
_FRONTMATTER_EXAMPLE = (
    "`---` / `phase: C-judge` / `status: complete` / `inputs: [40-premises.md]` / `---`"
)


class Frontier:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.error: str | None = None
        self.meta: dict = {}
        self.digest_lines: int | None = None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            # A finding on this file, not a traceback that ends the whole report.
            self.error = f"unreadable ({e.__class__.__name__})"
            return
        m = re.match(r"\A---\s*\n(.*?)\n---\s*\n?", text, re.DOTALL)
        if not m:
            self.error = (
                "no YAML frontmatter — open the file with a block of lines like "
                + _FRONTMATTER_EXAMPLE
            )
            return
        try:
            meta = yaml.safe_load(m.group(1))
        except yaml.YAMLError as e:
            self.error = f"frontmatter does not parse ({e.__class__.__name__})"
            return
        if not isinstance(meta, dict):
            self.error = "frontmatter is not a mapping"
            return
        self.meta = meta
        body = text[m.end():]
        dm = re.search(r"^## Digest\s*$(.*?)(?=^## |\Z)", body, re.MULTILINE | re.DOTALL)
        if dm:
            self.digest_lines = len([ln for ln in dm.group(1).splitlines() if ln.strip()])

    @property
    def status(self) -> str | None:
        return self.meta.get("status")

    @property
    def inventory(self) -> dict:
        inv = self.meta.get("inventory")
        return inv if isinstance(inv, dict) else {}

    @property
    def inputs(self) -> list[str]:
        """The consumed frontiers' names — a bare filename or a mapping's `path`."""
        ins = self.meta.get("inputs")
        refs = []
        for i in ins if isinstance(ins, list) else []:
            ref = i.get("path") if isinstance(i, dict) else i
            if isinstance(ref, str) and ref:
                refs.append(ref)
        return refs


def _load(directory: Path) -> dict[str, Frontier]:
    return {p.name: Frontier(p) for p in sorted(directory.glob("*.md"))}


def _lint_frontmatter(name: str, f: Frontier, findings: list[str]) -> None:
    """The declared slots: a closed-vocabulary `status`, a `phase`, integer counts."""
    if f.status not in _STATUS:
        findings.append(
            f"{name}: status `{f.status}` is not one of {sorted(_STATUS)}."
        )
    if not f.meta.get("phase"):
        findings.append(
            f"{name}: frontmatter carries no `phase` — e.g. {_FRONTMATTER_EXAMPLE}"
        )
    for cat, n in f.inventory.items():
        if not isinstance(n, int):
            findings.append(
                f"{name}: inventory `{cat}: {n!r}` is not an integer count — write the "
                f"number (computed with grep -c/wc over the payload), or drop the key."
            )


def _lint_digest(name: str, f: Frontier, findings: list[str]) -> None:
    """The `## Digest` section — the leaf's inline return, verbatim and capped."""
    if f.digest_lines is None:
        findings.append(f"{name}: no `## Digest` section — add `## Digest` right after the frontmatter "
            f"holding the ≤{_DIGEST_CAP}-line summary the leaf returns inline.")
    elif f.digest_lines > _DIGEST_CAP:
        findings.append(
            f"{name}: digest runs {f.digest_lines} lines (cap {_DIGEST_CAP}) — move detail "
            f"into the payload sections below it; the digest is what the spine reads."
        )


def _lint_inputs(
    name: str, f: Frontier, frontiers: dict[str, Frontier], directory: Path,
    findings: list[str],
) -> None:
    """Each `inputs` entry names a frontier: a bare filename, or a mapping with `path`."""
    raw_inputs = f.meta.get("inputs")
    if raw_inputs is not None and not isinstance(raw_inputs, list):
        findings.append(
            f"{name}: `inputs` is not a list — write it as `inputs: [10-brief.md, ...]`."
        )
        return
    for entry in raw_inputs or []:
        ref = entry.get("path") if isinstance(entry, dict) else entry
        if not isinstance(ref, str) or not ref:
            findings.append(
                f"{name}: input entry {entry!r} names no file — write the consumed "
                f"frontier's filename, e.g. `inputs: [10-brief.md]`."
            )
            continue
        # Match by bare filename (`./10-brief.md` == `frontiers/10-brief.md`); messages keep
        # the author's spelling.
        if Path(ref).name not in frontiers:
            _lint_absent_producer(name, ref, Path(ref).name, directory, findings)


def _lint_absent_producer(
    name: str, ref: str, norm: str, directory: Path, findings: list[str]
) -> None:
    """An input naming no frontier in the chain. Only a numeric-prefixed name claims to be
    a sibling; anything else is an external input with nothing to reconcile."""
    if not re.match(r"^\d+-", norm):
        return
    if norm.endswith(".md"):
        findings.append(f"{name}: input `{ref}` names no frontier in {directory.name}/.")
    elif not (directory / ref).exists():
        findings.append(f"{name}: input `{ref}` does not exist.")


def check(directory: Path, only: str | None = None) -> list[str]:
    frontiers = _load(directory)
    findings: list[str] = []
    for name, f in frontiers.items():
        if only is not None and name != only:
            continue
        if f.error:
            findings.append(f"{name}: {f.error}.")
            continue
        _lint_frontmatter(name, f, findings)
        _lint_digest(name, f, findings)
        _lint_inputs(name, f, frontiers, directory, findings)
    return findings


def resume(directory: Path) -> int:
    frontiers = _load(directory)
    first_anomaly: str | None = None
    for name, f in frontiers.items():
        state: list[str] = []
        halted = False
        if f.error:
            state.append(f"UNPARSEABLE ({f.error})")
        elif f.status == "design-refuted":
            # A deliberate halt; the correction routes to the human (SKILL.md, "Early exit").
            halted = True
        elif f.status != "complete":
            state.append(str(f.status).upper())
        mtime = f.path.stat().st_mtime
        for ref in f.inputs:
            src = directory / ref
            if src.exists() and src.stat().st_mtime > mtime:
                state.append(f"STALE (older than {src.name})")
                break
        label = "; ".join(state) if state else ("DESIGN-REFUTED (halt)" if halted else "complete")
        print(f"  {name}: phase {f.meta.get('phase', '?')} — {label}")
        if halted and first_anomaly is None:
            print(
                f"\n[resume] `{name}` is design-refuted — the run halted on purpose. Route the "
                f"correction to the human (§7) before any re-entry."
            )
            return 0
        if state and first_anomaly is None:
            first_anomaly = name
    if first_anomaly:
        print(f"\n[resume] re-enter at `{first_anomaly}` — first blocked/stale/unparseable frontier.")
    elif frontiers:
        # Only written files are seen; a run that died mid-phase leaves no anomaly on disk.
        print(
            f"\n[resume] chain is complete through {list(frontiers)[-1]} — this scan sees only "
            f"frontiers already written; cross-check the phase map for frontiers not yet "
            f"written, then proceed to the next phase."
        )
    else:
        print("\n[resume] no frontiers yet — start at phase A.")
    return 0


def main(argv: list[str]) -> int:
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--only"}, flags={"--resume"})
    do_resume = opts["resume"]
    only = Path(opts["only"]).name if opts["only"] else None
    directory = Path(args[0]) if args else _config.repo_root() / ".spec-flow" / "frontiers"
    if not directory.is_dir():
        if do_resume:
            print(f"[resume] no frontiers directory at {directory} — start at phase 0.")
            return 0
        print(f"check_frontiers: {directory} is not a directory", file=sys.stderr)
        return 2
    if do_resume:
        return resume(directory)
    if not any(directory.glob("*.md")):
        print(f"check_frontiers: no *.md frontiers under {directory}", file=sys.stderr)
        return 2
    if only is not None and not (only.endswith(".md") and (directory / only).is_file()):
        # A sidecar's `.py` payload is not a frontier; name its `.md` sidecar instead.
        print(f"check_frontiers: --only {only} names no frontier (*.md) in {directory}",
              file=sys.stderr)
        return 2
    findings = check(directory, only)
    for f in findings:
        print(f"  FRONTIER {f}")
    scope = f"{directory}/{only}" if only else str(directory)
    print(f"\n[check_frontiers] {len(findings)} finding(s) over {scope}.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
