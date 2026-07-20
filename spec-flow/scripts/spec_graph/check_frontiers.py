#!/usr/bin/env python3
"""spec-graph check #5 — frontier-chain conservation and the resume scan.

The write-tests frontier files (SKILL.md, "Frontiers") carry one machine-read sliver:
YAML frontmatter with `phase`, `status`, `inventory`, and `inputs` echoing the consumed
frontiers' inventories. Conservation — counts in equal counts out, every drop named —
was previously an LLM leaf walking the chain in phase F; it is arithmetic over
frontmatter, so this check walks it instead, and the orchestrator can run it at every
phase boundary: a broken frontier is found where it was written, not at the final baton.

What is checked, per `*.md` file in the frontiers directory:

* frontmatter parses, `status` is in the closed vocabulary, `phase` is present,
  `inventory` is a mapping of category → integer count;
* every `inputs` entry names an existing sibling file, and its `inventory_echo` equals
  the producer's actual `inventory` — a mismatch means the two declarations disagree,
  and the count must be recomputed from the payload content, never resolved by copying
  either side (in the contract's smoke runs the break was a producer misdeclaring,
  caught by the consumer's computed echo);
* the `## Digest` section exists and holds ≤15 lines (the leaf's inline return, verbatim);
* the dispositions sum rule: an inventory carrying `consensus`/`forks`/`silent_branches`/
  `drops` must sum to the `premises` count it echoed — every premise leaves with a
  recorded disposition.

`--resume` prints the chain's state (file, phase, status, staleness against its inputs)
and where to re-enter: the first frontier that is blocked, unparseable, or older than an
input. Informational — always exits 0 when the directory exists.

Usage:
    spec-graph frontiers [dir] [--resume]
(default dir: <repo root>/.spec-flow/frontiers)
Exit codes: 0 clean, 1 findings, 2 the directory is missing or holds no frontiers.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

import _config

_STATUS = {"complete", "design-refuted", "blocked"}
_DIGEST_CAP = 15
_DISPOSITIONS = {"consensus", "forks", "silent_branches", "drops"}


class Frontier:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.error: str | None = None
        self.meta: dict = {}
        self.digest_lines: int | None = None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            # Same class as unparseable frontmatter: a finding on this file, never a traceback
            # that takes the whole chain's report down with it.
            self.error = f"unreadable ({e.__class__.__name__})"
            return
        m = re.match(r"\A---\s*\n(.*?)\n---\s*\n?", text, re.DOTALL)
        if not m:
            self.error = "no YAML frontmatter (file must open with a `---` block)"
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
    def inputs(self) -> list[dict]:
        ins = self.meta.get("inputs")
        return [i for i in ins if isinstance(i, dict)] if isinstance(ins, list) else []


def _load(directory: Path) -> dict[str, Frontier]:
    return {p.name: Frontier(p) for p in sorted(directory.glob("*.md"))}


def check(directory: Path) -> list[str]:
    frontiers = _load(directory)
    findings: list[str] = []
    for name, f in frontiers.items():
        if f.error:
            findings.append(f"{name}: {f.error}.")
            continue
        if f.status not in _STATUS:
            findings.append(
                f"{name}: status `{f.status}` is not one of {sorted(_STATUS)}."
            )
        if not f.meta.get("phase"):
            findings.append(f"{name}: frontmatter carries no `phase`.")
        for cat, n in f.inventory.items():
            if not isinstance(n, int):
                findings.append(
                    f"{name}: inventory `{cat}: {n!r}` is not an integer count — counts are "
                    f"computed, never recalled."
                )
        if f.digest_lines is None:
            findings.append(f"{name}: no `## Digest` section — the leaf's inline return has no home.")
        elif f.digest_lines > _DIGEST_CAP:
            findings.append(
                f"{name}: digest runs {f.digest_lines} lines (cap {_DIGEST_CAP}) — measured "
                f"drift runs long, not short."
            )
        echoed_premises: int | None = None
        raw_inputs = f.meta.get("inputs")
        for entry in (raw_inputs if isinstance(raw_inputs, list) else []):
            # The `inputs` property keeps only mappings — a bare string (`inputs:
            # [10-brief.md]`, the natural shorthand) would otherwise vanish from
            # reconciliation entirely: no echo check, no finding, no staleness.
            if not isinstance(entry, dict):
                findings.append(
                    f"{name}: input entry {entry!r} is not a mapping — each input must be a "
                    f"mapping with `path` + `inventory_echo`, or its echo is never reconciled."
                )
        for inp in f.inputs:
            ref = str(inp.get("path") or "")
            if not ref:
                # A pathless entry has no producer to reconcile against — and in the resume
                # scan it would resolve to the directory itself (false STALE on every write).
                findings.append(
                    f"{name}: input entry carries no `path` — the echo has no producer to "
                    f"reconcile against."
                )
                continue
            # `./10-brief.md` and `frontiers/10-brief.md` name the same sibling: reconcile by
            # the bare filename, but keep the raw ref in messages so the author sees their own
            # spelling. A decorated ref that skipped normalization skipped the echo check too.
            norm = Path(ref).name
            echo = inp.get("inventory_echo")
            producer = frontiers.get(norm)
            if producer is None:
                # Only a numeric-prefixed name claims to be a sibling in this chain. Anything
                # else — the design doc, an issue thread, a sidecar payload — is an external
                # or non-frontier input with no frontmatter to reconcile against.
                if re.match(r"^\d+-", norm) and norm.endswith(".md"):
                    findings.append(f"{name}: input `{ref}` names no frontier in {directory.name}/.")
                elif re.match(r"^\d+-", norm) and not (directory / ref).exists():
                    findings.append(f"{name}: input `{ref}` does not exist.")
                continue
            if producer.error:
                continue  # already reported on the producer
            if isinstance(echo, dict):
                if isinstance(echo.get("premises"), int):
                    # SUM across inputs, never last-wins: a frontier that fans in two producers
                    # consumed both their premise counts, and comparing the dispositions against
                    # only the last echo both false-flags a conserved chain and hides a real drop.
                    echoed_premises = (echoed_premises or 0) + echo["premises"]
                if echo != producer.inventory:
                    diff = {
                        k: (echo.get(k), producer.inventory.get(k))
                        for k in set(echo) | set(producer.inventory)
                        if echo.get(k) != producer.inventory.get(k)
                    }
                    findings.append(
                        f"{name}: inventory_echo for `{ref}` disagrees with its actual inventory "
                        f"— (echoed, actual) per category: {diff}. The two declarations disagree: "
                        f"recompute the count from the payload content — never resolve the "
                        f"mismatch by copying either side."
                    )
            else:
                findings.append(f"{name}: input `{ref}` carries no `inventory_echo` mapping.")
        # Dispositions sum rule: consensus + forks + silent_branches + drops == premises in.
        # ANY present disposition key engages the rule (phases/answer.md mandates all four):
        # requiring the full set let a partial inventory (`drops` omitted) skip the sum
        # entirely — exactly the shape a silent drop hides in.
        present = _DISPOSITIONS & set(f.inventory)
        if present and echoed_premises is not None:
            for missing in sorted(_DISPOSITIONS - present):
                findings.append(
                    f"{name}: inventory carries dispositions but omits `{missing}` — all four "
                    f"disposition categories are mandated, and a missing one is an unrecorded "
                    f"exit for a premise."
                )
            # Non-int counts were already flagged above (counts are computed, never recalled) —
            # skip them here rather than lose the whole report behind a TypeError mid-sum.
            total = sum(v for k in sorted(present) if isinstance(v := f.inventory[k], int))
            if total != echoed_premises:
                findings.append(
                    f"{name}: dispositions sum to {total} but {echoed_premises} premises were "
                    f"consumed — a premise left without a recorded disposition is the one loss "
                    f"no downstream check can see."
                )
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
            # A deliberate halt, not a hole in the chain: the run stops before the next
            # dispatch and the correction routes to the human (SKILL.md, "Early exit").
            halted = True
        elif f.status != "complete":
            state.append(str(f.status).upper())
        mtime = f.path.stat().st_mtime
        for inp in f.inputs:
            ref = str(inp.get("path") or "")
            if not ref:
                # `directory / ""` is the directory itself, whose mtime bumps on every sibling
                # write — a pathless entry would false-STALE the chain and move the re-entry
                # point. check() flags the entry; the scan just skips it.
                continue
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
        # The scan walks only files that EXIST — a run that died after writing 2 of 5
        # same-phase frontiers has no anomaly on disk, so completeness here is bounded.
        print(
            f"\n[resume] chain is complete through {list(frontiers)[-1]} — this scan sees only "
            f"frontiers already written; cross-check the phase map for frontiers not yet "
            f"written, then proceed to the next phase."
        )
    else:
        print("\n[resume] no frontiers yet — start at phase A.")
    return 0


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    do_resume = "--resume" in argv
    args = [a for a in argv if a != "--resume"]
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
    findings = check(directory)
    for f in findings:
        print(f"  CONSERVATION {f}")
    print(f"\n[check_frontiers] {len(findings)} finding(s) over {directory}.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
