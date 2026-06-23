#!/usr/bin/env python3
"""Shared baseline ratchet for the defender lint suite.

A gated lint emits findings; each finding carries a STABLE fingerprint — a path
plus the salient token, never a line number — so unrelated edits don't churn the
baseline. The accepted fingerprints live in a checked-in JSON config beside the
lint (`<lint>_baseline.json`). The lint fails (exit 1) only on a fingerprint NOT
in that config: a newly-introduced smell.

Why config (JSON), not code: exclusions are reviewable data, diffed in PRs like
any other config. JSON is stdlib-parseable, so the lints stay runnable as bare
`python scripts/lint/<lint>.py` with no third-party dependency on the path.

Baseline file shape — an object so each accepted fingerprint can carry a human
annotation that separates an *intentional* exclusion from un-triaged debt:

    {
      "//": "<generated header — what this file gates and how to regenerate>",
      "entries": {
        "defender/SKILL.md:wazuh": "intentional: protocol-surface identifier",
        "defender/foo.py:playground": ""        // "" = un-triaged: fix or annotate
      }
    }

The annotation is advisory: the gate only checks membership. Regenerate after a
deliberate change with `<lint>.py --update-baseline`; the rewrite MERGES, so it
preserves your annotations, adds new fingerprints with "", and drops resolved
ones.

Never hand-edit `entries` to silence a *new* finding — fix it, or (where the lint
supports one) use its inline `# lint-<name>: ok — <reason>` marker.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """One reported smell. `fingerprint` is the stable identity used for baseline
    membership (path + salient token, no line number). `display` is the
    human-readable report line (may include a line number)."""

    fingerprint: str
    display: str


def _load_entries(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def _write_entries(path: Path, entries: dict[str, str], *, header: str) -> None:
    payload = {"//": header, "entries": dict(sorted(entries.items()))}
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def gate(
    findings: list[Finding],
    baseline_path: Path,
    argv: list[str],
    *,
    label: str,
    header: str,
) -> int:
    """Drive the ratchet for one lint.

    With `--update-baseline` in argv: merge today's fingerprints into the baseline
    (preserving existing annotations, dropping resolved entries) and return 0.

    Otherwise: print the NEW findings prominently plus a baselined/new summary,
    and return 1 iff any finding's fingerprint is absent from the baseline.
    """
    current = {f.fingerprint for f in findings}
    baseline = _load_entries(baseline_path)

    if "--update-baseline" in argv:
        merged = {fp: baseline.get(fp, "") for fp in current}
        _write_entries(baseline_path, merged, header=header)
        added = len(current - baseline.keys())
        dropped = len(baseline.keys() - current)
        plural = "y" if len(merged) == 1 else "ies"
        print(
            f"[{label}] baseline updated: {len(merged)} entr{plural} "
            f"({added} added, {dropped} dropped) -> {baseline_path.name}"
        )
        return 0

    new = [f for f in findings if f.fingerprint not in baseline]
    baselined_count = len(findings) - len(new)

    if new:
        print(f"\n[{label}] NEW finding(s) absent from baseline ({len(new)}):")
        for f in new:
            print(f"  {f.display}")
        print(
            f"\nFix the finding, or — if intentional — run "
            f"`python scripts/lint/{label}.py --update-baseline` and annotate the "
            f"new entry in {baseline_path.name}."
        )
    print(
        f"\n[{label}] {len(findings)} finding(s): "
        f"{baselined_count} baselined, {len(new)} new."
    )
    return 1 if new else 0
