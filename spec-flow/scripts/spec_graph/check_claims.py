#!/usr/bin/env python3
"""spec-graph check #3 — a probed claim's instrument matches its kind (#633).

The ledger records, per claim, the `probe_kind` actually used (`executed | read | search`).
The escape this closes: a `behavior` or `primitive` claim — a claim about what code does over
an input — "probed" by READING the code. A read holds at parse level over exactly the input
the bug needs to see, so the suite pins the bug green. The prose rule "run it and watch" never
bit because nothing separated an execution from an inspection at gate time; this check is that
separation.

THE CHECK (deterministic, no LLM): for every claim whose verdict means it was probed
(`holds | refuted | unrefuted`), require a `probe_kind` present and drawn from the set its
`kind` admits — the `_REQUIRED` table below is the single source of truth for the mapping.
`unprobed`/`deferred` carry no instrument and are skipped (an `unprobed` load-bearing claim is
step-9's own finding, not this check's). An unknown `kind` or `probe_kind` is flagged too — the
closed vocabulary is enforced here.

Usage:
    spec-graph claims [graph.yaml ...] [--config <path>]
(the `spec-graph` wrapper in the plugin's bin/ is on the Bash PATH and finds this script itself.)
Exit 1 if any claim's instrument is wrong or missing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

import _config

# kind -> the probe_kinds it may legitimately close on. The one place the mapping lives: the
# rules.md prose describes it for the human, this table enforces it, and the check flags any
# drift. `read`/`search` are inspections; only `executed` runs the logic under test — which is
# why the behavior/primitive/reachability claims (about what code DOES) demand it.
_REQUIRED: dict[str, set[str]] = {
    "referential": {"read", "search"},   # the symbol/path exists — read/import/stat, or a defs search
    "census": {"search"},                # the full hit list — the search that established it
    "behavior": {"executed"},            # what existing code does on an input — run it
    "primitive": {"executed"},           # an I/O primitive's contract — execute it
    "reachability": {"executed"},        # a break-attempt is an execution
    "discharge": {"executed", "read", "search"},  # inherits its cited claim's instrument (#634 pins the cross-claim link)
}
_PROBE_KINDS = {"executed", "read", "search"}
_PROBED = {"holds", "refuted", "unrefuted"}   # an instrument was used — require probe_kind
_UNPROBED = {"unprobed", "deferred"}          # nothing run yet — skip (step-9 handles unprobed)


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def check(path: Path) -> list[str]:
    findings: list[str] = []
    for c in _load(path).get("claims", []) or []:
        cid = c.get("id", "<no-id>")
        kind, verdict, pk = c.get("kind"), c.get("verdict"), c.get("probe_kind")
        if kind not in _REQUIRED:
            findings.append(f"{path.name}:{cid}: unknown kind `{kind}` (not one of {sorted(_REQUIRED)}).")
            continue
        if verdict in _UNPROBED:
            continue
        if verdict not in _PROBED:
            findings.append(f"{path.name}:{cid}: unknown verdict `{verdict}`.")
            continue
        if pk is None:
            findings.append(
                f"{path.name}:{cid}: `{kind}` is {verdict} but records no `probe_kind` "
                f"— name the instrument used ({sorted(_REQUIRED[kind])})."
            )
        elif pk not in _PROBE_KINDS:
            findings.append(f"{path.name}:{cid}: unknown probe_kind `{pk}` (not one of {sorted(_PROBE_KINDS)}).")
        elif pk not in _REQUIRED[kind]:
            findings.append(
                f"{path.name}:{cid}: `{kind}` requires probe_kind {sorted(_REQUIRED[kind])} but closed "
                f"on `{pk}` — a claim about what code does over an input is not settled by reading it."
            )
    return findings


def main(argv: list[str]) -> int:
    config: str | None = None
    args: list[str] = []
    it = iter(argv)
    for a in it:
        if a == "--config":
            config = next(it, None)
        else:
            args.append(a)
    cfg = _config.load(config)
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        print("check_claims: no spec_graph_*.yaml found", file=sys.stderr)
        return 0
    findings = [f for p in paths for f in check(p)]
    for f in findings:
        print(f"  INSTRUMENT {f}")
    print(f"\n[check_claims] {len(findings)} claim-instrument finding(s) over {len(paths)} graph(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
