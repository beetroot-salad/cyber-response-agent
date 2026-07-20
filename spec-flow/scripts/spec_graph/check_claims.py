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

THE SPEND-POINT PASS (same run): rules.md's "a spend-point closes only by citation", as a
field — `cites: [<claim id>, ...]`. Any `cites` anywhere in the gate block or on a demand
must resolve to a claim that exists and was probed (`holds | refuted | unrefuted`) — a
citation of an `unprobed`/`deferred` claim rests on nothing executed. `cites` is REQUIRED
on: a `fired: false` for a judgment rule (R0, R5, R6 — where no slot predicate computed the
no; `spec-graph gate` verifies the computed rules' `fired` flags against the slots), every
`pre_discharged` credit, and every `form: waiver` demand. The `binds_waivers` /
`exercise_waivers` / `actor_waivers` maps cannot carry a `cites` without a shape change
check_binds/check_actors would trip over — those citations stay a phase-F hand check.

Usage:
    spec-graph claims [graph.yaml ...] [--config <path>]
(the `spec-graph` wrapper in the plugin's bin/ is on the Bash PATH and finds this script itself.)
Exit 1 if any claim's instrument is wrong or missing, or any spend-point citation is
missing, dangling, or unprobed.
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
#: fired:false here rests on an agent's reading, not a slot predicate — it must cite.
_JUDGMENT_RULES = {"R0", "R5", "R6"}


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        graph = yaml.safe_load(fh) or {}
    if not isinstance(graph, dict):
        # Valid YAML, wrong shape — a caught error (exit 2, "could not read"), not an
        # AttributeError traceback behind exit 1 ("found findings").
        raise TypeError(f"top level is a {type(graph).__name__}, not a mapping")
    return graph


def _cited(entry: dict) -> list[str]:
    c = entry.get("cites")
    if c is None:
        return []
    return [str(x) for x in c] if isinstance(c, list) else [str(c)]


def check_spend_points(path: Path, graph: dict | None = None) -> list[str]:
    graph = _load(path) if graph is None else graph
    # Ids coerced with str() to match `_cited`, which stringifies every citation — an
    # int-keyed ledger made `cites: [12]` dangle against the claim it names.
    verdicts = {
        str(c.get("id")): c.get("verdict")
        for c in graph.get("claims", []) or []
        if c.get("id") is not None
    }
    findings: list[str] = []

    def resolve(where: str, entry: dict, required: str | None = None) -> None:
        ids = _cited(entry)
        if not ids and required:
            findings.append(
                f"{path.name}:{where}: {required} closes with no `cites` — an uncited "
                f"rationale is asserted, a finding, not a pass (rules.md, 'Probed claims')."
            )
        for cid in ids:
            if cid not in verdicts:
                findings.append(f"{path.name}:{where}: cites `{cid}`, which is no claim in "
                                f"this graph's ledger.")
            elif verdicts[cid] not in _PROBED:
                findings.append(
                    f"{path.name}:{where}: cites `{cid}` (verdict `{verdicts[cid]}`) — a "
                    f"spend-point resting on a claim nothing has probed."
                )

    gate = graph.get("gate", {}) or {}
    for e in gate.get("evaluated", []) or []:
        rule = str(e.get("rule"))
        need = (f"judgment rule {rule} `fired: false`"
                if e.get("fired") is False and rule in _JUDGMENT_RULES else None)
        resolve(f"gate.evaluated[{rule}]", e, need)
    for e in gate.get("pre_discharged", []) or []:
        resolve(f"gate.pre_discharged[{e.get('element')}]", e, "a pre-discharge credit")
    for e in gate.get("obligations", []) or []:
        resolve(f"gate.obligations[{e.get('element')}]", e)
    for e in gate.get("holes", []) or []:
        # A hole that spawned a demand (`resolved_to`) closes through that demand; one
        # closed by judgment alone ("unreachable", "out of scope") is a spend-point —
        # rules.md: it closes only by citation.
        need = ("a hole resolved with no spawned demand"
                if e.get("resolution") and not e.get("resolved_to") else None)
        resolve(f"gate.holes[{e.get('element')}]", e, need)
    for d in graph.get("demands", []) or []:
        if d.get("form") == "waiver":
            resolve(f"demand {d.get('id')}", d, "a waiver's rationale")
        else:
            resolve(f"demand {d.get('id')}", d)
    return findings


def check(path: Path, graph: dict | None = None) -> list[str]:
    findings: list[str] = []
    for c in (_load(path) if graph is None else graph).get("claims", []) or []:
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
        # 2, not 0: the whole toolchain's contract (verify.md) is 2 = could not look —
        # a run with nothing to check must not read as clean.
        print("check_claims: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    findings: list[str] = []
    spend: list[str] = []
    unreadable: list[Path] = []
    for p in paths:
        # Parsed ONCE and handed to both passes: the two used to load the same graph
        # independently, doubling every read and parse. Both passes run INSIDE the try —
        # nested wrong shapes (a string where a mapping belongs) surface as AttributeError
        # mid-walk, the same could-not-read class as a bad top level.
        try:
            graph = _load(p)
            findings.extend(check(p, graph))
            spend.extend(check_spend_points(p, graph))
        except (OSError, yaml.YAMLError, TypeError, AttributeError) as e:
            # Collected, not returned on: bailing here threw away every finding the
            # already-checked graphs produced.
            print(f"check_claims: cannot read {p}: {e.__class__.__name__}: {e}", file=sys.stderr)
            unreadable.append(p)
            continue
    for f in findings:
        print(f"  INSTRUMENT {f}")
    for f in spend:
        print(f"  CITATION {f}")
    # Counted by kind: an instrument mismatch and an uncited spend-point are different slips.
    print(f"\n[check_claims] {len(findings)} claim-instrument finding(s), {len(spend)} "
          f"spend-point citation finding(s) over {len(paths)} graph(s).")
    if unreadable:
        return 2
    return 1 if findings or spend else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
