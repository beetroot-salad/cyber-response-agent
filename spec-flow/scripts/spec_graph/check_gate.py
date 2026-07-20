#!/usr/bin/env python3
"""spec-graph check #4 — compute the gate's rule triggers from the formal slots.

rules.md defines R1–R5 as predicates over formal slots; this check evaluates those
predicates mechanically, so the gate leaf annotates computed firings instead of
re-deriving them by prompt. What stays with the agent is exactly what the rules flag
as judgment: R0's bidirectional prose reconciliation, R5's tightening extension, and
R6's chooser/sanitizer walk. The tool still *requires* their `gate.evaluated` entries,
so a judgment rule nobody ran reads as skipped, never as clean.

Three outputs, one artifact:

* **findings** (default) — a computed trigger with no recorded answer: no demand binds
  the obligated address, and no `gate.obligations`/`holes`/`pre_discharged` entry
  records the hit. Plus the consistency arm: `gate.evaluated` marks a rule
  `fired: false` that the slots say fired, or omits a rule entirely.
* **R0 formal half** — a `binds:` address resolving to nothing in the structure, an
  `unknown` invariant field with no matching hole, a `key_axes`/`interpolates` member
  outside the `axes:` registry, an edge endpoint no element defines.
* **`--residue`** — the computed triggers as a YAML skeleton (rule, element, reason),
  for the phase-D annotator to fill with witnesses and route. Never exits 1: it is the
  question list, produced before the answers exist.

Delta scoping follows rules.md's Procedure: an element or edge is in the delta when
its `provenance` is `design` (or an edge's `mode` is `remove`); a trigger fires when
any element it reads is in the delta. A graph with no design-provenance element at all
cannot scope, so the whole structure is treated as delta and a WARN says so.

Usage:
    spec-graph gate [graph.yaml ...] [--residue] [--config <path>]
Exit codes: 0 clean, 1 findings, 2 the graph could not be read/parsed (never a
silent pass). `--residue` always exits 0 unless the graph is unreadable.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

import _config

RULES = ("R0", "R1", "R2", "R3", "R4", "R5", "R6")
#: The halves no slot predicate computes; their `evaluated` entry is demanded, not derived.
JUDGMENT = {
    "R0": "the bidirectional prose reconciliation (design sentence ↔ element)",
    "R5": "the tightening/safe-by-construction extension",
    "R6": "the rendered-sink chooser/sanitizer walk",
}

_INTERACTS = re.compile(r"^interacts\(\s*([\w.-]+)\s*->\s*([\w.-]+)\s*\)(\.\w+)?$")
_DRIVES = re.compile(r"^drives\(\s*([\w.-]+)\s*->\s*([\w.-]+)\s*\)$")
_CELL = re.compile(r"^([\w.-]+)\.(domain\.(?:distinguished|alternatives)|access)\[(.*)\]$")
_FACET = re.compile(r"^([\w.-]+)\.(payload|identity|domain|access)$")


class Trigger:
    """One computed rule hit: the rule, the obligated address, and why it fired."""

    def __init__(self, rule: str, element: str, reason: str) -> None:
        self.rule, self.element, self.reason = rule, element, reason


class Graph:
    def __init__(self, path: Path) -> None:
        self.path = path
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            # Valid YAML, wrong shape. Without this the first `.get` raised AttributeError,
            # which `main` does not catch — so a malformed artifact exited 1 ("found findings")
            # behind a traceback instead of 2 ("could not read").
            raise TypeError(f"top level is a {type(raw).__name__}, not a mapping")
        self.demands: list[dict] = raw.get("demands", []) or []
        structure = raw.get("structure", {}) or {}
        self.axes: list[str] = structure.get("axes", []) or []
        self.actors: dict[str, dict] = {a.get("id"): a for a in structure.get("actors", []) or []}
        self.boundaries: dict[str, dict] = {
            b.get("id"): b for b in structure.get("boundaries", []) or []
        }
        self.interacts: list[dict] = structure.get("interacts", []) or []
        self.drives: list[dict] = structure.get("drives", []) or []
        gate = raw.get("gate", {}) or {}
        self.evaluated: dict[str, object] = {
            e.get("rule"): e.get("fired") for e in gate.get("evaluated", []) or []
        }
        # Every recorded answer, keyed by rule: an obligation, a hole, or a pre-discharge
        # all count as "the gate saw this element" — routing is the agent's, not ours.
        self.recorded: dict[str, list[str]] = {}
        for section in ("obligations", "holes", "pre_discharged"):
            for entry in gate.get(section, []) or []:
                self.recorded.setdefault(str(entry.get("rule")), []).append(
                    str(entry.get("element", ""))
                )

    def facet(self, boundary: str, name: str) -> dict | None:
        b = self.boundaries.get(boundary)
        facets = (b or {}).get("facets") or {}
        f = facets.get(name)
        return f if isinstance(f, dict) else None

    def in_delta(self, *elements: dict | None) -> bool:
        return any(e is not None and e.get("provenance") == "design" for e in elements)

    def answered(self, rule: str, element: str) -> bool:
        """Whether the graph records an answer for a computed trigger: an executable demand
        binds the obligated address, or a gate entry for the rule names it. Per-cell
        addresses (`b.access[via]`, `b.domain.…[v]`) must match exactly — per-cell discharge
        is the discipline R3/R4 exist for; coarser addresses accept a facet-or-root match."""
        exact = _CELL.match(element) is not None
        root = _root(element)
        for d in self.demands:
            if d.get("form", "test") != "test":
                continue
            for b in d.get("binds", []) or []:
                b = str(b)
                if b == element or (not exact and _root(b) == root):
                    return True
        for rec in self.recorded.get(rule, []):
            if rec == element or (not exact and _root(rec) == root):
                return True
        return False


def _root(address: str) -> str:
    m = _INTERACTS.match(address) or _DRIVES.match(address)
    if m:
        return m.group(2)  # the boundary/target end — what the obligation is about
    return re.split(r"[.\[]", address, maxsplit=1)[0].strip()


def _resolves(g: Graph, address: str) -> bool:
    """Whether a `binds:` address names something in structure ∪ delta (schema.md forms)."""
    address = str(address)
    m = _INTERACTS.match(address)
    if m:
        return any(
            e.get("from") == m.group(1) and e.get("to") == m.group(2) for e in g.interacts
        )
    m = _DRIVES.match(address)
    if m:
        return any(
            e.get("from") == m.group(1) and e.get("to") == m.group(2) for e in g.drives
        )
    m = _CELL.match(address)
    if m:
        bid, slot, member = m.groups()
        if slot == "access":
            f = g.facet(bid, "access")
            return f is not None and member in (f.get("constraints_by_via") or {})
        f = g.facet(bid, "domain")
        if f is None:
            return False
        if slot.endswith("distinguished"):
            return any(str(v) == member for v in f.get("distinguished") or [])
        return any(
            str((a or {}).get("value")) == member for a in f.get("documented_alternatives") or []
        )
    m = _FACET.match(address)
    if m:
        return g.facet(m.group(1), m.group(2)) is not None
    return address in g.actors or address in g.boundaries


def _covered(axis: str, interpolates: list, identity: dict) -> bool:
    """R2 key coverage: the axis itself is interpolated, or an injective derivation of it is.
    `injective: false` does NOT cover its axis (rules.md R2a)."""
    if axis in interpolates:
        return True
    return any(
        (d or {}).get("fn_of") == axis
        and (d or {}).get("value") in interpolates
        and (d or {}).get("injective") is True
        for d in identity.get("derivations") or []
    )


def _r0(g: Graph) -> list[str]:
    """The formal half of R0. Findings, not triggers: each names the artifact defect
    directly — there is no obligation to mint, the graph itself is ill-formed."""
    findings: list[str] = []
    for d in g.demands:
        did = d.get("id", "<no-id>")
        for b in d.get("binds", []) or []:
            if not _resolves(g, str(b)):
                findings.append(
                    f"R0 {g.path.name}:{did}: binds `{b}` resolves to nothing in structure — "
                    f"a dangling address (extraction gap or phantom design)."
                )
    for kind, edges, targets in (
        ("interacts", g.interacts, g.boundaries),
        ("drives", g.drives, g.actors),
    ):
        for e in edges:
            src, dst = e.get("from"), e.get("to")
            if src not in g.actors:
                findings.append(
                    f"R0 {g.path.name}: {kind}({src}->{dst}) — `from: {src}` names no actor."
                )
            if dst not in targets:
                findings.append(
                    f"R0 {g.path.name}: {kind}({src}->{dst}) — `to: {dst}` names no "
                    f"{'boundary' if kind == 'interacts' else 'actor'}."
                )
    axes = set(g.axes)
    for bid in g.boundaries:
        identity = g.facet(bid, "identity") or {}
        for ax in identity.get("key_axes") or []:
            if ax not in axes:
                findings.append(
                    f"R0 {g.path.name}: {bid}.identity.key_axes member `{ax}` is not in the "
                    f"`axes:` registry {sorted(axes)}."
                )
        for d in identity.get("derivations") or []:
            if (d or {}).get("fn_of") not in axes:
                findings.append(
                    f"R0 {g.path.name}: {bid}.identity derivation `{(d or {}).get('value')}` "
                    f"derives from `{(d or {}).get('fn_of')}`, not a registered axis."
                )
        # Keyed on `key_axes`, not on the facet's mere presence: a `sharing: serialized-append`
        # sink legitimately claims NO key, and demanding evidence for it asked the author to
        # justify a key they never asserted.
        if identity.get("key_axes") and not identity.get("evidence"):
            findings.append(
                f"R0 {g.path.name}: {bid}.identity claims key_axes with no `evidence` — "
                f"a claimed key without evidence is treated as unknown (schema.md)."
            )
    for e in g.interacts:
        identity = g.facet(str(e.get("to")), "identity") or {}
        derived = {(d or {}).get("value") for d in identity.get("derivations") or []}
        for ax in e.get("interpolates") or []:
            if ax not in axes and ax not in derived:
                findings.append(
                    f"R0 {g.path.name}: interacts({e.get('from')}->{e.get('to')}) interpolates "
                    f"`{ax}` — neither a registered axis nor a declared derivation."
                )
    # `unknown` invariants are holes to route, not lint errors — but an unknown with no
    # recorded hole is a finding: the confession was made and then nobody heard it.
    for bid in g.boundaries:
        for facet_name, fields in (
            ("access", [("constraints_by_via", "constraints")]),
            ("domain", [("documented_alternatives", "crosses_validation")]),
        ):
            f = g.facet(bid, facet_name)
            if f is None:
                continue
            if facet_name == "access":
                for via, cell in (f.get("constraints_by_via") or {}).items():
                    if (cell or {}).get("constraints") == "unknown":
                        el = f"{bid}.access[{via}]"
                        if not g.answered("R0", el):
                            findings.append(
                                f"R0 {g.path.name}: {el} constraints are `unknown` and no hole "
                                f"records the undecided policy — decide it, then pin it."
                            )
            else:
                for alt in f.get("documented_alternatives") or []:
                    if (alt or {}).get("crosses_validation") == "unknown":
                        el = f"{bid}.domain.alternatives[{(alt or {}).get('value')}]"
                        if not g.answered("R0", el):
                            findings.append(
                                f"R0 {g.path.name}: {el} `crosses_validation` is `unknown` with "
                                f"no recorded hole — grounding establishes the crossing."
                            )
    return findings


def _triggers(g: Graph) -> tuple[list[Trigger], list[str]]:
    """R1–R5 over the formal slots. Returns (triggers, key-coverage findings) — a key gap is
    a direct finding (the slots already contain the answer), not a question to route."""
    delta_scoped = any(
        e.get("provenance") == "design"
        for e in [*g.actors.values(), *g.boundaries.values(), *g.interacts, *g.drives]
    )
    if not delta_scoped:
        print(
            f"  WARN [check_gate] {g.path.name}: no element carries `provenance: design` — "
            f"cannot scope the delta, so every rule fires over the whole structure.",
            file=sys.stderr,
        )

    def in_delta(*elements: dict | None) -> bool:
        return (not delta_scoped) or g.in_delta(*elements)

    triggers: list[Trigger] = []
    coverage: list[str] = []

    # R1 — unread channel: an edge sends into a payload-facet boundary.
    for e in g.interacts:
        if not e.get("sends"):
            continue
        dst = str(e.get("to"))
        # A `sends:` whose target lacks a payload facet is still an outbound channel — the
        # facet's absence is a modeling gap, not a reason to stay quiet about the edge.
        if in_delta(e, g.boundaries.get(dst), g.actors.get(str(e.get("from")))):
            el = f"interacts({e.get('from')}->{dst}).payload"
            triggers.append(Trigger(
                "R1", el,
                f"`{e.get('from')}` sends into `{dst}` — the outbound payload needs an "
                f"executable shape demand or the channel ships unread.",
            ))

    # R2 — shared sink: an identity-facet boundary with ≥2 writers, or a driven writer.
    for bid in g.boundaries:
        identity = g.facet(bid, "identity")
        if identity is None:
            continue
        writers = [e for e in g.interacts if e.get("to") == bid and e.get("mode") == "write"]
        driven = [
            e for e in writers
            if any(d.get("to") == e.get("from") for d in g.drives)
        ]
        fires = len({e.get("from") for e in writers}) >= 2 or bool(driven)
        involved = [g.boundaries.get(bid), *writers, *driven]
        if not fires or not in_delta(*involved):
            continue
        names = sorted({str(e.get("from")) for e in writers})
        triggers.append(Trigger(
            "R2", f"{bid}.identity",
            f"writers {names} share the `{bid}` sink"
            + (" and at least one is driven over multiple invocations" if driven else "")
            + " — a uniqueness demand must drive them into one root at the composition frame.",
        ))
        for e in writers:
            for ax in identity.get("key_axes") or []:
                if _covered(ax, e.get("interpolates") or [], identity):
                    continue
                # A recorded R2 answer on this boundary means the coverage question reached
                # the gate — the demand it minted owns the cross-key assertion from here.
                if g.answered("R2", f"{bid}.identity"):
                    continue
                coverage.append(
                        f"R2 {g.path.name}: writer interacts({e.get('from')}->{bid}) does not "
                        f"cover key axis `{ax}` — its `interpolates` names neither the axis nor "
                        f"an injective derivation of it (a lost-write/cross-read shape)."
                    )

    # R3 — cross-via parity: an access-facet boundary reachable over ≥2 vias.
    for bid in g.boundaries:
        access = g.facet(bid, "access")
        if access is None:
            continue
        vias = access.get("constraints_by_via") or {}
        if len(vias) < 2:
            continue
        edges = [e for e in g.interacts if e.get("to") == bid]
        if not in_delta(g.boundaries.get(bid), *edges):
            continue
        for via in vias:
            triggers.append(Trigger(
                "R3", f"{bid}.access[{via}]",
                f"`{bid}` is reachable over {sorted(vias)} — every constraint the established "
                f"via enforces must hold on the `{via}` cell too (per-cell discharge).",
            ))

    # R4 — domain coverage: a read edge into a domain-facet boundary.
    for bid in g.boundaries:
        domain = g.facet(bid, "domain")
        if domain is None:
            continue
        readers = [e for e in g.interacts if e.get("to") == bid and e.get("mode") == "read"]
        if not readers or not in_delta(g.boundaries.get(bid), *readers):
            continue
        for v in domain.get("distinguished") or []:
            triggers.append(Trigger(
                "R4", f"{bid}.domain.distinguished[{v}]",
                f"distinguished member `{v!r}` must be individually exercised"
                + (
                    " — above all: it is falsy and `falsy_valid` is true, the "
                    "`x or DEFAULT` swallow shape"
                    if not v and domain.get("falsy_valid") is True else ""
                ) + ".",
            ))
        for alt in domain.get("documented_alternatives") or []:
            v = (alt or {}).get("value")
            triggers.append(Trigger(
                "R4", f"{bid}.domain.alternatives[{v}]",
                f"documented alternative `{v}` must be pinned"
                + (
                    " — it crosses validation, so the advertised combination works or "
                    "fails loud"
                    if (alt or {}).get("crosses_validation") is True else ""
                ) + ".",
            ))

    # R5 — subtraction: a `mode: remove` edge whose target has live dependents.
    for e in g.interacts:
        if e.get("mode") != "remove":
            continue
        bid = str(e.get("to"))
        dependents = sorted({
            str(x.get("from")) for x in g.interacts
            if x.get("to") == bid and x.get("mode") != "remove"
        })
        if dependents:
            triggers.append(Trigger(
                "R5", bid,
                f"`{e.get('from')}` removes its edge to `{bid}` while {dependents} still "
                f"depend on it — each dependent's workflow needs a survival demand (or the "
                f"substitute's structural inability is a design hole).",
            ))
    return triggers, coverage


def check(path: Path) -> tuple[list[str], list[Trigger]]:
    g = Graph(path)
    findings = _r0(g)
    triggers, coverage = _triggers(g)
    findings.extend(coverage)
    for rule in RULES:
        if rule not in g.evaluated:
            hint = f" ({JUDGMENT[rule]})" if rule in JUDGMENT else ""
            findings.append(
                f"EVALUATED {path.name}: no `gate.evaluated` entry for {rule}{hint} — "
                f"a rule with no entry reads as skipped, not as clean."
            )
    for t in triggers:
        if g.answered(t.rule, t.element):
            continue
        if g.evaluated.get(t.rule) is False:
            findings.append(
                f"FIRED-FALSE {path.name}: gate.evaluated marks {t.rule} `fired: false`, but "
                f"the slots fire it on `{t.element}` — {t.reason}"
            )
        else:
            findings.append(
                f"UNANSWERED {path.name}: {t.rule} fires on `{t.element}` and the graph records "
                f"no answer — no executable demand binds it, no obligation/hole/pre-discharge "
                f"names it. {t.reason}"
            )
    return findings, triggers


def _residue(path: Path, triggers: list[Trigger]) -> None:
    """The computed question list, as YAML the annotator fills in (witnesses, routes)."""
    print(f"# computed residue skeleton — {path.name}")
    print("# judgment halves NOT computed here: "
          + "; ".join(f"{r}: {w}" for r, w in JUDGMENT.items()))
    out = [
        {"rule": t.rule, "element": t.element, "reason": t.reason, "witness": "<fill>",
         "route": "<obligation | hole | pre_discharged | waiver-candidate>"}
        for t in triggers
    ]
    print(yaml.safe_dump(out, sort_keys=False, allow_unicode=True, width=100))


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    config: str | None = None
    residue = False
    args: list[str] = []
    it = iter(argv)
    for a in it:
        if a == "--config":
            config = next(it, None)
        elif a == "--residue":
            residue = True
        else:
            args.append(a)
    cfg = _config.load(config)
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        print("check_gate: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    all_findings: list[str] = []
    for p in paths:
        try:
            findings, triggers = check(p)
        except (OSError, yaml.YAMLError, TypeError) as e:
            # Never a silent pass: a graph the gate cannot read must not certify clean.
            print(f"check_gate: cannot read {p}: {e.__class__.__name__}: {e}", file=sys.stderr)
            return 2
        if residue:
            _residue(p, triggers)
        else:
            all_findings.extend(findings)
    if residue:
        return 0
    for f in all_findings:
        print(f"  {f}")
    print(f"\n[check_gate] {len(all_findings)} finding(s) over {len(paths)} graph(s).")
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
