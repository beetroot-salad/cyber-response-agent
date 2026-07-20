#!/usr/bin/env python3
"""spec-graph check #8 — formal-slot validation against schema.md's closed vocabularies.

schema.md's slot discipline: every formal slot draws from a closed vocabulary, every
semantic slot is an `nl:` sentence, and nothing in between. Until this linter, the
closed-vocabulary check was a hand pass recorded per run in `handoff.deviations`
(rules.md, "The artifact"); this is that pass, mechanical. A value outside its
vocabulary is either a typo (fix it) or a vocabulary the schema must deliberately grow
(rare, demand-driven — grow schema.md and this table together, one commit).

Checked: top-level and structure keys; demand kind/form vocabularies and the
form-conditional fields (a `form: test` demand is a pointer — `discharged_by`, no
`outcome`; clause/waiver carry `outcome.nl`); actor/edge/facet vocabularies; unique
demand and claim ids; gate entries referencing rules R0–R6 and demands that exist.
NOT checked here: address resolution and rule triggers (check_gate), prose⊄binds
(check_binds), claim instruments (check_claims), test existence (check_binds).

Usage:
    spec-graph lint [graph.yaml ...] [--config <path>]
Exit codes: 0 clean, 1 findings, 2 a graph could not be read/parsed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

import _config

_TOP = {"schema_version", "design", "base", "demands", "structure", "claims", "gate",
        "handoff", "binds_waivers", "exercise_waivers", "actor_waivers"}
_STRUCTURE = {"axes", "actors", "boundaries", "interacts", "drives"}
_KINDS = {"behavior", "seam", "shape", "uniqueness", "parity", "domain-outcome",
          "survival", "negative"}
_FORMS = {"clause", "test", "waiver"}
_FRAMES = {"leg", "composition"}
_PROVENANCE = {"design", "code"}
_MODES = {"invoke", "read", "write", "remove"}
_MULTIPLICITY = {"serial", "concurrent"}
_FACETS = {"payload", "identity", "domain", "access"}
_SHARING = {"unique-key", "serialized-append"}
_TRUST = {"operator", "attacker-influenced", "derived"}
_PAYLOAD_INVARIANTS = {"roles-disjoint-sources", "all-slots-bound"}
_RULES = {"R0", "R1", "R2", "R3", "R4", "R5", "R6"}
_HANDOFF = {"forks", "refuted", "deferred", "drops", "nullstub_passes", "deviations"}
_GATE = {"evaluated", "obligations", "holes", "pre_discharged"}


def _vocab(findings: list[str], where: str, field: str, value, allowed: set) -> None:
    if value not in allowed:
        findings.append(f"{where}: `{field}: {value}` is not one of {sorted(allowed)}.")


def _mappings(findings: list[str], n: str, label: str, entries) -> list[dict]:
    """A linter lints the malformed shape instead of dying on it: a bare string (or any
    non-mapping) where schema.md declares a mapping entry is a SLOT finding naming the
    entry — uncaught, it surfaced as an AttributeError traceback behind exit 1."""
    kept: list[dict] = []
    for entry in entries or []:
        if isinstance(entry, dict):
            kept.append(entry)
        else:
            findings.append(
                f"{n}: {label} entry `{entry}` is a {type(entry).__name__}, not a mapping."
            )
    return kept


def check(path: Path) -> list[str]:
    graph = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(graph, dict):
        # Valid YAML, wrong shape — exit 2 ("could not read"), not an AttributeError
        # traceback behind exit 1 ("found findings").
        raise TypeError(f"top level is a {type(graph).__name__}, not a mapping")
    n = path.name
    findings: list[str] = []
    for k in set(graph) - _TOP:
        findings.append(f"{n}: unknown top-level key `{k}` (schema.md, 'The artifact').")
    if graph.get("schema_version") != 1:
        findings.append(f"{n}: schema_version `{graph.get('schema_version')}` (expected 1).")
    for field in ("design", "base"):
        if not graph.get(field):
            findings.append(f"{n}: `{field}` is missing — write-code-from-spec's gate reads it.")

    demand_ids: set[str] = set()
    for d in _mappings(findings, n, "demands", graph.get("demands")):
        did = d.get("id")
        where = f"{n}:{did or '<no-id>'}"
        if not did:
            findings.append(f"{where}: demand with no `id`.")
        elif did in demand_ids:
            findings.append(f"{where}: duplicate demand id.")
        demand_ids.add(did)
        _vocab(findings, where, "kind", d.get("kind"), _KINDS)
        form = d.get("form", "test")
        _vocab(findings, where, "form", form, _FORMS)
        binds = d.get("binds")
        if not binds:
            findings.append(f"{where}: `binds` is empty — a demand must bind ≥1 address.")
        elif not isinstance(binds, list):
            # A truthy scalar passed the emptiness check, then check_gate iterated the
            # string per-character — binds must be a list of addresses.
            findings.append(f"{where}: `binds` must be a list of addresses, not a "
                            f"{type(binds).__name__}.")
        if "executable" in d and d["executable"] != (form == "test"):
            findings.append(
                f"{where}: `executable: {d['executable']}` contradicts form `{form}` — it is "
                f"derived (form == test), never set independently."
            )
        outcome_nl = ((d.get("outcome") or {}).get("nl") or "").strip() \
            if isinstance(d.get("outcome"), dict) else ""
        if form == "test":
            if not d.get("discharged_by"):
                findings.append(f"{where}: form:test demand carries no `discharged_by` pointer.")
            if d.get("outcome") is not None:
                findings.append(
                    f"{where}: form:test demand inlines an `outcome` — the prose lives in the "
                    f"pointed-to test's docstring (the test IS the executable form)."
                )
        else:
            if not outcome_nl:
                findings.append(f"{where}: form:{form} demand has no `outcome: {{nl: …}}` sentence.")
            if d.get("discharged_by"):
                findings.append(f"{where}: form:{form} demand names a `discharged_by` — only "
                                f"form:test points at a test.")

    structure = graph.get("structure", {}) or {}
    for k in set(structure) - _STRUCTURE:
        findings.append(f"{n}: unknown structure key `{k}`.")
    for a in _mappings(findings, n, "actors", structure.get("actors")):
        where = f"{n}:actor {a.get('id', '<no-id>')}"
        _vocab(findings, where, "frame", a.get("frame"), _FRAMES)
        _vocab(findings, where, "provenance", a.get("provenance"), _PROVENANCE)
    for b in _mappings(findings, n, "boundaries", structure.get("boundaries")):
        where = f"{n}:boundary {b.get('id', '<no-id>')}"
        _vocab(findings, where, "provenance", b.get("provenance"), _PROVENANCE)
        facets = b.get("facets")
        if facets is None or not isinstance(facets, dict):
            findings.append(f"{where}: `facets` must be a mapping (may be {{}}).")
            continue
        for k in set(facets) - _FACETS:
            findings.append(f"{where}: unknown facet `{k}`.")
        payload = facets.get("payload") or {}
        for inv in payload.get("invariants", []) or []:
            _vocab(findings, f"{where}.payload", "invariants member", inv, _PAYLOAD_INVARIANTS)
        identity = facets.get("identity") or {}
        if identity:
            _vocab(findings, f"{where}.identity", "sharing", identity.get("sharing"), _SHARING)
            for der in identity.get("derivations", []) or []:
                if not isinstance((der or {}).get("injective"), bool):
                    findings.append(
                        f"{where}.identity: derivation `{(der or {}).get('value')}` needs "
                        f"`injective: true|false` — R2's coverage predicate reads it."
                    )
        domain = facets.get("domain") or {}
        if domain:
            fv = domain.get("falsy_valid")
            if fv is not None and not isinstance(fv, bool):
                findings.append(f"{where}.domain: `falsy_valid: {fv}` must be true|false.")
            # The YAML scalar trap: an unquoted `off`/`no`/`true`/`null` member parses as
            # bool/None, and check_gate's address matching stringifies it to `True`/`None` —
            # the cell the author meant can then never be bound. Quote the intended string.
            for v in domain.get("distinguished", []) or []:
                if isinstance(v, bool) or v is None:
                    findings.append(
                        f"{where}.domain: distinguished member `{v}` parsed as YAML "
                        f"{type(v).__name__} — quote the intended string."
                    )
            for alt in domain.get("documented_alternatives", []) or []:
                av = (alt or {}).get("value")
                if isinstance(av, bool) or av is None:
                    findings.append(
                        f"{where}.domain: alternative value `{av}` parsed as YAML "
                        f"{type(av).__name__} — quote the intended string."
                    )
                cv = (alt or {}).get("crosses_validation")
                if cv not in (True, False, "unknown"):
                    findings.append(
                        f"{where}.domain: alternative `{(alt or {}).get('value')}` needs "
                        f"`crosses_validation: true|false|unknown`."
                    )
        access = facets.get("access") or {}
        for via, cell in (access.get("constraints_by_via") or {}).items():
            _vocab(findings, f"{where}.access[{via}]", "trust", (cell or {}).get("trust"), _TRUST)
            cons = (cell or {}).get("constraints")
            if not (cons == "unknown" or isinstance(cons, list)):
                findings.append(
                    f"{where}.access[{via}]: `constraints` must be a list or `unknown` "
                    f"(an explicit confession, never a silent null)."
                )
    for e in _mappings(findings, n, "interacts", structure.get("interacts")):
        where = f"{n}:interacts({e.get('from')}->{e.get('to')})"
        _vocab(findings, where, "mode", e.get("mode"), _MODES)
        _vocab(findings, where, "provenance", e.get("provenance"), _PROVENANCE)
        if not e.get("via"):
            findings.append(f"{where}: no `via` — the per-repo vocabulary is open, empty is not.")
    for e in _mappings(findings, n, "drives", structure.get("drives")):
        where = f"{n}:drives({e.get('from')}->{e.get('to')})"
        _vocab(findings, where, "multiplicity", e.get("multiplicity"), _MULTIPLICITY)
        _vocab(findings, where, "provenance", e.get("provenance"), _PROVENANCE)

    claim_ids: set[str] = set()
    for c in graph.get("claims", []) or []:
        cid = c.get("id")
        if not cid:
            findings.append(f"{n}: claim with no `id` — nothing downstream can cite it.")
        elif cid in claim_ids:
            findings.append(f"{n}:{cid}: duplicate claim id.")
        claim_ids.add(cid)
        # kind/verdict/probe_kind vocabularies are check_claims' — one source, not two.

    gate = graph.get("gate", {}) or {}
    for k in set(gate) - _GATE:
        findings.append(f"{n}: unknown gate key `{k}`.")
    for entry in _mappings(findings, n, "gate.evaluated", gate.get("evaluated")):
        where = f"{n}:gate.evaluated"
        _vocab(findings, where, "rule", entry.get("rule"), _RULES)
        if not isinstance(entry.get("fired"), bool):
            findings.append(f"{where}: {entry.get('rule')} `fired: {entry.get('fired')}` "
                            f"must be true|false.")
    for section, ref_field in (("obligations", "discharged_by"), ("pre_discharged", "by")):
        for entry in _mappings(findings, n, f"gate.{section}", gate.get(section)):
            _vocab(findings, f"{n}:gate.{section}", "rule", entry.get("rule"), _RULES)
            ref = entry.get(ref_field)
            if not ref:
                # rules.md declares the shape WITH the pointer — a bare entry still counts
                # as "the gate saw this element" in check_gate, so an entry pointing at no
                # demand is a silencer, not a discharge.
                findings.append(
                    f"{n}:gate.{section}: entry for `{entry.get('element')}` carries no "
                    f"`{ref_field}` — the shape requires the demand pointer."
                )
            elif ref not in demand_ids:
                findings.append(
                    f"{n}:gate.{section}: `{ref_field}: {ref}` names no demand in this graph."
                )
    for entry in _mappings(findings, n, "gate.holes", gate.get("holes")):
        _vocab(findings, f"{n}:gate.holes", "rule", entry.get("rule"), _RULES)
        rt = entry.get("resolved_to")
        if rt and rt not in demand_ids:
            findings.append(f"{n}:gate.holes: `resolved_to: {rt}` names no demand.")

    for k in set(graph.get("handoff", {}) or {}) - _HANDOFF:
        findings.append(f"{n}: unknown handoff key `{k}`.")
    return findings


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
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
        print("check_lint: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    all_findings: list[str] = []
    unreadable: list[Path] = []
    for p in paths:
        try:
            all_findings.extend(check(p))
        # AttributeError is the backstop for nested wrong shapes the per-list tolerance
        # above does not cover — the same could-not-read class as a bad top level, never
        # a traceback behind exit 1. Collected, not returned on: bailing here threw away
        # every finding the already-linted graphs produced.
        except (OSError, yaml.YAMLError, TypeError, AttributeError) as e:
            print(f"check_lint: cannot read {p}: {e.__class__.__name__}: {e}", file=sys.stderr)
            unreadable.append(p)
            continue
    for f in all_findings:
        print(f"  SLOT {f}")
    print(f"\n[check_lint] {len(all_findings)} formal-slot finding(s) over {len(paths)} graph(s).")
    if unreadable:
        return 2
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
