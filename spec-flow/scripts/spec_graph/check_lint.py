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

import _cli
import _config
import _schema

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
_RULES = set(_schema.RULES)
_HANDOFF = {"forks", "refuted", "deferred", "drops", "nullstub_passes", "deviations"}
_GATE = {"evaluated", "obligations", "holes", "pre_discharged"}


class _Lint:
    """The accumulator every `_rule_*` below appends to.

    schema.md's slots are independent of each other, so this check is a LIST of rules
    over one graph rather than one walk: each rule reads the slots it owns and appends
    its own findings, and `check` is just the order they run in. Exactly one value
    crosses rules — `demand_ids`, filled by `_rule_demands` and read by the gate rules
    that must resolve a pointer to a demand — and `_RULES`' order is what guarantees it
    is populated first.

    Sections are read through `section()` at the point of use rather than unpacked in
    `__init__`, so a section holding the wrong shape (`structure:` as a scalar) surfaces
    from the rule that owns it instead of from the constructor, before any rule has run.
    """

    def __init__(self, path: Path) -> None:
        self.graph = _cli.load_graph(path)
        self.n = path.name
        self.findings: list[str] = []
        self.demand_ids: set[str] = set()

    def add(self, message: str) -> None:
        self.findings.append(message)

    def section(self, key: str) -> dict:
        """A top-level mapping section, tolerant of both an absent and a null slot."""
        return self.graph.get(key, {}) or {}

    def vocab(self, where: str, field: str, value, allowed: set) -> None:
        if value not in allowed:
            self.add(f"{where}: `{field}: {value}` is not one of {sorted(allowed)}.")

    def mappings(self, label: str, entries) -> list[dict]:
        """A linter lints the malformed shape instead of dying on it: a bare string (or any
        non-mapping) where schema.md declares a mapping entry is a SLOT finding naming the
        entry — uncaught, it surfaced as an AttributeError traceback behind exit 1."""
        kept: list[dict] = []
        for entry in entries or []:
            if isinstance(entry, dict):
                kept.append(entry)
            else:
                self.add(
                    f"{self.n}: {label} entry `{entry}` is a "
                    f"{type(entry).__name__}, not a mapping."
                )
        return kept


def _rule_top_level(lint: _Lint) -> None:
    for k in set(lint.graph) - _TOP:
        lint.add(f"{lint.n}: unknown top-level key `{k}` (schema.md, 'The artifact').")
    if lint.graph.get("schema_version") != 1:
        lint.add(
            f"{lint.n}: schema_version `{lint.graph.get('schema_version')}` (expected 1)."
        )
    for field in ("design", "base"):
        if not lint.graph.get(field):
            lint.add(
                f"{lint.n}: `{field}` is missing — write-code-from-spec's gate reads it."
            )


def _rule_demands(lint: _Lint) -> None:
    """Demand ids, the kind/form vocabularies, and the `binds` shape. Also fills
    `lint.demand_ids` — the gate rules resolve their pointers against it."""
    for d in lint.mappings("demands", lint.graph.get("demands")):
        did = d.get("id")
        where = f"{lint.n}:{did or '<no-id>'}"
        if not did:
            lint.add(f"{where}: demand with no `id`.")
        elif did in lint.demand_ids:
            lint.add(f"{where}: duplicate demand id.")
        lint.demand_ids.add(did)
        lint.vocab(where, "kind", d.get("kind"), _KINDS)
        form = d.get("form", "test")
        lint.vocab(where, "form", form, _FORMS)
        binds = d.get("binds")
        if not binds:
            lint.add(f"{where}: `binds` is empty — a demand must bind ≥1 address.")
        elif not isinstance(binds, list):
            # A truthy scalar passed the emptiness check, then check_gate iterated the
            # string per-character — binds must be a list of addresses.
            lint.add(f"{where}: `binds` must be a list of addresses, not a "
                     f"{type(binds).__name__}.")
        if "executable" in d and d["executable"] != (form == "test"):
            lint.add(
                f"{where}: `executable: {d['executable']}` contradicts form `{form}` — it is "
                f"derived (form == test), never set independently."
            )
        _demand_form(lint, where, d, form)


def _demand_form(lint: _Lint, where: str, d: dict, form: str) -> None:
    """The form-conditional half: a `form: test` demand is a POINTER (`discharged_by`, no
    inlined `outcome`); clause/waiver carry the `outcome.nl` sentence and point at nothing."""
    outcome_nl = ((d.get("outcome") or {}).get("nl") or "").strip() \
        if isinstance(d.get("outcome"), dict) else ""
    if form == "test":
        if not d.get("discharged_by"):
            lint.add(f"{where}: form:test demand carries no `discharged_by` pointer.")
        if d.get("outcome") is not None:
            lint.add(
                f"{where}: form:test demand inlines an `outcome` — the prose lives in the "
                f"pointed-to test's docstring (the test IS the executable form)."
            )
    else:
        if not outcome_nl:
            lint.add(f"{where}: form:{form} demand has no `outcome: {{nl: …}}` sentence.")
        if d.get("discharged_by"):
            lint.add(f"{where}: form:{form} demand names a `discharged_by` — only "
                     f"form:test points at a test.")


def _rule_structure_keys(lint: _Lint) -> None:
    for k in set(lint.section("structure")) - _STRUCTURE:
        lint.add(f"{lint.n}: unknown structure key `{k}`.")


def _rule_actors(lint: _Lint) -> None:
    for a in lint.mappings("actors", lint.section("structure").get("actors")):
        where = f"{lint.n}:actor {a.get('id', '<no-id>')}"
        lint.vocab(where, "frame", a.get("frame"), _FRAMES)
        lint.vocab(where, "provenance", a.get("provenance"), _PROVENANCE)


def _rule_boundaries(lint: _Lint) -> None:
    for b in lint.mappings("boundaries", lint.section("structure").get("boundaries")):
        where = f"{lint.n}:boundary {b.get('id', '<no-id>')}"
        lint.vocab(where, "provenance", b.get("provenance"), _PROVENANCE)
        facets = b.get("facets")
        if not isinstance(facets, dict):
            lint.add(f"{where}: `facets` must be a mapping (may be {{}}).")
            continue
        for k in set(facets) - _FACETS:
            lint.add(f"{where}: unknown facet `{k}`.")
        _facet_payload(lint, where, facets.get("payload") or {})
        _facet_identity(lint, where, facets.get("identity") or {})
        _facet_domain(lint, where, facets.get("domain") or {})
        _facet_access(lint, where, facets.get("access") or {})


def _facet_payload(lint: _Lint, where: str, payload: dict) -> None:
    for inv in payload.get("invariants", []) or []:
        lint.vocab(f"{where}.payload", "invariants member", inv, _PAYLOAD_INVARIANTS)


def _facet_identity(lint: _Lint, where: str, identity: dict) -> None:
    if not identity:
        return
    lint.vocab(f"{where}.identity", "sharing", identity.get("sharing"), _SHARING)
    for der in identity.get("derivations", []) or []:
        if not isinstance((der or {}).get("injective"), bool):
            lint.add(
                f"{where}.identity: derivation `{(der or {}).get('value')}` needs "
                f"`injective: true|false` — R2's coverage predicate reads it."
            )


def _facet_domain(lint: _Lint, where: str, domain: dict) -> None:
    if not domain:
        return
    fv = domain.get("falsy_valid")
    if fv is not None and not isinstance(fv, bool):
        lint.add(f"{where}.domain: `falsy_valid: {fv}` must be true|false.")
    # The YAML scalar trap: an unquoted `off`/`no`/`true`/`null` member parses as
    # bool/None, and check_gate's address matching stringifies it to `True`/`None` —
    # the cell the author meant can then never be bound. Quote the intended string.
    for v in domain.get("distinguished", []) or []:
        if isinstance(v, bool) or v is None:
            lint.add(
                f"{where}.domain: distinguished member `{v}` parsed as YAML "
                f"{type(v).__name__} — quote the intended string."
            )
    for alt in domain.get("documented_alternatives", []) or []:
        _domain_alternative(lint, where, alt or {})


def _domain_alternative(lint: _Lint, where: str, alt: dict) -> None:
    av = alt.get("value")
    if isinstance(av, bool) or av is None:
        lint.add(
            f"{where}.domain: alternative value `{av}` parsed as YAML "
            f"{type(av).__name__} — quote the intended string."
        )
    cv = alt.get("crosses_validation")
    if cv not in (True, False, "unknown"):
        lint.add(
            f"{where}.domain: alternative `{alt.get('value')}` needs "
            f"`crosses_validation: true|false|unknown`."
        )


def _facet_access(lint: _Lint, where: str, access: dict) -> None:
    for via, cell in (access.get("constraints_by_via") or {}).items():
        lint.vocab(f"{where}.access[{via}]", "trust", (cell or {}).get("trust"), _TRUST)
        cons = (cell or {}).get("constraints")
        if not (cons == "unknown" or isinstance(cons, list)):
            lint.add(
                f"{where}.access[{via}]: `constraints` must be a list or `unknown` "
                f"(an explicit confession, never a silent null)."
            )


def _rule_interacts(lint: _Lint) -> None:
    for e in lint.mappings("interacts", lint.section("structure").get("interacts")):
        where = f"{lint.n}:interacts({e.get('from')}->{e.get('to')})"
        lint.vocab(where, "mode", e.get("mode"), _MODES)
        lint.vocab(where, "provenance", e.get("provenance"), _PROVENANCE)
        if not e.get("via"):
            lint.add(f"{where}: no `via` — the per-repo vocabulary is open, empty is not.")


def _rule_drives(lint: _Lint) -> None:
    for e in lint.mappings("drives", lint.section("structure").get("drives")):
        where = f"{lint.n}:drives({e.get('from')}->{e.get('to')})"
        lint.vocab(where, "multiplicity", e.get("multiplicity"), _MULTIPLICITY)
        lint.vocab(where, "provenance", e.get("provenance"), _PROVENANCE)


def _rule_claims(lint: _Lint) -> None:
    # kind/verdict/probe_kind vocabularies are check_claims' — one source, not two.
    claim_ids: set[str] = set()
    for c in lint.graph.get("claims", []) or []:
        cid = c.get("id")
        if not cid:
            lint.add(f"{lint.n}: claim with no `id` — nothing downstream can cite it.")
        elif cid in claim_ids:
            lint.add(f"{lint.n}:{cid}: duplicate claim id.")
        claim_ids.add(cid)


def _rule_gate_keys(lint: _Lint) -> None:
    for k in set(lint.section("gate")) - _GATE:
        lint.add(f"{lint.n}: unknown gate key `{k}`.")


def _rule_gate_evaluated(lint: _Lint) -> None:
    for entry in lint.mappings("gate.evaluated", lint.section("gate").get("evaluated")):
        where = f"{lint.n}:gate.evaluated"
        lint.vocab(where, "rule", entry.get("rule"), _RULES)
        if not isinstance(entry.get("fired"), bool):
            lint.add(f"{where}: {entry.get('rule')} `fired: {entry.get('fired')}` "
                     f"must be true|false.")


def _rule_gate_discharges(lint: _Lint) -> None:
    """`obligations`/`pre_discharged`: the rule vocabulary, and the demand pointer each
    entry's shape requires. Reads `lint.demand_ids` — `_rule_demands` runs first."""
    gate = lint.section("gate")
    for section, ref_field in (("obligations", "discharged_by"), ("pre_discharged", "by")):
        for entry in lint.mappings(f"gate.{section}", gate.get(section)):
            lint.vocab(f"{lint.n}:gate.{section}", "rule", entry.get("rule"), _RULES)
            ref = entry.get(ref_field)
            if not ref:
                # rules.md declares the shape WITH the pointer — a bare entry still counts
                # as "the gate saw this element" in check_gate, so an entry pointing at no
                # demand is a silencer, not a discharge.
                lint.add(
                    f"{lint.n}:gate.{section}: entry for `{entry.get('element')}` carries no "
                    f"`{ref_field}` — the shape requires the demand pointer."
                )
            elif ref not in lint.demand_ids:
                lint.add(
                    f"{lint.n}:gate.{section}: `{ref_field}: {ref}` names no demand in "
                    f"this graph."
                )


def _rule_gate_holes(lint: _Lint) -> None:
    for entry in lint.mappings("gate.holes", lint.section("gate").get("holes")):
        lint.vocab(f"{lint.n}:gate.holes", "rule", entry.get("rule"), _RULES)
        rt = entry.get("resolved_to")
        if rt and rt not in lint.demand_ids:
            lint.add(f"{lint.n}:gate.holes: `resolved_to: {rt}` names no demand.")


def _rule_handoff(lint: _Lint) -> None:
    for k in set(lint.section("handoff")) - _HANDOFF:
        lint.add(f"{lint.n}: unknown handoff key `{k}`.")


#: The check, in order. Order is contract, not taste: findings print in the order they
#: were appended, and `_rule_demands` must precede the two gate rules that resolve a
#: pointer against the demand ids it collects. Named `_LINT_RULES`, not `_RULES` —
#: `_RULES` above is the R0–R6 gate vocabulary `vocab()` validates against.
_LINT_RULES = (
    _rule_top_level,
    _rule_demands,
    _rule_structure_keys,
    _rule_actors,
    _rule_boundaries,
    _rule_interacts,
    _rule_drives,
    _rule_claims,
    _rule_gate_keys,
    _rule_gate_evaluated,
    _rule_gate_discharges,
    _rule_gate_holes,
    _rule_handoff,
)


def check(path: Path) -> list[str]:
    lint = _Lint(path)
    for rule in _LINT_RULES:
        rule(lint)
    return lint.findings


def main(argv: list[str]) -> int:
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--config"})
    cfg = _config.load(opts["config"])
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
